//! Transaction-free runtime coordination for one admitted NIP-46 event.

use core::{fmt, str::FromStr as _};
use std::{error::Error, sync::Arc};

use nostr::{JsonUtil as _, Kind, PublicKey as NostrPublicKey, Tag, Timestamp, UnsignedEvent};
use radroots_identity::PublicKey;
use radroots_nostr_connect::{
    message::{RemoteSessionCapability, Response, SignedEvent as ConnectSignedEvent},
    permission::Permissions,
    uri::RelayUrl,
};
use radroots_service_host::{EntropySource, SystemEntropy, SystemWallClock, WallClock};
use sha2::{Digest, Sha256};

use crate::state_response::MycNip46PendingResponseCommitRequest;

use crate::{
    MycConfigDocumentV1, MycConnectionAdmissionPolicy, MycConnectionDecision,
    MycConnectionDecisionRecord, MycConnectionNonce, MycConnectionPermissionSet,
    MycConnectionPolicyGeneration, MycConnectionTimeUnixMs, MycNip46AdmissionLimits,
    MycNip46AuthoredTimePolicy, MycNip46CommitRequest, MycNip46EncryptionContext,
    MycNip46ObservedAtUnixSeconds, MycNip46ResponseCommitRequest, MycNip46Work, MycNip46WorkKind,
    MycProviderCorrelationId, MycProviderDeadlineUnixMs, MycProviderNip44Version,
    MycProviderOperation, MycProviderOperationId, MycProviderOperationInput,
    MycProviderPublicIdentity, MycProviderResponseObservedAtUnixMs, MycProviderRole,
    MycRateRelayId, MycRequestReceivedAtUnixMs, MycSignerOperationNonce, MycSignerRequestAdmission,
    MycSignerRequestMethod, MycStateHost, MycTaskCancellation, admit_myc_nip46_event,
    prepare_myc_nip46_decrypt_work, prepare_myc_nip46_request, prepare_myc_nip46_work,
    provider_executor::MycProviderExecutor, verify_myc_nip46_event,
};

const RESPONSE_ENCRYPT_OPERATION_DOMAIN: &[u8] =
    b"radroots.myc.nip46.response_encrypt.operation.v1\0";
const RESPONSE_ENCRYPT_CORRELATION_DOMAIN: &[u8] =
    b"radroots.myc.nip46.response_encrypt.correlation.v1\0";
const RESPONSE_SIGN_OPERATION_DOMAIN: &[u8] = b"radroots.myc.nip46.response_sign.operation.v1\0";
const RESPONSE_SIGN_CORRELATION_DOMAIN: &[u8] =
    b"radroots.myc.nip46.response_sign.correlation.v1\0";
const NIP46_RPC_KIND: u16 = 24_133;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycNip46DispatchDisposition {
    Dropped,
    PendingApproval,
    Completed,
    ExactResponseReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycNip46DispatchErrorKind {
    Provider,
    State,
    Runtime,
}

pub(crate) struct MycNip46DispatchError {
    kind: MycNip46DispatchErrorKind,
}

impl MycNip46DispatchError {
    pub(crate) const fn kind(&self) -> MycNip46DispatchErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycNip46DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46DispatchError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycNip46DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc NIP-46 dispatch failed")
    }
}

impl Error for MycNip46DispatchError {}

const fn dispatch_error(kind: MycNip46DispatchErrorKind) -> MycNip46DispatchError {
    MycNip46DispatchError { kind }
}

pub(crate) struct MycRuntimeNip46Coordinator {
    configuration: Arc<MycConfigDocumentV1>,
    state: Arc<MycStateHost>,
    providers: Arc<MycProviderExecutor>,
    limits: MycNip46AdmissionLimits,
    authored_time: MycNip46AuthoredTimePolicy,
    provider_timeout_ms: u64,
    response_relays: Box<[RelayUrl]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MycRuntimeNip46AdmissionEvidence {
    request_nonce: [u8; 32],
    received_at: MycRequestReceivedAtUnixMs,
}

impl fmt::Debug for MycRuntimeNip46AdmissionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycRuntimeNip46AdmissionEvidence([redacted])")
    }
}

impl MycRuntimeNip46AdmissionEvidence {
    pub(crate) fn new(
        request_nonce: [u8; 32],
        received_at_unix_ms: u64,
    ) -> Result<Self, MycNip46DispatchError> {
        Ok(Self {
            request_nonce,
            received_at: MycRequestReceivedAtUnixMs::new(received_at_unix_ms)
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
        })
    }
}

impl MycRuntimeNip46Coordinator {
    pub(crate) fn new(
        configuration: Arc<MycConfigDocumentV1>,
        state: Arc<MycStateHost>,
        providers: Arc<MycProviderExecutor>,
    ) -> Result<Self, MycNip46DispatchError> {
        let limits = MycNip46AdmissionLimits::from_config(&configuration)
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let past =
            configuration_integer(&configuration, "/transport/ingress/maximum_past_seconds")?;
        let future =
            configuration_integer(&configuration, "/transport/ingress/maximum_future_seconds")?;
        let authored_time = MycNip46AuthoredTimePolicy::new(past, future)
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let provider_timeout_ms = configuration_integer(
            &configuration,
            "/transport/ingress/subscription_deadline_ms",
        )?;
        let response_relays = response_relays(&configuration)?;
        Ok(Self {
            configuration,
            state,
            providers,
            limits,
            authored_time,
            provider_timeout_ms,
            response_relays,
        })
    }

    pub(crate) async fn process(
        &self,
        raw_event: &[u8],
        relay_id: MycRateRelayId,
        observed_at_unix_ms: u64,
        admission_evidence: MycRuntimeNip46AdmissionEvidence,
        cancellation: &MycTaskCancellation,
    ) -> Result<MycNip46DispatchDisposition, MycNip46DispatchError> {
        let observed_seconds = observed_at_unix_ms / 1_000;
        let bounded = match admit_myc_nip46_event(self.limits, raw_event) {
            Ok(bounded) => bounded,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let observed = match MycNip46ObservedAtUnixSeconds::new(observed_seconds) {
            Ok(observed) => observed,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let verified = match verify_myc_nip46_event(
            bounded,
            self.transport_binding()?,
            observed,
            self.authored_time,
        ) {
            Ok(verified) => verified,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let decrypt_deadline = self.provider_deadline()?;
        let decrypt = match prepare_myc_nip46_decrypt_work(
            verified,
            self.transport_binding()?,
            decrypt_deadline,
        ) {
            Ok(work) => work,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let decrypt_response = self
            .providers
            .execute(
                decrypt.operation().owned_for_runtime(),
                provider_observed_now()?,
                cancellation,
            )
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Provider))?;
        let decrypted = match decrypt.complete(decrypt_response, self.limits) {
            Ok(request) => request,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let received_at = MycConnectionTimeUnixMs::new(admission_evidence.received_at.get())
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let prepared = match prepare_myc_nip46_request(
            decrypted,
            MycSignerOperationNonce::from_injected_entropy(admission_evidence.request_nonce),
            admission_evidence.received_at,
        ) {
            Ok(request) => request,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };
        let admission = self
            .state
            .repository()
            .admit_signer_request(prepared.signer_request())
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?;
        if matches!(admission, MycSignerRequestAdmission::ConflictingReuse(_)) {
            return Ok(MycNip46DispatchDisposition::Dropped);
        }
        if self
            .state
            .repository()
            .read_nip46_response_by_operation(admission.record().operation_id())
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?
            .is_some()
        {
            return Ok(MycNip46DispatchDisposition::ExactResponseReplay);
        }

        let connection = if prepared.method() == MycSignerRequestMethod::Connect {
            None
        } else {
            self.state
                .repository()
                .read_active_connection_for_client(
                    admission.record().client_public_key(),
                    received_at,
                )
                .await
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?
        };
        let provider_deadline = matches!(
            prepared.method(),
            MycSignerRequestMethod::SignEvent
                | MycSignerRequestMethod::Nip04Encrypt
                | MycSignerRequestMethod::Nip04Decrypt
                | MycSignerRequestMethod::Nip44Encrypt
                | MycSignerRequestMethod::Nip44Decrypt
        )
        .then(|| self.provider_deadline())
        .transpose()?;
        let work = match prepare_myc_nip46_work(
            prepared,
            admission.record().clone(),
            connection,
            self.configuration.provider_contract(),
            received_at,
            provider_deadline,
        ) {
            Ok(work) => work,
            Err(_) => return Ok(MycNip46DispatchDisposition::Dropped),
        };

        let connect_decision = if work.kind() == MycNip46WorkKind::Connect {
            let request = self
                .connection_request(&work, relay_id, received_at)
                .await?;
            let admission = self
                .state
                .repository()
                .admit_connection(&request)
                .await
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?;
            let Some(record) = admission.record().cloned() else {
                return Ok(MycNip46DispatchDisposition::Dropped);
            };
            if record.decision() == MycConnectionDecision::PendingApproval {
                let committed_at = connection_time_now()?;
                let protocol_response = self.protocol_response(&work, Some(&record), None)?;
                let signed = self
                    .signed_protocol_response(&work, protocol_response, committed_at, cancellation)
                    .await?;
                let commit = MycNip46PendingResponseCommitRequest::new(
                    &work,
                    &record,
                    &signed.operation,
                    &signed.response,
                    crate::MycDeliveryTimeUnixMs::new(committed_at.get())
                        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
                )
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
                self.state
                    .repository()
                    .commit_nip46_pending_response(&commit)
                    .await
                    .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?;
                return Ok(MycNip46DispatchDisposition::PendingApproval);
            }
            if record.decision() == MycConnectionDecision::Challenged {
                return Ok(MycNip46DispatchDisposition::PendingApproval);
            }
            Some(record)
        } else {
            None
        };

        let provider_response = if let Some(operation) = work.provider_operation() {
            Some(
                self.providers
                    .execute(
                        operation.owned_for_runtime(),
                        provider_observed_now()?,
                        cancellation,
                    )
                    .await
                    .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Provider))?,
            )
        } else {
            None
        };
        let completed_at = connection_time_now()?;
        let completion = MycNip46CommitRequest::new(
            &work,
            connect_decision.as_ref(),
            provider_response.as_ref(),
            completed_at,
        )
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let protocol_response =
            self.protocol_response(&work, connect_decision.as_ref(), provider_response.as_ref())?;
        let signed = self
            .signed_protocol_response(&work, protocol_response, completed_at, cancellation)
            .await?;
        let commit = MycNip46ResponseCommitRequest::new(
            &completion,
            &signed.operation,
            &signed.response,
            crate::MycDeliveryTimeUnixMs::new(completed_at.get())
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
        )
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        self.state
            .repository()
            .commit_nip46_response(&commit)
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?;
        Ok(MycNip46DispatchDisposition::Completed)
    }

    async fn signed_protocol_response(
        &self,
        work: &MycNip46Work,
        response: Response,
        committed_at: MycConnectionTimeUnixMs,
        cancellation: &MycTaskCancellation,
    ) -> Result<SignedRuntimeResponse, MycNip46DispatchError> {
        let envelope = response
            .into_envelope(work.request_record().request_id().as_str())
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let plaintext = serde_json::to_vec(&envelope)
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let encrypted = self
            .encrypt_response(work, &plaintext, cancellation)
            .await?;
        self.sign_response(work, &encrypted, committed_at, cancellation)
            .await
    }

    fn transport_binding(&self) -> Result<&crate::MycProviderBinding, MycNip46DispatchError> {
        self.configuration
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
    }

    fn provider_deadline(&self) -> Result<MycProviderDeadlineUnixMs, MycNip46DispatchError> {
        wall_time_millis()?
            .checked_add(self.provider_timeout_ms)
            .and_then(|value| MycProviderDeadlineUnixMs::new(value).ok())
            .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
    }

    async fn connection_request(
        &self,
        work: &MycNip46Work,
        relay_id: MycRateRelayId,
        observed_at: MycConnectionTimeUnixMs,
    ) -> Result<crate::MycConnectionAdmissionRequest, MycNip46DispatchError> {
        let client = work.request_record().client_public_key();
        let normalized = self.configuration.normalized();
        let contains = |pointer: &str| {
            normalized
                .pointer(pointer)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some(client.as_hex()))
                })
        };
        let policy = if contains("/policy/denied_clients") {
            MycConnectionAdmissionPolicy::Denied
        } else if contains("/policy/trusted_clients") {
            MycConnectionAdmissionPolicy::Trusted
        } else {
            MycConnectionAdmissionPolicy::ExplicitApproval
        };
        let authorized_until = if policy == MycConnectionAdmissionPolicy::Trusted
            && normalized
                .pointer("/policy/challenges/enabled")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        {
            let lifetime = configuration_integer(
                &self.configuration,
                "/policy/challenges/authorized_lifetime_ms",
            )?;
            Some(
                observed_at
                    .get()
                    .checked_add(lifetime)
                    .and_then(|value| MycConnectionTimeUnixMs::new(value).ok())
                    .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
            )
        } else {
            None
        };
        let generation = self
            .state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::State))?;
        let mut nonce = [0_u8; 32];
        SystemEntropy
            .fill_bytes(&mut nonce)
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        work.connection_admission_request(
            MycConnectionPolicyGeneration::new(u64::from(generation))
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
            MycConnectionNonce::from_injected_entropy(nonce),
            observed_at,
            authorized_until,
            policy,
            relay_id,
        )
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
    }

    fn protocol_response(
        &self,
        work: &MycNip46Work,
        connect: Option<&MycConnectionDecisionRecord>,
        provider: Option<&crate::MycVerifiedProviderResponse>,
    ) -> Result<Response, MycNip46DispatchError> {
        let user = PublicKey::from_hex(
            self.configuration
                .provider_contract()
                .binding(MycProviderRole::User)
                .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?
                .expected_identity()
                .as_hex(),
        )
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        match work.method() {
            MycSignerRequestMethod::Connect => {
                match connect.map(MycConnectionDecisionRecord::decision) {
                    Some(MycConnectionDecision::Allowed) => Ok(Response::UserPublicKey(user)),
                    Some(MycConnectionDecision::PendingApproval) => Ok(Response::PendingConnection),
                    Some(MycConnectionDecision::Denied) => Ok(Response::Error {
                        result: None,
                        error: "connection_denied".to_owned(),
                    }),
                    _ => Err(dispatch_error(MycNip46DispatchErrorKind::Runtime)),
                }
            }
            MycSignerRequestMethod::GetPublicKey => Ok(Response::UserPublicKey(user)),
            MycSignerRequestMethod::GetSessionCapability => {
                let permissions = protocol_permissions(
                    work.connection()
                        .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?
                        .granted_permissions(),
                )?;
                Ok(Response::RemoteSessionCapability(
                    RemoteSessionCapability::try_new(
                        user,
                        self.response_relays.to_vec(),
                        permissions,
                    )
                    .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
                ))
            }
            MycSignerRequestMethod::SignEvent => {
                let bytes = provider
                    .and_then(crate::MycVerifiedProviderResponse::signed_event_bytes)
                    .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
                let json = core::str::from_utf8(bytes)
                    .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
                Ok(Response::SignedEvent(
                    ConnectSignedEvent::from_json(json)
                        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?,
                ))
            }
            MycSignerRequestMethod::Nip04Encrypt => {
                Ok(Response::Nip04Encrypt(protected_text(provider)?))
            }
            MycSignerRequestMethod::Nip04Decrypt => {
                Ok(Response::Nip04Decrypt(protected_text(provider)?))
            }
            MycSignerRequestMethod::Nip44Encrypt => {
                Ok(Response::Nip44Encrypt(protected_text(provider)?))
            }
            MycSignerRequestMethod::Nip44Decrypt => {
                Ok(Response::Nip44Decrypt(protected_text(provider)?))
            }
            MycSignerRequestMethod::Ping => Ok(Response::Pong),
            MycSignerRequestMethod::SwitchRelays => Ok(Response::RelayListUnchanged),
            MycSignerRequestMethod::Logout => Ok(Response::LogoutAcknowledged),
        }
    }

    async fn encrypt_response(
        &self,
        work: &MycNip46Work,
        plaintext: &[u8],
        cancellation: &MycTaskCancellation,
    ) -> Result<Vec<u8>, MycNip46DispatchError> {
        let binding = self
            .configuration
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let peer =
            MycProviderPublicIdentity::new(work.request_record().client_public_key().as_hex())
                .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let input = match work.encryption_context() {
            MycNip46EncryptionContext::Nip04 => {
                MycProviderOperationInput::nip04_encrypt(peer, plaintext)
            }
            MycNip46EncryptionContext::Nip44V2 => MycProviderOperationInput::nip44_encrypt(
                peer,
                MycProviderNip44Version::V2,
                plaintext,
            ),
        }
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let operation = derived_operation(
            binding,
            work,
            RESPONSE_ENCRYPT_OPERATION_DOMAIN,
            RESPONSE_ENCRYPT_CORRELATION_DOMAIN,
            self.provider_deadline()?,
            input,
        )?;
        let response = self
            .providers
            .execute(operation, provider_observed_now()?, cancellation)
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Provider))?;
        response
            .protected_payload()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Provider))
    }

    async fn sign_response(
        &self,
        work: &MycNip46Work,
        ciphertext: &[u8],
        completed_at: MycConnectionTimeUnixMs,
        cancellation: &MycTaskCancellation,
    ) -> Result<SignedRuntimeResponse, MycNip46DispatchError> {
        let content = core::str::from_utf8(ciphertext)
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Provider))?;
        let user_binding = self
            .configuration
            .provider_contract()
            .binding(MycProviderRole::User)
            .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let user = NostrPublicKey::from_hex(user_binding.expected_identity().as_hex())
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let client = NostrPublicKey::from_hex(work.request_record().client_public_key().as_hex())
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let unsigned = UnsignedEvent::new(
            user,
            Timestamp::from_secs(completed_at.get() / 1_000),
            Kind::Custom(NIP46_RPC_KIND),
            vec![Tag::public_key(client)],
            content,
        );
        let input = MycProviderOperationInput::sign_event(unsigned.as_json().as_bytes())
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
        let operation = derived_operation(
            user_binding,
            work,
            RESPONSE_SIGN_OPERATION_DOMAIN,
            RESPONSE_SIGN_CORRELATION_DOMAIN,
            self.provider_deadline()?,
            input,
        )?;
        let response = self
            .providers
            .execute(
                operation.owned_for_runtime(),
                provider_observed_now()?,
                cancellation,
            )
            .await
            .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Provider))?;
        Ok(SignedRuntimeResponse {
            operation,
            response,
        })
    }
}

struct SignedRuntimeResponse {
    operation: MycProviderOperation,
    response: crate::MycVerifiedProviderResponse,
}

fn derived_operation(
    binding: &crate::MycProviderBinding,
    work: &MycNip46Work,
    operation_domain: &[u8],
    correlation_domain: &[u8],
    deadline: MycProviderDeadlineUnixMs,
    input: MycProviderOperationInput,
) -> Result<MycProviderOperation, MycNip46DispatchError> {
    let identity = work.request_record().operation_id();
    MycProviderOperation::new(
        binding,
        MycProviderOperationId::from_bytes(derived_identifier(
            operation_domain,
            identity.as_bytes(),
        )),
        MycProviderCorrelationId::from_bytes(derived_identifier(
            correlation_domain,
            identity.as_bytes(),
        )),
        deadline,
        input,
    )
    .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn derived_identifier(domain: &[u8], operation_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(operation_id);
    hasher.finalize().into()
}

fn protected_text(
    provider: Option<&crate::MycVerifiedProviderResponse>,
) -> Result<String, MycNip46DispatchError> {
    provider
        .and_then(crate::MycVerifiedProviderResponse::protected_payload)
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .map(str::to_owned)
        .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn protocol_permissions(
    permissions: &MycConnectionPermissionSet,
) -> Result<Permissions, MycNip46DispatchError> {
    let value = permissions
        .permissions()
        .iter()
        .map(|permission| permission.code())
        .collect::<Vec<_>>()
        .join(",");
    Permissions::from_str(&value).map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn response_relays(
    configuration: &MycConfigDocumentV1,
) -> Result<Box<[RelayUrl]>, MycNip46DispatchError> {
    let relays = configuration
        .normalized()
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))?;
    relays
        .iter()
        .filter(|relay| relay.pointer("/write").and_then(serde_json::Value::as_bool) == Some(true))
        .map(|relay| {
            relay
                .pointer("/url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
                .and_then(|url| {
                    RelayUrl::parse(url)
                        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn wall_time_millis() -> Result<u64, MycNip46DispatchError> {
    SystemWallClock
        .now_utc()
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))?
        .get()
        .checked_mul(1_000)
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn connection_time_now() -> Result<MycConnectionTimeUnixMs, MycNip46DispatchError> {
    MycConnectionTimeUnixMs::new(wall_time_millis()?)
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn provider_observed_now() -> Result<MycProviderResponseObservedAtUnixMs, MycNip46DispatchError> {
    MycProviderResponseObservedAtUnixMs::new(wall_time_millis()?)
        .map_err(|_| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

fn configuration_integer(
    configuration: &MycConfigDocumentV1,
    pointer: &str,
) -> Result<u64, MycNip46DispatchError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| dispatch_error(MycNip46DispatchErrorKind::Runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_evidence_is_copyable_across_exact_runtime_retries() {
        let evidence = MycRuntimeNip46AdmissionEvidence::new([0x5a; 32], 1_725_000_000_000)
            .expect("admission evidence");
        assert_eq!(evidence, evidence);
        assert_eq!(evidence.request_nonce, [0x5a; 32]);
        assert_eq!(evidence.received_at.get(), 1_725_000_000_000);
        assert_eq!(
            format!("{evidence:?}"),
            "MycRuntimeNip46AdmissionEvidence([redacted])"
        );
        assert!(MycRuntimeNip46AdmissionEvidence::new([0x5a; 32], 0).is_err());
        assert!(MycRuntimeNip46AdmissionEvidence::new([0x5a; 32], u64::MAX).is_err());
    }
}
