//! Transaction-free NIP-46 decryption, method admission, and provider work.

use core::fmt;
use std::error::Error;

use nostr::UnsignedEvent as NostrUnsignedEvent;
use radroots_nostr_connect::{
    message::{Request, RequestMessage, UnsignedEvent as ConnectUnsignedEvent},
    server::required_permission,
};
use sha2::{Digest, Sha256};

use crate::{
    MycConnectionAdmissionPolicy, MycConnectionAdmissionRequest, MycConnectionNonce,
    MycConnectionPermission, MycConnectionPermissionSet, MycConnectionPolicyGeneration,
    MycConnectionRecord, MycConnectionStatus, MycConnectionTimeUnixMs, MycNip46AdmissionLimits,
    MycNip46EncryptionContext, MycProviderBinding, MycProviderContract, MycProviderCorrelationId,
    MycProviderDeadlineUnixMs, MycProviderNip44Version, MycProviderOperation,
    MycProviderOperationId, MycProviderOperationInput, MycProviderPublicIdentity, MycProviderRole,
    MycRateRelayId, MycReplayBoundNip46Request, MycRequestReceivedAtUnixMs,
    MycSignerOperationNonce, MycSignerRequest, MycSignerRequestMethod, MycSignerRequestRecord,
    MycVerifiedNip46Event, MycVerifiedProviderResponse, admit_myc_nip46_request,
    bind_myc_nip46_replay, verify_myc_nip46_request,
};

const DECRYPT_OPERATION_ID_DOMAIN: &[u8] = b"radroots.myc.nip46.decrypt.operation.v1\0";
const DECRYPT_CORRELATION_ID_DOMAIN: &[u8] = b"radroots.myc.nip46.decrypt.correlation.v1\0";

/// Stable source-free Step 145 failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46WorkErrorKind {
    InvalidBinding,
    DecryptionRejected,
    UnsupportedMethod,
    PermissionDenied,
    ConnectionExpired,
    ProviderWorkRejected,
}

impl MycNip46WorkErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "nip46_work_binding_invalid",
            Self::DecryptionRejected => "nip46_decryption_rejected",
            Self::UnsupportedMethod => "nip46_method_unsupported",
            Self::PermissionDenied => "nip46_permission_denied",
            Self::ConnectionExpired => "nip46_connection_inactive",
            Self::ProviderWorkRejected => "nip46_provider_work_rejected",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "NIP-46 work binding is invalid",
            Self::DecryptionRejected => "NIP-46 decrypted request was rejected",
            Self::UnsupportedMethod => "NIP-46 method is unsupported",
            Self::PermissionDenied => "NIP-46 permission was denied",
            Self::ConnectionExpired => "NIP-46 connection is not active",
            Self::ProviderWorkRejected => "NIP-46 provider work was rejected",
        }
    }
}

/// One redacted source-free Step 145 failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46WorkError {
    kind: MycNip46WorkErrorKind,
}

impl MycNip46WorkError {
    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycNip46WorkErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycNip46WorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46WorkError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycNip46WorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycNip46WorkError {}

const fn work_error(kind: MycNip46WorkErrorKind) -> MycNip46WorkError {
    MycNip46WorkError { kind }
}

/// Provider-bound work that must complete before plaintext request admission.
pub struct MycNip46DecryptWork {
    event: MycVerifiedNip46Event,
    operation: MycProviderOperation,
}

impl MycNip46DecryptWork {
    /// Returns the exact transport-provider operation for external execution.
    #[must_use]
    pub const fn operation(&self) -> &MycProviderOperation {
        &self.operation
    }

    /// Binds an independently verified provider result to the exact event.
    pub fn complete(
        self,
        response: MycVerifiedProviderResponse,
        limits: MycNip46AdmissionLimits,
    ) -> Result<MycDecryptedNip46Request, MycNip46WorkError> {
        let expected_capability = self.operation.input().capability();
        if response.operation_id() != self.operation.operation_id()
            || response.correlation_id() != self.operation.correlation_id()
            || response.instance() != self.operation.instance()
            || response.role() != MycProviderRole::Transport
            || response.capability() != expected_capability
            || response.nip44_version() != self.operation.input().nip44_version()
            || !response.matches_operation(&self.operation)
        {
            return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
        }
        let plaintext = response
            .protected_payload()
            .ok_or_else(|| work_error(MycNip46WorkErrorKind::DecryptionRejected))?;
        let bounded = admit_myc_nip46_request(limits, plaintext)
            .map_err(|_| work_error(MycNip46WorkErrorKind::DecryptionRejected))?;
        let request = verify_myc_nip46_request(bounded)
            .map_err(|_| work_error(MycNip46WorkErrorKind::DecryptionRejected))?;
        let replay = bind_myc_nip46_replay(self.event, request)
            .map_err(|_| work_error(MycNip46WorkErrorKind::DecryptionRejected))?;
        Ok(MycDecryptedNip46Request { replay })
    }
}

impl fmt::Debug for MycNip46DecryptWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46DecryptWork")
            .field("event", &"[redacted]")
            .field("operation", &self.operation)
            .finish()
    }
}

/// Constructs the exact transport-provider decryption work for one verified event.
pub fn prepare_myc_nip46_decrypt_work(
    event: MycVerifiedNip46Event,
    transport: &MycProviderBinding,
    deadline: MycProviderDeadlineUnixMs,
) -> Result<MycNip46DecryptWork, MycNip46WorkError> {
    if transport.role() != MycProviderRole::Transport
        || transport.expected_identity() != event.receiver_public_key()
    {
        return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
    }
    let operation_id = MycProviderOperationId::from_bytes(derive_decrypt_identity(
        DECRYPT_OPERATION_ID_DOMAIN,
        event.event_id().as_bytes(),
    ));
    let correlation_id = MycProviderCorrelationId::from_bytes(derive_decrypt_identity(
        DECRYPT_CORRELATION_ID_DOMAIN,
        event.event_id().as_bytes(),
    ));
    let peer = MycProviderPublicIdentity::new(event.client_public_key().as_hex())
        .map_err(|_| work_error(MycNip46WorkErrorKind::InvalidBinding))?;
    let input = match event.encryption_context() {
        MycNip46EncryptionContext::Nip04 => {
            MycProviderOperationInput::nip04_decrypt(peer, event.encrypted_content().as_bytes())
        }
        MycNip46EncryptionContext::Nip44V2 => MycProviderOperationInput::nip44_decrypt(
            peer,
            MycProviderNip44Version::V2,
            event.encrypted_content().as_bytes(),
        ),
    }
    .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    let operation =
        MycProviderOperation::new(transport, operation_id, correlation_id, deadline, input)
            .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    Ok(MycNip46DecryptWork { event, operation })
}

fn derive_decrypt_identity(domain: &[u8], event_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(event_id);
    hasher.finalize().into()
}

/// Non-forgeable proof that the typed request came from the exact decrypt work.
pub struct MycDecryptedNip46Request {
    replay: MycReplayBoundNip46Request,
}

impl fmt::Debug for MycDecryptedNip46Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDecryptedNip46Request([redacted])")
    }
}

/// Exact request ready for durable admission but not provider execution.
pub struct MycPreparedNip46Request {
    signer_request: MycSignerRequest,
    request: Request,
}

impl MycPreparedNip46Request {
    /// Returns the exact input for the short durable request-admission transaction.
    #[must_use]
    pub const fn signer_request(&self) -> &MycSignerRequest {
        &self.signer_request
    }

    /// Returns the exact closed method admitted before persistence.
    #[must_use]
    pub const fn method(&self) -> MycSignerRequestMethod {
        self.signer_request.method()
    }
}

impl fmt::Debug for MycPreparedNip46Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycPreparedNip46Request")
            .field("method", &self.method())
            .field("request", &"[redacted]")
            .finish()
    }
}

/// Converts one proven decrypted request into exact durable-admission input.
pub fn prepare_myc_nip46_request(
    decrypted: MycDecryptedNip46Request,
    nonce: MycSignerOperationNonce,
    received_at: MycRequestReceivedAtUnixMs,
) -> Result<MycPreparedNip46Request, MycNip46WorkError> {
    let method = MycSignerRequestMethod::parse(decrypted.replay.method())
        .ok_or_else(|| work_error(MycNip46WorkErrorKind::UnsupportedMethod))?;
    let message: RequestMessage = serde_json::from_slice(decrypted.replay.canonical_request())
        .map_err(|_| work_error(MycNip46WorkErrorKind::InvalidBinding))?;
    if message.payload().method().as_str() != method.as_str()
        || message
            .request_id()
            .map(|request_id| request_id.as_str() != decrypted.replay.request_id().as_str())
            .unwrap_or(true)
    {
        return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
    }
    let signer_request = MycSignerRequest::new(
        decrypted.replay.client_public_key().clone(),
        decrypted.replay.request_id().clone(),
        decrypted.replay.event_id(),
        method,
        decrypted.replay.request_digest(),
        nonce,
        received_at,
    );
    Ok(MycPreparedNip46Request {
        signer_request,
        request: message.request,
    })
}

/// Exact Step 145 work classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46WorkKind {
    Connect,
    Local,
    Provider,
}

enum Nip46WorkPayload {
    Connect {
        client: crate::MycNip46ClientPublicKey,
        permissions: MycConnectionPermissionSet,
    },
    Local,
    Provider(MycProviderOperation),
}

/// Sealed request work constructed only after durable request admission.
pub struct MycNip46Work {
    request: MycSignerRequestRecord,
    connection: Option<MycConnectionRecord>,
    method: MycSignerRequestMethod,
    payload: Nip46WorkPayload,
}

impl MycNip46Work {
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn local_for_test(
        request: MycSignerRequestRecord,
        connection: MycConnectionRecord,
        method: MycSignerRequestMethod,
    ) -> Self {
        assert!(matches!(
            method,
            MycSignerRequestMethod::GetPublicKey
                | MycSignerRequestMethod::GetSessionCapability
                | MycSignerRequestMethod::Ping
                | MycSignerRequestMethod::SwitchRelays
                | MycSignerRequestMethod::Logout
        ));
        Self {
            request,
            connection: Some(connection),
            method,
            payload: Nip46WorkPayload::Local,
        }
    }

    /// Returns the exact admitted durable request record.
    #[must_use]
    pub const fn request_record(&self) -> &MycSignerRequestRecord {
        &self.request
    }

    /// Returns the exact active connection used for non-connect work.
    #[must_use]
    pub const fn connection(&self) -> Option<&MycConnectionRecord> {
        self.connection.as_ref()
    }

    /// Returns the exact admitted request method.
    #[must_use]
    pub const fn method(&self) -> MycSignerRequestMethod {
        self.method
    }

    /// Returns the work class without exposing protected parameters.
    #[must_use]
    pub const fn kind(&self) -> MycNip46WorkKind {
        match &self.payload {
            Nip46WorkPayload::Connect { .. } => MycNip46WorkKind::Connect,
            Nip46WorkPayload::Local => MycNip46WorkKind::Local,
            Nip46WorkPayload::Provider(_) => MycNip46WorkKind::Provider,
        }
    }

    /// Returns the provider operation only for provider-bearing work.
    #[must_use]
    pub const fn provider_operation(&self) -> Option<&MycProviderOperation> {
        match &self.payload {
            Nip46WorkPayload::Provider(operation) => Some(operation),
            Nip46WorkPayload::Connect { .. } | Nip46WorkPayload::Local => None,
        }
    }

    /// Constructs the exact Step 144 admission request for connect work.
    pub fn connection_admission_request(
        &self,
        policy_generation: MycConnectionPolicyGeneration,
        nonce: MycConnectionNonce,
        observed_at: MycConnectionTimeUnixMs,
        authorized_until: Option<MycConnectionTimeUnixMs>,
        policy: MycConnectionAdmissionPolicy,
        relay_id: MycRateRelayId,
    ) -> Result<MycConnectionAdmissionRequest, MycNip46WorkError> {
        let Nip46WorkPayload::Connect {
            client,
            permissions,
        } = &self.payload
        else {
            return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
        };
        MycConnectionAdmissionRequest::new(
            self.request.operation_id(),
            client.clone(),
            permissions.clone(),
            policy_generation,
            nonce,
            observed_at,
            authorized_until,
            policy,
            relay_id,
        )
        .map_err(|_| work_error(MycNip46WorkErrorKind::InvalidBinding))
    }
}

impl fmt::Debug for MycNip46Work {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46Work")
            .field("method", &self.method)
            .field("kind", &self.kind())
            .field("request", &"[redacted]")
            .field(
                "connection",
                &self.connection.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Binds an admitted request and optional active connection to exact work.
///
/// This function accepts no repository, host, transaction, provider executor,
/// clock, or entropy source. Provider execution therefore starts only after
/// the caller's durable request-admission transaction has ended.
pub fn prepare_myc_nip46_work(
    prepared: MycPreparedNip46Request,
    record: MycSignerRequestRecord,
    connection: Option<MycConnectionRecord>,
    providers: &MycProviderContract,
    observed_at: MycConnectionTimeUnixMs,
    provider_deadline: Option<MycProviderDeadlineUnixMs>,
) -> Result<MycNip46Work, MycNip46WorkError> {
    let MycPreparedNip46Request {
        signer_request,
        request,
    } = prepared;
    if !record.matches_request(&signer_request) || observed_at.get() < record.received_at().get() {
        return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
    }
    let method = signer_request.method();
    let request = match request {
        Request::Connect {
            remote_signer_public_key,
            secret,
            requested_permissions,
            client_metadata: _,
        } => {
            if connection.is_some() || provider_deadline.is_some() || secret.is_some() {
                return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
            }
            let user = user_binding(providers)?;
            if remote_signer_public_key.to_hex() != user.expected_identity().as_hex() {
                return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
            }
            let permissions = connect_permissions(requested_permissions.as_slice())?;
            return Ok(MycNip46Work {
                request: record,
                connection: None,
                method,
                payload: Nip46WorkPayload::Connect {
                    client: signer_request.client_public_key().clone(),
                    permissions,
                },
            });
        }
        Request::Custom { .. } => {
            return Err(work_error(MycNip46WorkErrorKind::UnsupportedMethod));
        }
        request => request,
    };

    let connection = connection.ok_or_else(|| work_error(MycNip46WorkErrorKind::InvalidBinding))?;
    if connection.client_public_key() != signer_request.client_public_key() {
        return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
    }
    if connection.status() != MycConnectionStatus::Active
        || connection
            .authorized_until()
            .is_some_and(|until| observed_at > until)
    {
        return Err(work_error(MycNip46WorkErrorKind::ConnectionExpired));
    }
    if let Some(permission) = required_permission(&request) {
        let permission = protocol_permission(&permission.to_string())?;
        if !connection.granted_permissions().contains(permission) {
            return Err(work_error(MycNip46WorkErrorKind::PermissionDenied));
        }
    }

    let payload = match request {
        Request::GetPublicKey
        | Request::GetSessionCapability
        | Request::Ping
        | Request::SwitchRelays
        | Request::Logout => {
            if provider_deadline.is_some() {
                return Err(work_error(MycNip46WorkErrorKind::InvalidBinding));
            }
            Nip46WorkPayload::Local
        }
        Request::SignEvent(event) => {
            let input = sign_event_input(&event, providers)?;
            provider_work(
                providers,
                &record,
                observed_at,
                provider_deadline,
                Ok(input),
            )?
        }
        Request::Nip04Encrypt {
            public_key,
            plaintext,
        } => provider_work(
            providers,
            &record,
            observed_at,
            provider_deadline,
            MycProviderOperationInput::nip04_encrypt(
                provider_identity(&public_key.to_hex())?,
                plaintext.as_bytes(),
            ),
        )?,
        Request::Nip04Decrypt {
            public_key,
            ciphertext,
        } => provider_work(
            providers,
            &record,
            observed_at,
            provider_deadline,
            MycProviderOperationInput::nip04_decrypt(
                provider_identity(&public_key.to_hex())?,
                ciphertext.as_bytes(),
            ),
        )?,
        Request::Nip44Encrypt {
            public_key,
            plaintext,
        } => provider_work(
            providers,
            &record,
            observed_at,
            provider_deadline,
            MycProviderOperationInput::nip44_encrypt(
                provider_identity(&public_key.to_hex())?,
                MycProviderNip44Version::V2,
                plaintext.as_bytes(),
            ),
        )?,
        Request::Nip44Decrypt {
            public_key,
            ciphertext,
        } => provider_work(
            providers,
            &record,
            observed_at,
            provider_deadline,
            MycProviderOperationInput::nip44_decrypt(
                provider_identity(&public_key.to_hex())?,
                MycProviderNip44Version::V2,
                ciphertext.as_bytes(),
            ),
        )?,
        Request::Connect { .. } | Request::Custom { .. } => {
            return Err(work_error(MycNip46WorkErrorKind::UnsupportedMethod));
        }
    };

    Ok(MycNip46Work {
        request: record,
        connection: Some(connection),
        method,
        payload,
    })
}

fn provider_work(
    providers: &MycProviderContract,
    record: &MycSignerRequestRecord,
    observed_at: MycConnectionTimeUnixMs,
    deadline: Option<MycProviderDeadlineUnixMs>,
    input: Result<MycProviderOperationInput, crate::MycProviderContractError>,
) -> Result<Nip46WorkPayload, MycNip46WorkError> {
    let deadline = deadline.ok_or_else(|| work_error(MycNip46WorkErrorKind::InvalidBinding))?;
    if deadline.get() <= observed_at.get() {
        return Err(work_error(MycNip46WorkErrorKind::ProviderWorkRejected));
    }
    let input = input.map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    let operation = MycProviderOperation::new(
        user_binding(providers)?,
        MycProviderOperationId::from_bytes(*record.operation_id().as_bytes()),
        MycProviderCorrelationId::from_bytes(*record.correlation_id().as_bytes()),
        deadline,
        input,
    )
    .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    Ok(Nip46WorkPayload::Provider(operation))
}

fn user_binding(providers: &MycProviderContract) -> Result<&MycProviderBinding, MycNip46WorkError> {
    providers
        .binding(MycProviderRole::User)
        .ok_or_else(|| work_error(MycNip46WorkErrorKind::InvalidBinding))
}

fn sign_event_input(
    event: &ConnectUnsignedEvent,
    providers: &MycProviderContract,
) -> Result<MycProviderOperationInput, MycNip46WorkError> {
    let canonical = event.as_json();
    let unsigned: NostrUnsignedEvent = serde_json::from_str(&canonical)
        .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    let reencoded = serde_json::to_vec(&unsigned)
        .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))?;
    if reencoded.as_slice() != canonical.as_bytes()
        || unsigned.verify_id().is_err()
        || unsigned.pubkey.to_hex() != user_binding(providers)?.expected_identity().as_hex()
    {
        return Err(work_error(MycNip46WorkErrorKind::ProviderWorkRejected));
    }
    MycProviderOperationInput::sign_event(canonical.as_bytes())
        .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))
}

fn provider_identity(value: &str) -> Result<MycProviderPublicIdentity, MycNip46WorkError> {
    MycProviderPublicIdentity::new(value)
        .map_err(|_| work_error(MycNip46WorkErrorKind::ProviderWorkRejected))
}

fn protocol_permission(value: &str) -> Result<MycConnectionPermission, MycNip46WorkError> {
    MycConnectionPermission::parse(value)
        .ok_or_else(|| work_error(MycNip46WorkErrorKind::UnsupportedMethod))
}

fn connect_permissions(
    permissions: &[radroots_nostr_connect::permission::Permission],
) -> Result<MycConnectionPermissionSet, MycNip46WorkError> {
    let permissions = permissions
        .iter()
        .map(|permission| protocol_permission(&permission.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if permissions.iter().any(|permission| {
        !matches!(
            permission,
            MycConnectionPermission::SignEvent(_)
                | MycConnectionPermission::Nip04Encrypt
                | MycConnectionPermission::Nip04Decrypt
                | MycConnectionPermission::Nip44Encrypt
                | MycConnectionPermission::Nip44Decrypt
                | MycConnectionPermission::SwitchRelays
        )
    }) {
        return Err(work_error(MycNip46WorkErrorKind::PermissionDenied));
    }
    MycConnectionPermissionSet::new(&permissions)
        .map_err(|_| work_error(MycNip46WorkErrorKind::PermissionDenied))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use nostr::{
        EventBuilder, JsonUtil as _, Keys, Kind, Tag, Timestamp,
        UnsignedEvent as NostrUnsignedEvent,
        nips::{nip04, nip44},
    };
    use radroots_nostr_connect::{
        Method,
        message::{Request, RequestMessage, UnsignedEvent as ConnectUnsignedEvent},
    };

    use crate::{
        MycConfigDocumentV1, MycConfigProfile, MycNip46AuthoredTimePolicy,
        MycNip46ObservedAtUnixSeconds, MycProviderCapability, MycProviderResponseObservedAtUnixMs,
        admit_myc_nip46_event, parse_myc_config_v1,
        provider_verification::verify_protected_response_for_test, verify_myc_nip46_event,
    };

    use super::*;

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
    const OBSERVED_AT_SECONDS: u64 = 1_725_000_000;
    const RECEIVED_AT_MS: u64 = 1_725_000_000_000;
    const PROVIDER_DEADLINE_MS: u64 = RECEIVED_AT_MS + 10_000;

    fn keys(seed: u8) -> Keys {
        Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
    }

    fn configuration() -> MycConfigDocumentV1 {
        let source = CONFIG
            .replacen(
                "4444444444444444444444444444444444444444444444444444444444444444",
                &keys(2).public_key().to_hex(),
                1,
            )
            .replacen(
                "2222222222222222222222222222222222222222222222222222222222222222",
                &keys(3).public_key().to_hex(),
                1,
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("test configuration")
    }

    fn verified_event(
        request: &Request,
        nip44_v2: bool,
        created_at: u64,
    ) -> (MycVerifiedNip46Event, Vec<u8>) {
        let client = keys(1);
        let transport = keys(2);
        let message = RequestMessage::try_new(format!("request-{created_at}"), request.clone())
            .expect("request message");
        let plaintext = serde_json::to_vec(&message).expect("canonical request");
        let content = if nip44_v2 {
            nip44::encrypt(
                client.secret_key(),
                &transport.public_key(),
                &plaintext,
                nip44::Version::V2,
            )
            .expect("NIP-44 encryption")
        } else {
            nip04::encrypt(client.secret_key(), &transport.public_key(), &plaintext)
                .expect("NIP-04 encryption")
        };
        let event = EventBuilder::new(Kind::Custom(24_133), content)
            .tag(Tag::public_key(transport.public_key()))
            .custom_created_at(Timestamp::from_secs(created_at))
            .sign_with_keys(&client)
            .expect("signed request event");
        let config = configuration();
        let limits = MycNip46AdmissionLimits::from_config(&config).expect("admission limits");
        let wire = serde_json::to_vec(&event).expect("event wire");
        let event = verify_myc_nip46_event(
            admit_myc_nip46_event(limits, &wire).expect("bounded event"),
            config
                .provider_contract()
                .binding(MycProviderRole::Transport)
                .expect("transport binding"),
            MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT_SECONDS).expect("observation"),
            MycNip46AuthoredTimePolicy::new(120, 120).expect("authored-time policy"),
        )
        .expect("verified event");
        (event, plaintext)
    }

    fn decrypted(request: &Request, nip44_v2: bool, created_at: u64) -> MycDecryptedNip46Request {
        let (event, plaintext) = verified_event(request, nip44_v2, created_at);
        let config = configuration();
        let transport = config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding");
        let work = prepare_myc_nip46_decrypt_work(
            event,
            transport,
            MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline"),
        )
        .expect("decrypt work");
        let response = verify_protected_response_for_test(transport, work.operation(), &plaintext)
            .expect("verified provider response");
        work.complete(
            response,
            MycNip46AdmissionLimits::from_config(&config).expect("admission limits"),
        )
        .expect("decrypted request")
    }

    fn prepared_request(request: Request, seed: u8) -> MycPreparedNip46Request {
        prepare_myc_nip46_request(
            decrypted(&request, true, OBSERVED_AT_SECONDS + u64::from(seed)),
            MycSignerOperationNonce::from_injected_entropy([seed; 32]),
            MycRequestReceivedAtUnixMs::new(RECEIVED_AT_MS + u64::from(seed))
                .expect("received time"),
        )
        .expect("prepared request")
    }

    fn active_connection(
        prepared: &MycPreparedNip46Request,
        permissions: &[MycConnectionPermission],
        authorized_until: Option<u64>,
    ) -> MycConnectionRecord {
        MycConnectionRecord::active_for_test(
            prepared.signer_request.client_public_key().clone(),
            MycConnectionPermissionSet::new(permissions).expect("permissions"),
            authorized_until
                .map(|value| MycConnectionTimeUnixMs::new(value).expect("authorization deadline")),
        )
    }

    fn unsigned_sign_event() -> ConnectUnsignedEvent {
        unsigned_sign_event_for(3)
    }

    fn unsigned_sign_event_for(author_seed: u8) -> ConnectUnsignedEvent {
        let event = NostrUnsignedEvent::new(
            keys(author_seed).public_key(),
            Timestamp::from_secs(OBSERVED_AT_SECONDS),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "bounded test event",
        );
        ConnectUnsignedEvent::from_json(&event.as_json()).expect("connect unsigned event")
    }

    fn protocol_request(method: Method, params: Vec<String>) -> Request {
        Request::from_parts(method, params).expect("protocol request")
    }

    #[test]
    fn verified_decryption_is_bound_to_the_exact_event_and_context() {
        let request = Request::Ping;
        for (nip44_v2, expected_capability, expected_version) in [
            (false, MycProviderCapability::Nip04Decrypt, None),
            (
                true,
                MycProviderCapability::Nip44Decrypt,
                Some(MycProviderNip44Version::V2),
            ),
        ] {
            let (event, plaintext) = verified_event(&request, nip44_v2, OBSERVED_AT_SECONDS);
            let config = configuration();
            let transport = config
                .provider_contract()
                .binding(MycProviderRole::Transport)
                .expect("transport binding");
            let work = prepare_myc_nip46_decrypt_work(
                event,
                transport,
                MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline"),
            )
            .expect("decrypt work");
            assert_eq!(work.operation().role(), MycProviderRole::Transport);
            assert_eq!(work.operation().input().capability(), expected_capability);
            assert_eq!(work.operation().input().nip44_version(), expected_version);
            let response =
                verify_protected_response_for_test(transport, work.operation(), &plaintext)
                    .expect("verified response");
            work.complete(
                response,
                MycNip46AdmissionLimits::from_config(&config).expect("limits"),
            )
            .expect("exact event completion");
        }

        let (first_event, plaintext) = verified_event(&request, true, OBSERVED_AT_SECONDS + 1);
        let (second_event, _) = verified_event(&request, true, OBSERVED_AT_SECONDS + 2);
        let config = configuration();
        let transport = config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding");
        let first = prepare_myc_nip46_decrypt_work(
            first_event,
            transport,
            MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline"),
        )
        .expect("first work");
        let second = prepare_myc_nip46_decrypt_work(
            second_event,
            transport,
            MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline"),
        )
        .expect("second work");
        let response = verify_protected_response_for_test(transport, first.operation(), &plaintext)
            .expect("first response");
        assert_ne!(
            first.operation().operation_id(),
            second.operation().operation_id()
        );
        assert_eq!(
            second
                .complete(
                    response,
                    MycNip46AdmissionLimits::from_config(&config).expect("limits"),
                )
                .expect_err("cross-event response"),
            work_error(MycNip46WorkErrorKind::InvalidBinding)
        );
    }

    #[test]
    fn exact_method_inventory_maps_to_local_and_user_provider_work() {
        let peer = keys(4).public_key().to_hex();
        let cases = vec![
            (Request::GetPublicKey, None, MycNip46WorkKind::Local, None),
            (
                Request::GetSessionCapability,
                None,
                MycNip46WorkKind::Local,
                None,
            ),
            (Request::Ping, None, MycNip46WorkKind::Local, None),
            (Request::Logout, None, MycNip46WorkKind::Local, None),
            (
                Request::SwitchRelays,
                Some(MycConnectionPermission::SwitchRelays),
                MycNip46WorkKind::Local,
                None,
            ),
            (
                Request::SignEvent(unsigned_sign_event()),
                Some(MycConnectionPermission::SignEvent(1)),
                MycNip46WorkKind::Provider,
                Some(MycProviderCapability::SignEvent),
            ),
            (
                protocol_request(Method::Nip04Encrypt, vec![peer.clone(), "bounded".into()]),
                Some(MycConnectionPermission::Nip04Encrypt),
                MycNip46WorkKind::Provider,
                Some(MycProviderCapability::Nip04Encrypt),
            ),
            (
                protocol_request(
                    Method::Nip04Decrypt,
                    vec![
                        peer.clone(),
                        "QUFBQUFBQUFBQUFBQUFBQQ==?iv=QUFBQUFBQUFBQUFBQUFBQQ==".into(),
                    ],
                ),
                Some(MycConnectionPermission::Nip04Decrypt),
                MycNip46WorkKind::Provider,
                Some(MycProviderCapability::Nip04Decrypt),
            ),
            (
                protocol_request(Method::Nip44Encrypt, vec![peer.clone(), "bounded".into()]),
                Some(MycConnectionPermission::Nip44Encrypt),
                MycNip46WorkKind::Provider,
                Some(MycProviderCapability::Nip44Encrypt),
            ),
            (
                protocol_request(
                    Method::Nip44Decrypt,
                    vec![
                        peer,
                        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    ],
                ),
                Some(MycConnectionPermission::Nip44Decrypt),
                MycNip46WorkKind::Provider,
                Some(MycProviderCapability::Nip44Decrypt),
            ),
        ];
        for (index, (request, permission, expected_kind, expected_capability)) in
            cases.into_iter().enumerate()
        {
            let prepared = prepared_request(request, u8::try_from(index + 1).expect("seed"));
            let record = prepared.signer_request.admitted_record_for_test();
            let permissions = permission.into_iter().collect::<Vec<_>>();
            let connection =
                active_connection(&prepared, &permissions, Some(RECEIVED_AT_MS + 100_000));
            let provider_deadline = (expected_kind == MycNip46WorkKind::Provider)
                .then(|| MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline"));
            let work = prepare_myc_nip46_work(
                prepared,
                record,
                Some(connection),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                provider_deadline,
            )
            .expect("governed work");
            assert_eq!(work.kind(), expected_kind);
            assert_eq!(
                work.provider_operation()
                    .map(|operation| operation.input().capability()),
                expected_capability
            );
            if let Some(operation) = work.provider_operation() {
                assert_eq!(operation.role(), MycProviderRole::User);
                assert_eq!(
                    operation.operation_id().as_bytes(),
                    work.request_record().operation_id().as_bytes()
                );
            }
        }
    }

    #[test]
    fn connect_and_nonconnect_authorization_fail_closed() {
        let connect = protocol_request(
            Method::Connect,
            vec![
                keys(3).public_key().to_hex(),
                String::new(),
                "nip44_encrypt,sign_event:kind:1".into(),
            ],
        );
        let prepared = prepared_request(connect, 20);
        let record = prepared.signer_request.admitted_record_for_test();
        let work = prepare_myc_nip46_work(
            prepared,
            record,
            None,
            configuration().provider_contract(),
            MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
            None,
        )
        .expect("connect work");
        assert_eq!(work.kind(), MycNip46WorkKind::Connect);
        work.connection_admission_request(
            MycConnectionPolicyGeneration::new(1).expect("generation"),
            MycConnectionNonce::from_injected_entropy([0x44; 32]),
            MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
            MycRateRelayId::new("primary").expect("relay"),
        )
        .expect("admission request");

        let secret_connect = protocol_request(
            Method::Connect,
            vec![keys(3).public_key().to_hex(), "forbidden-secret".into()],
        );
        let prepared = prepared_request(secret_connect, 21);
        let record = prepared.signer_request.admitted_record_for_test();
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                record,
                None,
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                None,
            )
            .expect_err("connect secret"),
            work_error(MycNip46WorkErrorKind::InvalidBinding)
        );

        let prepared = prepared_request(
            protocol_request(
                Method::Nip44Encrypt,
                vec![keys(4).public_key().to_hex(), "protected-marker".into()],
            ),
            22,
        );
        let record = prepared.signer_request.admitted_record_for_test();
        let denied = active_connection(&prepared, &[], Some(RECEIVED_AT_MS + 100_000));
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                record,
                Some(denied),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                Some(MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline")),
            )
            .expect_err("missing permission"),
            work_error(MycNip46WorkErrorKind::PermissionDenied)
        );

        let prepared = prepared_request(Request::Ping, 24);
        let record = prepared.signer_request.admitted_record_for_test();
        let expired = active_connection(&prepared, &[], Some(RECEIVED_AT_MS + 500));
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                record,
                Some(expired),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                None,
            )
            .expect_err("expired connection"),
            work_error(MycNip46WorkErrorKind::ConnectionExpired)
        );

        let prepared = prepared_request(
            protocol_request(
                Method::Nip04Encrypt,
                vec![keys(4).public_key().to_hex(), "bounded".into()],
            ),
            25,
        );
        let record = prepared.signer_request.admitted_record_for_test();
        let connection = active_connection(
            &prepared,
            &[MycConnectionPermission::Nip04Encrypt],
            Some(RECEIVED_AT_MS + 100_000),
        );
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                record,
                Some(connection),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(PROVIDER_DEADLINE_MS).expect("observation"),
                Some(MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline")),
            )
            .expect_err("nonfuture provider deadline"),
            work_error(MycNip46WorkErrorKind::ProviderWorkRejected)
        );

        let prepared = prepared_request(Request::SignEvent(unsigned_sign_event_for(4)), 28);
        let record = prepared.signer_request.admitted_record_for_test();
        let connection = active_connection(
            &prepared,
            &[MycConnectionPermission::SignEvent(1)],
            Some(RECEIVED_AT_MS + 100_000),
        );
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                record,
                Some(connection),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                Some(MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("deadline")),
            )
            .expect_err("wrong signing author"),
            work_error(MycNip46WorkErrorKind::ProviderWorkRejected)
        );

        let prepared = prepared_request(Request::Ping, 26);
        let mismatched = prepared_request(Request::Ping, 27)
            .signer_request
            .admitted_record_for_test();
        let connection = active_connection(&prepared, &[], Some(RECEIVED_AT_MS + 100_000));
        assert_eq!(
            prepare_myc_nip46_work(
                prepared,
                mismatched,
                Some(connection),
                configuration().provider_contract(),
                MycConnectionTimeUnixMs::new(RECEIVED_AT_MS + 1_000).expect("observation"),
                None,
            )
            .expect_err("mismatched durable request"),
            work_error(MycNip46WorkErrorKind::InvalidBinding)
        );

        let custom = Request::Custom {
            method: Method::custom("vendor_method").expect("custom method"),
            params: vec!["protected-marker".to_owned()],
        };
        assert_eq!(
            prepare_myc_nip46_request(
                decrypted(&custom, true, OBSERVED_AT_SECONDS + 23),
                MycSignerOperationNonce::from_injected_entropy([23; 32]),
                MycRequestReceivedAtUnixMs::new(RECEIVED_AT_MS).expect("received"),
            )
            .expect_err("custom method"),
            work_error(MycNip46WorkErrorKind::UnsupportedMethod)
        );
    }

    #[test]
    fn errors_and_work_debug_are_source_free_and_redacted() {
        for kind in [
            MycNip46WorkErrorKind::InvalidBinding,
            MycNip46WorkErrorKind::DecryptionRejected,
            MycNip46WorkErrorKind::UnsupportedMethod,
            MycNip46WorkErrorKind::PermissionDenied,
            MycNip46WorkErrorKind::ConnectionExpired,
            MycNip46WorkErrorKind::ProviderWorkRejected,
        ] {
            let error = work_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.code().is_empty());
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }

        let prepared = prepared_request(Request::Ping, 30);
        assert!(!format!("{prepared:?}").contains("request-"));
        assert!(!format!("{prepared:?}").contains("protected-marker"));
        assert!(MycProviderResponseObservedAtUnixMs::new(PROVIDER_DEADLINE_MS).is_ok());
    }
}
