//! Sealed execution over the two governed signer-provider implementations.

#![allow(
    dead_code,
    reason = "Step 159 Unit 12 seals the executor before Unit 15 runtime graph wiring"
)]

use core::fmt;
use std::{error::Error, sync::Arc};

use nostr::{
    JsonUtil as _, Keys, PublicKey, SecretKey, UnsignedEvent,
    nips::{nip04, nip44},
};

use crate::provider_local_signer::{ProtectedWireHex, WireCapability, WireProviderResult};
use crate::provider_verification::verify_encrypted_provider_response;
use crate::{
    MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION, MYC_PROVIDER_INPUT_MAX_BYTES, MycConfigDocumentV1,
    MycDecryptedIdentity, MycLocalSignerClient, MycProviderBinding, MycProviderCapability,
    MycProviderKind, MycProviderOperation, MycProviderResponseObservedAtUnixMs, MycProviderRole,
    MycRuntimeContext, MycTaskCancellation, MycVerifiedProviderResponse,
    open_myc_encrypted_identity, resolve_myc_wrapping_credential,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycProviderExecutionErrorKind {
    Binding,
    Open,
    Operation,
    Cancelled,
    Transport,
    Verification,
    UnsupportedPlatform,
}

pub(crate) struct MycProviderExecutionError {
    kind: MycProviderExecutionErrorKind,
}

impl MycProviderExecutionError {
    pub(crate) const fn kind(&self) -> MycProviderExecutionErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycProviderExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderExecutionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycProviderExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc provider execution failed")
    }
}

impl Error for MycProviderExecutionError {}

const fn execution_error(kind: MycProviderExecutionErrorKind) -> MycProviderExecutionError {
    MycProviderExecutionError { kind }
}

enum ExecutableProvider {
    EncryptedFile {
        binding: MycProviderBinding,
        identity: Arc<MycDecryptedIdentity>,
    },
    LocalSigner {
        binding: MycProviderBinding,
        client: Box<MycLocalSignerClient>,
    },
}

impl ExecutableProvider {
    const fn role(&self) -> MycProviderRole {
        match self {
            Self::EncryptedFile { binding, .. } | Self::LocalSigner { binding, .. } => {
                binding.role()
            }
        }
    }
}

pub(crate) struct MycProviderExecutor {
    providers: Box<[ExecutableProvider]>,
}

impl MycProviderExecutor {
    pub(crate) async fn open(
        runtime: &MycRuntimeContext,
        configuration: &MycConfigDocumentV1,
        cancellation: &MycTaskCancellation,
    ) -> Result<Self, MycProviderExecutionError> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (runtime, configuration, cancellation);
            return Err(execution_error(
                MycProviderExecutionErrorKind::UnsupportedPlatform,
            ));
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut providers =
                Vec::with_capacity(configuration.provider_contract().bindings().len());
            for binding in configuration.provider_contract().bindings() {
                if cancellation.is_cancelled() {
                    return Err(execution_error(MycProviderExecutionErrorKind::Cancelled));
                }
                match binding.kind() {
                    MycProviderKind::EncryptedFile => {
                        let runtime = runtime.clone();
                        let binding = binding.clone();
                        let worker_binding = binding.clone();
                        let mut worker = tokio::task::spawn_blocking(move || {
                            let credential =
                                resolve_myc_wrapping_credential(&runtime, &worker_binding)
                                    .map_err(|_| ())?;
                            open_myc_encrypted_identity(&worker_binding, &credential)
                                .map_err(|_| ())
                        });
                        let identity = tokio::select! {
                            result = &mut worker => result
                                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Open))?
                                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Open))?,
                            () = cancellation.cancelled() => {
                                let _ = worker.await;
                                return Err(execution_error(MycProviderExecutionErrorKind::Cancelled));
                            }
                        };
                        providers.push(ExecutableProvider::EncryptedFile {
                            binding,
                            identity: Arc::new(identity),
                        });
                    }
                    MycProviderKind::LocalSigner => {
                        let client = MycLocalSignerClient::new(binding)
                            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Open))?;
                        providers.push(ExecutableProvider::LocalSigner {
                            binding: binding.clone(),
                            client: Box::new(client),
                        });
                    }
                }
            }
            if providers.len() != configuration.provider_contract().bindings().len() {
                return Err(execution_error(MycProviderExecutionErrorKind::Binding));
            }
            Ok(Self {
                providers: providers.into_boxed_slice(),
            })
        }
    }

    pub(crate) async fn execute(
        &self,
        operation: MycProviderOperation,
        observed_at: MycProviderResponseObservedAtUnixMs,
        cancellation: &MycTaskCancellation,
    ) -> Result<MycVerifiedProviderResponse, MycProviderExecutionError> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.role() == operation.role())
            .ok_or_else(|| execution_error(MycProviderExecutionErrorKind::Binding))?;
        if cancellation.is_cancelled() {
            return Err(execution_error(MycProviderExecutionErrorKind::Cancelled));
        }
        match provider {
            ExecutableProvider::EncryptedFile { binding, identity } => {
                let binding = binding.clone();
                let identity = Arc::clone(identity);
                let mut worker = tokio::task::spawn_blocking(move || {
                    let result = execute_encrypted(&identity, &operation)?;
                    Ok::<_, MycProviderExecutionError>((operation, result))
                });
                tokio::select! {
                    joined = &mut worker => {
                        let (operation, result) = joined
                            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))??;
                        verify_encrypted_provider_response(&binding, &operation, observed_at, result)
                            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Verification))
                    }
                    () = cancellation.cancelled() => {
                        // A blocking cryptographic call cannot be abandoned. Join it before
                        // returning cancellation so no protected operation is detached.
                        // The result is deliberately discarded and never becomes domain authority.
                        let _ = worker.await;
                        Err(execution_error(MycProviderExecutionErrorKind::Cancelled))
                    }
                }
            }
            ExecutableProvider::LocalSigner { binding, client } => {
                tokio::select! {
                    result = client.execute(&operation) => {
                        let response = result.map_err(|_| execution_error(MycProviderExecutionErrorKind::Transport))?;
                        response
                            .verify(binding, &operation, observed_at)
                            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Verification))
                    }
                    () = cancellation.cancelled() => {
                        Err(execution_error(MycProviderExecutionErrorKind::Cancelled))
                    }
                }
            }
        }
    }

    pub(crate) fn contains_role(&self, role: MycProviderRole) -> bool {
        self.providers
            .iter()
            .any(|provider| provider.role() == role)
    }
}

impl fmt::Debug for MycProviderExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderExecutor")
            .field("provider_count", &self.providers.len())
            .finish()
    }
}

fn execute_encrypted(
    identity: &MycDecryptedIdentity,
    operation: &MycProviderOperation,
) -> Result<WireProviderResult, MycProviderExecutionError> {
    if operation.provider() != MycProviderKind::EncryptedFile
        || operation.expected_identity() != identity.public_identity()
    {
        return Err(execution_error(MycProviderExecutionErrorKind::Binding));
    }
    let secret = SecretKey::from_slice(identity.secret_bytes())
        .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
    let keys = Keys::new(secret);
    let input = operation.input();
    let peer = || {
        input
            .peer()
            .ok_or_else(|| execution_error(MycProviderExecutionErrorKind::Binding))
            .and_then(|identity| {
                PublicKey::from_hex(identity.as_hex())
                    .map_err(|_| execution_error(MycProviderExecutionErrorKind::Binding))
            })
    };
    let bytes = || {
        input
            .bytes()
            .ok_or_else(|| execution_error(MycProviderExecutionErrorKind::Binding))
    };
    match input.capability() {
        MycProviderCapability::Describe => Ok(WireProviderResult::Describe {
            public_identity: identity.public_identity().as_hex().to_owned(),
            protocol_version: MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION,
            capabilities: MycProviderCapability::ALL
                .into_iter()
                .filter(|capability| capability_allowed_for_role(operation.role(), *capability))
                .map(WireCapability::from)
                .collect(),
            maximum_request_bytes: MYC_PROVIDER_INPUT_MAX_BYTES as u64,
        }),
        MycProviderCapability::PublicIdentity => Ok(WireProviderResult::PublicIdentity {
            public_identity: identity.public_identity().as_hex().to_owned(),
        }),
        MycProviderCapability::SignEvent => {
            let unsigned: UnsignedEvent = serde_json::from_slice(bytes()?)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            let signed = unsigned
                .sign_with_keys(&keys)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            Ok(WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(signed.as_json().as_bytes()),
            })
        }
        MycProviderCapability::Nip04Encrypt => {
            let peer = peer()?;
            let payload = nip04::encrypt(keys.secret_key(), &peer, bytes()?)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            Ok(WireProviderResult::Nip04Encrypt {
                peer: peer.to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(payload.as_bytes()),
            })
        }
        MycProviderCapability::Nip04Decrypt => {
            let peer = peer()?;
            let payload = core::str::from_utf8(bytes()?)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            let plaintext = nip04::decrypt(keys.secret_key(), &peer, payload)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            Ok(WireProviderResult::Nip04Decrypt {
                peer: peer.to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(plaintext.as_bytes()),
            })
        }
        MycProviderCapability::Nip44Encrypt => {
            let peer = peer()?;
            let payload = nip44::encrypt(keys.secret_key(), &peer, bytes()?, nip44::Version::V2)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            Ok(WireProviderResult::Nip44Encrypt {
                peer: peer.to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(payload.as_bytes()),
            })
        }
        MycProviderCapability::Nip44Decrypt => {
            let peer = peer()?;
            let payload = core::str::from_utf8(bytes()?)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            let plaintext = nip44::decrypt(keys.secret_key(), &peer, payload)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Operation))?;
            Ok(WireProviderResult::Nip44Decrypt {
                peer: peer.to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(plaintext.as_bytes()),
            })
        }
    }
}

const fn capability_allowed_for_role(
    role: MycProviderRole,
    capability: MycProviderCapability,
) -> bool {
    match role {
        MycProviderRole::Transport => !matches!(capability, MycProviderCapability::SignEvent),
        MycProviderRole::User => true,
        MycProviderRole::Discovery => matches!(
            capability,
            MycProviderCapability::Describe
                | MycProviderCapability::PublicIdentity
                | MycProviderCapability::SignEvent
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use nostr::{JsonUtil as _, Kind, Tag, Timestamp};

    use super::*;
    use crate::{
        MycConfigProfile, MycProviderCorrelationId, MycProviderDeadlineUnixMs,
        MycProviderNip44Version, MycProviderOperationId, MycProviderOperationInput,
        parse_myc_config_v1,
    };

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn keys(seed: u8) -> Keys {
        Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
    }

    fn secret(seed: u8) -> [u8; 32] {
        let mut secret = [0_u8; 32];
        secret[0] = seed;
        secret
    }

    fn configuration() -> MycConfigDocumentV1 {
        let source = CONFIG
            .replacen(
                "4444444444444444444444444444444444444444444444444444444444444444",
                &keys(2).public_key().to_hex(),
                1,
            )
            .replacen(
                "3333333333333333333333333333333333333333333333333333333333333333",
                &keys(4).public_key().to_hex(),
                1,
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal).expect("configuration")
    }

    fn operation(
        binding: &MycProviderBinding,
        seed: u8,
        input: MycProviderOperationInput,
    ) -> MycProviderOperation {
        MycProviderOperation::new(
            binding,
            MycProviderOperationId::from_bytes([seed; 32]),
            MycProviderCorrelationId::from_bytes([seed.wrapping_add(1); 32]),
            MycProviderDeadlineUnixMs::new(2_000_000_000_000).expect("deadline"),
            input,
        )
        .expect("operation")
    }

    #[test]
    fn encrypted_executor_produces_independently_verified_results() {
        let configuration = configuration();
        let binding = configuration
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding");
        let identity = MycDecryptedIdentity::from_test_secret(secret(2));
        let peer = MycDecryptedIdentity::from_test_secret(secret(5));
        let observed =
            MycProviderResponseObservedAtUnixMs::new(1_999_999_999_999).expect("observed time");

        for (seed, input) in [
            (1, MycProviderOperationInput::describe()),
            (2, MycProviderOperationInput::public_identity()),
            (
                3,
                MycProviderOperationInput::nip04_encrypt(
                    peer.public_identity().clone(),
                    b"nip04 protected",
                )
                .expect("NIP-04 input"),
            ),
            (
                4,
                MycProviderOperationInput::nip44_encrypt(
                    peer.public_identity().clone(),
                    MycProviderNip44Version::V2,
                    b"nip44 protected",
                )
                .expect("NIP-44 input"),
            ),
        ] {
            let operation = operation(binding, seed, input);
            let result = execute_encrypted(&identity, &operation).expect("encrypted result");
            let verified =
                verify_encrypted_provider_response(binding, &operation, observed, result)
                    .expect("independent verification");
            assert!(verified.matches_operation(&operation));
        }

        let discovery = configuration
            .provider_contract()
            .binding(MycProviderRole::Discovery)
            .expect("discovery binding");
        let discovery_identity = MycDecryptedIdentity::from_test_secret(secret(4));
        let unsigned = nostr::UnsignedEvent::new(
            discovery_identity
                .public_identity()
                .as_hex()
                .parse()
                .expect("public key"),
            Timestamp::from_secs(1_725_000_000),
            Kind::Custom(31_990),
            Vec::<Tag>::new(),
            "{}",
        );
        let operation = operation(
            discovery,
            5,
            MycProviderOperationInput::sign_event(unsigned.as_json().as_bytes())
                .expect("sign input"),
        );
        let result = execute_encrypted(&discovery_identity, &operation).expect("signature");
        let verified = verify_encrypted_provider_response(discovery, &operation, observed, result)
            .expect("verified signature");
        assert!(verified.matches_operation(&operation));
    }

    #[test]
    fn capability_matrix_and_diagnostics_are_closed() {
        for capability in MycProviderCapability::ALL {
            assert_eq!(
                capability_allowed_for_role(MycProviderRole::Transport, capability),
                !matches!(capability, MycProviderCapability::SignEvent)
            );
            assert!(capability_allowed_for_role(
                MycProviderRole::User,
                capability
            ));
            assert_eq!(
                capability_allowed_for_role(MycProviderRole::Discovery, capability),
                matches!(
                    capability,
                    MycProviderCapability::Describe
                        | MycProviderCapability::PublicIdentity
                        | MycProviderCapability::SignEvent
                )
            );
        }
        for kind in [
            MycProviderExecutionErrorKind::Binding,
            MycProviderExecutionErrorKind::Open,
            MycProviderExecutionErrorKind::Operation,
            MycProviderExecutionErrorKind::Cancelled,
            MycProviderExecutionErrorKind::Transport,
            MycProviderExecutionErrorKind::Verification,
            MycProviderExecutionErrorKind::UnsupportedPlatform,
        ] {
            let error = execution_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.source().is_none());
            assert!(!format!("{error} {error:?}").contains("protected"));
        }
    }
}
