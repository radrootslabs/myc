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
use sha2::{Digest as _, Sha256};

use crate::provider_local_signer::{ProtectedWireHex, WireCapability, WireProviderResult};
use crate::provider_verification::verify_encrypted_provider_response;
use crate::{
    MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION, MYC_PROVIDER_INPUT_MAX_BYTES, MycConfigDocumentV1,
    MycDecryptedIdentity, MycLocalSignerClient, MycProviderBinding, MycProviderCapability,
    MycProviderCorrelationId, MycProviderDeadlineUnixMs, MycProviderKind, MycProviderOperation,
    MycProviderOperationId, MycProviderOperationInput, MycProviderResponseObservedAtUnixMs,
    MycProviderRole, MycRuntimeContext, MycTaskCancellation, MycVerifiedProviderResponse,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{open_myc_encrypted_identity, resolve_myc_wrapping_credential};

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

struct OwnedBlockingTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T: Send + 'static> OwnedBlockingTask<T> {
    fn spawn(task: impl FnOnce() -> T + Send + 'static) -> Self {
        Self {
            handle: Some(tokio::task::spawn_blocking(task)),
        }
    }

    async fn join(
        &mut self,
        failure: MycProviderExecutionErrorKind,
    ) -> Result<T, MycProviderExecutionError> {
        let result = match self.handle.as_mut() {
            Some(handle) => handle.await,
            None => return Err(execution_error(failure)),
        };
        self.handle.take();
        result.map_err(|_| execution_error(failure))
    }
}

impl<T> Drop for OwnedBlockingTask<T> {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        handle.abort();
        while !handle.is_finished() {
            std::thread::park_timeout(core::time::Duration::from_millis(1));
        }
    }
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
                        let mut worker = OwnedBlockingTask::spawn(move || {
                            let credential =
                                resolve_myc_wrapping_credential(&runtime, &worker_binding)
                                    .map_err(|_| ())?;
                            open_myc_encrypted_identity(&worker_binding, &credential)
                                .map_err(|_| ())
                        });
                        let identity = tokio::select! {
                            result = worker.join(MycProviderExecutionErrorKind::Open) => result?
                                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Open))?,
                            () = cancellation.cancelled() => {
                                let _ = worker.join(MycProviderExecutionErrorKind::Open).await;
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
                let mut worker = OwnedBlockingTask::spawn(move || {
                    let result = execute_encrypted(&identity, &operation)?;
                    Ok::<_, MycProviderExecutionError>((operation, result))
                });
                tokio::select! {
                    joined = worker.join(MycProviderExecutionErrorKind::Operation) => {
                        let (operation, result) = joined??;
                        verify_encrypted_provider_response(&binding, &operation, observed_at, result)
                            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Verification))
                    }
                    () = cancellation.cancelled() => {
                        // A blocking cryptographic call cannot be abandoned. Join it before
                        // returning cancellation so no protected operation is detached.
                        // The result is deliberately discarded and never becomes domain authority.
                        let _ = worker.join(MycProviderExecutionErrorKind::Operation).await;
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

    pub(crate) async fn probe_all(
        &self,
        observed_at_unix_ms: u64,
        seed: [u8; 32],
        cancellation: &MycTaskCancellation,
    ) -> Result<(), MycProviderExecutionError> {
        let observed_at = MycProviderResponseObservedAtUnixMs::new(observed_at_unix_ms)
            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Binding))?;
        for (index, provider) in self.providers.iter().enumerate() {
            let role = provider.role();
            let binding = match provider {
                ExecutableProvider::EncryptedFile { binding, .. }
                | ExecutableProvider::LocalSigner { binding, .. } => binding,
            };
            let timeout = binding
                .local_signer_limits()
                .map_or(15_000, |limits| limits.request_deadline_ms());
            let deadline = observed_at_unix_ms
                .checked_add(timeout)
                .and_then(|value| MycProviderDeadlineUnixMs::new(value).ok())
                .ok_or_else(|| execution_error(MycProviderExecutionErrorKind::Binding))?;
            let index = u32::try_from(index)
                .map_err(|_| execution_error(MycProviderExecutionErrorKind::Binding))?;
            let operation = MycProviderOperation::new(
                binding,
                MycProviderOperationId::from_bytes(probe_identifier(
                    b"operation",
                    &seed,
                    index,
                    role,
                )),
                MycProviderCorrelationId::from_bytes(probe_identifier(
                    b"correlation",
                    &seed,
                    index,
                    role,
                )),
                deadline,
                MycProviderOperationInput::describe(),
            )
            .map_err(|_| execution_error(MycProviderExecutionErrorKind::Binding))?;
            let response = self.execute(operation, observed_at, cancellation).await?;
            if response.role() != role || response.capability() != MycProviderCapability::Describe {
                return Err(execution_error(MycProviderExecutionErrorKind::Verification));
            }
        }
        Ok(())
    }
}

fn probe_identifier(kind: &[u8], seed: &[u8; 32], index: u32, role: MycProviderRole) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"radroots.myc.provider_probe.v1\0");
    hasher.update(u64::try_from(kind.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(kind);
    hasher.update(seed);
    hasher.update(index.to_be_bytes());
    hasher.update(role.as_str().as_bytes());
    hasher.finalize().into()
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

    #[test]
    fn provider_probe_identifiers_are_domain_seed_index_and_role_bound() {
        let seed = [7_u8; 32];
        let operation = probe_identifier(b"operation", &seed, 0, MycProviderRole::Transport);
        assert_eq!(
            operation,
            probe_identifier(b"operation", &seed, 0, MycProviderRole::Transport)
        );
        assert_ne!(
            operation,
            probe_identifier(b"correlation", &seed, 0, MycProviderRole::Transport)
        );
        assert_ne!(
            operation,
            probe_identifier(b"operation", &[8_u8; 32], 0, MycProviderRole::Transport)
        );
        assert_ne!(
            operation,
            probe_identifier(b"operation", &seed, 1, MycProviderRole::Transport)
        );
        assert_ne!(
            operation,
            probe_identifier(b"operation", &seed, 0, MycProviderRole::User)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_blocking_provider_work_drains_it_before_returning() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = Arc::clone(&completed);
        let task = OwnedBlockingTask::spawn(move || {
            entered_tx.send(()).expect("entered signal");
            release_rx.recv().expect("release signal");
            worker_completed.store(true, Ordering::SeqCst);
        });
        entered_rx.recv().expect("worker entered");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(25));
            release_tx.send(()).expect("release worker");
        });

        drop(task);

        releaser.join().expect("releaser joined");
        assert!(completed.load(Ordering::SeqCst));
    }
}
