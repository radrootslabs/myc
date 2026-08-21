//! Strict bounded local-signer transport over the hardened Lib admin client.

use core::fmt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use core::time::Duration;
use std::error::Error;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroizing;

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
use crate::MycProviderNip44Version;
use crate::{
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MycProviderBinding, MycProviderCapability,
    MycProviderInstanceId, MycProviderOperation, MycProviderRole,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{MycProviderKind, MycProviderNip44Version, MycProviderPublicIdentity};

/// Exact local-signer wire contract version.
pub const MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION: u32 = 1;
/// The one fixed local-signer provider endpoint.
pub const MYC_LOCAL_SIGNER_ENDPOINT: &str = "/v1/provider/operation";

const PROTECTED_WIRE_HEX_MAX_UTF8_BYTES: usize = MYC_PROVIDER_OUTPUT_MAX_BYTES * 2;

/// Stable source-free local-signer transport failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycLocalSignerTransportErrorKind {
    InvalidBinding,
    InvalidOperation,
    InvalidLimits,
    RequestEncoding,
    RequestLimit,
    Transport,
    Deadline,
    Response,
    RemoteFailure,
    UnsupportedPlatform,
}

impl MycLocalSignerTransportErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "local_signer_binding_invalid",
            Self::InvalidOperation => "local_signer_operation_invalid",
            Self::InvalidLimits => "local_signer_limits_invalid",
            Self::RequestEncoding => "local_signer_request_encoding_failed",
            Self::RequestLimit => "local_signer_request_limit_exceeded",
            Self::Transport => "local_signer_transport_failed",
            Self::Deadline => "local_signer_deadline_exceeded",
            Self::Response => "local_signer_response_invalid",
            Self::RemoteFailure => "local_signer_remote_failed",
            Self::UnsupportedPlatform => "local_signer_platform_unsupported",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "local signer binding is invalid",
            Self::InvalidOperation => "local signer operation is invalid",
            Self::InvalidLimits => "local signer limits are invalid",
            Self::RequestEncoding => "local signer request encoding failed",
            Self::RequestLimit => "local signer request exceeds its bound",
            Self::Transport => "local signer transport failed",
            Self::Deadline => "local signer deadline elapsed",
            Self::Response => "local signer response is invalid",
            Self::RemoteFailure => "local signer returned a failure",
            Self::UnsupportedPlatform => "local signer transport is unsupported",
        }
    }
}

/// One source-free local-signer transport failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycLocalSignerTransportError {
    kind: MycLocalSignerTransportErrorKind,
}

impl MycLocalSignerTransportError {
    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> MycLocalSignerTransportErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycLocalSignerTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycLocalSignerTransportError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycLocalSignerTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycLocalSignerTransportError {}

const fn transport_error(kind: MycLocalSignerTransportErrorKind) -> MycLocalSignerTransportError {
    MycLocalSignerTransportError { kind }
}

/// A strictly decoded but semantically untrusted local-signer success.
///
/// Step 135 independently verifies every binding and operation result before
/// any caller may treat this value as usable. Cancellation or timeout does not
/// prove that the external signer performed no operation, and this value never
/// represents publication.
pub struct MycLocalSignerUntrustedResponse {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    outer_correlation_id: radroots_service_host::AdminCorrelationId,
    response: LocalSignerResponse,
}

impl fmt::Debug for MycLocalSignerUntrustedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycLocalSignerUntrustedResponse")
            .field("correlation_id", &{
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if self.outer_correlation_id.as_str().is_empty() {
                        "[invalid]"
                    } else {
                        "[redacted]"
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    "[redacted]"
                }
            })
            .field("provider_instance", &self.response.provider_instance)
            .field("role", &self.response.role)
            .field("capability", &self.response.capability)
            .field("result", &"[redacted]")
            .finish()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Bounded client for one configured local-signer Unix socket.
pub struct MycLocalSignerClient {
    transport: radroots_service_host::AdminClient,
    target: radroots_service_host::AdminClientTarget,
    permits: tokio::sync::Semaphore,
    request_deadline: Duration,
    role: MycProviderRole,
    instance: MycProviderInstanceId,
    expected_identity: MycProviderPublicIdentity,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
/// Unsupported-target local-signer client placeholder.
pub struct MycLocalSignerClient {
    _private: (),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl MycLocalSignerClient {
    /// Constructs a client from one validated local-signer provider binding.
    pub fn new(binding: &MycProviderBinding) -> Result<Self, MycLocalSignerTransportError> {
        use radroots_service_host::{AdminClient, AdminClientTarget, AdminTransportLimits};

        if binding.kind() != MycProviderKind::LocalSigner {
            return Err(transport_error(
                MycLocalSignerTransportErrorKind::InvalidBinding,
            ));
        }
        let socket_path = binding
            .local_signer_socket_path()
            .ok_or_else(|| transport_error(MycLocalSignerTransportErrorKind::InvalidBinding))?;
        let limits = binding
            .local_signer_limits()
            .ok_or_else(|| transport_error(MycLocalSignerTransportErrorKind::InvalidBinding))?;
        let request_deadline = Duration::from_millis(limits.request_deadline_ms());
        let mut transport_values = AdminTransportLimits::DEFAULT.values();
        transport_values.request_body_utf8_bytes = u32::try_from(limits.request_max_bytes())
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidLimits))?;
        transport_values.response_body_utf8_bytes = u32::try_from(limits.response_max_bytes())
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidLimits))?;
        transport_values.concurrent_connections = limits.concurrency();
        transport_values.request_deadline = request_deadline;
        let transport_limits = AdminTransportLimits::new(transport_values)
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidLimits))?;
        let transport = AdminClient::new(socket_path, transport_limits)
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidBinding))?;
        let target = AdminClientTarget::new(MYC_LOCAL_SIGNER_ENDPOINT)
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidBinding))?;
        Ok(Self {
            transport,
            target,
            permits: tokio::sync::Semaphore::new(limits.concurrency() as usize),
            request_deadline,
            role: binding.role(),
            instance: binding.instance(),
            expected_identity: binding.expected_identity().clone(),
        })
    }

    /// Executes one already-bound operation and returns only untrusted output.
    pub async fn execute(
        &self,
        operation: &MycProviderOperation,
    ) -> Result<MycLocalSignerUntrustedResponse, MycLocalSignerTransportError> {
        use radroots_service_host::{AdminCorrelationId, AdminOperationId};

        self.validate_operation(operation)?;
        let request = LocalSignerRequest::from_operation(operation)?;
        let operation_id = AdminOperationId::new(hex::encode(operation.operation_id().as_bytes()))
            .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidOperation))?;
        let correlation_id =
            AdminCorrelationId::new(hex::encode(operation.correlation_id().as_bytes()))
                .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::InvalidOperation))?;
        let response = tokio::time::timeout(self.request_deadline, async {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::Transport))?;
            self.transport
                .mutate::<_, LocalSignerResponse>(
                    &self.target,
                    operation_id,
                    Some(correlation_id.clone()),
                    request,
                )
                .await
                .map_err(map_admin_error)
        })
        .await
        .map_err(|_| transport_error(MycLocalSignerTransportErrorKind::Deadline))??;
        Ok(MycLocalSignerUntrustedResponse {
            outer_correlation_id: response.correlation_id().clone(),
            response: response.into_result(),
        })
    }

    fn validate_operation(
        &self,
        operation: &MycProviderOperation,
    ) -> Result<(), MycLocalSignerTransportError> {
        if operation.provider() != MycProviderKind::LocalSigner
            || operation.role() != self.role
            || operation.instance() != self.instance
            || operation.expected_identity() != &self.expected_identity
        {
            return Err(transport_error(
                MycLocalSignerTransportErrorKind::InvalidOperation,
            ));
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl MycLocalSignerClient {
    /// Fails closed before any transport work on unsupported targets.
    pub fn new(_binding: &MycProviderBinding) -> Result<Self, MycLocalSignerTransportError> {
        Err(transport_error(
            MycLocalSignerTransportErrorKind::UnsupportedPlatform,
        ))
    }

    /// Fails closed before any transport work on unsupported targets.
    pub async fn execute(
        &self,
        _operation: &MycProviderOperation,
    ) -> Result<MycLocalSignerUntrustedResponse, MycLocalSignerTransportError> {
        Err(transport_error(
            MycLocalSignerTransportErrorKind::UnsupportedPlatform,
        ))
    }
}

impl fmt::Debug for MycLocalSignerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycLocalSignerClient")
            .field("socket_path", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_admin_error(error: radroots_service_host::AdminClientError) -> MycLocalSignerTransportError {
    use radroots_service_host::AdminClientErrorKind;

    let kind = match error.kind() {
        AdminClientErrorKind::SocketPath => MycLocalSignerTransportErrorKind::InvalidBinding,
        AdminClientErrorKind::RequestEncoding => MycLocalSignerTransportErrorKind::RequestEncoding,
        AdminClientErrorKind::RequestLimit => MycLocalSignerTransportErrorKind::RequestLimit,
        AdminClientErrorKind::Deadline => MycLocalSignerTransportErrorKind::Deadline,
        AdminClientErrorKind::Connect | AdminClientErrorKind::Transport => {
            MycLocalSignerTransportErrorKind::Transport
        }
        AdminClientErrorKind::QueryLimit
        | AdminClientErrorKind::ResponseHeaders
        | AdminClientErrorKind::ResponseLimit
        | AdminClientErrorKind::ResponseContentType
        | AdminClientErrorKind::ResponseHttpVersion
        | AdminClientErrorKind::MalformedResponse
        | AdminClientErrorKind::UnsupportedContractVersion => {
            MycLocalSignerTransportErrorKind::Response
        }
        AdminClientErrorKind::ServerFailure => MycLocalSignerTransportErrorKind::RemoteFailure,
    };
    transport_error(kind)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireRole {
    Transport,
    User,
    Discovery,
}

impl From<MycProviderRole> for WireRole {
    fn from(role: MycProviderRole) -> Self {
        match role {
            MycProviderRole::Transport => Self::Transport,
            MycProviderRole::User => Self::User,
            MycProviderRole::Discovery => Self::Discovery,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireProviderInstance {
    Transport,
    User,
    Discovery,
}

impl From<MycProviderInstanceId> for WireProviderInstance {
    fn from(instance: MycProviderInstanceId) -> Self {
        match instance {
            MycProviderInstanceId::Transport => Self::Transport,
            MycProviderInstanceId::User => Self::User,
            MycProviderInstanceId::Discovery => Self::Discovery,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireCapability {
    Describe,
    PublicIdentity,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
}

impl From<MycProviderCapability> for WireCapability {
    fn from(capability: MycProviderCapability) -> Self {
        match capability {
            MycProviderCapability::Describe => Self::Describe,
            MycProviderCapability::PublicIdentity => Self::PublicIdentity,
            MycProviderCapability::SignEvent => Self::SignEvent,
            MycProviderCapability::Nip04Encrypt => Self::Nip04Encrypt,
            MycProviderCapability::Nip04Decrypt => Self::Nip04Decrypt,
            MycProviderCapability::Nip44Encrypt => Self::Nip44Encrypt,
            MycProviderCapability::Nip44Decrypt => Self::Nip44Decrypt,
        }
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSignerRequest {
    contract_version: u32,
    provider_instance: WireProviderInstance,
    role: WireRole,
    operation_id: String,
    correlation_id: String,
    absolute_deadline_unix_ms: u64,
    expected_identity: String,
    capability: WireCapability,
    input: WireProviderInput,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
impl LocalSignerRequest {
    fn from_operation(
        operation: &MycProviderOperation,
    ) -> Result<Self, MycLocalSignerTransportError> {
        Ok(Self {
            contract_version: MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION,
            provider_instance: operation.instance().into(),
            role: operation.role().into(),
            operation_id: hex::encode(operation.operation_id().as_bytes()),
            correlation_id: hex::encode(operation.correlation_id().as_bytes()),
            absolute_deadline_unix_ms: operation.deadline().get(),
            expected_identity: operation.expected_identity().as_hex().to_owned(),
            capability: operation.input().capability().into(),
            input: WireProviderInput::from_operation(operation)?,
        })
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireProviderInput {
    Describe,
    PublicIdentity,
    SignEvent {
        payload_hex: ProtectedWireHex,
    },
    Nip04Encrypt {
        peer: String,
        payload_hex: ProtectedWireHex,
    },
    Nip04Decrypt {
        peer: String,
        payload_hex: ProtectedWireHex,
    },
    Nip44Encrypt {
        peer: String,
        version: u8,
        payload_hex: ProtectedWireHex,
    },
    Nip44Decrypt {
        peer: String,
        version: u8,
        payload_hex: ProtectedWireHex,
    },
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
impl WireProviderInput {
    fn from_operation(
        operation: &MycProviderOperation,
    ) -> Result<Self, MycLocalSignerTransportError> {
        let input = operation.input();
        let protected = || {
            input
                .bytes()
                .map(ProtectedWireHex::from_bytes)
                .ok_or_else(|| transport_error(MycLocalSignerTransportErrorKind::InvalidOperation))
        };
        let peer = || {
            input
                .peer()
                .map(|identity| identity.as_hex().to_owned())
                .ok_or_else(|| transport_error(MycLocalSignerTransportErrorKind::InvalidOperation))
        };
        let version = || {
            input
                .nip44_version()
                .map(MycProviderNip44Version::as_u8)
                .ok_or_else(|| transport_error(MycLocalSignerTransportErrorKind::InvalidOperation))
        };
        match input.capability() {
            MycProviderCapability::Describe => Ok(Self::Describe),
            MycProviderCapability::PublicIdentity => Ok(Self::PublicIdentity),
            MycProviderCapability::SignEvent => Ok(Self::SignEvent {
                payload_hex: protected()?,
            }),
            MycProviderCapability::Nip04Encrypt => Ok(Self::Nip04Encrypt {
                peer: peer()?,
                payload_hex: protected()?,
            }),
            MycProviderCapability::Nip04Decrypt => Ok(Self::Nip04Decrypt {
                peer: peer()?,
                payload_hex: protected()?,
            }),
            MycProviderCapability::Nip44Encrypt => Ok(Self::Nip44Encrypt {
                peer: peer()?,
                version: version()?,
                payload_hex: protected()?,
            }),
            MycProviderCapability::Nip44Decrypt => Ok(Self::Nip44Decrypt {
                peer: peer()?,
                version: version()?,
                payload_hex: protected()?,
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSignerResponse {
    contract_version: u32,
    provider_instance: WireProviderInstance,
    role: WireRole,
    operation_id: String,
    correlation_id: String,
    absolute_deadline_unix_ms: u64,
    expected_identity: String,
    capability: WireCapability,
    result: WireProviderResult,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireProviderResult {
    Describe {
        public_identity: String,
        protocol_version: u32,
        capabilities: Vec<WireCapability>,
        maximum_request_bytes: u64,
    },
    PublicIdentity {
        public_identity: String,
    },
    SignEvent {
        payload_hex: ProtectedWireHex,
    },
    Nip04Encrypt {
        payload_hex: ProtectedWireHex,
    },
    Nip04Decrypt {
        payload_hex: ProtectedWireHex,
    },
    Nip44Encrypt {
        version: u8,
        payload_hex: ProtectedWireHex,
    },
    Nip44Decrypt {
        version: u8,
        payload_hex: ProtectedWireHex,
    },
}

struct ProtectedWireHex(Zeroizing<String>);

impl ProtectedWireHex {
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(hex::encode(bytes)))
    }

    fn from_string(value: String) -> Result<Self, MycLocalSignerTransportError> {
        if value.len() > PROTECTED_WIRE_HEX_MAX_UTF8_BYTES
            || !value.len().is_multiple_of(2)
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(transport_error(MycLocalSignerTransportErrorKind::Response));
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

impl Serialize for ProtectedWireHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProtectedWireHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = ProtectedWireHex;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded lowercase even-length hexadecimal")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > PROTECTED_WIRE_HEX_MAX_UTF8_BYTES {
                    return Err(E::custom("protected wire value exceeds its bound"));
                }
                ProtectedWireHex::from_string(value.to_owned()).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ProtectedWireHex::from_string(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        MycConfigProfile, MycProviderCorrelationId, MycProviderDeadlineUnixMs,
        MycProviderOperationId, MycProviderOperationInput, MycProviderPublicIdentity,
        parse_myc_config_v1,
    };

    use super::*;

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn user_binding(socket: &Path, deadline_ms: u64, concurrency: u32) -> MycProviderBinding {
        let source = CONFIG
            .replace(
                "/run/radroots/services/myc/primary/user-signer.sock",
                socket.to_str().expect("UTF-8 test socket"),
            )
            .replacen(
                "request_deadline_ms = 15000",
                &format!("request_deadline_ms = {deadline_ms}"),
                1,
            )
            .replacen(
                "concurrency = 32",
                &format!("concurrency = {concurrency}"),
                1,
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("test configuration")
            .provider_contract()
            .binding(MycProviderRole::User)
            .expect("user binding")
            .clone()
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
    fn protected_wire_hex_is_bounded_canonical_and_redacted() {
        let value = ProtectedWireHex::from_bytes(b"protected-value");
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            format!("\"{}\"", hex::encode(b"protected-value"))
        );
        for invalid in ["a", "AA", "0g"] {
            assert!(serde_json::from_str::<ProtectedWireHex>(&format!("\"{invalid}\"")).is_err());
        }
        let oversized = format!("\"{}\"", "a".repeat(PROTECTED_WIRE_HEX_MAX_UTF8_BYTES + 2));
        assert!(serde_json::from_str::<ProtectedWireHex>(&oversized).is_err());
    }

    #[test]
    fn transport_errors_are_source_free_and_fixed() {
        for kind in [
            MycLocalSignerTransportErrorKind::InvalidBinding,
            MycLocalSignerTransportErrorKind::InvalidOperation,
            MycLocalSignerTransportErrorKind::InvalidLimits,
            MycLocalSignerTransportErrorKind::RequestEncoding,
            MycLocalSignerTransportErrorKind::RequestLimit,
            MycLocalSignerTransportErrorKind::Transport,
            MycLocalSignerTransportErrorKind::Deadline,
            MycLocalSignerTransportErrorKind::Response,
            MycLocalSignerTransportErrorKind::RemoteFailure,
            MycLocalSignerTransportErrorKind::UnsupportedPlatform,
        ] {
            let error = transport_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.code().is_empty());
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn every_operation_has_one_closed_internal_tag_and_complete_binding() {
        let binding = user_binding(Path::new("/run/test-signer.sock"), 15_000, 1);
        let peer = MycProviderPublicIdentity::new(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("peer");
        let inputs = [
            MycProviderOperationInput::describe(),
            MycProviderOperationInput::public_identity(),
            MycProviderOperationInput::sign_event(b"unsigned-event").expect("sign"),
            MycProviderOperationInput::nip04_encrypt(peer.clone(), b"plaintext")
                .expect("nip04 encrypt"),
            MycProviderOperationInput::nip04_decrypt(peer.clone(), b"ciphertext")
                .expect("nip04 decrypt"),
            MycProviderOperationInput::nip44_encrypt(
                peer.clone(),
                MycProviderNip44Version::V2,
                b"plaintext",
            )
            .expect("nip44 encrypt"),
            MycProviderOperationInput::nip44_decrypt(
                peer,
                MycProviderNip44Version::V2,
                b"ciphertext",
            )
            .expect("nip44 decrypt"),
        ];
        let expected = [
            "describe",
            "public_identity",
            "sign_event",
            "nip04_encrypt",
            "nip04_decrypt",
            "nip44_encrypt",
            "nip44_decrypt",
        ];
        for (index, (input, expected)) in inputs.into_iter().zip(expected).enumerate() {
            let operation = operation(&binding, index as u8 + 1, input);
            let request = LocalSignerRequest::from_operation(&operation).expect("wire request");
            let value = serde_json::to_value(request).expect("request JSON");
            assert_eq!(value["contract_version"], 1);
            assert_eq!(value["provider_instance"], "user");
            assert_eq!(value["role"], "user");
            assert_eq!(value["capability"], expected);
            assert_eq!(value["input"]["type"], expected);
            assert_eq!(value["operation_id"].as_str().map(str::len), Some(64));
            assert_eq!(value["correlation_id"].as_str().map(str::len), Some(64));
            assert_eq!(value["absolute_deadline_unix_ms"], 2_000_000_000_000_u64);
            assert_eq!(
                value["expected_identity"],
                binding.expected_identity().as_hex()
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod native {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use radroots_service_host::{
            AdminHttpMethod, AdminMutationRequest, AdminRouter, AdminServer, AdminTransportLimits,
            CancellationToken, EntropyError, EntropySource, UnixAdminSocketBinding,
            UnixAdminSocketWriterAuthority,
        };

        use super::*;

        struct FixedEntropy;

        impl EntropySource for FixedEntropy {
            fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), EntropyError> {
                destination.fill(7);
                Ok(())
            }
        }

        fn runtime_directory() -> tempfile::TempDir {
            tempfile::Builder::new()
                .prefix("myc-ls-")
                .tempdir_in("/tmp")
                .expect("short runtime directory")
        }

        async fn start_server<F, Fut>(
            directory: &tempfile::TempDir,
            handler: F,
        ) -> (
            std::path::PathBuf,
            CancellationToken,
            tokio::task::JoinHandle<()>,
        )
        where
            F: Fn(radroots_service_host::AdminRequest) -> Fut + Send + Sync + 'static,
            Fut: core::future::Future<Output = radroots_service_host::AdminRouteOutcome>
                + Send
                + 'static,
        {
            let socket = directory.path().join("user-signer.sock");
            let authority = UnixAdminSocketWriterAuthority::acquire(directory.path())
                .expect("writer authority");
            let binding = UnixAdminSocketBinding::bind(authority, &socket)
                .await
                .expect("socket binding");
            let mut router = AdminRouter::new();
            router
                .route(AdminHttpMethod::Post, MYC_LOCAL_SIGNER_ENDPOINT, handler)
                .expect("provider route");
            let server = AdminServer::new(router, AdminTransportLimits::DEFAULT, FixedEntropy)
                .expect("admin server");
            let cancellation = CancellationToken::new();
            let server_cancellation = cancellation.clone();
            let task = tokio::spawn(async move {
                server
                    .serve(binding, server_cancellation)
                    .await
                    .expect("serve local signer");
            });
            (socket, cancellation, task)
        }

        fn response_from(request: LocalSignerRequest) -> LocalSignerResponse {
            LocalSignerResponse {
                contract_version: request.contract_version,
                provider_instance: request.provider_instance,
                role: request.role,
                operation_id: request.operation_id,
                correlation_id: request.correlation_id,
                absolute_deadline_unix_ms: request.absolute_deadline_unix_ms,
                expected_identity: request.expected_identity.clone(),
                capability: request.capability,
                result: WireProviderResult::PublicIdentity {
                    public_identity: request.expected_identity,
                },
            }
        }

        #[tokio::test]
        async fn hardened_admin_round_trip_carries_exact_bound_operation() {
            let directory = runtime_directory();
            let (socket, cancellation, task) = start_server(&directory, |request| async move {
                let envelope = request
                    .decode_json::<AdminMutationRequest<LocalSignerRequest>>()
                    .expect("strict mutation request");
                let response = response_from(envelope.into_request());
                request.success(&response).expect("provider response")
            })
            .await;
            let binding = user_binding(&socket, 1_000, 2);
            let operation = operation(&binding, 4, MycProviderOperationInput::public_identity());
            let client = MycLocalSignerClient::new(&binding).expect("client");
            let response = client.execute(&operation).await.expect("transport success");
            assert_eq!(
                response.outer_correlation_id.as_str(),
                hex::encode(operation.correlation_id().as_bytes())
            );
            assert_eq!(response.response.contract_version, 1);
            assert_eq!(
                response.response.provider_instance,
                WireProviderInstance::User
            );
            assert_eq!(response.response.role, WireRole::User);
            assert_eq!(response.response.capability, WireCapability::PublicIdentity);
            assert_eq!(
                format!("{response:?}"),
                "MycLocalSignerUntrustedResponse { correlation_id: \"[redacted]\", provider_instance: User, role: User, capability: PublicIdentity, result: \"[redacted]\" }"
            );
            cancellation.cancel();
            task.await.expect("server task");
        }

        #[tokio::test]
        async fn malformed_success_shape_is_normalized_without_raw_response_exposure() {
            let directory = runtime_directory();
            let (socket, cancellation, task) = start_server(&directory, |request| async move {
                let _: AdminMutationRequest<LocalSignerRequest> =
                    request.decode_json().expect("strict mutation request");
                request
                    .success(&serde_json::json!({"unexpected": "protected-response"}))
                    .expect("malformed semantic success")
            })
            .await;
            let binding = user_binding(&socket, 1_000, 2);
            let operation = operation(&binding, 5, MycProviderOperationInput::public_identity());
            let client = MycLocalSignerClient::new(&binding).expect("client");
            let error = client
                .execute(&operation)
                .await
                .expect_err("malformed response");
            assert_eq!(error.kind(), MycLocalSignerTransportErrorKind::Response);
            assert!(!format!("{error} {error:?}").contains("protected-response"));
            cancellation.cancel();
            task.await.expect("server task");
        }

        #[tokio::test]
        async fn configured_deadline_and_per_client_concurrency_are_enforced() {
            let directory = runtime_directory();
            let active = Arc::new(AtomicUsize::new(0));
            let maximum = Arc::new(AtomicUsize::new(0));
            let handler_active = Arc::clone(&active);
            let handler_maximum = Arc::clone(&maximum);
            let (socket, cancellation, task) = start_server(&directory, move |request| {
                let active = Arc::clone(&handler_active);
                let maximum = Arc::clone(&handler_maximum);
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    let envelope = request
                        .decode_json::<AdminMutationRequest<LocalSignerRequest>>()
                        .expect("strict request");
                    request
                        .success(&response_from(envelope.into_request()))
                        .expect("response")
                }
            })
            .await;
            let binding = user_binding(&socket, 500, 1);
            let client = Arc::new(MycLocalSignerClient::new(&binding).expect("client"));
            let first = operation(&binding, 1, MycProviderOperationInput::public_identity());
            let second = operation(&binding, 2, MycProviderOperationInput::public_identity());
            let first_client = Arc::clone(&client);
            let second_client = Arc::clone(&client);
            let (first_result, second_result) = tokio::join!(
                async move { first_client.execute(&first).await },
                async move { second_client.execute(&second).await }
            );
            first_result.expect("first response");
            second_result.expect("second response");
            assert_eq!(maximum.load(Ordering::SeqCst), 1);
            cancellation.cancel();
            task.await.expect("server task");

            let directory = runtime_directory();
            let (socket, cancellation, task) = start_server(&directory, |request| async move {
                tokio::time::sleep(Duration::from_millis(75)).await;
                let envelope = request
                    .decode_json::<AdminMutationRequest<LocalSignerRequest>>()
                    .expect("strict request");
                request
                    .success(&response_from(envelope.into_request()))
                    .expect("response")
            })
            .await;
            let binding = user_binding(&socket, 10, 1);
            let client = MycLocalSignerClient::new(&binding).expect("deadline client");
            let operation = operation(&binding, 3, MycProviderOperationInput::public_identity());
            assert_eq!(
                client
                    .execute(&operation)
                    .await
                    .expect_err("deadline")
                    .kind(),
                MycLocalSignerTransportErrorKind::Deadline
            );
            cancellation.cancel();
            task.await.expect("server task");
        }

        #[tokio::test]
        async fn wrong_provider_and_request_limit_fail_before_transport_success() {
            let socket = Path::new("/run/test-signer.sock");
            let mut source = CONFIG
                .replace(
                    "/run/radroots/services/myc/primary/user-signer.sock",
                    socket.to_str().expect("UTF-8 socket"),
                )
                .replacen("request_max_bytes = 65536", "request_max_bytes = 1", 1);
            source = source.replacen("concurrency = 32", "concurrency = 1", 1);
            let tiny = parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
                .expect("tiny configuration")
                .provider_contract()
                .binding(MycProviderRole::User)
                .expect("tiny binding")
                .clone();
            let client = MycLocalSignerClient::new(&tiny).expect("tiny client");
            assert_eq!(client.transport.limits().request_body_utf8_bytes(), 1);
            assert_eq!(
                client.transport.limits().response_body_utf8_bytes(),
                1_048_576
            );
            assert_eq!(client.transport.limits().concurrent_connections(), 1);
            assert_eq!(
                client.transport.limits().request_deadline(),
                Duration::from_secs(15)
            );
            assert_eq!(client.permits.available_permits(), 1);
            let tiny_operation = operation(&tiny, 9, MycProviderOperationInput::public_identity());
            assert_eq!(
                client
                    .execute(&tiny_operation)
                    .await
                    .expect_err("request bound")
                    .kind(),
                MycLocalSignerTransportErrorKind::RequestLimit
            );

            let encrypted = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::RepoLocal)
                .expect("configuration")
                .provider_contract()
                .binding(MycProviderRole::Transport)
                .expect("encrypted binding")
                .clone();
            assert_eq!(
                MycLocalSignerClient::new(&encrypted)
                    .expect_err("wrong provider")
                    .kind(),
                MycLocalSignerTransportErrorKind::InvalidBinding
            );

            let mismatched =
                operation(&encrypted, 10, MycProviderOperationInput::public_identity());
            assert_eq!(
                client
                    .execute(&mismatched)
                    .await
                    .expect_err("mismatched operation")
                    .kind(),
                MycLocalSignerTransportErrorKind::InvalidOperation
            );
        }
    }
}
