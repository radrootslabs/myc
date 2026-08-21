//! Independent semantic verification for untrusted signer-provider responses.

use core::fmt;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use nostr::{Event, UnsignedEvent};
use zeroize::Zeroizing;

use crate::provider_contract::MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES;
use crate::provider_local_signer::{
    LocalSignerUntrustedParts, MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION,
    MycLocalSignerUntrustedResponse, ProtectedWireHex, WireCapability, WireProviderInstance,
    WireProviderResult, WireRole,
};
use crate::{
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MycProviderBinding, MycProviderCapability,
    MycProviderCapabilitySet, MycProviderCorrelationId, MycProviderInstanceId, MycProviderKind,
    MycProviderNip44Version, MycProviderOperation, MycProviderOperationId,
    MycProviderPublicIdentity, MycProviderRole,
};

const NIP44_V2_VERSION: u8 = 2;
const NIP44_V2_FIXED_PAYLOAD_BYTES: usize = 67;

/// Positive injected completion-observation time for provider verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycProviderResponseObservedAtUnixMs(u64);

impl MycProviderResponseObservedAtUnixMs {
    /// Validates a positive UTC millisecond value representable by governed time types.
    pub fn new(value: u64) -> Result<Self, MycProviderVerificationError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(verification_error(
                MycProviderVerificationErrorKind::InvalidObservationTime,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the exact injected value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable source-free provider-verification failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycProviderVerificationErrorKind {
    InvalidObservationTime,
    InvalidBinding,
    LateResponse,
    ResponseBinding,
    ResultShape,
    Identity,
    Capability,
    Size,
    Event,
    Nip04,
    Nip44,
}

impl MycProviderVerificationErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidObservationTime => "provider_observation_time_invalid",
            Self::InvalidBinding => "provider_verification_binding_invalid",
            Self::LateResponse => "provider_response_late",
            Self::ResponseBinding => "provider_response_binding_invalid",
            Self::ResultShape => "provider_result_shape_invalid",
            Self::Identity => "provider_result_identity_invalid",
            Self::Capability => "provider_result_capability_invalid",
            Self::Size => "provider_result_size_invalid",
            Self::Event => "provider_signed_event_invalid",
            Self::Nip04 => "provider_nip04_result_invalid",
            Self::Nip44 => "provider_nip44_result_invalid",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidObservationTime => "provider observation time is invalid",
            Self::InvalidBinding => "provider verification binding is invalid",
            Self::LateResponse => "provider response missed its deadline",
            Self::ResponseBinding => "provider response binding is invalid",
            Self::ResultShape => "provider result shape is invalid",
            Self::Identity => "provider result identity is invalid",
            Self::Capability => "provider result capability is invalid",
            Self::Size => "provider result size is invalid",
            Self::Event => "provider signed event is invalid",
            Self::Nip04 => "provider NIP-04 result is invalid",
            Self::Nip44 => "provider NIP-44 result is invalid",
        }
    }
}

/// One source-free provider-verification failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycProviderVerificationError {
    kind: MycProviderVerificationErrorKind,
}

impl MycProviderVerificationError {
    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> MycProviderVerificationErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycProviderVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderVerificationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycProviderVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycProviderVerificationError {}

const fn verification_error(
    kind: MycProviderVerificationErrorKind,
) -> MycProviderVerificationError {
    MycProviderVerificationError { kind }
}

enum VerifiedProviderResult {
    Describe {
        public_identity: MycProviderPublicIdentity,
        protocol_version: u32,
        capabilities: MycProviderCapabilitySet,
        maximum_request_bytes: u64,
    },
    PublicIdentity(MycProviderPublicIdentity),
    SignedEvent(Zeroizing<Vec<u8>>),
    Protected {
        payload: Zeroizing<Vec<u8>>,
        nip44_version: Option<MycProviderNip44Version>,
    },
}

/// One fully correlated, deadline-admitted, independently verified provider result.
///
/// This value proves only local semantic admission. It is not publication,
/// durable commit evidence, or proof that a cancelled provider call had no effect.
pub struct MycVerifiedProviderResponse {
    operation_id: MycProviderOperationId,
    correlation_id: MycProviderCorrelationId,
    instance: MycProviderInstanceId,
    role: MycProviderRole,
    capability: MycProviderCapability,
    result: VerifiedProviderResult,
}

impl MycVerifiedProviderResponse {
    /// Returns the exact verified operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> MycProviderOperationId {
        self.operation_id
    }

    /// Returns the exact verified correlation identity.
    #[must_use]
    pub const fn correlation_id(&self) -> MycProviderCorrelationId {
        self.correlation_id
    }

    /// Returns the exact verified provider instance.
    #[must_use]
    pub const fn instance(&self) -> MycProviderInstanceId {
        self.instance
    }

    /// Returns the exact verified provider role.
    #[must_use]
    pub const fn role(&self) -> MycProviderRole {
        self.role
    }

    /// Returns the exact verified capability.
    #[must_use]
    pub const fn capability(&self) -> MycProviderCapability {
        self.capability
    }

    /// Returns a verified public identity for describe/public-identity results.
    #[must_use]
    pub const fn public_identity(&self) -> Option<&MycProviderPublicIdentity> {
        match &self.result {
            VerifiedProviderResult::Describe {
                public_identity, ..
            }
            | VerifiedProviderResult::PublicIdentity(public_identity) => Some(public_identity),
            VerifiedProviderResult::SignedEvent(_) | VerifiedProviderResult::Protected { .. } => {
                None
            }
        }
    }

    /// Returns the verified protocol version for a describe result.
    #[must_use]
    pub const fn protocol_version(&self) -> Option<u32> {
        match &self.result {
            VerifiedProviderResult::Describe {
                protocol_version, ..
            } => Some(*protocol_version),
            _ => None,
        }
    }

    /// Returns the verified capability set for a describe result.
    #[must_use]
    pub const fn capabilities(&self) -> Option<MycProviderCapabilitySet> {
        match &self.result {
            VerifiedProviderResult::Describe { capabilities, .. } => Some(*capabilities),
            _ => None,
        }
    }

    /// Returns the verified provider request bound for a describe result.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> Option<u64> {
        match &self.result {
            VerifiedProviderResult::Describe {
                maximum_request_bytes,
                ..
            } => Some(*maximum_request_bytes),
            _ => None,
        }
    }

    /// Returns the exact canonical independently verified signed-event bytes.
    ///
    /// These are the bytes returned by the provider after canonical-form,
    /// field, author, event-ID, and signature verification. Consumers that
    /// persist or publish the result must retain these exact bytes.
    #[must_use]
    pub fn signed_event_bytes(&self) -> Option<&[u8]> {
        match &self.result {
            VerifiedProviderResult::SignedEvent(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Returns the verified protected operation output, if applicable.
    #[must_use]
    pub fn protected_payload(&self) -> Option<&[u8]> {
        match &self.result {
            VerifiedProviderResult::Protected { payload, .. } => Some(payload),
            _ => None,
        }
    }

    /// Returns the exact verified NIP-44 version, if applicable.
    #[must_use]
    pub const fn nip44_version(&self) -> Option<MycProviderNip44Version> {
        match &self.result {
            VerifiedProviderResult::Protected { nip44_version, .. } => *nip44_version,
            _ => None,
        }
    }
}

impl fmt::Debug for MycVerifiedProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycVerifiedProviderResponse")
            .field("operation_id", &"[redacted]")
            .field("correlation_id", &"[redacted]")
            .field("instance", &self.instance)
            .field("role", &self.role)
            .field("capability", &self.capability)
            .field("result", &"[redacted]")
            .finish()
    }
}

impl MycLocalSignerUntrustedResponse {
    /// Independently verifies this untrusted response against its original call.
    pub fn verify(
        self,
        binding: &MycProviderBinding,
        operation: &MycProviderOperation,
        observed_at: MycProviderResponseObservedAtUnixMs,
    ) -> Result<MycVerifiedProviderResponse, MycProviderVerificationError> {
        verify_response(binding, operation, observed_at, self.into_parts())
    }
}

fn verify_response(
    binding: &MycProviderBinding,
    operation: &MycProviderOperation,
    observed_at: MycProviderResponseObservedAtUnixMs,
    parts: LocalSignerUntrustedParts,
) -> Result<MycVerifiedProviderResponse, MycProviderVerificationError> {
    if binding.kind() != MycProviderKind::LocalSigner
        || operation.provider() != MycProviderKind::LocalSigner
        || operation.role() != binding.role()
        || operation.instance() != binding.instance()
        || operation.expected_identity() != binding.expected_identity()
        || !binding
            .required_capabilities()
            .contains(operation.input().capability())
    {
        return Err(verification_error(
            MycProviderVerificationErrorKind::InvalidBinding,
        ));
    }
    if observed_at.get() > operation.deadline().get() {
        return Err(verification_error(
            MycProviderVerificationErrorKind::LateResponse,
        ));
    }

    let expected_operation_id = hex::encode(operation.operation_id().as_bytes());
    let expected_correlation_id = hex::encode(operation.correlation_id().as_bytes());
    let response = parts.response;
    if response.contract_version != MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION
        || response.provider_instance != WireProviderInstance::from(operation.instance())
        || response.role != WireRole::from(operation.role())
        || response.operation_id != expected_operation_id
        || response.correlation_id != expected_correlation_id
        || parts.outer_correlation_id.as_ref() != expected_correlation_id
        || response.absolute_deadline_unix_ms != operation.deadline().get()
        || response.expected_identity != operation.expected_identity().as_hex()
        || response.capability != WireCapability::from(operation.input().capability())
    {
        return Err(verification_error(
            MycProviderVerificationErrorKind::ResponseBinding,
        ));
    }

    let result = verify_result(binding, operation, response.result)?;
    Ok(MycVerifiedProviderResponse {
        operation_id: operation.operation_id(),
        correlation_id: operation.correlation_id(),
        instance: operation.instance(),
        role: operation.role(),
        capability: operation.input().capability(),
        result,
    })
}

fn verify_result(
    binding: &MycProviderBinding,
    operation: &MycProviderOperation,
    result: WireProviderResult,
) -> Result<VerifiedProviderResult, MycProviderVerificationError> {
    match (operation.input().capability(), result) {
        (
            MycProviderCapability::Describe,
            WireProviderResult::Describe {
                public_identity,
                protocol_version,
                capabilities,
                maximum_request_bytes,
            },
        ) => verify_describe(
            binding,
            public_identity,
            protocol_version,
            capabilities,
            maximum_request_bytes,
        ),
        (
            MycProviderCapability::PublicIdentity,
            WireProviderResult::PublicIdentity { public_identity },
        ) => {
            verify_identity(operation.expected_identity(), &public_identity)?;
            Ok(VerifiedProviderResult::PublicIdentity(
                operation.expected_identity().clone(),
            ))
        }
        (MycProviderCapability::SignEvent, WireProviderResult::SignEvent { payload_hex }) => {
            verify_signed_event(operation, decode_payload(payload_hex)?)
        }
        (
            MycProviderCapability::Nip04Encrypt,
            WireProviderResult::Nip04Encrypt { peer, payload_hex },
        ) => {
            verify_peer(operation, &peer)?;
            let payload = decode_payload(payload_hex)?;
            let expected_plaintext = operation.input().bytes().ok_or_else(result_shape)?;
            verify_nip04_ciphertext(&payload, Some(expected_plaintext.len()))?;
            Ok(VerifiedProviderResult::Protected {
                payload,
                nip44_version: None,
            })
        }
        (
            MycProviderCapability::Nip04Decrypt,
            WireProviderResult::Nip04Decrypt { peer, payload_hex },
        ) => {
            verify_peer(operation, &peer)?;
            let input = operation.input().bytes().ok_or_else(result_shape)?;
            let ciphertext_length = verify_nip04_ciphertext(input, None)?;
            let payload = decode_payload_allow_empty(payload_hex)?;
            if payload.len() >= ciphertext_length {
                return Err(verification_error(MycProviderVerificationErrorKind::Nip04));
            }
            Ok(VerifiedProviderResult::Protected {
                payload,
                nip44_version: None,
            })
        }
        (
            MycProviderCapability::Nip44Encrypt,
            WireProviderResult::Nip44Encrypt {
                peer,
                version,
                payload_hex,
            },
        ) => {
            verify_peer(operation, &peer)?;
            let requested_version = operation.input().nip44_version().ok_or_else(result_shape)?;
            if version != requested_version.as_u8() {
                return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
            }
            let plaintext = operation.input().bytes().ok_or_else(result_shape)?;
            let payload = decode_payload(payload_hex)?;
            verify_nip44_ciphertext(&payload, Some(plaintext.len()), requested_version)?;
            Ok(VerifiedProviderResult::Protected {
                payload,
                nip44_version: Some(requested_version),
            })
        }
        (
            MycProviderCapability::Nip44Decrypt,
            WireProviderResult::Nip44Decrypt {
                peer,
                version,
                payload_hex,
            },
        ) => {
            verify_peer(operation, &peer)?;
            let requested_version = operation.input().nip44_version().ok_or_else(result_shape)?;
            if version != requested_version.as_u8() {
                return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
            }
            let input = operation.input().bytes().ok_or_else(result_shape)?;
            let padded_length = verify_nip44_ciphertext(input, None, requested_version)?;
            let payload = decode_payload(payload_hex)?;
            if payload.len() > padded_length
                || payload.len() > MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES
            {
                return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
            }
            Ok(VerifiedProviderResult::Protected {
                payload,
                nip44_version: Some(requested_version),
            })
        }
        _ => Err(result_shape()),
    }
}

fn verify_describe(
    binding: &MycProviderBinding,
    public_identity: String,
    protocol_version: u32,
    capabilities: Vec<WireCapability>,
    maximum_request_bytes: u64,
) -> Result<VerifiedProviderResult, MycProviderVerificationError> {
    verify_identity(binding.expected_identity(), &public_identity)?;
    if protocol_version != MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION {
        return Err(verification_error(
            MycProviderVerificationErrorKind::ResponseBinding,
        ));
    }
    if capabilities.is_empty() || capabilities.len() > 7 {
        return Err(verification_error(
            MycProviderVerificationErrorKind::Capability,
        ));
    }
    let capabilities: Vec<MycProviderCapability> = capabilities
        .into_iter()
        .map(MycProviderCapability::from)
        .collect();
    let capabilities = MycProviderCapabilitySet::new(&capabilities)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Capability))?;
    if binding
        .required_capabilities()
        .iter()
        .any(|capability| !capabilities.contains(capability))
    {
        return Err(verification_error(
            MycProviderVerificationErrorKind::Capability,
        ));
    }
    let limits = binding
        .local_signer_limits()
        .ok_or_else(|| verification_error(MycProviderVerificationErrorKind::InvalidBinding))?;
    if maximum_request_bytes != limits.request_max_bytes() {
        return Err(verification_error(MycProviderVerificationErrorKind::Size));
    }
    Ok(VerifiedProviderResult::Describe {
        public_identity: binding.expected_identity().clone(),
        protocol_version,
        capabilities,
        maximum_request_bytes,
    })
}

fn verify_identity(
    expected: &MycProviderPublicIdentity,
    actual: &str,
) -> Result<(), MycProviderVerificationError> {
    if actual != expected.as_hex() {
        return Err(verification_error(
            MycProviderVerificationErrorKind::Identity,
        ));
    }
    Ok(())
}

fn verify_peer(
    operation: &MycProviderOperation,
    actual: &str,
) -> Result<(), MycProviderVerificationError> {
    if operation
        .input()
        .peer()
        .map(MycProviderPublicIdentity::as_hex)
        != Some(actual)
    {
        return Err(verification_error(
            MycProviderVerificationErrorKind::ResponseBinding,
        ));
    }
    Ok(())
}

fn decode_payload(
    payload: ProtectedWireHex,
) -> Result<Zeroizing<Vec<u8>>, MycProviderVerificationError> {
    let payload = payload
        .into_bytes()
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::ResultShape))?;
    if payload.is_empty() || payload.len() > MYC_PROVIDER_OUTPUT_MAX_BYTES {
        return Err(verification_error(MycProviderVerificationErrorKind::Size));
    }
    Ok(payload)
}

fn decode_payload_allow_empty(
    payload: ProtectedWireHex,
) -> Result<Zeroizing<Vec<u8>>, MycProviderVerificationError> {
    let payload = payload
        .into_bytes()
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::ResultShape))?;
    if payload.len() > MYC_PROVIDER_OUTPUT_MAX_BYTES {
        return Err(verification_error(MycProviderVerificationErrorKind::Size));
    }
    Ok(payload)
}

fn verify_signed_event(
    operation: &MycProviderOperation,
    payload: Zeroizing<Vec<u8>>,
) -> Result<VerifiedProviderResult, MycProviderVerificationError> {
    let unsigned_bytes = operation.input().bytes().ok_or_else(result_shape)?;
    let mut unsigned: UnsignedEvent = serde_json::from_slice(unsigned_bytes)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Event))?;
    let canonical_unsigned = serde_json::to_vec(&unsigned)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Event))?;
    if canonical_unsigned != unsigned_bytes
        || unsigned.verify_id().is_err()
        || unsigned.pubkey.to_hex() != operation.expected_identity().as_hex()
    {
        return Err(verification_error(MycProviderVerificationErrorKind::Event));
    }
    let expected_id = unsigned.id();
    let event: Event = serde_json::from_slice(&payload)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Event))?;
    let canonical_event = serde_json::to_vec(&event)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Event))?;
    if canonical_event.as_slice() != payload.as_slice()
        || event.pubkey != unsigned.pubkey
        || event.created_at != unsigned.created_at
        || event.kind != unsigned.kind
        || event.tags != unsigned.tags
        || event.content != unsigned.content
        || event.id != expected_id
        || event.verify().is_err()
    {
        return Err(verification_error(MycProviderVerificationErrorKind::Event));
    }
    Ok(VerifiedProviderResult::SignedEvent(payload))
}

fn verify_nip04_ciphertext(
    payload: &[u8],
    plaintext_length: Option<usize>,
) -> Result<usize, MycProviderVerificationError> {
    let rendered = core::str::from_utf8(payload)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Nip04))?;
    let (ciphertext, iv) = rendered
        .split_once("?iv=")
        .ok_or_else(|| verification_error(MycProviderVerificationErrorKind::Nip04))?;
    if ciphertext.is_empty() || iv.is_empty() || iv.contains("?iv=") {
        return Err(verification_error(MycProviderVerificationErrorKind::Nip04));
    }
    let ciphertext = decode_canonical_base64(ciphertext, MycProviderVerificationErrorKind::Nip04)?;
    let iv = decode_canonical_base64(iv, MycProviderVerificationErrorKind::Nip04)?;
    if iv.len() != 16 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(verification_error(MycProviderVerificationErrorKind::Nip04));
    }
    if let Some(length) = plaintext_length {
        let expected = length
            .checked_div(16)
            .and_then(|blocks| blocks.checked_add(1))
            .and_then(|blocks| blocks.checked_mul(16))
            .ok_or_else(|| verification_error(MycProviderVerificationErrorKind::Size))?;
        if ciphertext.len() != expected {
            return Err(verification_error(MycProviderVerificationErrorKind::Nip04));
        }
    }
    Ok(ciphertext.len())
}

fn verify_nip44_ciphertext(
    payload: &[u8],
    plaintext_length: Option<usize>,
    version: MycProviderNip44Version,
) -> Result<usize, MycProviderVerificationError> {
    let rendered = core::str::from_utf8(payload)
        .map_err(|_| verification_error(MycProviderVerificationErrorKind::Nip44))?;
    let decoded = decode_canonical_base64(rendered, MycProviderVerificationErrorKind::Nip44)?;
    if version.as_u8() != NIP44_V2_VERSION
        || decoded.first().copied() != Some(version.as_u8())
        || decoded.len() < NIP44_V2_FIXED_PAYLOAD_BYTES + 32
    {
        return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
    }
    let padded = decoded
        .len()
        .checked_sub(NIP44_V2_FIXED_PAYLOAD_BYTES)
        .ok_or_else(|| verification_error(MycProviderVerificationErrorKind::Nip44))?;
    if let Some(length) = plaintext_length {
        let expected = nip44_padding_length(length)
            .and_then(|value| NIP44_V2_FIXED_PAYLOAD_BYTES.checked_add(value))
            .ok_or_else(|| verification_error(MycProviderVerificationErrorKind::Nip44))?;
        if decoded.len() != expected {
            return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
        }
    } else if !is_valid_nip44_padding_length(padded) {
        return Err(verification_error(MycProviderVerificationErrorKind::Nip44));
    }
    Ok(padded)
}

fn decode_canonical_base64(
    value: &str,
    kind: MycProviderVerificationErrorKind,
) -> Result<Vec<u8>, MycProviderVerificationError> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| verification_error(kind))?;
    if BASE64_STANDARD.encode(&decoded) != value {
        return Err(verification_error(kind));
    }
    Ok(decoded)
}

fn nip44_padding_length(length: usize) -> Option<usize> {
    if length == 0 || length > MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES {
        return None;
    }
    if length <= 32 {
        return Some(32);
    }
    let next_power = length.checked_next_power_of_two()?;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power.checked_div(8)?
    };
    chunk.checked_mul(length.checked_sub(1)?.checked_div(chunk)?.checked_add(1)?)
}

fn is_valid_nip44_padding_length(padded: usize) -> bool {
    if !(32..=65_536).contains(&padded) {
        return false;
    }
    if padded <= 256 {
        return padded.is_multiple_of(32);
    }
    let Some(next_power) = padded.checked_next_power_of_two() else {
        return false;
    };
    let chunk = next_power / 8;
    padded.is_multiple_of(chunk)
}

const fn result_shape() -> MycProviderVerificationError {
    verification_error(MycProviderVerificationErrorKind::ResultShape)
}

impl From<WireCapability> for MycProviderCapability {
    fn from(capability: WireCapability) -> Self {
        match capability {
            WireCapability::Describe => Self::Describe,
            WireCapability::PublicIdentity => Self::PublicIdentity,
            WireCapability::SignEvent => Self::SignEvent,
            WireCapability::Nip04Encrypt => Self::Nip04Encrypt,
            WireCapability::Nip04Decrypt => Self::Nip04Decrypt,
            WireCapability::Nip44Encrypt => Self::Nip44Encrypt,
            WireCapability::Nip44Decrypt => Self::Nip44Decrypt,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::path::Path;

    use nostr::nips::{nip04, nip44};
    use nostr::{Keys, Kind, SecretKey, Tag, Timestamp};

    use crate::provider_local_signer::{LocalSignerResponse, MycLocalSignerUntrustedResponse};
    use crate::{
        MycConfigProfile, MycProviderCorrelationId, MycProviderDeadlineUnixMs,
        MycProviderOperationId, MycProviderOperationInput, parse_myc_config_v1,
    };

    use super::*;

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn keys(seed: u8) -> Keys {
        Keys::new(SecretKey::from_slice(&[seed; 32]).expect("test secret"))
    }

    fn binding(identity: &Keys) -> MycProviderBinding {
        let source = CONFIG
            .replace(
                "/run/radroots/services/myc/primary/user-signer.sock",
                Path::new("/run/test-verifier.sock")
                    .to_str()
                    .expect("test socket"),
            )
            .replace(
                "2222222222222222222222222222222222222222222222222222222222222222",
                &identity.public_key().to_hex(),
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("test config")
            .provider_contract()
            .binding(MycProviderRole::User)
            .expect("user binding")
            .clone()
    }

    fn encrypted_transport_binding() -> MycProviderBinding {
        parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("test config")
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding")
            .clone()
    }

    fn make_operation(
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

    fn parts(
        operation: &MycProviderOperation,
        result: WireProviderResult,
    ) -> LocalSignerUntrustedParts {
        let operation_id = hex::encode(operation.operation_id().as_bytes());
        let correlation_id = hex::encode(operation.correlation_id().as_bytes());
        LocalSignerUntrustedParts {
            outer_correlation_id: correlation_id.clone().into(),
            response: LocalSignerResponse {
                contract_version: MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION,
                provider_instance: operation.instance().into(),
                role: operation.role().into(),
                operation_id,
                correlation_id,
                absolute_deadline_unix_ms: operation.deadline().get(),
                expected_identity: operation.expected_identity().as_hex().to_owned(),
                capability: operation.input().capability().into(),
                result,
            },
        }
    }

    fn observed() -> MycProviderResponseObservedAtUnixMs {
        MycProviderResponseObservedAtUnixMs::new(1_999_999_999_999).expect("observed")
    }

    fn public_identity_result(operation: &MycProviderOperation) -> WireProviderResult {
        WireProviderResult::PublicIdentity {
            public_identity: operation.expected_identity().as_hex().to_owned(),
        }
    }

    fn verify(
        binding: &MycProviderBinding,
        operation: &MycProviderOperation,
        result: WireProviderResult,
    ) -> Result<MycVerifiedProviderResponse, MycProviderVerificationError> {
        MycLocalSignerUntrustedResponse::from_parts(parts(operation, result)).verify(
            binding,
            operation,
            observed(),
        )
    }

    fn assert_binding_rejected(
        binding: &MycProviderBinding,
        operation: &MycProviderOperation,
        mutate: impl FnOnce(&mut LocalSignerUntrustedParts),
    ) {
        let mut untrusted = parts(operation, public_identity_result(operation));
        mutate(&mut untrusted);
        let error = MycLocalSignerUntrustedResponse::from_parts(untrusted)
            .verify(binding, operation, observed())
            .expect_err("binding mismatch");
        assert_eq!(
            error.kind(),
            MycProviderVerificationErrorKind::ResponseBinding
        );
    }

    #[test]
    fn observed_time_and_errors_are_bounded_source_free_and_redacted() {
        assert!(MycProviderResponseObservedAtUnixMs::new(0).is_err());
        assert!(MycProviderResponseObservedAtUnixMs::new(i64::MAX as u64).is_ok());
        assert!(MycProviderResponseObservedAtUnixMs::new(i64::MAX as u64 + 1).is_err());
        for kind in [
            MycProviderVerificationErrorKind::InvalidObservationTime,
            MycProviderVerificationErrorKind::InvalidBinding,
            MycProviderVerificationErrorKind::LateResponse,
            MycProviderVerificationErrorKind::ResponseBinding,
            MycProviderVerificationErrorKind::ResultShape,
            MycProviderVerificationErrorKind::Identity,
            MycProviderVerificationErrorKind::Capability,
            MycProviderVerificationErrorKind::Size,
            MycProviderVerificationErrorKind::Event,
            MycProviderVerificationErrorKind::Nip04,
            MycProviderVerificationErrorKind::Nip44,
        ] {
            let error = verification_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.code().is_empty());
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn every_outer_and_inner_binding_must_match_the_original_operation() {
        let identity = keys(1);
        let binding = binding(&identity);
        let operation = make_operation(&binding, 3, MycProviderOperationInput::public_identity());
        let verified = verify(&binding, &operation, public_identity_result(&operation))
            .expect("verified identity");
        assert_eq!(verified.operation_id(), operation.operation_id());
        assert_eq!(verified.correlation_id(), operation.correlation_id());
        assert_eq!(verified.role(), MycProviderRole::User);
        assert_eq!(verified.instance(), MycProviderInstanceId::User);
        assert_eq!(
            verified.public_identity(),
            Some(operation.expected_identity())
        );

        let error = MycLocalSignerUntrustedResponse::from_parts(parts(
            &operation,
            public_identity_result(&operation),
        ))
        .verify(&encrypted_transport_binding(), &operation, observed())
        .expect_err("wrong configured binding");
        assert_eq!(
            error.kind(),
            MycProviderVerificationErrorKind::InvalidBinding
        );

        assert_binding_rejected(&binding, &operation, |parts| {
            parts.outer_correlation_id = "00".into();
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.contract_version = 2;
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.operation_id = "00".into();
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.correlation_id = "00".into();
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.absolute_deadline_unix_ms -= 1;
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.expected_identity = keys(2).public_key().to_hex();
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.capability = WireCapability::Describe;
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.role = WireRole::Transport;
        });
        assert_binding_rejected(&binding, &operation, |parts| {
            parts.response.provider_instance = WireProviderInstance::Transport;
        });

        let late = MycProviderResponseObservedAtUnixMs::new(operation.deadline().get() + 1)
            .expect("late observation");
        let error = MycLocalSignerUntrustedResponse::from_parts(parts(
            &operation,
            public_identity_result(&operation),
        ))
        .verify(&binding, &operation, late)
        .expect_err("late result");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::LateResponse);

        let exact = MycProviderResponseObservedAtUnixMs::new(operation.deadline().get())
            .expect("exact deadline");
        MycLocalSignerUntrustedResponse::from_parts(parts(
            &operation,
            public_identity_result(&operation),
        ))
        .verify(&binding, &operation, exact)
        .expect("exact deadline admitted");
    }

    #[test]
    fn describe_requires_exact_identity_protocol_capabilities_and_size() {
        let identity = keys(1);
        let binding = binding(&identity);
        let operation = make_operation(&binding, 4, MycProviderOperationInput::describe());
        let all = [
            WireCapability::Describe,
            WireCapability::PublicIdentity,
            WireCapability::SignEvent,
            WireCapability::Nip04Encrypt,
            WireCapability::Nip04Decrypt,
            WireCapability::Nip44Encrypt,
            WireCapability::Nip44Decrypt,
        ];
        let result = || WireProviderResult::Describe {
            public_identity: operation.expected_identity().as_hex().to_owned(),
            protocol_version: 1,
            capabilities: all.to_vec(),
            maximum_request_bytes: binding
                .local_signer_limits()
                .expect("limits")
                .request_max_bytes(),
        };
        let verified = verify(&binding, &operation, result()).expect("describe");
        assert_eq!(verified.protocol_version(), Some(1));
        assert_eq!(verified.capabilities().expect("capabilities").len(), 7);
        assert_eq!(verified.maximum_request_bytes(), Some(65_536));

        let duplicate = WireProviderResult::Describe {
            public_identity: operation.expected_identity().as_hex().to_owned(),
            protocol_version: 1,
            capabilities: vec![WireCapability::Describe, WireCapability::Describe],
            maximum_request_bytes: 65_536,
        };
        assert_eq!(
            verify(&binding, &operation, duplicate).unwrap_err().kind(),
            MycProviderVerificationErrorKind::Capability
        );
        let missing = WireProviderResult::Describe {
            public_identity: operation.expected_identity().as_hex().to_owned(),
            protocol_version: 1,
            capabilities: vec![WireCapability::Describe, WireCapability::PublicIdentity],
            maximum_request_bytes: 65_536,
        };
        assert_eq!(
            verify(&binding, &operation, missing).unwrap_err().kind(),
            MycProviderVerificationErrorKind::Capability
        );
        let wrong_size = WireProviderResult::Describe {
            public_identity: operation.expected_identity().as_hex().to_owned(),
            protocol_version: 1,
            capabilities: all.to_vec(),
            maximum_request_bytes: 65_535,
        };
        assert_eq!(
            verify(&binding, &operation, wrong_size).unwrap_err().kind(),
            MycProviderVerificationErrorKind::Size
        );
        let wrong_protocol = WireProviderResult::Describe {
            public_identity: operation.expected_identity().as_hex().to_owned(),
            protocol_version: 2,
            capabilities: all.to_vec(),
            maximum_request_bytes: 65_536,
        };
        assert_eq!(
            verify(&binding, &operation, wrong_protocol)
                .unwrap_err()
                .kind(),
            MycProviderVerificationErrorKind::ResponseBinding
        );
        let wrong_identity = WireProviderResult::Describe {
            public_identity: keys(2).public_key().to_hex(),
            protocol_version: 1,
            capabilities: all.to_vec(),
            maximum_request_bytes: 65_536,
        };
        assert_eq!(
            verify(&binding, &operation, wrong_identity)
                .unwrap_err()
                .kind(),
            MycProviderVerificationErrorKind::Identity
        );
    }

    #[test]
    fn signed_event_must_match_every_canonical_unsigned_field_and_signature() {
        let identity = keys(1);
        let binding = binding(&identity);
        let unsigned = UnsignedEvent::new(
            identity.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "signed content",
        );
        let unsigned_bytes = serde_json::to_vec(&unsigned).expect("unsigned JSON");
        let operation = make_operation(
            &binding,
            5,
            MycProviderOperationInput::sign_event(&unsigned_bytes).expect("sign input"),
        );
        let event = unsigned
            .clone()
            .sign_with_keys(&identity)
            .expect("signed event");
        let event_bytes = serde_json::to_vec(&event).expect("event JSON");
        let verified = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(&event_bytes),
            },
        )
        .expect("verified event");
        assert_eq!(verified.signed_event_bytes(), Some(event_bytes.as_slice()));
        assert!(!format!("{verified:?}").contains("signed content"));

        let altered = UnsignedEvent::new(
            identity.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "altered content",
        )
        .sign_with_keys(&identity)
        .expect("altered event");
        let error = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(
                    &serde_json::to_vec(&altered).expect("altered JSON"),
                ),
            },
        )
        .expect_err("altered fields");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Event);

        let other_identity = keys(2);
        let wrong_author = UnsignedEvent::new(
            other_identity.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "signed content",
        )
        .sign_with_keys(&other_identity)
        .expect("wrong-author event");
        let error = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(
                    &serde_json::to_vec(&wrong_author).expect("wrong-author JSON"),
                ),
            },
        )
        .expect_err("wrong author");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Event);

        let mut wrong_id = event.clone();
        wrong_id.id = nostr::EventId::all_zeros();
        let error = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(
                    &serde_json::to_vec(&wrong_id).expect("wrong-id JSON"),
                ),
            },
        )
        .expect_err("wrong event ID");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Event);

        let mut wrong_signature = event.clone();
        wrong_signature.sig = altered.sig;
        let error = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(
                    &serde_json::to_vec(&wrong_signature).expect("wrong-signature JSON"),
                ),
            },
        )
        .expect_err("wrong signature");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Event);

        let noncanonical_input = format!(" {}", String::from_utf8(unsigned_bytes).unwrap());
        let noncanonical_operation = make_operation(
            &binding,
            6,
            MycProviderOperationInput::sign_event(noncanonical_input.as_bytes())
                .expect("bounded input"),
        );
        let error = verify(
            &binding,
            &noncanonical_operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(&event_bytes),
            },
        )
        .expect_err("noncanonical unsigned event");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Event);
    }

    #[test]
    fn nip04_direction_peer_shape_and_padding_are_independently_bound() {
        let identity = keys(1);
        let peer = keys(2);
        let binding = binding(&identity);
        let peer_identity =
            MycProviderPublicIdentity::new(&peer.public_key().to_hex()).expect("peer");
        let plaintext = b"nip04 plaintext";
        let ciphertext = nip04::encrypt(
            identity.secret_key(),
            &peer.public_key(),
            plaintext.as_slice(),
        )
        .expect("nip04 ciphertext");
        let encrypt = make_operation(
            &binding,
            7,
            MycProviderOperationInput::nip04_encrypt(peer_identity.clone(), plaintext)
                .expect("encrypt input"),
        );
        let verified = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip04Encrypt {
                peer: peer.public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(ciphertext.as_bytes()),
            },
        )
        .expect("nip04 encrypt");
        assert_eq!(verified.protected_payload(), Some(ciphertext.as_bytes()));

        let error = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip04Encrypt {
                peer: keys(3).public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(ciphertext.as_bytes()),
            },
        )
        .expect_err("wrong peer");
        assert_eq!(
            error.kind(),
            MycProviderVerificationErrorKind::ResponseBinding
        );
        let error = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip04Encrypt {
                peer: peer.public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(b"not-ciphertext"),
            },
        )
        .expect_err("malformed ciphertext");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Nip04);

        let decrypt = make_operation(
            &binding,
            8,
            MycProviderOperationInput::nip04_decrypt(peer_identity, ciphertext.as_bytes())
                .expect("decrypt input"),
        );
        let verified = verify(
            &binding,
            &decrypt,
            WireProviderResult::Nip04Decrypt {
                peer: peer.public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(plaintext),
            },
        )
        .expect("nip04 decrypt");
        assert_eq!(verified.protected_payload(), Some(plaintext.as_slice()));

        let error = verify(
            &binding,
            &decrypt,
            WireProviderResult::Nip04Decrypt {
                peer: peer.public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(&[0; 32]),
            },
        )
        .expect_err("plaintext cannot fill the complete ciphertext block capacity");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Nip04);
    }

    #[test]
    fn nip44_direction_peer_version_shape_and_padding_are_independently_bound() {
        let identity = keys(1);
        let peer = keys(2);
        let binding = binding(&identity);
        let peer_identity =
            MycProviderPublicIdentity::new(&peer.public_key().to_hex()).expect("peer");
        let plaintext = b"nip44 plaintext";
        assert!(
            MycProviderOperationInput::nip44_encrypt(
                peer_identity.clone(),
                MycProviderNip44Version::V2,
                b""
            )
            .is_err()
        );
        let ciphertext = nip44::encrypt(
            identity.secret_key(),
            &peer.public_key(),
            plaintext.as_slice(),
            nip44::Version::V2,
        )
        .expect("nip44 ciphertext");
        let encrypt = make_operation(
            &binding,
            9,
            MycProviderOperationInput::nip44_encrypt(
                peer_identity.clone(),
                MycProviderNip44Version::V2,
                plaintext,
            )
            .expect("encrypt input"),
        );
        let verified = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip44Encrypt {
                peer: peer.public_key().to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(ciphertext.as_bytes()),
            },
        )
        .expect("nip44 encrypt");
        assert_eq!(verified.nip44_version(), Some(MycProviderNip44Version::V2));

        let error = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip44Encrypt {
                peer: peer.public_key().to_hex(),
                version: 3,
                payload_hex: ProtectedWireHex::from_bytes(ciphertext.as_bytes()),
            },
        )
        .expect_err("wrong version");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Nip44);

        let error = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip44Encrypt {
                peer: keys(3).public_key().to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(ciphertext.as_bytes()),
            },
        )
        .expect_err("wrong peer");
        assert_eq!(
            error.kind(),
            MycProviderVerificationErrorKind::ResponseBinding
        );
        let error = verify(
            &binding,
            &encrypt,
            WireProviderResult::Nip44Encrypt {
                peer: peer.public_key().to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(b"not-base64"),
            },
        )
        .expect_err("malformed ciphertext");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Nip44);

        let decrypt = make_operation(
            &binding,
            10,
            MycProviderOperationInput::nip44_decrypt(
                peer_identity,
                MycProviderNip44Version::V2,
                ciphertext.as_bytes(),
            )
            .expect("decrypt input"),
        );
        let verified = verify(
            &binding,
            &decrypt,
            WireProviderResult::Nip44Decrypt {
                peer: peer.public_key().to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(plaintext),
            },
        )
        .expect("nip44 decrypt");
        assert_eq!(verified.protected_payload(), Some(plaintext.as_slice()));

        let error = verify(
            &binding,
            &decrypt,
            WireProviderResult::Nip44Decrypt {
                peer: peer.public_key().to_hex(),
                version: 2,
                payload_hex: ProtectedWireHex::from_bytes(&[0; 33]),
            },
        )
        .expect_err("plaintext cannot exceed the ciphertext padding capacity");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Nip44);
    }

    #[test]
    fn wrong_result_shape_and_semantic_output_overflow_fail_before_exposure() {
        let identity = keys(1);
        let binding = binding(&identity);
        let operation = make_operation(&binding, 11, MycProviderOperationInput::public_identity());
        let error = verify(
            &binding,
            &operation,
            WireProviderResult::SignEvent {
                payload_hex: ProtectedWireHex::from_bytes(b"event"),
            },
        )
        .expect_err("wrong shape");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::ResultShape);

        let peer = keys(2);
        let peer_identity =
            MycProviderPublicIdentity::new(&peer.public_key().to_hex()).expect("peer");
        let decrypt = make_operation(
            &binding,
            12,
            MycProviderOperationInput::nip04_decrypt(
                peer_identity,
                nip04::encrypt(identity.secret_key(), &peer.public_key(), "input")
                    .expect("ciphertext")
                    .as_bytes(),
            )
            .expect("decrypt input"),
        );
        let oversized = vec![7_u8; MYC_PROVIDER_OUTPUT_MAX_BYTES + 1];
        let error = verify(
            &binding,
            &decrypt,
            WireProviderResult::Nip04Decrypt {
                peer: peer.public_key().to_hex(),
                payload_hex: ProtectedWireHex::from_bytes(&oversized),
            },
        )
        .expect_err("oversized output");
        assert_eq!(error.kind(), MycProviderVerificationErrorKind::Size);
    }

    #[test]
    fn nip44_padding_model_matches_all_exact_protocol_boundaries() {
        for (length, padded) in [
            (1, 32),
            (32, 32),
            (33, 64),
            (256, 256),
            (257, 320),
            (MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES, 65_536),
        ] {
            assert_eq!(nip44_padding_length(length), Some(padded));
            assert!(is_valid_nip44_padding_length(padded));
        }
        assert_eq!(nip44_padding_length(0), None);
        assert_eq!(
            nip44_padding_length(MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES + 1),
            None
        );
        for invalid in [0, 31, 33, 288, 65_537] {
            assert!(!is_valid_nip44_padding_length(invalid));
        }
    }
}
