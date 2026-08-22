//! Cryptographic and typed verification for structurally admitted NIP-46 input.

use core::fmt;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use nostr::{Event, Kind};
use radroots_nostr_connect::{
    message::{RPC_KIND, RequestMessage},
    method::METHOD_MAX_BYTES,
};
use serde::Deserialize;

use crate::{
    MycBoundedNip46Event, MycBoundedNip46Request, MycNip46ClientPublicKey, MycNip46EventId,
    MycNip46RequestId, MycProviderBinding, MycProviderPublicIdentity, MycProviderRole,
};

const NIP04_IV_BYTES: usize = 16;
const NIP04_BLOCK_BYTES: usize = 16;
const NIP44_VERSION_V2: u8 = 2;
const NIP44_NONCE_BYTES: usize = 32;
const NIP44_LENGTH_PREFIX_BYTES: usize = 2;
const NIP44_HMAC_BYTES: usize = 32;
const NIP44_MIN_PADDED_BYTES: usize = 32;
const NIP44_MAX_PADDED_BYTES: usize = 65_536;

/// Encryption envelope declared by one verified NIP-46 event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycNip46EncryptionContext {
    Nip04,
    Nip44V2,
}

/// Injected UTC second at which an inbound event is verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycNip46ObservedAtUnixSeconds(u64);

impl MycNip46ObservedAtUnixSeconds {
    /// Validates a positive instant representable by SQLite's signed integer.
    pub fn new(value: u64) -> Result<Self, MycNip46VerificationError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(verification_error(
                MycNip46VerificationErrorKind::InvalidObservationTime,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the injected UTC second.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Explicit caller-selected authored-time window with no implicit default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MycNip46AuthoredTimePolicy {
    maximum_past_seconds: u64,
    maximum_future_seconds: u64,
}

impl MycNip46AuthoredTimePolicy {
    /// Validates inclusive past and future tolerances.
    pub fn new(
        maximum_past_seconds: u64,
        maximum_future_seconds: u64,
    ) -> Result<Self, MycNip46VerificationError> {
        if i64::try_from(maximum_past_seconds).is_err()
            || i64::try_from(maximum_future_seconds).is_err()
        {
            return Err(verification_error(
                MycNip46VerificationErrorKind::InvalidTimePolicy,
            ));
        }
        Ok(Self {
            maximum_past_seconds,
            maximum_future_seconds,
        })
    }

    /// Returns the inclusive maximum event age.
    #[must_use]
    pub const fn maximum_past_seconds(self) -> u64 {
        self.maximum_past_seconds
    }

    /// Returns the inclusive maximum future skew.
    #[must_use]
    pub const fn maximum_future_seconds(self) -> u64 {
        self.maximum_future_seconds
    }
}

/// Stable source-free classification for NIP-46 verification failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46VerificationErrorKind {
    InvalidObservationTime,
    InvalidTimePolicy,
    InvalidTransportBinding,
    MalformedEvent,
    NonCanonicalEvent,
    InvalidKind,
    InvalidSender,
    InvalidReceiver,
    InvalidEventId,
    InvalidSignature,
    AuthoredTimeRejected,
    InvalidNip04Envelope,
    InvalidNip44Envelope,
    InvalidTypedRequest,
}

impl MycNip46VerificationErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidObservationTime => "NIP-46 observation time is invalid",
            Self::InvalidTimePolicy => "NIP-46 authored-time policy is invalid",
            Self::InvalidTransportBinding => "NIP-46 transport binding is invalid",
            Self::MalformedEvent => "NIP-46 event cannot be decoded",
            Self::NonCanonicalEvent => "NIP-46 event encoding is not canonical",
            Self::InvalidKind => "NIP-46 event kind is invalid",
            Self::InvalidSender => "NIP-46 event sender is invalid",
            Self::InvalidReceiver => "NIP-46 event receiver is invalid",
            Self::InvalidEventId => "NIP-46 event identifier is invalid",
            Self::InvalidSignature => "NIP-46 event signature is invalid",
            Self::AuthoredTimeRejected => "NIP-46 event authored time is outside policy",
            Self::InvalidNip04Envelope => "NIP-46 NIP-04 envelope is invalid",
            Self::InvalidNip44Envelope => "NIP-46 NIP-44 envelope is invalid",
            Self::InvalidTypedRequest => "NIP-46 typed request is invalid",
        }
    }
}

/// One redacted NIP-46 verification failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46VerificationError {
    kind: MycNip46VerificationErrorKind,
}

impl MycNip46VerificationError {
    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycNip46VerificationErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycNip46VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46VerificationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycNip46VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycNip46VerificationError {}

/// One cryptographically verified encrypted NIP-46 event.
pub struct MycVerifiedNip46Event {
    original: Box<[u8]>,
    encrypted_content: Box<str>,
    event_id: MycNip46EventId,
    client_public_key: MycNip46ClientPublicKey,
    receiver_public_key: MycProviderPublicIdentity,
    authored_at_unix_seconds: u64,
    encryption_context: MycNip46EncryptionContext,
}

impl MycVerifiedNip46Event {
    /// Returns the exact signed event bytes admitted by Step 141.
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Returns the verified event identity.
    #[must_use]
    pub const fn event_id(&self) -> MycNip46EventId {
        self.event_id
    }

    /// Returns the verified client transport identity.
    #[must_use]
    pub const fn client_public_key(&self) -> &MycNip46ClientPublicKey {
        &self.client_public_key
    }

    pub(crate) const fn receiver_public_key(&self) -> &MycProviderPublicIdentity {
        &self.receiver_public_key
    }

    /// Returns the verified event authored time.
    #[must_use]
    pub const fn authored_at_unix_seconds(&self) -> u64 {
        self.authored_at_unix_seconds
    }

    /// Returns the verified encrypted-envelope context.
    #[must_use]
    pub const fn encryption_context(&self) -> MycNip46EncryptionContext {
        self.encryption_context
    }

    /// Returns the bounded ciphertext for the later governed decryption boundary.
    #[must_use]
    pub fn encrypted_content(&self) -> &str {
        &self.encrypted_content
    }
}

impl fmt::Debug for MycVerifiedNip46Event {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycVerifiedNip46Event")
            .field("wire_bytes", &self.original.len())
            .field("ciphertext_bytes", &self.encrypted_content.len())
            .field("authored_at_unix_seconds", &self.authored_at_unix_seconds)
            .field("encryption_context", &self.encryption_context)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// One exact typed NIP-46 request decoded from admitted plaintext.
pub struct MycVerifiedNip46Request {
    request_id: MycNip46RequestId,
    method: Box<str>,
    canonical_request: Box<[u8]>,
    parameter_count: usize,
    parameter_bytes: usize,
}

impl MycVerifiedNip46Request {
    /// Returns the validated request identity.
    #[must_use]
    pub const fn request_id(&self) -> &MycNip46RequestId {
        &self.request_id
    }

    /// Returns the canonical typed method spelling.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the typed parameter count without exposing parameters.
    #[must_use]
    pub const fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    /// Returns the aggregate typed parameter byte count.
    #[must_use]
    pub const fn parameter_bytes(&self) -> usize {
        self.parameter_bytes
    }

    pub(crate) fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }
}

impl fmt::Debug for MycVerifiedNip46Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycVerifiedNip46Request")
            .field("method", &"[redacted]")
            .field("canonical_bytes", &self.canonical_request.len())
            .field("parameter_count", &self.parameter_count)
            .field("parameter_bytes", &self.parameter_bytes)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Verifies one already bounded encrypted NIP-46 event without decrypting it.
pub fn verify_myc_nip46_event(
    bounded: MycBoundedNip46Event,
    expected_transport: &MycProviderBinding,
    observed_at: MycNip46ObservedAtUnixSeconds,
    authored_time_policy: MycNip46AuthoredTimePolicy,
) -> Result<MycVerifiedNip46Event, MycNip46VerificationError> {
    if expected_transport.role() != MycProviderRole::Transport {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidTransportBinding,
        ));
    }
    let expected_receiver = expected_transport.expected_identity();
    let (original, encrypted_content) = bounded.into_verification_parts();
    let canonical: CanonicalEventFields<'_> = serde_json::from_slice(&original)
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::MalformedEvent))?;
    let event: Event = serde_json::from_slice(&original)
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::MalformedEvent))?;

    if canonical.id != event.id.to_hex()
        || canonical.pubkey != event.pubkey.to_hex()
        || canonical.sig != event.sig.to_string()
        || canonical.created_at != event.created_at.as_secs()
        || canonical.kind != u64::from(event.kind.as_u16())
        || canonical.content != event.content
    {
        return Err(verification_error(
            MycNip46VerificationErrorKind::NonCanonicalEvent,
        ));
    }
    if event.kind != Kind::Custom(RPC_KIND) {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidKind,
        ));
    }
    let client_public_key = MycNip46ClientPublicKey::new(&event.pubkey.to_hex())
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::InvalidSender))?;
    if event.pubkey.to_hex() == expected_receiver.as_hex() {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidSender,
        ));
    }
    let expected_recipient = ["p", expected_receiver.as_hex()];
    if event.tags.len() != 1
        || event.tags.as_slice()[0]
            .as_slice()
            .iter()
            .map(String::as_str)
            .ne(expected_recipient)
    {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidReceiver,
        ));
    }
    if !event.verify_id() {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidEventId,
        ));
    }
    if !event.verify_signature() {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidSignature,
        ));
    }
    verify_authored_time(
        event.created_at.as_secs(),
        observed_at.get(),
        authored_time_policy,
    )?;
    let encryption_context = verify_encryption_context(&encrypted_content)?;

    Ok(MycVerifiedNip46Event {
        original,
        encrypted_content,
        event_id: MycNip46EventId::from_bytes(event.id.to_bytes()),
        client_public_key,
        receiver_public_key: expected_receiver.clone(),
        authored_at_unix_seconds: event.created_at.as_secs(),
        encryption_context,
    })
}

/// Decodes one already bounded plaintext request through the canonical NIP-46 model.
pub fn verify_myc_nip46_request(
    bounded: MycBoundedNip46Request,
) -> Result<MycVerifiedNip46Request, MycNip46VerificationError> {
    let (plaintext, parameter_count, parameter_bytes) = bounded.into_verification_parts();
    let message: RequestMessage = serde_json::from_slice(&plaintext)
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::InvalidTypedRequest))?;
    let request_id = message
        .request_id()
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::InvalidTypedRequest))?;
    let request_id = MycNip46RequestId::new(request_id.as_str())
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::InvalidTypedRequest))?;
    let method = message.payload().method().to_string();
    if method.is_empty() || method.len() > METHOD_MAX_BYTES {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidTypedRequest,
        ));
    }
    let canonical_request = serde_json::to_vec(&message)
        .map_err(|_| verification_error(MycNip46VerificationErrorKind::InvalidTypedRequest))?;

    Ok(MycVerifiedNip46Request {
        request_id,
        method: method.into_boxed_str(),
        canonical_request: canonical_request.into_boxed_slice(),
        parameter_count,
        parameter_bytes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalEventFields<'a> {
    id: &'a str,
    pubkey: &'a str,
    created_at: u64,
    kind: u64,
    #[serde(rename = "tags")]
    _tags: serde::de::IgnoredAny,
    content: &'a str,
    sig: &'a str,
}

fn verify_authored_time(
    authored_at: u64,
    observed_at: u64,
    policy: MycNip46AuthoredTimePolicy,
) -> Result<(), MycNip46VerificationError> {
    let earliest = observed_at.saturating_sub(policy.maximum_past_seconds());
    let latest = observed_at.saturating_add(policy.maximum_future_seconds());
    if !(earliest..=latest).contains(&authored_at) {
        return Err(verification_error(
            MycNip46VerificationErrorKind::AuthoredTimeRejected,
        ));
    }
    Ok(())
}

fn verify_encryption_context(
    ciphertext: &str,
) -> Result<MycNip46EncryptionContext, MycNip46VerificationError> {
    if ciphertext.contains("?iv=") {
        verify_nip04_envelope(ciphertext)?;
        Ok(MycNip46EncryptionContext::Nip04)
    } else {
        verify_nip44_envelope(ciphertext)?;
        Ok(MycNip46EncryptionContext::Nip44V2)
    }
}

fn verify_nip04_envelope(ciphertext: &str) -> Result<(), MycNip46VerificationError> {
    let (encrypted, iv) = ciphertext
        .split_once("?iv=")
        .ok_or_else(|| verification_error(MycNip46VerificationErrorKind::InvalidNip04Envelope))?;
    if encrypted.is_empty() || iv.is_empty() || iv.contains("?iv=") {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidNip04Envelope,
        ));
    }
    let encrypted = decode_canonical_base64(
        encrypted,
        MycNip46VerificationErrorKind::InvalidNip04Envelope,
    )?;
    let iv = decode_canonical_base64(iv, MycNip46VerificationErrorKind::InvalidNip04Envelope)?;
    if encrypted.is_empty()
        || !encrypted.len().is_multiple_of(NIP04_BLOCK_BYTES)
        || iv.len() != NIP04_IV_BYTES
    {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidNip04Envelope,
        ));
    }
    Ok(())
}

fn verify_nip44_envelope(ciphertext: &str) -> Result<(), MycNip46VerificationError> {
    let decoded = decode_canonical_base64(
        ciphertext,
        MycNip46VerificationErrorKind::InvalidNip44Envelope,
    )?;
    if decoded.first() != Some(&NIP44_VERSION_V2) {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidNip44Envelope,
        ));
    }
    let overhead = 1usize
        .checked_add(NIP44_NONCE_BYTES)
        .and_then(|value| value.checked_add(NIP44_LENGTH_PREFIX_BYTES))
        .and_then(|value| value.checked_add(NIP44_HMAC_BYTES))
        .expect("fixed NIP-44 overhead fits usize");
    let padded = decoded
        .len()
        .checked_sub(overhead)
        .ok_or_else(|| verification_error(MycNip46VerificationErrorKind::InvalidNip44Envelope))?;
    if !is_valid_nip44_padding_length(padded) {
        return Err(verification_error(
            MycNip46VerificationErrorKind::InvalidNip44Envelope,
        ));
    }
    Ok(())
}

fn decode_canonical_base64(
    encoded: &str,
    kind: MycNip46VerificationErrorKind,
) -> Result<Vec<u8>, MycNip46VerificationError> {
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| verification_error(kind))?;
    if BASE64_STANDARD.encode(&decoded) != encoded {
        return Err(verification_error(kind));
    }
    Ok(decoded)
}

fn is_valid_nip44_padding_length(length: usize) -> bool {
    if !(NIP44_MIN_PADDED_BYTES..=NIP44_MAX_PADDED_BYTES).contains(&length) {
        return false;
    }
    if length <= 256 {
        return length.is_power_of_two();
    }
    let exponent = usize::BITS - 1 - length.leading_zeros();
    let chunk = 1usize << (exponent - 3);
    length.is_multiple_of(chunk)
}

const fn verification_error(kind: MycNip46VerificationErrorKind) -> MycNip46VerificationError {
    MycNip46VerificationError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_time_boundaries_are_inclusive_and_checked() {
        let policy = MycNip46AuthoredTimePolicy::new(10, 2).expect("policy");
        assert!(verify_authored_time(90, 100, policy).is_ok());
        assert!(verify_authored_time(102, 100, policy).is_ok());
        assert_eq!(
            verify_authored_time(89, 100, policy).unwrap_err().kind(),
            MycNip46VerificationErrorKind::AuthoredTimeRejected
        );
        assert_eq!(
            verify_authored_time(103, 100, policy).unwrap_err().kind(),
            MycNip46VerificationErrorKind::AuthoredTimeRejected
        );
    }

    #[test]
    fn every_protocol_padding_boundary_is_closed() {
        for valid in [32, 64, 128, 256, 288, 320, 65_536] {
            assert!(is_valid_nip44_padding_length(valid));
        }
        for invalid in [0, 31, 33, 257, 287, 65_535, 65_537] {
            assert!(!is_valid_nip44_padding_length(invalid));
        }
    }

    #[test]
    fn every_error_is_fixed_and_source_free() {
        for kind in [
            MycNip46VerificationErrorKind::InvalidObservationTime,
            MycNip46VerificationErrorKind::InvalidTimePolicy,
            MycNip46VerificationErrorKind::InvalidTransportBinding,
            MycNip46VerificationErrorKind::MalformedEvent,
            MycNip46VerificationErrorKind::NonCanonicalEvent,
            MycNip46VerificationErrorKind::InvalidKind,
            MycNip46VerificationErrorKind::InvalidSender,
            MycNip46VerificationErrorKind::InvalidReceiver,
            MycNip46VerificationErrorKind::InvalidEventId,
            MycNip46VerificationErrorKind::InvalidSignature,
            MycNip46VerificationErrorKind::AuthoredTimeRejected,
            MycNip46VerificationErrorKind::InvalidNip04Envelope,
            MycNip46VerificationErrorKind::InvalidNip44Envelope,
            MycNip46VerificationErrorKind::InvalidTypedRequest,
        ] {
            let error = verification_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
    }
}
