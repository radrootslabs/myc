//! Durable NIP-46 request identity and idempotent admission.

use core::fmt;
use std::error::Error;

use nostr::PublicKey;
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind,
    state_repository::{PersistedMetadata, RepositoryOperationError, require_expected_metadata},
};

/// Maximum UTF-8 byte length of a canonical NIP-46 request identifier.
pub const MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES: usize = 128;

/// Maximum canonical decrypted request bytes accepted by the state boundary.
pub const MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES: usize = 262_144;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"radroots.myc.nip46.request.v1\0";
const REQUEST_IDENTITY_DOMAIN: &[u8] = b"radroots.myc.nip46.request_identity.v1\0";
const OPERATION_ID_DOMAIN: &[u8] = b"radroots.myc.nip46.operation.v1\0";
const CORRELATION_ID_DOMAIN: &[u8] = b"radroots.myc.nip46.correlation.v1\0";

const READ_BY_DEDUP_SQL: &str = r#"SELECT
    CASE WHEN typeof(r.operation_id) = 'blob' AND length(r.operation_id) = 32
        THEN r.operation_id ELSE NULL END AS operation_id,
    CASE WHEN typeof(r.correlation_id) = 'blob' AND length(r.correlation_id) = 32
        THEN r.correlation_id ELSE NULL END AS correlation_id,
    CASE WHEN typeof(r.operation_nonce) = 'blob' AND length(r.operation_nonce) = 32
        THEN r.operation_nonce ELSE NULL END AS operation_nonce,
    CASE
        WHEN typeof(r.request_identity_sha256) = 'blob'
            AND length(r.request_identity_sha256) = 32
        THEN r.request_identity_sha256
        ELSE NULL
    END AS request_identity_sha256,
    CASE
        WHEN typeof(selected.request_sha256) = 'blob'
            AND length(selected.request_sha256) = 32
        THEN selected.request_sha256
        ELSE NULL
    END AS selected_request_sha256,
    CASE
        WHEN typeof(request_dedup.request_sha256) = 'blob'
            AND length(request_dedup.request_sha256) = 32
        THEN request_dedup.request_sha256
        ELSE NULL
    END AS logical_request_sha256,
    CASE
        WHEN typeof(request_dedup.operation_id) = 'blob'
            AND length(request_dedup.operation_id) = 32
        THEN request_dedup.operation_id
        ELSE NULL
    END AS logical_operation_id,
    CASE
        WHEN typeof(r.client_public_key) = 'text'
            AND length(CAST(r.client_public_key AS BLOB)) = 64
        THEN r.client_public_key
        ELSE NULL
    END AS client_public_key,
    CASE
        WHEN typeof(r.request_id) = 'text'
            AND length(CAST(r.request_id AS BLOB)) BETWEEN 1 AND 128
        THEN r.request_id
        ELSE NULL
    END AS request_id,
    CASE WHEN typeof(r.first_event_id) = 'blob' AND length(r.first_event_id) = 32
        THEN r.first_event_id ELSE NULL END AS first_event_id,
    CASE
        WHEN typeof(r.method) = 'text'
            AND length(CAST(r.method AS BLOB)) BETWEEN 1 AND 64
        THEN r.method
        ELSE NULL
    END AS method,
    CASE WHEN typeof(r.request_sha256) = 'blob' AND length(r.request_sha256) = 32
        THEN r.request_sha256 ELSE NULL END AS request_sha256,
    CASE
        WHEN typeof(r.received_at_unix_ms) = 'integer'
            AND r.received_at_unix_ms BETWEEN 1 AND 9223372036854775807
        THEN r.received_at_unix_ms
        ELSE NULL
    END AS received_at_unix_ms,
    CASE
        WHEN typeof(request_dedup.replay_count) = 'integer'
            AND request_dedup.replay_count BETWEEN 0 AND 9223372036854775807
        THEN request_dedup.replay_count
        ELSE NULL
    END AS replay_count,
    CASE
        WHEN typeof(request_dedup.conflict_count) = 'integer'
            AND request_dedup.conflict_count BETWEEN 0 AND 9223372036854775807
        THEN request_dedup.conflict_count
        ELSE NULL
    END AS conflict_count,
    CASE
        WHEN typeof(request_dedup.last_seen_at_unix_ms) = 'integer'
            AND request_dedup.last_seen_at_unix_ms BETWEEN 1 AND 9223372036854775807
        THEN request_dedup.last_seen_at_unix_ms
        ELSE NULL
    END AS last_seen_at_unix_ms
FROM nip46_request_dedup AS selected
JOIN nip46_requests AS r ON r.operation_id = selected.operation_id
JOIN nip46_request_dedup AS request_dedup
  ON request_dedup.dedup_kind = 'request'
 AND request_dedup.identity_sha256 = r.request_identity_sha256
WHERE selected.dedup_kind = ? AND selected.identity_sha256 = ?
LIMIT 2"#;

const INSERT_REQUEST_SQL: &str = r#"INSERT INTO nip46_requests (
    operation_id,
    correlation_id,
    operation_nonce,
    request_identity_sha256,
    client_public_key,
    request_id,
    first_event_id,
    method,
    request_sha256,
    received_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

const INSERT_DEDUP_SQL: &str = r#"INSERT INTO nip46_request_dedup (
    dedup_kind,
    identity_sha256,
    request_sha256,
    operation_id,
    replay_count,
    conflict_count,
    first_seen_at_unix_ms,
    last_seen_at_unix_ms
) VALUES (?, ?, ?, ?, ?, 0, ?, ?)"#;

const RECORD_REPLAY_SQL: &str = r#"UPDATE nip46_request_dedup
SET replay_count = replay_count + 1,
    last_seen_at_unix_ms = MAX(last_seen_at_unix_ms, ?)
WHERE dedup_kind = ?
  AND identity_sha256 = ?
  AND replay_count < 9223372036854775807"#;

const RECORD_CONFLICT_SQL: &str = r#"UPDATE nip46_request_dedup
SET conflict_count = conflict_count + 1,
    last_seen_at_unix_ms = MAX(last_seen_at_unix_ms, ?)
WHERE dedup_kind = ?
  AND identity_sha256 = ?
  AND conflict_count < 9223372036854775807"#;

/// A bounded canonical NIP-46 request ID.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MycNip46RequestId(Box<str>);

impl MycNip46RequestId {
    /// Validates borrowed input before allocating an owned identifier.
    pub fn new(value: &str) -> Result<Self, MycSignerRequestError> {
        if value.is_empty()
            || value.len() > MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(MycSignerRequestError::new(
                MycSignerRequestErrorKind::InvalidRequestId,
            ));
        }
        Ok(Self(value.into()))
    }

    /// Returns the exact canonical request ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MycNip46RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNip46RequestId([redacted])")
    }
}

/// One validated NIP-46 client public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MycNip46ClientPublicKey(Box<str>);

impl MycNip46ClientPublicKey {
    /// Parses one canonical lowercase 32-byte x-only public key.
    pub fn new(value: &str) -> Result<Self, MycSignerRequestError> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(MycSignerRequestError::new(
                MycSignerRequestErrorKind::InvalidClientIdentity,
            ));
        }
        let public_key = PublicKey::from_hex(value).map_err(|_| {
            MycSignerRequestError::new(MycSignerRequestErrorKind::InvalidClientIdentity)
        })?;
        if public_key.to_hex() != value {
            return Err(MycSignerRequestError::new(
                MycSignerRequestErrorKind::InvalidClientIdentity,
            ));
        }
        Ok(Self(value.into()))
    }

    /// Returns the canonical public identity.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MycNip46ClientPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNip46ClientPublicKey([redacted])")
    }
}

macro_rules! redacted_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

redacted_digest!(MycNip46EventId);
redacted_digest!(MycSignerRequestDigest);
redacted_digest!(MycSignerOperationId);
redacted_digest!(MycSignerCorrelationId);

impl MycSignerOperationId {
    pub(crate) const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// One-use entropy evidence for a new logical signer operation.
///
/// The runtime obtains these bytes from its injected entropy source. Admission
/// consumes the value, binds it to the logical request identity, and persists
/// it so the resulting operation identity can be revalidated after restart.
#[derive(PartialEq, Eq)]
pub struct MycSignerOperationNonce([u8; 32]);

impl MycSignerOperationNonce {
    /// Wraps exact bytes supplied by the injected entropy boundary.
    #[must_use]
    pub const fn from_injected_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycSignerOperationNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycSignerOperationNonce([redacted])")
    }
}

impl MycNip46EventId {
    /// Constructs an event identity from an already verified NIP-01 event ID.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl MycSignerRequestDigest {
    /// Hashes exact canonical decrypted request bytes under the Myc domain.
    pub fn for_canonical_request(bytes: &[u8]) -> Result<Self, MycSignerRequestError> {
        if bytes.is_empty() || bytes.len() > MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES {
            return Err(MycSignerRequestError::new(
                MycSignerRequestErrorKind::InvalidCanonicalRequest,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        hasher.update(
            u64::try_from(bytes.len())
                .expect("bounded request length fits u64")
                .to_be_bytes(),
        );
        hasher.update(bytes);
        Ok(Self(hasher.finalize().into()))
    }
}

/// Exact supported NIP-46 method identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycSignerRequestMethod {
    Connect,
    GetPublicKey,
    GetSessionCapability,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
    Ping,
    SwitchRelays,
    Logout,
}

impl MycSignerRequestMethod {
    /// Returns the canonical NIP-46 wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::GetPublicKey => "get_public_key",
            Self::GetSessionCapability => "get_session_capability",
            Self::SignEvent => "sign_event",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Ping => "ping",
            Self::SwitchRelays => "switch_relays",
            Self::Logout => "logout",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "connect" => Some(Self::Connect),
            "get_public_key" => Some(Self::GetPublicKey),
            "get_session_capability" => Some(Self::GetSessionCapability),
            "sign_event" => Some(Self::SignEvent),
            "nip04_encrypt" => Some(Self::Nip04Encrypt),
            "nip04_decrypt" => Some(Self::Nip04Decrypt),
            "nip44_encrypt" => Some(Self::Nip44Encrypt),
            "nip44_decrypt" => Some(Self::Nip44Decrypt),
            "ping" => Some(Self::Ping),
            "switch_relays" => Some(Self::SwitchRelays),
            "logout" => Some(Self::Logout),
            _ => None,
        }
    }
}

/// Positive UTC millisecond instant at which a request reached admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycRequestReceivedAtUnixMs(u64);

impl MycRequestReceivedAtUnixMs {
    /// Validates a positive instant representable by SQLite's signed integer.
    pub fn new(value: u64) -> Result<Self, MycSignerRequestError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(MycSignerRequestError::new(
                MycSignerRequestErrorKind::InvalidReceivedAt,
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the validated UTC millisecond instant.
    pub const fn get(self) -> u64 {
        self.0
    }

    fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated request time fits SQLite integer")
    }
}

/// Fully validated request-admission input.
#[derive(PartialEq, Eq)]
pub struct MycSignerRequest {
    client_public_key: MycNip46ClientPublicKey,
    request_id: MycNip46RequestId,
    event_id: MycNip46EventId,
    method: MycSignerRequestMethod,
    request_digest: MycSignerRequestDigest,
    request_identity: [u8; 32],
    operation_nonce: MycSignerOperationNonce,
    received_at: MycRequestReceivedAtUnixMs,
}

impl MycSignerRequest {
    /// Binds validated input to one caller-supplied injected-entropy value.
    #[must_use]
    pub fn new(
        client_public_key: MycNip46ClientPublicKey,
        request_id: MycNip46RequestId,
        event_id: MycNip46EventId,
        method: MycSignerRequestMethod,
        request_digest: MycSignerRequestDigest,
        operation_nonce: MycSignerOperationNonce,
        received_at: MycRequestReceivedAtUnixMs,
    ) -> Self {
        let request_identity = derive_request_identity(&client_public_key, &request_id);
        Self {
            client_public_key,
            request_id,
            event_id,
            method,
            request_digest,
            request_identity,
            operation_nonce,
            received_at,
        }
    }

    fn owned(&self) -> Self {
        Self {
            client_public_key: self.client_public_key.clone(),
            request_id: self.request_id.clone(),
            event_id: self.event_id,
            method: self.method,
            request_digest: self.request_digest,
            request_identity: self.request_identity,
            operation_nonce: MycSignerOperationNonce(self.operation_nonce.0),
            received_at: self.received_at,
        }
    }

    pub(crate) const fn client_public_key(&self) -> &MycNip46ClientPublicKey {
        &self.client_public_key
    }

    pub(crate) const fn request_id(&self) -> &MycNip46RequestId {
        &self.request_id
    }

    pub(crate) const fn event_id(&self) -> MycNip46EventId {
        self.event_id
    }

    pub(crate) const fn method(&self) -> MycSignerRequestMethod {
        self.method
    }

    pub(crate) const fn request_digest(&self) -> MycSignerRequestDigest {
        self.request_digest
    }

    pub(crate) const fn received_at(&self) -> MycRequestReceivedAtUnixMs {
        self.received_at
    }

    fn derived_operation_id(&self) -> MycSignerOperationId {
        MycSignerOperationId(derive_operation_id(
            &self.request_identity,
            &self.operation_nonce,
        ))
    }

    fn derived_correlation_id(&self) -> MycSignerCorrelationId {
        MycSignerCorrelationId(derive_digest(
            CORRELATION_ID_DOMAIN,
            self.derived_operation_id().as_bytes(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn admitted_record_for_test(&self) -> MycSignerRequestRecord {
        MycSignerRequestRecord {
            operation_id: self.derived_operation_id(),
            correlation_id: self.derived_correlation_id(),
            client_public_key: self.client_public_key.clone(),
            request_id: self.request_id.clone(),
            first_event_id: self.event_id,
            method: self.method,
            request_digest: self.request_digest,
            received_at: self.received_at,
            replay_count: 0,
            conflict_count: 0,
            last_seen_at: self.received_at,
        }
    }
}

impl fmt::Debug for MycSignerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycSignerRequest([redacted])")
    }
}

/// Durable state of one accepted logical NIP-46 request.
#[derive(Clone, PartialEq, Eq)]
pub struct MycSignerRequestRecord {
    operation_id: MycSignerOperationId,
    correlation_id: MycSignerCorrelationId,
    client_public_key: MycNip46ClientPublicKey,
    request_id: MycNip46RequestId,
    first_event_id: MycNip46EventId,
    method: MycSignerRequestMethod,
    request_digest: MycSignerRequestDigest,
    received_at: MycRequestReceivedAtUnixMs,
    replay_count: u64,
    conflict_count: u64,
    last_seen_at: MycRequestReceivedAtUnixMs,
}

impl MycSignerRequestRecord {
    #[must_use]
    /// Returns the stable logical operation identity.
    pub const fn operation_id(&self) -> MycSignerOperationId {
        self.operation_id
    }

    #[must_use]
    /// Returns the stable correlation identity.
    pub const fn correlation_id(&self) -> MycSignerCorrelationId {
        self.correlation_id
    }

    #[must_use]
    /// Returns the closed request method recorded for the operation.
    pub const fn method(&self) -> MycSignerRequestMethod {
        self.method
    }

    #[must_use]
    /// Returns the number of accepted exact replays.
    pub const fn replay_count(&self) -> u64 {
        self.replay_count
    }

    #[must_use]
    /// Returns the number of rejected conflicting reuses.
    pub const fn conflict_count(&self) -> u64 {
        self.conflict_count
    }

    pub(crate) fn matches_request(&self, request: &MycSignerRequest) -> bool {
        self.operation_id == request.derived_operation_id()
            && self.correlation_id == request.derived_correlation_id()
            && &self.client_public_key == request.client_public_key()
            && &self.request_id == request.request_id()
            && self.first_event_id == request.event_id()
            && self.method == request.method()
            && self.request_digest == request.request_digest()
            && self.received_at == request.received_at()
    }

    pub(crate) const fn received_at(&self) -> MycRequestReceivedAtUnixMs {
        self.received_at
    }
}

impl fmt::Debug for MycSignerRequestRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycSignerRequestRecord")
            .field("method", &self.method)
            .field("replay_count", &self.replay_count)
            .field("conflict_count", &self.conflict_count)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Idempotent result of durable request admission.
#[derive(Clone, PartialEq, Eq)]
pub enum MycSignerRequestAdmission {
    Admitted(MycSignerRequestRecord),
    ExactReplay(MycSignerRequestRecord),
    ConflictingReuse(MycSignerRequestRecord),
}

impl MycSignerRequestAdmission {
    #[must_use]
    /// Returns the durable record associated with the admission outcome.
    pub const fn record(&self) -> &MycSignerRequestRecord {
        match self {
            Self::Admitted(record) | Self::ExactReplay(record) | Self::ConflictingReuse(record) => {
                record
            }
        }
    }
}

impl fmt::Debug for MycSignerRequestAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admitted(_) => "MycSignerRequestAdmission::Admitted([redacted])",
            Self::ExactReplay(_) => "MycSignerRequestAdmission::ExactReplay([redacted])",
            Self::ConflictingReuse(_) => "MycSignerRequestAdmission::ConflictingReuse([redacted])",
        })
    }
}

/// Stable source-free input failure for request construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycSignerRequestErrorKind {
    InvalidRequestId,
    InvalidClientIdentity,
    InvalidCanonicalRequest,
    InvalidReceivedAt,
}

impl MycSignerRequestErrorKind {
    #[must_use]
    /// Returns the stable machine-readable classification.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequestId => "signer_request_id_invalid",
            Self::InvalidClientIdentity => "signer_request_client_identity_invalid",
            Self::InvalidCanonicalRequest => "signer_request_payload_invalid",
            Self::InvalidReceivedAt => "signer_request_time_invalid",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycSignerRequestError {
    kind: MycSignerRequestErrorKind,
}

impl MycSignerRequestError {
    const fn new(kind: MycSignerRequestErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    /// Returns the stable failure class.
    pub const fn kind(self) -> MycSignerRequestErrorKind {
        self.kind
    }

    #[must_use]
    /// Returns the stable machine-readable failure code.
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycSignerRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycSignerRequestErrorKind::InvalidRequestId => "NIP-46 request ID is invalid",
            MycSignerRequestErrorKind::InvalidClientIdentity => "NIP-46 client identity is invalid",
            MycSignerRequestErrorKind::InvalidCanonicalRequest => {
                "canonical NIP-46 request is invalid"
            }
            MycSignerRequestErrorKind::InvalidReceivedAt => "NIP-46 request time is invalid",
        })
    }
}

impl fmt::Debug for MycSignerRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycSignerRequestError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycSignerRequestError {}

impl MycStateRepository<'_> {
    /// Atomically admits a new request, replays an exact request, or records conflict.
    pub async fn admit_signer_request(
        &self,
        request: &MycSignerRequest,
    ) -> Result<MycSignerRequestAdmission, MycStateRepositoryError> {
        let request = request.owned();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(|error| match error {
                            RepositoryOperationError::Binding => RequestOperationError::Binding,
                            RepositoryOperationError::Storage => RequestOperationError::Storage,
                        })?;
                    admit_request(transaction, &request).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestOperationError {
    Binding,
    Storage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DedupKind {
    Request,
    Event,
}

impl DedupKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Event => "event",
        }
    }
}

async fn admit_request(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycSignerRequest,
) -> Result<MycSignerRequestAdmission, RequestOperationError> {
    let request_match =
        read_by_dedup(transaction, DedupKind::Request, &request.request_identity).await?;
    let event_match =
        read_by_dedup(transaction, DedupKind::Event, request.event_id.as_bytes()).await?;

    match (request_match, event_match) {
        (None, None) => insert_new_request(transaction, request).await,
        (Some(existing), event) if exact_request(&existing, request) => {
            if let Some(event) = event {
                if event.operation_id != existing.operation_id {
                    record_conflict(
                        transaction,
                        DedupKind::Request,
                        &request.request_identity,
                        request.received_at,
                    )
                    .await?;
                    return read_outcome(
                        transaction,
                        DedupKind::Request,
                        &request.request_identity,
                        MycSignerRequestAdmission::ConflictingReuse,
                    )
                    .await;
                }
                record_replay(
                    transaction,
                    DedupKind::Event,
                    request.event_id.as_bytes(),
                    request.received_at,
                )
                .await?;
            } else {
                insert_dedup(
                    transaction,
                    DedupKind::Event,
                    request.event_id.as_bytes(),
                    request.request_digest.as_bytes(),
                    existing.operation_id.as_bytes(),
                    0,
                    request.received_at,
                )
                .await?;
            }
            record_replay(
                transaction,
                DedupKind::Request,
                &request.request_identity,
                request.received_at,
            )
            .await?;
            read_outcome(
                transaction,
                DedupKind::Request,
                &request.request_identity,
                MycSignerRequestAdmission::ExactReplay,
            )
            .await
        }
        (Some(_), _) => {
            record_conflict(
                transaction,
                DedupKind::Request,
                &request.request_identity,
                request.received_at,
            )
            .await?;
            read_outcome(
                transaction,
                DedupKind::Request,
                &request.request_identity,
                MycSignerRequestAdmission::ConflictingReuse,
            )
            .await
        }
        (None, Some(_)) => {
            record_conflict(
                transaction,
                DedupKind::Event,
                request.event_id.as_bytes(),
                request.received_at,
            )
            .await?;
            let record = read_by_dedup(transaction, DedupKind::Event, request.event_id.as_bytes())
                .await?
                .ok_or(RequestOperationError::Binding)?;
            Ok(MycSignerRequestAdmission::ConflictingReuse(record))
        }
    }
}

async fn insert_new_request(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycSignerRequest,
) -> Result<MycSignerRequestAdmission, RequestOperationError> {
    let operation_id = MycSignerOperationId(derive_operation_id(
        &request.request_identity,
        &request.operation_nonce,
    ));
    let correlation_id = MycSignerCorrelationId(derive_digest(
        CORRELATION_ID_DOMAIN,
        operation_id.as_bytes(),
    ));
    let result = sqlx::query(INSERT_REQUEST_SQL)
        .bind(operation_id.as_bytes().as_slice())
        .bind(correlation_id.as_bytes().as_slice())
        .bind(request.operation_nonce.0.as_slice())
        .bind(request.request_identity.as_slice())
        .bind(request.client_public_key.as_hex())
        .bind(request.request_id.as_str())
        .bind(request.event_id.as_bytes().as_slice())
        .bind(request.method.as_str())
        .bind(request.request_digest.as_bytes().as_slice())
        .bind(request.received_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RequestOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(RequestOperationError::Storage);
    }
    insert_dedup(
        transaction,
        DedupKind::Request,
        &request.request_identity,
        request.request_digest.as_bytes(),
        operation_id.as_bytes(),
        0,
        request.received_at,
    )
    .await?;
    insert_dedup(
        transaction,
        DedupKind::Event,
        request.event_id.as_bytes(),
        request.request_digest.as_bytes(),
        operation_id.as_bytes(),
        0,
        request.received_at,
    )
    .await?;
    read_outcome(
        transaction,
        DedupKind::Request,
        &request.request_identity,
        MycSignerRequestAdmission::Admitted,
    )
    .await
}

async fn insert_dedup(
    transaction: &mut ServiceSqliteTransaction<'_>,
    kind: DedupKind,
    identity: &[u8; 32],
    request_digest: &[u8; 32],
    operation_id: &[u8; 32],
    replay_count: i64,
    received_at: MycRequestReceivedAtUnixMs,
) -> Result<(), RequestOperationError> {
    let result = sqlx::query(INSERT_DEDUP_SQL)
        .bind(kind.as_str())
        .bind(identity.as_slice())
        .bind(request_digest.as_slice())
        .bind(operation_id.as_slice())
        .bind(replay_count)
        .bind(received_at.sqlite_value())
        .bind(received_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RequestOperationError::Storage)?;
    (result.rows_affected() == 1)
        .then_some(())
        .ok_or(RequestOperationError::Storage)
}

async fn record_replay(
    transaction: &mut ServiceSqliteTransaction<'_>,
    kind: DedupKind,
    identity: &[u8; 32],
    received_at: MycRequestReceivedAtUnixMs,
) -> Result<(), RequestOperationError> {
    update_counter(transaction, RECORD_REPLAY_SQL, kind, identity, received_at).await
}

async fn record_conflict(
    transaction: &mut ServiceSqliteTransaction<'_>,
    kind: DedupKind,
    identity: &[u8; 32],
    received_at: MycRequestReceivedAtUnixMs,
) -> Result<(), RequestOperationError> {
    update_counter(
        transaction,
        RECORD_CONFLICT_SQL,
        kind,
        identity,
        received_at,
    )
    .await
}

async fn update_counter(
    transaction: &mut ServiceSqliteTransaction<'_>,
    sql: &'static str,
    kind: DedupKind,
    identity: &[u8; 32],
    received_at: MycRequestReceivedAtUnixMs,
) -> Result<(), RequestOperationError> {
    let result = sqlx::query(sql)
        .bind(received_at.sqlite_value())
        .bind(kind.as_str())
        .bind(identity.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RequestOperationError::Storage)?;
    (result.rows_affected() == 1)
        .then_some(())
        .ok_or(RequestOperationError::Storage)
}

async fn read_outcome(
    transaction: &mut ServiceSqliteTransaction<'_>,
    kind: DedupKind,
    identity: &[u8; 32],
    outcome: fn(MycSignerRequestRecord) -> MycSignerRequestAdmission,
) -> Result<MycSignerRequestAdmission, RequestOperationError> {
    read_by_dedup(transaction, kind, identity)
        .await?
        .map(outcome)
        .ok_or(RequestOperationError::Binding)
}

async fn read_by_dedup(
    transaction: &mut ServiceSqliteTransaction<'_>,
    kind: DedupKind,
    identity: &[u8; 32],
) -> Result<Option<MycSignerRequestRecord>, RequestOperationError> {
    let rows = sqlx::query(READ_BY_DEDUP_SQL)
        .bind(kind.as_str())
        .bind(identity.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| RequestOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(RequestOperationError::Binding);
    }
    rows.first()
        .map(|row| parse_record(row, kind, identity))
        .transpose()
}

fn parse_record(
    row: &sqlx::sqlite::SqliteRow,
    selected_kind: DedupKind,
    selected_identity: &[u8; 32],
) -> Result<MycSignerRequestRecord, RequestOperationError> {
    let operation_id = MycSignerOperationId(exact_digest(row, "operation_id")?);
    let correlation_id = MycSignerCorrelationId(exact_digest(row, "correlation_id")?);
    let operation_nonce = exact_digest(row, "operation_nonce")?;
    let request_identity = exact_digest(row, "request_identity_sha256")?;
    let selected_request_digest = exact_digest(row, "selected_request_sha256")?;
    let logical_request_digest = exact_digest(row, "logical_request_sha256")?;
    let logical_operation_id = exact_digest(row, "logical_operation_id")?;
    let request_digest = exact_digest(row, "request_sha256")?;
    let client_public_key = MycNip46ClientPublicKey::new(bounded_text(row, "client_public_key")?)
        .map_err(|_| RequestOperationError::Binding)?;
    let request_id = MycNip46RequestId::new(bounded_text(row, "request_id")?)
        .map_err(|_| RequestOperationError::Binding)?;
    if (selected_kind == DedupKind::Request && selected_identity != &request_identity)
        || selected_request_digest != request_digest
        || logical_request_digest != request_digest
        || logical_operation_id != *operation_id.as_bytes()
        || derive_request_identity(&client_public_key, &request_id) != request_identity
        || derive_operation_id(&request_identity, &MycSignerOperationNonce(operation_nonce))
            != *operation_id.as_bytes()
        || derive_digest(CORRELATION_ID_DOMAIN, operation_id.as_bytes())
            != *correlation_id.as_bytes()
    {
        return Err(RequestOperationError::Binding);
    }
    let method = MycSignerRequestMethod::parse(bounded_text(row, "method")?)
        .ok_or(RequestOperationError::Binding)?;
    let received_at = bounded_time(row, "received_at_unix_ms")?;
    let last_seen_at = bounded_time(row, "last_seen_at_unix_ms")?;
    if last_seen_at < received_at {
        return Err(RequestOperationError::Binding);
    }
    Ok(MycSignerRequestRecord {
        operation_id,
        correlation_id,
        client_public_key,
        request_id,
        first_event_id: MycNip46EventId(exact_digest(row, "first_event_id")?),
        method,
        request_digest: MycSignerRequestDigest(request_digest),
        received_at,
        replay_count: bounded_count(row, "replay_count")?,
        conflict_count: bounded_count(row, "conflict_count")?,
        last_seen_at,
    })
}

fn exact_request(existing: &MycSignerRequestRecord, request: &MycSignerRequest) -> bool {
    existing.client_public_key == request.client_public_key
        && existing.request_id == request.request_id
        && existing.method == request.method
        && existing.request_digest == request.request_digest
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], RequestOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| RequestOperationError::Binding)?
        .ok_or(RequestOperationError::Binding)?
        .try_into()
        .map_err(|_| RequestOperationError::Binding)
}

fn bounded_text<'row>(
    row: &'row sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<&'row str, RequestOperationError> {
    row.try_get::<Option<&str>, _>(column)
        .map_err(|_| RequestOperationError::Binding)?
        .ok_or(RequestOperationError::Binding)
}

fn bounded_time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycRequestReceivedAtUnixMs, RequestOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| RequestOperationError::Binding)?;
    let value = u64::try_from(value).map_err(|_| RequestOperationError::Binding)?;
    MycRequestReceivedAtUnixMs::new(value).map_err(|_| RequestOperationError::Binding)
}

fn bounded_count(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, RequestOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| RequestOperationError::Binding)?;
    u64::try_from(value).map_err(|_| RequestOperationError::Binding)
}

pub(crate) fn derive_request_identity(
    client_public_key: &MycNip46ClientPublicKey,
    request_id: &MycNip46RequestId,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_IDENTITY_DOMAIN);
    update_length_prefixed(&mut hasher, client_public_key.as_hex().as_bytes());
    update_length_prefixed(&mut hasher, request_id.as_str().as_bytes());
    hasher.finalize().into()
}

fn derive_digest(domain: &[u8], value: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

fn derive_operation_id(request_identity: &[u8; 32], nonce: &MycSignerOperationNonce) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_ID_DOMAIN);
    hasher.update(request_identity);
    hasher.update(nonce.0);
    hasher.finalize().into()
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("bounded identity length fits u64")
            .to_be_bytes(),
    );
    hasher.update(value);
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<RequestOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(RequestOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(RequestOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
