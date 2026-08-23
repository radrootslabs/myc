//! Durable delivery-job identity, bounded target attempts, and lease evidence.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::MycSignerOperationId;
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};

/// Maximum immutable relay targets on one delivery job.
pub const MYC_DELIVERY_TARGET_MAX_COUNT: usize = 32;
/// Maximum durable attempts for one target.
pub const MYC_DELIVERY_ATTEMPT_MAX_COUNT: u32 = 32;
/// Maximum UTF-8 byte length of a canonical delivery relay identifier.
pub const MYC_DELIVERY_RELAY_ID_MAX_BYTES: usize = 64;
/// Maximum caller-injected full-jitter delay for one retry.
pub const MYC_DELIVERY_RETRY_JITTER_MAX_MS: u64 = 300_000;

const JOB_ID_DOMAIN: &[u8] = b"radroots.myc.delivery_job.v1\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"radroots.myc.delivery_attempt.v1\0";

const READ_ACTIVE_JOB_COUNT_SQL: &str =
    "SELECT COUNT(*) AS row_count FROM delivery_jobs WHERE status IN ('pending', 'active')";

const READ_RUNTIME_OUTBOX_STATUS_SQL: &str = r#"SELECT
    COUNT(CASE WHEN status IN ('pending', 'active') THEN 1 END) AS pending_count,
    (SELECT COUNT(*) FROM delivery_targets WHERE status = 'unknown') AS unknown_count,
    MIN(CASE WHEN status IN ('pending', 'active') THEN created_at_unix_ms ELSE NULL END)
        AS oldest_pending_at_unix_ms,
    typeof(MIN(CASE WHEN status IN ('pending', 'active') THEN created_at_unix_ms ELSE NULL END))
        AS oldest_pending_type
FROM delivery_jobs"#;

const READ_NEXT_READY_TARGET_SQL: &str = r#"SELECT
    CASE WHEN typeof(t.job_id) = 'blob' AND length(t.job_id) = 32
        THEN t.job_id ELSE NULL END AS job_id,
    CASE WHEN typeof(t.relay_id) = 'text'
        AND length(CAST(t.relay_id AS BLOB)) BETWEEN 1 AND 64
        THEN t.relay_id ELSE NULL END AS relay_id
FROM delivery_targets t
JOIN delivery_jobs j ON j.job_id = t.job_id
WHERE j.status IN ('pending', 'active')
    AND t.status IN ('pending', 'retryable', 'unknown')
    AND t.active_attempt_id IS NULL
    AND (t.next_attempt_at_unix_ms IS NULL OR t.next_attempt_at_unix_ms <= ?)
ORDER BY j.created_at_unix_ms, t.job_id, t.target_index
LIMIT 2"#;

const READ_JOB_SQL: &str = r#"SELECT
    CASE WHEN typeof(job_id) = 'blob' AND length(job_id) = 32
        THEN job_id ELSE NULL END AS job_id,
    CASE WHEN typeof(source_kind) = 'text' AND length(CAST(source_kind AS BLOB)) <= 32
        THEN source_kind ELSE NULL END AS source_kind,
    CASE WHEN typeof(source_id) = 'blob' AND length(source_id) = 32
        THEN source_id ELSE NULL END AS source_id,
    CASE WHEN typeof(artifact_sha256) = 'blob' AND length(artifact_sha256) = 32
        THEN artifact_sha256 ELSE NULL END AS artifact_sha256,
    CASE WHEN typeof(policy_mode) = 'text' AND length(CAST(policy_mode AS BLOB)) <= 32
        THEN policy_mode ELSE NULL END AS policy_mode,
    required_acknowledgements, max_attempts, initial_backoff_ms,
    maximum_backoff_ms, attempt_deadline_ms,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    created_at_unix_ms, updated_at_unix_ms, finalized_at_unix_ms,
    typeof(finalized_at_unix_ms) AS finalized_at_type
FROM delivery_jobs
WHERE job_id = ?
LIMIT 2"#;

const READ_JOB_BY_SOURCE_SQL: &str = r#"SELECT
    CASE WHEN typeof(job_id) = 'blob' AND length(job_id) = 32
        THEN job_id ELSE NULL END AS job_id,
    CASE WHEN typeof(source_kind) = 'text' AND length(CAST(source_kind AS BLOB)) <= 32
        THEN source_kind ELSE NULL END AS source_kind,
    CASE WHEN typeof(source_id) = 'blob' AND length(source_id) = 32
        THEN source_id ELSE NULL END AS source_id,
    CASE WHEN typeof(artifact_sha256) = 'blob' AND length(artifact_sha256) = 32
        THEN artifact_sha256 ELSE NULL END AS artifact_sha256,
    CASE WHEN typeof(policy_mode) = 'text' AND length(CAST(policy_mode AS BLOB)) <= 32
        THEN policy_mode ELSE NULL END AS policy_mode,
    required_acknowledgements, max_attempts, initial_backoff_ms,
    maximum_backoff_ms, attempt_deadline_ms,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    created_at_unix_ms, updated_at_unix_ms, finalized_at_unix_ms,
    typeof(finalized_at_unix_ms) AS finalized_at_type
FROM delivery_jobs
WHERE source_kind = ? AND source_id = ?
LIMIT 2"#;

const READ_TARGETS_SQL: &str = r#"SELECT
    target_index,
    CASE WHEN typeof(relay_id) = 'text'
        AND length(CAST(relay_id AS BLOB)) BETWEEN 1 AND 64
        THEN relay_id ELSE NULL END AS relay_id,
    required, attempt_count,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    CASE WHEN typeof(active_attempt_id) = 'blob' AND length(active_attempt_id) = 32
        THEN active_attempt_id ELSE NULL END AS active_attempt_id,
    typeof(active_attempt_id) AS active_attempt_id_type,
    next_attempt_at_unix_ms,
    typeof(next_attempt_at_unix_ms) AS next_attempt_at_type,
    updated_at_unix_ms
FROM delivery_targets
WHERE job_id = ?
ORDER BY target_index
LIMIT 33"#;

const READ_ATTEMPTS_SQL: &str = r#"SELECT
    CASE WHEN typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
        THEN attempt_id ELSE NULL END AS attempt_id,
    attempt_number,
    CASE WHEN typeof(attempt_nonce) = 'blob' AND length(attempt_nonce) = 32
        THEN attempt_nonce ELSE NULL END AS attempt_nonce,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    leased_at_unix_ms, lease_expires_at_unix_ms,
    submitted_at_unix_ms, typeof(submitted_at_unix_ms) AS submitted_at_type,
    resolved_at_unix_ms, typeof(resolved_at_unix_ms) AS resolved_at_type,
    CASE WHEN typeof(reason_code) = 'text' AND length(CAST(reason_code AS BLOB)) <= 32
        THEN reason_code ELSE NULL END AS reason_code,
    typeof(reason_code) AS reason_code_type
FROM delivery_attempts
WHERE job_id = ? AND target_index = ?
ORDER BY attempt_number
LIMIT 33"#;

const READ_ATTEMPT_SQL: &str = r#"SELECT
    CASE WHEN typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
        THEN attempt_id ELSE NULL END AS attempt_id,
    attempt_number,
    CASE WHEN typeof(attempt_nonce) = 'blob' AND length(attempt_nonce) = 32
        THEN attempt_nonce ELSE NULL END AS attempt_nonce,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    leased_at_unix_ms, lease_expires_at_unix_ms,
    submitted_at_unix_ms, typeof(submitted_at_unix_ms) AS submitted_at_type,
    resolved_at_unix_ms, typeof(resolved_at_unix_ms) AS resolved_at_type,
    CASE WHEN typeof(reason_code) = 'text' AND length(CAST(reason_code AS BLOB)) <= 32
        THEN reason_code ELSE NULL END AS reason_code,
    typeof(reason_code) AS reason_code_type
FROM delivery_attempts
WHERE job_id = ? AND target_index = ? AND attempt_id = ?
LIMIT 2"#;

const READ_ATTEMPT_BY_NONCE_SQL: &str = r#"SELECT
    CASE WHEN typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
        THEN attempt_id ELSE NULL END AS attempt_id,
    attempt_number,
    CASE WHEN typeof(attempt_nonce) = 'blob' AND length(attempt_nonce) = 32
        THEN attempt_nonce ELSE NULL END AS attempt_nonce,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    leased_at_unix_ms, lease_expires_at_unix_ms,
    submitted_at_unix_ms, typeof(submitted_at_unix_ms) AS submitted_at_type,
    resolved_at_unix_ms, typeof(resolved_at_unix_ms) AS resolved_at_type,
    CASE WHEN typeof(reason_code) = 'text' AND length(CAST(reason_code AS BLOB)) <= 32
        THEN reason_code ELSE NULL END AS reason_code,
    typeof(reason_code) AS reason_code_type
FROM delivery_attempts
WHERE job_id = ? AND target_index = ? AND attempt_nonce = ?
LIMIT 2"#;

const INSERT_JOB_SQL: &str = r#"INSERT INTO delivery_jobs (
    job_id, source_kind, source_id, artifact_sha256, policy_mode,
    required_acknowledgements, max_attempts, initial_backoff_ms,
    maximum_backoff_ms, attempt_deadline_ms, status,
    created_at_unix_ms, updated_at_unix_ms, finalized_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL)"#;

const INSERT_TARGET_SQL: &str = r#"INSERT INTO delivery_targets (
    job_id, target_index, relay_id, required, attempt_count, status,
    active_attempt_id, next_attempt_at_unix_ms, updated_at_unix_ms
) VALUES (?, ?, ?, ?, 0, 'pending', NULL, NULL, ?)"#;

const INSERT_ATTEMPT_SQL: &str = r#"INSERT INTO delivery_attempts (
    attempt_id, job_id, target_index, attempt_number, attempt_nonce, status,
    leased_at_unix_ms, lease_expires_at_unix_ms, submitted_at_unix_ms,
    resolved_at_unix_ms, reason_code
) VALUES (?, ?, ?, ?, ?, 'leased', ?, ?, NULL, NULL, NULL)"#;

const CLAIM_TARGET_SQL: &str = r#"UPDATE delivery_targets
SET attempt_count = ?, status = 'leased', active_attempt_id = ?,
    next_attempt_at_unix_ms = NULL, updated_at_unix_ms = ?
WHERE job_id = ? AND target_index = ? AND attempt_count = ?
    AND status IN ('pending', 'retryable', 'unknown')
    AND active_attempt_id IS NULL"#;

const MARK_JOB_ACTIVE_SQL: &str = r#"UPDATE delivery_jobs
SET status = 'active', updated_at_unix_ms = ?
WHERE job_id = ? AND status = 'pending'"#;

const MARK_ATTEMPT_SUBMITTED_SQL: &str = r#"UPDATE delivery_attempts
SET status = 'submitted', submitted_at_unix_ms = ?
WHERE attempt_id = ? AND job_id = ? AND target_index = ?
    AND status = 'leased' AND lease_expires_at_unix_ms >= ?"#;

const MARK_TARGET_SUBMITTED_SQL: &str = r#"UPDATE delivery_targets
SET status = 'submitted', updated_at_unix_ms = ?
WHERE job_id = ? AND target_index = ? AND active_attempt_id = ? AND status = 'leased'"#;

const RESOLVE_ATTEMPT_SQL: &str = r#"UPDATE delivery_attempts
SET status = ?, resolved_at_unix_ms = ?, reason_code = ?
WHERE attempt_id = ? AND job_id = ? AND target_index = ? AND status = ?"#;

const RESOLVE_TARGET_SQL: &str = r#"UPDATE delivery_targets
SET status = ?, active_attempt_id = NULL, next_attempt_at_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE job_id = ? AND target_index = ? AND active_attempt_id = ? AND status = ?"#;

const FINALIZE_JOB_SQL: &str = r#"UPDATE delivery_jobs
SET status = ?, updated_at_unix_ms = ?, finalized_at_unix_ms = ?
WHERE job_id = ? AND status IN ('pending', 'active')"#;

/// Stable source-free construction failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryStateErrorKind {
    InvalidTime,
    InvalidRelayId,
    InvalidPolicy,
    InvalidRetryJitter,
}

impl MycDeliveryStateErrorKind {
    /// Returns the stable machine-readable classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTime => "delivery_time_invalid",
            Self::InvalidRelayId => "delivery_relay_id_invalid",
            Self::InvalidPolicy => "delivery_policy_invalid",
            Self::InvalidRetryJitter => "delivery_retry_jitter_invalid",
        }
    }
}

/// Source-free delivery-state construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycDeliveryStateError {
    kind: MycDeliveryStateErrorKind,
}

impl MycDeliveryStateError {
    const fn new(kind: MycDeliveryStateErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycDeliveryStateErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycDeliveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycDeliveryStateErrorKind::InvalidTime => "delivery time is invalid",
            MycDeliveryStateErrorKind::InvalidRelayId => "delivery relay identity is invalid",
            MycDeliveryStateErrorKind::InvalidPolicy => "delivery policy is invalid",
            MycDeliveryStateErrorKind::InvalidRetryJitter => "delivery retry jitter is invalid",
        })
    }
}

impl fmt::Debug for MycDeliveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryStateError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycDeliveryStateError {}

/// Caller-injected full-jitter delay, later relationship-checked against a job.
///
/// The runtime entropy adapter owns generation. State code accepts only this
/// bounded value and persists the exact resulting retry schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycDeliveryRetryJitter(u64);

impl MycDeliveryRetryJitter {
    /// Validates one injected full-jitter delay.
    pub fn new(value_ms: u64) -> Result<Self, MycDeliveryStateError> {
        if value_ms > MYC_DELIVERY_RETRY_JITTER_MAX_MS {
            return Err(MycDeliveryStateError::new(
                MycDeliveryStateErrorKind::InvalidRetryJitter,
            ));
        }
        Ok(Self(value_ms))
    }

    /// Returns the exact injected delay in milliseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! redacted_id {
    ($name:ident, $debug:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
                formatter.write_str($debug)
            }
        }
    };
}

redacted_id!(MycDeliveryJobId, "MycDeliveryJobId([redacted])");
redacted_id!(MycDeliveryAttemptId, "MycDeliveryAttemptId([redacted])");
redacted_id!(
    MycDeliveryArtifactDigest,
    "MycDeliveryArtifactDigest([redacted])"
);

impl MycDeliveryJobId {
    pub(crate) const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl MycDeliveryArtifactDigest {
    /// Wraps an independently verified exact-artifact SHA-256 identity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// One-use injected entropy for a new delivery attempt lease.
pub struct MycDeliveryAttemptNonce([u8; 32]);

impl MycDeliveryAttemptNonce {
    /// Wraps exact entropy supplied by the caller's injected boundary.
    #[must_use]
    pub const fn from_injected_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycDeliveryAttemptNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDeliveryAttemptNonce([redacted])")
    }
}

/// Positive UTC millisecond evidence representable by SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycDeliveryTimeUnixMs(u64);

impl MycDeliveryTimeUnixMs {
    /// Validates one positive UTC millisecond instant.
    pub fn new(value: u64) -> Result<Self, MycDeliveryStateError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(MycDeliveryStateError::new(
                MycDeliveryStateErrorKind::InvalidTime,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated instant.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated delivery time fits SQLite")
    }
}

/// Canonical configured relay identifier used as a durable target identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycDeliveryRelayId(Box<str>);

impl MycDeliveryRelayId {
    /// Validates the frozen lower-snake relay grammar before allocation.
    pub fn new(value: &str) -> Result<Self, MycDeliveryStateError> {
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MYC_DELIVERY_RELAY_ID_MAX_BYTES
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
            && !bytes.windows(2).any(|window| window == b"__");
        if !valid {
            return Err(MycDeliveryStateError::new(
                MycDeliveryStateErrorKind::InvalidRelayId,
            ));
        }
        Ok(Self(value.into()))
    }

    /// Returns the canonical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MycDeliveryRelayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDeliveryRelayId([redacted])")
    }
}

/// Closed delivery-policy mode copied from normalized configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryPolicyMode {
    AtLeastOneRequired,
    AllRequired,
    RequiredQuorum,
}

impl MycDeliveryPolicyMode {
    /// Returns the exact durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtLeastOneRequired => "at_least_one_required",
            Self::AllRequired => "all_required",
            Self::RequiredQuorum => "required_quorum",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "at_least_one_required" => Some(Self::AtLeastOneRequired),
            "all_required" => Some(Self::AllRequired),
            "required_quorum" => Some(Self::RequiredQuorum),
            _ => None,
        }
    }
}

/// Immutable configured target identity.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MycDeliveryTargetPolicy {
    relay_id: MycDeliveryRelayId,
    required: bool,
}

/// Immutable configured delivery and retry authority.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MycDeliveryPolicies {
    mode: MycDeliveryPolicyMode,
    required_acknowledgements: u32,
    max_attempts: u32,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    attempt_deadline_ms: u64,
    outbox_maximum: usize,
    targets: Box<[MycDeliveryTargetPolicy]>,
}

impl MycDeliveryPolicies {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mode: MycDeliveryPolicyMode,
        configured_quorum: Option<u32>,
        max_attempts: u32,
        initial_backoff_ms: u64,
        maximum_backoff_ms: u64,
        attempt_deadline_ms: u64,
        outbox_maximum: usize,
        mut targets: Vec<(MycDeliveryRelayId, bool)>,
    ) -> Result<Self, MycDeliveryStateError> {
        targets.sort_by(|left, right| left.0.cmp(&right.0));
        let required_count = targets.iter().filter(|(_, required)| *required).count();
        let required_acknowledgements = match mode {
            MycDeliveryPolicyMode::AtLeastOneRequired => 1,
            MycDeliveryPolicyMode::AllRequired => u32::try_from(required_count).unwrap_or(u32::MAX),
            MycDeliveryPolicyMode::RequiredQuorum => configured_quorum.unwrap_or(0),
        };
        let valid = !targets.is_empty()
            && targets.len() <= MYC_DELIVERY_TARGET_MAX_COUNT
            && !targets.windows(2).any(|window| window[0].0 == window[1].0)
            && required_acknowledgements != 0
            && usize::try_from(required_acknowledgements)
                .is_ok_and(|required| required <= targets.len())
            && usize::try_from(required_acknowledgements)
                .is_ok_and(|required| required <= required_count)
            && (1..=MYC_DELIVERY_ATTEMPT_MAX_COUNT).contains(&max_attempts)
            && initial_backoff_ms != 0
            && initial_backoff_ms <= maximum_backoff_ms
            && maximum_backoff_ms <= 300_000
            && attempt_deadline_ms != 0
            && attempt_deadline_ms <= 30_000
            && (1..=65_536).contains(&outbox_maximum);
        if !valid {
            return Err(MycDeliveryStateError::new(
                MycDeliveryStateErrorKind::InvalidPolicy,
            ));
        }
        Ok(Self {
            mode,
            required_acknowledgements,
            max_attempts,
            initial_backoff_ms,
            maximum_backoff_ms,
            attempt_deadline_ms,
            outbox_maximum,
            targets: targets
                .into_iter()
                .map(|(relay_id, required)| MycDeliveryTargetPolicy { relay_id, required })
                .collect(),
        })
    }

    pub(crate) const fn outbox_maximum(&self) -> usize {
        self.outbox_maximum
    }
}

impl fmt::Debug for MycDeliveryPolicies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryPolicies")
            .field("mode", &self.mode)
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// Closed authority that produced the exact bytes retained by a delivery job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliverySourceKind {
    SignerResponse,
    DiscoveryHandler,
}

impl MycDeliverySourceKind {
    /// Returns the exact durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignerResponse => "signer_response",
            Self::DiscoveryHandler => "discovery_handler",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "signer_response" => Some(Self::SignerResponse),
            "discovery_handler" => Some(Self::DiscoveryHandler),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MycDeliverySource {
    kind: MycDeliverySourceKind,
    id: [u8; 32],
}

impl MycDeliverySource {
    pub(crate) const fn signer_response(operation_id: MycSignerOperationId) -> Self {
        Self {
            kind: MycDeliverySourceKind::SignerResponse,
            id: *operation_id.as_bytes(),
        }
    }

    pub(crate) const fn discovery_handler(generation_id: [u8; 32]) -> Self {
        Self {
            kind: MycDeliverySourceKind::DiscoveryHandler,
            id: generation_id,
        }
    }

    pub(crate) const fn kind(self) -> MycDeliverySourceKind {
        self.kind
    }

    pub(crate) const fn id(self) -> [u8; 32] {
        self.id
    }
}

impl fmt::Debug for MycDeliverySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliverySource")
            .field("kind", &self.kind)
            .field("id", &"[redacted]")
            .finish()
    }
}

/// Durable job state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryJobStatus {
    Pending,
    Active,
    Delivered,
    Failed,
    Unknown,
}

impl MycDeliveryJobStatus {
    /// Returns the exact durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "delivered" => Some(Self::Delivered),
            "failed" => Some(Self::Failed),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Durable per-target state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryTargetStatus {
    Pending,
    Leased,
    Submitted,
    Delivered,
    Retryable,
    Unknown,
    Exhausted,
}

impl MycDeliveryTargetStatus {
    /// Returns the exact durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Submitted => "submitted",
            Self::Delivered => "delivered",
            Self::Retryable => "retryable",
            Self::Unknown => "unknown",
            Self::Exhausted => "exhausted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "leased" => Some(Self::Leased),
            "submitted" => Some(Self::Submitted),
            "delivered" => Some(Self::Delivered),
            "retryable" => Some(Self::Retryable),
            "unknown" => Some(Self::Unknown),
            "exhausted" => Some(Self::Exhausted),
            _ => None,
        }
    }
}

/// Durable attempt state; `Unknown` is distinct from proof of failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryAttemptStatus {
    Leased,
    Submitted,
    Delivered,
    Failed,
    Unknown,
}

impl MycDeliveryAttemptStatus {
    /// Returns the exact durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::Submitted => "submitted",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "leased" => Some(Self::Leased),
            "submitted" => Some(Self::Submitted),
            "delivered" => Some(Self::Delivered),
            "failed" => Some(Self::Failed),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Closed evidence for a terminal attempt observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDeliveryAttemptOutcome {
    Delivered,
    RelayRejected,
    TransportFailed,
    UnknownAcknowledgement,
}

impl MycDeliveryAttemptOutcome {
    const fn status(self) -> MycDeliveryAttemptStatus {
        match self {
            Self::Delivered => MycDeliveryAttemptStatus::Delivered,
            Self::RelayRejected | Self::TransportFailed => MycDeliveryAttemptStatus::Failed,
            Self::UnknownAcknowledgement => MycDeliveryAttemptStatus::Unknown,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Delivered => "accepted",
            Self::RelayRejected => "relay_rejected",
            Self::TransportFailed => "transport_failed",
            Self::UnknownAcknowledgement => "acknowledgement_lost",
        }
    }
}

/// Immutable summary of one retained delivery job.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDeliveryJobRecord {
    id: MycDeliveryJobId,
    source: MycDeliverySource,
    artifact_digest: MycDeliveryArtifactDigest,
    policy_mode: MycDeliveryPolicyMode,
    required_acknowledgements: u32,
    max_attempts: u32,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    attempt_deadline_ms: u64,
    status: MycDeliveryJobStatus,
    created_at: MycDeliveryTimeUnixMs,
    updated_at: MycDeliveryTimeUnixMs,
    finalized_at: Option<MycDeliveryTimeUnixMs>,
    targets: Box<[MycDeliveryTargetRecord]>,
}

impl MycDeliveryJobRecord {
    pub(crate) const fn source_id(&self) -> &[u8; 32] {
        &self.source.id
    }

    #[must_use]
    pub const fn id(&self) -> MycDeliveryJobId {
        self.id
    }
    #[must_use]
    pub const fn operation_id(&self) -> Option<MycSignerOperationId> {
        match self.source.kind {
            MycDeliverySourceKind::SignerResponse => {
                Some(MycSignerOperationId::from_persisted(self.source.id))
            }
            MycDeliverySourceKind::DiscoveryHandler => None,
        }
    }
    #[must_use]
    pub const fn source_kind(&self) -> MycDeliverySourceKind {
        self.source.kind
    }
    #[must_use]
    pub const fn artifact_digest(&self) -> MycDeliveryArtifactDigest {
        self.artifact_digest
    }
    #[must_use]
    pub const fn policy_mode(&self) -> MycDeliveryPolicyMode {
        self.policy_mode
    }
    #[must_use]
    pub const fn required_acknowledgements(&self) -> u32 {
        self.required_acknowledgements
    }
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
    #[must_use]
    pub const fn initial_backoff_ms(&self) -> u64 {
        self.initial_backoff_ms
    }
    #[must_use]
    pub const fn maximum_backoff_ms(&self) -> u64 {
        self.maximum_backoff_ms
    }
    #[must_use]
    pub const fn attempt_deadline_ms(&self) -> u64 {
        self.attempt_deadline_ms
    }
    #[must_use]
    pub const fn status(&self) -> MycDeliveryJobStatus {
        self.status
    }
    #[must_use]
    pub const fn targets(&self) -> &[MycDeliveryTargetRecord] {
        &self.targets
    }
    #[must_use]
    pub const fn created_at(&self) -> MycDeliveryTimeUnixMs {
        self.created_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> MycDeliveryTimeUnixMs {
        self.updated_at
    }
    #[must_use]
    pub const fn finalized_at(&self) -> Option<MycDeliveryTimeUnixMs> {
        self.finalized_at
    }
}

impl fmt::Debug for MycDeliveryJobRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryJobRecord")
            .field("source_kind", &self.source.kind)
            .field("status", &self.status)
            .field("target_count", &self.targets.len())
            .finish()
    }
}

/// Immutable summary of one configured target and its current state.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDeliveryTargetRecord {
    index: u32,
    relay_id: MycDeliveryRelayId,
    required: bool,
    attempt_count: u32,
    status: MycDeliveryTargetStatus,
    active_attempt_id: Option<MycDeliveryAttemptId>,
    next_attempt_at: Option<MycDeliveryTimeUnixMs>,
    updated_at: MycDeliveryTimeUnixMs,
}

impl MycDeliveryTargetRecord {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }
    #[must_use]
    pub const fn relay_id(&self) -> &MycDeliveryRelayId {
        &self.relay_id
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }
    #[must_use]
    pub const fn status(&self) -> MycDeliveryTargetStatus {
        self.status
    }
    #[must_use]
    pub const fn active_attempt_id(&self) -> Option<MycDeliveryAttemptId> {
        self.active_attempt_id
    }
    #[must_use]
    pub const fn next_attempt_at(&self) -> Option<MycDeliveryTimeUnixMs> {
        self.next_attempt_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> MycDeliveryTimeUnixMs {
        self.updated_at
    }
}

impl fmt::Debug for MycDeliveryTargetRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryTargetRecord")
            .field("required", &self.required)
            .field("attempt_count", &self.attempt_count)
            .field("status", &self.status)
            .finish()
    }
}

/// Immutable identity plus append-only state for one bounded delivery attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDeliveryAttemptRecord {
    id: MycDeliveryAttemptId,
    number: u32,
    status: MycDeliveryAttemptStatus,
    leased_at: MycDeliveryTimeUnixMs,
    lease_expires_at: MycDeliveryTimeUnixMs,
    submitted_at: Option<MycDeliveryTimeUnixMs>,
    resolved_at: Option<MycDeliveryTimeUnixMs>,
    reason: Option<&'static str>,
}

impl MycDeliveryAttemptRecord {
    #[must_use]
    pub const fn id(&self) -> MycDeliveryAttemptId {
        self.id
    }
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }
    #[must_use]
    pub const fn status(&self) -> MycDeliveryAttemptStatus {
        self.status
    }
    #[must_use]
    pub const fn leased_at(&self) -> MycDeliveryTimeUnixMs {
        self.leased_at
    }
    #[must_use]
    pub const fn lease_expires_at(&self) -> MycDeliveryTimeUnixMs {
        self.lease_expires_at
    }
    #[must_use]
    pub const fn submitted_at(&self) -> Option<MycDeliveryTimeUnixMs> {
        self.submitted_at
    }
    #[must_use]
    pub const fn resolved_at(&self) -> Option<MycDeliveryTimeUnixMs> {
        self.resolved_at
    }
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        self.reason
    }
}

impl fmt::Debug for MycDeliveryAttemptRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryAttemptRecord")
            .field("number", &self.number)
            .field("status", &self.status)
            .finish()
    }
}

/// New or idempotently replayed delivery-job creation.
#[derive(Clone, PartialEq, Eq)]
pub enum MycDeliveryJobAdmission {
    Created(MycDeliveryJobRecord),
    ExactReplay(MycDeliveryJobRecord),
}

impl MycDeliveryJobAdmission {
    #[must_use]
    pub const fn record(&self) -> &MycDeliveryJobRecord {
        match self {
            Self::Created(record) | Self::ExactReplay(record) => record,
        }
    }
}

impl fmt::Debug for MycDeliveryJobAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Created(_) => "MycDeliveryJobAdmission::Created([redacted])",
            Self::ExactReplay(_) => "MycDeliveryJobAdmission::ExactReplay([redacted])",
        })
    }
}

/// Result of attempting to claim one target.
#[derive(Clone, PartialEq, Eq)]
pub enum MycDeliveryClaim {
    Claimed(MycDeliveryAttemptRecord),
    ExactReplay(MycDeliveryAttemptRecord),
    NotReady,
    Terminal,
}

impl fmt::Debug for MycDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Claimed(_) => "MycDeliveryClaim::Claimed([redacted])",
            Self::ExactReplay(_) => "MycDeliveryClaim::ExactReplay([redacted])",
            Self::NotReady => "MycDeliveryClaim::NotReady",
            Self::Terminal => "MycDeliveryClaim::Terminal",
        })
    }
}

impl MycStateRepository<'_> {
    pub(crate) async fn read_runtime_outbox_status(
        &self,
    ) -> Result<crate::MycOutboxStatusV1, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let rows = sqlx::query(READ_RUNTIME_OUTBOX_STATUS_SQL)
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| DeliveryOperationError::Storage)?;
                    let [row] = rows.as_slice() else {
                        return Err(DeliveryOperationError::Binding);
                    };
                    let count = |column| {
                        row.try_get::<i64, _>(column)
                            .ok()
                            .and_then(|value| u64::try_from(value).ok())
                            .ok_or(DeliveryOperationError::Binding)
                    };
                    let oldest = match row
                        .try_get::<&str, _>("oldest_pending_type")
                        .map_err(|_| DeliveryOperationError::Binding)?
                    {
                        "null" => None,
                        "integer" => {
                            let milliseconds = count("oldest_pending_at_unix_ms")?;
                            Some(
                                crate::MycStatusUnixSeconds::new(milliseconds / 1_000)
                                    .map_err(|_| DeliveryOperationError::Binding)?,
                            )
                        }
                        _ => return Err(DeliveryOperationError::Binding),
                    };
                    Ok(crate::MycOutboxStatusV1::new(
                        count("pending_count")?,
                        count("unknown_count")?,
                        oldest,
                    ))
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Returns the first exact target eligible for bounded delivery work.
    ///
    /// Selection is deterministic and performs no claim or network I/O. The
    /// subsequent claim transaction remains the sole lease authority.
    pub(crate) async fn next_ready_delivery_target(
        &self,
        observed_at: MycDeliveryTimeUnixMs,
    ) -> Result<Option<(MycDeliveryJobId, MycDeliveryRelayId)>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let rows = sqlx::query(READ_NEXT_READY_TARGET_SQL)
                        .bind(observed_at.sqlite_value())
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| DeliveryOperationError::Storage)?;
                    match rows.as_slice() {
                        [] => Ok(None),
                        [row] => {
                            let job_id = MycDeliveryJobId::from_persisted(blob32(row, "job_id")?);
                            let relay_id = MycDeliveryRelayId::new(text(row, "relay_id")?)
                                .map_err(|_| DeliveryOperationError::Binding)?;
                            Ok(Some((job_id, relay_id)))
                        }
                        _ => Err(DeliveryOperationError::Binding),
                    }
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Claims one eligible target under a bounded expiring attempt lease.
    pub async fn claim_delivery_target(
        &self,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
        nonce: MycDeliveryAttemptNonce,
        claimed_at: MycDeliveryTimeUnixMs,
    ) -> Result<MycDeliveryClaim, MycStateRepositoryError> {
        let relay_id = relay_id.clone();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    claim_target(transaction, job_id, &relay_id, &nonce, claimed_at).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Records that the exact leased attempt reached the external submission boundary.
    pub async fn mark_delivery_attempt_submitted(
        &self,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
        attempt_id: MycDeliveryAttemptId,
        submitted_at: MycDeliveryTimeUnixMs,
    ) -> Result<MycDeliveryAttemptRecord, MycStateRepositoryError> {
        let relay_id = relay_id.clone();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    mark_submitted(transaction, job_id, &relay_id, attempt_id, submitted_at).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Persists delivered, proven-failed, or unknown acknowledgement evidence.
    pub async fn record_delivery_attempt_outcome(
        &self,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
        attempt_id: MycDeliveryAttemptId,
        outcome: MycDeliveryAttemptOutcome,
        retry_jitter: MycDeliveryRetryJitter,
        observed_at: MycDeliveryTimeUnixMs,
    ) -> Result<MycDeliveryJobRecord, MycStateRepositoryError> {
        let relay_id = relay_id.clone();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    record_outcome(
                        transaction,
                        job_id,
                        &relay_id,
                        attempt_id,
                        outcome,
                        retry_jitter,
                        observed_at,
                    )
                    .await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Converts an expired pre-submit lease to failure or a submitted lease to unknown.
    pub async fn recover_expired_delivery_lease(
        &self,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
        attempt_id: MycDeliveryAttemptId,
        retry_jitter: MycDeliveryRetryJitter,
        observed_at: MycDeliveryTimeUnixMs,
    ) -> Result<MycDeliveryJobRecord, MycStateRepositoryError> {
        let relay_id = relay_id.clone();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    recover_expired(
                        transaction,
                        job_id,
                        &relay_id,
                        attempt_id,
                        retry_jitter,
                        observed_at,
                    )
                    .await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads one bounded job snapshot and its immutable target set.
    pub async fn read_delivery_job(
        &self,
        job_id: MycDeliveryJobId,
    ) -> Result<Option<MycDeliveryJobRecord>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    read_job(transaction, job_id).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads at most the configured 32 attempts for one retained target.
    pub async fn read_delivery_attempts(
        &self,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
    ) -> Result<Box<[MycDeliveryAttemptRecord]>, MycStateRepositoryError> {
        let relay_id = relay_id.clone();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let job = read_job(transaction, job_id)
                        .await?
                        .ok_or(DeliveryOperationError::Binding)?;
                    let target = target_by_relay(&job, &relay_id)?;
                    read_attempts(transaction, job_id, target.index).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryOperationError {
    Binding,
    Storage,
}

async fn verify_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), DeliveryOperationError> {
    require_expected_metadata(transaction, expected)
        .await
        .map_err(|error| match error {
            RepositoryOperationError::Binding => DeliveryOperationError::Binding,
            RepositoryOperationError::Storage => DeliveryOperationError::Storage,
        })
}

pub(crate) async fn create_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    source: MycDeliverySource,
    artifact_digest: MycDeliveryArtifactDigest,
    created_at: MycDeliveryTimeUnixMs,
    policy: &MycDeliveryPolicies,
) -> Result<MycDeliveryJobAdmission, DeliveryOperationError> {
    if let Some(existing) = read_job_by_source(transaction, source).await? {
        return exact_job(&existing, source, artifact_digest, created_at, policy)
            .then_some(MycDeliveryJobAdmission::ExactReplay(existing))
            .ok_or(DeliveryOperationError::Binding);
    }
    let active_jobs = sqlx::query(READ_ACTIVE_JOB_COUNT_SQL)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?
        .try_get::<i64, _>("row_count")
        .map_err(|_| DeliveryOperationError::Binding)?;
    if usize::try_from(active_jobs)
        .ok()
        .is_none_or(|count| count >= policy.outbox_maximum)
    {
        return Err(DeliveryOperationError::Binding);
    }
    let job_id = derive_job_id(source, artifact_digest);
    let result = sqlx::query(INSERT_JOB_SQL)
        .bind(job_id.as_bytes().as_slice())
        .bind(source.kind().as_str())
        .bind(source.id().as_slice())
        .bind(artifact_digest.as_bytes().as_slice())
        .bind(policy.mode.as_str())
        .bind(i64::from(policy.required_acknowledgements))
        .bind(i64::from(policy.max_attempts))
        .bind(
            i64::try_from(policy.initial_backoff_ms)
                .map_err(|_| DeliveryOperationError::Binding)?,
        )
        .bind(
            i64::try_from(policy.maximum_backoff_ms)
                .map_err(|_| DeliveryOperationError::Binding)?,
        )
        .bind(
            i64::try_from(policy.attempt_deadline_ms)
                .map_err(|_| DeliveryOperationError::Binding)?,
        )
        .bind(created_at.sqlite_value())
        .bind(created_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    for (index, target) in policy.targets.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| DeliveryOperationError::Binding)?;
        let result = sqlx::query(INSERT_TARGET_SQL)
            .bind(job_id.as_bytes().as_slice())
            .bind(i64::from(index))
            .bind(target.relay_id.as_str())
            .bind(target.required)
            .bind(created_at.sqlite_value())
            .execute(&mut *transaction)
            .await
            .map_err(|_| DeliveryOperationError::Storage)?;
        require_one(result.rows_affected())?;
    }
    let record = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    Ok(MycDeliveryJobAdmission::Created(record))
}

async fn claim_target(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    nonce: &MycDeliveryAttemptNonce,
    claimed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryClaim, DeliveryOperationError> {
    let job = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    if matches!(
        job.status,
        MycDeliveryJobStatus::Delivered
            | MycDeliveryJobStatus::Failed
            | MycDeliveryJobStatus::Unknown
    ) {
        return Ok(MycDeliveryClaim::Terminal);
    }
    let target = target_by_relay(&job, relay_id)?.clone();
    if let Some(existing) = read_attempt_by_nonce(transaction, job_id, target.index, nonce).await? {
        return Ok(MycDeliveryClaim::ExactReplay(existing));
    }
    if target.active_attempt_id.is_some()
        || target.next_attempt_at.is_some_and(|next| next > claimed_at)
    {
        return Ok(MycDeliveryClaim::NotReady);
    }
    if matches!(
        target.status,
        MycDeliveryTargetStatus::Delivered | MycDeliveryTargetStatus::Exhausted
    ) || target.attempt_count >= job.max_attempts
    {
        return Ok(MycDeliveryClaim::Terminal);
    }
    let attempt_number = target.attempt_count + 1;
    let lease_expires_value = claimed_at
        .get()
        .checked_add(job.attempt_deadline_ms)
        .ok_or(DeliveryOperationError::Binding)?;
    let lease_expires = MycDeliveryTimeUnixMs::new(lease_expires_value)
        .map_err(|_| DeliveryOperationError::Binding)?;
    let attempt_id = derive_attempt_id(job_id, target.index, attempt_number, nonce);
    let result = sqlx::query(INSERT_ATTEMPT_SQL)
        .bind(attempt_id.as_bytes().as_slice())
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(i64::from(attempt_number))
        .bind(nonce.0.as_slice())
        .bind(claimed_at.sqlite_value())
        .bind(lease_expires.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let result = sqlx::query(CLAIM_TARGET_SQL)
        .bind(i64::from(attempt_number))
        .bind(attempt_id.as_bytes().as_slice())
        .bind(claimed_at.sqlite_value())
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(i64::from(target.attempt_count))
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let result = sqlx::query(MARK_JOB_ACTIVE_SQL)
        .bind(claimed_at.sqlite_value())
        .bind(job_id.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    if result.rows_affected() > 1 {
        return Err(DeliveryOperationError::Storage);
    }
    let attempt = read_attempt(transaction, job_id, target.index, attempt_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    Ok(MycDeliveryClaim::Claimed(attempt))
}

async fn mark_submitted(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    attempt_id: MycDeliveryAttemptId,
    submitted_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryAttemptRecord, DeliveryOperationError> {
    let job = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    let target = target_by_relay(&job, relay_id)?;
    let attempt = read_attempt(transaction, job_id, target.index, attempt_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    if attempt.status == MycDeliveryAttemptStatus::Submitted {
        return (attempt.submitted_at == Some(submitted_at))
            .then_some(attempt)
            .ok_or(DeliveryOperationError::Binding);
    }
    if attempt.status != MycDeliveryAttemptStatus::Leased
        || submitted_at < attempt.leased_at
        || submitted_at > attempt.lease_expires_at
        || target.active_attempt_id != Some(attempt_id)
        || target.status != MycDeliveryTargetStatus::Leased
    {
        return Err(DeliveryOperationError::Binding);
    }
    let result = sqlx::query(MARK_ATTEMPT_SUBMITTED_SQL)
        .bind(submitted_at.sqlite_value())
        .bind(attempt_id.as_bytes().as_slice())
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(submitted_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let result = sqlx::query(MARK_TARGET_SUBMITTED_SQL)
        .bind(submitted_at.sqlite_value())
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(attempt_id.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    read_attempt(transaction, job_id, target.index, attempt_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)
}

async fn record_outcome(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    attempt_id: MycDeliveryAttemptId,
    outcome: MycDeliveryAttemptOutcome,
    retry_jitter: MycDeliveryRetryJitter,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryJobRecord, DeliveryOperationError> {
    let job = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    let target = target_by_relay(&job, relay_id)?.clone();
    let attempt = read_attempt(transaction, job_id, target.index, attempt_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    if matches!(
        attempt.status,
        MycDeliveryAttemptStatus::Delivered
            | MycDeliveryAttemptStatus::Failed
            | MycDeliveryAttemptStatus::Unknown
    ) {
        return (attempt.status == outcome.status()
            && attempt.reason == Some(outcome.reason())
            && attempt.resolved_at == Some(observed_at))
        .then_some(job)
        .ok_or(DeliveryOperationError::Binding);
    }
    let required_prior = match outcome {
        MycDeliveryAttemptOutcome::Delivered
        | MycDeliveryAttemptOutcome::UnknownAcknowledgement => MycDeliveryAttemptStatus::Submitted,
        MycDeliveryAttemptOutcome::RelayRejected => MycDeliveryAttemptStatus::Submitted,
        MycDeliveryAttemptOutcome::TransportFailed => attempt.status,
    };
    if attempt.status != required_prior
        || !matches!(
            required_prior,
            MycDeliveryAttemptStatus::Leased | MycDeliveryAttemptStatus::Submitted
        )
        || target.active_attempt_id != Some(attempt_id)
        || observed_at < attempt.leased_at
        || attempt
            .submitted_at
            .is_some_and(|submitted_at| observed_at < submitted_at)
        || observed_at > attempt.lease_expires_at
    {
        return Err(DeliveryOperationError::Binding);
    }
    resolve_attempt_and_target(
        transaction,
        &job,
        &target,
        &attempt,
        required_prior,
        outcome.status(),
        outcome.reason(),
        retry_jitter,
        observed_at,
    )
    .await?;
    finalize_job_if_terminal(transaction, job_id, observed_at).await
}

pub(crate) async fn recover_expired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    attempt_id: MycDeliveryAttemptId,
    retry_jitter: MycDeliveryRetryJitter,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryJobRecord, DeliveryOperationError> {
    let job = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    let target = target_by_relay(&job, relay_id)?.clone();
    let attempt = read_attempt(transaction, job_id, target.index, attempt_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    if matches!(
        attempt.status,
        MycDeliveryAttemptStatus::Delivered
            | MycDeliveryAttemptStatus::Failed
            | MycDeliveryAttemptStatus::Unknown
    ) {
        return Ok(job);
    }
    if observed_at <= attempt.lease_expires_at || target.active_attempt_id != Some(attempt_id) {
        return Err(DeliveryOperationError::Binding);
    }
    let (terminal, reason) = match attempt.status {
        MycDeliveryAttemptStatus::Leased => (
            MycDeliveryAttemptStatus::Failed,
            "lease_expired_before_submit",
        ),
        MycDeliveryAttemptStatus::Submitted => {
            (MycDeliveryAttemptStatus::Unknown, "acknowledgement_lost")
        }
        MycDeliveryAttemptStatus::Delivered
        | MycDeliveryAttemptStatus::Failed
        | MycDeliveryAttemptStatus::Unknown => unreachable!(),
    };
    resolve_attempt_and_target(
        transaction,
        &job,
        &target,
        &attempt,
        attempt.status,
        terminal,
        reason,
        retry_jitter,
        observed_at,
    )
    .await?;
    finalize_job_if_terminal(transaction, job_id, observed_at).await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_attempt_and_target(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job: &MycDeliveryJobRecord,
    target: &MycDeliveryTargetRecord,
    attempt: &MycDeliveryAttemptRecord,
    prior: MycDeliveryAttemptStatus,
    terminal: MycDeliveryAttemptStatus,
    reason: &'static str,
    retry_jitter: MycDeliveryRetryJitter,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<(), DeliveryOperationError> {
    let result = sqlx::query(RESOLVE_ATTEMPT_SQL)
        .bind(terminal.as_str())
        .bind(observed_at.sqlite_value())
        .bind(reason)
        .bind(attempt.id.as_bytes().as_slice())
        .bind(job.id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(prior.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let attempts_remaining = target.attempt_count < job.max_attempts;
    let schedules_retry = attempts_remaining
        && matches!(
            terminal,
            MycDeliveryAttemptStatus::Failed | MycDeliveryAttemptStatus::Unknown
        );
    if !schedules_retry && retry_jitter.get() != 0 {
        return Err(DeliveryOperationError::Binding);
    }
    let (target_status, next_attempt) = match terminal {
        MycDeliveryAttemptStatus::Delivered => (MycDeliveryTargetStatus::Delivered, None),
        MycDeliveryAttemptStatus::Failed if attempts_remaining => (
            MycDeliveryTargetStatus::Retryable,
            Some(next_attempt_time(
                job,
                attempt.number,
                retry_jitter,
                observed_at,
            )?),
        ),
        MycDeliveryAttemptStatus::Unknown => (
            MycDeliveryTargetStatus::Unknown,
            attempts_remaining
                .then(|| next_attempt_time(job, attempt.number, retry_jitter, observed_at))
                .transpose()?,
        ),
        MycDeliveryAttemptStatus::Failed => (MycDeliveryTargetStatus::Exhausted, None),
        MycDeliveryAttemptStatus::Leased | MycDeliveryAttemptStatus::Submitted => {
            return Err(DeliveryOperationError::Binding);
        }
    };
    let result = sqlx::query(RESOLVE_TARGET_SQL)
        .bind(target_status.as_str())
        .bind(next_attempt.map(MycDeliveryTimeUnixMs::sqlite_value))
        .bind(observed_at.sqlite_value())
        .bind(job.id.as_bytes().as_slice())
        .bind(i64::from(target.index))
        .bind(attempt.id.as_bytes().as_slice())
        .bind(match prior {
            MycDeliveryAttemptStatus::Leased => "leased",
            MycDeliveryAttemptStatus::Submitted => "submitted",
            _ => return Err(DeliveryOperationError::Binding),
        })
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    require_one(result.rows_affected())
}

pub(crate) async fn finalize_job_if_terminal(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryJobRecord, DeliveryOperationError> {
    let job = read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)?;
    let delivered_required = job
        .targets
        .iter()
        .filter(|target| target.required && target.status == MycDeliveryTargetStatus::Delivered)
        .count();
    let possible_required = job
        .targets
        .iter()
        .filter(|target| {
            target.required
                && target.status != MycDeliveryTargetStatus::Exhausted
                && !(target.status == MycDeliveryTargetStatus::Unknown
                    && target.attempt_count >= job.max_attempts)
        })
        .count();
    let required = usize::try_from(job.required_acknowledgements)
        .map_err(|_| DeliveryOperationError::Binding)?;
    let delivered = match job.policy_mode {
        MycDeliveryPolicyMode::AtLeastOneRequired => delivered_required >= required,
        MycDeliveryPolicyMode::AllRequired | MycDeliveryPolicyMode::RequiredQuorum => {
            delivered_required >= required
        }
    };
    let possible = match job.policy_mode {
        MycDeliveryPolicyMode::AtLeastOneRequired => possible_required >= required,
        MycDeliveryPolicyMode::AllRequired | MycDeliveryPolicyMode::RequiredQuorum => {
            possible_required >= required
        }
    };
    if delivered || !possible {
        let terminal = if delivered {
            MycDeliveryJobStatus::Delivered
        } else if job.targets.iter().any(|target| {
            target.required
                && target.status == MycDeliveryTargetStatus::Unknown
                && target.attempt_count >= job.max_attempts
        }) {
            MycDeliveryJobStatus::Unknown
        } else {
            MycDeliveryJobStatus::Failed
        };
        let result = sqlx::query(FINALIZE_JOB_SQL)
            .bind(terminal.as_str())
            .bind(observed_at.sqlite_value())
            .bind(observed_at.sqlite_value())
            .bind(job_id.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| DeliveryOperationError::Storage)?;
        if result.rows_affected() > 1 {
            return Err(DeliveryOperationError::Storage);
        }
    }
    read_job(transaction, job_id)
        .await?
        .ok_or(DeliveryOperationError::Binding)
}

fn next_attempt_time(
    job: &MycDeliveryJobRecord,
    attempt_number: u32,
    jitter: MycDeliveryRetryJitter,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDeliveryTimeUnixMs, DeliveryOperationError> {
    let exponent = attempt_number.saturating_sub(1).min(31);
    let factor = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let maximum_delay = job
        .initial_backoff_ms
        .saturating_mul(factor)
        .min(job.maximum_backoff_ms);
    if jitter.get() > maximum_delay {
        return Err(DeliveryOperationError::Binding);
    }
    let value = observed_at
        .get()
        .checked_add(jitter.get())
        .ok_or(DeliveryOperationError::Binding)?;
    MycDeliveryTimeUnixMs::new(value).map_err(|_| DeliveryOperationError::Binding)
}

async fn read_job_by_source(
    transaction: &mut ServiceSqliteTransaction<'_>,
    source: MycDeliverySource,
) -> Result<Option<MycDeliveryJobRecord>, DeliveryOperationError> {
    let rows = sqlx::query(READ_JOB_BY_SOURCE_SQL)
        .bind(source.kind().as_str())
        .bind(source.id().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    let job = read_job_rows(transaction, rows).await?;
    match job {
        Some(job) if job.source == source => Ok(Some(job)),
        Some(_) => Err(DeliveryOperationError::Binding),
        None => Ok(None),
    }
}

pub(crate) async fn read_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
) -> Result<Option<MycDeliveryJobRecord>, DeliveryOperationError> {
    let rows = sqlx::query(READ_JOB_SQL)
        .bind(job_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    read_job_rows(transaction, rows).await
}

async fn read_job_rows(
    transaction: &mut ServiceSqliteTransaction<'_>,
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Option<MycDeliveryJobRecord>, DeliveryOperationError> {
    if rows.len() > 1 {
        return Err(DeliveryOperationError::Binding);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let id = MycDeliveryJobId(blob32(row, "job_id")?);
    let source_kind = MycDeliverySourceKind::parse(text(row, "source_kind")?)
        .ok_or(DeliveryOperationError::Binding)?;
    let source = MycDeliverySource {
        kind: source_kind,
        id: blob32(row, "source_id")?,
    };
    let artifact_digest = MycDeliveryArtifactDigest(blob32(row, "artifact_sha256")?);
    let policy_mode = MycDeliveryPolicyMode::parse(text(row, "policy_mode")?)
        .ok_or(DeliveryOperationError::Binding)?;
    let required_acknowledgements = positive_u32(row, "required_acknowledgements")?;
    let max_attempts = positive_u32(row, "max_attempts")?;
    if max_attempts > MYC_DELIVERY_ATTEMPT_MAX_COUNT {
        return Err(DeliveryOperationError::Binding);
    }
    let initial_backoff_ms = positive_u64(row, "initial_backoff_ms")?;
    let maximum_backoff_ms = positive_u64(row, "maximum_backoff_ms")?;
    let attempt_deadline_ms = positive_u64(row, "attempt_deadline_ms")?;
    if initial_backoff_ms > maximum_backoff_ms
        || maximum_backoff_ms > 300_000
        || attempt_deadline_ms > 30_000
    {
        return Err(DeliveryOperationError::Binding);
    }
    let status =
        MycDeliveryJobStatus::parse(text(row, "status")?).ok_or(DeliveryOperationError::Binding)?;
    let created_at = time(row, "created_at_unix_ms")?;
    let updated_at = time(row, "updated_at_unix_ms")?;
    let finalized_at = optional_time(row, "finalized_at_unix_ms", "finalized_at_type")?;
    let targets = read_targets(transaction, id).await?;
    let valid = !targets.is_empty()
        && targets.len() <= MYC_DELIVERY_TARGET_MAX_COUNT
        && targets
            .iter()
            .enumerate()
            .all(|(index, target)| usize::try_from(target.index) == Ok(index))
        && matches!(
            status,
            MycDeliveryJobStatus::Delivered
                | MycDeliveryJobStatus::Failed
                | MycDeliveryJobStatus::Unknown
        ) == finalized_at.is_some()
        && targets.iter().all(|target| {
            target.status != MycDeliveryTargetStatus::Unknown
                || target.next_attempt_at.is_some()
                || target.attempt_count == max_attempts
        });
    if !valid {
        return Err(DeliveryOperationError::Binding);
    }
    Ok(Some(MycDeliveryJobRecord {
        id,
        source,
        artifact_digest,
        policy_mode,
        required_acknowledgements,
        max_attempts,
        initial_backoff_ms,
        maximum_backoff_ms,
        attempt_deadline_ms,
        status,
        created_at,
        updated_at,
        finalized_at,
        targets,
    }))
}

async fn read_targets(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
) -> Result<Box<[MycDeliveryTargetRecord]>, DeliveryOperationError> {
    let rows = sqlx::query(READ_TARGETS_SQL)
        .bind(job_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    if rows.len() > MYC_DELIVERY_TARGET_MAX_COUNT {
        return Err(DeliveryOperationError::Binding);
    }
    rows.iter()
        .map(parse_target)
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn parse_target(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<MycDeliveryTargetRecord, DeliveryOperationError> {
    let index = nonnegative_u32(row, "target_index")?;
    let relay_id = MycDeliveryRelayId::new(text(row, "relay_id")?)
        .map_err(|_| DeliveryOperationError::Binding)?;
    let required = bool_value(row, "required")?;
    let attempt_count = nonnegative_u32(row, "attempt_count")?;
    if attempt_count > MYC_DELIVERY_ATTEMPT_MAX_COUNT {
        return Err(DeliveryOperationError::Binding);
    }
    let status = MycDeliveryTargetStatus::parse(text(row, "status")?)
        .ok_or(DeliveryOperationError::Binding)?;
    let active_attempt_id = optional_blob32(row, "active_attempt_id", "active_attempt_id_type")?
        .map(MycDeliveryAttemptId);
    let next_attempt_at = optional_time(row, "next_attempt_at_unix_ms", "next_attempt_at_type")?;
    let updated_at = time(row, "updated_at_unix_ms")?;
    let active = matches!(
        status,
        MycDeliveryTargetStatus::Leased | MycDeliveryTargetStatus::Submitted
    );
    let retryable = status == MycDeliveryTargetStatus::Retryable;
    if active != active_attempt_id.is_some()
        || (retryable && next_attempt_at.is_none())
        || (!retryable && status != MycDeliveryTargetStatus::Unknown && next_attempt_at.is_some())
    {
        return Err(DeliveryOperationError::Binding);
    }
    Ok(MycDeliveryTargetRecord {
        index,
        relay_id,
        required,
        attempt_count,
        status,
        active_attempt_id,
        next_attempt_at,
        updated_at,
    })
}

pub(crate) async fn read_attempts(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    target_index: u32,
) -> Result<Box<[MycDeliveryAttemptRecord]>, DeliveryOperationError> {
    let rows = sqlx::query(READ_ATTEMPTS_SQL)
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target_index))
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    if rows.len() > usize::try_from(MYC_DELIVERY_ATTEMPT_MAX_COUNT).unwrap_or(usize::MAX) {
        return Err(DeliveryOperationError::Binding);
    }
    rows.iter()
        .map(parse_attempt)
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

async fn read_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    target_index: u32,
    attempt_id: MycDeliveryAttemptId,
) -> Result<Option<MycDeliveryAttemptRecord>, DeliveryOperationError> {
    let rows = sqlx::query(READ_ATTEMPT_SQL)
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target_index))
        .bind(attempt_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    one_attempt(rows)
}

async fn read_attempt_by_nonce(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    target_index: u32,
    nonce: &MycDeliveryAttemptNonce,
) -> Result<Option<MycDeliveryAttemptRecord>, DeliveryOperationError> {
    let rows = sqlx::query(READ_ATTEMPT_BY_NONCE_SQL)
        .bind(job_id.as_bytes().as_slice())
        .bind(i64::from(target_index))
        .bind(nonce.0.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryOperationError::Storage)?;
    one_attempt(rows)
}

fn one_attempt(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Option<MycDeliveryAttemptRecord>, DeliveryOperationError> {
    if rows.len() > 1 {
        return Err(DeliveryOperationError::Binding);
    }
    rows.first().map(parse_attempt).transpose()
}

fn parse_attempt(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<MycDeliveryAttemptRecord, DeliveryOperationError> {
    let id = MycDeliveryAttemptId(blob32(row, "attempt_id")?);
    let number = positive_u32(row, "attempt_number")?;
    if number > MYC_DELIVERY_ATTEMPT_MAX_COUNT {
        return Err(DeliveryOperationError::Binding);
    }
    let _nonce = blob32(row, "attempt_nonce")?;
    let status = MycDeliveryAttemptStatus::parse(text(row, "status")?)
        .ok_or(DeliveryOperationError::Binding)?;
    let leased_at = time(row, "leased_at_unix_ms")?;
    let lease_expires_at = time(row, "lease_expires_at_unix_ms")?;
    let submitted_at = optional_time(row, "submitted_at_unix_ms", "submitted_at_type")?;
    let resolved_at = optional_time(row, "resolved_at_unix_ms", "resolved_at_type")?;
    let reason = optional_reason(row)?;
    let valid = lease_expires_at > leased_at
        && match status {
            MycDeliveryAttemptStatus::Leased => {
                submitted_at.is_none() && resolved_at.is_none() && reason.is_none()
            }
            MycDeliveryAttemptStatus::Submitted => {
                submitted_at.is_some() && resolved_at.is_none() && reason.is_none()
            }
            MycDeliveryAttemptStatus::Delivered => {
                submitted_at.is_some() && resolved_at.is_some() && reason == Some("accepted")
            }
            MycDeliveryAttemptStatus::Failed => resolved_at.is_some() && reason.is_some(),
            MycDeliveryAttemptStatus::Unknown => {
                submitted_at.is_some()
                    && resolved_at.is_some()
                    && reason == Some("acknowledgement_lost")
            }
        };
    valid
        .then_some(MycDeliveryAttemptRecord {
            id,
            number,
            status,
            leased_at,
            lease_expires_at,
            submitted_at,
            resolved_at,
            reason,
        })
        .ok_or(DeliveryOperationError::Binding)
}

fn optional_reason(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<&'static str>, DeliveryOperationError> {
    let kind = row
        .try_get::<&str, _>("reason_code_type")
        .map_err(|_| DeliveryOperationError::Binding)?;
    if kind == "null" {
        return Ok(None);
    }
    if kind != "text" {
        return Err(DeliveryOperationError::Binding);
    }
    match row
        .try_get::<Option<&str>, _>("reason_code")
        .map_err(|_| DeliveryOperationError::Binding)?
        .ok_or(DeliveryOperationError::Binding)?
    {
        "accepted" => Ok(Some("accepted")),
        "relay_rejected" => Ok(Some("relay_rejected")),
        "transport_failed" => Ok(Some("transport_failed")),
        "lease_expired_before_submit" => Ok(Some("lease_expired_before_submit")),
        "acknowledgement_lost" => Ok(Some("acknowledgement_lost")),
        _ => Err(DeliveryOperationError::Binding),
    }
}

fn target_by_relay<'a>(
    job: &'a MycDeliveryJobRecord,
    relay_id: &MycDeliveryRelayId,
) -> Result<&'a MycDeliveryTargetRecord, DeliveryOperationError> {
    job.targets
        .iter()
        .find(|target| target.relay_id == *relay_id)
        .ok_or(DeliveryOperationError::Binding)
}

fn exact_job(
    job: &MycDeliveryJobRecord,
    source: MycDeliverySource,
    artifact_digest: MycDeliveryArtifactDigest,
    created_at: MycDeliveryTimeUnixMs,
    policy: &MycDeliveryPolicies,
) -> bool {
    job.source == source
        && job.artifact_digest == artifact_digest
        && job.policy_mode == policy.mode
        && job.required_acknowledgements == policy.required_acknowledgements
        && job.max_attempts == policy.max_attempts
        && job.initial_backoff_ms == policy.initial_backoff_ms
        && job.maximum_backoff_ms == policy.maximum_backoff_ms
        && job.attempt_deadline_ms == policy.attempt_deadline_ms
        && job.created_at == created_at
        && job.targets.len() == policy.targets.len()
        && job
            .targets
            .iter()
            .zip(policy.targets.iter())
            .all(|(actual, expected)| {
                actual.relay_id == expected.relay_id && actual.required == expected.required
            })
}

fn derive_job_id(
    source: MycDeliverySource,
    artifact: MycDeliveryArtifactDigest,
) -> MycDeliveryJobId {
    let mut hasher = Sha256::new();
    hasher.update(JOB_ID_DOMAIN);
    if source.kind() == MycDeliverySourceKind::DiscoveryHandler {
        hasher.update(b"discovery_handler\0");
    }
    hasher.update(source.id());
    hasher.update(artifact.as_bytes());
    MycDeliveryJobId(hasher.finalize().into())
}

fn derive_attempt_id(
    job_id: MycDeliveryJobId,
    target_index: u32,
    attempt_number: u32,
    nonce: &MycDeliveryAttemptNonce,
) -> MycDeliveryAttemptId {
    let mut hasher = Sha256::new();
    hasher.update(ATTEMPT_ID_DOMAIN);
    hasher.update(job_id.as_bytes());
    hasher.update(target_index.to_be_bytes());
    hasher.update(attempt_number.to_be_bytes());
    hasher.update(nonce.0);
    MycDeliveryAttemptId(hasher.finalize().into())
}

fn text<'a>(
    row: &'a sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<&'a str, DeliveryOperationError> {
    row.try_get::<Option<&str>, _>(column)
        .map_err(|_| DeliveryOperationError::Binding)?
        .ok_or(DeliveryOperationError::Binding)
}

fn blob32(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<[u8; 32], DeliveryOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| DeliveryOperationError::Binding)?
        .ok_or(DeliveryOperationError::Binding)?
        .try_into()
        .map_err(|_| DeliveryOperationError::Binding)
}

fn optional_blob32(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<[u8; 32]>, DeliveryOperationError> {
    match row
        .try_get::<&str, _>(type_column)
        .map_err(|_| DeliveryOperationError::Binding)?
    {
        "null" => Ok(None),
        "blob" => blob32(row, column).map(Some),
        _ => Err(DeliveryOperationError::Binding),
    }
}

fn positive_u32(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u32, DeliveryOperationError> {
    nonnegative_u32(row, column).and_then(|value| {
        (value != 0)
            .then_some(value)
            .ok_or(DeliveryOperationError::Binding)
    })
}

fn nonnegative_u32(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u32, DeliveryOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| DeliveryOperationError::Binding)?;
    u32::try_from(value).map_err(|_| DeliveryOperationError::Binding)
}

fn positive_u64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, DeliveryOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| DeliveryOperationError::Binding)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(DeliveryOperationError::Binding)
}

fn bool_value(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<bool, DeliveryOperationError> {
    match row
        .try_get::<i64, _>(column)
        .map_err(|_| DeliveryOperationError::Binding)?
    {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DeliveryOperationError::Binding),
    }
}

fn time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycDeliveryTimeUnixMs, DeliveryOperationError> {
    let value = positive_u64(row, column)?;
    MycDeliveryTimeUnixMs::new(value).map_err(|_| DeliveryOperationError::Binding)
}

fn optional_time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<MycDeliveryTimeUnixMs>, DeliveryOperationError> {
    match row
        .try_get::<&str, _>(type_column)
        .map_err(|_| DeliveryOperationError::Binding)?
    {
        "null" => Ok(None),
        "integer" => time(row, column).map(Some),
        _ => Err(DeliveryOperationError::Binding),
    }
}

fn require_one(rows: u64) -> Result<(), DeliveryOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(DeliveryOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<DeliveryOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(DeliveryOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(DeliveryOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
