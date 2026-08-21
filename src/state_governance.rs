//! Durable bounded audit, rate-window, retention, and compaction state.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::{MycConnectionId, MycConnectionTimeUnixMs, MycSignerOperationId};

/// Maximum governed rate-window duration.
pub const MYC_RATE_WINDOW_MAX_MS: u64 = 86_400_000;
/// Maximum attempts admitted in one governed rate window.
pub const MYC_RATE_MAX_ATTEMPTS: u32 = 10_000;
/// Maximum retained duration for rate-window evidence.
pub const MYC_RATE_RETENTION_MAX_MS: u64 = 2_592_000_000;
/// Maximum tracked non-global subjects for one rate-limit class.
pub const MYC_RATE_MAX_TRACKED_SUBJECTS: u32 = 65_536;
/// Maximum retained duration for safe audit evidence.
pub const MYC_AUDIT_RETENTION_MAX_MS: u64 = 31_536_000_000;
/// Maximum audit records returned in one page.
pub const MYC_AUDIT_PAGE_MAX_ITEMS: u16 = 200;
/// Maximum rows removed from either bounded evidence class in one compaction.
pub const MYC_COMPACTION_MAX_ROWS: u16 = 4_096;
/// Maximum UTF-8 bytes in a configured stable relay ID.
pub const MYC_RATE_RELAY_ID_MAX_BYTES: usize = 64;

const AUDIT_ID_DOMAIN: &[u8] = b"radroots.myc.operation_audit.v1\0";
const GLOBAL_SUBJECT_DOMAIN: &[u8] = b"radroots.myc.rate_subject.global.v1\0";
const RELAY_SUBJECT_DOMAIN: &[u8] = b"radroots.myc.rate_subject.relay.v1\0";
const CONNECTION_SUBJECT_DOMAIN: &[u8] = b"radroots.myc.rate_subject.connection.v1\0";

const READ_AUDIT_STATE_SQL: &str =
    "SELECT next_sequence FROM myc_audit_state WHERE singleton = 1 LIMIT 2";
const ADVANCE_AUDIT_STATE_SQL: &str =
    "UPDATE myc_audit_state SET next_sequence = ? WHERE singleton = 1 AND next_sequence = ?";
const READ_AUDIT_BY_ID_SQL: &str = r#"SELECT
    operation_audit.audit_sequence,
    CASE WHEN typeof(operation_audit.correlation_id) = 'blob'
        AND length(operation_audit.correlation_id) = 32
        THEN operation_audit.correlation_id ELSE NULL END AS correlation_id,
    CASE WHEN typeof(operation_audit.audit_kind) = 'text'
        AND length(CAST(operation_audit.audit_kind AS BLOB)) <= 40
        THEN operation_audit.audit_kind ELSE NULL END AS audit_kind,
    CASE WHEN typeof(operation_audit.outcome) = 'text'
        AND length(CAST(operation_audit.outcome AS BLOB)) <= 16
        THEN operation_audit.outcome ELSE NULL END AS outcome,
    CASE WHEN typeof(operation_audit.reason_code) = 'text'
        AND length(CAST(operation_audit.reason_code AS BLOB)) <= 48
        THEN operation_audit.reason_code ELSE NULL END AS reason_code,
    operation_audit.occurred_at_unix_ms,
    CASE WHEN typeof(request_audit.operation_id) = 'blob'
        AND length(request_audit.operation_id) = 32
        THEN request_audit.operation_id ELSE NULL END AS operation_id,
    CASE WHEN typeof(request_audit.audit_kind) = 'text'
        AND length(CAST(request_audit.audit_kind AS BLOB)) <= 40
        THEN request_audit.audit_kind ELSE NULL END AS request_audit_kind,
    CASE WHEN typeof(request_record.correlation_id) = 'blob'
        AND length(request_record.correlation_id) = 32
        THEN request_record.correlation_id ELSE NULL END AS request_correlation_id
FROM operation_audit
LEFT JOIN nip46_request_audit AS request_audit
    ON request_audit.audit_sequence = operation_audit.audit_sequence
LEFT JOIN nip46_requests AS request_record
    ON request_record.operation_id = request_audit.operation_id
WHERE operation_audit.audit_id = ? LIMIT 2"#;
const INSERT_AUDIT_SQL: &str = r#"INSERT INTO operation_audit (
    audit_sequence, audit_id, correlation_id, audit_kind, outcome, reason_code,
    occurred_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?)"#;
const INSERT_REQUEST_AUDIT_SQL: &str = r#"INSERT INTO nip46_request_audit (
    operation_id, audit_kind, audit_sequence
) VALUES (?, ?, ?)"#;

const READ_RATE_SQL: &str = r#"SELECT
    window_started_at_unix_ms, window_ends_at_unix_ms,
    accepted_count, rejected_count, lifetime_accepted_count,
    lifetime_rejected_count, last_observed_at_unix_ms, retention_expires_at_unix_ms
FROM connection_rate_windows
WHERE rate_kind = ? AND subject_scope = ? AND subject_sha256 = ?
LIMIT 2"#;
const COUNT_RATE_SUBJECTS_SQL: &str = r#"SELECT COUNT(*)
FROM connection_rate_windows
WHERE rate_kind = ? AND subject_scope = ?"#;
const INSERT_RATE_SQL: &str = r#"INSERT INTO connection_rate_windows (
    rate_kind, subject_scope, subject_sha256, window_started_at_unix_ms,
    window_ends_at_unix_ms, accepted_count, rejected_count,
    lifetime_accepted_count, lifetime_rejected_count,
    last_observed_at_unix_ms, retention_expires_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;
const UPDATE_RATE_SQL: &str = r#"UPDATE connection_rate_windows SET
    window_started_at_unix_ms = ?, window_ends_at_unix_ms = ?,
    accepted_count = ?, rejected_count = ?, lifetime_accepted_count = ?,
    lifetime_rejected_count = ?, last_observed_at_unix_ms = ?,
    retention_expires_at_unix_ms = ?
WHERE rate_kind = ? AND subject_scope = ? AND subject_sha256 = ?
    AND last_observed_at_unix_ms = ?"#;

/// Stable construction and validation failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycGovernanceStateErrorKind {
    InvalidRatePolicy,
    InvalidRelayId,
    InvalidPageLimit,
    InvalidCompactionPolicy,
}

impl MycGovernanceStateErrorKind {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRatePolicy => "governance_rate_policy_invalid",
            Self::InvalidRelayId => "governance_relay_id_invalid",
            Self::InvalidPageLimit => "governance_audit_page_limit_invalid",
            Self::InvalidCompactionPolicy => "governance_compaction_policy_invalid",
        }
    }
}

/// Source-free governance-state validation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycGovernanceStateError {
    kind: MycGovernanceStateErrorKind,
}

impl MycGovernanceStateError {
    const fn new(kind: MycGovernanceStateErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycGovernanceStateErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycGovernanceStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycGovernanceStateErrorKind::InvalidRatePolicy => "rate policy is invalid",
            MycGovernanceStateErrorKind::InvalidRelayId => "rate relay ID is invalid",
            MycGovernanceStateErrorKind::InvalidPageLimit => "audit page limit is invalid",
            MycGovernanceStateErrorKind::InvalidCompactionPolicy => "compaction policy is invalid",
        })
    }
}

impl fmt::Debug for MycGovernanceStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycGovernanceStateError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycGovernanceStateError {}

/// Closed rate-window classes. Their subject scope is fixed by contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycRateLimitClass {
    ConnectionAdmission,
    ChallengeCreation,
    ChallengeAuthorization,
}

impl MycRateLimitClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAdmission => "connection_admission",
            Self::ChallengeCreation => "challenge_creation",
            Self::ChallengeAuthorization => "challenge_authorization",
        }
    }
}

/// Validated bounded rate-window policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycRateLimitPolicy {
    class: MycRateLimitClass,
    window_ms: u64,
    max_attempts: u32,
    retention_ms: u64,
    maximum_tracked_subjects: u32,
}

impl MycRateLimitPolicy {
    /// Constructs one exact policy from fully normalized configuration values.
    pub fn new(
        class: MycRateLimitClass,
        window_ms: u64,
        max_attempts: u32,
        retention_ms: u64,
        maximum_tracked_subjects: u32,
    ) -> Result<Self, MycGovernanceStateError> {
        if window_ms == 0
            || window_ms > MYC_RATE_WINDOW_MAX_MS
            || max_attempts == 0
            || max_attempts > MYC_RATE_MAX_ATTEMPTS
            || retention_ms < window_ms
            || retention_ms > MYC_RATE_RETENTION_MAX_MS
            || maximum_tracked_subjects == 0
            || maximum_tracked_subjects > MYC_RATE_MAX_TRACKED_SUBJECTS
        {
            return Err(MycGovernanceStateError::new(
                MycGovernanceStateErrorKind::InvalidRatePolicy,
            ));
        }
        Ok(Self {
            class,
            window_ms,
            max_attempts,
            retention_ms,
            maximum_tracked_subjects,
        })
    }

    /// Returns the closed policy class.
    #[must_use]
    pub const fn class(self) -> MycRateLimitClass {
        self.class
    }
}

impl fmt::Debug for MycRateLimitPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRateLimitPolicy")
            .field("class", &self.class)
            .field("values", &"[bounded]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MycGovernancePolicies {
    connection_admission: MycRateLimitPolicy,
    challenge_creation: MycRateLimitPolicy,
    challenge_authorization: MycRateLimitPolicy,
    audit_retention_ms: u64,
    relays: Box<[MycRateRelayId]>,
}

impl MycGovernancePolicies {
    pub(crate) fn new(
        connection_admission: MycRateLimitPolicy,
        challenge_creation: MycRateLimitPolicy,
        challenge_authorization: MycRateLimitPolicy,
        audit_retention_ms: u64,
        relays: Box<[MycRateRelayId]>,
    ) -> Result<Self, MycGovernanceStateError> {
        if connection_admission.class != MycRateLimitClass::ConnectionAdmission
            || challenge_creation.class != MycRateLimitClass::ChallengeCreation
            || challenge_authorization.class != MycRateLimitClass::ChallengeAuthorization
            || audit_retention_ms == 0
            || audit_retention_ms > MYC_AUDIT_RETENTION_MAX_MS
            || relays.is_empty()
        {
            return Err(MycGovernanceStateError::new(
                MycGovernanceStateErrorKind::InvalidRatePolicy,
            ));
        }
        Ok(Self {
            connection_admission,
            challenge_creation,
            challenge_authorization,
            audit_retention_ms,
            relays,
        })
    }

    pub(crate) const fn rate_policy(&self, class: MycRateLimitClass) -> MycRateLimitPolicy {
        match class {
            MycRateLimitClass::ConnectionAdmission => self.connection_admission,
            MycRateLimitClass::ChallengeCreation => self.challenge_creation,
            MycRateLimitClass::ChallengeAuthorization => self.challenge_authorization,
        }
    }

    pub(crate) fn admits_relay(&self, relay: &MycRateRelayId) -> bool {
        self.relays.iter().any(|configured| configured == relay)
    }

    pub(crate) const fn audit_retention_ms(&self) -> u64 {
        self.audit_retention_ms
    }
}

/// Validated configured relay identity used only to derive bounded rate scope.
#[derive(Clone, PartialEq, Eq)]
pub struct MycRateRelayId(Box<str>);

impl MycRateRelayId {
    /// Validates one stable lower-snake relay identity before allocation.
    pub fn new(value: &str) -> Result<Self, MycGovernanceStateError> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MYC_RATE_RELAY_ID_MAX_BYTES
            || !bytes[0].is_ascii_lowercase()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || bytes.windows(2).any(|pair| pair == b"__")
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(MycGovernanceStateError::new(
                MycGovernanceStateErrorKind::InvalidRelayId,
            ));
        }
        Ok(Self(value.into()))
    }
}

impl fmt::Debug for MycRateRelayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycRateRelayId([redacted])")
    }
}

/// Injected stable correlation identity for non-NIP-46 operator work.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycAuditCorrelationId([u8; 32]);

impl MycAuditCorrelationId {
    /// Constructs an opaque caller-injected correlation identity.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycAuditCorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycAuditCorrelationId([redacted])")
    }
}

/// Closed audit event classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAuditKind {
    ConnectionAdmission,
    ConnectionOperatorDecision,
    ConnectionExpiry,
    ChallengeCreation,
    ChallengeAuthorization,
    GovernanceCompaction,
}

impl MycAuditKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionAdmission => "connection_admission",
            Self::ConnectionOperatorDecision => "connection_operator_decision",
            Self::ConnectionExpiry => "connection_expiry",
            Self::ChallengeCreation => "challenge_creation",
            Self::ChallengeAuthorization => "challenge_authorization",
            Self::GovernanceCompaction => "governance_compaction",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "connection_admission" => Some(Self::ConnectionAdmission),
            "connection_operator_decision" => Some(Self::ConnectionOperatorDecision),
            "connection_expiry" => Some(Self::ConnectionExpiry),
            "challenge_creation" => Some(Self::ChallengeCreation),
            "challenge_authorization" => Some(Self::ChallengeAuthorization),
            "governance_compaction" => Some(Self::GovernanceCompaction),
            _ => None,
        }
    }
}

/// Closed audit outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAuditOutcome {
    Succeeded,
    Rejected,
    Failed,
}

impl MycAuditOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "succeeded" => Some(Self::Succeeded),
            "rejected" => Some(Self::Rejected),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Closed safe audit reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAuditReasonCode {
    Trusted,
    ApprovalRequired,
    PolicyDenied,
    OperatorApproved,
    OperatorDenied,
    ConnectionExpired,
    ChallengeRequired,
    ChallengeAuthorized,
    ChallengeExpired,
    RateLimited,
    Compacted,
}

impl MycAuditReasonCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::ApprovalRequired => "approval_required",
            Self::PolicyDenied => "policy_denied",
            Self::OperatorApproved => "operator_approved",
            Self::OperatorDenied => "operator_denied",
            Self::ConnectionExpired => "connection_expired",
            Self::ChallengeRequired => "challenge_required",
            Self::ChallengeAuthorized => "challenge_authorized",
            Self::ChallengeExpired => "challenge_expired",
            Self::RateLimited => "rate_limited",
            Self::Compacted => "compacted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "trusted" => Some(Self::Trusted),
            "approval_required" => Some(Self::ApprovalRequired),
            "policy_denied" => Some(Self::PolicyDenied),
            "operator_approved" => Some(Self::OperatorApproved),
            "operator_denied" => Some(Self::OperatorDenied),
            "connection_expired" => Some(Self::ConnectionExpired),
            "challenge_required" => Some(Self::ChallengeRequired),
            "challenge_authorized" => Some(Self::ChallengeAuthorized),
            "challenge_expired" => Some(Self::ChallengeExpired),
            "rate_limited" => Some(Self::RateLimited),
            "compacted" => Some(Self::Compacted),
            _ => None,
        }
    }
}

/// One validated safe audit record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycAuditRecord {
    sequence: u64,
    correlation_id: MycAuditCorrelationId,
    operation_id: Option<MycSignerOperationId>,
    kind: MycAuditKind,
    outcome: MycAuditOutcome,
    reason: MycAuditReasonCode,
    occurred_at: MycConnectionTimeUnixMs,
}

impl MycAuditRecord {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the opaque correlation identity bound to this record.
    #[must_use]
    pub const fn correlation_id(&self) -> MycAuditCorrelationId {
        self.correlation_id
    }

    /// Returns the typed signer-operation identity when this is request audit.
    #[must_use]
    pub const fn operation_id(&self) -> Option<MycSignerOperationId> {
        self.operation_id
    }

    #[must_use]
    pub const fn kind(&self) -> MycAuditKind {
        self.kind
    }

    #[must_use]
    pub const fn outcome(&self) -> MycAuditOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn reason(&self) -> MycAuditReasonCode {
        self.reason
    }

    #[must_use]
    pub const fn occurred_at(&self) -> MycConnectionTimeUnixMs {
        self.occurred_at
    }
}

impl fmt::Debug for MycAuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAuditRecord")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("correlation", &"[redacted]")
            .finish()
    }
}

/// Validated audit page limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycAuditPageLimit(u16);

impl MycAuditPageLimit {
    pub fn new(value: u16) -> Result<Self, MycGovernanceStateError> {
        (value != 0 && value <= MYC_AUDIT_PAGE_MAX_ITEMS)
            .then_some(Self(value))
            .ok_or_else(|| {
                MycGovernanceStateError::new(MycGovernanceStateErrorKind::InvalidPageLimit)
            })
    }
}

/// Immutable bounded audit page.
pub struct MycAuditPage {
    snapshot_sequence: u64,
    items: Box<[MycAuditRecord]>,
    next_before_sequence: Option<u64>,
}

impl MycAuditPage {
    #[must_use]
    pub const fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }

    #[must_use]
    pub fn items(&self) -> &[MycAuditRecord] {
        &self.items
    }

    #[must_use]
    pub const fn next_before_sequence(&self) -> Option<u64> {
        self.next_before_sequence
    }
}

impl fmt::Debug for MycAuditPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAuditPage")
            .field("snapshot_sequence", &self.snapshot_sequence)
            .field("item_count", &self.items.len())
            .finish()
    }
}

/// Explicit bounded retention and compaction policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycGovernanceCompactionPolicy {
    audit_retention_ms: u64,
    maximum_rows_per_class: u16,
}

impl MycGovernanceCompactionPolicy {
    pub fn new(
        audit_retention_ms: u64,
        maximum_rows_per_class: u16,
    ) -> Result<Self, MycGovernanceStateError> {
        if audit_retention_ms == 0
            || audit_retention_ms > MYC_AUDIT_RETENTION_MAX_MS
            || maximum_rows_per_class == 0
            || maximum_rows_per_class > MYC_COMPACTION_MAX_ROWS
        {
            return Err(MycGovernanceStateError::new(
                MycGovernanceStateErrorKind::InvalidCompactionPolicy,
            ));
        }
        Ok(Self {
            audit_retention_ms,
            maximum_rows_per_class,
        })
    }
}

/// Bounded compaction result. Authoritative domain state is never included.
/// Counts describe this invocation; an exact correlation replay is a zero-work success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycGovernanceCompactionOutcome {
    removed_audit_records: u16,
    removed_rate_subjects: u16,
}

impl MycGovernanceCompactionOutcome {
    #[must_use]
    pub const fn removed_audit_records(self) -> u16 {
        self.removed_audit_records
    }

    #[must_use]
    pub const fn removed_rate_subjects(self) -> u16 {
        self.removed_rate_subjects
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AuditEvidence {
    pub(crate) correlation: MycAuditCorrelationId,
    pub(crate) occurred_at: MycConnectionTimeUnixMs,
    pub(crate) operation_id: Option<MycSignerOperationId>,
}

#[derive(Clone, Copy)]
pub(crate) enum RateSubject {
    Global,
    Relay([u8; 32]),
    Connection(MycConnectionId),
}

pub(crate) fn relay_subject(relay: &MycRateRelayId) -> RateSubject {
    RateSubject::Relay(hash_framed(RELAY_SUBJECT_DOMAIN, relay.0.as_bytes()))
}

pub(crate) fn global_subject() -> RateSubject {
    RateSubject::Global
}

pub(crate) fn connection_subject(connection: MycConnectionId) -> RateSubject {
    RateSubject::Connection(connection)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GovernanceOperationError {
    Binding,
    Storage,
}

pub(crate) async fn govern_rate_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    policy: MycRateLimitPolicy,
    expected_class: MycRateLimitClass,
    subjects: &[RateSubject],
    evidence: AuditEvidence,
    audit_kind: MycAuditKind,
) -> Result<bool, GovernanceOperationError> {
    if policy.class != expected_class || subjects.is_empty() || subjects.len() > 2 {
        return Err(GovernanceOperationError::Binding);
    }
    if let Some(existing) = read_audit_by_id(
        transaction,
        derive_audit_id(evidence.correlation, audit_kind),
    )
    .await?
    {
        return (existing.correlation_id == evidence.correlation
            && existing.operation_id == evidence.operation_id
            && existing.kind == audit_kind
            && existing.outcome == MycAuditOutcome::Rejected
            && existing.reason == MycAuditReasonCode::RateLimited)
            .then_some(false)
            .ok_or(GovernanceOperationError::Binding);
    }
    let mut states = Vec::with_capacity(subjects.len());
    for subject in subjects {
        states.push(load_rate_state(transaction, policy, *subject, evidence.occurred_at).await?);
    }
    let admitted = states.iter().all(|state| state.can_accept(policy));
    for state in &states {
        persist_rate_state(transaction, policy, *state, evidence.occurred_at, admitted).await?;
    }
    if !admitted {
        record_audit(
            transaction,
            evidence,
            audit_kind,
            MycAuditOutcome::Rejected,
            MycAuditReasonCode::RateLimited,
        )
        .await?;
    }
    Ok(admitted)
}

pub(crate) async fn record_audit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    evidence: AuditEvidence,
    kind: MycAuditKind,
    outcome: MycAuditOutcome,
    reason: MycAuditReasonCode,
) -> Result<MycAuditRecord, GovernanceOperationError> {
    let audit_id = derive_audit_id(evidence.correlation, kind);
    if let Some(existing) = read_audit_by_id(transaction, audit_id).await? {
        return (existing.correlation_id == evidence.correlation
            && existing.operation_id == evidence.operation_id
            && existing.kind == kind
            && existing.outcome == outcome
            && existing.reason == reason
            && existing.occurred_at == evidence.occurred_at)
            .then_some(existing)
            .ok_or(GovernanceOperationError::Binding);
    }
    let current = read_audit_state(transaction).await?;
    let sequence = current
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(GovernanceOperationError::Binding)?;
    let result = sqlx::query(ADVANCE_AUDIT_STATE_SQL)
        .bind(i64::try_from(sequence).map_err(|_| GovernanceOperationError::Binding)?)
        .bind(i64::try_from(current).map_err(|_| GovernanceOperationError::Binding)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let result = sqlx::query(INSERT_AUDIT_SQL)
        .bind(i64::try_from(sequence).map_err(|_| GovernanceOperationError::Binding)?)
        .bind(audit_id.as_slice())
        .bind(evidence.correlation.0.as_slice())
        .bind(kind.as_str())
        .bind(outcome.as_str())
        .bind(reason.as_str())
        .bind(to_i64(evidence.occurred_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    require_one(result.rows_affected())?;
    if let Some(operation_id) = evidence.operation_id {
        let result = sqlx::query(INSERT_REQUEST_AUDIT_SQL)
            .bind(operation_id.as_bytes().as_slice())
            .bind(kind.as_str())
            .bind(i64::try_from(sequence).map_err(|_| GovernanceOperationError::Binding)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| GovernanceOperationError::Storage)?;
        require_one(result.rows_affected())?;
    }
    Ok(MycAuditRecord {
        sequence,
        correlation_id: evidence.correlation,
        operation_id: evidence.operation_id,
        kind,
        outcome,
        reason,
        occurred_at: evidence.occurred_at,
    })
}

impl MycStateRepository<'_> {
    /// Reads one deterministic, snapshot-bounded page of safe audit evidence.
    pub async fn read_audit_page(
        &self,
        limit: MycAuditPageLimit,
        snapshot_sequence: Option<u64>,
        before_sequence: Option<u64>,
    ) -> Result<MycAuditPage, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    read_audit_page(transaction, limit, snapshot_sequence, before_sequence).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Removes only expired safe audit and rate-window evidence in bounded batches.
    pub async fn compact_governance_evidence(
        &self,
        observed_at: MycConnectionTimeUnixMs,
        policy: MycGovernanceCompactionPolicy,
        correlation: MycAuditCorrelationId,
    ) -> Result<MycGovernanceCompactionOutcome, MycStateRepositoryError> {
        if policy.audit_retention_ms != self.expected().governance_audit_retention_ms() {
            return Err(MycStateRepositoryError::new(
                MycStateRepositoryErrorKind::Binding,
            ));
        }
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    compact_governance(transaction, observed_at, policy, correlation).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone, Copy)]
struct RateState {
    subject: RateSubject,
    existing_last: Option<u64>,
    window_started: u64,
    window_ends: u64,
    accepted: u64,
    rejected: u64,
    lifetime_accepted: u64,
    lifetime_rejected: u64,
}

impl RateState {
    fn can_accept(self, policy: MycRateLimitPolicy) -> bool {
        self.accepted < u64::from(policy.max_attempts)
    }
}

async fn load_rate_state(
    transaction: &mut ServiceSqliteTransaction<'_>,
    policy: MycRateLimitPolicy,
    subject: RateSubject,
    observed_at: MycConnectionTimeUnixMs,
) -> Result<RateState, GovernanceOperationError> {
    let (scope, digest) = subject_parts(subject);
    let rows = sqlx::query(READ_RATE_SQL)
        .bind(policy.class.as_str())
        .bind(scope)
        .bind(digest.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(GovernanceOperationError::Binding);
    }
    let now = observed_at.get();
    let Some(row) = rows.first() else {
        if scope != "global" {
            let count = sqlx::query_scalar::<_, i64>(COUNT_RATE_SUBJECTS_SQL)
                .bind(policy.class.as_str())
                .bind(scope)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| GovernanceOperationError::Storage)?;
            let count = u64::try_from(count).map_err(|_| GovernanceOperationError::Binding)?;
            if count >= u64::from(policy.maximum_tracked_subjects) {
                return Err(GovernanceOperationError::Binding);
            }
        }
        return Ok(RateState {
            subject,
            existing_last: None,
            window_started: now,
            window_ends: checked_time_add(now, policy.window_ms)?,
            accepted: 0,
            rejected: 0,
            lifetime_accepted: 0,
            lifetime_rejected: 0,
        });
    };
    let mut state = RateState {
        subject,
        existing_last: Some(bounded_i64(row, "last_observed_at_unix_ms")?),
        window_started: bounded_i64(row, "window_started_at_unix_ms")?,
        window_ends: bounded_i64(row, "window_ends_at_unix_ms")?,
        accepted: bounded_nonnegative(row, "accepted_count")?,
        rejected: bounded_nonnegative(row, "rejected_count")?,
        lifetime_accepted: bounded_nonnegative(row, "lifetime_accepted_count")?,
        lifetime_rejected: bounded_nonnegative(row, "lifetime_rejected_count")?,
    };
    let retention_expires = bounded_i64(row, "retention_expires_at_unix_ms")?;
    let last = state
        .existing_last
        .ok_or(GovernanceOperationError::Binding)?;
    if now < last
        || state.window_started > last
        || state.window_ends < last
        || retention_expires < last
        || state.accepted > u64::from(policy.max_attempts)
    {
        return Err(GovernanceOperationError::Binding);
    }
    if now > state.window_ends {
        state.window_started = now;
        state.window_ends = checked_time_add(now, policy.window_ms)?;
        state.accepted = 0;
        state.rejected = 0;
    }
    Ok(state)
}

async fn persist_rate_state(
    transaction: &mut ServiceSqliteTransaction<'_>,
    policy: MycRateLimitPolicy,
    state: RateState,
    observed_at: MycConnectionTimeUnixMs,
    admitted: bool,
) -> Result<(), GovernanceOperationError> {
    let (scope, digest) = subject_parts(state.subject);
    let accepted = state.accepted + u64::from(admitted);
    let rejected = state.rejected + u64::from(!admitted);
    let lifetime_accepted = state.lifetime_accepted + u64::from(admitted);
    let lifetime_rejected = state.lifetime_rejected + u64::from(!admitted);
    for value in [accepted, rejected, lifetime_accepted, lifetime_rejected] {
        if value > i64::MAX as u64 {
            return Err(GovernanceOperationError::Binding);
        }
    }
    let retention_expires = checked_time_add(observed_at.get(), policy.retention_ms)?;
    let mut query = if state.existing_last.is_some() {
        sqlx::query(UPDATE_RATE_SQL)
    } else {
        sqlx::query(INSERT_RATE_SQL)
    };
    if state.existing_last.is_some() {
        query = query
            .bind(to_i64(state.window_started)?)
            .bind(to_i64(state.window_ends)?)
            .bind(to_i64(accepted)?)
            .bind(to_i64(rejected)?)
            .bind(to_i64(lifetime_accepted)?)
            .bind(to_i64(lifetime_rejected)?)
            .bind(to_i64(observed_at.get())?)
            .bind(to_i64(retention_expires)?)
            .bind(policy.class.as_str())
            .bind(scope)
            .bind(digest.as_slice())
            .bind(to_i64(
                state
                    .existing_last
                    .ok_or(GovernanceOperationError::Binding)?,
            )?);
    } else {
        query = query
            .bind(policy.class.as_str())
            .bind(scope)
            .bind(digest.as_slice())
            .bind(to_i64(state.window_started)?)
            .bind(to_i64(state.window_ends)?)
            .bind(to_i64(accepted)?)
            .bind(to_i64(rejected)?)
            .bind(to_i64(lifetime_accepted)?)
            .bind(to_i64(lifetime_rejected)?)
            .bind(to_i64(observed_at.get())?)
            .bind(to_i64(retention_expires)?);
    }
    let result = query
        .execute(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    require_one(result.rows_affected())
}

async fn read_audit_page(
    transaction: &mut ServiceSqliteTransaction<'_>,
    limit: MycAuditPageLimit,
    requested_snapshot: Option<u64>,
    before: Option<u64>,
) -> Result<MycAuditPage, GovernanceOperationError> {
    let high_water = read_audit_state(transaction).await?;
    let snapshot = requested_snapshot.unwrap_or(high_water);
    if snapshot > high_water
        || before.is_some_and(|value| value == 0 || value > snapshot.saturating_add(1))
    {
        return Err(GovernanceOperationError::Binding);
    }
    let before = before.unwrap_or_else(|| snapshot.saturating_add(1));
    let fetch_limit = u32::from(limit.0) + 1;
    let rows = sqlx::query(
        r#"SELECT audit_id FROM operation_audit
        WHERE audit_sequence <= ? AND audit_sequence < ?
        ORDER BY audit_sequence DESC LIMIT ?"#,
    )
    .bind(to_i64(snapshot)?)
    .bind(to_i64(before)?)
    .bind(i64::from(fetch_limit))
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| GovernanceOperationError::Storage)?;
    if rows.len() > usize::try_from(fetch_limit).map_err(|_| GovernanceOperationError::Binding)? {
        return Err(GovernanceOperationError::Binding);
    }
    let has_more = rows.len() > usize::from(limit.0);
    let mut items = Vec::with_capacity(rows.len().min(usize::from(limit.0)));
    for row in rows.iter().take(usize::from(limit.0)) {
        let id = bounded_digest(row, "audit_id")?;
        items.push(
            read_audit_by_id(transaction, id)
                .await?
                .ok_or(GovernanceOperationError::Binding)?,
        );
    }
    let next = has_more
        .then(|| items.last().map(|item| item.sequence))
        .flatten();
    Ok(MycAuditPage {
        snapshot_sequence: snapshot,
        items: items.into_boxed_slice(),
        next_before_sequence: next,
    })
}

async fn compact_governance(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at: MycConnectionTimeUnixMs,
    policy: MycGovernanceCompactionPolicy,
    correlation: MycAuditCorrelationId,
) -> Result<MycGovernanceCompactionOutcome, GovernanceOperationError> {
    if let Some(existing) = read_audit_by_id(
        transaction,
        derive_audit_id(correlation, MycAuditKind::GovernanceCompaction),
    )
    .await?
    {
        return (existing.correlation_id == correlation
            && existing.operation_id.is_none()
            && existing.kind == MycAuditKind::GovernanceCompaction
            && existing.outcome == MycAuditOutcome::Succeeded
            && existing.reason == MycAuditReasonCode::Compacted
            && existing.occurred_at == observed_at)
            .then_some(MycGovernanceCompactionOutcome {
                removed_audit_records: 0,
                removed_rate_subjects: 0,
            })
            .ok_or(GovernanceOperationError::Binding);
    }
    let cutoff = observed_at.get().saturating_sub(policy.audit_retention_ms);
    let limit = i64::from(policy.maximum_rows_per_class);
    let request_links = sqlx::query(
        r#"DELETE FROM nip46_request_audit WHERE audit_sequence IN (
            SELECT audit_sequence FROM operation_audit
            WHERE occurred_at_unix_ms < ? ORDER BY audit_sequence ASC LIMIT ?
        )"#,
    )
    .bind(to_i64(cutoff)?)
    .bind(limit)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GovernanceOperationError::Storage)?;
    let _ = request_links;
    let audit = sqlx::query(
        r#"DELETE FROM operation_audit WHERE audit_sequence IN (
            SELECT audit_sequence FROM operation_audit
            WHERE occurred_at_unix_ms < ? ORDER BY audit_sequence ASC LIMIT ?
        )"#,
    )
    .bind(to_i64(cutoff)?)
    .bind(limit)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GovernanceOperationError::Storage)?;
    let rates = sqlx::query(
        r#"DELETE FROM connection_rate_windows WHERE rowid IN (
            SELECT rowid FROM connection_rate_windows
            WHERE retention_expires_at_unix_ms < ?
            ORDER BY retention_expires_at_unix_ms ASC, rate_kind ASC,
                subject_scope ASC, subject_sha256 ASC LIMIT ?
        )"#,
    )
    .bind(to_i64(observed_at.get())?)
    .bind(limit)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GovernanceOperationError::Storage)?;
    let removed_audit_records =
        u16::try_from(audit.rows_affected()).map_err(|_| GovernanceOperationError::Binding)?;
    let removed_rate_subjects =
        u16::try_from(rates.rows_affected()).map_err(|_| GovernanceOperationError::Binding)?;
    record_audit(
        transaction,
        AuditEvidence {
            correlation,
            occurred_at: observed_at,
            operation_id: None,
        },
        MycAuditKind::GovernanceCompaction,
        MycAuditOutcome::Succeeded,
        MycAuditReasonCode::Compacted,
    )
    .await?;
    Ok(MycGovernanceCompactionOutcome {
        removed_audit_records,
        removed_rate_subjects,
    })
}

async fn read_audit_state(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<u64, GovernanceOperationError> {
    let rows = sqlx::query(READ_AUDIT_STATE_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(GovernanceOperationError::Binding);
    }
    bounded_nonnegative(&rows[0], "next_sequence")
}

async fn read_audit_by_id(
    transaction: &mut ServiceSqliteTransaction<'_>,
    audit_id: [u8; 32],
) -> Result<Option<MycAuditRecord>, GovernanceOperationError> {
    let rows = sqlx::query(READ_AUDIT_BY_ID_SQL)
        .bind(audit_id.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| GovernanceOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(GovernanceOperationError::Binding);
    }
    rows.first().map(decode_audit).transpose()
}

fn decode_audit(row: &sqlx::sqlite::SqliteRow) -> Result<MycAuditRecord, GovernanceOperationError> {
    let correlation_id = MycAuditCorrelationId(bounded_digest(row, "correlation_id")?);
    let kind = bounded_text(row, "audit_kind")
        .and_then(|value| MycAuditKind::parse(&value).ok_or(GovernanceOperationError::Binding))?;
    let outcome = bounded_text(row, "outcome").and_then(|value| {
        MycAuditOutcome::parse(&value).ok_or(GovernanceOperationError::Binding)
    })?;
    let reason = bounded_text(row, "reason_code").and_then(|value| {
        MycAuditReasonCode::parse(&value).ok_or(GovernanceOperationError::Binding)
    })?;
    let operation_id =
        optional_digest(row, "operation_id")?.map(MycSignerOperationId::from_persisted);
    let request_audit_kind = optional_text(row, "request_audit_kind")?;
    let request_correlation_id = optional_digest(row, "request_correlation_id")?;
    let request_bound = matches!(
        kind,
        MycAuditKind::ConnectionAdmission
            | MycAuditKind::ChallengeCreation
            | MycAuditKind::ChallengeAuthorization
    );
    if request_bound
        != (operation_id.is_some()
            && request_audit_kind.as_deref() == Some(kind.as_str())
            && request_correlation_id == Some(correlation_id.0))
        || (!request_bound
            && (operation_id.is_some()
                || request_audit_kind.is_some()
                || request_correlation_id.is_some()))
    {
        return Err(GovernanceOperationError::Binding);
    }
    let sequence = bounded_i64(row, "audit_sequence")?;
    let occurred_at = MycConnectionTimeUnixMs::new(bounded_i64(row, "occurred_at_unix_ms")?)
        .map_err(|_| GovernanceOperationError::Binding)?;
    Ok(MycAuditRecord {
        sequence,
        correlation_id,
        operation_id,
        kind,
        outcome,
        reason,
        occurred_at,
    })
}

async fn verify_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), GovernanceOperationError> {
    require_expected_metadata(transaction, expected)
        .await
        .map_err(|error| match error {
            RepositoryOperationError::Binding => GovernanceOperationError::Binding,
            RepositoryOperationError::Storage => GovernanceOperationError::Storage,
        })
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<GovernanceOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(GovernanceOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(GovernanceOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}

fn subject_parts(subject: RateSubject) -> (&'static str, [u8; 32]) {
    match subject {
        RateSubject::Global => ("global", hash_framed(GLOBAL_SUBJECT_DOMAIN, b"global")),
        RateSubject::Relay(digest) => ("relay", digest),
        RateSubject::Connection(connection) => (
            "connection",
            hash_framed(CONNECTION_SUBJECT_DOMAIN, connection.as_bytes()),
        ),
    }
}

fn derive_audit_id(correlation: MycAuditCorrelationId, kind: MycAuditKind) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_ID_DOMAIN);
    hasher.update(correlation.0);
    hasher.update((kind.as_str().len() as u64).to_be_bytes());
    hasher.update(kind.as_str().as_bytes());
    hasher.finalize().into()
}

fn hash_framed(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn checked_time_add(left: u64, right: u64) -> Result<u64, GovernanceOperationError> {
    left.checked_add(right)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(GovernanceOperationError::Binding)
}

fn to_i64(value: u64) -> Result<i64, GovernanceOperationError> {
    i64::try_from(value).map_err(|_| GovernanceOperationError::Binding)
}

fn bounded_i64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, GovernanceOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| GovernanceOperationError::Binding)?;
    u64::try_from(value).map_err(|_| GovernanceOperationError::Binding)
}

fn bounded_nonnegative(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, GovernanceOperationError> {
    bounded_i64(row, column)
}

fn bounded_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], GovernanceOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| GovernanceOperationError::Binding)?
        .ok_or(GovernanceOperationError::Binding)?
        .try_into()
        .map_err(|_| GovernanceOperationError::Binding)
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Box<str>, GovernanceOperationError> {
    row.try_get::<Option<String>, _>(column)
        .map_err(|_| GovernanceOperationError::Binding)?
        .ok_or(GovernanceOperationError::Binding)
        .map(String::into_boxed_str)
}

fn optional_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<[u8; 32]>, GovernanceOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| GovernanceOperationError::Binding)?
        .map(|value| {
            value
                .try_into()
                .map_err(|_| GovernanceOperationError::Binding)
        })
        .transpose()
}

fn optional_text(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<Box<str>>, GovernanceOperationError> {
    row.try_get::<Option<String>, _>(column)
        .map_err(|_| GovernanceOperationError::Binding)
        .map(|value| value.map(String::into_boxed_str))
}

fn require_one(rows: u64) -> Result<(), GovernanceOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(GovernanceOperationError::Binding)
}
