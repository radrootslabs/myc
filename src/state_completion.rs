//! Atomic durable completion of one admitted NIP-46 operation.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::ServiceSqliteTransaction;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use radroots_service_sqlite::{ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind};
use sha2::{Digest, Sha256};
use sqlx::Row;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::{
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MycConnectionDecision, MycConnectionDecisionRecord,
    MycConnectionId, MycConnectionStatus, MycConnectionTimeUnixMs, MycNip46Work, MycNip46WorkKind,
    MycSignerCorrelationId, MycSignerOperationId, MycSignerRequestMethod, MycSignerRequestRecord,
    MycVerifiedProviderResponse,
};

const READ_REQUEST_SQL: &str = r#"SELECT
    CASE WHEN typeof(correlation_id) = 'blob' AND length(correlation_id) = 32
        THEN correlation_id ELSE NULL END AS correlation_id,
    CASE WHEN typeof(method) = 'text' AND length(CAST(method AS BLOB)) BETWEEN 1 AND 32
        THEN method ELSE NULL END AS method,
    received_at_unix_ms
FROM nip46_requests WHERE operation_id = ? LIMIT 2"#;

const READ_CONNECTION_SQL: &str = r#"SELECT
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    policy_generation, updated_at_unix_ms
FROM connections WHERE connection_id = ? LIMIT 2"#;

const READ_CONNECT_DECISION_SQL: &str = r#"SELECT
    CASE WHEN typeof(decision) = 'text' AND length(CAST(decision AS BLOB)) <= 32
        THEN decision ELSE NULL END AS decision,
    CASE WHEN typeof(connection_id) = 'blob' AND length(connection_id) = 32
        THEN connection_id ELSE NULL END AS connection_id,
    typeof(connection_id) AS connection_id_type
FROM nip46_request_decisions WHERE operation_id = ? LIMIT 2"#;

const READ_COMMIT_SQL: &str = r#"SELECT
    CASE WHEN typeof(correlation_id) = 'blob' AND length(correlation_id) = 32
        THEN correlation_id ELSE NULL END AS correlation_id,
    CASE WHEN typeof(method) = 'text' AND length(CAST(method AS BLOB)) BETWEEN 1 AND 32
        THEN method ELSE NULL END AS method,
    CASE WHEN typeof(connection_id) = 'blob' AND length(connection_id) = 32
        THEN connection_id ELSE NULL END AS connection_id,
    typeof(connection_id) AS connection_id_type,
    CASE WHEN typeof(session_effect) = 'text' AND length(CAST(session_effect AS BLOB)) <= 32
        THEN session_effect ELSE NULL END AS session_effect,
    CASE WHEN typeof(provider_operation_id) = 'blob' AND length(provider_operation_id) = 32
        THEN provider_operation_id ELSE NULL END AS provider_operation_id,
    typeof(provider_operation_id) AS provider_operation_id_type,
    CASE WHEN typeof(provider_artifact_kind) = 'text'
        AND length(CAST(provider_artifact_kind AS BLOB)) <= 16
        THEN provider_artifact_kind ELSE NULL END AS provider_artifact_kind,
    CASE WHEN typeof(provider_artifact_sha256) = 'blob'
        AND length(provider_artifact_sha256) = 32
        THEN provider_artifact_sha256 ELSE NULL END AS provider_artifact_sha256,
    typeof(provider_artifact_sha256) AS provider_artifact_sha256_type,
    CASE WHEN typeof(provider_artifact) = 'blob'
        AND length(provider_artifact) BETWEEN 1 AND 1048576
        THEN provider_artifact ELSE NULL END AS provider_artifact,
    typeof(provider_artifact) AS provider_artifact_type,
    CASE WHEN typeof(reason_code) = 'text' AND length(CAST(reason_code AS BLOB)) <= 32
        THEN reason_code ELSE NULL END AS reason_code,
    CASE WHEN typeof(outcome) = 'text' AND length(CAST(outcome AS BLOB)) <= 16
        THEN outcome ELSE NULL END AS outcome,
    completed_at_unix_ms
FROM nip46_operation_commits WHERE operation_id = ? LIMIT 2"#;

const INSERT_COMMIT_SQL: &str = r#"INSERT INTO nip46_operation_commits (
    operation_id, correlation_id, method, connection_id, session_effect,
    provider_operation_id, provider_artifact_kind, provider_artifact_sha256,
    provider_artifact, outcome, reason_code, completed_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'succeeded', ?, ?)"#;

const REVOKE_CONNECTION_SQL: &str = r#"UPDATE connections
SET status = 'expired', updated_at_unix_ms = ?, authorized_until_unix_ms = NULL
WHERE connection_id = ? AND status = 'active' AND policy_generation = ?"#;

/// Closed session mutation committed with a NIP-46 operation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46SessionEffect {
    None,
    ConnectionAdmitted,
    ConnectionRevoked,
}

impl MycNip46SessionEffect {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ConnectionAdmitted => "connection_admitted",
            Self::ConnectionRevoked => "connection_revoked",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "connection_admitted" => Some(Self::ConnectionAdmitted),
            "connection_revoked" => Some(Self::ConnectionRevoked),
            _ => None,
        }
    }
}

/// Stable construction failure classes for a NIP-46 completion commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46CommitErrorKind {
    InvalidBinding,
    InvalidTime,
}

impl MycNip46CommitErrorKind {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "nip46_commit_binding_invalid",
            Self::InvalidTime => "nip46_commit_time_invalid",
        }
    }
}

/// Source-free redacted construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46CommitError {
    kind: MycNip46CommitErrorKind,
}

impl MycNip46CommitError {
    const fn new(kind: MycNip46CommitErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycNip46CommitErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycNip46CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycNip46CommitErrorKind::InvalidBinding => "NIP-46 completion binding is invalid",
            MycNip46CommitErrorKind::InvalidTime => "NIP-46 completion time is invalid",
        })
    }
}

impl fmt::Debug for MycNip46CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46CommitError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycNip46CommitError {}

/// One sealed, independently bound NIP-46 completion request.
pub struct MycNip46CommitRequest {
    request: MycSignerRequestRecord,
    connection_id: Option<MycConnectionId>,
    connection_generation: Option<u64>,
    connect_decision: Option<MycConnectionDecision>,
    session_effect: MycNip46SessionEffect,
    provider_operation_id: Option<[u8; 32]>,
    artifact: Option<Box<[u8]>>,
    artifact_sha256: Option<[u8; 32]>,
    reason_code: &'static str,
    completed_at: MycConnectionTimeUnixMs,
    #[cfg(test)]
    fail_after_session_effect: bool,
}

impl MycNip46CommitRequest {
    /// Binds already-admitted work and any independently verified provider output.
    ///
    /// A terminal connect decision is required for connect work. Provider work
    /// requires its exact verified result. Local work accepts neither. Only an
    /// independently verified signed-event result is retained as an artifact;
    /// protected provider output is deliberately not persisted here.
    pub fn new(
        work: &MycNip46Work,
        connect_decision: Option<&MycConnectionDecisionRecord>,
        provider_response: Option<&MycVerifiedProviderResponse>,
        completed_at: MycConnectionTimeUnixMs,
    ) -> Result<Self, MycNip46CommitError> {
        if completed_at.get() < work.request_record().received_at().get()
            || work
                .connection()
                .is_some_and(|connection| completed_at < connection.updated_at())
        {
            return Err(MycNip46CommitError::new(
                MycNip46CommitErrorKind::InvalidTime,
            ));
        }

        let mut connection_id = work.connection().map(|connection| connection.id());
        let mut connection_generation = work
            .connection()
            .map(|connection| connection.policy_generation().get());
        let mut terminal_connect_decision = None;
        let (session_effect, reason_code) = match work.kind() {
            MycNip46WorkKind::Connect => {
                if provider_response.is_some() {
                    return Err(MycNip46CommitError::new(
                        MycNip46CommitErrorKind::InvalidBinding,
                    ));
                }
                let decision = connect_decision.ok_or_else(|| {
                    MycNip46CommitError::new(MycNip46CommitErrorKind::InvalidBinding)
                })?;
                if decision.operation_id() != work.request_record().operation_id()
                    || !matches!(
                        decision.decision(),
                        MycConnectionDecision::Allowed | MycConnectionDecision::Denied
                    )
                {
                    return Err(MycNip46CommitError::new(
                        MycNip46CommitErrorKind::InvalidBinding,
                    ));
                }
                if completed_at < decision.decided_at() {
                    return Err(MycNip46CommitError::new(
                        MycNip46CommitErrorKind::InvalidTime,
                    ));
                }
                connection_id = decision.connection().map(|connection| connection.id());
                connection_generation = decision
                    .connection()
                    .map(|connection| connection.policy_generation().get());
                terminal_connect_decision = Some(decision.decision());
                match decision.decision() {
                    MycConnectionDecision::Allowed => {
                        if decision.connection().is_none_or(|connection| {
                            connection.status() != MycConnectionStatus::Active
                        }) {
                            return Err(MycNip46CommitError::new(
                                MycNip46CommitErrorKind::InvalidBinding,
                            ));
                        }
                        (
                            MycNip46SessionEffect::ConnectionAdmitted,
                            "connection_admitted",
                        )
                    }
                    MycConnectionDecision::Denied => {
                        if decision.connection().is_some() {
                            return Err(MycNip46CommitError::new(
                                MycNip46CommitErrorKind::InvalidBinding,
                            ));
                        }
                        (MycNip46SessionEffect::None, "connection_denied")
                    }
                    MycConnectionDecision::PendingApproval | MycConnectionDecision::Challenged => {
                        unreachable!("nonterminal decisions rejected above")
                    }
                }
            }
            MycNip46WorkKind::Local => {
                if connect_decision.is_some() || provider_response.is_some() {
                    return Err(MycNip46CommitError::new(
                        MycNip46CommitErrorKind::InvalidBinding,
                    ));
                }
                if work.method() == MycSignerRequestMethod::Logout {
                    (MycNip46SessionEffect::ConnectionRevoked, "session_revoked")
                } else {
                    (MycNip46SessionEffect::None, "completed")
                }
            }
            MycNip46WorkKind::Provider => {
                if connect_decision.is_some() {
                    return Err(MycNip46CommitError::new(
                        MycNip46CommitErrorKind::InvalidBinding,
                    ));
                }
                (MycNip46SessionEffect::None, "completed")
            }
        };

        let provider = bind_provider_result(work, provider_response)?;
        Ok(Self {
            request: work.request_record().clone(),
            connection_id,
            connection_generation,
            connect_decision: terminal_connect_decision,
            session_effect,
            provider_operation_id: provider.operation_id,
            artifact: provider.artifact,
            artifact_sha256: provider.artifact_sha256,
            reason_code,
            completed_at,
            #[cfg(test)]
            fail_after_session_effect: false,
        })
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn fail_after_session_effect_for_test(mut self) -> Self {
        self.fail_after_session_effect = true;
        self
    }
}

impl fmt::Debug for MycNip46CommitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46CommitRequest")
            .field("method", &self.request.method())
            .field("session_effect", &self.session_effect)
            .field("artifact", &self.artifact.as_ref().map(|_| "[redacted]"))
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Immutable result of the atomic local completion transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct MycNip46CommitRecord {
    operation_id: MycSignerOperationId,
    correlation_id: MycSignerCorrelationId,
    method: MycSignerRequestMethod,
    connection_id: Option<MycConnectionId>,
    session_effect: MycNip46SessionEffect,
    artifact_sha256: Option<[u8; 32]>,
    completed_at: MycConnectionTimeUnixMs,
}

impl MycNip46CommitRecord {
    #[must_use]
    pub const fn operation_id(&self) -> MycSignerOperationId {
        self.operation_id
    }
    #[must_use]
    pub const fn correlation_id(&self) -> MycSignerCorrelationId {
        self.correlation_id
    }
    #[must_use]
    pub const fn method(&self) -> MycSignerRequestMethod {
        self.method
    }
    #[must_use]
    pub const fn connection_id(&self) -> Option<MycConnectionId> {
        self.connection_id
    }
    #[must_use]
    pub const fn session_effect(&self) -> MycNip46SessionEffect {
        self.session_effect
    }
    #[must_use]
    pub const fn artifact_sha256(&self) -> Option<&[u8; 32]> {
        self.artifact_sha256.as_ref()
    }
    #[must_use]
    pub const fn completed_at(&self) -> MycConnectionTimeUnixMs {
        self.completed_at
    }
}

impl fmt::Debug for MycNip46CommitRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46CommitRecord")
            .field("method", &self.method)
            .field("session_effect", &self.session_effect)
            .field("artifact", &self.artifact_sha256.map(|_| "[redacted]"))
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// New or exact-replayed completion result.
#[derive(Clone, PartialEq, Eq)]
pub enum MycNip46CommitAdmission {
    Committed(MycNip46CommitRecord),
    ExactReplay(MycNip46CommitRecord),
}

impl MycNip46CommitAdmission {
    #[must_use]
    pub const fn record(&self) -> &MycNip46CommitRecord {
        match self {
            Self::Committed(record) | Self::ExactReplay(record) => record,
        }
    }
}

impl fmt::Debug for MycNip46CommitAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "MycNip46CommitAdmission::Committed([redacted])",
            Self::ExactReplay(_) => "MycNip46CommitAdmission::ExactReplay([redacted])",
        })
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
impl MycStateRepository<'_> {
    /// Atomically records the Step 147 completion component.
    ///
    /// This integration-branch checkpoint is not a complete production
    /// response commit. Step 148 must compose this component with the outer
    /// signed response, immutable relay targets, and initial outbox state in
    /// the same transaction before RCLD-RSHR-080 may be promoted to `master`.
    pub(crate) async fn commit_nip46_operation(
        &self,
        request: &MycNip46CommitRequest,
    ) -> Result<MycNip46CommitAdmission, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        let request = request.owned();
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(map_repository_error)?;
                    commit_operation(transaction, &request).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

impl MycNip46CommitRequest {
    pub(crate) const fn signer_request(&self) -> &MycSignerRequestRecord {
        &self.request
    }

    pub(crate) const fn completed_at(&self) -> MycConnectionTimeUnixMs {
        self.completed_at
    }

    pub(crate) fn owned(&self) -> Self {
        Self {
            request: self.request.clone(),
            connection_id: self.connection_id,
            connection_generation: self.connection_generation,
            connect_decision: self.connect_decision,
            session_effect: self.session_effect,
            provider_operation_id: self.provider_operation_id,
            artifact: self.artifact.clone(),
            artifact_sha256: self.artifact_sha256,
            reason_code: self.reason_code,
            completed_at: self.completed_at,
            #[cfg(test)]
            fail_after_session_effect: self.fail_after_session_effect,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitOperationError {
    Binding,
    Storage,
}

pub(crate) async fn commit_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46CommitRequest,
) -> Result<MycNip46CommitAdmission, CommitOperationError> {
    verify_request(transaction, request).await?;
    if let Some(existing) = read_commit(transaction, request).await? {
        return Ok(MycNip46CommitAdmission::ExactReplay(existing));
    }
    verify_connect_decision(transaction, request).await?;
    verify_or_apply_session_effect(transaction, request).await?;
    #[cfg(test)]
    if request.fail_after_session_effect {
        return Err(CommitOperationError::Storage);
    }
    let artifact_kind = if request.artifact.is_some() {
        "signed_event"
    } else {
        "none"
    };
    let result = sqlx::query(INSERT_COMMIT_SQL)
        .bind(request.request.operation_id().as_bytes().as_slice())
        .bind(request.request.correlation_id().as_bytes().as_slice())
        .bind(request.request.method().as_str())
        .bind(request.connection_id.map(|id| id.as_bytes().to_vec()))
        .bind(request.session_effect.as_str())
        .bind(request.provider_operation_id.map(|id| id.to_vec()))
        .bind(artifact_kind)
        .bind(request.artifact_sha256.map(|digest| digest.to_vec()))
        .bind(request.artifact.as_deref())
        .bind(request.reason_code)
        .bind(to_i64(request.completed_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    require_one(result.rows_affected())?;
    read_commit(transaction, request)
        .await?
        .map(MycNip46CommitAdmission::Committed)
        .ok_or(CommitOperationError::Binding)
}

async fn verify_request(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46CommitRequest,
) -> Result<(), CommitOperationError> {
    let rows = sqlx::query(READ_REQUEST_SQL)
        .bind(request.request.operation_id().as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    let [row] = rows.as_slice() else {
        return Err(CommitOperationError::Binding);
    };
    let correlation = exact_bytes(row, "correlation_id")?;
    let method = bounded_text(row, "method")?;
    let received_at = positive_i64(row, "received_at_unix_ms")?;
    (correlation == *request.request.correlation_id().as_bytes()
        && method == request.request.method().as_str()
        && received_at == request.request.received_at().get()
        && request.completed_at.get() >= received_at)
        .then_some(())
        .ok_or(CommitOperationError::Binding)
}

async fn verify_connect_decision(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46CommitRequest,
) -> Result<(), CommitOperationError> {
    let Some(expected_decision) = request.connect_decision else {
        return Ok(());
    };
    let rows = sqlx::query(READ_CONNECT_DECISION_SQL)
        .bind(request.request.operation_id().as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    let [row] = rows.as_slice() else {
        return Err(CommitOperationError::Binding);
    };
    let decision = bounded_text(row, "decision")?;
    let connection = optional_exact_bytes(row, "connection_id", "connection_id_type")?;
    (decision
        == match expected_decision {
            MycConnectionDecision::Allowed => "allowed",
            MycConnectionDecision::Denied => "denied",
            MycConnectionDecision::PendingApproval | MycConnectionDecision::Challenged => {
                return Err(CommitOperationError::Binding);
            }
        }
        && connection == request.connection_id.map(|id| *id.as_bytes()))
    .then_some(())
    .ok_or(CommitOperationError::Binding)
}

async fn verify_or_apply_session_effect(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46CommitRequest,
) -> Result<(), CommitOperationError> {
    let Some(connection_id) = request.connection_id else {
        return (request.connection_generation.is_none()
            && request.session_effect == MycNip46SessionEffect::None)
            .then_some(())
            .ok_or(CommitOperationError::Binding);
    };
    let generation = request
        .connection_generation
        .ok_or(CommitOperationError::Binding)?;
    let rows = sqlx::query(READ_CONNECTION_SQL)
        .bind(connection_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    let [row] = rows.as_slice() else {
        return Err(CommitOperationError::Binding);
    };
    let status = bounded_text(row, "status")?;
    let actual_generation = positive_i64(row, "policy_generation")?;
    let updated_at = positive_i64(row, "updated_at_unix_ms")?;
    if actual_generation != generation || request.completed_at.get() < updated_at {
        return Err(CommitOperationError::Binding);
    }
    match request.session_effect {
        MycNip46SessionEffect::ConnectionRevoked => {
            if status != "active" {
                return Err(CommitOperationError::Binding);
            }
            let result = sqlx::query(REVOKE_CONNECTION_SQL)
                .bind(to_i64(request.completed_at.get())?)
                .bind(connection_id.as_bytes().as_slice())
                .bind(to_i64(generation)?)
                .execute(&mut *transaction)
                .await
                .map_err(|_| CommitOperationError::Storage)?;
            require_one(result.rows_affected())
        }
        MycNip46SessionEffect::None | MycNip46SessionEffect::ConnectionAdmitted => (status
            == "active")
            .then_some(())
            .ok_or(CommitOperationError::Binding),
    }
}

async fn read_commit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46CommitRequest,
) -> Result<Option<MycNip46CommitRecord>, CommitOperationError> {
    let rows = sqlx::query(READ_COMMIT_SQL)
        .bind(request.request.operation_id().as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(CommitOperationError::Binding);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let correlation = exact_bytes(row, "correlation_id")?;
    let method = MycSignerRequestMethod::parse(bounded_text(row, "method")?)
        .ok_or(CommitOperationError::Binding)?;
    let connection = optional_exact_bytes(row, "connection_id", "connection_id_type")?;
    let session_effect = MycNip46SessionEffect::parse(bounded_text(row, "session_effect")?)
        .ok_or(CommitOperationError::Binding)?;
    let provider_operation =
        optional_exact_bytes(row, "provider_operation_id", "provider_operation_id_type")?;
    let artifact_kind = bounded_text(row, "provider_artifact_kind")?;
    let artifact_digest = optional_exact_bytes(
        row,
        "provider_artifact_sha256",
        "provider_artifact_sha256_type",
    )?;
    let artifact = optional_bounded_blob(row, "provider_artifact", "provider_artifact_type")?;
    let reason = bounded_text(row, "reason_code")?;
    let outcome = bounded_text(row, "outcome")?;
    let completed_at = positive_i64(row, "completed_at_unix_ms")?;
    let exact = correlation == *request.request.correlation_id().as_bytes()
        && method == request.request.method()
        && connection == request.connection_id.map(|id| *id.as_bytes())
        && session_effect == request.session_effect
        && provider_operation == request.provider_operation_id
        && artifact_digest == request.artifact_sha256
        && artifact.as_deref() == request.artifact.as_deref()
        && artifact_kind
            == if request.artifact.is_some() {
                "signed_event"
            } else {
                "none"
            }
        && reason == request.reason_code
        && outcome == "succeeded"
        && completed_at == request.completed_at.get();
    if !exact {
        return Err(CommitOperationError::Binding);
    }
    Ok(Some(MycNip46CommitRecord {
        operation_id: request.request.operation_id(),
        correlation_id: request.request.correlation_id(),
        method,
        connection_id: request.connection_id,
        session_effect,
        artifact_sha256: artifact_digest,
        completed_at: request.completed_at,
    }))
}

struct BoundProviderResult {
    operation_id: Option<[u8; 32]>,
    artifact: Option<Box<[u8]>>,
    artifact_sha256: Option<[u8; 32]>,
}

fn bind_provider_result(
    work: &MycNip46Work,
    response: Option<&MycVerifiedProviderResponse>,
) -> Result<BoundProviderResult, MycNip46CommitError> {
    let Some(operation) = work.provider_operation() else {
        if response.is_some() {
            return Err(MycNip46CommitError::new(
                MycNip46CommitErrorKind::InvalidBinding,
            ));
        }
        return Ok(BoundProviderResult {
            operation_id: None,
            artifact: None,
            artifact_sha256: None,
        });
    };
    let response = response
        .ok_or_else(|| MycNip46CommitError::new(MycNip46CommitErrorKind::InvalidBinding))?;
    if response.operation_id() != operation.operation_id()
        || response.correlation_id() != operation.correlation_id()
        || response.instance() != operation.instance()
        || response.role() != operation.role()
        || response.capability() != operation.input().capability()
        || !response.matches_operation(operation)
    {
        return Err(MycNip46CommitError::new(
            MycNip46CommitErrorKind::InvalidBinding,
        ));
    }
    let artifact: Option<Box<[u8]>> = response.signed_event_bytes().map(Box::<[u8]>::from);
    if artifact
        .as_deref()
        .is_some_and(|bytes| bytes.is_empty() || bytes.len() > MYC_PROVIDER_OUTPUT_MAX_BYTES)
    {
        return Err(MycNip46CommitError::new(
            MycNip46CommitErrorKind::InvalidBinding,
        ));
    }
    let digest = artifact
        .as_deref()
        .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)));
    Ok(BoundProviderResult {
        operation_id: Some(*operation.operation_id().as_bytes()),
        artifact,
        artifact_sha256: digest,
    })
}

fn exact_bytes(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], CommitOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| CommitOperationError::Binding)?
        .ok_or(CommitOperationError::Binding)?
        .try_into()
        .map_err(|_| CommitOperationError::Binding)
}

fn optional_exact_bytes(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<[u8; 32]>, CommitOperationError> {
    let value = row
        .try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| CommitOperationError::Binding)?;
    let kind = row
        .try_get::<String, _>(type_column)
        .map_err(|_| CommitOperationError::Binding)?;
    match (kind.as_str(), value) {
        ("null", None) => Ok(None),
        ("blob", Some(bytes)) => bytes
            .try_into()
            .map(Some)
            .map_err(|_| CommitOperationError::Binding),
        _ => Err(CommitOperationError::Binding),
    }
}

fn optional_bounded_blob(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<Box<[u8]>>, CommitOperationError> {
    let value = row
        .try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| CommitOperationError::Binding)?;
    let kind = row
        .try_get::<String, _>(type_column)
        .map_err(|_| CommitOperationError::Binding)?;
    match (kind.as_str(), value) {
        ("null", None) => Ok(None),
        ("blob", Some(bytes))
            if !bytes.is_empty() && bytes.len() <= MYC_PROVIDER_OUTPUT_MAX_BYTES =>
        {
            Ok(Some(bytes.into_boxed_slice()))
        }
        _ => Err(CommitOperationError::Binding),
    }
}

fn bounded_text<'row>(
    row: &'row sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<&'row str, CommitOperationError> {
    row.try_get::<Option<&str>, _>(column)
        .map_err(|_| CommitOperationError::Binding)?
        .ok_or(CommitOperationError::Binding)
}

fn positive_i64(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<u64, CommitOperationError> {
    row.try_get::<i64, _>(column)
        .map_err(|_| CommitOperationError::Binding)
        .and_then(|value| u64::try_from(value).map_err(|_| CommitOperationError::Binding))
        .and_then(|value| {
            (value != 0)
                .then_some(value)
                .ok_or(CommitOperationError::Binding)
        })
}

fn to_i64(value: u64) -> Result<i64, CommitOperationError> {
    i64::try_from(value).map_err(|_| CommitOperationError::Binding)
}

fn require_one(rows: u64) -> Result<(), CommitOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(CommitOperationError::Storage)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
const fn map_repository_error(error: RepositoryOperationError) -> CommitOperationError {
    match error {
        RepositoryOperationError::Binding => CommitOperationError::Binding,
        RepositoryOperationError::Storage => CommitOperationError::Storage,
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn map_transaction_error(
    error: ServiceSqliteTransactionError<CommitOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(CommitOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(CommitOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
