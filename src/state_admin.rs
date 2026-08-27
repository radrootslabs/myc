//! Bounded durable idempotency for permissioned Myc admin mutations.

use core::{fmt, future::Future, pin::Pin};
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    MycAdminRequestDocument, MycAdminResponseDocument, MycAdminRoute, MycStateRepository,
    state_repository::{PersistedMetadata, RepositoryOperationError, require_expected_metadata},
};

/// Maximum encoded length of a durable admin operation identifier.
pub const MYC_ADMIN_OPERATION_ID_MAX_BYTES: usize = 128;
/// Maximum canonical response-model bytes retained for replay.
pub const MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES: usize = 8_192;
/// Maximum encoded success envelope for an 8,192-byte model and 128-byte correlation ID.
pub const MYC_ADMIN_OPERATION_RESPONSE_ENVELOPE_MAX_UTF8_BYTES: u32 = 8_382;
/// Maximum retained completed operations after expiry pruning.
pub const MYC_ADMIN_OPERATION_COMPLETED_LIMIT: u16 = 4_096;
/// Maximum retained operations whose external outcome is unresolved.
pub const MYC_ADMIN_OPERATION_PREPARED_LIMIT: u8 = 128;
/// Minimum configurable completed-response retention.
pub const MYC_ADMIN_OPERATION_MIN_RETENTION_MS: u64 = 1;
/// Maximum configurable completed-response retention.
pub const MYC_ADMIN_OPERATION_MAX_RETENTION_MS: u64 = 31_536_000_000;
/// Frozen seven-day completed-response retention.
pub const MYC_ADMIN_OPERATION_DEFAULT_RETENTION_MS: u64 = 604_800_000;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"radroots.myc.admin_operation_request.v1\0";
const PRUNE_LIMIT: i64 = 4_096;

const PRUNE_EXPIRED_SQL: &str = r#"DELETE FROM myc_admin_operations
WHERE operation_id IN (
    SELECT operation_id FROM myc_admin_operations
    WHERE state = 'completed' AND expires_at_unix_ms <= ?
    ORDER BY expires_at_unix_ms, operation_id
    LIMIT ?
)"#;

const READ_OPERATION_SQL: &str = r#"SELECT
    CASE WHEN typeof(route) = 'text' AND length(CAST(route AS BLOB)) BETWEEN 1 AND 128
        THEN route ELSE NULL END AS route,
    CASE WHEN typeof(request_sha256) = 'blob' AND length(request_sha256) = 32
        THEN request_sha256 ELSE NULL END AS request_sha256,
    CASE WHEN typeof(state) = 'text' AND length(CAST(state AS BLOB)) <= 16
        THEN state ELSE NULL END AS state,
    CASE WHEN typeof(response_model) = 'blob' AND length(response_model) BETWEEN 1 AND 8192
        THEN response_model ELSE NULL END AS response_model,
    typeof(response_model) AS response_model_type,
    CASE WHEN typeof(response_sha256) = 'blob' AND length(response_sha256) = 32
        THEN response_sha256 ELSE NULL END AS response_sha256,
    typeof(response_sha256) AS response_sha256_type,
    prepared_at_unix_ms,
    completed_at_unix_ms,
    typeof(completed_at_unix_ms) AS completed_at_type,
    expires_at_unix_ms,
    typeof(expires_at_unix_ms) AS expires_at_type
FROM myc_admin_operations
WHERE operation_id = ?
LIMIT 2"#;

const READ_COUNTS_SQL: &str = r#"SELECT
    COUNT(CASE WHEN state = 'completed' THEN 1 END) AS completed_count,
    COUNT(CASE WHEN state = 'prepared' THEN 1 END) AS prepared_count
FROM myc_admin_operations"#;

const INSERT_PREPARED_SQL: &str = r#"INSERT INTO myc_admin_operations (
    operation_id, route, request_sha256, state, prepared_at_unix_ms
) VALUES (?, ?, ?, 'prepared', ?)"#;

const COMPLETE_OPERATION_SQL: &str = r#"UPDATE myc_admin_operations
SET state = 'completed', response_model = ?, response_sha256 = ?,
    completed_at_unix_ms = ?, expires_at_unix_ms = ?
WHERE operation_id = ? AND state = 'prepared'"#;

/// Stable source-free admin-journal failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAdminOperationErrorKind {
    InvalidMode,
    InvalidInput,
    OperationConflict,
    OperationOutcomeUnknown,
    ResourceExhausted,
    Binding,
    Transaction,
    CommitOutcomeUnknown,
}

impl MycAdminOperationErrorKind {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "admin_operation_mode_invalid",
            Self::InvalidInput => "admin_operation_input_invalid",
            Self::OperationConflict => "operation_conflict",
            Self::OperationOutcomeUnknown => "operation_outcome_unknown",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Binding => "admin_operation_binding_invalid",
            Self::Transaction => "admin_operation_transaction_failed",
            Self::CommitOutcomeUnknown => "admin_operation_commit_outcome_unknown",
        }
    }
}

/// Redacted admin-journal error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycAdminOperationError {
    kind: MycAdminOperationErrorKind,
}

impl MycAdminOperationError {
    const fn new(kind: MycAdminOperationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycAdminOperationErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycAdminOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycAdminOperationErrorKind::InvalidMode => {
                "Myc admin operation requires writable state"
            }
            MycAdminOperationErrorKind::InvalidInput => "Myc admin operation input is invalid",
            MycAdminOperationErrorKind::OperationConflict => {
                "Myc admin operation identity conflicts with retained evidence"
            }
            MycAdminOperationErrorKind::OperationOutcomeUnknown => {
                "Myc admin operation outcome is unknown"
            }
            MycAdminOperationErrorKind::ResourceExhausted => {
                "Myc admin operation capacity is exhausted"
            }
            MycAdminOperationErrorKind::Binding => "Myc admin operation journal binding is invalid",
            MycAdminOperationErrorKind::Transaction => "Myc admin operation transaction failed",
            MycAdminOperationErrorKind::CommitOutcomeUnknown => {
                "Myc admin operation commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for MycAdminOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAdminOperationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycAdminOperationError {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AdminOperationIdBinding(Box<str>);

impl AdminOperationIdBinding {
    fn new(value: &str) -> Result<Self, MycAdminOperationError> {
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MYC_ADMIN_OPERATION_ID_MAX_BYTES
            && bytes[0].is_ascii_alphanumeric()
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        valid
            .then(|| Self(value.into()))
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminOperationIdBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminOperationIdBinding([redacted])")
    }
}

/// Injected UTC millisecond evidence representable by SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycAdminOperationTimeUnixMs(u64);

impl MycAdminOperationTimeUnixMs {
    /// Validates one UTC millisecond instant without reading ambient time.
    pub fn new(value: u64) -> Result<Self, MycAdminOperationError> {
        i64::try_from(value)
            .map(|_| Self(value))
            .map_err(|_| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))
    }

    /// Returns the validated instant.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated admin operation time fits SQLite")
    }
}

/// Explicit bounded completed-response retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycAdminOperationJournalPolicy {
    completed_retention_ms: u64,
}

impl MycAdminOperationJournalPolicy {
    /// Admits the frozen inclusive retention range.
    pub fn new(completed_retention_ms: u64) -> Result<Self, MycAdminOperationError> {
        (MYC_ADMIN_OPERATION_MIN_RETENTION_MS..=MYC_ADMIN_OPERATION_MAX_RETENTION_MS)
            .contains(&completed_retention_ms)
            .then_some(Self {
                completed_retention_ms,
            })
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))
    }

    /// Returns the exact seven-day policy.
    #[must_use]
    pub const fn seven_days() -> Self {
        Self {
            completed_retention_ms: MYC_ADMIN_OPERATION_DEFAULT_RETENTION_MS,
        }
    }

    /// Returns the admitted retention duration.
    #[must_use]
    pub const fn completed_retention_ms(self) -> u64 {
        self.completed_retention_ms
    }
}

/// Sealed evidence that one external or cross-resource mutation is unresolved.
pub struct MycPreparedAdminOperation {
    operation_id: AdminOperationIdBinding,
    route: MycAdminRoute,
    request_sha256: [u8; 32],
    prepared_at: MycAdminOperationTimeUnixMs,
}

impl fmt::Debug for MycPreparedAdminOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycPreparedAdminOperation")
            .field("route", &self.route)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Result of mutation admission after bounded expiry pruning.
pub enum MycAdminOperationAdmission {
    Prepared(MycPreparedAdminOperation),
    ExactReplay(MycAdminResponseDocument),
}

impl fmt::Debug for MycAdminOperationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepared(_) => "MycAdminOperationAdmission::Prepared([redacted])",
            Self::ExactReplay(_) => "MycAdminOperationAdmission::ExactReplay([redacted])",
        })
    }
}

/// Result of completing a previously prepared operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAdminOperationCompletion {
    Completed,
    ExactReplay,
}

impl MycStateRepository<'_> {
    /// Atomically commits one SQLite-only admin mutation and its replay receipt.
    ///
    /// The supplied operation runs inside the same governed transaction that
    /// admits the operation identifier and records the canonical response. A
    /// domain failure therefore leaves neither a prepared journal row nor a
    /// partial domain effect.
    pub(crate) async fn execute_database_admin_operation<F>(
        &self,
        request: &MycAdminRequestDocument,
        completed_at: MycAdminOperationTimeUnixMs,
        policy: MycAdminOperationJournalPolicy,
        operation: F,
    ) -> Result<MycAdminResponseDocument, MycAdminOperationError>
    where
        F: for<'a, 'b> FnOnce(
                &'a mut ServiceSqliteTransaction<'b>,
            ) -> AdminDatabaseOperationFuture<'a>
            + Send
            + 'static,
    {
        if !self.is_writable() {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidMode,
            ));
        }
        let binding = AdminRequestBinding::from_document(request)?;
        let expires_at = completed_at
            .get()
            .checked_add(policy.completed_retention_ms())
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))?;
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AdminJournalOperationError::from)?;
                    let prepared = match prepare_operation(transaction, &binding, completed_at)
                        .await?
                    {
                        MycAdminOperationAdmission::ExactReplay(response) => return Ok(response),
                        MycAdminOperationAdmission::Prepared(prepared) => prepared,
                    };
                    let response = operation(transaction).await?;
                    if response.route() != binding.route
                        || response.canonical_bytes().is_empty()
                        || response.canonical_bytes().len()
                            > MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
                    {
                        return Err(AdminJournalOperationError::InvalidInput);
                    }
                    complete_operation(
                        transaction,
                        &PreparedBinding::from_prepared(&prepared),
                        response.canonical_bytes(),
                        completed_at,
                        expires_at,
                    )
                    .await?;
                    Ok(response)
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    pub(crate) async fn complete_prepared_database_admin_operation<F>(
        &self,
        prepared: &MycPreparedAdminOperation,
        completed_at: MycAdminOperationTimeUnixMs,
        policy: MycAdminOperationJournalPolicy,
        operation: F,
    ) -> Result<MycAdminResponseDocument, MycAdminOperationError>
    where
        F: for<'a, 'b> FnOnce(
                &'a mut ServiceSqliteTransaction<'b>,
            ) -> AdminDatabaseOperationFuture<'a>
            + Send
            + 'static,
    {
        if !self.is_writable() {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidMode,
            ));
        }
        if completed_at < prepared.prepared_at {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidInput,
            ));
        }
        let expires_at = completed_at
            .get()
            .checked_add(policy.completed_retention_ms())
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))?;
        let binding = PreparedBinding::from_prepared(prepared);
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AdminJournalOperationError::from)?;
                    let response = operation(transaction).await?;
                    if response.route() != binding.route
                        || response.canonical_bytes().is_empty()
                        || response.canonical_bytes().len()
                            > MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
                    {
                        return Err(AdminJournalOperationError::InvalidInput);
                    }
                    complete_operation(
                        transaction,
                        &binding,
                        response.canonical_bytes(),
                        completed_at,
                        expires_at,
                    )
                    .await?;
                    Ok(response)
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Prunes a bounded expired prefix and admits or replays one mutation.
    pub async fn prepare_admin_operation(
        &self,
        request: &MycAdminRequestDocument,
        observed_at: MycAdminOperationTimeUnixMs,
    ) -> Result<MycAdminOperationAdmission, MycAdminOperationError> {
        if !self.is_writable() {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidMode,
            ));
        }
        let binding = AdminRequestBinding::from_document(request)?;
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AdminJournalOperationError::from)?;
                    prepare_operation(transaction, &binding, observed_at).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Completes one external mutation only after its durable effect exists.
    pub async fn complete_admin_operation(
        &self,
        prepared: &MycPreparedAdminOperation,
        response: &MycAdminResponseDocument,
        completed_at: MycAdminOperationTimeUnixMs,
        policy: MycAdminOperationJournalPolicy,
    ) -> Result<MycAdminOperationCompletion, MycAdminOperationError> {
        if !self.is_writable() {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidMode,
            ));
        }
        if response.route() != prepared.route
            || response.canonical_bytes().is_empty()
            || response.canonical_bytes().len() > MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
            || completed_at < prepared.prepared_at
        {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidInput,
            ));
        }
        let expires_at = completed_at
            .get()
            .checked_add(policy.completed_retention_ms())
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))?;
        let binding = PreparedBinding::from_prepared(prepared);
        let response = response.canonical_bytes().to_vec().into_boxed_slice();
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AdminJournalOperationError::from)?;
                    complete_operation(transaction, &binding, &response, completed_at, expires_at)
                        .await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

struct AdminRequestBinding {
    operation_id: AdminOperationIdBinding,
    route: MycAdminRoute,
    request_sha256: [u8; 32],
}

impl AdminRequestBinding {
    fn from_document(request: &MycAdminRequestDocument) -> Result<Self, MycAdminOperationError> {
        if !request.route().is_mutation() {
            return Err(MycAdminOperationError::new(
                MycAdminOperationErrorKind::InvalidInput,
            ));
        }
        let operation_id = request
            .operation_id()
            .ok_or_else(|| MycAdminOperationError::new(MycAdminOperationErrorKind::InvalidInput))?;
        Ok(Self {
            operation_id: AdminOperationIdBinding::new(operation_id)?,
            route: request.route(),
            request_sha256: request_digest(request),
        })
    }
}

struct PreparedBinding {
    operation_id: AdminOperationIdBinding,
    route: MycAdminRoute,
    request_sha256: [u8; 32],
    prepared_at: MycAdminOperationTimeUnixMs,
}

impl PreparedBinding {
    fn from_prepared(prepared: &MycPreparedAdminOperation) -> Self {
        Self {
            operation_id: prepared.operation_id.clone(),
            route: prepared.route,
            request_sha256: prepared.request_sha256,
            prepared_at: prepared.prepared_at,
        }
    }
}

enum StoredOperation {
    Prepared {
        route: MycAdminRoute,
        request_sha256: [u8; 32],
        prepared_at: MycAdminOperationTimeUnixMs,
    },
    Completed {
        route: MycAdminRoute,
        request_sha256: [u8; 32],
        response: Box<[u8]>,
        response_sha256: [u8; 32],
        prepared_at: MycAdminOperationTimeUnixMs,
        completed_at: MycAdminOperationTimeUnixMs,
        expires_at: MycAdminOperationTimeUnixMs,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdminJournalOperationError {
    InvalidInput,
    Conflict,
    OutcomeUnknown,
    ResourceExhausted,
    Binding,
    Storage,
}

pub(crate) type AdminDatabaseOperationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<MycAdminResponseDocument, AdminJournalOperationError>>
            + Send
            + 'a,
    >,
>;

impl From<RepositoryOperationError> for AdminJournalOperationError {
    fn from(error: RepositoryOperationError) -> Self {
        match error {
            RepositoryOperationError::Binding => Self::Binding,
            RepositoryOperationError::Storage => Self::Storage,
        }
    }
}

async fn prepare_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    binding: &AdminRequestBinding,
    observed_at: MycAdminOperationTimeUnixMs,
) -> Result<MycAdminOperationAdmission, AdminJournalOperationError> {
    prune_expired(transaction, observed_at).await?;
    if let Some(existing) = read_operation(transaction, &binding.operation_id).await? {
        return match existing {
            StoredOperation::Prepared {
                route,
                request_sha256,
                ..
            } if route == binding.route && request_sha256 == binding.request_sha256 => {
                Err(AdminJournalOperationError::OutcomeUnknown)
            }
            StoredOperation::Completed {
                route,
                request_sha256,
                response,
                response_sha256,
                ..
            } if route == binding.route && request_sha256 == binding.request_sha256 => {
                if sha256(&response) != response_sha256 {
                    return Err(AdminJournalOperationError::Binding);
                }
                MycAdminResponseDocument::from_canonical_bytes(route, &response)
                    .map(MycAdminOperationAdmission::ExactReplay)
                    .map_err(|_| AdminJournalOperationError::Binding)
            }
            StoredOperation::Prepared { .. } | StoredOperation::Completed { .. } => {
                Err(AdminJournalOperationError::Conflict)
            }
        };
    }
    let (completed, prepared) = read_counts(transaction).await?;
    let reserved = completed
        .checked_add(prepared)
        .ok_or(AdminJournalOperationError::Binding)?;
    if reserved >= u64::from(MYC_ADMIN_OPERATION_COMPLETED_LIMIT)
        || prepared >= u64::from(MYC_ADMIN_OPERATION_PREPARED_LIMIT)
    {
        return Err(AdminJournalOperationError::ResourceExhausted);
    }
    let result = sqlx::query(INSERT_PREPARED_SQL)
        .bind(binding.operation_id.as_str())
        .bind(binding.route.operation_id())
        .bind(binding.request_sha256.as_slice())
        .bind(observed_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    require_one(result.rows_affected())?;
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Prepared {
            route,
            request_sha256,
            prepared_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && prepared_at == observed_at =>
        {
            Ok(MycAdminOperationAdmission::Prepared(
                MycPreparedAdminOperation {
                    operation_id: binding.operation_id.clone(),
                    route,
                    request_sha256,
                    prepared_at,
                },
            ))
        }
        Some(_) | None => Err(AdminJournalOperationError::Binding),
    }
}

async fn complete_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    binding: &PreparedBinding,
    response: &[u8],
    completed_at: MycAdminOperationTimeUnixMs,
    expires_at: u64,
) -> Result<MycAdminOperationCompletion, AdminJournalOperationError> {
    let response_sha256 = sha256(response);
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Completed {
            route,
            request_sha256,
            response: existing_response,
            response_sha256: existing_sha256,
            ..
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && existing_response.as_ref() == response
            && existing_sha256 == response_sha256 =>
        {
            return Ok(MycAdminOperationCompletion::ExactReplay);
        }
        Some(StoredOperation::Completed { .. }) => {
            return Err(AdminJournalOperationError::Conflict);
        }
        Some(StoredOperation::Prepared {
            route,
            request_sha256,
            prepared_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && prepared_at == binding.prepared_at => {}
        Some(StoredOperation::Prepared { .. }) => {
            return Err(AdminJournalOperationError::Conflict);
        }
        None => return Err(AdminJournalOperationError::Binding),
    }
    let (completed, _) = read_counts(transaction).await?;
    if completed >= u64::from(MYC_ADMIN_OPERATION_COMPLETED_LIMIT) {
        return Err(AdminJournalOperationError::ResourceExhausted);
    }
    let result = sqlx::query(COMPLETE_OPERATION_SQL)
        .bind(response)
        .bind(response_sha256.as_slice())
        .bind(completed_at.sqlite_value())
        .bind(i64::try_from(expires_at).map_err(|_| AdminJournalOperationError::InvalidInput)?)
        .bind(binding.operation_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    require_one(result.rows_affected())?;
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Completed {
            route,
            request_sha256,
            response: actual_response,
            response_sha256: actual_sha256,
            prepared_at,
            completed_at: actual_completed_at,
            expires_at: actual_expires_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && actual_response.as_ref() == response
            && actual_sha256 == response_sha256
            && prepared_at == binding.prepared_at
            && actual_completed_at == completed_at
            && actual_expires_at.get() == expires_at =>
        {
            Ok(MycAdminOperationCompletion::Completed)
        }
        Some(_) | None => Err(AdminJournalOperationError::Binding),
    }
}

async fn prune_expired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at: MycAdminOperationTimeUnixMs,
) -> Result<(), AdminJournalOperationError> {
    sqlx::query(PRUNE_EXPIRED_SQL)
        .bind(observed_at.sqlite_value())
        .bind(PRUNE_LIMIT)
        .execute(&mut *transaction)
        .await
        .map(|_| ())
        .map_err(|_| AdminJournalOperationError::Storage)
}

async fn read_counts(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<(u64, u64), AdminJournalOperationError> {
    let rows = sqlx::query(READ_COUNTS_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(AdminJournalOperationError::Binding);
    }
    let completed = rows[0]
        .try_get::<i64, _>("completed_count")
        .map_err(|_| AdminJournalOperationError::Binding)?;
    let prepared = rows[0]
        .try_get::<i64, _>("prepared_count")
        .map_err(|_| AdminJournalOperationError::Binding)?;
    Ok((
        u64::try_from(completed).map_err(|_| AdminJournalOperationError::Binding)?,
        u64::try_from(prepared).map_err(|_| AdminJournalOperationError::Binding)?,
    ))
}

async fn read_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: &AdminOperationIdBinding,
) -> Result<Option<StoredOperation>, AdminJournalOperationError> {
    let rows = sqlx::query(READ_OPERATION_SQL)
        .bind(operation_id.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(AdminJournalOperationError::Binding);
    }
    rows.first().map(decode_operation).transpose()
}

fn decode_operation(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<StoredOperation, AdminJournalOperationError> {
    let route = row
        .try_get::<Option<&str>, _>("route")
        .map_err(|_| AdminJournalOperationError::Binding)?
        .and_then(parse_route)
        .ok_or(AdminJournalOperationError::Binding)?;
    let request_sha256 = exact_digest(row, "request_sha256")?;
    let state = row
        .try_get::<Option<&str>, _>("state")
        .map_err(|_| AdminJournalOperationError::Binding)?
        .ok_or(AdminJournalOperationError::Binding)?;
    let prepared_at = time(row, "prepared_at_unix_ms")?;
    match state {
        "prepared" => {
            require_null(row, "response_model_type")?;
            require_null(row, "response_sha256_type")?;
            require_null(row, "completed_at_type")?;
            require_null(row, "expires_at_type")?;
            Ok(StoredOperation::Prepared {
                route,
                request_sha256,
                prepared_at,
            })
        }
        "completed" => {
            require_type(row, "response_model_type", "blob")?;
            require_type(row, "response_sha256_type", "blob")?;
            require_type(row, "completed_at_type", "integer")?;
            require_type(row, "expires_at_type", "integer")?;
            let response = row
                .try_get::<Option<Vec<u8>>, _>("response_model")
                .map_err(|_| AdminJournalOperationError::Binding)?
                .ok_or(AdminJournalOperationError::Binding)?
                .into_boxed_slice();
            Ok(StoredOperation::Completed {
                route,
                request_sha256,
                response,
                response_sha256: exact_digest(row, "response_sha256")?,
                prepared_at,
                completed_at: time(row, "completed_at_unix_ms")?,
                expires_at: time(row, "expires_at_unix_ms")?,
            })
        }
        _ => Err(AdminJournalOperationError::Binding),
    }
}

fn request_digest(request: &MycAdminRequestDocument) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hash_field(&mut hasher, request.route().operation_id().as_bytes());
    match request.parameter_binding() {
        Some((name, value)) => {
            hasher.update([1]);
            hash_field(&mut hasher, name.as_bytes());
            hash_field(&mut hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
    hash_field(&mut hasher, request.model_bytes());
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded field length")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn parse_route(value: &str) -> Option<MycAdminRoute> {
    MycAdminRoute::ALL
        .into_iter()
        .find(|route| route.is_mutation() && route.operation_id() == value)
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], AdminJournalOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?
        .ok_or(AdminJournalOperationError::Binding)?
        .try_into()
        .map_err(|_| AdminJournalOperationError::Binding)
}

fn time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycAdminOperationTimeUnixMs, AdminJournalOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?;
    MycAdminOperationTimeUnixMs::new(
        u64::try_from(value).map_err(|_| AdminJournalOperationError::Binding)?,
    )
    .map_err(|_| AdminJournalOperationError::Binding)
}

fn require_null(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<(), AdminJournalOperationError> {
    require_type(row, column, "null")
}

fn require_type(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    expected: &str,
) -> Result<(), AdminJournalOperationError> {
    (row.try_get::<&str, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?
        == expected)
        .then_some(())
        .ok_or(AdminJournalOperationError::Binding)
}

fn require_one(rows: u64) -> Result<(), AdminJournalOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(AdminJournalOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<AdminJournalOperationError>,
) -> MycAdminOperationError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycAdminOperationError::new(MycAdminOperationErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(AdminJournalOperationError::InvalidInput) => MycAdminOperationErrorKind::InvalidInput,
        Some(AdminJournalOperationError::Conflict) => MycAdminOperationErrorKind::OperationConflict,
        Some(AdminJournalOperationError::OutcomeUnknown) => {
            MycAdminOperationErrorKind::OperationOutcomeUnknown
        }
        Some(AdminJournalOperationError::ResourceExhausted) => {
            MycAdminOperationErrorKind::ResourceExhausted
        }
        Some(AdminJournalOperationError::Binding) => MycAdminOperationErrorKind::Binding,
        Some(AdminJournalOperationError::Storage) | None => MycAdminOperationErrorKind::Transaction,
    };
    MycAdminOperationError::new(kind)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
    use radroots_storage::event::SourceGeneration;

    use super::*;
    use crate::{
        MycConfigProfile, MycRuntimeContext, MycStateHost, MycStateMetadata,
        RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, initialize_myc_state,
        open_myc_state_read_write, parse_myc_cli_v1_from, parse_myc_config_v1,
        resolve_myc_runtime_context,
    };

    const CONFIG: &[u8] = include_bytes!("../contracts/services_hardening/config.v1.example.toml");

    fn runtime(root: &Path) -> MycRuntimeContext {
        let invocation = parse_myc_cli_v1_from([
            "myc",
            "--profile",
            "repo-local",
            "--instance",
            "primary",
            "--repo-local-root",
            root.to_str().expect("UTF-8 root"),
            "run",
        ])
        .expect("invocation");
        resolve_myc_runtime_context(
            &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
            &invocation,
        )
        .expect("runtime")
    }

    fn migration_build() -> MigrationBuildIdentity {
        MigrationBuildIdentity::new(
            env!("CARGO_PKG_VERSION"),
            "1111111111111111111111111111111111111111",
            "053d0c750bf9cd683c6ea37cefe7e79617ba629f",
            "rustc-test",
            "test-target",
            "service-host",
            1,
            crate::MYC_STATE_SCHEMA_VERSION,
            1,
            1,
            1,
        )
        .expect("build")
    }

    async fn fixture() -> (
        tempfile::TempDir,
        MycRuntimeContext,
        MycStateMetadata,
        MycStateHost,
    ) {
        let directory = tempfile::tempdir().expect("root");
        let runtime = runtime(directory.path());
        fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
        fs::set_permissions(
            runtime.context().paths().state(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("state mode");
        let configuration =
            parse_myc_config_v1(CONFIG, MycConfigProfile::RepoLocal).expect("configuration");
        let metadata = MycStateMetadata::new(
            &runtime,
            &configuration,
            SourceGeneration::new([0x5a; 32]).expect("generation"),
            1_725_000_000_000,
        )
        .expect("metadata");
        let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("time");
        let build = migration_build();
        initialize_myc_state(&runtime, &metadata, applied_at, &build)
            .await
            .expect("initialize");
        let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
            .await
            .expect("open");
        (directory, runtime, metadata, host)
    }

    fn request(
        operation_id: &str,
        connection_id: &str,
        generation: u64,
    ) -> MycAdminRequestDocument {
        let model = format!(
            "{{\"confirmation\":\"approve\",\"expected_generation\":{generation},\"permissions\":\"nip04_decrypt\"}}"
        );
        MycAdminRequestDocument::mutation_for_test(
            MycAdminRoute::ConnectionApprove,
            operation_id,
            Some(("connection_id", connection_id)),
            model.as_bytes(),
        )
    }

    fn response_document(operation_id: &str, generation: u64) -> MycAdminResponseDocument {
        let model = format!(
            "{{\"connection_id\":\"connection-1\",\"current_state\":\"approved\",\"generation\":{generation},\"operation_id\":\"{operation_id}\",\"previous_state\":\"pending\"}}"
        );
        MycAdminResponseDocument::from_canonical_bytes(
            MycAdminRoute::ConnectionApprove,
            model.as_bytes(),
        )
        .expect("response")
    }

    #[test]
    fn identifier_policy_time_and_public_diagnostics_are_bounded_and_redacted() {
        for valid in [
            "a",
            "A0._:-z",
            &"x".repeat(MYC_ADMIN_OPERATION_ID_MAX_BYTES),
        ] {
            assert!(AdminOperationIdBinding::new(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "-first", "space value", "slash/value", "é"] {
            assert!(AdminOperationIdBinding::new(invalid).is_err(), "{invalid}");
        }
        assert!(
            AdminOperationIdBinding::new(&"x".repeat(MYC_ADMIN_OPERATION_ID_MAX_BYTES + 1))
                .is_err()
        );
        let identifier = AdminOperationIdBinding::new("protected-operation").expect("ID");
        assert_eq!(
            format!("{identifier:?}"),
            "AdminOperationIdBinding([redacted])"
        );

        assert!(MycAdminOperationJournalPolicy::new(0).is_err());
        assert!(MycAdminOperationJournalPolicy::new(MYC_ADMIN_OPERATION_MIN_RETENTION_MS).is_ok());
        assert!(MycAdminOperationJournalPolicy::new(MYC_ADMIN_OPERATION_MAX_RETENTION_MS).is_ok());
        assert!(
            MycAdminOperationJournalPolicy::new(MYC_ADMIN_OPERATION_MAX_RETENTION_MS + 1).is_err()
        );
        assert_eq!(
            MycAdminOperationJournalPolicy::seven_days().completed_retention_ms(),
            MYC_ADMIN_OPERATION_DEFAULT_RETENTION_MS
        );
        assert!(MycAdminOperationTimeUnixMs::new(i64::MAX as u64).is_ok());
        assert!(MycAdminOperationTimeUnixMs::new(i64::MAX as u64 + 1).is_err());
        assert_eq!(PRUNE_LIMIT, i64::from(MYC_ADMIN_OPERATION_COMPLETED_LIMIT));

        for kind in [
            MycAdminOperationErrorKind::InvalidMode,
            MycAdminOperationErrorKind::InvalidInput,
            MycAdminOperationErrorKind::OperationConflict,
            MycAdminOperationErrorKind::OperationOutcomeUnknown,
            MycAdminOperationErrorKind::ResourceExhausted,
            MycAdminOperationErrorKind::Binding,
            MycAdminOperationErrorKind::Transaction,
            MycAdminOperationErrorKind::CommitOutcomeUnknown,
        ] {
            let error = MycAdminOperationError::new(kind);
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("protected-operation"));
            assert!(!rendered.contains("/tmp/secret"));
            assert!(Error::source(&error).is_none());
        }
    }

    #[test]
    fn request_digest_binds_route_parameter_and_canonical_model_without_retaining_them() {
        let first = request("digest-1", "connection-1", 1);
        let same = request("digest-1", "connection-1", 1);
        let changed_parameter = request("digest-1", "connection-2", 1);
        let changed_model = request("digest-1", "connection-1", 2);
        assert_eq!(request_digest(&first), request_digest(&same));
        assert_ne!(request_digest(&first), request_digest(&changed_parameter));
        assert_ne!(request_digest(&first), request_digest(&changed_model));
    }

    #[tokio::test]
    async fn prepare_complete_replay_conflict_and_expiry_are_exact() {
        let (_directory, _runtime, _metadata, host) = fixture().await;
        let repository = host.repository();
        let first = request("journal-1", "connection-1", 1);
        let prepared = match repository
            .prepare_admin_operation(&first, MycAdminOperationTimeUnixMs::new(10).unwrap())
            .await
            .expect("prepare")
        {
            MycAdminOperationAdmission::Prepared(prepared) => prepared,
            MycAdminOperationAdmission::ExactReplay(_) => panic!("unexpected replay"),
        };
        let same_prepared = repository
            .prepare_admin_operation(&first, MycAdminOperationTimeUnixMs::new(10).unwrap())
            .await
            .expect_err("retained Prepared is ambiguous");
        assert_eq!(
            same_prepared.kind(),
            MycAdminOperationErrorKind::OperationOutcomeUnknown
        );
        let changed = request("journal-1", "connection-2", 1);
        assert_eq!(
            repository
                .prepare_admin_operation(&changed, MycAdminOperationTimeUnixMs::new(10).unwrap())
                .await
                .expect_err("path binding conflict")
                .kind(),
            MycAdminOperationErrorKind::OperationConflict
        );

        let response = response_document("journal-1", 1);
        assert_eq!(
            repository
                .complete_admin_operation(
                    &prepared,
                    &response,
                    MycAdminOperationTimeUnixMs::new(20).unwrap(),
                    MycAdminOperationJournalPolicy::new(2).unwrap(),
                )
                .await
                .expect("complete"),
            MycAdminOperationCompletion::Completed
        );
        assert_eq!(
            repository
                .complete_admin_operation(
                    &prepared,
                    &response,
                    MycAdminOperationTimeUnixMs::new(21).unwrap(),
                    MycAdminOperationJournalPolicy::new(2).unwrap(),
                )
                .await
                .expect("idempotent completion"),
            MycAdminOperationCompletion::ExactReplay
        );
        let different_response = response_document("journal-1", 2);
        assert_eq!(
            repository
                .complete_admin_operation(
                    &prepared,
                    &different_response,
                    MycAdminOperationTimeUnixMs::new(21).unwrap(),
                    MycAdminOperationJournalPolicy::new(2).unwrap(),
                )
                .await
                .expect_err("different completion conflicts")
                .kind(),
            MycAdminOperationErrorKind::OperationConflict
        );

        match repository
            .prepare_admin_operation(&first, MycAdminOperationTimeUnixMs::new(21).unwrap())
            .await
            .expect("replay before expiry")
        {
            MycAdminOperationAdmission::ExactReplay(replayed) => {
                assert_eq!(replayed.canonical_bytes(), response.canonical_bytes());
            }
            MycAdminOperationAdmission::Prepared(_) => panic!("unexpected prepare"),
        }
        assert!(matches!(
            repository
                .prepare_admin_operation(&first, MycAdminOperationTimeUnixMs::new(22).unwrap())
                .await
                .expect("exact expiry prunes before admission"),
            MycAdminOperationAdmission::Prepared(_)
        ));
        host.close().await.expect("close");
    }

    #[tokio::test]
    async fn database_only_admin_effect_and_receipt_share_one_transaction() {
        let (_directory, _runtime, _metadata, host) = fixture().await;
        let repository = host.repository();
        let request = request("atomic-admin-1", "connection-1", 1);
        let error = repository
            .execute_database_admin_operation(
                &request,
                MycAdminOperationTimeUnixMs::new(100).expect("time"),
                MycAdminOperationJournalPolicy::seven_days(),
                |transaction| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"INSERT INTO connection_rate_windows (
                                rate_kind, subject_scope, subject_sha256,
                                window_started_at_unix_ms, window_ends_at_unix_ms,
                                accepted_count, rejected_count, lifetime_accepted_count,
                                lifetime_rejected_count, last_observed_at_unix_ms,
                                retention_expires_at_unix_ms
                            ) VALUES ('connection_admission', 'global', ?, 1, 2, 0, 0, 0, 0, 1, 2)"#,
                        )
                        .bind([0xaa_u8; 32].as_slice())
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        Err(AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .expect_err("domain failure rolls back");
        assert_eq!(error.kind(), MycAdminOperationErrorKind::Binding);
        assert_eq!(
            repository
                .host()
                .transaction(|transaction| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM connection_rate_windows")
                            .fetch_one(&mut *transaction)
                            .await
                    })
                })
                .await
                .expect("rolled-back effect"),
            0
        );

        let expected = response_document("atomic-admin-1", 1);
        let expected_bytes = expected.canonical_bytes().to_vec();
        let committed = repository
            .execute_database_admin_operation(
                &request,
                MycAdminOperationTimeUnixMs::new(101).expect("time"),
                MycAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    let expected_bytes = expected_bytes.clone();
                    Box::pin(async move {
                        sqlx::query(
                            r#"INSERT INTO connection_rate_windows (
                                rate_kind, subject_scope, subject_sha256,
                                window_started_at_unix_ms, window_ends_at_unix_ms,
                                accepted_count, rejected_count, lifetime_accepted_count,
                                lifetime_rejected_count, last_observed_at_unix_ms,
                                retention_expires_at_unix_ms
                            ) VALUES ('connection_admission', 'global', ?, 3, 4, 0, 0, 0, 0, 3, 4)"#,
                        )
                        .bind([0xbb_u8; 32].as_slice())
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        MycAdminResponseDocument::from_canonical_bytes(
                            MycAdminRoute::ConnectionApprove,
                            &expected_bytes,
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .expect("atomic commit");
        let replay = repository
            .execute_database_admin_operation(
                &request,
                MycAdminOperationTimeUnixMs::new(102).expect("time"),
                MycAdminOperationJournalPolicy::seven_days(),
                |_transaction| {
                    Box::pin(
                        async move { panic!("exact replay must not execute the domain operation") },
                    )
                },
            )
            .await
            .expect("exact replay");
        assert_eq!(replay.canonical_bytes(), committed.canonical_bytes());
        assert_eq!(
            repository
                .host()
                .transaction(|transaction| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM connection_rate_windows")
                            .fetch_one(&mut *transaction)
                            .await
                    })
                })
                .await
                .expect("single committed effect"),
            1
        );
        host.close().await.expect("close");
    }

    #[tokio::test]
    async fn prepared_backup_shape_is_ambiguous_and_persists_no_path_or_request_content() {
        let (_directory, _runtime, _metadata, host) = fixture().await;
        let request = MycAdminRequestDocument::mutation_for_test(
            MycAdminRoute::StateBackup,
            "backup-1",
            None,
            br#"{"destination":"/tmp/never-store-this"}"#,
        );
        let repository = host.repository();
        assert!(matches!(
            repository
                .prepare_admin_operation(&request, MycAdminOperationTimeUnixMs::new(30).unwrap())
                .await
                .expect("prepare backup"),
            MycAdminOperationAdmission::Prepared(_)
        ));
        assert_eq!(
            repository
                .prepare_admin_operation(&request, MycAdminOperationTimeUnixMs::new(31).unwrap())
                .await
                .expect_err("backup outcome remains unknown")
                .kind(),
            MycAdminOperationErrorKind::OperationOutcomeUnknown
        );
        let row = repository
            .host()
            .transaction(|transaction| {
                Box::pin(async move {
                    sqlx::query(
                        "SELECT route, state, response_model, request_sha256, \
                         (SELECT group_concat(name, ',') FROM pragma_table_info('myc_admin_operations')) \
                         AS columns FROM myc_admin_operations WHERE operation_id = 'backup-1'",
                    )
                    .fetch_one(&mut *transaction)
                    .await
                })
            })
            .await
            .expect("inspect journal");
        assert_eq!(
            row.get::<String, _>("route"),
            MycAdminRoute::StateBackup.operation_id()
        );
        assert_eq!(row.get::<String, _>("state"), "prepared");
        assert!(row.get::<Option<Vec<u8>>, _>("response_model").is_none());
        assert_eq!(row.get::<Vec<u8>, _>("request_sha256").len(), 32);
        let columns = row.get::<String, _>("columns");
        for forbidden in [
            "path",
            "body",
            "correlation",
            "credential",
            "secret",
            "bundle",
        ] {
            assert!(!columns.contains(forbidden), "{columns}");
        }
        host.close().await.expect("close");
    }

    #[tokio::test]
    async fn exact_completed_and_prepared_caps_fail_closed_after_bounded_pruning() {
        let (_directory, _runtime, _metadata, host) = fixture().await;
        let repository = host.repository();
        repository
            .host()
            .transaction(|transaction| {
                Box::pin(async move {
                    let response = b"{}";
                    let digest = sha256(response);
                    for index in 0..(MYC_ADMIN_OPERATION_COMPLETED_LIMIT - 1) {
                        sqlx::query(
                            "INSERT INTO myc_admin_operations (operation_id, route, \
                             request_sha256, state, response_model, response_sha256, \
                             prepared_at_unix_ms, completed_at_unix_ms, expires_at_unix_ms) \
                             VALUES (?, ?, ?, 'completed', ?, ?, 1, 1, ?)",
                        )
                        .bind(format!("completed-{index}"))
                        .bind(MycAdminRoute::ConnectionApprove.operation_id())
                        .bind([0x11; 32].as_slice())
                        .bind(response.as_slice())
                        .bind(digest.as_slice())
                        .bind(i64::MAX)
                        .execute(&mut *transaction)
                        .await?;
                    }
                    Ok::<_, sqlx::Error>(())
                })
            })
            .await
            .expect("seed completed capacity");
        let reserved = match repository
            .prepare_admin_operation(
                &request("reserved-completion", "connection-1", 1),
                MycAdminOperationTimeUnixMs::new(2).unwrap(),
            )
            .await
            .expect("reserve final completed slot")
        {
            MycAdminOperationAdmission::Prepared(prepared) => prepared,
            MycAdminOperationAdmission::ExactReplay(_) => panic!("unexpected replay"),
        };
        assert_eq!(
            repository
                .prepare_admin_operation(
                    &request("new-completed", "connection-1", 1),
                    MycAdminOperationTimeUnixMs::new(2).unwrap(),
                )
                .await
                .expect_err("completed cap")
                .kind(),
            MycAdminOperationErrorKind::ResourceExhausted
        );
        assert_eq!(
            repository
                .complete_admin_operation(
                    &reserved,
                    &response_document("reserved-completion", 1),
                    MycAdminOperationTimeUnixMs::new(3).unwrap(),
                    MycAdminOperationJournalPolicy::seven_days(),
                )
                .await
                .expect("consume reserved completed slot"),
            MycAdminOperationCompletion::Completed
        );
        assert_eq!(
            repository
                .prepare_admin_operation(
                    &request("completed-cap", "connection-1", 1),
                    MycAdminOperationTimeUnixMs::new(4).unwrap(),
                )
                .await
                .expect_err("completed cap remains closed")
                .kind(),
            MycAdminOperationErrorKind::ResourceExhausted
        );
        host.close().await.expect("close completed fixture");

        let (_directory, _runtime, _metadata, host) = fixture().await;
        let repository = host.repository();
        repository
            .host()
            .transaction(|transaction| {
                Box::pin(async move {
                    for index in 0..MYC_ADMIN_OPERATION_PREPARED_LIMIT {
                        sqlx::query(
                            "INSERT INTO myc_admin_operations (operation_id, route, \
                             request_sha256, state, prepared_at_unix_ms) \
                             VALUES (?, ?, ?, 'prepared', 1)",
                        )
                        .bind(format!("prepared-{index}"))
                        .bind(MycAdminRoute::StateBackup.operation_id())
                        .bind([0x22; 32].as_slice())
                        .execute(&mut *transaction)
                        .await?;
                    }
                    Ok::<_, sqlx::Error>(())
                })
            })
            .await
            .expect("seed prepared capacity");
        assert_eq!(
            repository
                .prepare_admin_operation(
                    &request("new-prepared", "connection-1", 1),
                    MycAdminOperationTimeUnixMs::new(2).unwrap(),
                )
                .await
                .expect_err("prepared cap")
                .kind(),
            MycAdminOperationErrorKind::ResourceExhausted
        );
        host.close().await.expect("close prepared fixture");
    }

    #[tokio::test]
    async fn schema_admits_exact_response_model_cap_and_rejects_one_byte_over() {
        let (_directory, _runtime, _metadata, host) = fixture().await;
        let repository = host.repository();
        let exact = vec![b'x'; MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES];
        let exact_digest = sha256(&exact);
        repository
            .host()
            .transaction(|transaction| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO myc_admin_operations (operation_id, route, \
                         request_sha256, state, response_model, response_sha256, \
                         prepared_at_unix_ms, completed_at_unix_ms, expires_at_unix_ms) \
                         VALUES ('response-exact', ?, ?, 'completed', ?, ?, 1, 1, 2)",
                    )
                    .bind(MycAdminRoute::ConnectionApprove.operation_id())
                    .bind([0x33; 32].as_slice())
                    .bind(exact)
                    .bind(exact_digest.as_slice())
                    .execute(&mut *transaction)
                    .await
                    .map(|_| ())
                })
            })
            .await
            .expect("exact response cap");

        let excessive = vec![b'x'; MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES + 1];
        let excessive_digest = sha256(&excessive);
        assert!(
            repository
                .host()
                .transaction(|transaction| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO myc_admin_operations (operation_id, route, \
                             request_sha256, state, response_model, response_sha256, \
                             prepared_at_unix_ms, completed_at_unix_ms, expires_at_unix_ms) \
                             VALUES ('response-excessive', ?, ?, 'completed', ?, ?, 1, 1, 2)",
                        )
                        .bind(MycAdminRoute::ConnectionApprove.operation_id())
                        .bind([0x44; 32].as_slice())
                        .bind(excessive)
                        .bind(excessive_digest.as_slice())
                        .execute(&mut *transaction)
                        .await
                        .map(|_| ())
                    })
                })
                .await
                .is_err()
        );
        host.close().await.expect("close");
    }

    #[test]
    fn schema_and_source_freeze_response_and_pruning_bounds() {
        const SOURCE: &str = include_str!("state_admin.rs");
        const CATALOG: &str = include_str!("state_catalog.rs");
        let production = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(SOURCE.contains("length(response_model) BETWEEN 1 AND 8192"));
        assert!(SOURCE.contains("LIMIT ?"));
        assert!(CATALOG.contains("length(response_model) BETWEEN 1 AND 8192"));
        assert!(CATALOG.contains("CHECK (length(request_sha256) = 32)"));
        assert!(!CATALOG.contains("bundle_path"));
        assert!(!production.contains("correlation_id"));
        assert!(parse_route(MycAdminRoute::Status.operation_id()).is_none());
        assert_eq!(
            parse_route(MycAdminRoute::StateBackup.operation_id()),
            Some(MycAdminRoute::StateBackup)
        );
        let maximum_envelope = br#"{"contract_version":1,"ok":true,"correlation_id":""#.len()
            + radroots_service_host::ADMIN_CORRELATION_ID_MAX_UTF8_BYTES
            + br#"","result":"#.len()
            + MYC_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
            + 1;
        assert_eq!(
            maximum_envelope,
            MYC_ADMIN_OPERATION_RESPONSE_ENVELOPE_MAX_UTF8_BYTES as usize
        );
    }
}
