//! Atomic completion, exact signed-response, and initial delivery-state commit.

use core::fmt;
use std::error::Error;

use radroots_nostr::event::{Event as RadrootsNostrEvent, Kind as RadrootsNostrKind};
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::state_completion::{
    CommitOperationError, MycNip46CommitAdmission, MycNip46CommitRecord, MycNip46CommitRequest,
    commit_operation,
};
use crate::state_delivery::{
    DeliveryOperationError, MycDeliveryArtifactDigest, MycDeliveryJobAdmission, MycDeliveryJobId,
    MycDeliveryJobRecord, MycDeliverySource, MycDeliveryTimeUnixMs, create_job, read_job,
};
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::{
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MycProviderCapability, MycProviderOperation, MycProviderRole,
    MycSignerOperationId, MycVerifiedProviderResponse,
};

const NIP46_RPC_KIND: u16 = 24_133;

const INSERT_RESPONSE_SQL: &str = r#"INSERT INTO nip46_signed_responses (
    operation_id, response_provider_operation_id, response_event_id,
    response_sha256, response_bytes, authored_at_unix_s, committed_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?)"#;

const READ_RESPONSE_BY_OPERATION_SQL: &str = r#"SELECT
    CASE WHEN typeof(r.operation_id) = 'blob' AND length(r.operation_id) = 32
        THEN r.operation_id ELSE NULL END AS operation_id,
    CASE WHEN typeof(r.response_provider_operation_id) = 'blob'
            AND length(r.response_provider_operation_id) = 32
        THEN r.response_provider_operation_id ELSE NULL END AS response_provider_operation_id,
    CASE WHEN typeof(r.response_event_id) = 'blob' AND length(r.response_event_id) = 32
        THEN r.response_event_id ELSE NULL END AS response_event_id,
    CASE WHEN typeof(r.response_sha256) = 'blob' AND length(r.response_sha256) = 32
        THEN r.response_sha256 ELSE NULL END AS response_sha256,
    CASE WHEN typeof(r.response_bytes) = 'blob'
            AND length(r.response_bytes) BETWEEN 1 AND 1048576
        THEN r.response_bytes ELSE NULL END AS response_bytes,
    r.authored_at_unix_s, r.committed_at_unix_ms,
    CASE WHEN typeof(q.client_public_key) = 'text'
            AND length(CAST(q.client_public_key AS BLOB)) = 64
        THEN q.client_public_key ELSE NULL END AS client_public_key,
    CASE WHEN typeof(j.job_id) = 'blob' AND length(j.job_id) = 32
        THEN j.job_id ELSE NULL END AS job_id
FROM nip46_signed_responses r
JOIN nip46_requests q ON q.operation_id = r.operation_id
JOIN delivery_jobs j ON j.source_kind = 'signer_response'
    AND j.source_id = r.operation_id
WHERE r.operation_id = ?
LIMIT 2"#;

const READ_RESPONSE_BY_JOB_SQL: &str = r#"SELECT
    CASE WHEN typeof(r.operation_id) = 'blob' AND length(r.operation_id) = 32
        THEN r.operation_id ELSE NULL END AS operation_id,
    CASE WHEN typeof(r.response_provider_operation_id) = 'blob'
            AND length(r.response_provider_operation_id) = 32
        THEN r.response_provider_operation_id ELSE NULL END AS response_provider_operation_id,
    CASE WHEN typeof(r.response_event_id) = 'blob' AND length(r.response_event_id) = 32
        THEN r.response_event_id ELSE NULL END AS response_event_id,
    CASE WHEN typeof(r.response_sha256) = 'blob' AND length(r.response_sha256) = 32
        THEN r.response_sha256 ELSE NULL END AS response_sha256,
    CASE WHEN typeof(r.response_bytes) = 'blob'
            AND length(r.response_bytes) BETWEEN 1 AND 1048576
        THEN r.response_bytes ELSE NULL END AS response_bytes,
    r.authored_at_unix_s, r.committed_at_unix_ms,
    CASE WHEN typeof(q.client_public_key) = 'text'
            AND length(CAST(q.client_public_key AS BLOB)) = 64
        THEN q.client_public_key ELSE NULL END AS client_public_key,
    CASE WHEN typeof(j.job_id) = 'blob' AND length(j.job_id) = 32
        THEN j.job_id ELSE NULL END AS job_id
FROM delivery_jobs j
JOIN nip46_signed_responses r ON r.operation_id = j.source_id
JOIN nip46_requests q ON q.operation_id = r.operation_id
WHERE j.job_id = ? AND j.source_kind = 'signer_response'
LIMIT 2"#;

/// Stable construction failure classes for an atomic NIP-46 response commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46ResponseCommitErrorKind {
    InvalidBinding,
    InvalidResponse,
    InvalidTime,
}

impl MycNip46ResponseCommitErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "nip46_response_binding_invalid",
            Self::InvalidResponse => "nip46_response_invalid",
            Self::InvalidTime => "nip46_response_time_invalid",
        }
    }
}

/// Source-free, path-free construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46ResponseCommitError {
    kind: MycNip46ResponseCommitErrorKind,
}

impl MycNip46ResponseCommitError {
    const fn new(kind: MycNip46ResponseCommitErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycNip46ResponseCommitErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycNip46ResponseCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycNip46ResponseCommitErrorKind::InvalidBinding => "NIP-46 response binding is invalid",
            MycNip46ResponseCommitErrorKind::InvalidResponse => "NIP-46 signed response is invalid",
            MycNip46ResponseCommitErrorKind::InvalidTime => "NIP-46 response time is invalid",
        })
    }
}

impl fmt::Debug for MycNip46ResponseCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46ResponseCommitError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycNip46ResponseCommitError {}

/// Exact independently verified response and completion prepared before SQLite.
pub struct MycNip46ResponseCommitRequest {
    completion: MycNip46CommitRequest,
    response_provider_operation_id: [u8; 32],
    response_event_id: [u8; 32],
    response_digest: MycDeliveryArtifactDigest,
    response_bytes: Box<[u8]>,
    authored_at_unix_s: u64,
    committed_at: MycDeliveryTimeUnixMs,
    #[cfg(test)]
    fail_after_completion: bool,
    #[cfg(test)]
    fail_after_response: bool,
}

impl MycNip46ResponseCommitRequest {
    /// Binds one completion to a signature-verified canonical NIP-46 response event.
    pub fn new(
        completion: &MycNip46CommitRequest,
        response_operation: &MycProviderOperation,
        response: &MycVerifiedProviderResponse,
        committed_at: MycDeliveryTimeUnixMs,
    ) -> Result<Self, MycNip46ResponseCommitError> {
        if response_operation.role() != MycProviderRole::User
            || response_operation.input().capability() != MycProviderCapability::SignEvent
            || response.operation_id() != response_operation.operation_id()
            || response.correlation_id() != response_operation.correlation_id()
            || response.instance() != response_operation.instance()
            || response.role() != response_operation.role()
            || response.capability() != response_operation.input().capability()
            || !response.matches_operation(response_operation)
            || response_operation.operation_id().as_bytes()
                == completion.signer_request().operation_id().as_bytes()
        {
            return Err(Self::error(MycNip46ResponseCommitErrorKind::InvalidBinding));
        }
        let bytes = response
            .signed_event_bytes()
            .ok_or_else(|| Self::error(MycNip46ResponseCommitErrorKind::InvalidResponse))?;
        let event = validate_response_event(
            bytes,
            completion.signer_request().client_public_key().as_hex(),
            Some(response_operation.expected_identity().as_hex()),
        )?;
        let authored_at_unix_s = event.created_at.as_secs();
        if committed_at.get() < completion.completed_at().get()
            || authored_at_unix_s
                .checked_mul(1_000)
                .is_none_or(|authored_ms| authored_ms > committed_at.get())
        {
            return Err(Self::error(MycNip46ResponseCommitErrorKind::InvalidTime));
        }
        let response_digest = MycDeliveryArtifactDigest::from_bytes(Sha256::digest(bytes).into());
        Ok(Self {
            completion: completion.owned(),
            response_provider_operation_id: *response_operation.operation_id().as_bytes(),
            response_event_id: *event.id.as_bytes(),
            response_digest,
            response_bytes: Box::from(bytes),
            authored_at_unix_s,
            committed_at,
            #[cfg(test)]
            fail_after_completion: false,
            #[cfg(test)]
            fail_after_response: false,
        })
    }

    const fn error(kind: MycNip46ResponseCommitErrorKind) -> MycNip46ResponseCommitError {
        MycNip46ResponseCommitError::new(kind)
    }

    fn owned(&self) -> Self {
        Self {
            completion: self.completion.owned(),
            response_provider_operation_id: self.response_provider_operation_id,
            response_event_id: self.response_event_id,
            response_digest: self.response_digest,
            response_bytes: self.response_bytes.clone(),
            authored_at_unix_s: self.authored_at_unix_s,
            committed_at: self.committed_at,
            #[cfg(test)]
            fail_after_completion: self.fail_after_completion,
            #[cfg(test)]
            fail_after_response: self.fail_after_response,
        }
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn fail_after_completion_for_test(&self) -> Self {
        let mut request = self.owned();
        request.fail_after_completion = true;
        request
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn fail_after_response_for_test(&self) -> Self {
        let mut request = self.owned();
        request.fail_after_response = true;
        request
    }
}

impl fmt::Debug for MycNip46ResponseCommitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNip46ResponseCommitRequest([redacted])")
    }
}

/// Immutable exact signed response and its config-bound initial delivery state.
#[derive(Clone, PartialEq, Eq)]
pub struct MycNip46ResponseRecord {
    operation_id: MycSignerOperationId,
    response_provider_operation_id: [u8; 32],
    response_event_id: [u8; 32],
    response_digest: MycDeliveryArtifactDigest,
    response_bytes: Box<[u8]>,
    authored_at_unix_s: u64,
    committed_at: MycDeliveryTimeUnixMs,
    delivery_job: MycDeliveryJobRecord,
}

impl MycNip46ResponseRecord {
    #[must_use]
    pub const fn operation_id(&self) -> MycSignerOperationId {
        self.operation_id
    }
    #[must_use]
    pub const fn response_provider_operation_id(&self) -> &[u8; 32] {
        &self.response_provider_operation_id
    }
    #[must_use]
    pub const fn response_event_id(&self) -> &[u8; 32] {
        &self.response_event_id
    }
    #[must_use]
    pub const fn response_digest(&self) -> MycDeliveryArtifactDigest {
        self.response_digest
    }
    /// Returns the exact committed bytes that every retry must submit unchanged.
    #[must_use]
    pub fn signed_response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
    #[must_use]
    pub const fn authored_at_unix_s(&self) -> u64 {
        self.authored_at_unix_s
    }
    #[must_use]
    pub const fn committed_at(&self) -> MycDeliveryTimeUnixMs {
        self.committed_at
    }
    #[must_use]
    pub const fn delivery_job(&self) -> &MycDeliveryJobRecord {
        &self.delivery_job
    }
}

impl fmt::Debug for MycNip46ResponseRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46ResponseRecord")
            .field("delivery_job", &self.delivery_job)
            .field("response", &"[redacted]")
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Immutable result of the one response-authority transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct MycNip46ResponseCommitRecord {
    completion: MycNip46CommitRecord,
    response: MycNip46ResponseRecord,
}

impl MycNip46ResponseCommitRecord {
    #[must_use]
    pub const fn completion(&self) -> &MycNip46CommitRecord {
        &self.completion
    }
    #[must_use]
    pub const fn response(&self) -> &MycNip46ResponseRecord {
        &self.response
    }
}

impl fmt::Debug for MycNip46ResponseCommitRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNip46ResponseCommitRecord([redacted])")
    }
}

/// New or exact-replayed atomic response authority.
#[derive(Clone, PartialEq, Eq)]
pub enum MycNip46ResponseCommitAdmission {
    Committed(MycNip46ResponseCommitRecord),
    ExactReplay(MycNip46ResponseCommitRecord),
}

impl MycNip46ResponseCommitAdmission {
    #[must_use]
    pub const fn record(&self) -> &MycNip46ResponseCommitRecord {
        match self {
            Self::Committed(record) | Self::ExactReplay(record) => record,
        }
    }
}

impl fmt::Debug for MycNip46ResponseCommitAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "MycNip46ResponseCommitAdmission::Committed([redacted])",
            Self::ExactReplay(_) => "MycNip46ResponseCommitAdmission::ExactReplay([redacted])",
        })
    }
}

impl MycStateRepository<'_> {
    /// Atomically commits completion, exact response bytes, targets, and pending attempt state.
    pub async fn commit_nip46_response(
        &self,
        request: &MycNip46ResponseCommitRequest,
    ) -> Result<MycNip46ResponseCommitAdmission, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        let policy = self.expected().delivery_policies().clone();
        let request = request.owned();
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AtomicOperationError::from)?;
                    let completion = commit_operation(transaction, &request.completion)
                        .await
                        .map_err(AtomicOperationError::from)?;
                    match completion {
                        MycNip46CommitAdmission::ExactReplay(completion) => {
                            let response = read_response_by_operation(
                                transaction,
                                request.completion.signer_request().operation_id(),
                            )
                            .await?
                            .ok_or(AtomicOperationError::Binding)?;
                            exact_response(&response, &request)?;
                            Ok(MycNip46ResponseCommitAdmission::ExactReplay(
                                MycNip46ResponseCommitRecord {
                                    completion,
                                    response,
                                },
                            ))
                        }
                        MycNip46CommitAdmission::Committed(completion) => {
                            #[cfg(test)]
                            if request.fail_after_completion {
                                return Err(AtomicOperationError::Storage);
                            }
                            insert_response(transaction, &request).await?;
                            #[cfg(test)]
                            if request.fail_after_response {
                                return Err(AtomicOperationError::Storage);
                            }
                            let delivery = create_job(
                                transaction,
                                MycDeliverySource::signer_response(
                                    request.completion.signer_request().operation_id(),
                                ),
                                request.response_digest,
                                request.committed_at,
                                &policy,
                            )
                            .await
                            .map_err(AtomicOperationError::from)?;
                            if !matches!(delivery, MycDeliveryJobAdmission::Created(_)) {
                                return Err(AtomicOperationError::Binding);
                            }
                            let response = read_response_by_operation(
                                transaction,
                                request.completion.signer_request().operation_id(),
                            )
                            .await?
                            .ok_or(AtomicOperationError::Binding)?;
                            exact_response(&response, &request)?;
                            Ok(MycNip46ResponseCommitAdmission::Committed(
                                MycNip46ResponseCommitRecord {
                                    completion,
                                    response,
                                },
                            ))
                        }
                    }
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads the exact committed response bytes for a retained delivery job.
    pub async fn read_nip46_response(
        &self,
        job_id: MycDeliveryJobId,
    ) -> Result<Option<MycNip46ResponseRecord>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AtomicOperationError::from)?;
                    read_response_by_job(transaction, job_id).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads an already committed response by stable signer operation identity.
    ///
    /// Runtime replay handling uses this lookup before any provider call so an
    /// exact completed replay always reuses the originally committed bytes.
    pub(crate) async fn read_nip46_response_by_operation(
        &self,
        operation_id: MycSignerOperationId,
    ) -> Result<Option<MycNip46ResponseRecord>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &expected)
                        .await
                        .map_err(AtomicOperationError::from)?;
                    read_response_by_operation(transaction, operation_id).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtomicOperationError {
    Binding,
    Storage,
}

impl From<RepositoryOperationError> for AtomicOperationError {
    fn from(error: RepositoryOperationError) -> Self {
        match error {
            RepositoryOperationError::Binding => Self::Binding,
            RepositoryOperationError::Storage => Self::Storage,
        }
    }
}

impl From<CommitOperationError> for AtomicOperationError {
    fn from(error: CommitOperationError) -> Self {
        match error {
            CommitOperationError::Binding => Self::Binding,
            CommitOperationError::Storage => Self::Storage,
        }
    }
}

impl From<DeliveryOperationError> for AtomicOperationError {
    fn from(error: DeliveryOperationError) -> Self {
        match error {
            DeliveryOperationError::Binding => Self::Binding,
            DeliveryOperationError::Storage => Self::Storage,
        }
    }
}

async fn insert_response(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycNip46ResponseCommitRequest,
) -> Result<(), AtomicOperationError> {
    let result = sqlx::query(INSERT_RESPONSE_SQL)
        .bind(
            request
                .completion
                .signer_request()
                .operation_id()
                .as_bytes()
                .as_slice(),
        )
        .bind(request.response_provider_operation_id.as_slice())
        .bind(request.response_event_id.as_slice())
        .bind(request.response_digest.as_bytes().as_slice())
        .bind(request.response_bytes.as_ref())
        .bind(to_i64(request.authored_at_unix_s)?)
        .bind(to_i64(request.committed_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AtomicOperationError::Storage)?;
    (result.rows_affected() == 1)
        .then_some(())
        .ok_or(AtomicOperationError::Storage)
}

async fn read_response_by_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
) -> Result<Option<MycNip46ResponseRecord>, AtomicOperationError> {
    read_response(
        transaction,
        READ_RESPONSE_BY_OPERATION_SQL,
        operation_id.as_bytes(),
    )
    .await
}

async fn read_response_by_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
) -> Result<Option<MycNip46ResponseRecord>, AtomicOperationError> {
    read_response(transaction, READ_RESPONSE_BY_JOB_SQL, job_id.as_bytes()).await
}

pub(crate) async fn verify_response_for_delivery_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
) -> Result<(), DeliveryOperationError> {
    read_response_by_job(transaction, job_id)
        .await
        .map_err(|error| match error {
            AtomicOperationError::Binding => DeliveryOperationError::Binding,
            AtomicOperationError::Storage => DeliveryOperationError::Storage,
        })?
        .map(|_| ())
        .ok_or(DeliveryOperationError::Binding)
}

async fn read_response(
    transaction: &mut ServiceSqliteTransaction<'_>,
    sql: &'static str,
    identity: &[u8; 32],
) -> Result<Option<MycNip46ResponseRecord>, AtomicOperationError> {
    let rows = sqlx::query(sql)
        .bind(identity.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AtomicOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(AtomicOperationError::Binding);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let operation_id = MycSignerOperationId::from_persisted(blob32(row, "operation_id")?);
    let response_provider_operation_id = blob32(row, "response_provider_operation_id")?;
    let response_event_id = blob32(row, "response_event_id")?;
    let response_digest = MycDeliveryArtifactDigest::from_bytes(blob32(row, "response_sha256")?);
    let response_bytes = row
        .try_get::<Option<Vec<u8>>, _>("response_bytes")
        .map_err(|_| AtomicOperationError::Binding)?
        .ok_or(AtomicOperationError::Binding)?
        .into_boxed_slice();
    let authored_at_unix_s = positive_i64(row, "authored_at_unix_s")?;
    let committed_at = MycDeliveryTimeUnixMs::new(positive_i64(row, "committed_at_unix_ms")?)
        .map_err(|_| AtomicOperationError::Binding)?;
    let client_public_key = row
        .try_get::<Option<String>, _>("client_public_key")
        .map_err(|_| AtomicOperationError::Binding)?
        .ok_or(AtomicOperationError::Binding)?;
    let job_id = MycDeliveryJobId::from_persisted(blob32(row, "job_id")?);
    let actual_digest: [u8; 32] = Sha256::digest(&response_bytes).into();
    let event = validate_response_event(&response_bytes, &client_public_key, None)
        .map_err(|_| AtomicOperationError::Binding)?;
    if actual_digest != *response_digest.as_bytes()
        || event.id.as_bytes() != &response_event_id
        || event.created_at.as_secs() != authored_at_unix_s
    {
        return Err(AtomicOperationError::Binding);
    }
    let delivery_job = read_job(transaction, job_id)
        .await
        .map_err(AtomicOperationError::from)?
        .ok_or(AtomicOperationError::Binding)?;
    if delivery_job.operation_id() != Some(operation_id)
        || delivery_job.artifact_digest() != response_digest
        || delivery_job.created_at() != committed_at
    {
        return Err(AtomicOperationError::Binding);
    }
    Ok(Some(MycNip46ResponseRecord {
        operation_id,
        response_provider_operation_id,
        response_event_id,
        response_digest,
        response_bytes,
        authored_at_unix_s,
        committed_at,
        delivery_job,
    }))
}

fn exact_response(
    response: &MycNip46ResponseRecord,
    request: &MycNip46ResponseCommitRequest,
) -> Result<(), AtomicOperationError> {
    (response.operation_id == request.completion.signer_request().operation_id()
        && response.response_provider_operation_id == request.response_provider_operation_id
        && response.response_event_id == request.response_event_id
        && response.response_digest == request.response_digest
        && response.response_bytes.as_ref() == request.response_bytes.as_ref()
        && response.authored_at_unix_s == request.authored_at_unix_s
        && response.committed_at == request.committed_at)
        .then_some(())
        .ok_or(AtomicOperationError::Binding)
}

fn validate_response_event(
    bytes: &[u8],
    client_public_key: &str,
    expected_responder: Option<&str>,
) -> Result<RadrootsNostrEvent, MycNip46ResponseCommitError> {
    if bytes.is_empty() || bytes.len() > MYC_PROVIDER_OUTPUT_MAX_BYTES {
        return Err(MycNip46ResponseCommitRequest::error(
            MycNip46ResponseCommitErrorKind::InvalidResponse,
        ));
    }
    let event: RadrootsNostrEvent = serde_json::from_slice(bytes).map_err(|_| {
        MycNip46ResponseCommitRequest::error(MycNip46ResponseCommitErrorKind::InvalidResponse)
    })?;
    let canonical = serde_json::to_vec(&event).map_err(|_| {
        MycNip46ResponseCommitRequest::error(MycNip46ResponseCommitErrorKind::InvalidResponse)
    })?;
    let expected_recipient = ["p", client_public_key];
    let valid_recipient = event.tags.len() == 1
        && event.tags.as_slice()[0]
            .as_slice()
            .iter()
            .map(String::as_str)
            .eq(expected_recipient);
    if canonical != bytes
        || event.kind != RadrootsNostrKind::Custom(NIP46_RPC_KIND)
        || event.content.is_empty()
        || !valid_recipient
        || expected_responder.is_some_and(|expected| event.pubkey.to_hex() != expected)
        || event.verify().is_err()
    {
        return Err(MycNip46ResponseCommitRequest::error(
            MycNip46ResponseCommitErrorKind::InvalidResponse,
        ));
    }
    Ok(event)
}

fn blob32(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<[u8; 32], AtomicOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| AtomicOperationError::Binding)?
        .ok_or(AtomicOperationError::Binding)?
        .try_into()
        .map_err(|_| AtomicOperationError::Binding)
}

fn positive_i64(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<u64, AtomicOperationError> {
    row.try_get::<i64, _>(column)
        .map_err(|_| AtomicOperationError::Binding)
        .and_then(|value| u64::try_from(value).map_err(|_| AtomicOperationError::Binding))
        .and_then(|value| {
            value
                .checked_sub(1)
                .map(|_| value)
                .ok_or(AtomicOperationError::Binding)
        })
}

fn to_i64(value: u64) -> Result<i64, AtomicOperationError> {
    i64::try_from(value).map_err(|_| AtomicOperationError::Binding)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<AtomicOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(AtomicOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(AtomicOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
