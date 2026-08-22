//! Bounded restart recovery for committed exact-byte delivery work.

use core::fmt;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::state_delivery::{
    DeliveryOperationError, MycDeliveryAttemptId, MycDeliveryAttemptStatus, MycDeliveryJobId,
    MycDeliveryJobRecord, MycDeliveryJobStatus, MycDeliveryRetryJitter, MycDeliverySourceKind,
    MycDeliveryTargetStatus, MycDeliveryTimeUnixMs, finalize_job_if_terminal, read_attempts,
    read_job, recover_expired,
};
use crate::state_discovery::{
    MycDiscoveryPolicies, promote_current_if_desired, verify_document_for_delivery_job,
};
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::state_response::verify_response_for_delivery_job;

/// Maximum delivery jobs examined in one restart-recovery transaction.
pub const MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT: usize = 128;

const RECOVERY_JITTER_DOMAIN: &[u8] = b"radroots.myc.delivery_recovery_jitter.v1\0";

const READ_INVARIANTS_SQL: &str = r#"SELECT
    (SELECT COUNT(*) FROM delivery_jobs j
        WHERE (j.source_kind = 'signer_response' AND NOT EXISTS (
                SELECT 1 FROM nip46_signed_responses r
                WHERE r.operation_id = j.source_id
                    AND r.response_sha256 = j.artifact_sha256
            ))
            OR (j.source_kind = 'discovery_handler' AND NOT EXISTS (
                SELECT 1 FROM discovery_documents d
                WHERE d.generation_id = j.source_id
                    AND d.event_sha256 = j.artifact_sha256
            ))) AS invalid_sources,
    (SELECT COUNT(*) FROM nip46_signed_responses r
        WHERE NOT EXISTS (
            SELECT 1 FROM delivery_jobs j
            WHERE j.source_kind = 'signer_response' AND j.source_id = r.operation_id
        )) AS orphan_responses,
    (SELECT COUNT(*) FROM discovery_documents d
        WHERE NOT EXISTS (
            SELECT 1 FROM delivery_jobs j
            WHERE j.source_kind = 'discovery_handler' AND j.source_id = d.generation_id
        )) AS orphan_documents,
    (SELECT COUNT(*) FROM delivery_targets t
        WHERE NOT EXISTS (SELECT 1 FROM delivery_jobs j WHERE j.job_id = t.job_id))
        AS orphan_targets,
    (SELECT COUNT(*) FROM delivery_attempts a
        WHERE NOT EXISTS (
            SELECT 1 FROM delivery_targets t
            WHERE t.job_id = a.job_id AND t.target_index = a.target_index
        )) AS orphan_attempts,
    (SELECT COUNT(*) FROM delivery_jobs WHERE status IN ('pending', 'active')) AS active_jobs"#;

const READ_FIRST_JOB_IDS_SQL: &str = r#"SELECT
    CASE WHEN typeof(job_id) = 'blob' AND length(job_id) = 32
        THEN job_id ELSE NULL END AS job_id
FROM delivery_jobs
WHERE status IN ('pending', 'active')
    OR (status = 'delivered' AND source_kind = 'discovery_handler' AND EXISTS (
        SELECT 1 FROM discovery_publication_state s
        WHERE s.singleton = 1
            AND s.desired_job_id = delivery_jobs.job_id
            AND (s.current_job_id IS NULL OR s.current_job_id != s.desired_job_id)
    ))
ORDER BY job_id
LIMIT 129"#;

const READ_NEXT_JOB_IDS_SQL: &str = r#"SELECT
    CASE WHEN typeof(job_id) = 'blob' AND length(job_id) = 32
        THEN job_id ELSE NULL END AS job_id
FROM delivery_jobs
WHERE (status IN ('pending', 'active')
    OR (status = 'delivered' AND source_kind = 'discovery_handler' AND EXISTS (
        SELECT 1 FROM discovery_publication_state s
        WHERE s.singleton = 1
            AND s.desired_job_id = delivery_jobs.job_id
            AND (s.current_job_id IS NULL OR s.current_job_id != s.desired_job_id)
    ))) AND job_id > ?
ORDER BY job_id
LIMIT 129"#;

/// One-use entropy supplied by the runtime recovery boundary.
pub struct MycDeliveryRecoveryEntropy([u8; 32]);

impl MycDeliveryRecoveryEntropy {
    /// Wraps exact entropy from the caller's injected source.
    #[must_use]
    pub const fn from_injected_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycDeliveryRecoveryEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDeliveryRecoveryEntropy([redacted])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RecoveryCursor([u8; 32]);

/// Bounded, identity-free result of one restart-recovery transaction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycDeliveryRecoveryReport {
    examined_jobs: u32,
    recovered_expired_attempts: u32,
    finalized_jobs: u32,
    promoted_discovery_generations: u32,
    ready_targets: u32,
    scheduled_targets: u32,
    active_targets: u32,
    continuation: Option<RecoveryCursor>,
}

impl MycDeliveryRecoveryReport {
    #[must_use]
    pub const fn examined_jobs(self) -> u32 {
        self.examined_jobs
    }

    #[must_use]
    pub const fn recovered_expired_attempts(self) -> u32 {
        self.recovered_expired_attempts
    }

    #[must_use]
    pub const fn finalized_jobs(self) -> u32 {
        self.finalized_jobs
    }

    #[must_use]
    pub const fn promoted_discovery_generations(self) -> u32 {
        self.promoted_discovery_generations
    }

    #[must_use]
    pub const fn ready_targets(self) -> u32 {
        self.ready_targets
    }

    #[must_use]
    pub const fn scheduled_targets(self) -> u32 {
        self.scheduled_targets
    }

    #[must_use]
    pub const fn active_targets(self) -> u32 {
        self.active_targets
    }

    fn merge(&mut self, batch: Self) -> Result<(), RecoveryOperationError> {
        self.examined_jobs = add(self.examined_jobs, batch.examined_jobs)?;
        self.recovered_expired_attempts = add(
            self.recovered_expired_attempts,
            batch.recovered_expired_attempts,
        )?;
        self.finalized_jobs = add(self.finalized_jobs, batch.finalized_jobs)?;
        self.promoted_discovery_generations = add(
            self.promoted_discovery_generations,
            batch.promoted_discovery_generations,
        )?;
        self.ready_targets = add(self.ready_targets, batch.ready_targets)?;
        self.scheduled_targets = add(self.scheduled_targets, batch.scheduled_targets)?;
        self.active_targets = add(self.active_targets, batch.active_targets)?;
        self.continuation = batch.continuation;
        Ok(())
    }

    const fn empty() -> Self {
        Self {
            examined_jobs: 0,
            recovered_expired_attempts: 0,
            finalized_jobs: 0,
            promoted_discovery_generations: 0,
            ready_targets: 0,
            scheduled_targets: 0,
            active_targets: 0,
            continuation: None,
        }
    }
}

impl fmt::Debug for MycDeliveryRecoveryReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryRecoveryReport")
            .field("examined_jobs", &self.examined_jobs)
            .field(
                "recovered_expired_attempts",
                &self.recovered_expired_attempts,
            )
            .field("finalized_jobs", &self.finalized_jobs)
            .field(
                "promoted_discovery_generations",
                &self.promoted_discovery_generations,
            )
            .field("ready_targets", &self.ready_targets)
            .field("scheduled_targets", &self.scheduled_targets)
            .field("active_targets", &self.active_targets)
            .field("has_continuation", &self.continuation.is_some())
            .finish()
    }
}

impl MycStateRepository<'_> {
    /// Recovers startup delivery state in fixed bounded transactions without relay I/O.
    ///
    /// The later runtime owner must pause admission while invoking this method.
    /// Pagination remains sealed inside the repository, time and entropy are
    /// injected, and exact payload bytes and target membership never change.
    pub async fn recover_delivery_state(
        &self,
        observed_at: MycDeliveryTimeUnixMs,
        entropy: MycDeliveryRecoveryEntropy,
    ) -> Result<MycDeliveryRecoveryReport, MycStateRepositoryError> {
        let outbox_maximum = self.expected().outbox_maximum();
        let discovery_policy = self.expected().discovery_policies().cloned();
        let mut cursor = None;
        let mut aggregate = MycDeliveryRecoveryReport::empty();
        loop {
            let expected = PersistedMetadata::from(self.expected());
            let discovery_policy = discovery_policy.clone();
            let entropy_bytes = entropy.0;
            let batch = self
                .host()
                .transaction(move |transaction| {
                    Box::pin(async move {
                        require_expected_metadata(transaction, &expected)
                            .await
                            .map_err(RecoveryOperationError::from)?;
                        recover_batch(
                            transaction,
                            observed_at,
                            &entropy_bytes,
                            cursor,
                            outbox_maximum,
                            discovery_policy.as_ref(),
                        )
                        .await
                    })
                })
                .await
                .map_err(map_transaction_error)?;
            let next = batch.continuation;
            aggregate
                .merge(batch)
                .map_err(|_| MycStateRepositoryError::new(MycStateRepositoryErrorKind::Binding))?;
            let Some(next) = next else {
                aggregate.continuation = None;
                return Ok(aggregate);
            };
            cursor = Some(next);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryOperationError {
    Binding,
    Storage,
}

impl From<RepositoryOperationError> for RecoveryOperationError {
    fn from(error: RepositoryOperationError) -> Self {
        match error {
            RepositoryOperationError::Binding => Self::Binding,
            RepositoryOperationError::Storage => Self::Storage,
        }
    }
}

impl From<DeliveryOperationError> for RecoveryOperationError {
    fn from(error: DeliveryOperationError) -> Self {
        match error {
            DeliveryOperationError::Binding => Self::Binding,
            DeliveryOperationError::Storage => Self::Storage,
        }
    }
}

async fn recover_batch(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at: MycDeliveryTimeUnixMs,
    entropy: &[u8; 32],
    cursor: Option<RecoveryCursor>,
    outbox_maximum: usize,
    discovery_policy: Option<&MycDiscoveryPolicies>,
) -> Result<MycDeliveryRecoveryReport, RecoveryOperationError> {
    verify_global_invariants(transaction, outbox_maximum).await?;
    let mut job_ids = read_job_ids(transaction, cursor).await?;
    let has_more = job_ids.len() > MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT;
    if has_more {
        job_ids.truncate(MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT);
    }
    let continuation = has_more
        .then(|| job_ids.last().copied().map(RecoveryCursor))
        .flatten();
    let mut report = MycDeliveryRecoveryReport {
        examined_jobs: 0,
        recovered_expired_attempts: 0,
        finalized_jobs: 0,
        promoted_discovery_generations: 0,
        ready_targets: 0,
        scheduled_targets: 0,
        active_targets: 0,
        continuation,
    };
    for job_id in job_ids {
        let before = read_job(transaction, MycDeliveryJobId::from_persisted(job_id))
            .await?
            .ok_or(RecoveryOperationError::Binding)?;
        match before.source_kind() {
            MycDeliverySourceKind::SignerResponse => {
                verify_response_for_delivery_job(transaction, before.id()).await?;
            }
            MycDeliverySourceKind::DiscoveryHandler => {
                verify_document_for_delivery_job(transaction, &before, discovery_policy).await?;
            }
        }
        validate_attempt_histories(transaction, &before).await?;
        let mut current = before.clone();
        for target in before.targets() {
            let Some(attempt_id) = target.active_attempt_id() else {
                continue;
            };
            let attempts = read_attempts(transaction, before.id(), target.index()).await?;
            let attempt = attempts
                .last()
                .filter(|attempt| attempt.id() == attempt_id)
                .ok_or(RecoveryOperationError::Binding)?;
            if observed_at > attempt.lease_expires_at() {
                let jitter = recovery_jitter(&current, attempt.id(), attempt.number(), entropy)?;
                current = recover_expired(
                    transaction,
                    before.id(),
                    target.relay_id(),
                    attempt.id(),
                    jitter,
                    observed_at,
                )
                .await?;
                report.recovered_expired_attempts = increment(report.recovered_expired_attempts)?;
            }
        }
        current = finalize_job_if_terminal(transaction, before.id(), observed_at).await?;
        if !is_terminal(before.status()) && is_terminal(current.status()) {
            report.finalized_jobs = increment(report.finalized_jobs)?;
        }
        if current.status() == MycDeliveryJobStatus::Delivered
            && current.source_kind() == MycDeliverySourceKind::DiscoveryHandler
            && promote_current_if_desired(transaction, current.id(), observed_at).await?
        {
            report.promoted_discovery_generations =
                increment(report.promoted_discovery_generations)?;
        }
        let verified = read_job(transaction, current.id())
            .await?
            .ok_or(RecoveryOperationError::Binding)?;
        validate_attempt_histories(transaction, &verified).await?;
        classify_targets(&verified, observed_at, &mut report)?;
        report.examined_jobs = increment(report.examined_jobs)?;
    }
    Ok(report)
}

async fn verify_global_invariants(
    transaction: &mut ServiceSqliteTransaction<'_>,
    outbox_maximum: usize,
) -> Result<(), RecoveryOperationError> {
    let rows = sqlx::query(READ_INVARIANTS_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| RecoveryOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(RecoveryOperationError::Binding);
    }
    let row = &rows[0];
    for column in [
        "invalid_sources",
        "orphan_responses",
        "orphan_documents",
        "orphan_targets",
        "orphan_attempts",
    ] {
        if row
            .try_get::<i64, _>(column)
            .map_err(|_| RecoveryOperationError::Binding)?
            != 0
        {
            return Err(RecoveryOperationError::Binding);
        }
    }
    let active_jobs = row
        .try_get::<i64, _>("active_jobs")
        .map_err(|_| RecoveryOperationError::Binding)?;
    usize::try_from(active_jobs)
        .ok()
        .filter(|count| *count <= outbox_maximum)
        .map(|_| ())
        .ok_or(RecoveryOperationError::Binding)
}

async fn read_job_ids(
    transaction: &mut ServiceSqliteTransaction<'_>,
    cursor: Option<RecoveryCursor>,
) -> Result<Vec<[u8; 32]>, RecoveryOperationError> {
    let query = match cursor {
        Some(cursor) => sqlx::query(READ_NEXT_JOB_IDS_SQL).bind(cursor.0.as_slice()),
        None => sqlx::query(READ_FIRST_JOB_IDS_SQL),
    };
    let rows = query
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| RecoveryOperationError::Storage)?;
    if rows.len() > MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT + 1 {
        return Err(RecoveryOperationError::Binding);
    }
    rows.iter()
        .map(|row| {
            let bytes = row
                .try_get::<Option<Vec<u8>>, _>("job_id")
                .map_err(|_| RecoveryOperationError::Binding)?
                .ok_or(RecoveryOperationError::Binding)?;
            bytes
                .try_into()
                .map_err(|_| RecoveryOperationError::Binding)
        })
        .collect()
}

async fn validate_attempt_histories(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job: &MycDeliveryJobRecord,
) -> Result<(), RecoveryOperationError> {
    for target in job.targets() {
        let attempts = read_attempts(transaction, job.id(), target.index()).await?;
        if usize::try_from(target.attempt_count()) != Ok(attempts.len())
            || attempts
                .iter()
                .enumerate()
                .any(|(index, attempt)| usize::try_from(attempt.number()) != Ok(index + 1))
        {
            return Err(RecoveryOperationError::Binding);
        }
        let active = matches!(
            target.status(),
            MycDeliveryTargetStatus::Leased | MycDeliveryTargetStatus::Submitted
        );
        if active {
            let attempt = attempts.last().ok_or(RecoveryOperationError::Binding)?;
            let expected_status = match target.status() {
                MycDeliveryTargetStatus::Leased => MycDeliveryAttemptStatus::Leased,
                MycDeliveryTargetStatus::Submitted => MycDeliveryAttemptStatus::Submitted,
                _ => return Err(RecoveryOperationError::Binding),
            };
            if target.active_attempt_id() != Some(attempt.id())
                || attempt.status() != expected_status
            {
                return Err(RecoveryOperationError::Binding);
            }
        } else if attempts.last().is_some_and(|attempt| {
            matches!(
                attempt.status(),
                MycDeliveryAttemptStatus::Leased | MycDeliveryAttemptStatus::Submitted
            )
        }) {
            return Err(RecoveryOperationError::Binding);
        }
    }
    Ok(())
}

fn recovery_jitter(
    job: &MycDeliveryJobRecord,
    attempt_id: MycDeliveryAttemptId,
    attempt_number: u32,
    entropy: &[u8; 32],
) -> Result<MycDeliveryRetryJitter, RecoveryOperationError> {
    let exponent = attempt_number.saturating_sub(1).min(31);
    let factor = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let maximum = job
        .initial_backoff_ms()
        .saturating_mul(factor)
        .min(job.maximum_backoff_ms());
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_JITTER_DOMAIN);
    hasher.update(entropy);
    hasher.update(attempt_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let raw = u64::from_be_bytes(digest[..8].try_into().expect("fixed SHA-256 prefix"));
    let value = raw
        % maximum
            .checked_add(1)
            .ok_or(RecoveryOperationError::Binding)?;
    MycDeliveryRetryJitter::new(value).map_err(|_| RecoveryOperationError::Binding)
}

fn classify_targets(
    job: &MycDeliveryJobRecord,
    observed_at: MycDeliveryTimeUnixMs,
    report: &mut MycDeliveryRecoveryReport,
) -> Result<(), RecoveryOperationError> {
    for target in job.targets() {
        match target.status() {
            MycDeliveryTargetStatus::Pending => {
                report.ready_targets = increment(report.ready_targets)?;
            }
            MycDeliveryTargetStatus::Retryable | MycDeliveryTargetStatus::Unknown => {
                if target
                    .next_attempt_at()
                    .is_some_and(|next| next > observed_at)
                {
                    report.scheduled_targets = increment(report.scheduled_targets)?;
                } else if target.next_attempt_at().is_some() {
                    report.ready_targets = increment(report.ready_targets)?;
                }
            }
            MycDeliveryTargetStatus::Leased | MycDeliveryTargetStatus::Submitted => {
                report.active_targets = increment(report.active_targets)?;
            }
            MycDeliveryTargetStatus::Delivered | MycDeliveryTargetStatus::Exhausted => {}
        }
    }
    Ok(())
}

const fn is_terminal(status: MycDeliveryJobStatus) -> bool {
    matches!(
        status,
        MycDeliveryJobStatus::Delivered
            | MycDeliveryJobStatus::Failed
            | MycDeliveryJobStatus::Unknown
    )
}

fn increment(value: u32) -> Result<u32, RecoveryOperationError> {
    value.checked_add(1).ok_or(RecoveryOperationError::Binding)
}

fn add(left: u32, right: u32) -> Result<u32, RecoveryOperationError> {
    left.checked_add(right)
        .ok_or(RecoveryOperationError::Binding)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<RecoveryOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(RecoveryOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(RecoveryOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
