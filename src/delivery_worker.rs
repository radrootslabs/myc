//! Durable delivery orchestration over exact committed event bytes.

#![allow(
    dead_code,
    reason = "Step 159 Unit 12 seals the worker before Unit 15 runtime graph wiring"
)]

use core::fmt;
use std::error::Error;

use sha2::{Digest as _, Sha256};

use crate::transport_nostr_adapter::{
    MycNostrDeliveryAdapter, MycRelayAdapter, MycRelayExecutionOutcome,
};
use crate::{
    MycConfigDocumentV1, MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome, MycDeliveryClaim,
    MycDeliveryJobId, MycDeliveryJobRecord, MycDeliveryRelayId, MycDeliveryRetryJitter,
    MycDeliverySourceKind, MycDeliveryTimeUnixMs, MycStateRepository, MycTaskCancellation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycDeliveryWorkerErrorKind {
    Configuration,
    State,
    Artifact,
}

pub(crate) struct MycDeliveryWorkerError {
    kind: MycDeliveryWorkerErrorKind,
}

impl MycDeliveryWorkerError {
    pub(crate) const fn kind(&self) -> MycDeliveryWorkerErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycDeliveryWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDeliveryWorkerError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycDeliveryWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc delivery worker failed")
    }
}

impl Error for MycDeliveryWorkerError {}

const fn worker_error(kind: MycDeliveryWorkerErrorKind) -> MycDeliveryWorkerError {
    MycDeliveryWorkerError { kind }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum MycDeliveryWorkerResult {
    Completed(MycDeliveryJobRecord),
    ExactReplay,
    NotReady,
    Terminal,
}

impl fmt::Debug for MycDeliveryWorkerResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Completed(_) => "MycDeliveryWorkerResult::Completed([redacted])",
            Self::ExactReplay => "MycDeliveryWorkerResult::ExactReplay",
            Self::NotReady => "MycDeliveryWorkerResult::NotReady",
            Self::Terminal => "MycDeliveryWorkerResult::Terminal",
        })
    }
}

pub(crate) struct MycDeliveryExecutionEvidence {
    pub(crate) claimed_at: MycDeliveryTimeUnixMs,
    pub(crate) submitted_at: MycDeliveryTimeUnixMs,
    pub(crate) observed_at: MycDeliveryTimeUnixMs,
    pub(crate) retry_jitter: MycDeliveryRetryJitter,
}

impl fmt::Debug for MycDeliveryExecutionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDeliveryExecutionEvidence([sealed])")
    }
}

pub(crate) struct MycDeliveryWorker {
    adapter: MycNostrDeliveryAdapter,
}

impl MycDeliveryWorker {
    pub(crate) fn from_configuration(
        configuration: &MycConfigDocumentV1,
    ) -> Result<Self, MycDeliveryWorkerError> {
        let adapter = MycNostrDeliveryAdapter::from_configuration(configuration)
            .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::Configuration))?;
        Ok(Self { adapter })
    }

    pub(crate) async fn run_one(
        &self,
        repository: &MycStateRepository<'_>,
        job_id: MycDeliveryJobId,
        relay_id: &MycDeliveryRelayId,
        nonce: MycDeliveryAttemptNonce,
        evidence: MycDeliveryExecutionEvidence,
        cancellation: &MycTaskCancellation,
    ) -> Result<MycDeliveryWorkerResult, MycDeliveryWorkerError> {
        run_with_adapter(
            &self.adapter,
            repository,
            job_id,
            relay_id,
            nonce,
            evidence,
            cancellation,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_with_adapter<A: MycRelayAdapter>(
    adapter: &A,
    repository: &MycStateRepository<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    nonce: MycDeliveryAttemptNonce,
    evidence: MycDeliveryExecutionEvidence,
    cancellation: &MycTaskCancellation,
) -> Result<MycDeliveryWorkerResult, MycDeliveryWorkerError> {
    if cancellation.is_cancelled() {
        return Ok(MycDeliveryWorkerResult::NotReady);
    }
    let attempt = match repository
        .claim_delivery_target(job_id, relay_id, nonce, evidence.claimed_at)
        .await
        .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))?
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        MycDeliveryClaim::ExactReplay(_) => return Ok(MycDeliveryWorkerResult::ExactReplay),
        MycDeliveryClaim::NotReady => return Ok(MycDeliveryWorkerResult::NotReady),
        MycDeliveryClaim::Terminal => return Ok(MycDeliveryWorkerResult::Terminal),
    };
    let job = repository
        .read_delivery_job(job_id)
        .await
        .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))?
        .ok_or_else(|| worker_error(MycDeliveryWorkerErrorKind::Artifact))?;
    let exact_event_bytes = read_exact_event(repository, &job).await?;
    let request_id = request_id(job_id, attempt.id());
    let prepared = match adapter.prepare(
        relay_id,
        request_id,
        &exact_event_bytes,
        attempt.lease_expires_at().get(),
    ) {
        Ok(prepared) => prepared,
        Err(_) => {
            return persist_outcome(
                repository,
                job_id,
                relay_id,
                attempt.id(),
                MycDeliveryAttemptOutcome::TransportFailed,
                evidence,
            )
            .await;
        }
    };
    if cancellation.is_cancelled() {
        return persist_outcome(
            repository,
            job_id,
            relay_id,
            attempt.id(),
            MycDeliveryAttemptOutcome::TransportFailed,
            evidence,
        )
        .await;
    }
    repository
        .mark_delivery_attempt_submitted(job_id, relay_id, attempt.id(), evidence.submitted_at)
        .await
        .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))?;
    let outcome = tokio::select! {
        result = adapter.execute(prepared) => result.unwrap_or(MycRelayExecutionOutcome::UnknownAcknowledgement),
        () = cancellation.cancelled() => MycRelayExecutionOutcome::UnknownAcknowledgement,
    };
    let outcome = match outcome {
        MycRelayExecutionOutcome::Accepted => MycDeliveryAttemptOutcome::Delivered,
        MycRelayExecutionOutcome::Rejected => MycDeliveryAttemptOutcome::RelayRejected,
        MycRelayExecutionOutcome::TransportFailed => MycDeliveryAttemptOutcome::TransportFailed,
        MycRelayExecutionOutcome::UnknownAcknowledgement => {
            MycDeliveryAttemptOutcome::UnknownAcknowledgement
        }
    };
    persist_outcome(
        repository,
        job_id,
        relay_id,
        attempt.id(),
        outcome,
        evidence,
    )
    .await
}

async fn read_exact_event(
    repository: &MycStateRepository<'_>,
    job: &MycDeliveryJobRecord,
) -> Result<Box<[u8]>, MycDeliveryWorkerError> {
    let bytes: Box<[u8]> = match job.source_kind() {
        MycDeliverySourceKind::SignerResponse => repository
            .read_nip46_response(job.id())
            .await
            .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))?
            .filter(|record| record.delivery_job().id() == job.id())
            .map(|record| Box::from(record.signed_response_bytes()))
            .ok_or_else(|| worker_error(MycDeliveryWorkerErrorKind::Artifact))?,
        MycDeliverySourceKind::DiscoveryHandler => repository
            .read_discovery_document_for_job(job.id())
            .await
            .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))?
            .map(|record| Box::from(record.event_bytes()))
            .ok_or_else(|| worker_error(MycDeliveryWorkerErrorKind::Artifact))?,
    };
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if &digest != job.artifact_digest().as_bytes() {
        return Err(worker_error(MycDeliveryWorkerErrorKind::Artifact));
    }
    Ok(bytes)
}

async fn persist_outcome(
    repository: &MycStateRepository<'_>,
    job_id: MycDeliveryJobId,
    relay_id: &MycDeliveryRelayId,
    attempt_id: crate::MycDeliveryAttemptId,
    outcome: MycDeliveryAttemptOutcome,
    evidence: MycDeliveryExecutionEvidence,
) -> Result<MycDeliveryWorkerResult, MycDeliveryWorkerError> {
    repository
        .record_delivery_attempt_outcome(
            job_id,
            relay_id,
            attempt_id,
            outcome,
            evidence.retry_jitter,
            evidence.observed_at,
        )
        .await
        .map(MycDeliveryWorkerResult::Completed)
        .map_err(|_| worker_error(MycDeliveryWorkerErrorKind::State))
}

fn request_id(job_id: MycDeliveryJobId, attempt_id: crate::MycDeliveryAttemptId) -> String {
    let mut request = hex::encode(job_id.as_bytes());
    request.push(':');
    request.push_str(&hex::encode(attempt_id.as_bytes()));
    request
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::nip46_wave_080_a::{
        OBSERVED_AT_SECONDS, RECEIVED_AT_MS, configuration, connection_time, metadata,
        migration_evidence, runtime,
    };
    use crate::nip46_wave_080_b::{active_connection, atomic_response_request};
    use crate::{
        MycDeliveryAttemptStatus, MycDeliveryTargetStatus, MycNip46CommitRequest,
        MycTaskCancellation, initialize_myc_state, open_myc_state_read_write,
    };
    use tokio::sync::Notify;

    struct FakeAdapter {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        prepared_bytes: Arc<Mutex<Vec<u8>>>,
        outcome: MycRelayExecutionOutcome,
    }

    impl MycRelayAdapter for FakeAdapter {
        type Prepared = ();

        fn prepare(
            &self,
            _relay_id: &MycDeliveryRelayId,
            request_id: String,
            exact_event_bytes: &[u8],
            deadline_unix_ms: u64,
        ) -> Result<Self::Prepared, crate::transport_nostr_adapter::MycRelayAdapterError> {
            assert_eq!(request_id.len(), 129);
            assert!(deadline_unix_ms > RECEIVED_AT_MS);
            *self.prepared_bytes.lock().expect("prepared bytes") = exact_event_bytes.to_vec();
            Ok(())
        }

        fn execute<'a>(
            &'a self,
            (): Self::Prepared,
        ) -> crate::transport_nostr_adapter::RelayExecutionFuture<'a> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(self.outcome)
            })
        }
    }

    struct NoIoAdapter;

    impl MycRelayAdapter for NoIoAdapter {
        type Prepared = ();

        fn prepare(
            &self,
            _relay_id: &MycDeliveryRelayId,
            _request_id: String,
            _exact_event_bytes: &[u8],
            _deadline_unix_ms: u64,
        ) -> Result<Self::Prepared, crate::transport_nostr_adapter::MycRelayAdapterError> {
            panic!("an exact replay must not prepare a second relay operation")
        }

        fn execute<'a>(
            &'a self,
            (): Self::Prepared,
        ) -> crate::transport_nostr_adapter::RelayExecutionFuture<'a> {
            panic!("an exact replay must not execute a second relay operation")
        }
    }

    async fn committed_response_host(
        root: &std::path::Path,
    ) -> (crate::MycStateHost, MycDeliveryJobId, Vec<u8>) {
        let runtime = runtime(root);
        fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
        fs::set_permissions(
            runtime.context().paths().state(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("state mode");
        let metadata = metadata(&runtime);
        let config = configuration();
        let (applied_at, build) = migration_evidence();
        initialize_myc_state(&runtime, &metadata, applied_at, &build)
            .await
            .expect("initialization");
        let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
            .await
            .expect("state host");
        let repository = host.repository();
        let (work, _active, decision) = active_connection(&repository, &config).await;
        let completion = MycNip46CommitRequest::new(
            &work,
            Some(&decision),
            None,
            connection_time(RECEIVED_AT_MS + 2_001),
        )
        .expect("completion");
        let (response, exact_bytes) = atomic_response_request(&config, &completion);
        let committed = repository
            .commit_nip46_response(&response)
            .await
            .expect("committed response");
        (
            host,
            committed.record().response().delivery_job().id(),
            exact_bytes,
        )
    }

    fn evidence() -> MycDeliveryExecutionEvidence {
        MycDeliveryExecutionEvidence {
            claimed_at: MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 4_000).expect("claim time"),
            submitted_at: MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 4_001)
                .expect("submitted time"),
            observed_at: MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 4_002).expect("observed time"),
            retry_jitter: MycDeliveryRetryJitter::new(0).expect("jitter"),
        }
    }

    #[tokio::test]
    async fn exact_bytes_are_submitted_only_after_durable_submitted_state() {
        let root = tempfile::tempdir().expect("temporary root");
        let (host, job_id, exact_bytes) = committed_response_host(root.path()).await;
        let repository = host.repository();
        let relay = MycDeliveryRelayId::new("primary").expect("relay");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let prepared_bytes = Arc::new(Mutex::new(Vec::new()));
        let adapter = FakeAdapter {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            prepared_bytes: Arc::clone(&prepared_bytes),
            outcome: MycRelayExecutionOutcome::Accepted,
        };
        let (cancellation, _cancel) = MycTaskCancellation::test_pair();
        let run = run_with_adapter(
            &adapter,
            &repository,
            job_id,
            &relay,
            MycDeliveryAttemptNonce::from_injected_entropy([0xa1; 32]),
            evidence(),
            &cancellation,
        );
        let observe = async {
            entered.notified().await;
            let attempts = repository
                .read_delivery_attempts(job_id, &relay)
                .await
                .expect("submitted attempt");
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].status(), MycDeliveryAttemptStatus::Submitted);
            release.notify_one();
        };
        let (result, ()) = tokio::join!(run, observe);
        let MycDeliveryWorkerResult::Completed(job) = result.expect("delivery") else {
            panic!("delivery must complete");
        };
        assert_eq!(
            job.targets()[0].status(),
            MycDeliveryTargetStatus::Delivered
        );
        assert_eq!(
            prepared_bytes.lock().expect("prepared bytes").as_slice(),
            exact_bytes
        );
        host.close().await.expect("close");
    }

    #[tokio::test]
    async fn cancellation_after_submission_is_durably_unknown() {
        let root = tempfile::tempdir().expect("temporary root");
        let (host, job_id, _) = committed_response_host(root.path()).await;
        let repository = host.repository();
        let relay = MycDeliveryRelayId::new("primary").expect("relay");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let adapter = FakeAdapter {
            entered: Arc::clone(&entered),
            release,
            prepared_bytes: Arc::new(Mutex::new(Vec::new())),
            outcome: MycRelayExecutionOutcome::Accepted,
        };
        let (cancellation, cancel) = MycTaskCancellation::test_pair();
        let run = run_with_adapter(
            &adapter,
            &repository,
            job_id,
            &relay,
            MycDeliveryAttemptNonce::from_injected_entropy([0xa2; 32]),
            evidence(),
            &cancellation,
        );
        let cancel_after_submit = async {
            entered.notified().await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(run, cancel_after_submit);
        let MycDeliveryWorkerResult::Completed(job) = result.expect("unknown delivery") else {
            panic!("delivery must resolve");
        };
        assert_eq!(job.targets()[0].status(), MycDeliveryTargetStatus::Unknown);
        let attempts = repository
            .read_delivery_attempts(job_id, &relay)
            .await
            .expect("attempts");
        assert_eq!(attempts[0].status(), MycDeliveryAttemptStatus::Unknown);
        host.close().await.expect("close");
    }

    #[tokio::test]
    async fn concurrent_exact_replay_performs_no_second_external_operation() {
        let root = tempfile::tempdir().expect("temporary root");
        let (host, job_id, _) = committed_response_host(root.path()).await;
        let repository = host.repository();
        let relay = MycDeliveryRelayId::new("primary").expect("relay");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let adapter = FakeAdapter {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            prepared_bytes: Arc::new(Mutex::new(Vec::new())),
            outcome: MycRelayExecutionOutcome::Accepted,
        };
        let nonce = MycDeliveryAttemptNonce::from_injected_entropy([0xa3; 32]);
        let replay_nonce = MycDeliveryAttemptNonce::from_injected_entropy([0xa3; 32]);
        let (cancellation, _cancel) = MycTaskCancellation::test_pair();
        let run = run_with_adapter(
            &adapter,
            &repository,
            job_id,
            &relay,
            nonce,
            evidence(),
            &cancellation,
        );
        let replay = async {
            entered.notified().await;
            let result = run_with_adapter(
                &NoIoAdapter,
                &repository,
                job_id,
                &relay,
                replay_nonce,
                evidence(),
                &cancellation,
            )
            .await
            .expect("exact replay");
            assert_eq!(result, MycDeliveryWorkerResult::ExactReplay);
            release.notify_one();
        };
        let (result, ()) = tokio::join!(run, replay);
        assert!(matches!(
            result.expect("delivery"),
            MycDeliveryWorkerResult::Completed(_)
        ));
        host.close().await.expect("close");
    }

    #[test]
    fn worker_errors_are_source_free_and_redacted() {
        for kind in [
            MycDeliveryWorkerErrorKind::Configuration,
            MycDeliveryWorkerErrorKind::State,
            MycDeliveryWorkerErrorKind::Artifact,
        ] {
            let error = worker_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("secret"));
        }
        assert_eq!(OBSERVED_AT_SECONDS, 1_725_000_000);
    }
}
