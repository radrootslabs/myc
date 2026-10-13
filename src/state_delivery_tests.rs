//! Isolated native coverage for delivery selection through the real repository.

use std::{fs, os::unix::fs::PermissionsExt};

use crate::nip46_wave_080_a::{
    RECEIVED_AT_MS, configuration, connection_time, metadata, migration_evidence, runtime,
};
use crate::nip46_wave_080_b::{active_connection, atomic_response_request};
use crate::{
    MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome, MycDeliveryClaim, MycDeliveryJobStatus,
    MycDeliveryRelayId, MycDeliveryRetryJitter, MycDeliveryTargetStatus, MycDeliveryTimeUnixMs,
    MycNip46CommitRequest, initialize_myc_state, open_myc_state_read_write,
};

fn time(offset_ms: u64) -> MycDeliveryTimeUnixMs {
    MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + offset_ms).expect("fixture time")
}

#[tokio::test]
async fn ready_target_selection_is_read_only_ordered_and_respects_delivery_state() {
    let directory = tempfile::tempdir().expect("temporary state root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state directory mode");
    let metadata = metadata(&runtime);
    let configuration = configuration();
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_000))
            .await
            .expect("empty outbox selection"),
        None
    );

    let (work, _, decision) = active_connection(&repository, &configuration).await;
    let completion = MycNip46CommitRequest::new(
        &work,
        Some(&decision),
        None,
        connection_time(RECEIVED_AT_MS + 2_001),
    )
    .expect("connection completion");
    let (request, signed_bytes) = atomic_response_request(&configuration, &completion);
    let committed = repository
        .commit_nip46_response(&request)
        .await
        .expect("atomic response and delivery commit");
    let job_id = committed.record().response().delivery_job().id();
    let primary = MycDeliveryRelayId::new("primary").expect("primary target");
    let secondary = MycDeliveryRelayId::new("secondary").expect("secondary target");
    let before = repository
        .read_delivery_job(job_id)
        .await
        .expect("initial job read")
        .expect("initial job");
    assert_eq!(before.targets().len(), 2);
    assert_eq!(before.targets()[0].relay_id(), &primary);
    assert_eq!(before.targets()[1].relay_id(), &secondary);
    assert!(before.targets().iter().all(|target| {
        target.status() == MycDeliveryTargetStatus::Pending && target.attempt_count() == 0
    }));

    for _ in 0..2 {
        assert_eq!(
            repository
                .next_ready_delivery_target(time(4_000))
                .await
                .expect("two ready targets must select the first"),
            Some((job_id, primary.clone()))
        );
    }
    assert_eq!(
        repository
            .read_delivery_job(job_id)
            .await
            .expect("job after selection")
            .expect("retained job"),
        before,
        "selection must not mutate job or target state"
    );

    let first = match repository
        .claim_delivery_target(
            job_id,
            &primary,
            MycDeliveryAttemptNonce::from_injected_entropy([0xb1; 32]),
            time(4_000),
        )
        .await
        .expect("primary claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("expected fresh primary claim: {other:?}"),
    };
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_001))
            .await
            .expect("skip leased primary"),
        Some((job_id, secondary.clone()))
    );
    let second = match repository
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0xb2; 32]),
            time(4_001),
        )
        .await
        .expect("secondary claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("expected fresh secondary claim: {other:?}"),
    };
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_002))
            .await
            .expect("all targets leased"),
        None
    );
    for (relay, attempt) in [(&primary, &first), (&secondary, &second)] {
        repository
            .mark_delivery_attempt_submitted(job_id, relay, attempt.id(), time(4_002))
            .await
            .expect("record synthetic submission evidence");
    }
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_003))
            .await
            .expect("all targets submitted"),
        None
    );
    repository
        .record_delivery_attempt_outcome(
            job_id,
            &primary,
            first.id(),
            MycDeliveryAttemptOutcome::Delivered,
            MycDeliveryRetryJitter::new(0).expect("zero jitter"),
            time(4_003),
        )
        .await
        .expect("synthetic primary acknowledgement");
    let retryable = repository
        .record_delivery_attempt_outcome(
            job_id,
            &secondary,
            second.id(),
            MycDeliveryAttemptOutcome::TransportFailed,
            MycDeliveryRetryJitter::new(200).expect("bounded jitter"),
            time(4_003),
        )
        .await
        .expect("synthetic retryable secondary outcome");
    assert_eq!(retryable.status(), MycDeliveryJobStatus::Active);
    assert_eq!(retryable.targets()[1].next_attempt_at(), Some(time(4_203)));
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_202))
            .await
            .expect("retry not yet due"),
        None
    );
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_203))
            .await
            .expect("retry due at exact boundary"),
        Some((job_id, secondary.clone()))
    );
    let retry = match repository
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0xb3; 32]),
            time(4_203),
        )
        .await
        .expect("secondary retry claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("expected fresh retry claim: {other:?}"),
    };
    assert_eq!(retry.number(), 2);
    repository
        .mark_delivery_attempt_submitted(job_id, &secondary, retry.id(), time(4_204))
        .await
        .expect("record retry submission evidence");
    let delivered = repository
        .record_delivery_attempt_outcome(
            job_id,
            &secondary,
            retry.id(),
            MycDeliveryAttemptOutcome::Delivered,
            MycDeliveryRetryJitter::new(0).expect("zero jitter"),
            time(4_205),
        )
        .await
        .expect("synthetic retry acknowledgement");
    assert_eq!(delivered.status(), MycDeliveryJobStatus::Delivered);
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_206))
            .await
            .expect("terminal job is ineligible"),
        None
    );
    let retained = repository
        .read_nip46_response(job_id)
        .await
        .expect("response read")
        .expect("retained response");
    assert_eq!(retained.signed_response_bytes(), signed_bytes);
    repository
        .verify_delivery_invariants()
        .await
        .expect("delivery invariants after selection and claims");
    host.close().await.expect("state close");

    let reopened = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen state");
    let repository = reopened.repository();
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_207))
            .await
            .expect("terminal job remains ineligible after reopen"),
        None
    );
    assert_eq!(
        repository
            .read_nip46_response(job_id)
            .await
            .expect("reopened response read")
            .expect("reopened response")
            .signed_response_bytes(),
        signed_bytes
    );
    reopened.close().await.expect("reopened state close");
}
