//! Isolated native coverage for delivery selection through the real repository.

use std::{fs, os::unix::fs::PermissionsExt};

use radroots_storage::event::SourceGeneration;

use crate::nip46_wave_080_a::{
    RECEIVED_AT_MS, configuration, connection_time, keys, metadata, migration_evidence, runtime,
};
use crate::nip46_wave_080_b::{active_connection, atomic_response_request};
use crate::{
    MycConfigProfile, MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome, MycDeliveryClaim,
    MycDeliveryJobStatus, MycDeliveryRelayId, MycDeliveryRetryJitter, MycDeliveryTargetStatus,
    MycDeliveryTimeUnixMs, MycNip46CommitRequest, MycStateMetadata, initialize_myc_state,
    open_myc_state_read_write, parse_myc_config_v1,
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

#[tokio::test]
async fn ready_target_selection_skips_optional_unknown_at_attempt_ceiling() {
    let directory = tempfile::tempdir().expect("temporary state root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state directory mode");
    let source = include_str!("../contracts/services_hardening/config.v1.example.toml")
        .replacen(
            "4444444444444444444444444444444444444444444444444444444444444444",
            &keys(2).public_key().to_hex(),
            1,
        )
        .replacen(
            "2222222222222222222222222222222222222222222222222222222222222222",
            &keys(3).public_key().to_hex(),
            1,
        )
        .replacen("required = true", "required = false", 1)
        .replacen("max_attempts = 5", "max_attempts = 1", 1);
    let configuration = parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("one optional target with one attempt");
    let metadata = MycStateMetadata::new(
        &runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("fixture generation"),
        RECEIVED_AT_MS,
    )
    .expect("configuration-bound metadata");
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();
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
    let primary = MycDeliveryRelayId::new("primary").expect("optional primary target");
    let secondary = MycDeliveryRelayId::new("secondary").expect("required secondary target");
    assert_eq!(
        committed.record().response().delivery_job().max_attempts(),
        1
    );
    assert!(!committed.record().response().delivery_job().targets()[0].required());
    assert!(committed.record().response().delivery_job().targets()[1].required());
    let optional = match repository
        .claim_delivery_target(
            job_id,
            &primary,
            MycDeliveryAttemptNonce::from_injected_entropy([0xc1; 32]),
            time(4_000),
        )
        .await
        .expect("optional target claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("expected fresh optional claim: {other:?}"),
    };
    repository
        .mark_delivery_attempt_submitted(job_id, &primary, optional.id(), time(4_001))
        .await
        .expect("record synthetic submission evidence");
    let active = repository
        .record_delivery_attempt_outcome(
            job_id,
            &primary,
            optional.id(),
            MycDeliveryAttemptOutcome::UnknownAcknowledgement,
            MycDeliveryRetryJitter::new(0).expect("zero jitter at attempt ceiling"),
            time(4_002),
        )
        .await
        .expect("retain synthetic unknown acknowledgement");
    assert_eq!(active.status(), MycDeliveryJobStatus::Active);
    let unknown = active.targets()[0].clone();
    assert_eq!(unknown.status(), MycDeliveryTargetStatus::Unknown);
    assert_eq!(unknown.attempt_count(), 1);
    assert_eq!(unknown.next_attempt_at(), None);
    assert!(matches!(
        repository
            .claim_delivery_target(
                job_id,
                &primary,
                MycDeliveryAttemptNonce::from_injected_entropy([0xc2; 32]),
                time(4_003),
            )
            .await
            .expect("optional target has no remaining attempt"),
        MycDeliveryClaim::Terminal
    ));
    assert_eq!(
        repository
            .next_ready_delivery_target(time(4_003))
            .await
            .expect("select claimable required target"),
        Some((job_id, secondary.clone())),
        "an optional unknown target at its attempt ceiling must not starve required work"
    );
    let required = match repository
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0xc3; 32]),
            time(4_003),
        )
        .await
        .expect("required target claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("expected fresh required claim: {other:?}"),
    };
    repository
        .mark_delivery_attempt_submitted(job_id, &secondary, required.id(), time(4_004))
        .await
        .expect("record required submission evidence");
    let delivered = repository
        .record_delivery_attempt_outcome(
            job_id,
            &secondary,
            required.id(),
            MycDeliveryAttemptOutcome::Delivered,
            MycDeliveryRetryJitter::new(0).expect("zero jitter"),
            time(4_005),
        )
        .await
        .expect("synthetic required acknowledgement");
    assert_eq!(delivered.status(), MycDeliveryJobStatus::Delivered);
    assert_eq!(delivered.targets()[0], unknown);
    repository
        .verify_delivery_invariants()
        .await
        .expect("delivery invariants retain the optional unknown evidence");
    host.close().await.expect("state close");

    let reopened = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen state");
    let repository = reopened.repository();
    let retained = repository
        .read_delivery_job(job_id)
        .await
        .expect("reopened job read")
        .expect("retained job");
    assert_eq!(retained.status(), MycDeliveryJobStatus::Delivered);
    assert_eq!(retained.targets()[0], unknown);
    assert_eq!(
        repository
            .read_delivery_attempts(job_id, &primary)
            .await
            .expect("retained optional attempt")
            .len(),
        1
    );
    assert_eq!(
        repository
            .read_nip46_response(job_id)
            .await
            .expect("reopened response read")
            .expect("retained response")
            .signed_response_bytes(),
        signed_bytes
    );
    reopened.close().await.expect("reopened state close");
}
