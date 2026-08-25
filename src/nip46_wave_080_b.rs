//! Native test-only transaction qualification for RCLD-RSHR-080 wave 080-b.

use std::{error::Error as _, fs, os::unix::fs::PermissionsExt};

use nostr::{JsonUtil as _, Kind, Tag, Timestamp, UnsignedEvent as NostrUnsignedEvent};
use radroots_nostr_connect::message::Request;
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions as _, Connection as _, Row as _, sqlite::SqliteConnectOptions};

use crate::{
    MycAuditCorrelationId, MycConnectionAdmissionPolicy, MycConnectionNonce,
    MycConnectionOperatorDecision, MycConnectionPolicyGeneration, MycLocalSignerUntrustedResponse,
    MycNip46CommitAdmission, MycNip46CommitRequest, MycNip46ResponseCommitAdmission,
    MycNip46ResponseCommitRequest, MycNip46SessionEffect, MycProviderCorrelationId,
    MycProviderDeadlineUnixMs, MycProviderOperation, MycProviderOperationId,
    MycProviderOperationInput, MycProviderResponseObservedAtUnixMs, MycProviderRole,
    MycRateRelayId, MycSignerRequestAdmission, MycSignerRequestMethod, MycStateRepositoryErrorKind,
    initialize_myc_state, open_myc_state_read_write, prepare_myc_nip46_work,
    provider_local_signer::{ProtectedWireHex, WireProviderResult},
};

use super::nip46_wave_080_a::{
    Encryption, OBSERVED_AT_SECONDS, PROVIDER_DEADLINE_MS, RECEIVED_AT_MS, configuration,
    connect_request, connection_time, keys, metadata, migration_evidence, permissions,
    prepared_request, runtime, unsigned_sign_event, untrusted_response,
};
use crate::provider_verification::verify_encrypted_provider_response;
use crate::state_response::MycNip46PendingResponseCommitRequest;

pub(crate) async fn active_connection(
    repository: &crate::MycStateRepository<'_>,
    config: &crate::MycConfigDocumentV1,
) -> (
    crate::MycNip46Work,
    crate::MycConnectionRecord,
    crate::MycConnectionDecisionRecord,
) {
    let prepared = prepared_request(
        config,
        &keys(10),
        "step147-connect",
        connect_request(),
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 20,
        20,
        RECEIVED_AT_MS + 20,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("connect request admission");
    let work = prepare_myc_nip46_work(
        prepared,
        admitted.record().clone(),
        None,
        config.provider_contract(),
        connection_time(RECEIVED_AT_MS + 1_000),
        None,
    )
    .expect("connect work");
    let connection_request = work
        .connection_admission_request(
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            MycConnectionNonce::from_injected_entropy([0x51; 32]),
            connection_time(RECEIVED_AT_MS + 1_000),
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
            MycRateRelayId::new("primary").expect("relay ID"),
        )
        .expect("connection request");
    let pending = repository
        .admit_connection(&connection_request)
        .await
        .expect("pending connection");
    let record = pending.record().expect("pending record");
    let active = repository
        .decide_pending_connection(
            record.operation_id(),
            record.connection().expect("connection").id(),
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            connection_time(RECEIVED_AT_MS + 2_000),
            MycAuditCorrelationId::new([0x52; 32]),
            MycConnectionOperatorDecision::Approve {
                granted_permissions: permissions(),
                authorized_until: Some(connection_time(RECEIVED_AT_MS + 100_000)),
            },
        )
        .await
        .expect("approved connection");
    let decision = repository
        .read_connection_decision(record.operation_id())
        .await
        .expect("terminal connect decision");
    (work, active, decision)
}

async fn pending_connection(
    repository: &crate::MycStateRepository<'_>,
    config: &crate::MycConfigDocumentV1,
) -> (crate::MycNip46Work, crate::MycConnectionDecisionRecord) {
    let prepared = prepared_request(
        config,
        &keys(10),
        "pending-response-connect",
        connect_request(),
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 40,
        40,
        RECEIVED_AT_MS + 40,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("pending request admission");
    let work = prepare_myc_nip46_work(
        prepared,
        admitted.record().clone(),
        None,
        config.provider_contract(),
        connection_time(RECEIVED_AT_MS + 4_000),
        None,
    )
    .expect("pending connect work");
    let connection_request = work
        .connection_admission_request(
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            crate::MycConnectionNonce::from_injected_entropy([0x81; 32]),
            connection_time(RECEIVED_AT_MS + 4_000),
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
            MycRateRelayId::new("primary").expect("relay"),
        )
        .expect("pending connection request");
    let admission = repository
        .admit_connection(&connection_request)
        .await
        .expect("pending connection admission");
    let decision = admission.record().expect("pending decision").clone();
    assert_eq!(
        decision.decision(),
        crate::MycConnectionDecision::PendingApproval
    );
    (work, decision)
}

fn pending_response_request(
    config: &crate::MycConfigDocumentV1,
    work: &crate::MycNip46Work,
    decision: &crate::MycConnectionDecisionRecord,
) -> (MycNip46PendingResponseCommitRequest, Vec<u8>) {
    let unsigned = NostrUnsignedEvent::new(
        keys(2).public_key(),
        Timestamp::from_secs(OBSERVED_AT_SECONDS + 41),
        Kind::Custom(24_133),
        vec![Tag::public_key(keys(10).public_key())],
        "encrypted-pending-response",
    );
    let operation = MycProviderOperation::new(
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        MycProviderOperationId::from_bytes([0xa1; 32]),
        MycProviderCorrelationId::from_bytes([0xa2; 32]),
        MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("provider deadline"),
        MycProviderOperationInput::sign_event(unsigned.as_json().as_bytes())
            .expect("response signing input"),
    )
    .expect("pending response operation");
    let signed = unsigned
        .sign_with_keys(&keys(2))
        .expect("signed pending response");
    let bytes = serde_json::to_vec(&signed).expect("canonical pending response");
    let verified = verify_encrypted_provider_response(
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        &operation,
        MycProviderResponseObservedAtUnixMs::new(RECEIVED_AT_MS + 41_001).expect("response time"),
        WireProviderResult::SignEvent {
            payload_hex: ProtectedWireHex::from_bytes(&bytes),
        },
    )
    .expect("verified pending response");
    let request = MycNip46PendingResponseCommitRequest::new(
        work,
        decision,
        &operation,
        &verified,
        crate::MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 41_003).expect("commit time"),
    )
    .expect("pending response request");
    (request, bytes)
}

#[tokio::test]
async fn pending_approval_response_and_delivery_job_commit_atomically_and_replay_exactly() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
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
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();
    let (work, decision) = pending_connection(&repository, &config).await;
    let (request, response_bytes) = pending_response_request(&config, &work, &decision);
    let debug = format!("{request:?}");
    assert!(!debug.contains("encrypted-pending-response"));

    let rollback = repository
        .commit_nip46_pending_response(&request.fail_after_response_for_test())
        .await
        .expect_err("pending response without delivery must roll back");
    assert_eq!(
        rollback.kind(),
        crate::MycStateRepositoryErrorKind::Transaction
    );
    let committed = repository
        .commit_nip46_pending_response(&request)
        .await
        .expect("pending response commit");
    assert_eq!(committed.signed_response_bytes(), response_bytes);
    assert_eq!(
        committed.operation_id(),
        work.request_record().operation_id()
    );
    let replay = repository
        .commit_nip46_pending_response(&request)
        .await
        .expect("exact pending response replay");
    assert_eq!(replay, committed);
    let by_job = repository
        .read_nip46_response(committed.delivery_job().id())
        .await
        .expect("pending response read")
        .expect("retained pending response");
    assert_eq!(by_job, committed);
    repository
        .verify_delivery_invariants()
        .await
        .expect("pending response satisfies delivery invariants");
    repository
        .recover_delivery_state(
            crate::MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 41_004).expect("recovery time"),
            crate::MycDeliveryRecoveryEntropy::from_injected_entropy([0xa3; 32]),
        )
        .await
        .expect("pending response survives restart recovery");
    repository
        .verify_delivery_invariants()
        .await
        .expect("recovered pending response satisfies delivery invariants");
    host.close().await.expect("host close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_pending_responses")
            .fetch_one(&mut connection)
            .await
            .expect("pending response count"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_signed_responses")
            .fetch_one(&mut connection)
            .await
            .expect("terminal response count"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_operation_commits")
            .fetch_one(&mut connection)
            .await
            .expect("terminal operation count"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM delivery_jobs")
            .fetch_one(&mut connection)
            .await
            .expect("delivery job count"),
        1
    );
    connection.close().await.expect("inspection close");
}

pub(crate) fn atomic_response_request(
    config: &crate::MycConfigDocumentV1,
    completion: &MycNip46CommitRequest,
) -> (MycNip46ResponseCommitRequest, Vec<u8>) {
    let unsigned = NostrUnsignedEvent::new(
        keys(2).public_key(),
        Timestamp::from_secs(OBSERVED_AT_SECONDS + 3),
        Kind::Custom(24_133),
        vec![Tag::public_key(keys(10).public_key())],
        "encrypted-response",
    );
    let operation = MycProviderOperation::new(
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        MycProviderOperationId::from_bytes([0x91; 32]),
        MycProviderCorrelationId::from_bytes([0x92; 32]),
        MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("provider deadline"),
        MycProviderOperationInput::sign_event(unsigned.as_json().as_bytes())
            .expect("response signing input"),
    )
    .expect("response operation");
    let signed = unsigned.sign_with_keys(&keys(2)).expect("signed response");
    let bytes = serde_json::to_vec(&signed).expect("canonical response");
    let verified = verify_encrypted_provider_response(
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        &operation,
        MycProviderResponseObservedAtUnixMs::new(RECEIVED_AT_MS + 3_001).expect("response time"),
        WireProviderResult::SignEvent {
            payload_hex: ProtectedWireHex::from_bytes(&bytes),
        },
    )
    .expect("verified response");
    let request = MycNip46ResponseCommitRequest::new(
        completion,
        &operation,
        &verified,
        crate::MycDeliveryTimeUnixMs::new(RECEIVED_AT_MS + 3_003).expect("commit time"),
    )
    .expect("atomic response request");
    (request, bytes)
}

#[tokio::test]
async fn verified_signed_response_commits_completion_and_outbox_exactly_once() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
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
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();
    let (connect_work, active, connect_decision) = active_connection(&repository, &config).await;
    let connect_commit = MycNip46CommitRequest::new(
        &connect_work,
        Some(&connect_decision),
        None,
        connection_time(RECEIVED_AT_MS + 2_001),
    )
    .expect("connect completion");
    let invalid_binding = MycNip46CommitRequest::new(
        &connect_work,
        None,
        None,
        connection_time(RECEIVED_AT_MS + 2_001),
    )
    .expect_err("connect completion requires its terminal decision");
    assert_eq!(
        invalid_binding.kind(),
        crate::MycNip46CommitErrorKind::InvalidBinding
    );
    assert!(invalid_binding.source().is_none());
    assert!(!format!("{invalid_binding:?}").contains("step147-connect"));
    let invalid_time = MycNip46CommitRequest::new(
        &connect_work,
        Some(&connect_decision),
        None,
        connection_time(RECEIVED_AT_MS),
    )
    .expect_err("completion time precedes request admission");
    assert_eq!(
        invalid_time.kind(),
        crate::MycNip46CommitErrorKind::InvalidTime
    );
    assert!(invalid_time.source().is_none());
    let before_terminal_decision = MycNip46CommitRequest::new(
        &connect_work,
        Some(&connect_decision),
        None,
        connection_time(RECEIVED_AT_MS + 1_500),
    )
    .expect_err("completion time precedes terminal decision");
    assert_eq!(
        before_terminal_decision.kind(),
        crate::MycNip46CommitErrorKind::InvalidTime
    );
    assert_eq!(
        repository
            .commit_nip46_operation(&connect_commit)
            .await
            .expect("connect completion commit")
            .record()
            .session_effect(),
        MycNip46SessionEffect::ConnectionAdmitted
    );
    let (partial_response, _) = atomic_response_request(&config, &connect_commit);
    assert_eq!(
        repository
            .commit_nip46_response(&partial_response)
            .await
            .expect_err("completion-only legacy state is not repaired")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );

    let prepared = prepared_request(
        &config,
        &keys(10),
        "step147-sign",
        Request::SignEvent(unsigned_sign_event()),
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 21,
        21,
        RECEIVED_AT_MS + 21,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("sign request admission");
    assert!(matches!(admitted, MycSignerRequestAdmission::Admitted(_)));
    let work = prepare_myc_nip46_work(
        prepared,
        admitted.record().clone(),
        Some(active),
        config.provider_contract(),
        connection_time(RECEIVED_AT_MS + 3_000),
        Some(MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("provider deadline")),
    )
    .expect("sign work");
    let operation = work.provider_operation().expect("provider operation");
    let unsigned: NostrUnsignedEvent =
        serde_json::from_slice(operation.input().bytes().expect("canonical unsigned event"))
            .expect("unsigned event");
    let signed = unsigned.sign_with_keys(&keys(3)).expect("signed event");
    let signed_bytes = serde_json::to_vec(&signed).expect("canonical signed event");
    let response: MycLocalSignerUntrustedResponse = untrusted_response(
        operation,
        hex::encode(operation.correlation_id().as_bytes()),
        WireProviderResult::SignEvent {
            payload_hex: ProtectedWireHex::from_bytes(&signed_bytes),
        },
    );
    let verified = response
        .verify(
            config
                .provider_contract()
                .binding(MycProviderRole::User)
                .expect("user binding"),
            operation,
            MycProviderResponseObservedAtUnixMs::new(RECEIVED_AT_MS + 3_001)
                .expect("response time"),
        )
        .expect("verified signed event");
    let request = MycNip46CommitRequest::new(
        &work,
        None,
        Some(&verified),
        connection_time(RECEIVED_AT_MS + 3_002),
    )
    .expect("completion request");
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(&hex::encode(operation.operation_id().as_bytes())));
    assert!(!request_debug.contains(&hex::encode(operation.correlation_id().as_bytes())));
    assert!(!request_debug.contains(String::from_utf8_lossy(&signed_bytes).as_ref()));
    let (atomic_request, response_bytes) = atomic_response_request(&config, &request);
    assert_eq!(
        repository
            .commit_nip46_response(&atomic_request.fail_after_completion_for_test())
            .await
            .expect_err("completion-edge failure rolls back")
            .kind(),
        MycStateRepositoryErrorKind::Transaction
    );
    assert_eq!(
        repository
            .commit_nip46_response(&atomic_request.fail_after_response_for_test())
            .await
            .expect_err("response-edge failure rolls back")
            .kind(),
        MycStateRepositoryErrorKind::Transaction
    );
    let committed = repository
        .commit_nip46_response(&atomic_request)
        .await
        .expect("atomic response commit");
    assert!(matches!(
        committed,
        MycNip46ResponseCommitAdmission::Committed(_)
    ));
    assert_eq!(
        committed.record().completion().method(),
        MycSignerRequestMethod::SignEvent
    );
    assert_eq!(
        committed.record().completion().artifact_sha256(),
        Some(&<[u8; 32]>::from(Sha256::digest(&signed_bytes)))
    );
    assert_eq!(
        committed.record().response().signed_response_bytes(),
        response_bytes
    );
    assert!(
        committed
            .record()
            .response()
            .delivery_job()
            .targets()
            .iter()
            .all(|target| target.attempt_count() == 0
                && target.status() == crate::MycDeliveryTargetStatus::Pending)
    );
    let record_debug = format!("{:?}", committed.record());
    assert!(!record_debug.contains(&hex::encode(
        committed.record().completion().operation_id().as_bytes()
    )));
    assert!(!record_debug.contains(&hex::encode(
        committed.record().completion().correlation_id().as_bytes()
    )));
    assert!(!record_debug.contains(&hex::encode(Sha256::digest(&signed_bytes))));
    let replay = repository
        .commit_nip46_response(&atomic_request)
        .await
        .expect("exact atomic replay");
    assert!(matches!(
        replay,
        MycNip46ResponseCommitAdmission::ExactReplay(_)
    ));
    let retry = repository
        .read_nip46_response(committed.record().response().delivery_job().id())
        .await
        .expect("response retry read")
        .expect("retained response");
    assert_eq!(retry.signed_response_bytes(), response_bytes);
    host.close().await.expect("host close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    let row = sqlx::query(
        "SELECT provider_artifact, provider_artifact_sha256 FROM nip46_operation_commits \
         WHERE method = 'sign_event'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("committed artifact");
    assert_eq!(row.get::<Vec<u8>, _>("provider_artifact"), signed_bytes);
    assert_eq!(
        row.get::<Vec<u8>, _>("provider_artifact_sha256"),
        Sha256::digest(&signed_bytes).as_slice()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM delivery_jobs")
            .fetch_one(&mut connection)
            .await
            .expect("delivery job count"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_signed_responses")
            .fetch_one(&mut connection)
            .await
            .expect("response count"),
        1
    );
    connection.close().await.expect("inspection close");
}

#[tokio::test]
async fn session_revocation_and_completion_roll_back_together_then_replay_exactly() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
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
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();
    let (_connect_work, active, _connect_decision) = active_connection(&repository, &config).await;

    let prepared = prepared_request(
        &config,
        &keys(10),
        "step147-logout",
        Request::Logout,
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 22,
        22,
        RECEIVED_AT_MS + 22,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("logout request admission");
    let work = crate::MycNip46Work::local_for_test(
        admitted.record().clone(),
        active.clone(),
        MycSignerRequestMethod::Logout,
    );
    let failed =
        MycNip46CommitRequest::new(&work, None, None, connection_time(RECEIVED_AT_MS + 3_100))
            .expect("logout completion")
            .fail_after_session_effect_for_test();
    assert_eq!(
        repository
            .commit_nip46_operation(&failed)
            .await
            .expect_err("injected transaction failure")
            .kind(),
        MycStateRepositoryErrorKind::Transaction
    );

    let request =
        MycNip46CommitRequest::new(&work, None, None, connection_time(RECEIVED_AT_MS + 3_100))
            .expect("logout completion retry");
    let committed = repository
        .commit_nip46_operation(&request)
        .await
        .expect("rollback preserved retry authority");
    assert_eq!(
        committed.record().session_effect(),
        MycNip46SessionEffect::ConnectionRevoked
    );
    assert!(matches!(
        repository
            .commit_nip46_operation(&request)
            .await
            .expect("logout replay"),
        MycNip46CommitAdmission::ExactReplay(_)
    ));
    host.close().await.expect("host close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM connections WHERE connection_id = ?")
            .bind(active.id().as_bytes().as_slice())
            .fetch_one(&mut connection)
            .await
            .expect("connection status"),
        "expired"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_operation_commits")
            .fetch_one(&mut connection)
            .await
            .expect("completion count"),
        1
    );
    connection.close().await.expect("inspection close");
}
