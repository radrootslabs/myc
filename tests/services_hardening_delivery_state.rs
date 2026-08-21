#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_DELIVERY_RELAY_ID_MAX_BYTES, MYC_STATE_SCHEMA_VERSION, MycConfigProfile,
    MycDeliveryArtifactDigest, MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome,
    MycDeliveryAttemptStatus, MycDeliveryClaim, MycDeliveryJobAdmission, MycDeliveryJobRequest,
    MycDeliveryJobStatus, MycDeliveryPolicyMode, MycDeliveryRelayId, MycDeliveryStateErrorKind,
    MycDeliveryTargetStatus, MycDeliveryTimeUnixMs, MycNip46ClientPublicKey, MycNip46EventId,
    MycNip46RequestId, MycRequestReceivedAtUnixMs, MycSignerOperationNonce, MycSignerRequest,
    MycSignerRequestDigest, MycSignerRequestMethod, MycStateMetadata, MycStateRepositoryErrorKind,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, initialize_myc_state,
    open_myc_state_read_write, parse_myc_cli_v1_from, parse_myc_config_v1,
    resolve_myc_runtime_context,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const DELIVERY_SOURCE: &str = include_str!("../src/state_delivery.rs");
const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const CLIENT_PUBLIC_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn runtime(root: &Path) -> myc::MycRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root,
        "run",
    ])
    .expect("valid invocation");
    resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn prepare_state_directory(runtime: &myc::MycRuntimeContext) {
    let directory = runtime.context().paths().state();
    fs::create_dir_all(directory).expect("state directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("state mode");
}

fn metadata(runtime: &myc::MycRuntimeContext, source: &[u8]) -> MycStateMetadata {
    let configuration =
        parse_myc_config_v1(source, MycConfigProfile::RepoLocal).expect("configuration");
    MycStateMetadata::new(
        runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "b44119fbac5985be8127ad1bf56d2950e6399427",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        MYC_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

fn signer_request(request_id: &str, nonce: u8, received_at: u64) -> MycSignerRequest {
    let canonical = format!(r#"{{"id":"{request_id}","method":"ping","params":[]}}"#);
    MycSignerRequest::new(
        MycNip46ClientPublicKey::new(CLIENT_PUBLIC_KEY).expect("client identity"),
        MycNip46RequestId::new(request_id).expect("request ID"),
        MycNip46EventId::from_bytes([nonce; 32]),
        MycSignerRequestMethod::Ping,
        MycSignerRequestDigest::for_canonical_request(canonical.as_bytes()).expect("digest"),
        MycSignerOperationNonce::from_injected_entropy([nonce; 32]),
        MycRequestReceivedAtUnixMs::new(received_at).expect("time"),
    )
}

fn time(value: u64) -> MycDeliveryTimeUnixMs {
    MycDeliveryTimeUnixMs::new(value).expect("delivery time")
}

#[test]
fn delivery_inputs_and_diagnostics_are_closed_bounded_and_redacted() {
    let maximum = format!("a{}", "1".repeat(MYC_DELIVERY_RELAY_ID_MAX_BYTES - 1));
    assert!(MycDeliveryRelayId::new(&maximum).is_ok());
    for invalid in [
        "",
        "Primary",
        "relay-name",
        "relay__name",
        "relay_",
        &format!("a{maximum}"),
        &"x".repeat(1024 * 1024),
    ] {
        assert_eq!(
            MycDeliveryRelayId::new(invalid)
                .expect_err("invalid relay")
                .kind(),
            MycDeliveryStateErrorKind::InvalidRelayId
        );
    }
    for invalid in [0, i64::MAX.unsigned_abs() + 1] {
        assert_eq!(
            MycDeliveryTimeUnixMs::new(invalid)
                .expect_err("invalid time")
                .kind(),
            MycDeliveryStateErrorKind::InvalidTime
        );
    }
    assert!(MycDeliveryTimeUnixMs::new(i64::MAX.unsigned_abs()).is_ok());
    assert_eq!(
        [
            MycDeliveryPolicyMode::AtLeastOneRequired,
            MycDeliveryPolicyMode::AllRequired,
            MycDeliveryPolicyMode::RequiredQuorum,
        ]
        .map(MycDeliveryPolicyMode::as_str),
        ["at_least_one_required", "all_required", "required_quorum"]
    );

    let relay = MycDeliveryRelayId::new("relay_secret_123").expect("relay");
    let nonce = MycDeliveryAttemptNonce::from_injected_entropy([0x91; 32]);
    let digest = MycDeliveryArtifactDigest::from_bytes([0x92; 32]);
    let error = MycDeliveryRelayId::new("secret-invalid").expect_err("invalid");
    assert!(Error::source(&error).is_none());
    let rendered = format!("{relay:?} {nonce:?} {digest:?} {error} {error:?}");
    for secret in ["relay_secret_123", "secret-invalid", "145, 145", "146, 146"] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test]
async fn delivery_jobs_are_config_bound_idempotent_restart_safe_and_unknown_aware() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime, CONFIG_EXAMPLE);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let admitted = host
        .repository()
        .admit_signer_request(&signer_request("delivery-01", 0x31, 100))
        .await
        .expect("signer request");
    let request = MycDeliveryJobRequest::signer_response(
        admitted.record().operation_id(),
        MycDeliveryArtifactDigest::from_bytes([0x44; 32]),
        time(110),
    );
    let job = host
        .repository()
        .create_delivery_job(&request)
        .await
        .expect("job");
    assert!(matches!(job, MycDeliveryJobAdmission::Created(_)));
    let job_id = job.record().id();
    assert_eq!(
        job.record().policy_mode(),
        MycDeliveryPolicyMode::AllRequired
    );
    assert_eq!(job.record().required_acknowledgements(), 2);
    assert_eq!(job.record().max_attempts(), 5);
    assert_eq!(job.record().initial_backoff_ms(), 250);
    assert_eq!(job.record().maximum_backoff_ms(), 30_000);
    assert_eq!(job.record().attempt_deadline_ms(), 15_000);
    assert_eq!(job.record().targets().len(), 2);
    assert_eq!(job.record().targets()[0].relay_id().as_str(), "primary");
    assert_eq!(job.record().targets()[1].relay_id().as_str(), "secondary");
    assert!(
        job.record()
            .targets()
            .iter()
            .all(|target| target.required())
    );

    let replay = host
        .repository()
        .create_delivery_job(&request)
        .await
        .expect("exact replay");
    assert!(matches!(replay, MycDeliveryJobAdmission::ExactReplay(_)));
    let conflicting = MycDeliveryJobRequest::signer_response(
        admitted.record().operation_id(),
        MycDeliveryArtifactDigest::from_bytes([0x45; 32]),
        time(110),
    );
    assert_eq!(
        host.repository()
            .create_delivery_job(&conflicting)
            .await
            .expect_err("conflicting job")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );

    let primary = MycDeliveryRelayId::new("primary").expect("primary");
    let left_repository = host.repository();
    let right_repository = host.repository();
    let (left, right) = tokio::join!(
        left_repository.claim_delivery_target(
            job_id,
            &primary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x51; 32]),
            time(120),
        ),
        right_repository.claim_delivery_target(
            job_id,
            &primary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x51; 32]),
            time(120),
        )
    );
    let (claimed, replayed) = match (left.expect("left claim"), right.expect("right claim")) {
        (MycDeliveryClaim::Claimed(claimed), MycDeliveryClaim::ExactReplay(replayed))
        | (MycDeliveryClaim::ExactReplay(replayed), MycDeliveryClaim::Claimed(claimed)) => {
            (claimed, replayed)
        }
        outcome => panic!("unexpected concurrent outcome: {outcome:?}"),
    };
    assert_eq!(claimed.id(), replayed.id());
    assert_eq!(claimed.number(), 1);
    assert_eq!(
        host.repository()
            .record_delivery_attempt_outcome(
                job_id,
                &primary,
                claimed.id(),
                MycDeliveryAttemptOutcome::Delivered,
                time(121),
            )
            .await
            .expect_err("delivery before submission")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let submitted = host
        .repository()
        .mark_delivery_attempt_submitted(job_id, &primary, claimed.id(), time(121))
        .await
        .expect("submitted");
    assert_eq!(submitted.status(), MycDeliveryAttemptStatus::Submitted);
    let active = host
        .repository()
        .record_delivery_attempt_outcome(
            job_id,
            &primary,
            claimed.id(),
            MycDeliveryAttemptOutcome::Delivered,
            time(122),
        )
        .await
        .expect("primary delivered");
    assert_eq!(active.status(), MycDeliveryJobStatus::Active);

    let secondary = MycDeliveryRelayId::new("secondary").expect("secondary");
    let first = match host
        .repository()
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x61; 32]),
            time(123),
        )
        .await
        .expect("secondary claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("unexpected claim: {other:?}"),
    };
    host.repository()
        .mark_delivery_attempt_submitted(job_id, &secondary, first.id(), time(124))
        .await
        .expect("secondary submitted");
    let unknown = host
        .repository()
        .record_delivery_attempt_outcome(
            job_id,
            &secondary,
            first.id(),
            MycDeliveryAttemptOutcome::UnknownAcknowledgement,
            time(125),
        )
        .await
        .expect("unknown acknowledgement");
    assert_eq!(unknown.status(), MycDeliveryJobStatus::Active);
    assert_eq!(
        unknown.targets()[1].status(),
        MycDeliveryTargetStatus::Unknown
    );
    assert_eq!(unknown.targets()[1].next_attempt_at(), Some(time(375)));
    assert!(matches!(
        host.repository()
            .claim_delivery_target(
                job_id,
                &secondary,
                MycDeliveryAttemptNonce::from_injected_entropy([0x62; 32]),
                time(374),
            )
            .await
            .expect("not ready"),
        MycDeliveryClaim::NotReady
    ));
    let second = match host
        .repository()
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x62; 32]),
            time(375),
        )
        .await
        .expect("retry claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("unexpected retry: {other:?}"),
    };
    let retry = host
        .repository()
        .recover_expired_delivery_lease(job_id, &secondary, second.id(), time(15_376))
        .await
        .expect("expired pre-submit lease");
    assert_eq!(
        retry.targets()[1].status(),
        MycDeliveryTargetStatus::Retryable
    );
    assert_eq!(retry.targets()[1].next_attempt_at(), Some(time(15_876)));
    let third = match host
        .repository()
        .claim_delivery_target(
            job_id,
            &secondary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x63; 32]),
            time(15_876),
        )
        .await
        .expect("third claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("unexpected third claim: {other:?}"),
    };
    host.repository()
        .mark_delivery_attempt_submitted(job_id, &secondary, third.id(), time(15_877))
        .await
        .expect("third submitted");
    let delivered = host
        .repository()
        .record_delivery_attempt_outcome(
            job_id,
            &secondary,
            third.id(),
            MycDeliveryAttemptOutcome::Delivered,
            time(15_878),
        )
        .await
        .expect("job delivered");
    assert_eq!(delivered.status(), MycDeliveryJobStatus::Delivered);
    assert_eq!(delivered.finalized_at(), Some(time(15_878)));
    let attempts = host
        .repository()
        .read_delivery_attempts(job_id, &secondary)
        .await
        .expect("attempt history");
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].status(), MycDeliveryAttemptStatus::Unknown);
    assert_eq!(attempts[0].reason(), Some("acknowledgement_lost"));
    assert_eq!(attempts[1].status(), MycDeliveryAttemptStatus::Failed);
    assert_eq!(attempts[1].reason(), Some("lease_expired_before_submit"));
    assert_eq!(attempts[2].status(), MycDeliveryAttemptStatus::Delivered);
    host.close().await.expect("first close");

    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen");
    assert_eq!(
        host.repository()
            .read_delivery_job(job_id)
            .await
            .expect("read after reopen")
            .expect("job")
            .status(),
        MycDeliveryJobStatus::Delivered
    );
    host.close().await.expect("final close");
}

#[tokio::test]
async fn terminal_unknown_is_not_relabelled_as_failure_and_sql_guards_preserve_evidence() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let source = String::from_utf8(CONFIG_EXAMPLE.to_vec())
        .expect("UTF-8 config")
        .replace("max_attempts = 5", "max_attempts = 1");
    let metadata = metadata(&runtime, source.as_bytes());
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let admitted = host
        .repository()
        .admit_signer_request(&signer_request("delivery-unknown", 0x71, 100))
        .await
        .expect("request");
    let job = host
        .repository()
        .create_delivery_job(&MycDeliveryJobRequest::signer_response(
            admitted.record().operation_id(),
            MycDeliveryArtifactDigest::from_bytes([0x72; 32]),
            time(110),
        ))
        .await
        .expect("job");
    let job_id = job.record().id();
    let primary = MycDeliveryRelayId::new("primary").expect("primary");
    let attempt = match host
        .repository()
        .claim_delivery_target(
            job_id,
            &primary,
            MycDeliveryAttemptNonce::from_injected_entropy([0x73; 32]),
            time(120),
        )
        .await
        .expect("claim")
    {
        MycDeliveryClaim::Claimed(attempt) => attempt,
        other => panic!("unexpected claim: {other:?}"),
    };
    host.repository()
        .mark_delivery_attempt_submitted(job_id, &primary, attempt.id(), time(121))
        .await
        .expect("submit");
    let job = host
        .repository()
        .record_delivery_attempt_outcome(
            job_id,
            &primary,
            attempt.id(),
            MycDeliveryAttemptOutcome::UnknownAcknowledgement,
            time(122),
        )
        .await
        .expect("unknown");
    assert_eq!(job.status(), MycDeliveryJobStatus::Unknown);
    assert_eq!(job.targets()[0].status(), MycDeliveryTargetStatus::Unknown);
    assert_eq!(job.targets()[0].next_attempt_at(), None);
    assert_eq!(job.finalized_at(), Some(time(122)));
    host.close().await.expect("close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    for statement in [
        "DELETE FROM publication_attempts",
        "DELETE FROM publication_targets",
        "DELETE FROM publication_outbox",
        "UPDATE publication_targets SET relay_id = 'changed'",
        "UPDATE publication_outbox SET artifact_sha256 = zeroblob(32)",
    ] {
        assert!(
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .is_err(),
            "guard accepted {statement}"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM publication_attempts")
            .fetch_one(&mut connection)
            .await
            .expect("attempt count"),
        1
    );
    connection.close().await.expect("connection close");
}

#[test]
fn delivery_boundary_is_typed_sqlx_only_and_has_no_external_wait_or_legacy_authority() {
    assert!(LIB_SOURCE.contains("mod state_delivery;"));
    assert!(!LIB_SOURCE.contains("pub mod state_delivery;"));
    assert!(DELIVERY_SOURCE.contains("ServiceSqliteTransaction<'_>"));
    assert!(DELIVERY_SOURCE.contains("publication_attempts"));
    assert!(DELIVERY_SOURCE.contains("UnknownAcknowledgement"));
    assert!(CATALOG_SOURCE.contains("publication_outbox_no_delete"));
    assert!(CATALOG_SOURCE.contains("publication_targets_no_delete"));
    assert!(CATALOG_SOURCE.contains("publication_attempts_no_delete"));
    for forbidden in [
        "SqlitePool",
        "SqliteConnection",
        "BEGIN ",
        "COMMIT",
        "ROLLBACK",
        "relay_url",
        "reqwest",
        "tokio::spawn",
        "std::env",
        "std::time",
        "outbox_sqlite",
    ] {
        assert!(
            !DELIVERY_SOURCE.contains(forbidden),
            "found forbidden delivery authority `{forbidden}`"
        );
    }
}
