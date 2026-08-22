#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES, MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES,
    MYC_STATE_SCHEMA_VERSION, MycConfigProfile, MycNip46ClientPublicKey, MycNip46EventId,
    MycNip46RequestId, MycRequestReceivedAtUnixMs, MycSignerOperationNonce, MycSignerRequest,
    MycSignerRequestAdmission, MycSignerRequestDigest, MycSignerRequestErrorKind,
    MycSignerRequestMethod, MycStateMetadata, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, initialize_myc_state, open_myc_state_read_write, parse_myc_cli_v1_from,
    parse_myc_config_v1, resolve_myc_runtime_context,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const REQUEST_SOURCE: &str = include_str!("../src/state_request.rs");
const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const CLIENT_PUBLIC_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const REQUEST_BYTES: &[u8] = b"{\"id\":\"request-01\",\"method\":\"ping\",\"params\":[]}";

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
    .expect("valid test invocation");
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

fn metadata(runtime: &myc::MycRuntimeContext) -> MycStateMetadata {
    let configuration =
        parse_myc_config_v1(CONFIG_EXAMPLE, MycConfigProfile::RepoLocal).expect("configuration");
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

fn request(
    request_id: &str,
    event_byte: u8,
    method: MycSignerRequestMethod,
    bytes: &[u8],
    nonce_byte: u8,
    received_at: u64,
) -> MycSignerRequest {
    MycSignerRequest::new(
        MycNip46ClientPublicKey::new(CLIENT_PUBLIC_KEY).expect("client identity"),
        MycNip46RequestId::new(request_id).expect("request ID"),
        MycNip46EventId::from_bytes([event_byte; 32]),
        method,
        MycSignerRequestDigest::for_canonical_request(bytes).expect("request digest"),
        MycSignerOperationNonce::from_injected_entropy([nonce_byte; 32]),
        MycRequestReceivedAtUnixMs::new(received_at).expect("received time"),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn request_inputs_ids_methods_and_diagnostics_are_closed_bounded_and_stable() {
    let maximum_id = "a".repeat(MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES);
    assert!(MycNip46RequestId::new(&maximum_id).is_ok());
    for invalid in [
        "",
        " request",
        "request ",
        "request\n",
        &"a".repeat(MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES + 1),
        &"x".repeat(1024 * 1024),
    ] {
        assert_eq!(
            MycNip46RequestId::new(invalid)
                .expect_err("invalid request ID")
                .kind(),
            MycSignerRequestErrorKind::InvalidRequestId
        );
    }

    assert!(MycNip46ClientPublicKey::new(CLIENT_PUBLIC_KEY).is_ok());
    for invalid in [
        "22",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        assert_eq!(
            MycNip46ClientPublicKey::new(invalid)
                .expect_err("invalid client identity")
                .kind(),
            MycSignerRequestErrorKind::InvalidClientIdentity
        );
    }

    let maximum_request = vec![b'x'; MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES];
    assert!(MycSignerRequestDigest::for_canonical_request(&maximum_request).is_ok());
    assert_eq!(
        MycSignerRequestDigest::for_canonical_request(&[])
            .expect_err("empty request")
            .kind(),
        MycSignerRequestErrorKind::InvalidCanonicalRequest
    );
    assert_eq!(
        MycSignerRequestDigest::for_canonical_request(&vec![
            b'x';
            MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES
                + 1
        ])
        .expect_err("oversized request")
        .kind(),
        MycSignerRequestErrorKind::InvalidCanonicalRequest
    );

    assert!(MycRequestReceivedAtUnixMs::new(i64::MAX.unsigned_abs()).is_ok());
    for invalid in [0, i64::MAX.unsigned_abs() + 1] {
        assert_eq!(
            MycRequestReceivedAtUnixMs::new(invalid)
                .expect_err("invalid time")
                .kind(),
            MycSignerRequestErrorKind::InvalidReceivedAt
        );
    }

    let methods = [
        (MycSignerRequestMethod::Connect, "connect"),
        (MycSignerRequestMethod::GetPublicKey, "get_public_key"),
        (
            MycSignerRequestMethod::GetSessionCapability,
            "get_session_capability",
        ),
        (MycSignerRequestMethod::SignEvent, "sign_event"),
        (MycSignerRequestMethod::Nip04Encrypt, "nip04_encrypt"),
        (MycSignerRequestMethod::Nip04Decrypt, "nip04_decrypt"),
        (MycSignerRequestMethod::Nip44Encrypt, "nip44_encrypt"),
        (MycSignerRequestMethod::Nip44Decrypt, "nip44_decrypt"),
        (MycSignerRequestMethod::Ping, "ping"),
        (MycSignerRequestMethod::SwitchRelays, "switch_relays"),
        (MycSignerRequestMethod::Logout, "logout"),
    ];
    assert_eq!(
        methods.map(|(method, _)| method.as_str()),
        methods.map(|(_, wire)| wire)
    );

    assert_eq!(
        hex(MycSignerRequestDigest::for_canonical_request(REQUEST_BYTES)
            .expect("digest")
            .as_bytes()),
        "378d4f7906aed41e5af96c7000dfc57d9c4c4c9ad3d94b84e985621c25e727f2"
    );
    let nonce = MycSignerOperationNonce::from_injected_entropy([0x5a; 32]);
    assert_eq!(format!("{nonce:?}"), "MycSignerOperationNonce([redacted])");

    let error = MycNip46RequestId::new(" secret\n").expect_err("invalid input");
    assert!(Error::source(&error).is_none());
    let request = request(
        "request-01",
        0x44,
        MycSignerRequestMethod::Ping,
        REQUEST_BYTES,
        1,
        1,
    );
    let rendered = format!("{request:?} {error} {error:?}");
    for secret in [CLIENT_PUBLIC_KEY, "request-01", "secret", "378d4f79"] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test]
async fn request_admission_is_atomic_idempotent_conflict_aware_and_restart_stable() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");

    let first = request(
        "request-01",
        0x44,
        MycSignerRequestMethod::Ping,
        REQUEST_BYTES,
        100,
        100,
    );
    let admitted = host
        .repository()
        .admit_signer_request(&first)
        .await
        .expect("first admission");
    assert!(matches!(admitted, MycSignerRequestAdmission::Admitted(_)));
    assert_eq!(admitted.record().replay_count(), 0);
    assert_eq!(admitted.record().conflict_count(), 0);
    assert_eq!(
        hex(admitted.record().operation_id().as_bytes()),
        "c72e6b8e1824b94e8ce6284cff532895c3e8b80c7859e02decfc7fda88134444"
    );
    assert_eq!(
        hex(admitted.record().correlation_id().as_bytes()),
        "87d551e4c196fded2fa4d9335655711f64da873c552e7338f8e99541eb871654"
    );
    assert_ne!(
        admitted.record().operation_id().as_bytes(),
        admitted.record().correlation_id().as_bytes()
    );
    let first_operation_id = admitted.record().operation_id();
    let first_correlation_id = admitted.record().correlation_id();

    let same_event = request(
        "request-01",
        0x44,
        MycSignerRequestMethod::Ping,
        REQUEST_BYTES,
        101,
        101,
    );
    let replay = host
        .repository()
        .admit_signer_request(&same_event)
        .await
        .expect("same-event replay");
    assert!(matches!(replay, MycSignerRequestAdmission::ExactReplay(_)));
    assert_eq!(replay.record().replay_count(), 1);
    assert_eq!(replay.record().operation_id(), first_operation_id);
    assert_eq!(replay.record().correlation_id(), first_correlation_id);

    let new_event = request(
        "request-01",
        0x45,
        MycSignerRequestMethod::Ping,
        REQUEST_BYTES,
        102,
        102,
    );
    let replay = host
        .repository()
        .admit_signer_request(&new_event)
        .await
        .expect("new-event replay");
    assert!(matches!(replay, MycSignerRequestAdmission::ExactReplay(_)));
    assert_eq!(replay.record().replay_count(), 2);

    let changed_payload = request(
        "request-01",
        0x46,
        MycSignerRequestMethod::GetPublicKey,
        b"{\"id\":\"request-01\",\"method\":\"get_public_key\",\"params\":[]}",
        103,
        103,
    );
    let conflict = host
        .repository()
        .admit_signer_request(&changed_payload)
        .await
        .expect("request conflict");
    assert!(matches!(
        conflict,
        MycSignerRequestAdmission::ConflictingReuse(_)
    ));
    assert_eq!(conflict.record().method(), MycSignerRequestMethod::Ping);
    assert_eq!(conflict.record().conflict_count(), 1);

    let reused_event = request(
        "request-02",
        0x44,
        MycSignerRequestMethod::Ping,
        b"{\"id\":\"request-02\",\"method\":\"ping\",\"params\":[]}",
        104,
        104,
    );
    let conflict = host
        .repository()
        .admit_signer_request(&reused_event)
        .await
        .expect("event conflict");
    assert!(matches!(
        conflict,
        MycSignerRequestAdmission::ConflictingReuse(_)
    ));
    assert_eq!(conflict.record().operation_id(), first_operation_id);
    let rendered = format!("{admitted:?} {:?}", admitted.record());
    for secret in [CLIENT_PUBLIC_KEY, "request-01", "c72e6b8e"] {
        assert!(!rendered.contains(secret));
    }
    host.close().await.expect("close after first lifecycle");

    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopened writable host");
    let after_reopen = request(
        "request-01",
        0x47,
        MycSignerRequestMethod::Ping,
        REQUEST_BYTES,
        105,
        105,
    );
    let replay = host
        .repository()
        .admit_signer_request(&after_reopen)
        .await
        .expect("replay after reopen");
    assert!(matches!(replay, MycSignerRequestAdmission::ExactReplay(_)));
    assert_eq!(replay.record().replay_count(), 3);
    assert_eq!(replay.record().conflict_count(), 1);
    host.close().await.expect("final close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .read_only(true)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("test inspection connection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_requests")
            .fetch_one(&mut connection)
            .await
            .expect("request count"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_request_dedup")
            .fetch_one(&mut connection)
            .await
            .expect("dedup count"),
        4
    );
    let event_conflicts = sqlx::query_scalar::<_, i64>(
        "SELECT conflict_count FROM nip46_request_dedup \
         WHERE dedup_kind = 'event' AND identity_sha256 = ?",
    )
    .bind([0x44_u8; 32].as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("event conflict count");
    assert_eq!(event_conflicts, 1);
    assert!(
        sqlx::query("UPDATE nip46_requests SET received_at_unix_ms = 999")
            .execute(&mut connection)
            .await
            .is_err()
    );
    connection.close().await.expect("inspection close");
}

#[tokio::test]
async fn concurrent_identical_admission_creates_one_request_and_bounded_replay_evidence() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let request = request(
        "request-concurrent",
        0x55,
        MycSignerRequestMethod::Ping,
        b"concurrent",
        200,
        200,
    );
    let repository = host.repository();

    let (a, b, c, d, e, f, g, h) = tokio::join!(
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
        repository.admit_signer_request(&request),
    );
    let outcomes = [a, b, c, d, e, f, g, h]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("concurrent admissions");
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MycSignerRequestAdmission::Admitted(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MycSignerRequestAdmission::ExactReplay(_)))
            .count(),
        7
    );
    let final_record = outcomes
        .iter()
        .max_by_key(|outcome| outcome.record().replay_count())
        .expect("final replay record")
        .record();
    assert_eq!(final_record.replay_count(), 7);
    assert_eq!(final_record.conflict_count(), 0);
    host.close().await.expect("host close");
}

#[tokio::test]
async fn exact_schema_v3_state_advances_to_v9_before_request_admission() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("downgrade fixture connection");
    let shared_update = sqlx::query_scalar::<_, String>(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'radroots_service_metadata_guard_update'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("shared update trigger");
    let myc_update = sqlx::query_scalar::<_, String>(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'myc_state_metadata_no_update'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("Myc update trigger");
    let migration_delete = sqlx::query_scalar::<_, String>(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'schema_migrations_no_delete'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("migration delete trigger");
    for sql in [
        "DROP TRIGGER radroots_service_metadata_guard_update",
        "DROP TRIGGER myc_state_metadata_no_update",
        "DROP TRIGGER schema_migrations_no_delete",
        "DROP TRIGGER connection_rate_windows_guard_update",
        "DROP TRIGGER nip46_request_audit_no_update",
        "DROP TRIGGER operation_audit_no_update",
        "DROP TRIGGER myc_audit_state_no_delete",
        "DROP TRIGGER myc_audit_state_guard_update",
        "DROP TRIGGER connection_auth_challenges_no_delete",
        "DROP TRIGGER connection_auth_challenges_guard_update",
        "DROP TRIGGER nip46_request_decisions_no_delete",
        "DROP TRIGGER nip46_request_decisions_guard_update",
        "DROP TRIGGER connection_permissions_no_delete",
        "DROP TRIGGER connection_permissions_no_update",
        "DROP TRIGGER connections_no_delete",
        "DROP TRIGGER connections_guard_update",
        "DROP TRIGGER nip46_signed_responses_no_delete",
        "DROP TRIGGER nip46_signed_responses_no_update",
        "DROP TABLE nip46_signed_responses",
        "DROP TRIGGER nip46_operation_commits_no_delete",
        "DROP TRIGGER nip46_operation_commits_no_update",
        "DROP TABLE nip46_operation_commits",
        "DROP TABLE discovery_publication_state",
        "DROP TABLE discovery_documents",
        "DROP TABLE discovery_desired_state",
        "DROP TABLE delivery_attempts",
        "DROP TABLE delivery_targets",
        "DROP TABLE delivery_jobs",
        "DROP TABLE nip46_request_audit",
        "DROP TABLE operation_audit",
        "DROP TABLE connection_rate_windows",
        "DROP TABLE myc_audit_state",
        "DROP TABLE nip46_request_decisions",
        "DROP TABLE connection_auth_challenges",
        "DROP TABLE connection_permissions",
        "DROP TABLE connections",
        "UPDATE radroots_service_metadata SET state_schema_version = 3 WHERE singleton = 1",
        "UPDATE myc_state_metadata SET state_contract_version = 3 WHERE singleton = 1",
        "DELETE FROM schema_migrations WHERE version IN (4, 5, 6, 7, 8, 9)",
    ] {
        sqlx::query(sql)
            .execute(&mut connection)
            .await
            .expect("construct exact schema-v3 fixture");
    }
    for sql in [&shared_update, &myc_update, &migration_delete] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql.as_str()))
            .execute(&mut connection)
            .await
            .expect("restore exact governed trigger");
    }
    connection.close().await.expect("fixture connection close");

    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("schema-v3 upgrade");
    let admitted = host
        .repository()
        .admit_signer_request(&request(
            "request-after-v3",
            0x66,
            MycSignerRequestMethod::Ping,
            b"after-v3",
            0x66,
            300,
        ))
        .await
        .expect("request admission after migration");
    assert!(matches!(admitted, MycSignerRequestAdmission::Admitted(_)));
    host.close().await.expect("upgraded host close");
}

#[tokio::test]
async fn persisted_operation_entropy_tampering_fails_closed_as_a_binding_error() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let request = request(
        "request-tamper",
        0x77,
        MycSignerRequestMethod::Ping,
        b"tamper-check",
        0x77,
        400,
    );
    host.repository()
        .admit_signer_request(&request)
        .await
        .expect("initial request admission");
    host.close().await.expect("host close before tamper");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("tamper fixture connection");
    let request_guard = sqlx::query_scalar::<_, String>(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' \
         AND name = 'nip46_requests_no_update'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("request guard");
    sqlx::query("DROP TRIGGER nip46_requests_no_update")
        .execute(&mut connection)
        .await
        .expect("drop request guard for corruption fixture");
    sqlx::query("UPDATE nip46_requests SET operation_nonce = zeroblob(32)")
        .execute(&mut connection)
        .await
        .expect("corrupt persisted operation nonce");
    sqlx::raw_sql(sqlx::AssertSqlSafe(request_guard.as_str()))
        .execute(&mut connection)
        .await
        .expect("restore request guard");
    connection.close().await.expect("fixture connection close");

    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen structurally valid state");
    let error = host
        .repository()
        .admit_signer_request(&request)
        .await
        .expect_err("tampered operation binding");
    assert_eq!(error.kind(), myc::MycStateRepositoryErrorKind::Binding);
    host.close().await.expect("host close after rejection");
}

#[test]
fn request_store_is_sealed_transactional_bounded_and_independent_of_external_effects() {
    assert!(REQUEST_SOURCE.contains("ServiceSqliteTransaction<'_>"));
    assert!(REQUEST_SOURCE.contains("require_expected_metadata(transaction, &expected)"));
    assert!(REQUEST_SOURCE.contains("CASE WHEN typeof(r.operation_id) = 'blob'"));
    assert!(REQUEST_SOURCE.contains("END AS logical_operation_id"));
    assert!(REQUEST_SOURCE.contains("LIMIT 2"));
    assert!(REQUEST_SOURCE.contains("replay_count < 9223372036854775807"));
    assert!(REQUEST_SOURCE.contains("conflict_count < 9223372036854775807"));
    assert!(CATALOG_SOURCE.contains("CREATE TABLE nip46_requests"));
    assert!(CATALOG_SOURCE.contains("CREATE TABLE nip46_request_dedup"));
    assert!(CATALOG_SOURCE.contains("nip46_request_dedup_guard_update"));
    for forbidden in [
        "SqlitePool",
        "SqliteConnection",
        "BEGIN ",
        "COMMIT",
        "ROLLBACK",
        "std::fs",
        "std::env",
        "SystemTime",
        "Instant::now",
        "tokio::spawn",
        "spawn_blocking",
        "rand::",
        "getrandom",
        "SystemEntropy",
        "reqwest",
        "RelayPool",
        "provider.await",
    ] {
        assert!(
            !REQUEST_SOURCE.contains(forbidden),
            "found forbidden request-store authority `{forbidden}`"
        );
    }
}
