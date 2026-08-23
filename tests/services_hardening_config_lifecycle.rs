#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    error::Error,
    fs,
    num::NonZeroU32,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use myc::{
    MycConfigApplyErrorKind, MycConfigProfile, MycStateHostErrorKind, MycStateMetadata,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, initialize_myc_state,
    open_myc_state_inspection, open_myc_state_read_write, parse_myc_cli_v1_from,
    parse_myc_config_v1, resolve_myc_runtime_context,
};
use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, MigrationCatalog, OpenMode,
    SchemaCatalog, ServiceDatabaseIdentity, ServiceSqliteConnectionOptions, ServiceSqliteHost,
    ServiceSqlitePaths, initialize_database,
};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, Row, sqlite::SqliteConnectOptions};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONFIG_SOURCE: &str = include_str!("../src/state_config.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

fn runtime(root: &Path) -> myc::MycRuntimeContext {
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

fn prepare(runtime: &myc::MycRuntimeContext) {
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
}

fn configuration(source: &str) -> myc::MycConfigDocumentV1 {
    parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal).expect("configuration")
}

fn metadata(
    runtime: &myc::MycRuntimeContext,
    configuration: &myc::MycConfigDocumentV1,
) -> MycStateMetadata {
    MycStateMetadata::new(
        runtime,
        configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn build() -> MigrationBuildIdentity {
    build_for_schema(myc::MYC_STATE_SCHEMA_VERSION)
}

fn build_for_schema(state_schema_version: u32) -> MigrationBuildIdentity {
    build_for_contracts(state_schema_version, 1)
}

fn build_for_contracts(
    state_schema_version: u32,
    provider_contract_version: u32,
) -> MigrationBuildIdentity {
    MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "7d7b454b4c9ed86569671993bd03ca868b676665",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        state_schema_version,
        1,
        1,
        provider_contract_version,
    )
    .expect("build")
}

#[derive(Debug)]
struct TestInitializationError;

impl std::fmt::Display for TestInitializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("test catalog initialization failed")
    }
}

impl Error for TestInitializationError {}

async fn initialize_v9(runtime: &myc::MycRuntimeContext, metadata: &MycStateMetadata) {
    let full_migrations = myc::myc_migration_catalog().expect("full migrations");
    let migrations = MigrationCatalog::new(full_migrations.descriptors()[..8].iter().cloned())
        .expect("v9 migrations");
    let full_schema = myc::myc_schema_catalog().expect("full schema");
    let schema = SchemaCatalog::new(&migrations, full_schema.versions()[..9].iter().copied())
        .expect("v9 schema");
    let paths = ServiceSqlitePaths::from_runtime_context(runtime.context()).expect("paths");
    let initial = metadata.initial_database_metadata();
    let identity = ServiceDatabaseIdentity::new(
        &paths,
        initial.source_generation(),
        NonZeroU32::new(9).unwrap(),
        initial.application_id(),
    );
    let authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        initial,
        &schema,
        |path: PathBuf| async move {
            let connection = sqlx::SqliteConnection::connect_with(
                &SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(false)
                    .disable_statement_logging(),
            )
            .await
            .map_err(|_| TestInitializationError)?;
            connection
                .close()
                .await
                .map_err(|_| TestInitializationError)
        },
    )
    .await
    .expect("v9 initialize");
    let (host, outcome) = ServiceSqliteHost::open_initialized(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        authority,
        MigrationAppliedAtUnixSeconds::new(1_725_000_000).unwrap(),
        &build_for_schema(9),
        &[],
    )
    .await
    .expect("v9 migrations");
    assert_eq!(outcome.final_version(), 9);
    assert_eq!(outcome.applied_count(), 8);

    let digest = *metadata.configuration_digest().as_bytes();
    let identities = metadata.expected_identities();
    let transport: Box<str> = identities.transport().as_hex().into();
    let user: Box<str> = identities.user().as_hex().into();
    let discovery: Option<Box<str>> = identities.discovery().map(|value| value.as_hex().into());
    let versions = metadata.policy_versions();
    host.transaction(move |transaction| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO myc_state_metadata (singleton, normalized_config_sha256, \
                 transport_public_key, user_public_key, discovery_public_key, \
                 config_contract_version, state_contract_version, operator_contract_version, \
                 status_contract_version) VALUES (1, ?, ?, ?, ?, ?, 9, ?, ?)",
            )
            .bind(digest.as_slice())
            .bind(transport.as_ref())
            .bind(user.as_ref())
            .bind(discovery.as_deref())
            .bind(i64::from(versions.configuration()))
            .bind(i64::from(versions.operator()))
            .bind(i64::from(versions.status()))
            .execute(&mut *transaction)
            .await
            .map(|_| ())
        })
    })
    .await
    .expect("v9 Myc birth binding");
    host.close().await.expect("v9 close");
}

async fn initialize(runtime: &myc::MycRuntimeContext, metadata: &MycStateMetadata) {
    initialize_myc_state(
        runtime,
        metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_000).unwrap(),
        &build(),
    )
    .await
    .expect("initialize");
}

fn options(runtime: &myc::MycRuntimeContext) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging()
}

#[tokio::test]
async fn offline_apply_appends_one_generation_and_rebinds_future_startup() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize(&runtime, &current_metadata).await;

    let candidate_source = CONFIG.replace("level = \"info\"", "level = \"warn\"");
    let candidate = configuration(&candidate_source);
    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect("writer");
    let second_writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect_err("exclusive writer authority must reject a concurrent daemon");
    assert_eq!(second_writer.kind(), MycStateHostErrorKind::ReadWriteOpen);

    let mismatched_build = build_for_contracts(myc::MYC_STATE_SCHEMA_VERSION, 2);
    let mismatch = writer
        .repository()
        .apply_configuration(
            &current,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &mismatched_build,
        )
        .await
        .expect_err("provider contract mismatch");
    assert_eq!(mismatch.kind(), MycConfigApplyErrorKind::InvalidInput);

    let outcome = writer
        .repository()
        .apply_configuration(
            &current,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect("apply");
    assert_eq!(outcome.generation(), 2);
    assert_eq!(outcome.revoked_connection_count(), 0);
    assert_eq!(outcome.revoked_challenge_count(), 0);
    assert_eq!(
        format!("{outcome:?}"),
        "MycConfigApplyOutcome { generation: 2, revoked_connections: 0, revoked_challenges: 0 }"
    );
    writer.close().await.expect("close");

    let old = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_003).unwrap(),
        &build(),
    )
    .await
    .expect_err("old configuration must no longer bind");
    assert_eq!(old.kind(), MycStateHostErrorKind::Repository);

    let candidate_metadata = metadata(&runtime, &candidate);
    let writer = open_myc_state_read_write(
        &runtime,
        &candidate_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_003).unwrap(),
        &build(),
    )
    .await
    .expect("candidate startup");
    let replay = writer
        .repository()
        .apply_configuration(
            &candidate,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_004).unwrap(),
            &build(),
        )
        .await
        .expect("exact replay is an idempotent no-op");
    assert_eq!(replay.generation(), 2);
    assert_eq!(replay.revoked_connection_count(), 0);
    assert_eq!(replay.revoked_challenge_count(), 0);
    writer.close().await.expect("close candidate");

    let inspection = open_myc_state_inspection(&runtime, &candidate_metadata)
        .await
        .expect("inspection");
    let mode = inspection
        .repository()
        .apply_configuration(
            &candidate,
            &current,
            MigrationAppliedAtUnixSeconds::new(1_725_000_004).unwrap(),
            &build(),
        )
        .await
        .expect_err("inspection cannot apply");
    assert_eq!(mode.kind(), MycConfigApplyErrorKind::InvalidMode);
    inspection.close().await.expect("inspection close");

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("inspect database");
    let rows = sqlx::query(
        "SELECT generation, normalized_config_sha256 FROM myc_config_bindings ORDER BY generation",
    )
    .fetch_all(&mut connection)
    .await
    .expect("binding history");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<i64, _>(0), 1);
    assert_eq!(rows[1].get::<i64, _>(0), 2);
    assert_eq!(
        rows[0].get::<Vec<u8>, _>(1),
        current_metadata.configuration_digest().as_bytes()
    );
    assert_eq!(
        rows[1].get::<Vec<u8>, _>(1),
        candidate_metadata.configuration_digest().as_bytes()
    );
    let birth = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT normalized_config_sha256 FROM myc_state_metadata WHERE singleton = 1",
    )
    .fetch_one(&mut connection)
    .await
    .expect("birth binding");
    assert_eq!(birth, current_metadata.configuration_digest().as_bytes());
    let persisted = sqlx::query(
        "SELECT service_version, service_commit, lib_revision, rust_version, target, \
         feature_profile FROM myc_config_bindings ORDER BY generation",
    )
    .fetch_all(&mut connection)
    .await
    .expect("safe binding evidence");
    assert_eq!(persisted.len(), 2);
    let database_bytes = fs::read(runtime.artifacts().state_database()).expect("database bytes");
    for forbidden in [
        "wss://relay-primary.example.test/",
        "encrypted_file",
        "transport.key",
        directory.path().to_str().expect("UTF-8 temporary path"),
    ] {
        assert!(
            !database_bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "configuration history persisted forbidden source material"
        );
    }
    connection.close().await.expect("close database");
}

#[tokio::test]
async fn v9_upgrade_seeds_one_v10_binding_without_rewriting_birth_evidence() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize_v9(&runtime, &current_metadata).await;

    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_010).unwrap(),
        &build(),
    )
    .await
    .expect("upgrade to v10");
    writer.close().await.expect("close upgraded writer");

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("inspect upgrade");
    let birth_version = sqlx::query_scalar::<_, i64>(
        "SELECT state_contract_version FROM myc_state_metadata WHERE singleton = 1",
    )
    .fetch_one(&mut connection)
    .await
    .expect("birth version");
    assert_eq!(birth_version, 9);
    let binding = sqlx::query(
        "SELECT generation, state_contract_version, applied_at_unix_s, \
         normalized_config_sha256 FROM myc_config_bindings",
    )
    .fetch_one(&mut connection)
    .await
    .expect("seed binding");
    assert_eq!(binding.get::<i64, _>("generation"), 1);
    assert_eq!(binding.get::<i64, _>("state_contract_version"), 10);
    assert_eq!(binding.get::<i64, _>("applied_at_unix_s"), 1_725_000_010);
    assert_eq!(
        binding.get::<Vec<u8>, _>("normalized_config_sha256"),
        current_metadata.configuration_digest().as_bytes()
    );
    connection.close().await.expect("close inspection");
}

#[tokio::test]
async fn relay_change_is_blocked_by_nonterminal_work_but_safe_addition_is_admitted() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize(&runtime, &current_metadata).await;

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("database");
    sqlx::query(
        "INSERT INTO nip46_requests (operation_id, correlation_id, operation_nonce, \
         request_identity_sha256, client_public_key, request_id, first_event_id, \
         method, request_sha256, received_at_unix_ms) VALUES (?, ?, ?, ?, ?, \
         'config-lifecycle-job', ?, 'ping', ?, 1)",
    )
    .bind([0x12_u8; 32].as_slice())
    .bind([0x21_u8; 32].as_slice())
    .bind([0x22_u8; 32].as_slice())
    .bind([0x23_u8; 32].as_slice())
    .bind("7777777777777777777777777777777777777777777777777777777777777777")
    .bind([0x24_u8; 32].as_slice())
    .bind([0x25_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .expect("request source");
    sqlx::query(
        "INSERT INTO delivery_jobs (job_id, source_kind, source_id, artifact_sha256, \
         policy_mode, required_acknowledgements, max_attempts, initial_backoff_ms, \
         maximum_backoff_ms, attempt_deadline_ms, status, created_at_unix_ms, \
         updated_at_unix_ms, finalized_at_unix_ms) VALUES (?, 'signer_response', ?, ?, \
         'all_required', 1, 2, 1, 2, 2, 'pending', 1, 1, NULL)",
    )
    .bind([0x11_u8; 32].as_slice())
    .bind([0x12_u8; 32].as_slice())
    .bind([0x13_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .expect("job");
    sqlx::query(
        "INSERT INTO delivery_targets (job_id, target_index, relay_id, required, \
         attempt_count, status, active_attempt_id, next_attempt_at_unix_ms, \
         updated_at_unix_ms) VALUES (?, 0, 'primary', 1, 0, 'pending', NULL, NULL, 1)",
    )
    .bind([0x11_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .expect("target");
    connection.close().await.expect("close database");

    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect("writer");
    let changed = configuration(&CONFIG.replace(
        "wss://relay-primary.example.test/",
        "wss://relay-primary-next.example.test/",
    ));
    let conflict = writer
        .repository()
        .apply_configuration(
            &current,
            &changed,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect_err("retained job blocks relay mutation");
    assert_eq!(conflict.kind(), MycConfigApplyErrorKind::PolicyConflict);

    let authentication_changed = configuration(&CONFIG.replacen(
        "authentication = \"required\"",
        "authentication = \"disabled\"",
        1,
    ));
    let conflict = writer
        .repository()
        .apply_configuration(
            &current,
            &authentication_changed,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect_err("retained job blocks relay authentication mutation");
    assert_eq!(conflict.kind(), MycConfigApplyErrorKind::PolicyConflict);

    let addition_source = CONFIG.replace(
        "[transport]\n",
        "[[relays]]\nid = \"tertiary\"\nurl = \"wss://relay-tertiary.example.test/\"\nread = true\nwrite = true\nrequired = false\nauthentication = \"required\"\n\n[transport]\n",
    );
    let addition = configuration(&addition_source);
    let outcome = writer
        .repository()
        .apply_configuration(
            &current,
            &addition,
            MigrationAppliedAtUnixSeconds::new(1_725_000_003).unwrap(),
            &build(),
        )
        .await
        .expect("safe relay addition");
    assert_eq!(outcome.generation(), 2);
    writer.close().await.expect("close");
}

#[tokio::test]
async fn identity_change_atomically_revokes_live_connections_and_pending_challenges() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize(&runtime, &current_metadata).await;

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("database");
    for (id, status) in [(0x31_u8, "active"), (0x32_u8, "pending")] {
        sqlx::query(
            "INSERT INTO connections (connection_id, connection_nonce, client_public_key, \
             requested_permissions_sha256, policy_generation, status, created_at_unix_ms, \
             updated_at_unix_ms, authorized_until_unix_ms) VALUES (?, ?, ?, ?, 1, ?, 1, 1, ?)",
        )
        .bind([id; 32].as_slice())
        .bind([id.saturating_add(16); 32].as_slice())
        .bind("7777777777777777777777777777777777777777777777777777777777777777")
        .bind([0x41_u8; 32].as_slice())
        .bind(status)
        .bind((status == "active").then_some(10_000_i64))
        .execute(&mut connection)
        .await
        .expect("connection");
    }
    sqlx::query(
        "INSERT INTO nip46_requests (operation_id, correlation_id, operation_nonce, \
         request_identity_sha256, client_public_key, request_id, first_event_id, method, \
         request_sha256, received_at_unix_ms) VALUES (?, ?, ?, ?, ?, 'identity-change', ?, \
         'connect', ?, 1)",
    )
    .bind([0x33_u8; 32].as_slice())
    .bind([0x34_u8; 32].as_slice())
    .bind([0x35_u8; 32].as_slice())
    .bind([0x36_u8; 32].as_slice())
    .bind("7777777777777777777777777777777777777777777777777777777777777777")
    .bind([0x37_u8; 32].as_slice())
    .bind([0x38_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .expect("request");
    sqlx::query(
        "INSERT INTO connection_auth_challenges (challenge_id, challenge_nonce, \
         connection_id, operation_id, policy_generation, challenge_url, state, \
         issued_at_unix_ms, expires_at_unix_ms, resolved_at_unix_ms) \
         VALUES (?, ?, ?, ?, 1, 'https://myc.example.test/challenge', 'pending', 1, 10000, NULL)",
    )
    .bind([0x39_u8; 32].as_slice())
    .bind([0x3a_u8; 32].as_slice())
    .bind([0x31_u8; 32].as_slice())
    .bind([0x33_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .expect("challenge");
    connection.close().await.expect("close database");

    let candidate = configuration(&CONFIG.replace(
        "expected_public_key = \"2222222222222222222222222222222222222222222222222222222222222222\"",
        "expected_public_key = \"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"",
    ));
    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect("writer");
    let outcome = writer
        .repository()
        .apply_configuration(
            &current,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect("identity apply");
    assert_eq!(outcome.revoked_connection_count(), 2);
    assert_eq!(outcome.revoked_challenge_count(), 1);
    writer.close().await.expect("close writer");

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("inspect");
    let statuses =
        sqlx::query_scalar::<_, String>("SELECT status FROM connections ORDER BY connection_id")
            .fetch_all(&mut connection)
            .await
            .expect("connection statuses");
    assert_eq!(statuses, ["expired", "denied"]);
    let state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM connection_auth_challenges WHERE challenge_id = ?",
    )
    .bind([0x39_u8; 32].as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("challenge state");
    assert_eq!(state, "expired");
    connection.close().await.expect("close inspect");
}

#[tokio::test]
async fn permission_narrowing_revokes_only_connections_with_removed_grants() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize(&runtime, &current_metadata).await;

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("database");
    for (id, permission) in [(0x51_u8, "sign_event:kind:1"), (0x52_u8, "nip04_encrypt")] {
        sqlx::query(
            "INSERT INTO connections (connection_id, connection_nonce, client_public_key, \
             requested_permissions_sha256, policy_generation, status, created_at_unix_ms, \
             updated_at_unix_ms, authorized_until_unix_ms) VALUES (?, ?, ?, ?, 1, \
             'active', 1, 1, 10000)",
        )
        .bind([id; 32].as_slice())
        .bind([id.saturating_add(16); 32].as_slice())
        .bind("7777777777777777777777777777777777777777777777777777777777777777")
        .bind([id.saturating_add(32); 32].as_slice())
        .execute(&mut connection)
        .await
        .expect("connection");
        sqlx::query(
            "INSERT INTO connection_permissions (connection_id, permission_scope, \
             permission_code) VALUES (?, 'granted', ?)",
        )
        .bind([id; 32].as_slice())
        .bind(permission)
        .execute(&mut connection)
        .await
        .expect("permission");
    }
    connection.close().await.expect("close database");

    let candidate_source = CONFIG
        .replace(
            "permission_ceiling = [\"nip04_decrypt\", \"nip04_encrypt\", \"nip44_decrypt\", \"nip44_encrypt\", \"sign_event:kind:1\"]",
            "permission_ceiling = [\"nip04_decrypt\", \"nip04_encrypt\", \"nip44_decrypt\", \"nip44_encrypt\", \"sign_event:kind:2\"]",
        )
        .replace("allowed_sign_event_kinds = [1]", "allowed_sign_event_kinds = [2]");
    let candidate = configuration(&candidate_source);
    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect("writer");
    let outcome = writer
        .repository()
        .apply_configuration(
            &current,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect("narrowing apply");
    assert_eq!(outcome.revoked_connection_count(), 1);
    writer.close().await.expect("close writer");

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("inspect");
    let rows = sqlx::query("SELECT connection_id, status FROM connections ORDER BY connection_id")
        .fetch_all(&mut connection)
        .await
        .expect("statuses");
    assert_eq!(rows[0].get::<String, _>(1), "expired");
    assert_eq!(rows[1].get::<String, _>(1), "active");
    connection.close().await.expect("close inspect");
}

#[tokio::test]
async fn exact_history_capacity_fails_with_resource_exhausted_without_mutation() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    prepare(&runtime);
    let current = configuration(CONFIG);
    let current_metadata = metadata(&runtime, &current);
    initialize(&runtime, &current_metadata).await;

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("database");
    sqlx::query(
        "WITH RECURSIVE generation(value) AS (VALUES(2) UNION ALL \
         SELECT value + 1 FROM generation WHERE value < 1024) \
         INSERT INTO myc_config_bindings (generation, normalized_config_sha256, \
         transport_public_key, user_public_key, discovery_public_key, \
         config_contract_version, state_contract_version, operator_contract_version, \
         status_contract_version, applied_at_unix_s, service_version, service_commit, \
         lib_revision, rust_version, target, feature_profile, provider_contract_version) \
         SELECT generation.value, binding.normalized_config_sha256, \
         binding.transport_public_key, binding.user_public_key, binding.discovery_public_key, \
         binding.config_contract_version, binding.state_contract_version, \
         binding.operator_contract_version, binding.status_contract_version, \
         binding.applied_at_unix_s, binding.service_version, binding.service_commit, \
         binding.lib_revision, binding.rust_version, binding.target, binding.feature_profile, \
         binding.provider_contract_version FROM generation \
         CROSS JOIN myc_config_bindings AS binding WHERE binding.generation = 1",
    )
    .execute(&mut connection)
    .await
    .expect("fill bounded history");
    connection.close().await.expect("close database");

    let writer = open_myc_state_read_write(
        &runtime,
        &current_metadata,
        MigrationAppliedAtUnixSeconds::new(1_725_000_001).unwrap(),
        &build(),
    )
    .await
    .expect("writer");
    let candidate = configuration(&CONFIG.replace("level = \"info\"", "level = \"warn\""));
    let error = writer
        .repository()
        .apply_configuration(
            &current,
            &candidate,
            MigrationAppliedAtUnixSeconds::new(1_725_000_002).unwrap(),
            &build(),
        )
        .await
        .expect_err("full history");
    assert_eq!(error.kind(), MycConfigApplyErrorKind::ResourceExhausted);
    assert_eq!(error.code(), "resource_exhausted");
    assert!(Error::source(&error).is_none());
    writer.close().await.expect("close writer");

    let mut connection = sqlx::SqliteConnection::connect_with(&options(&runtime))
        .await
        .expect("inspect");
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM myc_config_bindings")
        .fetch_one(&mut connection)
        .await
        .expect("count");
    assert_eq!(count, 1024);
    connection.close().await.expect("close inspect");
}

#[test]
fn configuration_lifecycle_surface_is_sealed_and_diagnostics_are_safe() {
    assert!(LIB_SOURCE.contains("mod state_config;"));
    assert!(!LIB_SOURCE.contains("pub mod state_config;"));
    for forbidden in [
        "pub transaction:",
        "pub connection:",
        "pub pool:",
        "credential_reference",
        "envelope_path",
        "relay_url TEXT",
        "DELETE FROM myc_config_bindings",
        "UPDATE myc_config_bindings",
    ] {
        assert!(
            !CONFIG_SOURCE.contains(forbidden),
            "forbidden configuration-history surface `{forbidden}`"
        );
    }
    for kind in [
        MycConfigApplyErrorKind::InvalidMode,
        MycConfigApplyErrorKind::InvalidInput,
        MycConfigApplyErrorKind::Binding,
        MycConfigApplyErrorKind::PolicyConflict,
        MycConfigApplyErrorKind::ResourceExhausted,
        MycConfigApplyErrorKind::Transaction,
        MycConfigApplyErrorKind::CommitOutcomeUnknown,
    ] {
        let rendered = format!("{kind:?} {}", kind.code());
        for secret in ["relay-primary", "credential", "state.sqlite", "/var/lib"] {
            assert!(!rendered.contains(secret));
        }
    }
    let error = MycConfigApplyErrorKind::PolicyConflict;
    assert_eq!(error.code(), "config_apply_policy_conflict");
    let _source_free: fn(&myc::MycConfigApplyError) -> Option<&(dyn Error + 'static)> =
        Error::source;
}
