#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_STATE_SCHEMA_VERSION, MycConfigProfile, MycStateHostErrorKind, MycStateMetadata,
    MycStateRepositoryErrorKind, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    initialize_myc_state, open_myc_state_inspection, open_myc_state_read_write,
    parse_myc_cli_v1_from, parse_myc_config_v1, resolve_myc_runtime_context,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, Row, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const REPOSITORY_SOURCE: &str = include_str!("../src/state_repository.rs");

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
        "7d7b454b4c9ed86569671993bd03ca868b676665",
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

#[tokio::test]
async fn initialization_migrates_and_binds_exact_metadata_before_inspection() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime, CONFIG_EXAMPLE);
    let (applied_at, build) = migration_evidence();

    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialized current state");
    let inspection = open_myc_state_inspection(&runtime, &metadata)
        .await
        .expect("current inspection");
    inspection
        .repository()
        .verify_binding()
        .await
        .expect("typed repository verification");
    assert_eq!(
        format!("{:?}", inspection.repository()),
        "MycStateRepository { state: \"[sealed]\" }"
    );
    inspection.close().await.expect("inspection close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .read_only(true)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("test inspection connection");
    let row = sqlx::query(
        "SELECT state_schema_version FROM radroots_service_metadata WHERE singleton = 1",
    )
    .fetch_one(&mut connection)
    .await
    .expect("shared metadata row");
    assert_eq!(row.get::<i64, _>(0), i64::from(MYC_STATE_SCHEMA_VERSION));
    let migrations = sqlx::query("SELECT version, name FROM schema_migrations ORDER BY version")
        .fetch_all(&mut connection)
        .await
        .expect("migration rows");
    assert_eq!(migrations.len(), 10);
    assert_eq!(migrations[0].get::<i64, _>(0), 2);
    assert_eq!(
        migrations[0].get::<String, _>(1),
        "create_myc_state_metadata"
    );
    assert_eq!(migrations[1].get::<i64, _>(0), 3);
    assert_eq!(
        migrations[1].get::<String, _>(1),
        "create_nip46_request_admission"
    );
    assert_eq!(migrations[2].get::<i64, _>(0), 4);
    assert_eq!(
        migrations[2].get::<String, _>(1),
        "create_connection_authorization_state"
    );
    assert_eq!(migrations[3].get::<i64, _>(0), 5);
    assert_eq!(
        migrations[3].get::<String, _>(1),
        "create_bounded_governance_state"
    );
    assert_eq!(migrations[4].get::<i64, _>(0), 6);
    assert_eq!(
        migrations[4].get::<String, _>(1),
        "create_delivery_evidence_state"
    );
    assert_eq!(migrations[5].get::<i64, _>(0), 7);
    assert_eq!(
        migrations[5].get::<String, _>(1),
        "create_discovery_desired_state"
    );
    assert_eq!(migrations[6].get::<i64, _>(0), 8);
    assert_eq!(
        migrations[6].get::<String, _>(1),
        "create_nip46_operation_completion"
    );
    assert_eq!(migrations[7].get::<i64, _>(0), 9);
    assert_eq!(
        migrations[7].get::<String, _>(1),
        "create_nip46_atomic_response"
    );
    assert_eq!(migrations[8].get::<i64, _>(0), 10);
    assert_eq!(
        migrations[8].get::<String, _>(1),
        "create_configuration_binding_history"
    );
    assert_eq!(migrations[9].get::<i64, _>(0), 11);
    assert_eq!(
        migrations[9].get::<String, _>(1),
        "create_admin_operation_journal"
    );
    let binding = sqlx::query(
        "SELECT normalized_config_sha256, transport_public_key, user_public_key, \
         discovery_public_key, config_contract_version, state_contract_version, \
         operator_contract_version, status_contract_version \
         FROM myc_state_metadata WHERE singleton = 1",
    )
    .fetch_one(&mut connection)
    .await
    .expect("Myc metadata row");
    assert_eq!(
        binding.get::<Vec<u8>, _>(0),
        metadata.configuration_digest().as_bytes()
    );
    assert_eq!(
        binding.get::<String, _>(1),
        metadata.expected_identities().transport().as_hex()
    );
    assert_eq!(
        binding.get::<String, _>(2),
        metadata.expected_identities().user().as_hex()
    );
    assert_eq!(
        binding.get::<String, _>(3),
        metadata
            .expected_identities()
            .discovery()
            .expect("discovery identity")
            .as_hex()
    );
    assert_eq!(binding.get::<i64, _>(4), 1);
    assert_eq!(
        binding.get::<i64, _>(5),
        i64::from(MYC_STATE_SCHEMA_VERSION)
    );
    assert_eq!(binding.get::<i64, _>(6), 1);
    assert_eq!(binding.get::<i64, _>(7), 1);
    connection.close().await.expect("test connection close");
}

#[tokio::test]
async fn exact_binding_is_idempotent_and_conflicting_configuration_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let expected = metadata(&runtime, CONFIG_EXAMPLE);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &expected, applied_at, &build)
        .await
        .expect("initialization");

    let writer = open_myc_state_read_write(&runtime, &expected, applied_at, &build)
        .await
        .expect("idempotent exact open");
    writer
        .repository()
        .verify_binding()
        .await
        .expect("exact binding");
    writer.close().await.expect("writer close");

    let changed_source = String::from_utf8(CONFIG_EXAMPLE.to_vec())
        .expect("UTF-8 config")
        .replace("level = \"info\"", "level = \"warn\"");
    let changed = metadata(&runtime, changed_source.as_bytes());
    let error = open_myc_state_read_write(&runtime, &changed, applied_at, &build)
        .await
        .expect_err("changed normalized binding");
    assert_eq!(error.kind(), MycStateHostErrorKind::Repository);

    let inspection = open_myc_state_inspection(&runtime, &expected)
        .await
        .expect("original binding remains authoritative");
    inspection.close().await.expect("inspection close");
}

#[tokio::test]
async fn database_guards_reject_metadata_update_and_delete() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime, CONFIG_EXAMPLE);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("test connection");
    assert!(
        sqlx::query("UPDATE myc_state_metadata SET status_contract_version = 2")
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM myc_state_metadata")
            .execute(&mut connection)
            .await
            .is_err()
    );
    connection.close().await.expect("test connection close");
}

#[tokio::test]
async fn repository_boundary_is_sealed_typed_redacted_and_network_free() {
    assert!(LIB_SOURCE.contains("mod state_repository;"));
    assert!(!LIB_SOURCE.contains("pub mod state_repository;"));
    assert!(HOST_SOURCE.contains("pub const fn repository(&self) -> MycStateRepository<'_>"));
    assert!(REPOSITORY_SOURCE.contains(".transaction(move |transaction|"));
    assert!(REPOSITORY_SOURCE.contains("INSERT INTO myc_state_metadata"));
    for forbidden in [
        "SqliteConnection",
        "SqlitePool",
        "PoolConnection",
        "BEGIN ",
        "COMMIT",
        "ROLLBACK",
        "MycProvider",
        "provider_credential",
        "provider_envelope",
        "relay",
        "reqwest",
        "nostr::",
        "std::fs",
        "std::path",
        "std::env",
        "std::time",
    ] {
        assert!(
            !REPOSITORY_SOURCE.contains(forbidden),
            "found forbidden repository authority `{forbidden}`"
        );
    }

    let kind = myc::MycStateRepositoryErrorKind::Binding;
    assert_eq!(kind.code(), "state_repository_binding_invalid");
    let rendered = format!("{kind:?}");
    assert!(!rendered.contains("state.sqlite"));

    let directory = tempfile::tempdir().expect("temporary root");
    let context = runtime(directory.path());
    prepare_state_directory(&context);
    let metadata = metadata(&context, CONFIG_EXAMPLE);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&context, &metadata, applied_at, &build)
        .await
        .expect("initialization");
    let inspection = open_myc_state_inspection(&context, &metadata)
        .await
        .expect("inspection");
    inspection.close().await.expect("inspection close");
    let error = inspection
        .repository()
        .verify_binding()
        .await
        .expect_err("closed host rejects repository admission");
    assert_eq!(error.kind(), MycStateRepositoryErrorKind::Transaction);
    assert!(Error::source(&error).is_none());
    assert!(!format!("{error} {error:?}").contains("secret"));
}
