#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, num::NonZeroU32, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_STATE_SCHEMA_VERSION, MycStateHostErrorKind, MycStateHostMode, RadrootsHostEnvironment,
    RadrootsPathResolver, RadrootsPlatform, initialize_myc_state, open_myc_state_inspection,
    open_myc_state_read_write, parse_myc_cli_v1_from, resolve_myc_runtime_context,
};
use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, ServiceDatabaseMetadata,
    ServiceSqliteApplicationId, ServiceSqlitePaths,
};
use radroots_storage::event::SourceGeneration;

const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

fn runtime(root: &Path, instance: &str) -> myc::MycRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        instance,
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

fn metadata(runtime: &myc::MycRuntimeContext) -> ServiceDatabaseMetadata {
    let paths = ServiceSqlitePaths::from_runtime_context(runtime.context()).expect("SQLite paths");
    ServiceDatabaseMetadata::new(
        &paths,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        NonZeroU32::new(MYC_STATE_SCHEMA_VERSION).expect("schema version"),
        1_725_000_000_000,
        ServiceSqliteApplicationId::new(0x4d59_4331).expect("test application ID"),
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
        1,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

#[tokio::test]
async fn initialize_is_create_new_and_both_existing_open_modes_close_explicitly() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "primary");
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let identity = metadata.identity();
    let state = runtime.artifacts().state_database();
    let lock = runtime.artifacts().state_lock();

    assert!(!state.exists());
    initialize_myc_state(&runtime, &metadata)
        .await
        .expect("create-new initialization");
    assert!(state.is_file());
    assert!(lock.is_file());
    assert_eq!(
        fs::metadata(state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(lock).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let duplicate = initialize_myc_state(&runtime, &metadata)
        .await
        .expect_err("second initialization must fail");
    assert_eq!(duplicate.kind(), MycStateHostErrorKind::Initialize);

    let (applied_at, build) = migration_evidence();
    let writer = open_myc_state_read_write(&runtime, &identity, applied_at, &build)
        .await
        .expect("existing writable state");
    assert_eq!(writer.mode(), MycStateHostMode::ReadWriteExisting);
    assert_eq!(
        format!("{writer:?}"),
        "MycStateHost { mode: ReadWriteExisting, state: \"[sealed]\" }"
    );

    let contended = open_myc_state_inspection(&runtime, &identity)
        .await
        .expect_err("inspection must not bypass active writer authority");
    assert_eq!(contended.kind(), MycStateHostErrorKind::InspectionOpen);
    writer.close().await.expect("writer close");
    writer.close().await.expect("idempotent writer close");

    let inspection = open_myc_state_inspection(&runtime, &identity)
        .await
        .expect("existing inspection state");
    assert_eq!(inspection.mode(), MycStateHostMode::ReadOnlyInspection);
    inspection.close().await.expect("inspection close");

    let writer = open_myc_state_read_write(&runtime, &identity, applied_at, &build)
        .await
        .expect("authority reacquisition after explicit close");
    writer.close().await.expect("reopened writer close");
}

#[tokio::test]
async fn missing_state_and_mismatched_evidence_fail_before_database_creation() {
    let directory = tempfile::tempdir().expect("temporary root");
    let primary = runtime(directory.path(), "primary");
    let secondary = runtime(directory.path(), "secondary");
    prepare_state_directory(&primary);
    let primary_metadata = metadata(&primary);
    let primary_identity = primary_metadata.identity();
    let (applied_at, build) = migration_evidence();

    let missing = open_myc_state_read_write(&primary, &primary_identity, applied_at, &build)
        .await
        .expect_err("missing state is never created by open");
    assert_eq!(missing.kind(), MycStateHostErrorKind::ReadWriteOpen);
    assert!(!primary.artifacts().state_database().exists());

    let mismatch = initialize_myc_state(&secondary, &primary_metadata)
        .await
        .expect_err("cross-instance metadata");
    assert_eq!(mismatch.kind(), MycStateHostErrorKind::InvalidEvidence);
    assert_eq!(mismatch.code(), "state_evidence_invalid");
    assert!(Error::source(&mismatch).is_none());
    let rendered = format!("{mismatch} {mismatch:?}");
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains("state.sqlite"));
    assert!(!secondary.artifacts().state_database().exists());
}

#[test]
fn public_lifecycle_source_is_sealed() {
    assert!(LIB_SOURCE.contains("mod state_host;"));
    assert!(!LIB_SOURCE.contains("pub mod state_host;"));
    assert!(HOST_SOURCE.contains("host: ServiceSqliteHost"));
    assert!(!HOST_SOURCE.contains("pub host:"));
    for forbidden in [
        "pub fn transaction",
        "pub async fn transaction",
        "pub fn pool",
        "pub fn connection",
        "pub fn into_inner",
        "pub fn executor",
        "MigrationDescriptor::",
        "raw_sql",
        "CREATE TABLE",
        "PRAGMA application_id",
    ] {
        assert!(
            !HOST_SOURCE.contains(forbidden),
            "found forbidden lifecycle authority `{forbidden}`"
        );
    }
}
