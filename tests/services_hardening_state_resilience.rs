#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    error::Error,
    fs,
    num::NonZeroU64,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use myc::{
    MYC_STATE_SCHEMA_VERSION, MycConfigProfile, MycStateHostErrorKind,
    MycStateMaintenanceErrorKind, MycStateMetadata, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, finalize_myc_state_restore, initialize_myc_state, open_myc_state_inspection,
    open_myc_state_read_write, parse_myc_cli_v1_from, parse_myc_config_v1,
    resolve_myc_runtime_context, stage_myc_state_restore, verify_myc_state_backup,
};
use radroots_service_sqlite::{
    BackupCreatedAtUnixMs, IntegrityCheckOutcome, IntegrityCheckedAtUnixMs,
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity,
};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const MAINTENANCE_SOURCE: &str = include_str!("../src/state_maintenance.rs");

fn runtime(root: &Path, instance: &str) -> myc::MycRuntimeContext {
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        instance,
        "--repo-local-root",
        root.to_str().expect("UTF-8 temporary root"),
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
        "7d7b454b4c9ed86569671993bd03ca868b676665",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        myc::MYC_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

fn recovery_paths(runtime: &myc::MycRuntimeContext) -> [PathBuf; 4] {
    let state = runtime.context().paths().state();
    [
        state.join("state.restore-staged.sqlite"),
        state.join("state.restore-backup.sqlite"),
        state.join("state.restore-marker.v1"),
        state.join("state.restore-marker.v1.next"),
    ]
}

fn directory_inventory(directory: &Path) -> Vec<String> {
    let mut entries = fs::read_dir(directory)
        .expect("state directory")
        .map(|entry| {
            entry
                .expect("state entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[tokio::test]
async fn backup_integrity_and_offline_restore_obey_one_exact_myc_authority() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "primary");
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");

    let writer = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let cancelled_bundle = directory.path().join("cancelled-backup");
    let cancelled = tokio::time::timeout(
        Duration::from_nanos(1),
        writer.capture_online_backup(
            &cancelled_bundle,
            BackupCreatedAtUnixMs::new(1_725_000_000_100).expect("capture time"),
        ),
    )
    .await;
    assert!(cancelled.is_err(), "capture future must be cancellable");
    writer
        .close()
        .await
        .expect("close drains cancelled capture cleanup");
    assert!(!cancelled_bundle.exists());

    let writer = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer reacquisition after cancelled capture");
    let cancelled_integrity = tokio::time::timeout(
        Duration::from_nanos(1),
        writer.inspect_integrity(
            IntegrityCheckedAtUnixMs::new(1_725_000_000_200).expect("inspection time"),
        ),
    )
    .await;
    assert!(
        cancelled_integrity.is_err(),
        "integrity future must be cancellable"
    );
    let report = writer
        .inspect_integrity(
            IntegrityCheckedAtUnixMs::new(1_725_000_000_201).expect("retry inspection time"),
        )
        .await
        .expect("integrity retry after cancellation");
    assert_eq!(report.sqlite(), IntegrityCheckOutcome::Verified);
    assert_eq!(report.foreign_keys(), IntegrityCheckOutcome::Verified);
    assert!(report.diagnostics().is_empty());

    let bundle = directory.path().join("backup");
    let manifest = writer
        .capture_online_backup(
            &bundle,
            BackupCreatedAtUnixMs::new(1_725_000_000_300).expect("capture time"),
        )
        .await
        .expect("online backup");
    assert_eq!(manifest.service().as_str(), "myc");
    assert_eq!(manifest.instance().as_str(), "primary");
    assert_eq!(
        manifest.state_schema_version().get(),
        MYC_STATE_SCHEMA_VERSION
    );
    assert!(!manifest.protected_material_included());
    let members = fs::read_dir(&bundle)
        .expect("backup directory")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(members, ["state.sqlite"]);
    let manifest_bytes = manifest.canonical_bytes().to_vec();
    let manifest_digest = manifest.digest();
    let maximum_state_bytes =
        NonZeroU64::new(manifest.members()[0].byte_length()).expect("nonzero captured member");
    writer.close().await.expect("writer close");

    let live_path = runtime.artifacts().state_database();
    let state_directory = runtime.context().paths().state();
    let live_bytes_before_inspection = fs::read(live_path).expect("live bytes");
    let live_modified_before_inspection = fs::metadata(live_path)
        .expect("live metadata")
        .modified()
        .expect("live modified time");
    let inventory_before_inspection = directory_inventory(state_directory);
    let inspection = open_myc_state_inspection(&runtime, &metadata)
        .await
        .expect("read-only inspection");
    let inspection_report = inspection
        .inspect_integrity(
            IntegrityCheckedAtUnixMs::new(1_725_000_000_350).expect("inspection time"),
        )
        .await
        .expect("read-only integrity inspection");
    assert_eq!(inspection_report.sqlite(), IntegrityCheckOutcome::Verified);
    assert_eq!(
        inspection_report.foreign_keys(),
        IntegrityCheckOutcome::Verified
    );
    let forbidden_bundle = directory.path().join("inspection-backup");
    let error = inspection
        .capture_online_backup(
            &forbidden_bundle,
            BackupCreatedAtUnixMs::new(1_725_000_000_400).expect("capture time"),
        )
        .await
        .expect_err("read-only capture");
    assert_eq!(error.kind(), MycStateMaintenanceErrorKind::InvalidMode);
    assert!(!forbidden_bundle.exists());

    let verified = verify_myc_state_backup(
        &manifest_bytes,
        manifest_digest,
        &bundle,
        &metadata,
        maximum_state_bytes,
    )
    .expect("verified retained backup");
    let contended = stage_myc_state_restore(&runtime, &metadata, verified)
        .await
        .expect_err("offline staging must reject a live inspection host");
    assert_eq!(contended.kind(), MycStateMaintenanceErrorKind::Authority);
    inspection.close().await.expect("inspection close");
    assert_eq!(
        fs::read(live_path).expect("live bytes after inspection"),
        live_bytes_before_inspection
    );
    assert_eq!(
        fs::metadata(live_path)
            .expect("live metadata after inspection")
            .modified()
            .expect("live modified time after inspection"),
        live_modified_before_inspection
    );
    assert_eq!(
        directory_inventory(state_directory),
        inventory_before_inspection
    );

    let verified = verify_myc_state_backup(
        &manifest_bytes,
        manifest_digest,
        &bundle,
        &metadata,
        maximum_state_bytes,
    )
    .expect("reverified backup for runtime mismatch");
    let secondary = self::runtime(directory.path(), "secondary");
    let mismatch = stage_myc_state_restore(&secondary, &metadata, verified)
        .await
        .expect_err("runtime and metadata must remain cross-bound");
    assert_eq!(
        mismatch.kind(),
        MycStateMaintenanceErrorKind::InvalidEvidence
    );
    assert!(!secondary.artifacts().state_database().exists());
    assert!(recovery_paths(&secondary).iter().all(|path| !path.exists()));

    let verified = verify_myc_state_backup(
        &manifest_bytes,
        manifest_digest,
        &bundle,
        &metadata,
        maximum_state_bytes,
    )
    .expect("reverified backup");
    assert_eq!(
        format!("{verified:?}"),
        "MycVerifiedStateBackup([redacted])"
    );
    assert_eq!(
        verified.database_metadata().state_schema_version().get(),
        MYC_STATE_SCHEMA_VERSION
    );
    let staged = stage_myc_state_restore(&runtime, &metadata, verified)
        .await
        .expect("offline staging");
    assert_eq!(format!("{staged:?}"), "MycStagedStateRestore([redacted])");
    finalize_myc_state_restore(staged)
        .await
        .expect("atomic finalization");

    let unavailable = open_myc_state_inspection(&runtime, &metadata)
        .await
        .expect_err("inspection never performs restore recovery");
    assert_eq!(unavailable.kind(), MycStateHostErrorKind::InspectionOpen);
    let recovered = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable open reconciles exact recovery evidence");
    recovered
        .repository()
        .verify_binding()
        .await
        .expect("restored Myc binding");
    recovered.close().await.expect("recovered writer close");
    for path in recovery_paths(&runtime) {
        assert!(!path.exists(), "recovery evidence must be retired");
    }
}

#[tokio::test]
async fn exact_open_rejects_migration_history_drift_without_repair() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "primary");
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("test-only offline connection");
    sqlx::query("DROP TRIGGER schema_migrations_no_delete")
        .execute(&mut connection)
        .await
        .expect("remove immutable test guard");
    sqlx::query("DELETE FROM schema_migrations WHERE version = 2")
        .execute(&mut connection)
        .await
        .expect("create invalid migration prefix");
    connection.close().await.expect("test connection close");

    let error = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect_err("migration drift must fail closed");
    assert_eq!(error.kind(), MycStateHostErrorKind::ReadWriteOpen);
    let inspection = open_myc_state_inspection(&runtime, &metadata)
        .await
        .expect_err("inspection must reject migration drift");
    assert_eq!(inspection.kind(), MycStateHostErrorKind::InspectionOpen);
}

#[test]
fn maintenance_boundary_is_sealed_source_free_and_sqlx_owned() {
    assert!(LIB_SOURCE.contains("mod state_maintenance;"));
    assert!(!LIB_SOURCE.contains("pub mod state_maintenance;"));
    assert!(HOST_SOURCE.contains(".capture_online_backup(staging_directory, created_at)"));
    assert!(HOST_SOURCE.contains(".inspect_integrity(checked_at)"));
    assert!(MAINTENANCE_SOURCE.contains("verify_backup_bundle("));
    assert!(MAINTENANCE_SOURCE.contains("stage_verified_restore("));
    assert!(MAINTENANCE_SOURCE.contains("finalize_staged_restore("));
    for forbidden in [
        "sqlx::",
        "SqliteConnection",
        "SqlitePool",
        "raw_sql",
        "BEGIN ",
        "COMMIT",
        "ROLLBACK",
        "std::fs",
        "std::env",
        "std::time",
        "provider",
        "relay",
        "tokio::spawn",
        "spawn_blocking",
    ] {
        assert!(
            !MAINTENANCE_SOURCE.contains(forbidden),
            "found forbidden maintenance authority `{forbidden}`"
        );
    }

    for kind in [
        MycStateMaintenanceErrorKind::InvalidEvidence,
        MycStateMaintenanceErrorKind::InvalidMode,
        MycStateMaintenanceErrorKind::Catalog,
        MycStateMaintenanceErrorKind::Authority,
        MycStateMaintenanceErrorKind::Open,
        MycStateMaintenanceErrorKind::Metadata,
        MycStateMaintenanceErrorKind::Migration,
        MycStateMaintenanceErrorKind::Backup,
        MycStateMaintenanceErrorKind::Restore,
        MycStateMaintenanceErrorKind::Integrity,
        MycStateMaintenanceErrorKind::Recovery,
    ] {
        assert!(!kind.code().is_empty());
    }

    let error = verify_myc_state_backup(
        b"/tmp/secret-state.sqlite",
        radroots_service_sqlite::BackupManifestSha256::from_bytes([0x11; 32]),
        Path::new("/tmp/secret-bundle"),
        &metadata(&runtime(Path::new("/tmp/secret-root"), "primary")),
        NonZeroU64::new(1).expect("limit"),
    )
    .expect_err("invalid manifest");
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("/tmp"));
    assert!(!rendered.contains("sqlite"));
}
