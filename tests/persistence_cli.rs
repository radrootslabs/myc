use std::path::Path;
use std::process::Command;

use myc::{
    MycConfig, MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
    MycRuntime, MycRuntimeAuditBackend, MycSignerStateBackend,
};
use nostr::PublicKey;
use radroots_identity::RadrootsIdentity;
use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionDraft;
use serde_json::Value;

fn write_identity(path: &Path, secret_key: &str) {
    let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity");
    myc::identity_files::store_encrypted_identity(path, &identity).expect("save identity");
}

fn copy_dir_recursive(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("create copied dir");
    for entry in std::fs::read_dir(source).expect("read copied dir source") {
        let entry = entry.expect("dir entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_recursive(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).expect("copy file");
        }
    }
}

fn bootstrap_populated_json_runtime(temp: &tempfile::TempDir) -> (MycConfig, MycConfig) {
    let mut json_config = MycConfig::default();
    json_config.paths.state_dir = temp.path().join("state");
    json_config.paths.signer_identity_path = temp.path().join("signer.json");
    json_config.paths.user_identity_path = temp.path().join("user.json");

    write_identity(
        &json_config.paths.signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &json_config.paths.user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );

    let runtime = MycRuntime::bootstrap(json_config.clone()).expect("json runtime");
    let manager = runtime.signer_manager().expect("manager");
    let connection = manager
        .register_connection(RadrootsNostrSignerConnectionDraft::new(
            PublicKey::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("pubkey"),
            runtime.user_public_identity(),
        ))
        .expect("register connection");
    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        MycOperationAuditKind::ListenerResponsePublish,
        MycOperationAuditOutcome::Succeeded,
        Some(&connection.connection_id),
        Some("request-1"),
        1,
        1,
        "publish succeeded",
    ));

    let mut sqlite_config = json_config.clone();
    sqlite_config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
    sqlite_config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;

    (json_config, sqlite_config)
}

fn migrate_to_sqlite(temp: &tempfile::TempDir) -> MycConfig {
    let (_json_config, sqlite_config) = bootstrap_populated_json_runtime(temp);
    let env_path = temp.path().join("myc-sqlite.env");
    std::fs::write(
        &env_path,
        sqlite_config.to_env_string().expect("render sqlite env"),
    )
    .expect("write sqlite env");

    let output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("persistence")
        .arg("import-json-to-sqlite")
        .output()
        .expect("run import");
    assert!(output.status.success(), "{:?}", output);

    sqlite_config
}

fn write_env(path: &Path, config: &MycConfig) {
    std::fs::write(path, config.to_env_string().expect("render env")).expect("write env");
}

fn run_myc(env_path: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_myc"));
    command.arg("--env-file").arg(env_path);
    for arg in args {
        command.arg(arg);
    }
    command.output().expect("run myc")
}

#[test]
fn persistence_import_json_to_sqlite_cli_migrates_state_and_rejects_rerun() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (_json_config, sqlite_config) = bootstrap_populated_json_runtime(&temp);
    let env_path = temp.path().join("myc-sqlite.env");
    std::fs::write(
        &env_path,
        sqlite_config.to_env_string().expect("render sqlite env"),
    )
    .expect("write env");

    let output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("persistence")
        .arg("import-json-to-sqlite")
        .output()
        .expect("run import");

    assert!(output.status.success(), "{:?}", output);

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("import json");
    assert_eq!(parsed["signer_state"]["connection_count"], 1);
    assert_eq!(parsed["signer_state"]["request_audit_count"], 0);
    assert_eq!(parsed["runtime_audit"]["record_count"], 1);
    assert!(
        parsed["signer_state"]["destination_path"]
            .as_str()
            .expect("sqlite signer destination")
            .ends_with("signer-state.sqlite")
    );
    assert!(
        parsed["runtime_audit"]["destination_path"]
            .as_str()
            .expect("sqlite audit destination")
            .ends_with("operations.sqlite")
    );

    let sqlite_runtime = MycRuntime::bootstrap(sqlite_config.clone()).expect("sqlite runtime");
    assert_eq!(
        sqlite_runtime
            .signer_manager()
            .expect("sqlite manager")
            .list_connections()
            .expect("sqlite connections")
            .len(),
        1
    );
    assert_eq!(
        sqlite_runtime
            .operation_audit_store()
            .list_all()
            .expect("sqlite audit records")
            .len(),
        1
    );

    let rerun = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("persistence")
        .arg("import-json-to-sqlite")
        .output()
        .expect("rerun import");

    assert!(!rerun.status.success(), "{:?}", rerun);
    let stderr = String::from_utf8(rerun.stderr).expect("rerun stderr");
    assert!(stderr.contains("sqlite signer-state destination"));
}

#[test]
fn persistence_backup_cli_copies_sqlite_state_and_identity_files() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);
    let env_path = source.path().join("sqlite.env");
    write_env(&env_path, &sqlite_config);
    let backup_dir = source.path().join("backup");

    let output = run_myc(&env_path, &["persistence", "backup", "--out"]);
    assert!(
        !output.status.success(),
        "missing backup path should fail clap parsing"
    );

    let output = run_myc(
        &env_path,
        &[
            "persistence",
            "backup",
            "--out",
            backup_dir.to_str().expect("backup dir str"),
        ],
    );
    assert!(output.status.success(), "{:?}", output);

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("backup json");
    assert_eq!(parsed["signer_identity_reference"]["copied_file_count"], 2);
    assert_eq!(parsed["user_identity_reference"]["copied_file_count"], 2);
    assert_eq!(
        parsed["discovery_app_identity_reference"],
        Value::Null,
        "default config reuses signer identity and should not emit a dedicated discovery backup"
    );
    assert!(backup_dir.join("manifest.json").is_file());
    assert!(
        backup_dir
            .join("state")
            .join("signer-state.sqlite")
            .is_file()
    );
    assert!(
        backup_dir
            .join("state")
            .join("delivery-outbox.sqlite")
            .is_file()
    );
    assert!(
        backup_dir
            .join("state")
            .join("audit")
            .join("operations.sqlite")
            .is_file()
    );
    assert!(
        backup_dir
            .join("identity-references")
            .join("signer")
            .join("path")
            .is_file()
    );
    assert!(
        backup_dir
            .join("identity-references")
            .join("signer")
            .join("encrypted-key-path")
            .is_file()
    );
    assert!(
        backup_dir
            .join("identity-references")
            .join("user")
            .join("path")
            .is_file()
    );
    assert!(
        backup_dir
            .join("identity-references")
            .join("user")
            .join("encrypted-key-path")
            .is_file()
    );
}

#[test]
fn persistence_backup_cli_rejects_destination_inside_state_dir() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);
    let env_path = source.path().join("sqlite.env");
    write_env(&env_path, &sqlite_config);
    let nested_backup_dir = sqlite_config.paths.state_dir.join("backup");

    let output = run_myc(
        &env_path,
        &[
            "persistence",
            "backup",
            "--out",
            nested_backup_dir.to_str().expect("nested backup dir str"),
        ],
    );

    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("backup stderr");
    assert!(stderr.contains("cannot copy"));
}

#[test]
fn persistence_restore_cli_restores_backup_and_verify_restore_passes() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);
    let sqlite_env = source.path().join("sqlite.env");
    write_env(&sqlite_env, &sqlite_config);
    let backup_dir = source.path().join("backup");
    let backup = run_myc(
        &sqlite_env,
        &[
            "persistence",
            "backup",
            "--out",
            backup_dir.to_str().expect("backup dir str"),
        ],
    );
    assert!(backup.status.success(), "{:?}", backup);

    let restored = tempfile::tempdir().expect("restored tempdir");
    let restored_signer = restored.path().join("signer.json");
    let restored_user = restored.path().join("user.json");

    let mut restored_config = sqlite_config.clone();
    restored_config.paths.state_dir = restored.path().join("state");
    restored_config.paths.signer_identity_path = restored_signer;
    restored_config.paths.user_identity_path = restored_user;
    let restored_env = restored.path().join("restored.env");
    write_env(&restored_env, &restored_config);

    let restore = run_myc(
        &restored_env,
        &[
            "persistence",
            "restore",
            "--from",
            backup_dir.to_str().expect("backup dir str"),
        ],
    );
    assert!(restore.status.success(), "{:?}", restore);

    let restore_json: Value = serde_json::from_slice(&restore.stdout).expect("restore json");
    assert_eq!(
        restore_json["signer_identity_reference"]["restored_file_count"],
        2
    );
    assert_eq!(
        restore_json["user_identity_reference"]["restored_file_count"],
        2
    );
    assert!(
        restored_config
            .paths
            .state_dir
            .join("signer-state.sqlite")
            .is_file()
    );
    assert!(restored_config.paths.signer_identity_path.is_file());
    assert!(restored_config.paths.user_identity_path.is_file());
    assert!(
        myc::identity_files::encrypted_identity_wrapping_key_path(
            &restored_config.paths.signer_identity_path
        )
        .is_file()
    );
    assert!(
        myc::identity_files::encrypted_identity_wrapping_key_path(
            &restored_config.paths.user_identity_path
        )
        .is_file()
    );

    let output = run_myc(&restored_env, &["persistence", "verify-restore"]);

    assert!(output.status.success(), "{:?}", output);

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("verify restore json");
    assert_eq!(parsed["signer_state"]["backend"], "sqlite");
    assert_eq!(parsed["signer_state"]["connection_count"], 1);
    assert_eq!(parsed["runtime_audit"]["backend"], "sqlite");
    assert_eq!(parsed["runtime_audit"]["record_count"], 1);
    assert_eq!(parsed["delivery_outbox"]["queued_job_count"], 0);
    assert_eq!(parsed["delivery_outbox"]["unfinished_job_count"], 0);
    assert!(
        parsed["delivery_outbox"]["path"]
            .as_str()
            .expect("delivery outbox path")
            .ends_with("delivery-outbox.sqlite")
    );
}

#[test]
fn persistence_verify_restore_cli_rejects_missing_outbox_file() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);

    let restored = tempfile::tempdir().expect("restored tempdir");
    let restored_state_dir = restored.path().join("state");
    copy_dir_recursive(&sqlite_config.paths.state_dir, &restored_state_dir);
    let restored_signer = restored.path().join("signer.json");
    let restored_user = restored.path().join("user.json");
    std::fs::copy(&sqlite_config.paths.signer_identity_path, &restored_signer)
        .expect("copy signer identity");
    std::fs::copy(&sqlite_config.paths.user_identity_path, &restored_user)
        .expect("copy user identity");
    std::fs::remove_file(restored_state_dir.join("delivery-outbox.sqlite"))
        .expect("remove restored outbox");

    let mut restored_config = sqlite_config.clone();
    restored_config.paths.state_dir = restored_state_dir;
    restored_config.paths.signer_identity_path = restored_signer;
    restored_config.paths.user_identity_path = restored_user;
    let restored_env = restored.path().join("restored.env");
    std::fs::write(
        &restored_env,
        restored_config
            .to_env_string()
            .expect("render restored env"),
    )
    .expect("write restored env");

    let output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&restored_env)
        .arg("persistence")
        .arg("verify-restore")
        .output()
        .expect("run verify restore");

    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("verify restore stderr");
    assert!(
        stderr.contains("persistence verify-restore requires an existing delivery outbox file")
    );
}

#[test]
fn persistence_restore_cli_rejects_non_empty_destination() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);
    let sqlite_env = source.path().join("sqlite.env");
    write_env(&sqlite_env, &sqlite_config);
    let backup_dir = source.path().join("backup");
    let backup = run_myc(
        &sqlite_env,
        &[
            "persistence",
            "backup",
            "--out",
            backup_dir.to_str().expect("backup dir str"),
        ],
    );
    assert!(backup.status.success(), "{:?}", backup);

    let restored = tempfile::tempdir().expect("restored tempdir");
    let mut restored_config = sqlite_config.clone();
    restored_config.paths.state_dir = restored.path().join("state");
    restored_config.paths.signer_identity_path = restored.path().join("signer.json");
    restored_config.paths.user_identity_path = restored.path().join("user.json");
    std::fs::create_dir_all(&restored_config.paths.state_dir).expect("create restored state dir");
    std::fs::write(
        restored_config.paths.state_dir.join("existing.txt"),
        "occupied",
    )
    .expect("write occupied marker");
    let restored_env = restored.path().join("restored.env");
    write_env(&restored_env, &restored_config);

    let restore = run_myc(
        &restored_env,
        &[
            "persistence",
            "restore",
            "--from",
            backup_dir.to_str().expect("backup dir str"),
        ],
    );

    assert!(!restore.status.success(), "{:?}", restore);
    let stderr = String::from_utf8(restore.stderr).expect("restore stderr");
    assert!(stderr.contains("restore state directory"));
}

#[test]
fn persistence_verify_restore_cli_rejects_signer_identity_mismatch() {
    let source = tempfile::tempdir().expect("source tempdir");
    let sqlite_config = migrate_to_sqlite(&source);

    let restored = tempfile::tempdir().expect("restored tempdir");
    let restored_state_dir = restored.path().join("state");
    copy_dir_recursive(&sqlite_config.paths.state_dir, &restored_state_dir);
    let restored_signer = restored.path().join("other-signer.json");
    let restored_user = restored.path().join("user.json");
    write_identity(
        &restored_signer,
        "3333333333333333333333333333333333333333333333333333333333333333",
    );
    std::fs::copy(&sqlite_config.paths.user_identity_path, &restored_user)
        .expect("copy user identity");
    std::fs::copy(
        myc::identity_files::encrypted_identity_wrapping_key_path(
            &sqlite_config.paths.user_identity_path,
        ),
        myc::identity_files::encrypted_identity_wrapping_key_path(&restored_user),
    )
    .expect("copy user identity wrapping key");

    let mut restored_config = sqlite_config.clone();
    restored_config.paths.state_dir = restored_state_dir;
    restored_config.paths.signer_identity_path = restored_signer;
    restored_config.paths.user_identity_path = restored_user;
    let restored_env = restored.path().join("restored.env");
    std::fs::write(
        &restored_env,
        restored_config
            .to_env_string()
            .expect("render restored env"),
    )
    .expect("write restored env");

    let output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&restored_env)
        .arg("persistence")
        .arg("verify-restore")
        .output()
        .expect("run verify restore");

    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("verify restore stderr");
    assert!(stderr.contains("does not match persisted signer identity"));
}
