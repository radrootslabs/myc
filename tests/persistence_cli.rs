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
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity")
        .save_json(path)
        .expect("save identity");
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
fn persistence_verify_restore_cli_accepts_copied_sqlite_state() {
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
