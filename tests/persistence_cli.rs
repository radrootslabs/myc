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
