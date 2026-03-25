use std::path::Path;
use std::process::Command;

use myc::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord, MycRuntime};
use radroots_identity::RadrootsIdentity;
use serde_json::Value;

fn write_test_identity(path: &Path, secret_key: &str) {
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity from secret")
        .save_json(path)
        .expect("write identity");
}

fn write_env_file(temp: &tempfile::TempDir) -> std::path::PathBuf {
    let state_dir = temp.path().join("state");
    let signer_path = temp.path().join("signer.json");
    let user_path = temp.path().join("user.json");
    let env_path = temp.path().join("myc.env");

    write_test_identity(
        signer_path.as_path(),
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_test_identity(
        user_path.as_path(),
        "2222222222222222222222222222222222222222222222222222222222222222",
    );

    std::fs::write(
        &env_path,
        format!(
            "MYC_SERVICE_INSTANCE_NAME=myc-test\n\
MYC_LOGGING_FILTER=info,myc=info\n\
MYC_LOGGING_STDOUT=false\n\
MYC_PATHS_STATE_DIR={}\n\
MYC_PATHS_SIGNER_IDENTITY_PATH={}\n\
MYC_PATHS_USER_IDENTITY_PATH={}\n\
MYC_DISCOVERY_ENABLED=false\n\
MYC_TRANSPORT_ENABLED=false\n\
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=1\n",
            state_dir.display(),
            signer_path.display(),
            user_path.display(),
        ),
    )
    .expect("write env");

    env_path
}

#[test]
fn status_summary_command_emits_machine_readable_json() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_path = write_env_file(&temp);

    let output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("status")
        .arg("--view")
        .arg("summary")
        .output()
        .expect("run myc status");

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("status json");
    assert_eq!(value["status"], "unready");
    assert_eq!(value["ready"], false);
    assert_eq!(value["custody"]["signer"]["backend"], "filesystem");
    assert_eq!(value["custody"]["signer"]["resolved"], true);
    assert_eq!(value["transport"]["enabled"], false);
}

#[test]
fn metrics_command_emits_json_and_prometheus_formats() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_path = write_env_file(&temp);
    let config = myc::MycConfig::load_from_env_path(&env_path).expect("load config");
    let runtime = MycRuntime::bootstrap(config).expect("runtime");
    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        MycOperationAuditKind::AuthReplayRestore,
        MycOperationAuditOutcome::Restored,
        None,
        None,
        1,
        0,
        "restored pending request after failed replay publish",
    ));

    let json_output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("metrics")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run myc metrics json");
    assert!(json_output.status.success());
    let json_value: Value = serde_json::from_slice(&json_output.stdout).expect("metrics json");
    assert_eq!(json_value["runtime_replay_restore_count"], 1);

    let prometheus_output = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("metrics")
        .arg("--format")
        .arg("prometheus")
        .output()
        .expect("run myc metrics prometheus");
    assert!(prometheus_output.status.success());
    let rendered = String::from_utf8(prometheus_output.stdout).expect("utf8 metrics");
    assert!(rendered.contains("myc_runtime_replay_restore_total 1"));
    assert!(rendered.contains("myc_signer_request_total 0"));
}
