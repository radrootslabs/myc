use std::path::Path;
use std::process::Command;

use myc::{
    MycActiveIdentity, MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycOperationAuditKind,
    MycOperationAuditOutcome, MycOperationAuditRecord, MycRuntime,
};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{RadrootsNostrEventBuilder, RadrootsNostrKind};
use serde_json::Value;

fn write_test_identity(path: &Path, secret_key: &str) {
    let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity from secret");
    myc::identity_storage::store_encrypted_identity(path, &identity).expect("write identity");
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

fn signed_event(identity: &MycActiveIdentity) -> nostr::Event {
    identity
        .sign_event_builder(
            RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "operability"),
            "operability test event",
        )
        .expect("sign event")
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
    assert_eq!(value["custody"]["signer"]["backend"], "encrypted_file");
    assert_eq!(value["custody"]["signer"]["resolved"], true);
    assert_eq!(value["persistence"]["signer_state"]["backend"], "json_file");
    assert_eq!(
        value["persistence"]["runtime_audit"]["backend"],
        "jsonl_file"
    );
    assert_eq!(value["delivery_outbox"]["status"], "healthy");
    assert_eq!(value["delivery_outbox"]["ready"], true);
    assert_eq!(value["delivery_outbox"]["total_job_count"], 0);
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
    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        MycOperationAuditKind::DeliveryRecovery,
        MycOperationAuditOutcome::Succeeded,
        None,
        None,
        1,
        1,
        "recovered 1/1 delivery outbox job(s); republished 1",
    ));
    let outbox_record = MycDeliveryOutboxRecord::new(
        MycDeliveryOutboxKind::DiscoveryHandlerPublish,
        signed_event(runtime.signer_identity()),
        vec!["wss://relay.example.com".parse().expect("relay url")],
    )
    .expect("outbox record");
    runtime
        .delivery_outbox_store()
        .enqueue(&outbox_record)
        .expect("enqueue outbox record");

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
    assert_eq!(json_value["delivery_recovery_success_count"], 1);
    assert_eq!(json_value["delivery_outbox_total"], 1);
    assert_eq!(json_value["delivery_outbox_queued_count"], 1);

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
    assert!(rendered.contains("myc_delivery_recovery_success_total 1"));
    assert!(rendered.contains("myc_delivery_outbox_total 1"));
    assert!(rendered.contains("myc_signer_request_total 0"));
}
