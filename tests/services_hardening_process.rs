#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

struct ProcessFixture {
    root: tempfile::TempDir,
    config: PathBuf,
}

impl ProcessFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("repo-local root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure repo-local root");
        let config = root.path().join("myc.toml");
        Self { root, config }
    }

    fn command(&self, command: &[&str]) -> Command {
        let mut process = Command::new(env!("CARGO_BIN_EXE_myc"));
        process
            .args(["--profile", "repo-local", "--instance", "primary"])
            .arg("--repo-local-root")
            .arg(self.root.path())
            .arg("--config")
            .arg(&self.config)
            .args(command);
        process
    }

    fn run(&self, command: &[&str]) -> Output {
        self.command(command).output().expect("Myc process")
    }

    fn run_with_stdin(&self, command: &[&str], bytes: &[u8]) -> Output {
        let mut child = self
            .command(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Myc process");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
        child.wait_with_output().expect("process result")
    }

    fn state_directory(&self) -> PathBuf {
        self.root.path().join("data/services/myc/primary")
    }
}

fn repo_local_config() -> String {
    CONFIG_EXAMPLE
        .replace("wss://relay-primary.example.test/", "ws://127.0.0.1:9/")
        .replace("wss://relay-secondary.example.test/", "ws://127.0.0.1:10/")
        .replace("connect_deadline_ms = 10000", "connect_deadline_ms = 100")
}

fn stderr_code(output: &Output) -> String {
    let value: serde_json::Value = serde_json::from_slice(&output.stderr).expect("diagnostic JSON");
    value["code"].as_str().expect("diagnostic code").to_owned()
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(stderr_code(output), "success");
}

#[test]
fn binary_executes_config_state_backup_restore_and_doctor_boundaries() {
    let fixture = ProcessFixture::new();
    let config = repo_local_config();

    let initialized = fixture.run_with_stdin(&["config", "init"], config.as_bytes());
    assert_success(&initialized);
    assert_eq!(initialized.stdout, b"config_initialized\n");
    assert_eq!(
        std::fs::metadata(&fixture.config)
            .expect("config metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    std::fs::create_dir_all(fixture.state_directory()).expect("provisioned state directory");
    std::fs::set_permissions(
        fixture.state_directory(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("secure state directory");

    for (command, result) in [
        (&["config", "validate"][..], b"config_valid\n".as_slice()),
        (&["state", "init"][..], b"state_initialized\n".as_slice()),
        (&["state", "verify"][..], b"state_verified\n".as_slice()),
        (&["state", "migrate"][..], b"state_migrated\n".as_slice()),
    ] {
        let output = fixture.run(command);
        assert_eq!(
            output.status.code(),
            Some(0),
            "command {command:?}, stderr: {:?}",
            output.stderr
        );
        assert_success(&output);
        assert_eq!(output.stdout, result);
    }

    let shown = fixture.run(&["--output", "json", "config", "show"]);
    assert_success(&shown);
    let shown_value: serde_json::Value =
        serde_json::from_slice(&shown.stdout).expect("effective configuration JSON");
    assert_eq!(shown_value["schema"], "radroots.myc.effective-config");

    let schema = fixture.run(&["config", "schema"]);
    assert_success(&schema);
    let schema_value: serde_json::Value =
        serde_json::from_slice(&schema.stdout).expect("configuration schema JSON");
    assert_eq!(
        schema_value["$id"],
        "https://github.com/radrootslabs/myc/contracts/services_hardening/config.v1.schema.json"
    );

    let status = fixture.run(&["state", "status"]);
    assert_success(&status);
    let status_value: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("state status JSON");
    assert_eq!(status_value["generation"], 1);
    assert_eq!(status_value["schema_version"], 11);
    assert_eq!(status_value["integrity"], "verified");

    let bundle = fixture.root.path().join("backup");
    let backup = fixture
        .command(&["state", "backup", "--operation-id", "process-backup-01"])
        .arg("--target")
        .arg(&bundle)
        .args(["--expected-generation", "1", "--confirm"])
        .output()
        .expect("backup process");
    assert_success(&backup);
    assert!(!backup.stdout.ends_with(b"\n"));
    let manifest_bytes = backup.stdout.as_slice();
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest_bytes).expect("backup manifest");
    assert_eq!(manifest["service"], "myc");
    assert_eq!(manifest["instance"], "primary");
    let digest = hex::encode(Sha256::digest(manifest_bytes));
    let manifest_path = fixture.root.path().join("manifest.json");
    std::fs::write(&manifest_path, manifest_bytes).expect("manifest file");
    std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure manifest");

    let live_database = fixture.state_directory().join("state.sqlite");
    let mut corrupted = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&live_database)
        .expect("open live database for corruption fixture");
    corrupted
        .write_all(b"corrupt-live-database")
        .and_then(|()| corrupted.sync_all())
        .expect("persist corrupt live database fixture");
    drop(corrupted);

    let restored = fixture
        .command(&["state", "restore"])
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--manifest-sha256")
        .arg(&digest)
        .arg("--bundle")
        .arg(&bundle)
        .args(["--maximum-state-bytes", "16777216", "--confirm"])
        .output()
        .expect("restore process");
    assert_success(&restored);
    assert_eq!(restored.stdout, b"state_restore_finalized\n");

    let verified_after_restore = fixture.run(&["state", "verify"]);
    assert_success(&verified_after_restore);
    for artifact in [
        "state.restore-marker.v1",
        "state.restore-marker.v1.next",
        "state.restore-staged.sqlite",
        "state.restore-backup.sqlite",
    ] {
        assert!(!fixture.state_directory().join(artifact).exists());
    }

    let doctor = fixture.run(&["doctor"]);
    assert_eq!(doctor.status.code(), Some(6));
    assert_eq!(stderr_code(&doctor), "doctor_required_check_failed");
    let doctor_value: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor report JSON");
    assert_eq!(doctor_value["checks"].as_array().expect("checks").len(), 13);
    assert_eq!(doctor_value["checks"][12]["status"], "skipped");

    let run = fixture.run(&["run"]);
    assert_eq!(run.status.code(), Some(3));
    assert!(run.stdout.is_empty());
    assert_eq!(stderr_code(&run), "service_or_dependency_unavailable");
}

#[test]
fn binary_rejects_insecure_or_oversized_selected_documents_without_disclosure() {
    let fixture = ProcessFixture::new();
    std::fs::write(&fixture.config, repo_local_config()).expect("config");
    std::fs::set_permissions(&fixture.config, std::fs::Permissions::from_mode(0o620))
        .expect("insecure config mode");

    let insecure = fixture.run(&["config", "validate"]);
    assert_eq!(insecure.status.code(), Some(2));
    assert!(insecure.stdout.is_empty());
    assert_eq!(stderr_code(&insecure), "input_or_configuration");
    let rendered = String::from_utf8(insecure.stderr).expect("diagnostic text");
    assert!(!rendered.contains(fixture.config.to_str().expect("UTF-8 path")));

    std::fs::set_permissions(&fixture.config, std::fs::Permissions::from_mode(0o600))
        .expect("secure config mode");
    std::fs::write(
        &fixture.config,
        vec![b'x'; myc::MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES + 1],
    )
    .expect("oversized config");
    let oversized = fixture.run(&["config", "validate"]);
    assert_eq!(oversized.status.code(), Some(2));
    assert!(oversized.stdout.is_empty());
    assert_eq!(stderr_code(&oversized), "input_or_configuration");
}
