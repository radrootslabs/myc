#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/process_qualification.v1.json");
const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const PROCESS_DEADLINE: Duration = Duration::from_millis(30_000);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const PARALLEL_INSPECTIONS: usize = 8;
const SOAK_ITERATIONS: usize = 32;
const CRASH_FIXTURE_BYTES: i64 = 67_108_864;
const MAXIMUM_CAPTURED_OUTPUT_BYTES: usize = 8_192;

struct ProcessFixture {
    root: tempfile::TempDir,
    config: PathBuf,
}

impl ProcessFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("repo-local root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
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
            .args(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process
    }

    fn run(&self, command: &[&str]) -> Output {
        let child = self.command(command).spawn().expect("spawn Myc process");
        wait_bounded(child)
    }

    fn run_with_stdin(&self, command: &[&str], bytes: &[u8]) -> Output {
        let mut process = self.command(command);
        process.stdin(Stdio::piped());
        let mut child = process.spawn().expect("spawn Myc process");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write bounded stdin");
        wait_bounded(child)
    }

    fn state_directory(&self) -> PathBuf {
        self.root.path().join("data/services/myc/primary")
    }

    fn state_database(&self) -> PathBuf {
        self.state_directory().join("state.sqlite")
    }

    fn initialize(&self) {
        let initialized = self.run_with_stdin(&["config", "init"], repo_local_config().as_bytes());
        assert_success(&initialized);
        fs::create_dir_all(self.state_directory()).expect("state directory");
        fs::set_permissions(self.state_directory(), fs::Permissions::from_mode(0o700))
            .expect("secure state directory");
        assert_success(&self.run(&["state", "init"]));
    }
}

fn repo_local_config() -> String {
    CONFIG_EXAMPLE
        .replace("wss://relay-primary.example.test/", "ws://127.0.0.1:9/")
        .replace("wss://relay-secondary.example.test/", "ws://127.0.0.1:10/")
        .replace("connect_deadline_ms = 10000", "connect_deadline_ms = 100")
}

fn wait_bounded(mut child: Child) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if child.try_wait().expect("poll Myc process").is_some() {
            let output = child.wait_with_output().expect("collect Myc process");
            assert!(output.stdout.len() <= MAXIMUM_CAPTURED_OUTPUT_BYTES);
            assert!(output.stderr.len() <= MAXIMUM_CAPTURED_OUTPUT_BYTES);
            return output;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("reap timed-out Myc process");
            panic!(
                "Myc process exceeded the qualification deadline: {:?}",
                output.stderr
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_created_member(child: &mut Child, path: &Path) {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if path
            .metadata()
            .map(|metadata| metadata.is_file() && metadata.len() > 0)
            .unwrap_or(false)
        {
            return;
        }
        assert!(
            child.try_wait().expect("poll crash target").is_none(),
            "process exited before the crash boundary was observable"
        );
        assert!(
            Instant::now() < deadline,
            "crash boundary was not observed before the deadline"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn diagnostic_code(output: &Output) -> String {
    serde_json::from_slice::<Value>(&output.stderr).expect("bounded diagnostic JSON")["code"]
        .as_str()
        .expect("diagnostic code")
        .to_owned()
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(diagnostic_code(output), "success");
}

async fn inflate_database(path: &Path) {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("open qualification database");
    sqlx::query("CREATE TABLE process_qualification_padding (payload BLOB NOT NULL)")
        .execute(&mut connection)
        .await
        .expect("create temporary padding table");
    sqlx::query("INSERT INTO process_qualification_padding(payload) VALUES (zeroblob(?))")
        .bind(CRASH_FIXTURE_BYTES)
        .execute(&mut connection)
        .await
        .expect("write bounded padding");
    sqlx::query("DROP TABLE process_qualification_padding")
        .execute(&mut connection)
        .await
        .expect("remove temporary padding schema");
    connection
        .close()
        .await
        .expect("close qualification database");
    assert!(
        fs::metadata(path).expect("database metadata").len()
            >= u64::try_from(CRASH_FIXTURE_BYTES).expect("positive fixture bound")
    );
}

#[test]
fn qualification_contract_freezes_the_exact_process_and_component_corpus() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("qualification contract");
    assert_eq!(
        contract
            .as_object()
            .expect("qualification object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "actual_process_corpus",
            "binary",
            "bounds",
            "component_corpus",
            "contract_version",
            "deferred",
            "invariants",
            "schema",
            "service",
            "source_lock",
            "source_locked_shared_sqlite_corpus",
            "step",
        ])
    );
    assert_eq!(contract["schema"], "radroots.myc.process-qualification.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 161);
    assert_eq!(contract["service"], "myc");
    assert_eq!(contract["binary"], "myc");
    assert_eq!(
        contract["source_lock"],
        serde_json::json!({
            "schema": "radroots.service.source-lock.v2",
            "lib_revision": "053d0c750bf9cd683c6ea37cefe7e79617ba629f"
        })
    );
    assert_eq!(
        contract["bounds"],
        serde_json::json!({
            "process_deadline_ms": 30_000,
            "poll_interval_ms": 2,
            "parallel_inspection_processes": 8,
            "soak_iterations": 32,
            "crash_fixture_bytes": 67_108_864,
            "maximum_captured_output_bytes": 8_192
        })
    );
    assert_eq!(
        contract["actual_process_corpus"],
        serde_json::json!([
            "offline_state_and_diagnostics",
            "parallel_inspection_saturation",
            "bounded_reopen_soak",
            "backup_copy_sigkill_collision",
            "pre_marker_restore_sigkill_refusal",
            "durable_restore_recovery",
            "required_dependency_outage",
            "secret_and_path_redaction"
        ])
    );
    assert_eq!(
        contract["component_corpus"],
        serde_json::json!({
            "myc_atomicity": [
                "request_admission_is_atomic_idempotent_conflict_aware_and_restart_stable",
                "delivery_jobs_are_config_bound_idempotent_restart_safe_and_unknown_aware",
                "backup_integrity_and_offline_restore_obey_one_exact_myc_authority"
            ],
            "backlog_and_saturation": [
                "concurrent_identical_admission_creates_one_request_and_bounded_replay_evidence",
                "configured_denial_precedes_saturated_unknown_client_rate_windows",
                "challenge_creation_and_authorization_use_distinct_durable_rate_budgets"
            ],
            "recovery_and_crash": [
                "restart_recovery_is_bounded_jittered_and_idempotent",
                "terminal_unknown_is_not_relabelled_as_failure_and_sql_guards_preserve_evidence",
                "early_success_and_panic_are_fatal_and_join_their_cancelled_peer"
            ],
            "property_and_adversarial": [
                "duplicate_replay_conflict_and_distinct_relations_are_total",
                "event_object_is_closed_duplicate_free_nonnull_and_exactly_consumed",
                "exact_open_rejects_migration_history_drift_without_repair"
            ]
        })
    );
    assert_eq!(
        contract["source_locked_shared_sqlite_corpus"],
        serde_json::json!([
            "every_initialization_durability_edge_fails_once_and_rolls_back",
            "transaction_durability_edges_preserve_exact_commit_semantics",
            "backup_durability_edges_fail_once_clean_exact_stage_and_recover",
            "close_durability_edges_are_once_only_retryable_or_terminal",
            "every_marker_and_restore_durability_edge_is_wired_once",
            "sigkill_restore_boundaries_recover_exact_topologies_and_preserve_permissions"
        ])
    );
    assert_eq!(
        contract["invariants"],
        serde_json::json!({
            "actual_executable_required": true,
            "production_failpoint_surface": false,
            "test_environment_selector": false,
            "detached_test_worker": false,
            "live_database_unchanged_by_failed_backup": true,
            "orphan_restore_evidence_fails_closed": true,
            "durable_restore_evidence_reconciled_on_writable_reopen": true,
            "captured_output_bounded": true,
            "diagnostics_path_secret_free": true
        })
    );
    assert_eq!(
        contract["deferred"],
        serde_json::json!([
            "rcld_promotion",
            "parent_pin_alignment",
            "nix",
            "oci",
            "signing",
            "publication",
            "deployment"
        ])
    );
}

#[test]
fn actual_process_is_bounded_under_parallel_inspection_soak_and_outage() {
    let fixture = ProcessFixture::new();
    fixture.initialize();

    let children = (0..PARALLEL_INSPECTIONS)
        .map(|_| {
            fixture
                .command(&["state", "status"])
                .spawn()
                .expect("inspection process")
        })
        .collect::<Vec<_>>();
    for child in children {
        assert_success(&wait_bounded(child));
    }

    for iteration in 0..SOAK_ITERATIONS {
        let command = if iteration % 2 == 0 {
            &["state", "status"][..]
        } else {
            &["state", "verify"][..]
        };
        assert_success(&fixture.run(command));
    }

    let outage = fixture.run(&["run"]);
    assert_eq!(outage.status.code(), Some(3));
    assert!(outage.stdout.is_empty());
    assert_eq!(
        diagnostic_code(&outage),
        "service_or_dependency_unavailable"
    );
    let diagnostic = String::from_utf8(outage.stderr).expect("diagnostic UTF-8");
    assert!(!diagnostic.contains(fixture.root.path().to_str().expect("UTF-8 root")));
    assert!(!diagnostic.contains("relay-primary"));
}

#[tokio::test]
async fn actual_process_sigkill_boundaries_fail_closed_and_recover_exactly() {
    let fixture = ProcessFixture::new();
    fixture.initialize();
    inflate_database(&fixture.state_database()).await;
    assert_success(&fixture.run(&["state", "verify"]));

    let interrupted_bundle = fixture.root.path().join("interrupted-backup");
    let mut backup = fixture
        .command(&["state", "backup", "--operation-id", "crash-backup-01"])
        .arg("--target")
        .arg(&interrupted_bundle)
        .args(["--expected-generation", "1", "--confirm"])
        .spawn()
        .expect("spawn backup process");
    wait_for_created_member(&mut backup, &interrupted_bundle.join("state.sqlite"));
    backup.kill().expect("SIGKILL backup process");
    let backup_output = backup.wait_with_output().expect("reap backup process");
    assert!(!backup_output.status.success());
    assert_success(&fixture.run(&["state", "verify"]));
    assert!(interrupted_bundle.exists(), "crash collision evidence");
    fs::remove_dir_all(&interrupted_bundle).expect("remove owned crash fixture");

    let bundle = fixture.root.path().join("backup");
    let backup = fixture
        .command(&["state", "backup", "--operation-id", "crash-backup-02"])
        .arg("--target")
        .arg(&bundle)
        .args(["--expected-generation", "1", "--confirm"])
        .spawn()
        .expect("spawn complete backup");
    let backup_output = wait_bounded(backup);
    assert_success(&backup_output);
    let manifest_bytes = backup_output.stdout;
    let manifest_digest = hex::encode(Sha256::digest(&manifest_bytes));
    let manifest_path = fixture.root.path().join("manifest.json");
    fs::write(&manifest_path, &manifest_bytes).expect("manifest file");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
        .expect("secure manifest");

    let staged_path = fixture
        .state_directory()
        .join("state.restore-staged.sqlite");
    let mut restore = fixture
        .command(&["state", "restore"])
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--manifest-sha256")
        .arg(&manifest_digest)
        .arg("--bundle")
        .arg(&bundle)
        .args(["--maximum-state-bytes", "134217728", "--confirm"])
        .spawn()
        .expect("spawn restore process");
    wait_for_created_member(&mut restore, &staged_path);
    restore.kill().expect("SIGKILL restore process");
    let restore_output = restore.wait_with_output().expect("reap restore process");
    assert!(!restore_output.status.success());
    assert!(staged_path.exists(), "orphan stage is retained as evidence");

    let refused = fixture.run(&["state", "verify"]);
    assert_eq!(refused.status.code(), Some(4));
    assert_eq!(diagnostic_code(&refused), "state_or_identity_unavailable");
    fs::remove_file(&staged_path).expect("remove owned orphan stage fixture");
    assert_success(&fixture.run(&["state", "verify"]));

    let mut corrupted = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(fixture.state_database())
        .expect("open live database");
    corrupted
        .write_all(b"corrupt-live-database")
        .and_then(|()| corrupted.sync_all())
        .expect("persist corruption fixture");
    drop(corrupted);

    let restored = fixture
        .command(&["state", "restore"])
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--manifest-sha256")
        .arg(&manifest_digest)
        .arg("--bundle")
        .arg(&bundle)
        .args(["--maximum-state-bytes", "134217728", "--confirm"])
        .spawn()
        .expect("spawn final restore");
    assert_success(&wait_bounded(restored));
    assert!(
        fixture
            .state_directory()
            .join("state.restore-marker.v1")
            .exists()
    );
    assert!(
        fixture
            .state_directory()
            .join("state.restore-backup.sqlite")
            .exists()
    );
    assert_success(&fixture.run(&["state", "verify"]));
    for artifact in [
        "state.restore-marker.v1",
        "state.restore-marker.v1.next",
        "state.restore-staged.sqlite",
        "state.restore-backup.sqlite",
    ] {
        assert!(!fixture.state_directory().join(artifact).exists());
    }
}
