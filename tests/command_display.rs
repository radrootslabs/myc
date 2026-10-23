#![forbid(unsafe_code)]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn output(command: &mut Command, directory: &Path) -> Output {
    let mut child = command
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("command-display process exceeded its ten-second deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stdout.len() <= 16 * 1024 && output.stderr.len() <= 16 * 1024);
    output
}

#[test]
fn declared_help_succeeds_without_bootstrap_or_created_state() {
    for arguments in [
        vec!["--help"],
        vec!["config", "--help"],
        vec!["state", "restore", "--help"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let output = output(
            Command::new(env!("CARGO_BIN_EXE_myc"))
                .arg("--config")
                .arg(root.path().join("absent.toml"))
                .args(&arguments),
            root.path(),
        );
        assert!(output.status.success(), "{arguments:?}");
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("absent.toml"));
        assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
    }
}

#[test]
fn help_is_bounded_static_and_diagnostics_remain_redacted() {
    let error = myc::parse_myc_cli_v1_from([
        "caller-private-program",
        "--instance",
        "caller-private-instance",
        "--config",
        "/caller-private-path.toml",
        "state",
        "restore",
        "--help",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), myc::MycCliV1ErrorKind::HelpRequested);
    let help = error.help_text().unwrap();
    assert!(help.len() <= 16 * 1024 && help.contains("myc state restore"));
    assert!(!help.contains("caller-private"));
    assert!(!format!("{error} {error:?}").contains("Usage:"));
    let malformed =
        myc::parse_myc_cli_v1_from(["caller-private-program", "--caller-private-invalid"])
            .unwrap_err();
    assert_eq!(malformed.kind(), myc::MycCliV1ErrorKind::InvalidArguments);
    assert!(malformed.help_text().is_none());
    assert!(!format!("{malformed} {malformed:?}").contains("caller-private"));
}

#[test]
fn malformed_arguments_keep_the_exact_redacted_process_result() {
    let root = tempfile::tempdir().unwrap();
    let output = output(
        Command::new(env!("CARGO_BIN_EXE_myc")).arg("--caller-private-invalid"),
        root.path(),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"{\"schema\":\"radroots.myc.log.v1\",\"contract_version\":1,\"service\":\"myc\",\"level\":\"error\",\"event\":\"process_result\",\"code\":\"input_or_configuration\",\"exit_code\":2}\n");
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}
