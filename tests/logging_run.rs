use radroots_identity::RadrootsIdentity;
use radroots_log::{LogFileLayout, LoggingOptions};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn write_test_identity(path: &Path, secret_key: &str) {
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity from secret")
        .save_json(path)
        .expect("write identity");
}

fn wait_for_log_contents(
    path: &Path,
    timeout: Duration,
    expected_substrings: &[&str],
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match std::fs::read_to_string(path) {
            Ok(contents)
                if !contents.trim().is_empty()
                    && expected_substrings
                        .iter()
                        .all(|substring| contents.contains(substring)) =>
            {
                return Ok(contents);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to read log file: {error}")),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "timed out waiting for non-empty log file at {}",
        path.display()
    ))
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn myc_run_writes_non_empty_dated_log_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let logs_dir = temp.path().join("logs");
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
MYC_LOGGING_OUTPUT_DIR={}\n\
MYC_LOGGING_STDOUT=false\n\
MYC_PATHS_STATE_DIR={}\n\
MYC_PATHS_SIGNER_IDENTITY_PATH={}\n\
MYC_PATHS_USER_IDENTITY_PATH={}\n\
MYC_DISCOVERY_ENABLED=false\n\
MYC_TRANSPORT_ENABLED=false\n\
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=10\n",
            logs_dir.display(),
            state_dir.display(),
            signer_path.display(),
            user_path.display(),
        ),
    )
    .expect("write env");

    let expected_log_path = LoggingOptions {
        dir: Some(logs_dir.clone()),
        file_name: "log".to_owned(),
        stdout: false,
        default_level: Some("info,myc=info".to_owned()),
        file_layout: LogFileLayout::DatedFileName,
    }
    .resolved_current_log_file_path()
    .expect("resolved current log path");

    let mut child = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--env-file")
        .arg(&env_path)
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn myc");

    let contents = match wait_for_log_contents(
        expected_log_path.as_path(),
        Duration::from_secs(5),
        &["logging initialized", "myc runtime bootstrapped"],
    ) {
        Ok(contents) => contents,
        Err(error) => {
            kill_child(&mut child);
            panic!("{error}");
        }
    };

    kill_child(&mut child);

    assert!(expected_log_path.exists());
    assert!(contents.contains("logging initialized"));
    assert!(contents.contains("myc runtime bootstrapped"));
}
