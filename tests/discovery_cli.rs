use std::fs;
use std::path::Path;
use std::process::Command;

use radroots_identity::RadrootsIdentity;
use serde_json::Value;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn write_identity(path: &Path, secret_key: &str) {
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity")
        .save_json(path)
        .expect("save identity");
}

fn write_config(
    path: &Path,
    state_dir: &Path,
    signer_identity_path: &Path,
    user_identity_path: &Path,
    app_identity_path: &Path,
) {
    let config = format!(
        r#"[service]
instance_name = "myc"

[logging]
filter = "info,myc=info"

[paths]
state_dir = "{state_dir}"
signer_identity_path = "{signer_identity_path}"
user_identity_path = "{user_identity_path}"

[audit]
default_read_limit = 200
max_active_file_bytes = 262144
max_archived_files = 8

[discovery]
enabled = true
domain = "signer.example.com"
handler_identifier = "myc"
app_identity_path = "{app_identity_path}"
public_relays = ["wss://relay.example.com"]
publish_relays = ["wss://relay.example.com"]
nostrconnect_url_template = "https://signer.example.com/connect?uri=<nostrconnect>"
nip05_output_path = "{nip05_output_path}"

[discovery.metadata]
name = "myc"
display_name = "Mycorrhiza"
about = "NIP-46 signer"
website = "https://signer.example.com"
picture = "https://signer.example.com/logo.png"

[policy]
connection_approval = "explicit_user"

[transport]
enabled = false
connect_timeout_secs = 10
relays = []
"#,
        state_dir = state_dir.display(),
        signer_identity_path = signer_identity_path.display(),
        user_identity_path = user_identity_path.display(),
        app_identity_path = app_identity_path.display(),
        nip05_output_path = state_dir.join("public/.well-known/nostr.json").display(),
    );
    fs::write(path, config).expect("write config");
}

#[test]
fn export_bundle_and_verify_bundle_work_through_the_cli() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let bundle_dir = temp.path().join("bundle");

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    write_identity(
        &app_identity_path,
        "3333333333333333333333333333333333333333333333333333333333333333",
    );
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
    );

    let export = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--config")
        .arg(&config_path)
        .arg("discovery")
        .arg("export-bundle")
        .arg("--out")
        .arg(&bundle_dir)
        .output()?;

    assert!(
        export.status.success(),
        "export-bundle failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let export_output: Value = serde_json::from_slice(&export.stdout)?;
    assert_eq!(export_output["manifest"]["domain"], "signer.example.com");
    assert!(bundle_dir.join("bundle.json").exists());
    assert!(bundle_dir.join(".well-known/nostr.json").exists());
    assert!(bundle_dir.join("nip89-handler.json").exists());

    let verify = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--config")
        .arg(&config_path)
        .arg("discovery")
        .arg("verify-bundle")
        .arg("--dir")
        .arg(&bundle_dir)
        .output()?;

    assert!(
        verify.status.success(),
        "verify-bundle failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_output: Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verify_output["manifest"]["domain"], "signer.example.com");
    assert_eq!(
        verify_output["manifest"]["nip05_relative_path"],
        ".well-known/nostr.json"
    );
    assert_eq!(
        verify_output["manifest"]["nip89_relative_path"],
        "nip89-handler.json"
    );

    Ok(())
}
