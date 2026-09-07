use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const STEP: u16 = 300;
const GATE_DIGEST: &str = "0293aa6fc55f8e03e0eddf11bb8d28a89272cca330854aa3fd7a68633c2850f5";
const LIB_REVISION: &str = "055096853fca95e15d0f813d33a14aca13be3881";
const NIX_SHA256: &str = "a59ab70f97f6d571642d13c7506aafec0a4275520d53daee2d8451be7c495cd1";
const NIX_VERSION_SHA256: &str = "6db806391ffaea4cdb08ade0031feac399c0cd08474b3bfde8cb33f88a36c8e1";
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

const EXACT_SOURCES: &[(&str, &str)] = &[
    (
        "Cargo.lock",
        "ccb7593a1cecf74e1caf6fafaf0ba57ac9df6b6e566d522621ef4bbb1665d42f",
    ),
    (
        "Cargo.toml",
        "77cc84e4d873036bbe429fa1bc6e3363d804f6a274b167449f68774b815d73d8",
    ),
    (
        "contracts/release/myc-artifact-contract.v3.json",
        "edde8d77b701bb6e086b928c61fc003b5c3572669d2945ee4679485f23a2bddc",
    ),
    (
        "flake.lock",
        "5d5b11622c341292f429a5f93e55f38a3506431b139720ff62f983b35bf7d55f",
    ),
    (
        "flake.nix",
        "906b1cb7176e421d6bf067e76d6da2860a4863468651e9d768bc0933a1635eb4",
    ),
    (
        "radroots.service.source-lock.v3.toml",
        "070a210d79ecd385ae4beafe1dc1b16fd374f9564afc7d224e00be462c58b732",
    ),
];

pub(crate) struct Arguments {
    pub(crate) step: u16,
    pub(crate) check_id: String,
    pub(crate) source_revision: String,
    pub(crate) source_tree: String,
    pub(crate) candidate_digest: String,
    pub(crate) platform: String,
    pub(crate) execution_request_sha256: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask must remain under tools/xtask")
        .to_path_buf()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|_| "Step 300 JSON encoding failed".to_owned())
}

fn execute(command: &mut Command, label: &str) -> Result<Output, String> {
    let output = command
        .current_dir(root())
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .map_err(|_| format!("{label} could not start"))?;
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(format!("{label} exceeded its output bound"));
    }
    Ok(output)
}

fn bounded(command: &mut Command, label: &str) -> Result<Output, String> {
    let output = execute(command, label)?;
    if !output.status.success() {
        return Err(format!("{label} failed"));
    }
    Ok(output)
}

fn rejected(command: &mut Command, label: &str) -> Result<(), String> {
    if execute(command, label)?.status.success() {
        return Err(format!("{label} unexpectedly succeeded"));
    }
    Ok(())
}

fn resolve_nix() -> Result<PathBuf, String> {
    if let Some(explicit) = env::var_os("RSHR_NIX_EXECUTABLE") {
        return fs::canonicalize(explicit)
            .map_err(|_| "Step 300 Nix client is unavailable".to_owned());
    }
    let path = env::var_os("PATH").ok_or_else(|| "Step 300 PATH is absent".to_owned())?;
    env::split_paths(&path)
        .map(|directory| directory.join("nix"))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| fs::canonicalize(candidate).ok())
        .ok_or_else(|| "Step 300 Nix client is unavailable".to_owned())
}

fn object_keys(value: &Value, label: &str) -> Result<Vec<String>, String> {
    let mut keys = value
        .as_object()
        .ok_or_else(|| format!("Step 300 {label} is not an object"))?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort_unstable();
    Ok(keys)
}

fn require_source_lock() -> Result<(), String> {
    let root = root();
    let lock_bytes = fs::read(root.join("radroots.service.source-lock.v3.toml"))
        .map_err(|_| "Step 300 source lock is unreadable".to_owned())?;
    let lock: toml::Value = toml::from_str(
        std::str::from_utf8(&lock_bytes)
            .map_err(|_| "Step 300 source lock is not UTF-8".to_owned())?,
    )
    .map_err(|_| "Step 300 source lock is invalid".to_owned())?;
    let cargo_sha = sha256(
        &fs::read(root.join("Cargo.lock"))
            .map_err(|_| "Step 300 Cargo lock is unreadable".to_owned())?,
    );
    let flake_sha = sha256(
        &fs::read(root.join("flake.lock"))
            .map_err(|_| "Step 300 flake lock is unreadable".to_owned())?,
    );
    let artifact_sha = sha256(
        &fs::read(root.join("contracts/release/myc-artifact-contract.v3.json"))
            .map_err(|_| "Step 300 artifact contract is unreadable".to_owned())?,
    );
    if lock.get("schema").and_then(toml::Value::as_str) != Some("radroots.service.source-lock.v3")
        || lock
            .get("contract_version")
            .and_then(toml::Value::as_integer)
            != Some(3)
        || lock.get("revision").and_then(toml::Value::as_str) != Some(LIB_REVISION)
        || lock.get("cargo_lock_sha256").and_then(toml::Value::as_str) != Some(&cargo_sha)
        || lock["nix"]["material"].as_str() != Some("qualified")
        || lock["nix"]["lib_revision"].as_str() != Some(LIB_REVISION)
        || lock["nix"]["public_input_lock"]["sha256"].as_str() != Some(&flake_sha)
        || lock["artifact_contract"]["sha256"].as_str() != Some(&artifact_sha)
        || lock["sqlite"]["high_level_authority"].as_str() != Some("sqlx_only")
        || lock["sqlite"]["native_linkage_count"].as_integer() != Some(1)
    {
        return Err("Step 300 source lock differs".to_owned());
    }

    let flake_lock: Value = serde_json::from_slice(
        &fs::read(root.join("flake.lock"))
            .map_err(|_| "Step 300 flake lock is unreadable".to_owned())?,
    )
    .map_err(|_| "Step 300 flake lock is invalid".to_owned())?;
    if flake_lock.pointer("/nodes/root/inputs/lib") != Some(&json!("lib"))
        || flake_lock.pointer("/nodes/lib/locked/rev") != Some(&json!(LIB_REVISION))
        || flake_lock.pointer("/nodes/lib/original/rev") != Some(&json!(LIB_REVISION))
    {
        return Err("Step 300 exact Lib input differs".to_owned());
    }
    Ok(())
}

fn require_single_sqlite() -> Result<(), String> {
    let metadata = bounded(
        Command::new("cargo").args([
            "+1.97.1",
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
        ]),
        "Step 300 Cargo metadata",
    )?;
    let value: Value = serde_json::from_slice(&metadata.stdout)
        .map_err(|_| "Step 300 Cargo metadata is invalid".to_owned())?;
    let packages = value["packages"]
        .as_array()
        .ok_or_else(|| "Step 300 Cargo package inventory is absent".to_owned())?;
    let sqlite_ids = packages
        .iter()
        .filter(|package| package["name"] == "libsqlite3-sys")
        .filter_map(|package| package["id"].as_str())
        .collect::<Vec<_>>();
    if sqlite_ids.len() != 1 || packages.iter().any(|package| package["name"] == "rusqlite") {
        return Err("Step 300 native SQLite package inventory differs".to_owned());
    }
    let nodes = value["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| "Step 300 Cargo resolve inventory is absent".to_owned())?;
    let sqlite_node = nodes
        .iter()
        .find(|node| node["id"] == sqlite_ids[0])
        .ok_or_else(|| "Step 300 SQLite resolve node is absent".to_owned())?;
    let features = sqlite_node["features"]
        .as_array()
        .ok_or_else(|| "Step 300 SQLite features are absent".to_owned())?;
    if !features.iter().any(|feature| feature == "bundled") {
        return Err("Step 300 bundled SQLite feature is absent".to_owned());
    }
    Ok(())
}

fn require_outputs(nix: &Path) -> Result<(), String> {
    let show = bounded(
        Command::new(nix).args([
            "--offline",
            "flake",
            "show",
            "--json",
            "--all-systems",
            "--no-write-lock-file",
        ]),
        "Step 300 Nix output inventory",
    )?;
    let inventory: Value = serde_json::from_slice(&show.stdout)
        .map_err(|_| "Step 300 Nix output inventory is invalid".to_owned())?;
    let systems = ["aarch64-darwin", "x86_64-linux"];
    for family in ["apps", "checks", "devShells", "packages"] {
        if object_keys(&inventory[family], family)? != systems {
            return Err(format!("Step 300 {family} systems differ"));
        }
    }
    if object_keys(&inventory["nixosModules"], "nixosModules")? != ["default"]
        || inventory.pointer("/nixosModules/default/type") != Some(&json!("nixos-module"))
    {
        return Err("Step 300 NixOS module inventory differs".to_owned());
    }
    let expected_checks = [
        "check",
        "clippy",
        "config",
        "docs",
        "fmt",
        "integration",
        "package",
        "source-lock",
        "sqlx",
        "test",
    ];
    for system in systems {
        if object_keys(&inventory["apps"][system], "apps")? != ["default", "release-acceptance"]
            || object_keys(&inventory["checks"][system], "checks")? != expected_checks
            || object_keys(&inventory["devShells"][system], "devShells")? != ["default"]
            || inventory["packages"][system]["default"]["name"] != "myc-0.1.0"
            || inventory["apps"][system]["default"]["description"] != "Run the built myc service"
        {
            return Err("Step 300 service output inventory differs".to_owned());
        }
    }
    if object_keys(&inventory["packages"]["aarch64-darwin"], "Darwin packages")? != ["default"]
        || object_keys(&inventory["packages"]["x86_64-linux"], "Linux packages")?
            != ["default", "oci"]
        || inventory["packages"]["x86_64-linux"]["oci"]["name"] != "myc.tar.gz"
    {
        return Err("Step 300 platform-specific package inventory differs".to_owned());
    }
    for system in ["x86_64-darwin", "aarch64-linux", "x86_64-windows"] {
        rejected(
            Command::new(nix).args([
                "--offline",
                "eval",
                "--raw",
                &format!(".#packages.{system}.default.name"),
            ]),
            "Step 300 excluded-system evaluation",
        )?;
    }
    rejected(
        Command::new(nix).args([
            "--offline",
            "eval",
            "--raw",
            ".#packages.aarch64-darwin.oci.name",
        ]),
        "Step 300 Darwin OCI evaluation",
    )?;
    Ok(())
}

fn require_nix() -> Result<(), String> {
    let executable = resolve_nix()?;
    if sha256(&fs::read(&executable).map_err(|_| "Step 300 Nix client is unreadable")?)
        != NIX_SHA256
    {
        return Err("Step 300 Nix client identity differs".to_owned());
    }
    let version = bounded(
        Command::new(&executable).arg("--version"),
        "Step 300 Nix version",
    )?;
    if sha256(&version.stdout) != NIX_VERSION_SHA256 {
        return Err("Step 300 Nix version differs".to_owned());
    }
    bounded(
        Command::new(&executable).args([
            "--offline",
            "flake",
            "check",
            "--all-systems",
            "--no-build",
            "--no-write-lock-file",
        ]),
        "Step 300 Nix evaluation",
    )?;
    require_outputs(&executable)
}

fn expected_contract(verifier_sha256: &str) -> Value {
    json!({
        "argv_template": [
            "cargo", "extbuild", "run", "--", "cargo", "run", "--offline", "--locked",
            "-q", "-p", "myc_xtask", "--", "rshr-step-300-gate", "--step={step}",
            "--check-id={check_id}", "--source-revision={source_revision}",
            "--source-tree={source_tree}", "--candidate-digest={candidate_digest}",
            "--platform=macos_aarch64",
            "--execution-request-sha256={execution_request_sha256}"
        ],
        "assertion_id": [format!("step_300_gate_01_{GATE_DIGEST}")],
        "check_id": format!("gate-01-{GATE_DIGEST}"),
        "environment_authority": {
            "cache_policy_id": "rshr-200-step-287-cache-policy.v1",
            "cache_policy_sha256": "3e81d178bce97b6c349dfbb00c68fd6f620ac00b1a1c8d37b12e9998f3c9eaaa",
            "cadence_policy_id": "rshr-200-step-287-cadence-policy.v1",
            "cadence_policy_sha256": "d24903df8659ee3772297c84994911efe7d21cb8b988320ddc6ddce0431892a1",
            "isolation": "extbuild_host_constrained",
            "network": "disabled",
            "network_policy_id": "none",
            "network_policy_sha256": "none",
            "resource_policy_id": "rshr-200-step-287-resource-policy.v1",
            "resource_policy_sha256": "05d3c7a89185d3c55678d97955193fce2ed92b1eee5af99083d77ea64c98d14e"
        },
        "environment_names": [
            "EXT_BUILD_CONFIG", "EXT_BUILD_MACHINE_CONFIG", "EXT_BUILD_ROOT", "HOME", "PATH",
            "RUSTUP_TOOLCHAIN", "TMPDIR"
        ],
        "gate_definition_sha256": GATE_DIGEST,
        "required_platforms": ["macos_aarch64"],
        "required_tools": ["rustc"],
        "result_schema": "radroots.services-hardening.rshr-200-step-check-result.v1",
        "schema": "radroots.services-hardening.rshr-200-step-check-command.v1",
        "step": STEP,
        "verifier_path": "tools/xtask/src/rshr_202_step_300_gate.rs",
        "verifier_sha256": verifier_sha256
    })
}

pub(crate) fn run(arguments: Arguments) -> Result<(), String> {
    let check_id = format!("gate-01-{GATE_DIGEST}");
    if arguments.step != STEP
        || arguments.check_id != check_id
        || arguments.candidate_digest != "none"
        || arguments.platform != "macos_aarch64"
        || arguments.source_revision.len() != 40
        || arguments.source_tree.len() != 40
        || arguments.execution_request_sha256.len() != 64
        || !arguments
            .source_revision
            .bytes()
            .chain(arguments.source_tree.bytes())
            .chain(arguments.execution_request_sha256.bytes())
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Step 300 gate arguments differ".to_owned());
    }
    let root = root();
    if root.join(".github").exists() || root.join("radroots.service.source-lock.v2.toml").exists() {
        return Err("Step 300 forbidden legacy surface is present".to_owned());
    }
    for (relative, expected) in EXACT_SOURCES {
        let bytes = fs::read(root.join(relative))
            .map_err(|_| "Step 300 governed source is unreadable".to_owned())?;
        if sha256(&bytes) != *expected {
            return Err("Step 300 governed source bytes differ".to_owned());
        }
    }
    let flake_source = fs::read_to_string(root.join("flake.nix"))
        .map_err(|_| "Step 300 flake source is unreadable".to_owned())?;
    for forbidden in [
        "pkgs.clang",
        "libclang",
        "libsodium",
        "pkgs.openssl",
        "pkgs.pkg-config",
        "pkgs.sqlite",
    ] {
        if flake_source.contains(forbidden) {
            return Err("Step 300 forbidden native dependency is present".to_owned());
        }
    }

    let verifier_path = root.join("tools/xtask/src/rshr_202_step_300_gate.rs");
    let verifier_sha256 =
        sha256(&fs::read(verifier_path).map_err(|_| "Step 300 verifier is unreadable")?);
    let authority_path = root.join("contracts/rshr-202-step-300-gates.v1.json");
    let authority_bytes =
        fs::read(authority_path).map_err(|_| "Step 300 gate authority is unreadable")?;
    let authority: Value = serde_json::from_slice(&authority_bytes)
        .map_err(|_| "Step 300 gate authority is invalid".to_owned())?;
    let mut canonical_authority = canonical(&authority)?;
    canonical_authority.push(b'\n');
    let contracts = authority
        .get("gate_command_contract")
        .and_then(Value::as_array)
        .ok_or_else(|| "Step 300 gate contract is absent".to_owned())?;
    if authority_bytes != canonical_authority
        || authority.get("schema")
            != Some(&Value::String(
                "radroots.myc.rshr-202-step-300-gates.v1".to_owned(),
            ))
        || authority.get("step") != Some(&json!([STEP]))
        || contracts.as_slice() != [expected_contract(&verifier_sha256)]
    {
        return Err("Step 300 gate authority differs".to_owned());
    }

    require_source_lock()?;
    bounded(
        Command::new("cargo").args(["+1.97.1", "fmt", "--all", "--", "--check"]),
        "Step 300 formatting",
    )?;
    bounded(
        Command::new("cargo").args([
            "+1.97.1",
            "check",
            "--offline",
            "--locked",
            "--workspace",
            "--all-targets",
        ]),
        "Step 300 Cargo check",
    )?;
    require_single_sqlite()?;
    require_nix()?;

    let contract = &contracts[0];
    let assertion = json!([{
        "id": format!("step_300_gate_01_{GATE_DIGEST}"),
        "result": "pass"
    }]);
    let result = json!({
        "schema": "radroots.services-hardening.rshr-200-step-check-result.v1",
        "step": STEP,
        "check_id": check_id,
        "gate_definition_sha256": GATE_DIGEST,
        "source_revision": arguments.source_revision,
        "source_tree": arguments.source_tree,
        "candidate_generation": 0,
        "candidate_digest": "none",
        "command_contract_sha256": sha256(&canonical(contract)?),
        "verifier_sha256": verifier_sha256,
        "execution_request": [{
            "platform": arguments.platform,
            "sha256": arguments.execution_request_sha256
        }],
        "assertion_inventory_sha256": sha256(&canonical(&assertion)?),
        "assertion": assertion,
        "result": "pass"
    });
    let mut bytes = canonical(&result)?;
    bytes.push(b'\n');
    std::io::Write::write_all(&mut std::io::stdout().lock(), &bytes)
        .map_err(|_| "Step 300 result write failed".to_owned())
}
