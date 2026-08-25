#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/systemd_qualification.v1.json");
const UNIT: &str = include_str!("../packaging/systemd/myc@.service");
const VERIFY_SCRIPT: &str = include_str!("../scripts/verify-systemd.sh");

fn contract() -> Value {
    serde_json::from_str(CONTRACT).expect("systemd qualification contract")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_unit(source: &str, authority: &Value) -> Result<(), String> {
    if source.len() > 16_384 || !source.ends_with('\n') || source.contains(['\0', '\r']) {
        return Err("invalid unit bytes".to_owned());
    }

    let expected = authority["canonical_lines"]
        .as_array()
        .ok_or_else(|| "missing canonical lines".to_owned())?
        .iter()
        .map(|line| {
            line.as_str()
                .ok_or_else(|| "invalid canonical line".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actual = source
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    let forbidden = authority["forbidden_directives"]
        .as_array()
        .ok_or_else(|| "missing forbidden directives".to_owned())?
        .iter()
        .map(|directive| {
            directive
                .as_str()
                .ok_or_else(|| "invalid forbidden directive".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut section = "";
    let mut sections = Vec::new();
    let mut keys = BTreeSet::new();
    for line in &actual {
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            sections.push(section);
            continue;
        }
        let (key, _) = line
            .split_once('=')
            .ok_or_else(|| "invalid directive".to_owned())?;
        if section.is_empty() || forbidden.contains(key) {
            return Err("forbidden or unscoped directive".to_owned());
        }
        if !keys.insert(format!("{section}.{key}")) {
            return Err("duplicate directive".to_owned());
        }
    }
    if sections != ["Unit", "Service", "Install"] || actual != expected {
        return Err("unit differs from canonical contract".to_owned());
    }
    Ok(())
}

#[test]
fn systemd_contract_binds_the_exact_fail_closed_unit() {
    let authority = contract();
    assert_eq!(authority["schema"], "radroots.myc.systemd-qualification");
    assert_eq!(authority["schema_version"], 1);
    assert_eq!(authority["service"], "myc");
    assert_eq!(authority["unit_path"], "packaging/systemd/myc@.service");
    assert_eq!(
        authority["verification_script"],
        "scripts/verify-systemd.sh"
    );
    assert_eq!(authority["unit_sha256"], sha256_hex(UNIT.as_bytes()));
    validate_unit(UNIT, &authority).expect("canonical systemd unit");

    assert_eq!(authority["runtime_posture"]["type"], "simple");
    assert_eq!(
        authority["runtime_posture"]["readiness"],
        "cached_cli_no_sd_notify"
    );
    assert_eq!(
        authority["runtime_posture"]["restartable_exit_codes"],
        serde_json::json!([1, 3])
    );
    assert_eq!(
        authority["runtime_posture"]["nonrestartable_exit_codes"],
        serde_json::json!([2, 4, 5, 6])
    );
    assert_eq!(authority["runtime_posture"]["stop_timeout_seconds"], 310);
    assert_eq!(authority["verification"]["minimum_systemd_major"], 252);
    assert_eq!(authority["verification"]["maximum_exposure_score"], 3.0);
    assert_eq!(authority["verification"]["maximum_exposure_percent"], 30);
}

#[test]
fn systemd_unit_rejects_aliases_environment_duplicates_and_weaker_posture() {
    let authority = contract();
    let mutations = [
        UNIT.replace("ConfigurationDirectory=", "ConfigDirectory="),
        format!("{UNIT}Environment=MYC_SECRET=forbidden\n"),
        UNIT.replace(
            "NoNewPrivileges=yes",
            "NoNewPrivileges=yes\nNoNewPrivileges=yes",
        ),
        UNIT.replace(
            "RuntimeDirectoryPreserve=restart",
            "RuntimeDirectoryPreserve=yes",
        ),
        UNIT.replace("CapabilityBoundingSet=\n", ""),
    ];
    for mutation in mutations {
        assert!(validate_unit(&mutation, &authority).is_err());
    }
}

#[test]
fn systemd_verifier_is_linux_only_bounded_and_forge_agnostic() {
    for required in [
        "systemd 252 or newer is required",
        "systemd-analyze verify",
        "--offline=yes --threshold=30",
        "exact ExecStart was not admitted",
    ] {
        assert!(VERIFY_SCRIPT.contains(required), "missing `{required}`");
    }
    for forbidden in ["nix ", "oci", ".github", ".act", "_radroots", "docker"] {
        assert!(!VERIFY_SCRIPT.to_ascii_lowercase().contains(forbidden));
    }
    assert_eq!(
        contract()["deferred"],
        serde_json::json!([
            "compatibility_sensitive_memory_deny_write_execute",
            "compatibility_sensitive_system_call_filter",
            "resource_limits_step_231",
            "integration_wave_step_229",
            "rcld_promotion_step_235",
            "nix",
            "oci",
            "deployment",
            "production_activation"
        ])
    );
}
