#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::json;

const CONTRACT: &str = include_str!("../contracts/services_hardening/native_release.v1.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const LOCK: &str = include_str!("../Cargo.lock");
const FLAKE: &str = include_str!("../flake.nix");
const FLAKE_LOCK: &str = include_str!("../flake.lock");

const LIB_REVISION: &str = "7d7b454b4c9ed86569671993bd03ca868b676665";
const DEFERRED_NIX_LIB_REVISION: &str = "b44119fbac5985be8127ad1bf56d2950e6399427";
const LIB_REPOSITORY: &str = "https://github.com/radrootslabs/lib";

#[test]
fn native_release_contract_and_manifest_metadata_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("release contract");
    assert_eq!(
        contract,
        json!({
            "schema": "radroots.myc.native-release",
            "schema_version": 1,
            "contract_version": 1,
            "service": "myc",
            "package": {
                "name": "myc",
                "binary": "myc",
                "version": "0.1.0",
                "repository": "https://github.com/radrootslabs/myc",
                "publish_to_crates_io": false
            },
            "toolchain": {
                "rust_version": "1.97.1",
                "edition": "2024",
                "resolver": "3",
                "host_feature_profile": "service-host"
            },
            "release_profile": {
                "lto": "thin",
                "codegen_units": 1,
                "overflow_checks": true,
                "strip": "symbols",
                "panic": "unwind"
            },
            "source_lock": {
                "filename": "radroots.service.source-lock.v2.toml",
                "schema": "radroots.service.source-lock.v2",
                "generator": "cargo xtask service-source-lock",
                "lib_repository": LIB_REPOSITORY,
                "architecture": "radroots.crates.release.v2"
            },
            "contract_versions": {
                "config": 1,
                "state": 10,
                "admin": 1,
                "status": 1,
                "provider": 1
            },
            "native_targets": [
                { "target": "aarch64-unknown-linux-gnu", "posture": "target" },
                { "target": "x86_64-unknown-linux-gnu", "posture": "target" }
            ],
            "step_139_outputs": [
                "cargo_package_metadata",
                "release_profile",
                "dependency_source_trust",
                "service_source_lock"
            ],
            "deferred_to_step_160": [
                "native_binary_archive",
                "service_source_archive",
                "systemd_material",
                "sbom",
                "provenance",
                "notices",
                "checksums",
                "signing_inputs"
            ],
            "deferred_through_rcld_rshr_170": [
                "nix_evaluation",
                "nix_build",
                "nixos_module_qualification",
                "oci_artifact"
            ],
            "forbidden": [
                "local_or_path_lib_dependency",
                "floating_or_branch_lib_dependency",
                "mixed_lib_revision",
                "crates_io_publication",
                "signing",
                "tagging",
                "release_publication",
                "deployment"
            ]
        })
    );

    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let package = manifest["package"].as_table().expect("package");
    assert_eq!(
        package["repository"].as_str(),
        Some("https://github.com/radrootslabs/myc")
    );
    assert_eq!(package["readme"].as_str(), Some("README"));
    assert_eq!(package["publish"].as_bool(), Some(false));

    let metadata = &manifest["workspace"]["metadata"]["radroots"];
    assert_eq!(
        metadata["service_source_lock"],
        toml::Value::Table(toml::toml! {
            service = "myc"
            host_feature_profile = "service-host"
            nix_material = "deferred"
            config_contract_version = 1
            state_contract_version = 10
            admin_contract_version = 1
            status_contract_version = 1
            provider_contract_version = 1
        })
    );
    assert_eq!(
        metadata["service_release"],
        toml::Value::Table(toml::toml! {
            service = "myc"
            service_package = "myc"
            binary_name = "myc"
            version = "0.1.0"
        })
    );
    assert_eq!(
        manifest["profile"]["release"],
        toml::Value::Table(toml::toml! {
            lto = "thin"
            codegen-units = 1
            overflow-checks = true
            strip = "symbols"
            panic = "unwind"
        })
    );
}

#[test]
fn every_radroots_dependency_is_exactly_source_locked() {
    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let dependencies = manifest["dependencies"].as_table().expect("dependencies");
    let radroots = dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("radroots_"))
        .collect::<Vec<_>>();
    assert_eq!(radroots.len(), 7);
    for (name, dependency) in radroots {
        let dependency = dependency.as_table().expect("detailed dependency");
        assert_eq!(
            dependency.get("git").and_then(toml::Value::as_str),
            Some(LIB_REPOSITORY),
            "{name}"
        );
        assert_eq!(
            dependency.get("rev").and_then(toml::Value::as_str),
            Some(LIB_REVISION),
            "{name}"
        );
        assert_eq!(
            dependency.get("version").and_then(toml::Value::as_str),
            Some("=0.1.0-alpha"),
            "{name}"
        );
        for forbidden in ["path", "branch", "tag"] {
            assert!(
                !dependency.contains_key(forbidden),
                "{name} contains `{forbidden}`"
            );
        }
    }
    assert!(!MANIFEST.contains("[patch."));

    let sources = LOCK
        .lines()
        .filter_map(|line| line.strip_prefix("source = \"git+"))
        .filter_map(|line| line.strip_suffix('"'))
        .filter(|source| source.contains("radrootslabs/lib"))
        .collect::<BTreeSet<_>>();
    assert_eq!(sources.len(), 1);
    let source = sources.into_iter().next().expect("Lib source");
    assert!(source.contains(&format!("?rev={LIB_REVISION}#{LIB_REVISION}")));

    for required in [
        "lib = {",
        "github:radrootslabs/lib/b44119fbac5985be8127ad1bf56d2950e6399427",
        "flake = false;",
    ] {
        assert!(
            FLAKE.contains(required),
            "flake source data is missing `{required}`"
        );
    }
    let flake_lock: serde_json::Value =
        serde_json::from_str(FLAKE_LOCK).expect("flake source lock");
    assert_eq!(flake_lock["version"], 7);
    assert_eq!(flake_lock["root"], "root");
    assert_eq!(flake_lock["nodes"]["root"]["inputs"]["lib"], "lib");
    assert_eq!(
        flake_lock["nodes"]["lib"],
        json!({
            "locked": {
                "lastModified": 1787301679_u64,
                "narHash": "sha256-WOcgJuKhM9aP55yTuTM63uBf+/IroeBu26zy+lMkvpE=",
                "owner": "radrootslabs",
                "repo": "lib",
                "rev": DEFERRED_NIX_LIB_REVISION,
                "type": "github"
            },
            "original": {
                "owner": "radrootslabs",
                "repo": "lib",
                "rev": DEFERRED_NIX_LIB_REVISION,
                "type": "github"
            }
        })
    );
}

#[test]
fn removed_and_deferred_release_surfaces_cannot_be_smuggled_into_step_139() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("radroots.lib.source-lock.v1.toml").exists());
    assert!(!root.join("radroots.service.source-lock.v1.toml").exists());
    assert!(root.join("radroots.service.source-lock.v2.toml").is_file());
    for forbidden in [
        ".github",
        "target",
        "result",
        "artifacts",
        "dist",
        "sbom.cdx.json",
        "provenance-input.v1.json",
        "oci-image.tar.gz",
    ] {
        assert!(
            !root.join(forbidden).exists(),
            "forbidden generated surface `{forbidden}` exists"
        );
    }
    assert!(!CONTRACT.contains("qualified"));
    assert!(!CONTRACT.contains("production_ready"));
}
