#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::json;

const CONTRACT: &str = include_str!("../contracts/services_hardening/native_release.v2.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const LOCK: &str = include_str!("../Cargo.lock");
const FLAKE: &str = include_str!("../flake.nix");
const FLAKE_LOCK: &str = include_str!("../flake.lock");
const CARGO_CONFIG: &str = include_str!("../.cargo/config.toml");
const SYSTEMD_UNIT: &str = include_str!("../packaging/systemd/myc@.service");

const LIB_REVISION: &str = "d287d41c2cd97cd0e455445da90f22180029f089";
const DEFERRED_NIX_LIB_REVISION: &str = "b44119fbac5985be8127ad1bf56d2950e6399427";
const LIB_REPOSITORY: &str = "https://github.com/radrootslabs/lib";

#[test]
fn native_release_contract_and_manifest_metadata_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("release contract");
    assert_eq!(
        contract,
        json!({
            "schema": "radroots.myc.native-release",
            "schema_version": 2,
            "contract_version": 2,
            "predecessor": {
                "schema_version": 1,
                "filename": "native_release.v1.json",
                "transition": "forward_only_replace"
            },
            "service": "myc",
            "package": {
                "name": "myc",
                "binary": "myc",
                "version": "0.1.0",
                "repository": "https://github.com/radrootslabs/myc",
                "publish_to_crates_io": false
            },
            "generator": {
                "command": "cargo xtask native-release",
                "modes": ["check", "write"],
                "required_arguments": [
                    "mode", "target", "binary", "output", "source_date_epoch"
                ],
                "source_date_epoch_range": "1..=4294967295",
                "clean_exact_head": true,
                "target_binary_validation": "executable_elf64_little_endian_exact_machine",
                "canonical_json": "compact_utf8_json_with_one_final_lf",
                "deterministic_archives": true,
                "output_directory_mode": "0755",
                "output_file_mode": "0644",
                "durability": "sync_files_then_output_directory_then_parent"
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
                "lib_repository": LIB_REPOSITORY,
                "architecture": "radroots.crates.release.v2"
            },
            "contract_versions": {
                "config": 1,
                "state": 12,
                "admin": 1,
                "status": 1,
                "provider": 1
            },
            "native_targets": [
                { "target": "aarch64-unknown-linux-gnu", "posture": "target" },
                { "target": "x86_64-unknown-linux-gnu", "posture": "target" }
            ],
            "output_inventory": [
                "LICENSE",
                "SHA256SUMS",
                "THIRD-PARTY-NOTICES.txt",
                "artifact-manifest.v1.json",
                "binary.tar.gz",
                "config.example.toml",
                "config.schema.json",
                "provenance-input.v1.json",
                "radroots.service.source-lock.v2.toml",
                "sbom.cdx.json",
                "service-source.tar.gz",
                "systemd.service"
            ],
            "signing_inputs": [
                "SHA256SUMS",
                "artifact-manifest.v1.json",
                "provenance-input.v1.json"
            ],
            "provenance_posture": "deterministic_unsigned_slsa_v1_input_external_keys_only",
            "sbom_format": "cyclonedx_json_1_5_locked_cargo_graph",
            "source_archive": "locked_offline_cargo_build_with_vendored_dependencies",
            "checksum_format": "sha256_lower_hex_two_spaces_path_lf_sorted_by_path",
            "protected_material_included": false,
            "maximums": {
                "text_input_bytes": 1048576,
                "generated_document_bytes": 16777216,
                "cargo_metadata_bytes": 33554432,
                "binary_bytes": 536870912,
                "source_archive_bytes": 1073741824,
                "packages": 8192,
                "tracked_files": 4096
            },
            "deferred_through_rcld_rshr_170": [
                "nix_evaluation",
                "nix_build",
                "nixos_module_qualification",
                "oci_artifact"
            ],
            "forbidden": [
                "nix_input",
                "nixos_module_output",
                "oci_input",
                "oci_output",
                "protected_material",
                "parent_owned_human_docs",
                "private_harness",
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
            state_contract_version = 12
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
    assert_eq!(
        CARGO_CONFIG,
        "[alias]\nxtask = \"run --locked -p myc_xtask --\"\n"
    );
    for required in [
        "ExecStart=/usr/bin/myc --profile service-host --instance %i run",
        "ConfigurationDirectory=radroots/services/myc/%i",
        "StateDirectory=radroots/services/myc/%i",
        "RuntimeDirectory=radroots/services/myc/%i",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=",
    ] {
        assert!(SYSTEMD_UNIT.contains(required), "missing `{required}`");
    }
}

#[test]
fn every_radroots_dependency_is_exactly_source_locked() {
    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let dependencies = manifest["dependencies"].as_table().expect("dependencies");
    let radroots = dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("radroots_"))
        .collect::<Vec<_>>();
    assert_eq!(radroots.len(), 11);
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
fn native_release_surfaces_remain_generated_outside_the_source_tree() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("radroots.lib.source-lock.v1.toml").exists());
    assert!(!root.join("radroots.service.source-lock.v1.toml").exists());
    assert!(root.join("radroots.service.source-lock.v2.toml").is_file());
    assert!(
        !root
            .join("contracts/services_hardening/native_release.v1.json")
            .exists()
    );
    assert!(
        root.join("contracts/services_hardening/native_release.v2.json")
            .is_file()
    );
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
    assert!(!CONTRACT.contains("oci-image"));
    assert!(!CONTRACT.contains("nixos-module"));
}
