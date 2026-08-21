#![forbid(unsafe_code)]

use std::{error::Error, path::Path};

use myc::{
    MYC_CONFIG_SCHEMA_VERSION, MYC_OPERATOR_CONTRACT_VERSION, MYC_SIGNER_STATUS_CONTRACT_VERSION,
    MYC_STATE_APPLICATION_ID, MYC_STATE_SCHEMA_VERSION, MycConfigProfile, MycStateMetadata,
    MycStateMetadataErrorKind, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    parse_myc_cli_v1_from, parse_myc_config_v1, resolve_myc_runtime_context,
};
use radroots_storage::event::SourceGeneration;

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const METADATA_SOURCE: &str = include_str!("../src/state_metadata.rs");

fn runtime(root: &Path, profile: &str) -> myc::MycRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        profile,
        "--instance",
        "primary",
        "--repo-local-root",
        root,
        "run",
    ])
    .expect("valid test invocation");
    resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn state_metadata(
    runtime: &myc::MycRuntimeContext,
    source: &str,
) -> Result<MycStateMetadata, myc::MycStateMetadataError> {
    let configuration =
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal).expect("configuration");
    MycStateMetadata::new(
        runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
}

#[test]
fn exact_database_configuration_identity_and_policy_bindings_are_frozen() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let metadata = state_metadata(&runtime, EXAMPLE).expect("state metadata");
    let database = metadata.database();

    assert_eq!(MYC_STATE_APPLICATION_ID.to_be_bytes(), *b"RDMY");
    assert_eq!(database.application_id().get(), MYC_STATE_APPLICATION_ID);
    assert_eq!(database.service().as_str(), "myc");
    assert_eq!(database.instance().as_str(), "primary");
    assert_eq!(database.source_generation().as_bytes(), &[0x5a; 32]);
    assert_eq!(
        database.state_schema_version().get(),
        MYC_STATE_SCHEMA_VERSION
    );
    assert_eq!(database.created_at_unix_ms(), 1_725_000_000_000);

    let identities = metadata.expected_identities();
    assert_eq!(identities.transport().as_hex(), "4".repeat(64));
    assert_eq!(identities.user().as_hex(), "2".repeat(64));
    assert_eq!(
        identities.discovery().expect("discovery identity").as_hex(),
        "3".repeat(64)
    );

    let versions = metadata.policy_versions();
    assert_eq!(versions.configuration(), MYC_CONFIG_SCHEMA_VERSION);
    assert_eq!(versions.state(), MYC_STATE_SCHEMA_VERSION);
    assert_eq!(versions.operator(), MYC_OPERATOR_CONTRACT_VERSION);
    assert_eq!(versions.status(), MYC_SIGNER_STATUS_CONTRACT_VERSION);
    assert_eq!(
        hex::encode(metadata.configuration_digest().as_bytes()),
        "5fd8ecb8d526ed8cc2d5af8963838ea9a3707a74d0da6ed7c97851a4d6760a44"
    );
}

#[test]
fn digest_uses_fully_defaulted_values_and_changes_with_normalized_policy() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let explicit = state_metadata(&runtime, EXAMPLE).expect("explicit defaults");
    let implicit_source = EXAMPLE
        .replace("shutdown_grace_ms = 30000\n", "")
        .replace("level = \"info\"\n", "")
        .replace("format = \"json\"\n", "")
        .replace("busy_timeout_ms = 5000\n", "")
        .replace("max_connections = 8\n", "");
    let implicit = state_metadata(&runtime, &implicit_source).expect("implicit defaults");
    assert_eq!(
        explicit.configuration_digest(),
        implicit.configuration_digest()
    );

    let changed = state_metadata(
        &runtime,
        &EXAMPLE.replace("level = \"info\"", "level = \"warn\""),
    )
    .expect("changed policy");
    assert_ne!(
        explicit.configuration_digest(),
        changed.configuration_digest()
    );
}

#[test]
fn disabled_discovery_binds_no_discovery_identity() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let mut document = toml::from_str::<toml::Value>(EXAMPLE).expect("example TOML");
    document["identity"]["discovery"] = toml::Value::Table(
        [("enabled".to_owned(), toml::Value::Boolean(false))]
            .into_iter()
            .collect(),
    );
    document["discovery"] = toml::Value::Table(
        [("enabled".to_owned(), toml::Value::Boolean(false))]
            .into_iter()
            .collect(),
    );
    let source = toml::to_string(&document).expect("disabled-discovery TOML");
    let metadata = state_metadata(&runtime, &source).expect("state metadata");

    assert!(metadata.expected_identities().discovery().is_none());
}

#[test]
fn profile_and_invalid_nostr_identity_bindings_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let production = parse_myc_config_v1(EXAMPLE.as_bytes(), MycConfigProfile::Production)
        .expect("production configuration");
    let error = MycStateMetadata::new(
        &runtime,
        &production,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1,
    )
    .expect_err("profile mismatch");
    assert_eq!(error.kind(), MycStateMetadataErrorKind::Profile);
    assert!(Error::source(&error).is_none());

    let invalid_role = EXAMPLE.replacen(&"4".repeat(64), &"f".repeat(64), 1);
    assert!(
        parse_myc_config_v1(invalid_role.as_bytes(), MycConfigProfile::RepoLocal).is_err(),
        "an out-of-field role identity must not remain a valid configuration"
    );
    let invalid_client = EXAMPLE.replacen(&"7".repeat(64), &"f".repeat(64), 1);
    assert!(
        parse_myc_config_v1(invalid_client.as_bytes(), MycConfigProfile::RepoLocal).is_err(),
        "an out-of-field policy identity must not remain a valid configuration"
    );
}

#[test]
fn metadata_debug_error_and_package_boundary_disclose_no_values() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let metadata = state_metadata(&runtime, EXAMPLE).expect("state metadata");
    let rendered = format!("{metadata:?}");
    for forbidden in [
        directory.path().to_string_lossy().as_ref(),
        &"4".repeat(64),
        &"2".repeat(64),
        &"3".repeat(64),
        &hex::encode(metadata.configuration_digest().as_bytes()),
    ] {
        assert!(!rendered.contains(forbidden));
    }

    assert!(LIB_SOURCE.contains("mod state_metadata;"));
    assert!(!LIB_SOURCE.contains("pub mod state_metadata;"));
    for forbidden in [
        "sqlx::",
        "rusqlite",
        "CREATE TABLE",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "std::fs",
        "std::env",
        "std::time",
        "Serialize",
        "Deserialize",
    ] {
        assert!(
            !METADATA_SOURCE.contains(forbidden),
            "found forbidden metadata authority `{forbidden}`"
        );
    }
}
