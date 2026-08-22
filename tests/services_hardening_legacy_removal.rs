#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const ACTIVE_STATE_SOURCES: &[&str] = &[
    include_str!("../src/state_catalog.rs"),
    include_str!("../src/state_completion.rs"),
    include_str!("../src/state_connection.rs"),
    include_str!("../src/state_delivery.rs"),
    include_str!("../src/state_discovery.rs"),
    include_str!("../src/state_governance.rs"),
    include_str!("../src/state_host.rs"),
    include_str!("../src/state_maintenance.rs"),
    include_str!("../src/state_metadata.rs"),
    include_str!("../src/state_repository.rs"),
    include_str!("../src/state_request.rs"),
    include_str!("../src/state_response.rs"),
];

#[test]
fn prototype_environment_and_cli_sources_are_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        ".env.example",
        "src/cli.rs",
        "src/bin/myc_repo_local_identity_bootstrap.rs",
        "tests/discovery_cli.rs",
        "tests/logging_run.rs",
        "tests/operability_cli.rs",
        "tests/persistence_cli.rs",
        "tests/nip46_e2e.rs",
        "tests/operability_e2e.rs",
        "tests/operability_server.rs",
        "src/app/mod.rs",
        "src/app/backend.rs",
        "src/app/runtime.rs",
        "src/audit.rs",
        "src/audit_sqlite.rs",
        "src/config.rs",
        "src/control.rs",
        "src/discovery.rs",
        "src/operability/mod.rs",
        "src/operability/server.rs",
        "src/outbox.rs",
        "src/outbox_sqlite.rs",
        "src/paths.rs",
        "src/persistence.rs",
        "src/sql.rs",
        "src/signer/migrations.rs",
        "src/signer/sqlite.rs",
        "src/signer/store.rs",
        "src/transport.rs",
        "src/transport/nip46.rs",
        "migrations/0000_delivery_outbox_init.up.sql",
        "migrations/0000_delivery_outbox_init.down.sql",
        "migrations/0000_runtime_audit_init.up.sql",
        "migrations/0000_runtime_audit_init.down.sql",
        "migrations/signer/0000_init.up.sql",
        "migrations/signer/0000_init.down.sql",
        "migrations/signer/0001_publish_workflows.up.sql",
        "migrations/signer/0001_publish_workflows.down.sql",
        "migrations/signer/0002_client_metadata.up.sql",
        "migrations/signer/0002_client_metadata.down.sql",
    ] {
        assert!(
            !root.join(relative).exists(),
            "legacy source remains: {relative}"
        );
    }

    for forbidden in [
        "pub mod cli;",
        "run_from_env",
        "load_from_default_env_path",
        "load_from_env_path",
        "from_env_str",
        "to_env_string",
        "DEFAULT_ENV_PATH",
        "config_env_path",
        "process_path_selection",
        "path_selection_from_entries",
        "parse_path_profile_env",
        "\"MYC_",
        "pub mod app;",
        "pub mod audit;",
        "mod audit_sqlite;",
        "pub mod config;",
        "pub mod outbox;",
        "mod outbox_sqlite;",
        "pub mod persistence;",
        "pub mod sql;",
        "pub mod transport;",
        "pub mod operability;",
        "MycSignerStateBackend",
        "MycRuntimeAuditBackend",
        "import_json_to_sqlite",
        "MycJsonlOperationAuditStore",
        "MycSqliteOperationAuditStore",
        "MycSqliteDeliveryOutboxStore",
        "RadrootsNostrFileSignerStore",
        "RadrootsNostrSqliteSignerStore",
    ] {
        assert!(
            !LIB_SOURCE.contains(forbidden),
            "legacy selector remains: {forbidden}"
        );
    }
}

#[test]
fn active_state_tree_has_one_shared_database_and_no_legacy_backend() {
    assert_eq!(LIB_SOURCE.matches("mod state_").count(), 12);
    assert!(!LIB_SOURCE.contains("pub mod state_"));
    let active_state = ACTIVE_STATE_SOURCES.join("\n");
    for forbidden in [
        "signer-state.json",
        "signer-state.sqlite",
        "operations.jsonl",
        "operations.sqlite",
        "delivery-outbox.sqlite",
        "manifest.json",
        "backend selection",
        "SqlitePool",
        "Pool<Sqlite>",
        "import_json_to_sqlite",
        "MycSignerStateBackend",
        "MycRuntimeAuditBackend",
    ] {
        assert!(
            !active_state.contains(forbidden),
            "legacy state authority remains: {forbidden}"
        );
    }
}

#[test]
fn obsolete_provider_sources_and_dependencies_are_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "src/accounts.rs",
        "src/custody.rs",
        "src/error.rs",
        "src/host_identity.rs",
        "src/identity_files.rs",
        "src/logging.rs",
        "src/nostr_contract.rs",
        "src/policy.rs",
        "src/signing_adapter.rs",
        "src/signer/backend.rs",
        "src/signer/capability.rs",
        "src/signer/error.rs",
        "src/signer/evaluation.rs",
        "src/signer/manager.rs",
        "src/signer/mod.rs",
        "src/signer/model.rs",
        "src/signer/nip46.rs",
        "src/signer/test_fixtures.rs",
        "src/signer/test_support.rs",
    ] {
        assert!(
            !root.join(relative).exists(),
            "obsolete provider source remains: {relative}"
        );
    }

    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("dependencies table");
    for forbidden in [
        "axum",
        "keyring",
        "nostr-sdk",
        "radroots_identity",
        "radroots_event",
        "radroots_signing",
        "rand",
        "thiserror",
        "tracing",
        "tracing-appender",
        "tracing-subscriber",
        "uuid",
    ] {
        assert!(
            !dependencies.contains_key(forbidden),
            "obsolete provider dependency remains: {forbidden}"
        );
    }
    let secrets_features = dependencies["radroots_secrets"]["features"]
        .as_array()
        .expect("radroots_secrets features");
    assert_eq!(secrets_features, &[toml::Value::String("std".to_owned())]);
    let tokio_features = dependencies["tokio"]["features"]
        .as_array()
        .expect("Tokio features");
    assert!(
        !tokio_features
            .iter()
            .any(|feature| feature.as_str() == Some("process"))
    );
    assert!(!dependencies.contains_key("tempfile"));

    let dev_dependencies = manifest["dev-dependencies"]
        .as_table()
        .expect("dev-dependencies table");
    assert!(dev_dependencies.contains_key("tempfile"));
    for forbidden in ["futures-util", "serial_test", "tokio-tungstenite"] {
        assert!(
            !dev_dependencies.contains_key(forbidden),
            "obsolete development dependency remains: {forbidden}"
        );
    }
}

#[test]
fn binary_uses_only_the_hardened_parser_and_fails_closed_before_dispatch() {
    assert!(MAIN_SOURCE.contains("parse_myc_cli_v1_from(std::env::args_os())"));
    assert!(!MAIN_SOURCE.contains("MycConfig"));
    assert!(!MAIN_SOURCE.contains("MycRuntime"));

    let missing = Command::new(env!("CARGO_BIN_EXE_myc"))
        .env("MYC_PATHS_PROFILE", "service_host")
        .env("MYC_SERVICE_INSTANCE_NAME", "implicit")
        .output()
        .expect("run missing-selector case");
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(missing.stderr).expect("utf8 stderr"),
        "myc: command-line arguments are invalid\n"
    );

    let admitted = Command::new(env!("CARGO_BIN_EXE_myc"))
        .args(["--profile", "service-host", "--instance", "primary", "run"])
        .output()
        .expect("run admitted command");
    assert_eq!(admitted.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(admitted.stderr).expect("utf8 stderr"),
        "myc: command execution is unavailable\n"
    );
}

#[test]
fn removed_alias_and_leaf_arguments_fail_without_echoing_values() {
    for arguments in [
        vec!["--env-file", "/sensitive/config.env", "run"],
        vec!["metrics"],
        vec!["run", "--relay-url", "wss://sensitive.example"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_myc"))
            .args(["--profile", "service-host", "--instance", "primary"])
            .args(arguments)
            .output()
            .expect("run forbidden command");
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert_eq!(stderr, "myc: command-line arguments are invalid\n");
        assert!(!stderr.contains("sensitive"));
    }
}
