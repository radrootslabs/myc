#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const CONFIG_SOURCE: &str = include_str!("../src/config.rs");
const PATHS_SOURCE: &str = include_str!("../src/paths.rs");
const LOGGING_SOURCE: &str = include_str!("../src/logging.rs");
const PERSISTENCE_SOURCE: &str = include_str!("../src/persistence.rs");

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
    ] {
        assert!(
            !root.join(relative).exists(),
            "legacy source remains: {relative}"
        );
    }

    let governed_sources = [
        LIB_SOURCE,
        CONFIG_SOURCE,
        PATHS_SOURCE,
        LOGGING_SOURCE,
        PERSISTENCE_SOURCE,
    ]
    .join("\n");
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
    ] {
        assert!(
            !governed_sources.contains(forbidden),
            "legacy selector remains: {forbidden}"
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
