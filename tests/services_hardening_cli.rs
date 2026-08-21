#![forbid(unsafe_code)]

use std::error::Error;
use std::path::Path;

use myc::{
    MYC_INSTANCE_ID_MAX_BYTES, MycBootstrapProfileV1, MycCliV1ErrorKind, MycCommandV1,
    MycConfigCommandV1, MycIdentityCommandV1, MycStateCommandV1, parse_myc_cli_v1_from,
};

const CLI_SOURCE: &str = include_str!("../src/cli_v1.rs");

fn base(command: &[&str]) -> Vec<String> {
    let mut arguments = vec![
        "myc".to_owned(),
        "--profile".to_owned(),
        "service-host".to_owned(),
        "--instance".to_owned(),
        "primary".to_owned(),
    ];
    arguments.extend(command.iter().map(|value| (*value).to_owned()));
    arguments
}

#[test]
fn root_api_freezes_the_exact_command_inventory() {
    let vectors = [
        (vec!["run"], MycCommandV1::Run),
        (
            vec!["config", "init"],
            MycCommandV1::Config(MycConfigCommandV1::Init),
        ),
        (
            vec!["config", "validate"],
            MycCommandV1::Config(MycConfigCommandV1::Validate),
        ),
        (
            vec!["config", "show"],
            MycCommandV1::Config(MycConfigCommandV1::Show),
        ),
        (
            vec!["config", "schema"],
            MycCommandV1::Config(MycConfigCommandV1::Schema),
        ),
        (
            vec!["state", "init"],
            MycCommandV1::State(MycStateCommandV1::Init),
        ),
        (
            vec!["state", "status"],
            MycCommandV1::State(MycStateCommandV1::Status),
        ),
        (
            vec!["state", "backup"],
            MycCommandV1::State(MycStateCommandV1::Backup),
        ),
        (
            vec!["state", "restore"],
            MycCommandV1::State(MycStateCommandV1::Restore),
        ),
        (
            vec!["state", "verify"],
            MycCommandV1::State(MycStateCommandV1::Verify),
        ),
        (
            vec!["state", "migrate"],
            MycCommandV1::State(MycStateCommandV1::Migrate),
        ),
        (
            vec!["identity", "init"],
            MycCommandV1::Identity(MycIdentityCommandV1::Init),
        ),
        (
            vec!["identity", "status"],
            MycCommandV1::Identity(MycIdentityCommandV1::Status),
        ),
        (
            vec!["identity", "rekey"],
            MycCommandV1::Identity(MycIdentityCommandV1::Rekey),
        ),
        (
            vec!["identity", "replace"],
            MycCommandV1::Identity(MycIdentityCommandV1::Replace),
        ),
        (
            vec!["identity", "export-public"],
            MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic),
        ),
        (vec!["status"], MycCommandV1::Status),
        (vec!["doctor"], MycCommandV1::Doctor),
    ];

    for (arguments, expected) in vectors {
        assert_eq!(
            parse_myc_cli_v1_from(base(&arguments))
                .expect("governed command")
                .command(),
            expected
        );
    }
}

#[test]
fn root_api_exposes_validated_cross_bound_bootstrap_values() {
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "config",
        "validate",
        "--profile",
        "repo-local",
        "--instance",
        "dev-01",
        "--repo-local-root",
        "/repo/radroots",
        "--config",
        "/repo/radroots/config/services/myc/config.toml",
    ])
    .expect("repo-local invocation");
    assert_eq!(invocation.profile(), MycBootstrapProfileV1::RepoLocal);
    assert_eq!(invocation.instance(), "dev-01");
    assert_eq!(
        invocation.repo_local_root(),
        Some(Path::new("/repo/radroots"))
    );
    assert_eq!(
        invocation.config_path(),
        Some(Path::new("/repo/radroots/config/services/myc/config.toml"))
    );
    assert_eq!(MYC_INSTANCE_ID_MAX_BYTES, 128);
}

#[test]
fn root_api_rejects_prototype_and_arbitrary_leaf_arguments_safely() {
    for arguments in [
        base(&["--env-file", "/secret/config.env", "run"]),
        base(&["metrics"]),
        base(&["persistence", "backup"]),
        base(&["identity", "generate"]),
        base(&["run", "--relay-url", "wss://secret.example"]),
    ] {
        let error = parse_myc_cli_v1_from(arguments).expect_err("forbidden CLI shape");
        assert_eq!(error.kind(), MycCliV1ErrorKind::InvalidArguments);
        assert!(Error::source(&error).is_none());
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("secret"));
    }
}

#[test]
fn parser_is_single_pass_pure_and_privately_implemented() {
    assert_eq!(CLI_SOURCE.matches("RawMycCliV1::try_parse_from").count(), 1);
    for forbidden in [
        "std::env::",
        "env::args",
        "std::fs::",
        "tokio::",
        "serde_json::",
        "toml::",
        "pub mod cli_v1",
    ] {
        assert!(!CLI_SOURCE.contains(forbidden), "found `{forbidden}`");
    }

    let root = include_str!("../src/lib.rs");
    assert!(root.contains("mod cli_v1;"));
    assert!(!root.contains("pub mod cli_v1;"));
}
