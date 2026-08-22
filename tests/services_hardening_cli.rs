#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

use myc::{
    INSTANCE_ID_MAX_BYTES, MycBootstrapProfileV1, MycCliAdminOperationV1, MycCliOfflineOperationV1,
    MycCliPrimaryAuthorityV1, MycCliV1ErrorKind, MycCommandV1, MycConfigCommandV1,
    MycIdentityCommandV1, MycStateCommandV1, parse_myc_cli_v1_from, plan_myc_cli_v1,
};

const CLI_SOURCE: &str = include_str!("../src/cli_v1.rs");
const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

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
    assert_eq!(invocation.instance().as_str(), "dev-01");
    assert_eq!(
        invocation.repo_local_root(),
        Some(Path::new("/repo/radroots"))
    );
    assert_eq!(
        invocation.config_path(),
        Some(Path::new("/repo/radroots/config/services/myc/config.toml"))
    );
    assert_eq!(INSTANCE_ID_MAX_BYTES, 128);
}

#[test]
fn every_command_has_one_exact_nonforgeable_execution_plan() {
    let vectors = [
        ("run", vec!["run"], "daemon", None, None, false),
        (
            "config init",
            vec!["config", "init"],
            "offline",
            Some("config"),
            None,
            false,
        ),
        (
            "config validate",
            vec!["config", "validate"],
            "offline",
            Some("config"),
            None,
            false,
        ),
        (
            "config show",
            vec!["config", "show"],
            "offline",
            Some("config"),
            None,
            false,
        ),
        (
            "config schema",
            vec!["config", "schema"],
            "offline",
            Some("config"),
            None,
            false,
        ),
        (
            "state init",
            vec!["state", "init"],
            "offline",
            Some("state_exclusive"),
            None,
            false,
        ),
        (
            "state status",
            vec!["state", "status"],
            "live_unix_admin",
            Some("state_read_only"),
            Some("/v1/state/status"),
            true,
        ),
        (
            "state backup",
            vec!["state", "backup"],
            "live_unix_admin",
            Some("state_read_only"),
            Some("/v1/state/backup"),
            true,
        ),
        (
            "state restore",
            vec!["state", "restore"],
            "offline",
            Some("state_exclusive"),
            None,
            false,
        ),
        (
            "state verify",
            vec!["state", "verify"],
            "offline",
            Some("state_exclusive"),
            None,
            false,
        ),
        (
            "state migrate",
            vec!["state", "migrate"],
            "offline",
            Some("state_exclusive"),
            None,
            false,
        ),
        (
            "identity init",
            vec!["identity", "init"],
            "offline",
            Some("identity_exclusive"),
            None,
            false,
        ),
        (
            "identity status",
            vec!["identity", "status"],
            "live_unix_admin",
            Some("identity_read_only"),
            Some("/v1/identity/status"),
            true,
        ),
        (
            "identity rekey",
            vec!["identity", "rekey"],
            "live_unix_admin",
            None,
            Some("/v1/identity/rekey"),
            false,
        ),
        (
            "identity replace",
            vec!["identity", "replace"],
            "live_unix_admin",
            None,
            Some("/v1/identity/replace"),
            false,
        ),
        (
            "identity export-public",
            vec!["identity", "export-public"],
            "live_unix_admin",
            Some("identity_read_only"),
            Some("/v1/identity/public"),
            true,
        ),
        (
            "status",
            vec!["status"],
            "live_unix_admin",
            Some("state_read_only"),
            Some("/v1/status"),
            true,
        ),
        (
            "doctor",
            vec!["doctor"],
            "offline",
            Some("doctor"),
            None,
            false,
        ),
    ];
    let contract: serde_json::Value =
        serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    let dispatch = contract
        .get("cli_dispatch")
        .and_then(serde_json::Value::as_object)
        .expect("CLI dispatch contract");
    assert_eq!(
        dispatch.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "commands",
            "live_direct_sqlite_access",
            "live_mutation_offline_fallback",
            "parse_count",
            "primary_authorities",
            "read_only_offline_fallback_requires_free_daemon_writer_lock",
        ])
    );
    assert_eq!(
        dispatch
            .get("parse_count")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        dispatch
            .get("live_direct_sqlite_access")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        dispatch.get("primary_authorities"),
        Some(&serde_json::json!(["daemon", "offline", "live_unix_admin"]))
    );
    assert_eq!(
        dispatch
            .get("read_only_offline_fallback_requires_free_daemon_writer_lock")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("live_mutation_offline_fallback")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let commands = dispatch
        .get("commands")
        .and_then(serde_json::Value::as_array)
        .expect("command inventory");
    assert_eq!(commands.len(), vectors.len());

    for (index, (command, arguments, authority, offline, route, fallback)) in
        vectors.into_iter().enumerate()
    {
        let invocation = parse_myc_cli_v1_from(base(&arguments)).expect("command");
        let plan = plan_myc_cli_v1(&invocation);
        assert_eq!(authority_name(plan.primary_authority()), authority);
        assert_eq!(plan.offline_operation().map(offline_name), offline);
        assert_eq!(plan.admin_operation().map(admin_path), route);
        assert_eq!(plan.allows_daemon_unavailable_offline_fallback(), fallback);

        let row = commands[index].as_object().expect("command row");
        let mut expected_keys = BTreeSet::from(["command", "primary_authority"]);
        if offline.is_some() {
            expected_keys.insert("offline_operation");
        }
        if route.is_some() {
            expected_keys.insert("admin_route");
        }
        if fallback {
            expected_keys.insert("daemon_unavailable_offline_fallback");
        }
        assert_eq!(
            row.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_keys
        );
        assert_eq!(
            row.get("command").and_then(serde_json::Value::as_str),
            Some(command)
        );
        assert_eq!(
            row.get("primary_authority")
                .and_then(serde_json::Value::as_str),
            Some(authority)
        );
        assert_eq!(
            row.get("offline_operation")
                .and_then(serde_json::Value::as_str),
            offline
        );
        assert_eq!(
            row.get("admin_route").and_then(serde_json::Value::as_str),
            route
        );
        assert_eq!(
            row.get("daemon_unavailable_offline_fallback")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            fallback
        );
    }
}

fn authority_name(authority: MycCliPrimaryAuthorityV1) -> &'static str {
    match authority {
        MycCliPrimaryAuthorityV1::Daemon => "daemon",
        MycCliPrimaryAuthorityV1::Offline => "offline",
        MycCliPrimaryAuthorityV1::LiveUnixAdmin => "live_unix_admin",
    }
}

fn offline_name(operation: MycCliOfflineOperationV1) -> &'static str {
    match operation {
        MycCliOfflineOperationV1::Config => "config",
        MycCliOfflineOperationV1::StateExclusive => "state_exclusive",
        MycCliOfflineOperationV1::StateReadOnly => "state_read_only",
        MycCliOfflineOperationV1::IdentityExclusive => "identity_exclusive",
        MycCliOfflineOperationV1::IdentityReadOnly => "identity_read_only",
        MycCliOfflineOperationV1::Doctor => "doctor",
    }
}

fn admin_path(operation: MycCliAdminOperationV1) -> &'static str {
    match operation {
        MycCliAdminOperationV1::Status => "/v1/status",
        MycCliAdminOperationV1::StateStatus => "/v1/state/status",
        MycCliAdminOperationV1::StateBackup => "/v1/state/backup",
        MycCliAdminOperationV1::IdentityStatus => "/v1/identity/status",
        MycCliAdminOperationV1::IdentityRekey => "/v1/identity/rekey",
        MycCliAdminOperationV1::IdentityReplace => "/v1/identity/replace",
        MycCliAdminOperationV1::IdentityPublic => "/v1/identity/public",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cli_admin_operations_match_the_governed_route_inventory() {
    use myc::MycAdminRoute;

    let vectors = [
        (MycCliAdminOperationV1::Status, MycAdminRoute::Status),
        (
            MycCliAdminOperationV1::StateStatus,
            MycAdminRoute::StateStatus,
        ),
        (
            MycCliAdminOperationV1::StateBackup,
            MycAdminRoute::StateBackup,
        ),
        (
            MycCliAdminOperationV1::IdentityStatus,
            MycAdminRoute::IdentityStatus,
        ),
        (
            MycCliAdminOperationV1::IdentityRekey,
            MycAdminRoute::IdentityRekey,
        ),
        (
            MycCliAdminOperationV1::IdentityReplace,
            MycAdminRoute::IdentityReplace,
        ),
        (
            MycCliAdminOperationV1::IdentityPublic,
            MycAdminRoute::IdentityPublic,
        ),
    ];
    for (operation, route) in vectors {
        assert_eq!(operation.route(), route);
        assert_eq!(admin_path(operation), route.path());
    }
}

#[test]
fn execution_plan_debug_retains_no_bootstrap_or_path_values() {
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "secret-instance",
        "--repo-local-root",
        "/secret/repository",
        "--config",
        "/secret/config.toml",
        "identity",
        "rekey",
    ])
    .expect("valid invocation");
    let rendered = format!("{invocation:?} {:?}", plan_myc_cli_v1(&invocation));
    for forbidden in [
        "secret-instance",
        "/secret/repository",
        "/secret/config.toml",
    ] {
        assert!(!rendered.contains(forbidden));
    }
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
        "sqlx::",
        "open_myc_state_",
        "MycStateHost",
    ] {
        assert!(!CLI_SOURCE.contains(forbidden), "found `{forbidden}`");
    }

    assert_eq!(MAIN_SOURCE.matches("parse_myc_cli_v1_from").count(), 1);
    assert_eq!(MAIN_SOURCE.matches("plan_myc_cli_v1").count(), 1);
    for forbidden in ["sqlx::", "open_myc_state_", "MycStateHost"] {
        assert!(!MAIN_SOURCE.contains(forbidden), "found `{forbidden}`");
    }

    let root = include_str!("../src/lib.rs");
    assert!(root.contains("mod cli_v1;"));
    assert!(!root.contains("pub mod cli_v1;"));
}
