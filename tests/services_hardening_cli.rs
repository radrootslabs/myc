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
const PROCESS_SOURCE: &str = include_str!("../src/process_v1.rs");
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
        (vec!["run"], "run"),
        (vec!["config", "init"], "config_init"),
        (vec!["config", "validate"], "config_validate"),
        (vec!["config", "show"], "config_show"),
        (vec!["config", "schema"], "config_schema"),
        (
            vec!["config", "apply", "--candidate-config", "/candidate.toml"],
            "config_apply",
        ),
        (vec!["state", "init"], "state_init"),
        (vec!["state", "status"], "state_status"),
        (backup_command(), "state_backup"),
        (restore_command(), "state_restore"),
        (vec!["state", "verify"], "state_verify"),
        (vec!["state", "migrate"], "state_migrate"),
        (
            vec!["identity", "init", "--role", "transport"],
            "identity_init",
        ),
        (
            vec!["identity", "status", "--role", "user"],
            "identity_status",
        ),
        (
            vec!["identity", "export-public", "--role", "discovery"],
            "identity_export_public",
        ),
        (vec!["status"], "status"),
        (vec!["doctor"], "doctor"),
    ];

    for (arguments, expected) in vectors {
        assert_eq!(
            command_name(
                parse_myc_cli_v1_from(base(&arguments))
                    .expect("governed command")
                    .command()
            ),
            expected
        );
    }
}

fn backup_command() -> Vec<&'static str> {
    vec![
        "state",
        "backup",
        "--operation-id",
        "backup-01",
        "--target",
        "/backup/new",
        "--expected-generation",
        "7",
        "--confirm",
    ]
}

fn restore_command() -> Vec<&'static str> {
    vec![
        "state",
        "restore",
        "--manifest",
        "/backup/manifest.json",
        "--manifest-sha256",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "--bundle",
        "/backup/bundle",
        "--maximum-state-bytes",
        "1048576",
        "--confirm",
    ]
}

fn command_name(command: &MycCommandV1) -> &'static str {
    match command {
        MycCommandV1::Run => "run",
        MycCommandV1::Config(MycConfigCommandV1::Init) => "config_init",
        MycCommandV1::Config(MycConfigCommandV1::Validate) => "config_validate",
        MycCommandV1::Config(MycConfigCommandV1::Show) => "config_show",
        MycCommandV1::Config(MycConfigCommandV1::Schema) => "config_schema",
        MycCommandV1::Config(MycConfigCommandV1::Apply(_)) => "config_apply",
        MycCommandV1::State(MycStateCommandV1::Init) => "state_init",
        MycCommandV1::State(MycStateCommandV1::Status) => "state_status",
        MycCommandV1::State(MycStateCommandV1::Backup(_)) => "state_backup",
        MycCommandV1::State(MycStateCommandV1::Restore(_)) => "state_restore",
        MycCommandV1::State(MycStateCommandV1::Verify) => "state_verify",
        MycCommandV1::State(MycStateCommandV1::Migrate) => "state_migrate",
        MycCommandV1::Identity(MycIdentityCommandV1::Init(_)) => "identity_init",
        MycCommandV1::Identity(MycIdentityCommandV1::Status(_)) => "identity_status",
        MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic(_)) => "identity_export_public",
        MycCommandV1::Status => "status",
        MycCommandV1::Doctor => "doctor",
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
            "config apply",
            vec!["config", "apply", "--candidate-config", "/candidate.toml"],
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
            backup_command(),
            "live_unix_admin",
            Some("state_read_only"),
            Some("/v1/state/backup"),
            true,
        ),
        (
            "state restore",
            restore_command(),
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
            vec!["identity", "init", "--role", "transport"],
            "offline",
            Some("identity_exclusive"),
            None,
            false,
        ),
        (
            "identity status",
            vec!["identity", "status", "--role", "user"],
            "live_unix_admin",
            Some("identity_read_only"),
            Some("/v1/identity/status"),
            true,
        ),
        (
            "identity export-public",
            vec!["identity", "export-public", "--role", "discovery"],
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
            "bootstrap",
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
    assert_eq!(
        dispatch.get("bootstrap"),
        Some(&serde_json::json!({
            "output_modes": ["human", "json"],
            "default_output_mode": "human",
            "stdout": "results_only",
            "stderr": "diagnostics_only",
            "config_init": {
                "source": "bounded_nonsecret_toml_stdin",
                "persistence": "create_new_selected_path_mode_0600_file_and_parent_sync",
            },
            "config_loader": {
                "path": "selected_absolute_explicit_or_canonical_default",
                "maximum_utf8_bytes": 1048576,
                "no_follow": true,
                "regular_file": true,
                "single_link": true,
                "effective_user_owner": true,
                "group_or_other_write": false,
                "revalidate_after_read": ["parent_device_inode", "file_device_inode", "file_length"],
            },
            "config_apply": {
                "candidate_argument": "--candidate-config_absolute_path",
                "current_source": "selected_config_path",
                "mutates_config_files": false,
            },
            "identity": {
                "role_argument": "--role_transport_user_discovery",
                "init_provider": "configured_encrypted_file_only",
                "init_secret_source": "stdin_fixed_binary_v1_117_bytes",
            },
            "state_init": {
                "source_generation": "system_entropy_nonzero_32_bytes",
                "created_at": "system_wall_clock",
                "existing_state_open": "sealed_intent_discovers_actual_metadata",
            },
            "runtime": {
                "owner": "myc_binary",
                "count_per_process": 1,
                "worker_threads_default": 4,
                "worker_threads_range": [2, 32],
                "blocking_threads_default": 8,
                "blocking_threads_range": [1, 32],
                "cpu_derived_defaults": false,
            },
            "backup": {
                "operation_id_argument": "--operation-id",
                "target_argument": "--target-new-absolute-directory",
                "expected_generation_argument": "--expected-generation",
                "confirmation_argument": "--confirm",
                "offline_stdout": "exact_canonical_manifest_bytes_no_trailing_newline",
            },
            "restore": {
                "manifest_argument": "--manifest-absolute-file",
                "manifest_digest_argument": "--manifest-sha256",
                "bundle_argument": "--bundle-absolute-directory",
                "maximum_state_bytes_argument": "--maximum-state-bytes",
                "confirmation_argument": "--confirm",
                "expected_identity_source": "trusted_digest_bound_manifest_before_live_database_open",
            },
            "run": {
                "config_source": "secure_selected_path_loader",
                "runtime_owner": "myc_binary",
                "graph_owner": "myc-runtime-graph-shutdown",
            },
            "unsupported_command_success": false,
        }))
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
        "export-public",
        "--role",
        "discovery",
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
        base(&["identity", "rekey"]),
        base(&["identity", "replace"]),
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
    assert_eq!(MAIN_SOURCE.matches("execute_myc_cli_v1").count(), 1);
    assert_eq!(
        PROCESS_SOURCE
            .matches("plan_myc_cli_v1(&invocation)")
            .count(),
        1
    );
    for forbidden in ["sqlx::", "open_myc_state_", "MycStateHost"] {
        assert!(!MAIN_SOURCE.contains(forbidden), "found `{forbidden}`");
    }

    let root = include_str!("../src/lib.rs");
    assert!(root.contains("mod cli_v1;"));
    assert!(!root.contains("pub mod cli_v1;"));
}
