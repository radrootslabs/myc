#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MycConfigDocumentV1, MycConfigProfile, MycEncryptedIdentityProvisioningMaterial,
    MycProviderKind, MycProviderRole, MycRuntimeFoundationErrorKind, MycRuntimePrerequisite,
    MycStateMetadata, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    initialize_myc_state, open_myc_runtime_foundation, open_myc_state_read_write,
    parse_myc_cli_v1_from, parse_myc_config_v1, provision_myc_encrypted_identity,
    resolve_myc_runtime_context, resolve_myc_wrapping_credential,
};
use nostr::{Keys, SecretKey};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use serde_json::json;

const FOUNDATION_SOURCE: &str = include_str!("../src/runtime_foundation.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const CONTRACT_SOURCE: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");
const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

const TRANSPORT_ENCRYPTED: &str = r#"[identity.transport]
provider = "encrypted_file"
envelope_path = "/var/lib/radroots/services/myc/primary/secrets/transport.identity.ncrypt"
credential_reference = "transport_wrapping_key"
expected_public_key = "4444444444444444444444444444444444444444444444444444444444444444""#;

const DISCOVERY_ENCRYPTED: &str = r#"[identity.discovery.binding]
provider = "encrypted_file"
envelope_path = "/var/lib/radroots/services/myc/primary/secrets/discovery.identity.ncrypt"
credential_reference = "discovery_wrapping_key"
expected_public_key = "3333333333333333333333333333333333333333333333333333333333333333""#;

fn runtime(root: &Path) -> myc::MycRuntimeContext {
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root.to_str().expect("UTF-8 temporary root"),
        "run",
    ])
    .expect("valid test invocation");
    resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn prepare_state_directory(runtime: &myc::MycRuntimeContext) {
    let directory = runtime.context().paths().state();
    fs::create_dir_all(directory).expect("state directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("state mode");
}

fn local_transport_block(root: &Path) -> String {
    format!(
        r#"[identity.transport]
provider = "local_signer"
socket_path = "{}"
request_deadline_ms = 15000
request_max_bytes = 65536
response_max_bytes = 1048576
concurrency = 32
expected_public_key = "4444444444444444444444444444444444444444444444444444444444444444""#,
        root.join("transport-signer.sock").display()
    )
}

fn local_discovery_block(root: &Path) -> String {
    format!(
        r#"[identity.discovery.binding]
provider = "local_signer"
socket_path = "{}"
request_deadline_ms = 15000
request_max_bytes = 65536
response_max_bytes = 1048576
concurrency = 32
expected_public_key = "3333333333333333333333333333333333333333333333333333333333333333""#,
        root.join("discovery-signer.sock").display()
    )
}

fn all_local_source(root: &Path) -> String {
    let transport = local_transport_block(root);
    let discovery = local_discovery_block(root);
    let source = CONFIG_EXAMPLE
        .replacen(TRANSPORT_ENCRYPTED, &transport, 1)
        .replacen(DISCOVERY_ENCRYPTED, &discovery, 1);
    assert!(!source.contains(TRANSPORT_ENCRYPTED));
    assert!(!source.contains(DISCOVERY_ENCRYPTED));
    source
}

fn all_local_configuration(root: &Path) -> MycConfigDocumentV1 {
    parse_myc_config_v1(
        all_local_source(root).as_bytes(),
        MycConfigProfile::RepoLocal,
    )
    .expect("all-local configuration")
}

fn example_configuration() -> MycConfigDocumentV1 {
    parse_myc_config_v1(CONFIG_EXAMPLE.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("example configuration")
}

fn metadata(
    runtime: &myc::MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> MycStateMetadata {
    MycStateMetadata::new(
        runtime,
        configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "d287d41c2cd97cd0e455445da90f22180029f089",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        myc::MYC_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

#[tokio::test]
async fn foundation_owns_existing_state_and_never_claims_unproven_readiness() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let configuration = all_local_configuration(directory.path());
    let state_metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("state initialization");

    let foundation = open_myc_runtime_foundation(
        runtime.clone(),
        configuration,
        state_metadata.clone(),
        applied_at,
        &build,
    )
    .await
    .expect("existing-state foundation");
    for role in [
        MycProviderRole::Transport,
        MycProviderRole::User,
        MycProviderRole::Discovery,
    ] {
        assert_eq!(
            foundation.provider_kind(role),
            Some(MycProviderKind::LocalSigner)
        );
    }
    assert!(!foundation.readiness().is_ready());
    assert_eq!(
        foundation.readiness().required(),
        [
            MycRuntimePrerequisite::ExistingState,
            MycRuntimePrerequisite::TransportProvider,
            MycRuntimePrerequisite::UserProvider,
            MycRuntimePrerequisite::DiscoveryProvider,
            MycRuntimePrerequisite::OutboxRecovery,
            MycRuntimePrerequisite::RequiredRelayConnectivity,
            MycRuntimePrerequisite::RequiredRelaySubscription,
            MycRuntimePrerequisite::AdminListener,
        ]
    );
    assert_eq!(
        foundation.readiness().satisfied(),
        [MycRuntimePrerequisite::ExistingState]
    );
    assert_eq!(
        foundation
            .readiness()
            .reasons()
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>(),
        [
            "admin_listener_failed",
            "outbox_invariant_failed",
            "required_relay_unavailable",
            "signer_provider_unavailable",
            "subscriber_not_active",
        ]
    );

    let rendered = format!("{foundation:?}");
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains("transport-signer.sock"));
    assert!(!rendered.contains("4444444444444444"));

    let contended = open_myc_state_read_write(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect_err("foundation retains writer authority");
    assert_eq!(contended.kind(), myc::MycStateHostErrorKind::ReadWriteOpen);

    foundation.shutdown().await.expect("joined shutdown");
    let reopened = open_myc_state_read_write(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("authority released after joined shutdown");
    reopened.close().await.expect("reopened state close");
}

#[tokio::test]
async fn missing_state_and_configuration_mismatch_fail_without_mutation_or_lock_leak() {
    let missing_directory = tempfile::tempdir().expect("missing temporary root");
    let missing_runtime = runtime(missing_directory.path());
    prepare_state_directory(&missing_runtime);
    let missing_configuration = all_local_configuration(missing_directory.path());
    let missing_metadata = metadata(&missing_runtime, &missing_configuration);
    let (applied_at, build) = migration_evidence();
    let missing = open_myc_runtime_foundation(
        missing_runtime.clone(),
        missing_configuration,
        missing_metadata,
        applied_at,
        &build,
    )
    .await
    .expect_err("run never initializes missing state");
    assert_eq!(missing.kind(), MycRuntimeFoundationErrorKind::StateOpen);
    assert!(!missing_runtime.artifacts().state_database().exists());

    let directory = tempfile::tempdir().expect("mismatch temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let original = all_local_configuration(directory.path());
    let state_metadata = metadata(&runtime, &original);
    initialize_myc_state(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let changed_source = CONFIG_EXAMPLE.replacen("level = \"info\"", "level = \"debug\"", 1);
    let changed = parse_myc_config_v1(changed_source.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("changed configuration");
    let mismatch = open_myc_runtime_foundation(
        runtime.clone(),
        changed,
        state_metadata.clone(),
        applied_at,
        &build,
    )
    .await
    .expect_err("configuration digest mismatch");
    assert_eq!(
        mismatch.kind(),
        MycRuntimeFoundationErrorKind::InvalidBinding
    );
    assert!(Error::source(&mismatch).is_none());

    let reopened = open_myc_state_read_write(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("mismatch fails before writer acquisition");
    reopened.close().await.expect("reopened state close");
}

#[tokio::test]
async fn joined_encrypted_provider_failure_closes_the_already_open_state() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let configuration = example_configuration();
    let state_metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("state initialization");

    let failure = open_myc_runtime_foundation(
        runtime.clone(),
        configuration,
        state_metadata.clone(),
        applied_at,
        &build,
    )
    .await
    .expect_err("missing credential artifacts fail provider startup");
    assert_eq!(failure.kind(), MycRuntimeFoundationErrorKind::Provider);
    assert!(Error::source(&failure).is_none());

    let reopened = open_myc_state_read_write(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("failed provider startup closes state");
    reopened.close().await.expect("reopened state close");
}

#[tokio::test]
async fn joined_encrypted_provider_success_is_retained_as_proven_startup_evidence() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);

    let identity_secret = [1_u8; 32];
    let public_key = Keys::new(SecretKey::from_slice(&identity_secret).expect("identity secret"))
        .public_key()
        .to_hex();
    let envelope_parent = directory.path().join("envelopes");
    fs::create_dir(&envelope_parent).expect("envelope parent");
    fs::set_permissions(&envelope_parent, fs::Permissions::from_mode(0o700))
        .expect("envelope parent mode");
    let envelope_path = envelope_parent.join("transport.identity.ncrypt");
    let transport_encrypted = format!(
        r#"[identity.transport]
provider = "encrypted_file"
envelope_path = "{}"
credential_reference = "transport_wrapping_key"
expected_public_key = "{}""#,
        envelope_path.display(),
        public_key
    );
    let source = all_local_source(directory.path()).replacen(
        &local_transport_block(directory.path()),
        &transport_encrypted,
        1,
    );
    let configuration = parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("mixed provider configuration");
    let binding = configuration
        .provider_contract()
        .binding(MycProviderRole::Transport)
        .expect("transport binding");

    let secrets = runtime.context().paths().secrets();
    fs::create_dir_all(secrets).expect("secrets directory");
    fs::set_permissions(secrets, fs::Permissions::from_mode(0o700))
        .expect("secrets directory mode");
    let credential_path = secrets.join("transport_wrapping_key");
    fs::write(&credential_path, [9_u8; 32]).expect("offline credential fixture");
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))
        .expect("credential mode");
    let credential =
        resolve_myc_wrapping_credential(&runtime, binding).expect("credential resolution");
    let material = MycEncryptedIdentityProvisioningMaterial::new(
        identity_secret,
        [2_u8; 32],
        [3_u8; 24],
        [4_u8; 24],
    )
    .expect("provisioning material");
    provision_myc_encrypted_identity(binding, &credential, material)
        .expect("offline envelope provisioning");

    let state_metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &state_metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let foundation =
        open_myc_runtime_foundation(runtime, configuration, state_metadata, applied_at, &build)
            .await
            .expect("joined encrypted-provider startup");
    assert_eq!(
        foundation.provider_kind(MycProviderRole::Transport),
        Some(MycProviderKind::EncryptedFile)
    );
    assert!(
        foundation
            .readiness()
            .satisfied()
            .contains(&MycRuntimePrerequisite::TransportProvider)
    );
    assert!(!foundation.readiness().is_ready());
    foundation.shutdown().await.expect("joined shutdown");
}

#[test]
fn machine_contract_and_source_keep_the_foundation_sealed_and_deferred() {
    let contract: serde_json::Value =
        serde_json::from_str(CONTRACT_SOURCE).expect("runtime-foundation contract");
    assert_eq!(
        contract,
        json!({
            "schema": "radroots.myc.runtime-foundation",
            "schema_version": 1,
            "contract_version": 1,
            "state_open": {
                "mode": "read_write_existing",
                "initialize_if_missing": false,
                "raw_sqlite_authority_exposed": false
            },
            "provider_startup": {
                "encrypted_file": "supervised_joined_one_shot",
                "local_signer": "constructed_without_io_pending_handshake",
                "database_transaction_held": false,
                "detached_tasks": false,
                "protected_values_exposed": false
            },
            "readiness_prerequisites": [
                { "id": "existing_state", "condition": "always", "reason": "database_schema_mismatch" },
                { "id": "transport_provider", "condition": "always", "reason": "signer_provider_unavailable" },
                { "id": "user_provider", "condition": "always", "reason": "signer_provider_unavailable" },
                { "id": "discovery_provider", "condition": "discovery_enabled", "reason": "signer_provider_unavailable" },
                { "id": "outbox_recovery", "condition": "always", "reason": "outbox_invariant_failed" },
                { "id": "required_relay_connectivity", "condition": "required_relay_present", "reason": "required_relay_unavailable" },
                { "id": "required_relay_subscription", "condition": "required_read_relay_present", "reason": "subscriber_not_active" },
                { "id": "admin_listener", "condition": "always", "reason": "admin_listener_failed" },
                { "id": "operations_listener", "condition": "operations_enabled", "reason": "operations_listener_failed" }
            ],
            "initial_satisfaction": {
                "existing_state": "after_exact_existing_open",
                "encrypted_file_provider": "after_joined_identity_verification",
                "local_signer_provider": "not_before_verified_describe_handshake",
                "remaining_prerequisites": "later_owning_rcld"
            },
            "task_ownership": {
                "shared_supervisor": "radroots_service_host::TaskSupervisor",
                "startup_tasks": "one_shot",
                "lifetime_task": "critical_until_cancellation",
                "task_handles_exposed": false,
                "library_runtime_creation": false,
                "signal_installation": false,
                "process_exit": false
            },
            "deferred": [
                "provider_handshake",
                "outbox_recovery",
                "relay_connectivity",
                "relay_subscription",
                "admin_listener",
                "operations_listener",
                "cached_status",
                "signals",
                "final_supervised_task_graph"
            ]
        })
    );

    assert!(LIB_SOURCE.contains("mod runtime_foundation;"));
    assert!(!LIB_SOURCE.contains("pub mod runtime_foundation;"));
    for required in [
        "TaskSupervisor::new()",
        "TaskClassification::OneShot",
        "thread.join()",
        "open_myc_state_read_write",
    ] {
        assert!(
            FOUNDATION_SOURCE.contains(required),
            "missing required foundation boundary `{required}`"
        );
    }
    for forbidden in [
        "tokio::spawn",
        "spawn_blocking",
        "JoinHandle",
        "Runtime::new",
        "process::exit",
        "pub fn pool",
        "pub fn connection",
        "AdminServer::",
        "TcpListener",
    ] {
        assert!(
            !FOUNDATION_SOURCE.contains(forbidden),
            "found deferred or escaping authority `{forbidden}`"
        );
    }
}
