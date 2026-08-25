#![forbid(unsafe_code)]

use std::collections::BTreeSet;

const ROOT: &str = include_str!("../src/lib.rs");
const README: &str = include_str!("../README");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/myc.txt");
const ADMIN_V1: &str = include_str!("../src/admin_v1.rs");
const CONTROL_SURFACES_CONTRACT: &str =
    include_str!("../contracts/services_hardening/control_surfaces.v1.json");
const NIP46_VERIFICATION: &str = include_str!("../src/nip46_verification.rs");
const NIP46_AUTHORIZATION: &str = include_str!("../src/nip46_authorization.rs");
const NIP46_REPLAY: &str = include_str!("../src/nip46_replay.rs");
const NIP46_WORK: &str = include_str!("../src/nip46_work.rs");
const NIP46_WAVE_080_A: &str = include_str!("../src/nip46_wave_080_a.rs");
const NIP46_COMPLETION: &str = include_str!("../src/state_completion.rs");
const NIP46_RESPONSE: &str = include_str!("../src/state_response.rs");
const STATE_CATALOG: &str = include_str!("../src/state_catalog.rs");
const DELIVERY_RECOVERY: &str = include_str!("../src/state_recovery.rs");
const DELIVERY_WORKER: &str = include_str!("../src/delivery_worker.rs");
const PROVIDER_EXECUTOR: &str = include_str!("../src/provider_executor.rs");
const TRANSPORT_NOSTR_ADAPTER: &str = include_str!("../src/transport_nostr_adapter.rs");
const PROVIDER_DELIVERY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/provider_delivery.v1.json");
const DOCTOR_V1: &str = include_str!("../src/doctor_v1.rs");
const CONTROL_PLANE_WAVE_090_A: &str = include_str!("../src/control_plane_wave_090_a.rs");
const CONTROL_PLANE_WAVE_090_A_CONTRACT: &str =
    include_str!("../contracts/services_hardening/control_plane_wave_090_a.v1.json");
const DIAGNOSTICS_V1: &str = include_str!("../src/diagnostics_v1.rs");
const DIAGNOSTICS_CONTRACT: &str =
    include_str!("../contracts/services_hardening/diagnostics.v1.json");
const MAIN: &str = include_str!("../src/main.rs");
const PROCESS_V1: &str = include_str!("../src/process_v1.rs");
const PROCESS_V1_UNSUPPORTED: &str = include_str!("../src/process_v1_unsupported.rs");
const CONFIG_LOADER: &str = include_str!("../src/config_loader.rs");
const SYSTEM_DOCTOR: &str = include_str!("../src/system_doctor.rs");
const STATUS_V1: &str = include_str!("../src/status_v1.rs");
const RUNTIME_GRAPH: &str = include_str!("../src/runtime_graph.rs");
const RUNTIME_NIP46: &str = include_str!("../src/runtime_nip46.rs");
const RUNTIME_SIGNAL: &str = include_str!("../src/runtime_signal.rs");
const RUNTIME_SUPERVISION: &str = include_str!("../src/runtime_supervision.rs");
const RUNTIME_SUPERVISION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_supervision.v1.json");
const STATUS_CONTRACT: &str = include_str!("../contracts/services_hardening/status_cache.v1.json");
const OPERATIONS_V1: &str = include_str!("../src/operations_v1.rs");
const OPERATIONS_CONTRACT: &str =
    include_str!("../contracts/services_hardening/tcp_operations.v1.json");
const DISCOVERY_STATE: &str = include_str!("../src/state_discovery.rs");
const NIP46_VERIFICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_verification.v1.json");
const NIP46_REPLAY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_replay.v1.json");
const NIP46_AUTHORIZATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_authorization.v1.json");
const NIP46_WORK_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_work.v1.json");
const NIP46_WAVE_080_A_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_wave_080_a.v1.json");
const NIP46_COMPLETION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_completion.v1.json");
const NIP46_RESPONSE_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_response_commit.v1.json");
const NIP46_PENDING_RESPONSE_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_pending_response.v1.json");
const DELIVERY_RECOVERY_EXPORT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/delivery_recovery_export.v1.json");
const PROCESS_QUALIFICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/process_qualification.v1.json");
const SOURCES: &[&str] = &[
    include_str!("../src/admin_v1.rs"),
    include_str!("../src/cli_bootstrap.rs"),
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_loader.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/control_plane_wave_090_a.rs"),
    include_str!("../src/delivery_worker.rs"),
    include_str!("../src/doctor_v1.rs"),
    include_str!("../src/diagnostics_v1.rs"),
    include_str!("../src/nip46_admission.rs"),
    include_str!("../src/nip46_authorization.rs"),
    include_str!("../src/nip46_replay.rs"),
    include_str!("../src/nip46_verification.rs"),
    include_str!("../src/nip46_work.rs"),
    include_str!("../src/nip46_wave_080_b.rs"),
    include_str!("../src/operations_v1.rs"),
    include_str!("../src/process_v1.rs"),
    include_str!("../src/process_v1_unsupported.rs"),
    include_str!("../src/provider_contract.rs"),
    include_str!("../src/provider_credential.rs"),
    include_str!("../src/provider_envelope.rs"),
    include_str!("../src/provider_executor.rs"),
    include_str!("../src/provider_local_signer.rs"),
    include_str!("../src/provider_verification.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/runtime_foundation.rs"),
    include_str!("../src/runtime_graph.rs"),
    include_str!("../src/runtime_nip46.rs"),
    include_str!("../src/runtime_signal.rs"),
    include_str!("../src/runtime_supervision.rs"),
    include_str!("../src/status_v1.rs"),
    include_str!("../src/system_doctor.rs"),
    include_str!("../src/transport_nostr_adapter.rs"),
    include_str!("../src/state_catalog.rs"),
    include_str!("../src/state_admin.rs"),
    include_str!("../src/state_completion.rs"),
    include_str!("../src/state_config.rs"),
    include_str!("../src/state_connection.rs"),
    include_str!("../src/state_delivery.rs"),
    include_str!("../src/state_discovery.rs"),
    include_str!("../src/state_governance.rs"),
    include_str!("../src/state_host.rs"),
    include_str!("../src/state_maintenance.rs"),
    include_str!("../src/state_metadata.rs"),
    include_str!("../src/state_repository.rs"),
    include_str!("../src/state_recovery.rs"),
    include_str!("../src/state_request.rs"),
    include_str!("../src/state_response.rs"),
];

#[test]
fn implementation_modules_are_private_and_rustdoc_uses_the_reviewed_readme() {
    assert_eq!(
        ROOT.lines()
            .filter_map(|line| line.strip_prefix("mod "))
            .filter_map(|line| line.strip_suffix(';'))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "admin_v1",
            "cli_bootstrap",
            "cli_v1",
            "config_loader",
            "config_v1",
            "control_plane_wave_090_a",
            "delivery_worker",
            "doctor_v1",
            "diagnostics_v1",
            "nip46_admission",
            "nip46_authorization",
            "nip46_replay",
            "nip46_verification",
            "nip46_work",
            "nip46_wave_080_a",
            "nip46_wave_080_b",
            "operations_v1",
            "process_v1",
            "provider_contract",
            "provider_credential",
            "provider_envelope",
            "provider_executor",
            "provider_local_signer",
            "provider_verification",
            "runtime_context",
            "runtime_foundation",
            "runtime_graph",
            "runtime_nip46",
            "runtime_signal",
            "runtime_supervision",
            "status_v1",
            "system_doctor",
            "transport_nostr_adapter",
            "state_catalog",
            "state_admin",
            "state_completion",
            "state_config",
            "state_connection",
            "state_delivery",
            "state_discovery",
            "state_governance",
            "state_host",
            "state_maintenance",
            "state_metadata",
            "state_repository",
            "state_recovery",
            "state_request",
            "state_response",
        ])
    );
    assert!(!ROOT.contains("pub mod "));
    assert!(ROOT.contains("#![doc = include_str!(\"../README\")]"));

    for required in [
        "## Public API boundary",
        "one curated crate-root API",
        "public errors use Myc-owned stable classifications",
        "```compile_fail",
        "[Myc API baseline](contracts/api_baselines/myc.txt)",
        "Status publication and cached snapshots can be obtained only",
        "Schema v10 adds an append-only configuration-binding history capped at exactly\n1,024 generations",
        "Exact replay returns the retained generation without another\nappend or revocation",
        "Future startup\nmust present the latest normalized config and public-identity binding",
        "Schema v11 adds the bounded admin-operation journal",
        "at most 128 unresolved Prepared records and 4,096 completed responses",
        "caps a\nreplayed response model at 8,192 bytes",
        "admits at least 8,382 UTF-8 bytes",
        "The journal stores no request body, path,\ncorrelation ID, credential, bundle path, or secret",
        "Schema v12 adds immutable response authority for a connect request awaiting\nexplicit approval",
        "without recording a false terminal operation completion",
        "Exact\nreplay and delivery use only the retained signed bytes",
        "The Step 159 provider and delivery boundary is sealed inside the crate",
        "persists Submitted immediately before execution",
        "The selected absolute config path is opened no-follow through its retained\nparent descriptor",
        "One binary-owned Tokio runtime is created from the validated fixed thread\nlimits",
        "Restore derives expected backup identity\nfrom the trusted manifest digest",
        "The production adapter composes secure path and disk inspection",
        "It never publishes a relay event",
        "The production `run` path owns the exact five-role bounded graph",
        "Required relay subscriptions and provider handshakes complete before\nReady",
        "one configured absolute graceful-shutdown deadline",
        "## Executable qualification",
        "eight\nconcurrent inspection processes, 32 deterministic reopen iterations, and one\n64 MiB crash fixture",
        "without adding a production\nfailpoint, hidden command, environment selector, feature, or detached test\nworker",
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
    }
}

#[test]
fn step161_qualification_is_machine_bound_without_a_production_test_surface() {
    let contract: serde_json::Value =
        serde_json::from_str(PROCESS_QUALIFICATION_CONTRACT).expect("qualification contract");
    assert_eq!(contract["schema"], "radroots.myc.process-qualification.v1");
    assert_eq!(contract["step"], 161);
    assert_eq!(contract["invariants"]["actual_executable_required"], true);
    assert_eq!(
        contract["invariants"]["production_failpoint_surface"],
        false
    );
    assert_eq!(contract["invariants"]["test_environment_selector"], false);
    for source in SOURCES.iter().copied().chain([ROOT, MAIN]) {
        for forbidden in [
            "MYC_TEST_",
            "MYC_FAILPOINT",
            "process_qualification_failpoint",
            "qualification-only-command",
        ] {
            assert!(
                !source.contains(forbidden),
                "production source contains `{forbidden}`"
            );
        }
    }
}

#[test]
fn step159_runtime_graph_is_fixed_joined_and_binary_signal_owned() {
    for required in [
        "const TASK_ADMIN_SERVER: &str = \"admin_server\"",
        "const TASK_OPERATIONS_SERVER: &str = \"operations_server\"",
        "const TASK_RELAY_INGRESS: &str = \"relay_ingress\"",
        "const TASK_PROVIDER_DISPATCH: &str = \"provider_dispatch\"",
        "const TASK_DELIVERY_OUTBOX: &str = \"delivery_outbox\"",
        "open_initial_subscriptions(&ingress_adapter, &configuration).await",
        "required_relays_ready(slots)",
        "MycRuntimeNip46Coordinator::new",
        "let admission_evidence = runtime_nip46_admission_evidence()",
        "let mut retry = initial",
        "GracefulShutdown::new(grace)",
        "ProcessSignalAdapter::new(HostSignalSource::new(signals))",
        "publish(MycServicePhase::Ready)",
    ] {
        assert!(RUNTIME_GRAPH.contains(required), "missing `{required}`");
    }
    assert_eq!(RUNTIME_GRAPH.matches(".spawn(").count(), 5);
    assert!(RUNTIME_NIP46.contains("commit_nip46_response(&commit)"));
    assert!(RUNTIME_NIP46.contains("ExactResponseReplay"));
    assert!(RUNTIME_NIP46.contains("admission_evidence: MycRuntimeNip46AdmissionEvidence"));
    assert!(RUNTIME_SIGNAL.contains("pub trait MycProcessSignalSource: Send"));
    for forbidden in [
        "tokio::spawn",
        "spawn_blocking",
        "std::thread::spawn",
        "std::process::exit",
    ] {
        assert!(!RUNTIME_GRAPH.contains(forbidden), "found `{forbidden}`");
    }
}

#[test]
fn reviewed_api_is_root_only_and_exposes_no_implementation_authority() {
    for required in [
        "pub struct myc::MycCliExecutionPlanV1",
        "pub enum myc::MycCliPrimaryAuthorityV1",
        "pub enum myc::MycCliOfflineOperationV1",
        "pub enum myc::MycCliAdminOperationV1",
        "pub const fn myc::plan_myc_cli_v1",
        "pub enum myc::MycCliOutputModeV1",
        "pub struct myc::MycConfigApplyArgsV1",
        "pub struct myc::MycStateBackupArgsV1",
        "pub struct myc::MycStateRestoreArgsV1",
        "pub struct myc::MycIdentityCommandArgsV1",
        "pub struct myc::MycRuntimeThreadLimitsV1",
        "pub struct myc::MycConfigLoadError",
        "pub enum myc::MycConfigLoadErrorKind",
        "pub fn myc::execute_myc_cli_v1",
        "pub fn myc::initialize_myc_config_document",
        "pub fn myc::load_myc_config_candidate",
        "pub fn myc::load_myc_config_document",
        "pub struct myc::MycDoctorReport",
        "pub struct myc::MycLogRecord",
        "pub enum myc::MycLogEvent",
        "pub enum myc::MycLogLevel",
        "pub enum myc::MycProcessResult",
        "pub struct myc::MycDoctorCheckDefinition",
        "pub struct myc::MycDoctorCheckResult",
        "pub enum myc::MycDoctorCheckId",
        "pub enum myc::MycDoctorCheckStatus",
        "pub enum myc::MycDoctorAggregateStatus",
        "pub enum myc::MycDoctorObservation",
        "pub enum myc::MycDoctorRemediationCode",
        "pub trait myc::MycDoctorProbe",
        "pub async fn myc::run_myc_doctor",
        "pub struct myc::MycStatusPublisher",
        "pub struct myc::MycStatusReader",
        "pub struct myc::MycStatusSnapshot",
        "pub struct myc::MycStatusCommonV1",
        "pub struct myc::MycStatusObservationV1",
        "pub fn myc::myc_status_cache",
        "pub struct myc::MycOperationsServer",
        "pub struct myc::MycBoundOperationsServer",
        "pub struct myc::MycOperationsCancellationToken",
        "pub struct myc::MycOperationsError",
        "pub enum myc::MycOperationsErrorKind",
        "pub struct myc::MycAdminRequestDocument",
        "pub struct myc::MycAdminResponseDocument",
        "pub enum myc::MycAdminMethod",
        "pub enum myc::MycAdminRoute",
        "pub trait myc::MycAdminHandler",
        "pub struct myc::MycAdminRouter",
        "pub fn myc::build_myc_admin_router",
        "pub struct myc::MycAdminServer",
        "pub struct myc::MycBoundAdminServer",
        "pub struct myc::MycAdminCancellationToken",
        "pub struct myc::MycAdminServerError",
        "pub enum myc::MycAdminServerErrorKind",
        "pub struct myc::MycRuntimeContext",
        "pub struct myc::MycRuntimeFoundation",
        "pub struct myc::MycRuntimeReadiness",
        "pub enum myc::MycRuntimeReadinessReason",
        "pub struct myc::MycBoundedNip46Event",
        "pub struct myc::MycBoundedNip46Request",
        "pub struct myc::MycNip46AdmissionLimits",
        "pub enum myc::MycNip46AdmissionErrorKind",
        "pub struct myc::MycVerifiedNip46Event",
        "pub struct myc::MycVerifiedNip46Request",
        "pub struct myc::MycNip46AuthoredTimePolicy",
        "pub struct myc::MycNip46ConnectionIdentity",
        "pub struct myc::MycNip46LogicalRequestIdentity",
        "pub struct myc::MycNip46ReplayKey",
        "pub struct myc::MycReplayBoundNip46Request",
        "pub enum myc::MycNip46ReplayDisposition",
        "pub enum myc::MycNip46VerificationErrorKind",
        "pub struct myc::MycNip46DecryptWork",
        "pub struct myc::MycDecryptedNip46Request",
        "pub struct myc::MycPreparedNip46Request",
        "pub struct myc::MycNip46Work",
        "pub enum myc::MycNip46WorkKind",
        "pub enum myc::MycNip46WorkErrorKind",
        "pub struct myc::MycNip46WorkError",
        "pub struct myc::MycStateHost",
        "pub struct myc::MycStateRepository",
        "pub struct myc::MycPreparedAdminOperation",
        "pub enum myc::MycAdminOperationAdmission",
        "pub enum myc::MycAdminOperationCompletion",
        "pub struct myc::MycAdminOperationJournalPolicy",
        "pub struct myc::MycAdminOperationTimeUnixMs",
        "pub struct myc::MycAdminOperationError",
        "pub enum myc::MycAdminOperationErrorKind",
        "pub const myc::MYC_ADMIN_OPERATION_RESPONSE_ENVELOPE_MAX_UTF8_BYTES: u32",
        "pub async fn myc::MycStateRepository<'_>::prepare_admin_operation",
        "pub async fn myc::MycStateRepository<'_>::complete_admin_operation",
        "pub const myc::MYC_CONFIG_BINDING_MAX_GENERATIONS: u16",
        "pub struct myc::MycConfigApplyOutcome",
        "pub struct myc::MycConfigApplyError",
        "pub enum myc::MycConfigApplyErrorKind",
        "pub async fn myc::MycStateRepository<'_>::apply_configuration",
        "pub struct myc::MycNip46CommitRequest",
        "pub struct myc::MycNip46CommitRecord",
        "pub enum myc::MycNip46CommitAdmission",
        "pub enum myc::MycNip46SessionEffect",
        "pub enum myc::MycNip46CommitErrorKind",
        "pub struct myc::MycNip46ResponseCommitRequest",
        "pub struct myc::MycNip46ResponseRecord",
        "pub struct myc::MycNip46ResponseCommitRecord",
        "pub enum myc::MycNip46ResponseCommitAdmission",
        "pub enum myc::MycNip46ResponseCommitErrorKind",
        "pub async fn myc::MycStateRepository<'_>::commit_nip46_response",
        "pub async fn myc::MycStateRepository<'_>::read_nip46_response",
        "pub const myc::MYC_STATE_SCHEMA_VERSION_12_MIGRATION_SHA256: [u8; 32]",
        "pub const myc::MYC_STATE_SCHEMA_VERSION_12_OBJECT_COUNT: u32",
        "pub const myc::MYC_STATE_SCHEMA_VERSION_12_SHA256: [u8; 32]",
        "pub async fn myc::MycStateRepository<'_>::recover_delivery_state",
        "pub async fn myc::MycStateRepository<'_>::render_offline_nip05",
        "pub struct myc::MycDeliveryRecoveryEntropy",
        "pub struct myc::MycDeliveryRecoveryReport",
        "pub struct myc::MycNip05Document",
        "pub enum myc::MycNip05ExportSelection",
        "pub async fn myc::MycStateRepository<'_>::read_connection_decision",
        "pub fn myc::admit_myc_nip46_event",
        "pub fn myc::admit_myc_nip46_request",
        "pub fn myc::bind_myc_nip46_replay",
        "pub fn myc::prepare_myc_nip46_decrypt_work",
        "pub fn myc::prepare_myc_nip46_request",
        "pub fn myc::prepare_myc_nip46_work",
        "pub fn myc::verify_myc_nip46_event",
        "pub fn myc::verify_myc_nip46_request",
        "pub async fn myc::open_myc_runtime_foundation",
        "pub struct myc::MycCriticalTask",
        "pub struct myc::MycCriticalTaskError",
        "pub struct myc::MycRuntimeSupervisionError",
        "pub enum myc::MycRuntimeSupervisionErrorKind",
        "pub struct myc::MycSupervisedRuntime",
        "pub struct myc::MycTaskCancellation",
    ] {
        assert!(
            PUBLIC_API.contains(required),
            "reviewed API baseline is missing `{required}`"
        );
    }

    for module in [
        "admin_v1",
        "cli_bootstrap",
        "cli_v1",
        "config_loader",
        "config_v1",
        "control_plane_wave_090_a",
        "delivery_worker",
        "doctor_v1",
        "diagnostics_v1",
        "nip46_admission",
        "nip46_authorization",
        "nip46_replay",
        "nip46_verification",
        "nip46_work",
        "nip46_wave_080_a",
        "nip46_wave_080_b",
        "operations_v1",
        "process_v1",
        "provider_contract",
        "provider_credential",
        "provider_envelope",
        "provider_executor",
        "provider_local_signer",
        "provider_verification",
        "runtime_context",
        "runtime_foundation",
        "runtime_supervision",
        "status_v1",
        "system_doctor",
        "transport_nostr_adapter",
        "state_catalog",
        "state_admin",
        "state_completion",
        "state_config",
        "state_connection",
        "state_delivery",
        "state_discovery",
        "state_governance",
        "state_host",
        "state_maintenance",
        "state_metadata",
        "state_repository",
        "state_recovery",
        "state_request",
        "state_response",
    ] {
        assert!(
            !PUBLIC_API.contains(&format!("pub mod myc::{module}")),
            "implementation module `{module}` became public"
        );
        assert!(
            !PUBLIC_API.contains(&format!("myc::{module}::")),
            "implementation module `{module}` leaked into the public API"
        );
    }

    for forbidden in [
        "sqlx::",
        "serde::",
        "serde_json::",
        "futures_util::",
        "toml::",
        "url::",
        "nostr::",
        "radroots_secrets::",
        "radroots_service_host::",
        "TaskSupervisor",
        "SqlitePool",
        "SqliteConnection",
        "std::io::Error",
    ] {
        assert!(
            !PUBLIC_API.contains(forbidden),
            "implementation-owned public type `{forbidden}` escaped"
        );
    }
}

#[test]
fn status_cache_is_passive_latest_value_and_dependency_neutral() {
    for required in [
        "CachedServiceStatePublisher<MycCachedStatus>",
        "pub struct MycStatusPublisher",
        "pub struct MycStatusReader",
        "pub struct MycStatusSnapshot",
        "pub fn myc_status_cache(",
        "status.to_bounded_json()",
        ".publish(next.operations)",
        ".publish(next.detail)",
        "self.inner.snapshot()",
        "connection_counts: MycConnectionCountsV1",
        "oldest_pending_at_utc: Option<MycStatusUnixSeconds>",
        "MYC_STATUS_REASON_CODE_COUNT: usize = 12",
    ] {
        assert!(STATUS_V1.contains(required), "missing `{required}`");
    }
    for forbidden in [
        "sqlx::",
        "std::fs::",
        "tokio::spawn",
        "spawn_blocking",
        "std::time::SystemTime",
        "std::env::",
        "reqwest::",
        "url::Url",
        "provider.execute",
        "relay.connect",
        "dns",
    ] {
        assert!(!STATUS_V1.contains(forbidden), "found `{forbidden}`");
    }
    assert!(PUBLIC_API.contains("impl core::clone::Clone for myc::MycStatusReader"));
    assert!(!PUBLIC_API.contains("impl core::clone::Clone for myc::MycStatusPublisher"));
    assert!(!PUBLIC_API.contains("impl core::clone::Clone for myc::MycStatusSnapshot"));
    for required in [
        "identity_unavailable",
        "database_schema_mismatch",
        "database_read_only",
        "database_low_disk",
        "required_relay_unavailable",
        "subscriber_not_active",
        "signer_provider_unavailable",
        "outbox_invariant_failed",
        "publication_backlog_exceeded",
        "admin_listener_failed",
        "operations_listener_failed",
        "shutdown_in_progress",
    ] {
        assert!(
            STATUS_CONTRACT.contains(required),
            "status contract is missing `{required}`"
        );
    }
}

#[test]
fn step155_tcp_operations_are_exact_passive_and_dependency_neutral() {
    let contract: serde_json::Value =
        serde_json::from_str(OPERATIONS_CONTRACT).expect("Step 155 operations contract");
    assert_eq!(contract["schema"], "radroots.myc.tcp-operations.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 155);
    assert_eq!(contract["route_registration_extension"], false);
    for required in [
        "HostOperationsServer::new(listener, status.operations_cache())",
        "MycOperationsCancellationToken",
        "radroots_myc_service_phase",
        "radroots_myc_service_ready",
        "HostOperationsTransportLimits::new(values)",
        "HeaderLimitBelowParserFloor",
    ] {
        assert!(
            OPERATIONS_V1.contains(required) || STATUS_V1.contains(required),
            "Step 155 implementation is missing `{required}`"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs::",
        "tokio::spawn",
        "spawn_blocking",
        "SystemTime",
        "provider.execute",
        "relay.connect",
        "credential",
        "dns",
        "route(",
        "Router",
    ] {
        assert!(
            !OPERATIONS_V1.contains(forbidden),
            "Step 155 adapter gained forbidden authority `{forbidden}`"
        );
    }
    assert!(README.contains("exactly HTTP/1.1 `GET /livez`"));
    assert!(README.contains("Requests perform no SQLite"));
    assert!(!PUBLIC_API.contains("radroots_service_host::"));
}

#[test]
fn doctor_boundary_is_closed_bounded_and_dependency_neutral() {
    for required in [
        "MYC_DOCTOR_CHECK_COUNT: usize = 13",
        "MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES: usize = 256",
        "MYC_DOCTOR_REPORT_MAX_UTF8_BYTES: usize = 8_192",
        "for definition in CHECK_DEFINITIONS",
        "tokio::time::timeout(",
        "MycDoctorObservation::Skipped) if !definition.required",
        "MycDoctorObservation::Skipped) => MycDoctorCheckStatus::Fail",
    ] {
        assert!(DOCTOR_V1.contains(required), "missing `{required}`");
    }
    for forbidden in [
        "std::fs::",
        "sqlx::",
        "reqwest::",
        "url::Url",
        "std::env::",
        "raw_error",
        "PathBuf",
    ] {
        assert!(!DOCTOR_V1.contains(forbidden), "found `{forbidden}`");
    }
}

#[test]
fn step156_diagnostics_are_closed_stderr_only_and_whole_chain_redacted() {
    let contract: serde_json::Value =
        serde_json::from_str(DIAGNOSTICS_CONTRACT).expect("Step 156 diagnostics contract");
    assert_eq!(contract["schema"], "radroots.myc.diagnostics.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 156);
    assert_eq!(contract["stream_policy"]["result_data"], "stdout");
    assert_eq!(contract["stream_policy"]["logs_and_diagnostics"], "stderr");
    assert_eq!(contract["public_error_policy"]["error_source"], "none");
    for required in [
        "MYC_LOG_RECORD_MAX_UTF8_BYTES: usize = 512",
        "Self::Success => 0",
        "Self::DoctorRequiredCheckFailed => 6",
        "formatter.write_str(\"}\")",
        "MycLogRecord::process_result(result)",
    ] {
        assert!(
            DIAGNOSTICS_V1.contains(required) || MAIN.contains(required),
            "Step 156 implementation is missing `{required}`"
        );
    }
    assert!(MAIN.contains("eprintln!(\"{}\", MycLogRecord::process_result(result))"));
    for forbidden in [
        "process::exit",
        "{error}",
        "source()",
        "raw_error",
        "std::fs::",
        "sqlx::",
        "SystemTime",
    ] {
        assert!(
            !DIAGNOSTICS_V1.contains(forbidden) && !MAIN.contains(forbidden),
            "Step 156 diagnostic boundary gained `{forbidden}`"
        );
    }
    assert!(
        !MAIN
            .lines()
            .any(|line| line.trim_start().starts_with("println!("))
    );
    assert!(!SOURCES.join("\n").contains("fn source("));
    assert!(!PUBLIC_API.contains("std::io::Error"));
}

#[test]
fn step157_control_plane_wave_is_machine_bound_native_and_test_only() {
    let contract: serde_json::Value = serde_json::from_str(CONTROL_PLANE_WAVE_090_A_CONTRACT)
        .expect("Step 157 control-plane wave contract");
    assert_eq!(
        contract["schema"],
        "radroots.myc.control-plane-wave-090-a.v1"
    );
    assert_eq!(
        contract["steps"],
        serde_json::json!([152, 153, 154, 155, 156, 157])
    );
    assert_eq!(contract["gate"]["wave"], "090-a");
    assert_eq!(contract["gate"]["complete_after_step"], 157);
    assert_eq!(contract["gate"]["rcld_promotion_owner"], 162);
    assert!(ROOT.contains(
        "#[cfg(all(test, any(target_os = \"linux\", target_os = \"macos\")))]\nmod control_plane_wave_090_a;"
    ));
    for required in [
        "one_parse_offline_doctor",
        "required_doctor_failure_exits_6",
        "latest_cached_status_publication",
        "exact_passive_tcp_routes",
        "detailed_status_is_not_tcp_routable",
        "prevalidated_cached_value",
        "runtime_task_supervision",
    ] {
        assert!(
            CONTROL_PLANE_WAVE_090_A_CONTRACT.contains(required),
            "Step 157 corpus is missing `{required}`"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs::",
        "std::env::",
        "SystemTime",
        "reqwest::",
        "RelayPool",
        "provider_local_signer",
        "process::exit",
    ] {
        assert!(
            !CONTROL_PLANE_WAVE_090_A.contains(forbidden),
            "Step 157 gate gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn step158_runtime_supervision_is_one_owned_bounded_redacted_graph() {
    let contract: serde_json::Value = serde_json::from_str(RUNTIME_SUPERVISION_CONTRACT)
        .expect("Step 158 runtime-supervision contract");
    assert_eq!(contract["schema"], "radroots.myc.runtime-supervision.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 158);
    assert_eq!(contract["task_set"]["minimum_count"], 1);
    assert_eq!(contract["task_set"]["maximum_count"], 32);
    assert_eq!(contract["task_set"]["classification"], "critical");
    assert_eq!(
        contract["task_set"]["shutdown_phase_assignment"],
        "deferred_to_step_159"
    );
    assert_eq!(contract["task_set"]["detached_tasks"], false);
    assert_eq!(
        contract["fatal_outcomes"],
        serde_json::json!([
            "task_returned_error",
            "task_panicked",
            "unexpected_completion",
            "unexpected_cancellation",
            "join_failed"
        ])
    );
    assert_eq!(
        contract["fatal_effect"]["all_task_joins_observed_before_return"],
        true
    );
    assert_eq!(
        contract["deferred"],
        serde_json::json!([
            "process_panic_hook",
            "signal_installation",
            "first_signal_graceful_shutdown",
            "second_signal_forced_shutdown",
            "shutdown_grace_deadline",
            "ordered_durability_drain"
        ])
    );
    for required in [
        "MYC_CRITICAL_TASK_MAX_COUNT: usize = 32",
        ".take(MYC_CRITICAL_TASK_MAX_COUNT + 1)",
        "TaskClassification::Critical",
        "supervisor.request_cancellation()",
        "supervisor.supervise().await",
        "MycProcessResult::UnexpectedInternal",
        "MycLogRecord::critical_task_failed()",
        "MycTaskCancellation([sealed])",
        "MycCriticalTask([sealed])",
    ] {
        assert!(
            RUNTIME_SUPERVISION.contains(required),
            "Step 158 implementation is missing `{required}`"
        );
    }
    for forbidden in [
        "pub use radroots_service_host",
        "pub fn cancellation_token",
        "pub fn request_cancellation",
        "JoinHandle",
        "tokio::spawn",
        "spawn_blocking",
        "signal::",
        "process::exit",
        "std::time::SystemTime",
        "rand::",
        "getrandom",
        "fn source(",
    ] {
        assert!(
            !RUNTIME_SUPERVISION.contains(forbidden),
            "Step 158 boundary gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "one sealed, bounded critical-task graph",
        "task names and handles remain internal",
        "The binary owns signal\ninstallation",
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
    }
}

#[test]
fn step148_response_commit_is_one_atomic_exact_byte_authority() {
    let contract: serde_json::Value =
        serde_json::from_str(NIP46_RESPONSE_CONTRACT).expect("Step 148 contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-response-commit.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 148);
    assert_eq!(contract["schema_version"], 9);
    for required in [
        "sealed_step147_completion_component",
        "independently_signature_verified_canonical_kind_24133_event",
        "exact_signed_response_bytes_sha256_and_event_id",
        "zero_attempt_target_state",
        "committed_response_bytes_only",
        "completion_without_response_or_job",
        "fail_closed_without_repair",
        "relay_io_inside_transaction",
        "response_reconstruction_on_retry",
    ] {
        assert!(
            NIP46_RESPONSE_CONTRACT.contains(required),
            "Step 148 contract is missing `{required}`"
        );
    }
    for required in [
        "ServiceSqliteTransaction",
        "commit_operation(transaction",
        "nip46_signed_responses",
        "create_job(",
        "read_response_by_operation",
        "signed_response_bytes",
        "fail_after_completion_for_test",
        "fail_after_response_for_test",
    ] {
        assert!(
            NIP46_RESPONSE.contains(required),
            "Step 148 implementation is missing `{required}`"
        );
    }
    assert!(!PUBLIC_API.contains("commit_nip46_operation"));
    for forbidden in [
        "RelayPool",
        ".publish(",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "rand::",
        "getrandom",
        "SqlitePool",
        "rusqlite",
    ] {
        assert!(
            !NIP46_RESPONSE.contains(forbidden),
            "Step 148 gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn step221_pending_response_is_atomic_exact_and_nonterminal() {
    let contract: serde_json::Value = serde_json::from_str(NIP46_PENDING_RESPONSE_CONTRACT)
        .expect("Step 221 pending-response contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-pending-response.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 221);
    assert_eq!(contract["state_schema_version"], 12);
    assert_eq!(contract["terminal_effects"]["operation_completion"], false);
    assert_eq!(contract["terminal_effects"]["session_activation"], false);
    for required in [
        "immutable_explicit_approval_pending_decision",
        "exact_committed_pending_response_bytes",
        "response_edge_failure_rolls_back_response_and_delivery",
        "no_terminal_operation_commit_is_created",
        "live_nip46_client_observes_pending_then_continues_after_admin_approval",
        "false_terminal_operation_completion",
    ] {
        assert!(
            NIP46_PENDING_RESPONSE_CONTRACT.contains(required),
            "Step 221 contract is missing `{required}`"
        );
    }
    for required in [
        "commit_nip46_pending_response(&commit)",
        "Response::PendingConnection",
        "MycNip46DispatchDisposition::PendingApproval",
    ] {
        assert!(RUNTIME_NIP46.contains(required), "missing `{required}`");
    }
    for required in [
        "CREATE TABLE nip46_pending_responses",
        "nip46_signed_responses_guard_pending_insert",
        "fail_after_response_for_test",
    ] {
        assert!(NIP46_RESPONSE.contains(required) || STATE_CATALOG.contains(required));
    }
}

#[test]
fn step147_completion_is_atomic_redacted_and_defers_delivery_authority() {
    let contract: serde_json::Value =
        serde_json::from_str(NIP46_COMPLETION_CONTRACT).expect("Step 147 contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-completion.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 147);
    assert_eq!(contract["schema_version"], 8);
    for required in [
        "radroots.myc.nip46-completion.v1",
        "existing_durable_nip46_request",
        "existing_service_sqlite_transaction_runner",
        "connection_admission_or_logout_session_revocation",
        "exact_verified_inner_signed_event_bytes_and_sha256_when_present",
        "protected_provider_output\": \"not_persisted",
        "failed_transaction\": \"no_session_or_completion_effect",
        "step147_checkpoint\": \"integration_only_not_promotable",
        "step147_component\": \"composed_by_step148_atomic_response_commit",
        "composition_status\": \"satisfied_on_rcld_080_integration_branch",
        "commit_owner\": 148",
        "promotion_owner\": 151",
        "outer_signed_nip46_response\": 148",
        "outbox_and_initial_attempt_state\": 148",
        "outbox_creation",
    ] {
        assert!(
            NIP46_COMPLETION_CONTRACT.contains(required),
            "Step 147 contract is missing `{required}`"
        );
    }
    for required in [
        "ServiceSqliteTransaction",
        "nip46_operation_commits",
        "REVOKE_CONNECTION_SQL",
        "provider_artifact_sha256",
        "ExactReplay",
        "fail_after_session_effect_for_test",
    ] {
        assert!(
            NIP46_COMPLETION.contains(required),
            "Step 147 implementation is missing `{required}`"
        );
    }
    for forbidden in [
        "RelayPool",
        ".publish(",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "rand::",
        "getrandom",
        "SqlitePool",
        "rusqlite",
    ] {
        assert!(
            !NIP46_COMPLETION.contains(forbidden),
            "Step 147 gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn step145_work_is_exactly_bound_and_transaction_free() {
    for forbidden in [
        "sqlx::",
        "ServiceSqlite",
        "StateRepository",
        "StateHost",
        "ServiceSqliteTransaction",
        "tokio::spawn",
        "std::time::SystemTime",
        "rand::",
        "getrandom",
        "RelayPool",
    ] {
        assert!(
            !NIP46_WORK.contains(forbidden),
            "Step 145 gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "radroots.myc.nip46.decrypt.operation.v1\\\\0",
        "radroots.myc.nip46.decrypt.correlation.v1\\\\0",
        "radroots.myc.provider.operation_binding.v1\\\\0",
        "radroots_nostr_connect::server::required_permission",
        "after_durable_request_admission_returns",
        "alternate_plaintext_to_work_path",
        "custom_methods",
        "provider_execution",
        "response_commit",
        "relay_publication",
    ] {
        assert!(
            NIP46_WORK_CONTRACT.contains(required),
            "Step 145 contract is missing `{required}`"
        );
    }
}

#[test]
fn step146_first_wave_gate_is_machine_bound_and_test_only() {
    for required in [
        "radroots.myc.nip46-wave-080-a.v1",
        "nip04_ping_full_pipeline",
        "nip44_ping_full_pipeline",
        "nip44_connect_durable_approval",
        "nip44_sign_event_provider_work",
        "wrong_event_provider_response",
        "wrong_outer_provider_correlation",
        "late_provider_response",
        "wrong_provider_result_shape",
        "conflicting_request_id_reuse",
        "configured_connection_admission_rate_window",
        "existing_myc_state_repository",
        "existing_service_sqlite_transaction_runner",
        "\"complete_after_step\": 146",
        "\"rcld_promotion_owner\": 151",
    ] {
        assert!(
            NIP46_WAVE_080_A_CONTRACT.contains(required),
            "Step 146 corpus is missing `{required}`"
        );
    }
    assert!(ROOT.contains(
        "#[cfg(all(test, any(target_os = \"linux\", target_os = \"macos\")))]\nmod nip46_wave_080_a;"
    ));
    for forbidden in [
        "RelayPool",
        ".publish(",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "rand::",
        "getrandom",
        "SqlitePool",
        "SqliteConnection",
    ] {
        assert!(
            !NIP46_WAVE_080_A.contains(forbidden),
            "Step 146 gate gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn step150_admin_adapter_is_closed_typed_and_transport_bounded() {
    assert!(
        ROOT.contains("#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\nmod admin_v1;")
    );
    assert!(ROOT.contains(
        "#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\npub use admin_v1::{"
    ));
    for required in [
        "pub const ALL: [Self; 19]",
        "models.len() == 32",
        "operator_route_inventory_is_exact",
        "AdminMutationRequest<Value>",
        "strict_json(bytes)",
        "MycAdminDocumentErrorKind::DuplicateField",
        "MycAdminDocumentErrorKind::NullForbidden",
        "MycAdminHandlerErrorKind::InvalidCursor",
        "MycAdminHandlerErrorKind::OperationIdConflict",
        "original committed response",
        "same route, filters, and snapshot",
        "relay submission or delivery is not implied",
        "all_nineteen_routes_round_trip_over_the_hardened_unix_boundary",
    ] {
        assert!(
            ADMIN_V1.contains(required),
            "Step 150 adapter is missing `{required}`"
        );
    }
    for forbidden in [
        "TcpListener",
        "axum::",
        "warp::",
        "actix",
        "SqlitePool",
        "SqliteConnection",
        "tokio::spawn(async move { handler",
        "SystemTime",
        "rand::",
        "getrandom",
        "process::exit",
    ] {
        assert!(
            !ADMIN_V1.contains(forbidden),
            "Step 150 adapter gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "exact 19-route",
        "all 32 model",
        "Raw shared-host routers and JSON values never cross the public",
        "operation_id_conflict",
        "Unit 13\nseals that handler boundary inside the production `MycAdminServer`",
        "Unit 15 alone owns task\nspawning, provider/relay wiring, readiness, reconnect, and phase-aware\nshutdown",
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
    }
}

#[test]
fn step159_unit13_control_surfaces_are_sealed_and_machine_bound() {
    let contract: serde_json::Value =
        serde_json::from_str(CONTROL_SURFACES_CONTRACT).expect("control-surface contract");
    assert_eq!(contract["schema"], "radroots.myc.control-surfaces.v1");
    assert_eq!(contract["step"], 159);
    assert_eq!(contract["unit"], 13);
    assert_eq!(contract["admin"]["route_count"], 19);
    assert_eq!(contract["admin"]["model_count"], 32);
    assert_eq!(contract["status"]["publisher_count"], 1);
    assert_eq!(contract["operations"]["active_probe"], false);
    assert_eq!(contract["doctor"]["check_count"], 13);
    assert_eq!(
        contract["deferred"]["authoritative_daemon_task_graph"],
        "unit_15"
    );
    for required in [
        "AdminServer::with_system_entropy(router.into_inner(), limits)",
        ".pointer(\"/resource_limits/admin\")",
        "UnixAdminSocketWriterAuthority::acquire(runtime.context().paths().run())",
        "UnixAdminSocketBinding::bind(authority, runtime.artifacts().admin_socket())",
        "pub struct MycAdminServer",
        "pub struct MycBoundAdminServer",
        "pub struct MycAdminCancellationToken",
    ] {
        assert!(
            ADMIN_V1.contains(required),
            "Unit 13 is missing `{required}`"
        );
    }
    for forbidden in [
        "pub fn into_inner",
        "pub const fn into_inner",
        "pub fn listener",
        "TcpListener",
        "std::process::exit",
    ] {
        assert!(
            !ADMIN_V1.contains(forbidden),
            "Unit 13 exposes forbidden `{forbidden}`"
        );
    }
}

#[test]
fn step159_unit14_process_bootstrap_is_secure_bounded_and_daemon_deferred() {
    let process = PROCESS_V1
        .split("#[cfg(test)]")
        .next()
        .expect("production process source");
    let system_doctor = SYSTEM_DOCTOR
        .split("#[cfg(test)]")
        .next()
        .expect("production doctor source");
    assert_eq!(MAIN.matches("parse_myc_cli_v1_from").count(), 1);
    assert_eq!(MAIN.matches("execute_myc_cli_v1").count(), 1);
    for required in [
        "plan_myc_cli_v1(&invocation)",
        "Builder::new_multi_thread()",
        "worker_threads(limits.worker_threads())",
        "max_blocking_threads(limits.blocking_threads())",
        "ServiceBackupManifest::from_canonical_bytes",
        "parsed.digest() != arguments.manifest_sha256()",
        "read_secure_bounded_file(path, maximum)",
        "emit_exact_bytes(manifest.canonical_bytes())",
    ] {
        assert!(
            process.contains(required),
            "Unit 14 process boundary is missing `{required}`"
        );
    }
    assert_eq!(process.matches("Builder::new_multi_thread()").count(), 1);
    for forbidden in [
        "available_parallelism",
        "std::process::exit",
        "path(\"MYC_",
        "tokio::spawn",
        "tokio::task::spawn",
    ] {
        assert!(
            !process.contains(forbidden),
            "Unit 14 process boundary gained `{forbidden}`"
        );
    }

    for required in [
        "OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK",
        "OFlags::WRONLY",
        "OFlags::CREATE",
        "OFlags::EXCL",
        "Mode::RUSR | Mode::WUSR",
        "normalize_link_count(status.st_nlink) != 1",
        "status.st_uid != geteuid().as_raw()",
        "mode & 0o022 != 0",
        "file.sync_all()",
        "parent.sync_all()",
        "open_parent(&selected.parent)",
    ] {
        assert!(
            CONFIG_LOADER.contains(required),
            "Unit 14 config loader is missing `{required}`"
        );
    }
    for forbidden in ["canonicalize(", "create_dir_all", "from_current_process"] {
        assert!(
            !CONFIG_LOADER.contains(forbidden),
            "Unit 14 config loader gained `{forbidden}`"
        );
    }

    for required in [
        "MycDoctorCheckId::PathsPermissions",
        "MycDoctorCheckId::WriterLock",
        "MycDoctorCheckId::SqliteSchema",
        "MycDoctorCheckId::SqliteFreeSpace",
        "MycDoctorCheckId::SqliteIntegrity",
        "MycDoctorCheckId::OutboxInvariants",
        "MycDoctorCheckId::IdentityBinding",
        "MycDoctorCheckId::SignerProvider",
        "MycDoctorCheckId::AdminBindPolicy",
        "MycDoctorCheckId::OperationsBindPolicy",
        "MycDoctorCheckId::NetworkPolicy",
        "MycDoctorCheckId::RequiredRelays",
        "MycDoctorCheckId::ClockSkew",
        "MycDoctorObservation::Skipped",
        "probe_required_relays",
    ] {
        assert!(
            system_doctor.contains(required),
            "Unit 14 doctor adapter is missing `{required}`"
        );
    }
    for forbidden in ["publish(", "format!(\"{error", "to_string()", "source()"] {
        assert!(
            !system_doctor.contains(forbidden),
            "Unit 14 doctor adapter gained `{forbidden}`"
        );
    }

    for required in [
        "MycProcessResult::ServiceOrDependencyUnavailable",
        "MycProcessResult::InputOrConfiguration",
    ] {
        assert!(PROCESS_V1_UNSUPPORTED.contains(required));
    }
    for forbidden in [
        "std::fs",
        "sqlx::",
        "AdminClient",
        "tokio::",
        "MycStateHost",
        "MycProviderExecutor",
    ] {
        assert!(
            !PROCESS_V1_UNSUPPORTED.contains(forbidden),
            "unsupported process executor gained `{forbidden}`"
        );
    }
}

#[test]
fn step144_authorization_is_configuration_bound_and_reuses_durable_state() {
    for forbidden in [
        "sqlx::",
        "ServiceSqlite",
        "tokio::spawn",
        "std::time::SystemTime",
        "rand::",
        "getrandom",
        "RelayPool",
    ] {
        assert!(
            !NIP46_AUTHORIZATION.contains(forbidden),
            "Step 144 policy projection gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "normalized_configuration_bound_in_myc_state_metadata",
        "configured_denied_client_is_direct_denial_without_connection_or_rate_window",
        "configured_trusted_and_unknown_client_admissions_consume_global_and_relay_rate_windows",
        "all_unknown_clients_require_explicit_operator_approval",
        "exact_operator_configured_url_only",
        "separate_configuration_bound_connection_scope",
        "existing_myc_state_repository_and_service_sqlite_transaction",
        "\"new_store_or_limiter\": \"forbidden\"",
    ] {
        assert!(
            NIP46_AUTHORIZATION_CONTRACT.contains(required),
            "Step 144 contract is missing `{required}`"
        );
    }
}

#[test]
fn step143_replay_binding_remains_pure_and_reuses_the_durable_authority() {
    for forbidden in [
        "ServiceSqlite",
        "sqlx::",
        "tokio::spawn",
        "std::time::SystemTime",
        "rand::",
        "getrandom",
        "RelayPool",
        "nip04::decrypt",
        "nip44::decrypt",
    ] {
        assert!(
            !NIP46_REPLAY.contains(forbidden),
            "Step 143 gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "existing_myc_state_repository_dual_request_and_event_dedup",
        "\"new_replay_store\": \"forbidden\"",
        "\"plaintext_event_cryptographic_binding\"",
        "\"supported_method_admission\"",
        "\"database_mutation\"",
    ] {
        assert!(
            NIP46_REPLAY_CONTRACT.contains(required),
            "Step 143 contract is missing `{required}`"
        );
    }
}

#[test]
fn public_errors_remain_crate_owned_redacted_and_source_free() {
    let production = SOURCES.join("\n");

    assert!(!production.contains("fn source("));
    for forbidden in [
        "source: std::io::Error",
        "source: sqlx::Error",
        "source: serde_json::Error",
        "source: toml::de::Error",
        "source: url::ParseError",
    ] {
        assert!(
            !production.contains(forbidden),
            "raw error source `{forbidden}` escaped"
        );
    }

    let public_error_count = PUBLIC_API
        .lines()
        .filter(|line| line.starts_with("pub struct myc::") && line.ends_with("Error"))
        .count();
    assert_eq!(public_error_count, 36);
    assert!(PUBLIC_API.contains("pub struct myc::MycDoctorError"));
    assert!(PUBLIC_API.contains("pub struct myc::MycConfigApplyError"));
    assert!(PUBLIC_API.contains("pub struct myc::MycAdminOperationError"));
    assert!(PUBLIC_API.contains("pub struct myc::MycAdminServerError"));
    assert!(PUBLIC_API.contains("pub struct myc::MycConfigLoadError"));
    assert!(!PUBLIC_API.contains("pub struct myc::MycRuntimeFoundation {"));
    assert!(!PUBLIC_API.contains("pub struct myc::MycStateHost {"));
}

#[test]
fn step142_verification_remains_pure_and_defers_later_authority() {
    for forbidden in [
        "nip04::decrypt",
        "nip44::decrypt",
        "ServiceSqlite",
        "sqlx::",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "RelayPool",
    ] {
        assert!(
            !NIP46_VERIFICATION.contains(forbidden),
            "Step 142 gained forbidden authority `{forbidden}`"
        );
    }
    for required in [
        "\"decryption\": \"deferred_to_step_145\"",
        "\"plaintext_event_binding\": \"deferred_to_step_145\"",
        "\"replay_and_conflicting_reuse\": \"deferred_to_step_143\"",
        "\"authorization\"",
        "\"database_mutation\"",
        "\"relay_publication\"",
    ] {
        assert!(
            NIP46_VERIFICATION_CONTRACT.contains(required),
            "Step 142 contract is missing `{required}`"
        );
    }
}

#[test]
fn step149_recovery_and_offline_export_are_bounded_and_non_networked() {
    let contract: serde_json::Value =
        serde_json::from_str(DELIVERY_RECOVERY_EXPORT_CONTRACT).expect("Step 149 contract");
    assert_eq!(
        contract["schema"],
        "radroots.myc.delivery-recovery-export.v1"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 149);
    assert_eq!(contract["schema_version"], 9);
    for required in [
        "atomic_response_or_discovery_commit_only",
        "caller_injected_full_jitter_milliseconds",
        "internal_opaque_job_identity_cursor",
        "one_bounded_service_sqlite_transaction_per_batch",
        "signature_verified_canonical_active_response_bytes",
        "signature_verified_canonical_active_discovery_bytes",
        "delivered_desired_restart_promotion",
        "verified_committed_projection",
        "compact_canonical_utf8_json",
        "standalone_signer_delivery_job_creation",
        "final_supervised_startup_loop",
    ] {
        assert!(
            DELIVERY_RECOVERY_EXPORT_CONTRACT.contains(required),
            "Step 149 contract is missing `{required}`"
        );
    }
    for required in [
        "MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT: usize = 128",
        "READ_INVARIANTS_SQL",
        "recover_delivery_state",
        "verify_response_for_delivery_job",
        "verify_document_for_delivery_job",
        "recover_expired",
        "promote_current_if_desired",
    ] {
        assert!(
            DELIVERY_RECOVERY.contains(required),
            "Step 149 recovery is missing `{required}`"
        );
    }
    for required in [
        "render_offline_nip05",
        "MycNip05ExportSelection::Desired",
        "MycNip05ExportSelection::Current",
        "struct Nip05Output",
        "names: Nip05Names",
        "nip46: Nip46Discovery",
    ] {
        assert!(
            DISCOVERY_STATE.contains(required),
            "Step 149 offline export is missing `{required}`"
        );
    }
    for removed in ["MycDeliveryJobRequest", "create_delivery_job"] {
        assert!(
            !PUBLIC_API.contains(removed),
            "partial delivery authority remains public: `{removed}`"
        );
    }
    for forbidden in [
        "reqwest",
        "RelayPool",
        ".publish(",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "rand::",
        "getrandom",
        "rusqlite",
    ] {
        assert!(
            !DELIVERY_RECOVERY.contains(forbidden),
            "Step 149 recovery gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn step159_provider_delivery_is_sealed_exact_and_durability_ordered() {
    let contract: serde_json::Value = serde_json::from_str(PROVIDER_DELIVERY_CONTRACT)
        .expect("Step 159 provider-delivery contract");
    assert_eq!(contract["schema"], "radroots.myc.provider-delivery.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 159);
    assert_eq!(contract["unit"], "myc-provider-delivery");
    assert_eq!(
        contract["relay_adapter"]["implementation"],
        "radroots_transport_nostr"
    );
    assert_eq!(
        contract["durable_delivery"]["submitted_transition"],
        "immediately_after_prepare_before_execute"
    );
    for required in [
        "spawn_blocking",
        "OwnedBlockingTask",
        "worker.join(MycProviderExecutionErrorKind::Open).await",
        "handle.abort()",
        "handle.is_finished()",
        "verify_encrypted_provider_response",
        "MycLocalSignerClient",
    ] {
        assert!(
            PROVIDER_EXECUTOR.contains(required),
            "provider executor is missing `{required}`"
        );
    }
    for required in [
        "radroots_transport_nostr",
        "prepare_delivery(request)",
        "execute_prepared_delivery(prepared).await",
        "DeliveryOutcomeKind::Accepted",
        "DeliveryOutcomeKind::Rejected",
        "DeliveryOutcomeKind::Unavailable",
    ] {
        assert!(
            TRANSPORT_NOSTR_ADAPTER.contains(required),
            "transport adapter is missing `{required}`"
        );
    }
    for required in [
        "claim_delivery_target",
        "read_nip46_response",
        "read_discovery_document_for_job",
        "mark_delivery_attempt_submitted",
        "adapter.execute(prepared)",
        "MycDeliveryAttemptOutcome::UnknownAcknowledgement",
        "record_delivery_attempt_outcome",
    ] {
        assert!(
            DELIVERY_WORKER.contains(required),
            "delivery worker is missing `{required}`"
        );
    }
    for forbidden in [
        "pub struct myc::MycProviderExecutor",
        "pub struct myc::MycDeliveryWorker",
        "pub struct myc::MycNostrDeliveryAdapter",
        "radroots_transport_nostr::",
        "radroots_transport::",
    ] {
        assert!(
            !PUBLIC_API.contains(forbidden),
            "sealed delivery authority escaped: `{forbidden}`"
        );
    }
    for source in [PROVIDER_EXECUTOR, TRANSPORT_NOSTR_ADAPTER, DELIVERY_WORKER] {
        for forbidden in [
            "std::time::SystemTime",
            "Timestamp::now",
            "getrandom",
            "rand::",
            "tokio::runtime::Runtime",
            "tokio::spawn(",
        ] {
            assert!(
                !source.contains(forbidden),
                "Step 159 provider-delivery gained `{forbidden}`"
            );
        }
    }
}
