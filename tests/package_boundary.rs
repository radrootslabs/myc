#![forbid(unsafe_code)]

use std::collections::BTreeSet;

const ROOT: &str = include_str!("../src/lib.rs");
const README: &str = include_str!("../README");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/myc.txt");
const ADMIN_V1: &str = include_str!("../src/admin_v1.rs");
const NIP46_VERIFICATION: &str = include_str!("../src/nip46_verification.rs");
const NIP46_AUTHORIZATION: &str = include_str!("../src/nip46_authorization.rs");
const NIP46_REPLAY: &str = include_str!("../src/nip46_replay.rs");
const NIP46_WORK: &str = include_str!("../src/nip46_work.rs");
const NIP46_WAVE_080_A: &str = include_str!("../src/nip46_wave_080_a.rs");
const NIP46_COMPLETION: &str = include_str!("../src/state_completion.rs");
const NIP46_RESPONSE: &str = include_str!("../src/state_response.rs");
const DELIVERY_RECOVERY: &str = include_str!("../src/state_recovery.rs");
const DOCTOR_V1: &str = include_str!("../src/doctor_v1.rs");
const DIAGNOSTICS_V1: &str = include_str!("../src/diagnostics_v1.rs");
const DIAGNOSTICS_CONTRACT: &str =
    include_str!("../contracts/services_hardening/diagnostics.v1.json");
const MAIN: &str = include_str!("../src/main.rs");
const STATUS_V1: &str = include_str!("../src/status_v1.rs");
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
const DELIVERY_RECOVERY_EXPORT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/delivery_recovery_export.v1.json");
const SOURCES: &[&str] = &[
    include_str!("../src/admin_v1.rs"),
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/doctor_v1.rs"),
    include_str!("../src/diagnostics_v1.rs"),
    include_str!("../src/nip46_admission.rs"),
    include_str!("../src/nip46_authorization.rs"),
    include_str!("../src/nip46_replay.rs"),
    include_str!("../src/nip46_verification.rs"),
    include_str!("../src/nip46_work.rs"),
    include_str!("../src/operations_v1.rs"),
    include_str!("../src/provider_contract.rs"),
    include_str!("../src/provider_credential.rs"),
    include_str!("../src/provider_envelope.rs"),
    include_str!("../src/provider_local_signer.rs"),
    include_str!("../src/provider_verification.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/runtime_foundation.rs"),
    include_str!("../src/status_v1.rs"),
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
            "cli_v1",
            "config_v1",
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
            "provider_contract",
            "provider_credential",
            "provider_envelope",
            "provider_local_signer",
            "provider_verification",
            "runtime_context",
            "runtime_foundation",
            "status_v1",
            "state_catalog",
            "state_completion",
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
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
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
    ] {
        assert!(
            PUBLIC_API.contains(required),
            "reviewed API baseline is missing `{required}`"
        );
    }

    for module in [
        "admin_v1",
        "cli_v1",
        "config_v1",
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
        "provider_contract",
        "provider_credential",
        "provider_envelope",
        "provider_local_signer",
        "provider_verification",
        "runtime_context",
        "runtime_foundation",
        "status_v1",
        "state_catalog",
        "state_completion",
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
        "pub const ALL: [Self; 21]",
        "models.len() == 35",
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
        "all_twenty_one_routes_round_trip_over_the_hardened_unix_boundary",
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
        "exact 21-route",
        "all 35 model",
        "Raw shared-host routers and JSON values never cross the public",
        "operation_id_conflict",
        "not the later daemon runtime",
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
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
    assert_eq!(public_error_count, 30);
    assert!(PUBLIC_API.contains("pub struct myc::MycDoctorError"));
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
