#![forbid(unsafe_code)]

use std::collections::BTreeSet;

const ROOT: &str = include_str!("../src/lib.rs");
const README: &str = include_str!("../README");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/myc.txt");
const NIP46_VERIFICATION: &str = include_str!("../src/nip46_verification.rs");
const NIP46_AUTHORIZATION: &str = include_str!("../src/nip46_authorization.rs");
const NIP46_REPLAY: &str = include_str!("../src/nip46_replay.rs");
const NIP46_WORK: &str = include_str!("../src/nip46_work.rs");
const NIP46_VERIFICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_verification.v1.json");
const NIP46_REPLAY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_replay.v1.json");
const NIP46_AUTHORIZATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_authorization.v1.json");
const NIP46_WORK_CONTRACT: &str =
    include_str!("../contracts/services_hardening/nip46_work.v1.json");
const SOURCES: &[&str] = &[
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/nip46_admission.rs"),
    include_str!("../src/nip46_authorization.rs"),
    include_str!("../src/nip46_replay.rs"),
    include_str!("../src/nip46_verification.rs"),
    include_str!("../src/nip46_work.rs"),
    include_str!("../src/provider_contract.rs"),
    include_str!("../src/provider_credential.rs"),
    include_str!("../src/provider_envelope.rs"),
    include_str!("../src/provider_local_signer.rs"),
    include_str!("../src/provider_verification.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/runtime_foundation.rs"),
    include_str!("../src/state_catalog.rs"),
    include_str!("../src/state_connection.rs"),
    include_str!("../src/state_delivery.rs"),
    include_str!("../src/state_discovery.rs"),
    include_str!("../src/state_governance.rs"),
    include_str!("../src/state_host.rs"),
    include_str!("../src/state_maintenance.rs"),
    include_str!("../src/state_metadata.rs"),
    include_str!("../src/state_repository.rs"),
    include_str!("../src/state_request.rs"),
];

#[test]
fn implementation_modules_are_private_and_rustdoc_uses_the_reviewed_readme() {
    assert_eq!(
        ROOT.lines()
            .filter_map(|line| line.strip_prefix("mod "))
            .filter_map(|line| line.strip_suffix(';'))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "cli_v1",
            "config_v1",
            "nip46_admission",
            "nip46_authorization",
            "nip46_replay",
            "nip46_verification",
            "nip46_work",
            "provider_contract",
            "provider_credential",
            "provider_envelope",
            "provider_local_signer",
            "provider_verification",
            "runtime_context",
            "runtime_foundation",
            "state_catalog",
            "state_connection",
            "state_delivery",
            "state_discovery",
            "state_governance",
            "state_host",
            "state_maintenance",
            "state_metadata",
            "state_repository",
            "state_request",
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
    ] {
        assert!(README.contains(required), "README is missing `{required}`");
    }
}

#[test]
fn reviewed_api_is_root_only_and_exposes_no_implementation_authority() {
    for required in [
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
        "cli_v1",
        "config_v1",
        "nip46_admission",
        "nip46_authorization",
        "nip46_replay",
        "nip46_verification",
        "nip46_work",
        "provider_contract",
        "provider_credential",
        "provider_envelope",
        "provider_local_signer",
        "provider_verification",
        "runtime_context",
        "runtime_foundation",
        "state_catalog",
        "state_connection",
        "state_delivery",
        "state_discovery",
        "state_governance",
        "state_host",
        "state_maintenance",
        "state_metadata",
        "state_repository",
        "state_request",
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
    assert_eq!(public_error_count, 22);
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
