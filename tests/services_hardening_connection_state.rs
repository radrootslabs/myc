#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_AUDIT_PAGE_MAX_ITEMS, MYC_AUDIT_RETENTION_MAX_MS,
    MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES, MYC_COMPACTION_MAX_ROWS,
    MYC_CONNECTION_PERMISSION_MAX_COUNT, MYC_RATE_MAX_ATTEMPTS, MYC_RATE_MAX_TRACKED_SUBJECTS,
    MYC_RATE_RELAY_ID_MAX_BYTES, MYC_RATE_RETENTION_MAX_MS, MYC_RATE_WINDOW_MAX_MS,
    MYC_STATE_SCHEMA_VERSION, MycAuditCorrelationId, MycAuditKind, MycAuditOutcome,
    MycAuditPageLimit, MycAuditReasonCode, MycAuthorizationChallengeAdmission,
    MycAuthorizationChallengeNonce, MycAuthorizationChallengeRequest,
    MycAuthorizationChallengeState, MycAuthorizationChallengeUrl, MycConfigProfile,
    MycConnectionAdmission, MycConnectionAdmissionPolicy, MycConnectionAdmissionRequest,
    MycConnectionNonce, MycConnectionOperatorDecision, MycConnectionPermission,
    MycConnectionPermissionSet, MycConnectionPolicyGeneration, MycConnectionStateErrorKind,
    MycConnectionStatus, MycConnectionTimeUnixMs, MycGovernanceCompactionPolicy,
    MycGovernanceStateErrorKind, MycNip46ClientPublicKey, MycNip46EventId, MycNip46RequestId,
    MycRateLimitClass, MycRateLimitPolicy, MycRateRelayId, MycRequestReceivedAtUnixMs,
    MycSignerOperationId, MycSignerOperationNonce, MycSignerRequest, MycSignerRequestDigest,
    MycSignerRequestMethod, MycStateMetadata, MycStateRepository, MycStateRepositoryErrorKind,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, initialize_myc_state,
    open_myc_state_read_write, parse_myc_cli_v1_from, parse_myc_config_v1,
    resolve_myc_runtime_context,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const CONNECTION_SOURCE: &str = include_str!("../src/state_connection.rs");
const GOVERNANCE_SOURCE: &str = include_str!("../src/state_governance.rs");
const CLIENT_PUBLIC_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TRUSTED_CLIENT_PUBLIC_KEY: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";
const DENIED_CLIENT_PUBLIC_KEY: &str =
    "8888888888888888888888888888888888888888888888888888888888888888";

fn runtime(root: &Path) -> myc::MycRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
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

fn prepare_state_directory(runtime: &myc::MycRuntimeContext) {
    let directory = runtime.context().paths().state();
    fs::create_dir_all(directory).expect("state directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("state mode");
}

fn metadata(runtime: &myc::MycRuntimeContext) -> MycStateMetadata {
    metadata_from_bytes(runtime, CONFIG_EXAMPLE)
}

fn metadata_from_bytes(runtime: &myc::MycRuntimeContext, bytes: &[u8]) -> MycStateMetadata {
    let configuration =
        parse_myc_config_v1(bytes, MycConfigProfile::RepoLocal).expect("configuration");
    MycStateMetadata::new(
        runtime,
        &configuration,
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
        "053d0c750bf9cd683c6ea37cefe7e79617ba629f",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        MYC_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

fn client() -> MycNip46ClientPublicKey {
    MycNip46ClientPublicKey::new(CLIENT_PUBLIC_KEY).expect("client identity")
}

fn trusted_client() -> MycNip46ClientPublicKey {
    MycNip46ClientPublicKey::new(TRUSTED_CLIENT_PUBLIC_KEY).expect("trusted client identity")
}

fn denied_client() -> MycNip46ClientPublicKey {
    MycNip46ClientPublicKey::new(DENIED_CLIENT_PUBLIC_KEY).expect("denied client identity")
}

fn client_for_policy(policy: MycConnectionAdmissionPolicy) -> MycNip46ClientPublicKey {
    match policy {
        MycConnectionAdmissionPolicy::Trusted => trusted_client(),
        MycConnectionAdmissionPolicy::ExplicitApproval => client(),
        MycConnectionAdmissionPolicy::Denied => denied_client(),
    }
}

fn permission_set(permissions: &[MycConnectionPermission]) -> MycConnectionPermissionSet {
    MycConnectionPermissionSet::new(permissions).expect("permission set")
}

fn time(value: u64) -> MycConnectionTimeUnixMs {
    MycConnectionTimeUnixMs::new(value).expect("connection time")
}

fn policy_generation(value: u64) -> MycConnectionPolicyGeneration {
    MycConnectionPolicyGeneration::new(value).expect("policy generation")
}

fn audit_correlation(byte: u8) -> MycAuditCorrelationId {
    MycAuditCorrelationId::new([byte; 32])
}

async fn admit_request(
    repository: &MycStateRepository<'_>,
    client_public_key: MycNip46ClientPublicKey,
    request_id: &str,
    event_byte: u8,
    method: MycSignerRequestMethod,
    nonce_byte: u8,
    received_at: u64,
) -> MycSignerOperationId {
    let canonical = format!(
        "{{\"id\":\"{request_id}\",\"method\":\"{}\"}}",
        method.as_str()
    );
    let request = MycSignerRequest::new(
        client_public_key,
        MycNip46RequestId::new(request_id).expect("request ID"),
        MycNip46EventId::from_bytes([event_byte; 32]),
        method,
        MycSignerRequestDigest::for_canonical_request(canonical.as_bytes())
            .expect("request digest"),
        MycSignerOperationNonce::from_injected_entropy([nonce_byte; 32]),
        MycRequestReceivedAtUnixMs::new(received_at).expect("received time"),
    );
    repository
        .admit_signer_request(&request)
        .await
        .expect("request admission")
        .record()
        .operation_id()
}

fn connection_request(
    operation_id: MycSignerOperationId,
    permissions: MycConnectionPermissionSet,
    generation: u64,
    nonce_byte: u8,
    observed_at: u64,
    authorized_until: Option<u64>,
    policy: MycConnectionAdmissionPolicy,
) -> MycConnectionAdmissionRequest {
    MycConnectionAdmissionRequest::new(
        operation_id,
        client_for_policy(policy),
        permissions,
        policy_generation(generation),
        MycConnectionNonce::from_injected_entropy([nonce_byte; 32]),
        time(observed_at),
        authorized_until.map(time),
        policy,
        MycRateRelayId::new("primary").expect("relay ID"),
    )
    .expect("connection request")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn connection_inputs_are_closed_bounded_canonical_and_redacted() {
    let maximum = (0..MYC_CONNECTION_PERMISSION_MAX_COUNT)
        .map(|kind| MycConnectionPermission::SignEvent(u32::try_from(kind).expect("kind")))
        .collect::<Vec<_>>();
    let permissions = MycConnectionPermissionSet::new(&maximum).expect("maximum permissions");
    assert_eq!(
        permissions.permissions().len(),
        MYC_CONNECTION_PERMISSION_MAX_COUNT
    );
    assert_eq!(
        MycConnectionPermissionSet::new(&[
            MycConnectionPermission::Ping,
            MycConnectionPermission::Ping,
        ])
        .expect_err("duplicate permission")
        .kind(),
        MycConnectionStateErrorKind::InvalidPermissionSet
    );
    let excessive = (0..=MYC_CONNECTION_PERMISSION_MAX_COUNT)
        .map(|kind| MycConnectionPermission::SignEvent(u32::try_from(kind).expect("kind")))
        .collect::<Vec<_>>();
    assert_eq!(
        MycConnectionPermissionSet::new(&excessive)
            .expect_err("excessive permissions")
            .kind(),
        MycConnectionStateErrorKind::InvalidPermissionSet
    );
    assert!(MycConnectionPermissionSet::new(&[]).is_ok());
    assert!(
        MycConnectionPermissionSet::new(&[MycConnectionPermission::SignEvent(u32::MAX)]).is_ok()
    );

    assert!(MycConnectionPolicyGeneration::new(i64::MAX.unsigned_abs()).is_ok());
    assert!(MycConnectionTimeUnixMs::new(i64::MAX.unsigned_abs()).is_ok());
    for invalid in [0, i64::MAX.unsigned_abs() + 1] {
        assert_eq!(
            MycConnectionPolicyGeneration::new(invalid)
                .expect_err("invalid policy generation")
                .kind(),
            MycConnectionStateErrorKind::InvalidPolicyGeneration
        );
        assert_eq!(
            MycConnectionTimeUnixMs::new(invalid)
                .expect_err("invalid time")
                .kind(),
            MycConnectionStateErrorKind::InvalidTime
        );
    }

    for accepted in [
        "https://operator.example/authorize",
        "http://localhost:8080/authorize",
        "http://127.0.0.1/authorize",
        "http://[::1]/authorize",
    ] {
        assert_eq!(
            MycAuthorizationChallengeUrl::new(accepted)
                .expect("accepted URL")
                .as_str(),
            accepted
        );
    }
    let maximum_url = format!(
        "https://operator.example/{}",
        "a".repeat(MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES - 25)
    );
    assert_eq!(maximum_url.len(), MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES);
    assert!(MycAuthorizationChallengeUrl::new(&maximum_url).is_ok());
    for invalid in [
        "",
        "https://operator.example",
        "http://operator.example/authorize",
        "https://user@operator.example/authorize",
        "https://operator.example/authorize#fragment",
        &format!("https://operator.example/{}", "a".repeat(2_100)),
    ] {
        assert_eq!(
            MycAuthorizationChallengeUrl::new(invalid)
                .expect_err("invalid URL")
                .kind(),
            MycConnectionStateErrorKind::InvalidChallengeUrl
        );
    }

    let error = MycConnectionPolicyGeneration::new(0).expect_err("invalid generation");
    assert!(Error::source(&error).is_none());
    let rendered = format!(
        "{permissions:?} {:?} {:?} {error} {error:?}",
        MycConnectionNonce::from_injected_entropy([0x5a; 32]),
        MycAuthorizationChallengeUrl::new("https://operator.example/secret").expect("URL")
    );
    for secret in ["operator.example", "secret", "5a5a5a", CLIENT_PUBLIC_KEY] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn governance_inputs_are_closed_bounded_and_redacted() {
    assert!(
        MycRateLimitPolicy::new(
            MycRateLimitClass::ConnectionAdmission,
            MYC_RATE_WINDOW_MAX_MS,
            MYC_RATE_MAX_ATTEMPTS,
            MYC_RATE_RETENTION_MAX_MS,
            MYC_RATE_MAX_TRACKED_SUBJECTS,
        )
        .is_ok()
    );
    for invalid in [
        MycRateLimitPolicy::new(MycRateLimitClass::ConnectionAdmission, 0, 1, 1, 1),
        MycRateLimitPolicy::new(
            MycRateLimitClass::ConnectionAdmission,
            MYC_RATE_WINDOW_MAX_MS + 1,
            1,
            MYC_RATE_WINDOW_MAX_MS + 1,
            1,
        ),
        MycRateLimitPolicy::new(MycRateLimitClass::ConnectionAdmission, 1, 0, 1, 1),
        MycRateLimitPolicy::new(
            MycRateLimitClass::ConnectionAdmission,
            1,
            MYC_RATE_MAX_ATTEMPTS + 1,
            1,
            1,
        ),
        MycRateLimitPolicy::new(MycRateLimitClass::ConnectionAdmission, 2, 1, 1, 1),
        MycRateLimitPolicy::new(
            MycRateLimitClass::ConnectionAdmission,
            1,
            1,
            MYC_RATE_RETENTION_MAX_MS + 1,
            1,
        ),
        MycRateLimitPolicy::new(MycRateLimitClass::ConnectionAdmission, 1, 1, 1, 0),
        MycRateLimitPolicy::new(
            MycRateLimitClass::ConnectionAdmission,
            1,
            1,
            1,
            MYC_RATE_MAX_TRACKED_SUBJECTS + 1,
        ),
    ] {
        assert_eq!(
            invalid.expect_err("invalid rate policy").kind(),
            MycGovernanceStateErrorKind::InvalidRatePolicy
        );
    }

    let maximum_relay = format!("a{}", "1".repeat(MYC_RATE_RELAY_ID_MAX_BYTES - 1));
    assert!(MycRateRelayId::new(&maximum_relay).is_ok());
    for invalid in [
        "",
        "A",
        "relay-name",
        "relay__name",
        "relay_",
        &format!("a{maximum_relay}"),
    ] {
        assert_eq!(
            MycRateRelayId::new(invalid)
                .expect_err("invalid relay ID")
                .kind(),
            MycGovernanceStateErrorKind::InvalidRelayId
        );
    }
    assert!(MycAuditPageLimit::new(MYC_AUDIT_PAGE_MAX_ITEMS).is_ok());
    for value in [0, MYC_AUDIT_PAGE_MAX_ITEMS + 1] {
        assert_eq!(
            MycAuditPageLimit::new(value)
                .expect_err("invalid page limit")
                .kind(),
            MycGovernanceStateErrorKind::InvalidPageLimit
        );
    }
    assert!(
        MycGovernanceCompactionPolicy::new(MYC_AUDIT_RETENTION_MAX_MS, MYC_COMPACTION_MAX_ROWS,)
            .is_ok()
    );
    for invalid in [
        MycGovernanceCompactionPolicy::new(0, 1),
        MycGovernanceCompactionPolicy::new(MYC_AUDIT_RETENTION_MAX_MS + 1, 1),
        MycGovernanceCompactionPolicy::new(1, 0),
        MycGovernanceCompactionPolicy::new(1, MYC_COMPACTION_MAX_ROWS + 1),
    ] {
        let error = invalid.expect_err("invalid compaction policy");
        assert_eq!(
            error.kind(),
            MycGovernanceStateErrorKind::InvalidCompactionPolicy
        );
        assert!(Error::source(&error).is_none());
    }

    let relay = MycRateRelayId::new("relay_secret_123").expect("relay ID");
    let policy =
        MycRateLimitPolicy::new(MycRateLimitClass::ChallengeCreation, 7, 3, 9, 11).expect("policy");
    let rendered = format!("{relay:?} {policy:?} {:?}", audit_correlation(0x91));
    for secret in ["relay_secret_123", "[145, 145", "window_ms", "retention_ms"] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test]
async fn rate_windows_audit_pagination_retention_and_compaction_are_durable_and_bounded() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let configuration = std::str::from_utf8(CONFIG_EXAMPLE)
        .expect("UTF-8 configuration")
        .replacen(
            "[policy.retention]\nterminal_connections_ms = 604800000\nterminal_challenges_ms = 86400000\nrequest_dedup_ms = 604800000\naudit_ms = 2592000000\ncompleted_outbox_ms = 604800000",
            "[policy.retention]\nterminal_connections_ms = 604800000\nterminal_challenges_ms = 86400000\nrequest_dedup_ms = 604800000\naudit_ms = 500\ncompleted_outbox_ms = 604800000",
            1,
        )
        .replacen(
            "[rate_limits.connection_admission]\nscope = \"global_and_relay\"\nwindow_ms = 60000\nmax_attempts = 10\nretention_ms = 3600000\nmaximum_tracked_subjects = 4096",
            "[rate_limits.connection_admission]\nscope = \"global_and_relay\"\nwindow_ms = 100\nmax_attempts = 1\nretention_ms = 200\nmaximum_tracked_subjects = 8",
            1,
        );
    let metadata = metadata_from_bytes(&runtime, configuration.as_bytes());
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let repository = host.repository();

    let first_operation = admit_request(
        &repository,
        client(),
        "rate-first",
        0x80,
        MycSignerRequestMethod::Connect,
        0x81,
        100,
    )
    .await;
    let second_operation = admit_request(
        &repository,
        client(),
        "rate-second",
        0x82,
        MycSignerRequestMethod::Connect,
        0x83,
        100,
    )
    .await;
    let first_request = connection_request(
        first_operation,
        permission_set(&[MycConnectionPermission::Nip44Encrypt]),
        11,
        0x84,
        100,
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
    );
    let unconfigured_relay_request = MycConnectionAdmissionRequest::new(
        first_operation,
        client(),
        permission_set(&[MycConnectionPermission::Nip44Encrypt]),
        policy_generation(11),
        MycConnectionNonce::from_injected_entropy([0x84; 32]),
        time(100),
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
        MycRateRelayId::new("unconfigured").expect("relay ID"),
    )
    .expect("unconfigured relay request");
    assert_eq!(
        repository
            .admit_connection(&unconfigured_relay_request)
            .await
            .expect_err("unconfigured relay")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let second_request = connection_request(
        second_operation,
        permission_set(&[MycConnectionPermission::Nip44Encrypt]),
        11,
        0x85,
        100,
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
    );
    let (first, second) = tokio::join!(
        repository.admit_connection(&first_request),
        repository.admit_connection(&second_request)
    );
    let first = first.expect("first concurrent admission");
    let second = second.expect("second concurrent admission");
    assert_eq!(
        usize::from(matches!(first, MycConnectionAdmission::Admitted(_)))
            + usize::from(matches!(second, MycConnectionAdmission::Admitted(_))),
        1
    );
    assert_eq!(
        usize::from(matches!(first, MycConnectionAdmission::RateLimited))
            + usize::from(matches!(second, MycConnectionAdmission::RateLimited)),
        1
    );
    let (accepted_request, rejected_request) =
        if matches!(first, MycConnectionAdmission::Admitted(_)) {
            (&first_request, &second_request)
        } else {
            (&second_request, &first_request)
        };
    assert!(matches!(
        repository
            .admit_connection(rejected_request)
            .await
            .expect("stable rate-limited replay"),
        MycConnectionAdmission::RateLimited
    ));

    let boundary_operation = admit_request(
        &repository,
        client(),
        "rate-boundary",
        0x86,
        MycSignerRequestMethod::Connect,
        0x87,
        200,
    )
    .await;
    let boundary_request = connection_request(
        boundary_operation,
        permission_set(&[MycConnectionPermission::Nip44Encrypt]),
        11,
        0x88,
        200,
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
    );
    assert!(matches!(
        repository
            .admit_connection(&boundary_request)
            .await
            .expect("exact-window boundary"),
        MycConnectionAdmission::RateLimited
    ));

    let reset_operation = admit_request(
        &repository,
        client(),
        "rate-reset",
        0x89,
        MycSignerRequestMethod::Connect,
        0x8a,
        201,
    )
    .await;
    let reset_request = connection_request(
        reset_operation,
        permission_set(&[MycConnectionPermission::Nip44Encrypt]),
        11,
        0x8b,
        201,
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
    );
    assert!(matches!(
        repository
            .admit_connection(&reset_request)
            .await
            .expect("new window"),
        MycConnectionAdmission::Admitted(_)
    ));

    let page_one = repository
        .read_audit_page(MycAuditPageLimit::new(2).expect("page limit"), None, None)
        .await
        .expect("first audit page");
    assert_eq!(page_one.snapshot_sequence(), 4);
    assert_eq!(page_one.items().len(), 2);
    assert!(
        page_one
            .items()
            .iter()
            .all(|record| record.operation_id().is_some())
    );
    assert_eq!(page_one.items()[0].outcome(), MycAuditOutcome::Succeeded);
    assert_eq!(
        page_one.items()[1].reason(),
        MycAuditReasonCode::RateLimited
    );
    let page_two = repository
        .read_audit_page(
            MycAuditPageLimit::new(2).expect("page limit"),
            Some(page_one.snapshot_sequence()),
            page_one.next_before_sequence(),
        )
        .await
        .expect("second audit page");
    assert_eq!(page_two.items().len(), 2);
    assert!(page_two.next_before_sequence().is_none());
    assert_eq!(
        page_two
            .items()
            .iter()
            .filter(|record| record.outcome() == MycAuditOutcome::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        repository
            .read_audit_page(
                MycAuditPageLimit::new(1).expect("page limit"),
                Some(page_one.snapshot_sequence() + 1),
                None,
            )
            .await
            .expect_err("future snapshot")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    assert_eq!(
        repository
            .compact_governance_evidence(
                time(1_000),
                MycGovernanceCompactionPolicy::new(499, 1).expect("structural policy"),
                audit_correlation(0x8d),
            )
            .await
            .expect_err("retention policy must match bound configuration")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );

    host.close()
        .await
        .expect("host close before retention pass");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopened host");
    let repository = host.repository();
    assert_eq!(
        repository
            .read_audit_page(
                MycAuditPageLimit::new(4).expect("page limit"),
                Some(page_one.snapshot_sequence()),
                None,
            )
            .await
            .expect("reopened audit page")
            .items()
            .len(),
        4
    );
    let compacted = repository
        .compact_governance_evidence(
            time(1_000),
            MycGovernanceCompactionPolicy::new(500, MYC_COMPACTION_MAX_ROWS)
                .expect("compaction policy"),
            audit_correlation(0x8c),
        )
        .await
        .expect("bounded compaction");
    assert_eq!(compacted.removed_audit_records(), 4);
    assert_eq!(compacted.removed_rate_subjects(), 2);
    let replayed_compaction = repository
        .compact_governance_evidence(
            time(1_000),
            MycGovernanceCompactionPolicy::new(500, MYC_COMPACTION_MAX_ROWS)
                .expect("compaction policy"),
            audit_correlation(0x8c),
        )
        .await
        .expect("idempotent compaction replay");
    assert_eq!(replayed_compaction.removed_audit_records(), 0);
    assert_eq!(replayed_compaction.removed_rate_subjects(), 0);
    let retained = repository
        .read_audit_page(MycAuditPageLimit::new(2).expect("page limit"), None, None)
        .await
        .expect("retained compaction audit");
    assert_eq!(retained.items().len(), 1);
    assert_eq!(
        retained.items()[0].kind(),
        MycAuditKind::GovernanceCompaction
    );
    assert_eq!(
        retained.items()[0].correlation_id(),
        audit_correlation(0x8c)
    );
    assert!(retained.items()[0].operation_id().is_none());
    assert_eq!(retained.items()[0].reason(), MycAuditReasonCode::Compacted);
    assert!(matches!(
        repository
            .admit_connection(accepted_request)
            .await
            .expect("authoritative decision replay"),
        MycConnectionAdmission::ExactReplay(_)
    ));
    assert!(matches!(
        repository
            .admit_connection(&reset_request)
            .await
            .expect("second authoritative decision replay"),
        MycConnectionAdmission::ExactReplay(_)
    ));
    host.close().await.expect("final host close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .read_only(true)
        .disable_statement_logging();
    let mut database = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM connections")
            .fetch_one(&mut database)
            .await
            .expect("connection count"),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nip46_request_decisions")
            .fetch_one(&mut database)
            .await
            .expect("decision count"),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM operation_audit")
            .fetch_one(&mut database)
            .await
            .expect("audit count"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM connection_rate_windows")
            .fetch_one(&mut database)
            .await
            .expect("rate count"),
        0
    );
    database.close().await.expect("inspection close");
}

#[tokio::test]
async fn challenge_creation_and_authorization_use_distinct_durable_rate_budgets() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let configuration = std::str::from_utf8(CONFIG_EXAMPLE)
        .expect("UTF-8 configuration")
        .replacen(
            "[rate_limits.challenge_creation]\nscope = \"connection\"\nwindow_ms = 120000\nmax_attempts = 5\nretention_ms = 86400000\nmaximum_tracked_subjects = 16384",
            "[rate_limits.challenge_creation]\nscope = \"connection\"\nwindow_ms = 100\nmax_attempts = 2\nretention_ms = 200\nmaximum_tracked_subjects = 8",
            1,
        )
        .replacen(
            "[rate_limits.challenge_authorization]\nscope = \"connection\"\nwindow_ms = 120000\nmax_attempts = 5\nretention_ms = 86400000\nmaximum_tracked_subjects = 16384",
            "[rate_limits.challenge_authorization]\nscope = \"connection\"\nwindow_ms = 100\nmax_attempts = 1\nretention_ms = 200\nmaximum_tracked_subjects = 8",
            1,
        );
    let metadata = metadata_from_bytes(&runtime, configuration.as_bytes());
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let repository = host.repository();
    let connect = admit_request(
        &repository,
        trusted_client(),
        "distinct-rates-connect",
        0xa0,
        MycSignerRequestMethod::Connect,
        0xa1,
        10,
    )
    .await;
    let connection = repository
        .admit_connection(&connection_request(
            connect,
            permission_set(&[MycConnectionPermission::Nip44Encrypt]),
            17,
            0xa2,
            11,
            Some(1_000),
            MycConnectionAdmissionPolicy::Trusted,
        ))
        .await
        .expect("connection admission")
        .record()
        .expect("admission record")
        .connection()
        .expect("connection")
        .clone();
    let first_operation = admit_request(
        &repository,
        trusted_client(),
        "distinct-rates-first",
        0xa3,
        MycSignerRequestMethod::Ping,
        0xa4,
        20,
    )
    .await;
    let second_operation = admit_request(
        &repository,
        trusted_client(),
        "distinct-rates-second",
        0xa5,
        MycSignerRequestMethod::Ping,
        0xa6,
        21,
    )
    .await;
    let first_request = MycAuthorizationChallengeRequest::new(
        first_operation,
        connection.id(),
        policy_generation(17),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0xa7; 32]),
        time(22),
        time(200),
    )
    .expect("first challenge request");
    let second_request = MycAuthorizationChallengeRequest::new(
        second_operation,
        connection.id(),
        policy_generation(17),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0xa8; 32]),
        time(23),
        time(200),
    )
    .expect("second challenge request");
    let first = repository
        .issue_authorization_challenge(&first_request)
        .await
        .expect("first challenge");
    let second = repository
        .issue_authorization_challenge(&second_request)
        .await
        .expect("second challenge");
    assert!(matches!(
        first,
        MycAuthorizationChallengeAdmission::Created(_)
    ));
    assert!(matches!(
        second,
        MycAuthorizationChallengeAdmission::Created(_)
    ));
    let first_id = first.record().expect("first challenge record").id();
    let second_id = second.record().expect("second challenge record").id();
    assert!(
        repository
            .authorize_challenge(
                first_id,
                connection.id(),
                first_operation,
                policy_generation(17),
                time(24),
            )
            .await
            .expect("first authorization")
            .record()
            .is_some()
    );
    let limited = repository
        .authorize_challenge(
            second_id,
            connection.id(),
            second_operation,
            policy_generation(17),
            time(25),
        )
        .await
        .expect("bounded authorization");
    assert!(limited.record().is_none());
    assert!(format!("{limited:?}").contains("RateLimited"));
    assert!(
        repository
            .authorize_challenge(
                second_id,
                connection.id(),
                second_operation,
                policy_generation(17),
                time(125),
            )
            .await
            .expect("stable authorization rejection")
            .record()
            .is_none()
    );
    host.close().await.expect("host close");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopened host");
    assert!(
        host.repository()
            .authorize_challenge(
                second_id,
                connection.id(),
                second_operation,
                policy_generation(17),
                time(225),
            )
            .await
            .expect("reopened stable rejection")
            .record()
            .is_none()
    );
    host.close().await.expect("final close");
}

#[tokio::test]
async fn connection_admission_and_operator_decisions_are_atomic_replay_safe_and_denial_direct() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let repository = host.repository();

    let trusted_operation = admit_request(
        &repository,
        trusted_client(),
        "connect-trusted",
        0x10,
        MycSignerRequestMethod::Connect,
        0x11,
        100,
    )
    .await;
    let requested = permission_set(&[
        MycConnectionPermission::Nip44Encrypt,
        MycConnectionPermission::SignEvent(1),
    ]);
    let forged_unknown_policy = MycConnectionAdmissionRequest::new(
        trusted_operation,
        trusted_client(),
        requested.clone(),
        policy_generation(1),
        MycConnectionNonce::from_injected_entropy([0x1e; 32]),
        time(110),
        None,
        MycConnectionAdmissionPolicy::ExplicitApproval,
        MycRateRelayId::new("primary").expect("relay ID"),
    )
    .expect("structurally valid forged policy");
    assert_eq!(
        repository
            .admit_connection(&forged_unknown_policy)
            .await
            .expect_err("configuration decides trusted admission")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let above_ceiling = MycConnectionAdmissionRequest::new(
        trusted_operation,
        trusted_client(),
        permission_set(&[MycConnectionPermission::Ping]),
        policy_generation(1),
        MycConnectionNonce::from_injected_entropy([0x1d; 32]),
        time(110),
        Some(time(1_000)),
        MycConnectionAdmissionPolicy::Trusted,
        MycRateRelayId::new("primary").expect("relay ID"),
    )
    .expect("structurally valid permission expansion");
    assert_eq!(
        repository
            .admit_connection(&above_ceiling)
            .await
            .expect_err("configuration permission ceiling")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    assert_eq!(
        repository
            .admit_connection(&connection_request(
                trusted_operation,
                requested.clone(),
                1,
                0x1f,
                99,
                Some(1_000),
                MycConnectionAdmissionPolicy::Trusted,
            ))
            .await
            .expect_err("connection admission cannot predate the request")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let trusted = repository
        .admit_connection(&connection_request(
            trusted_operation,
            requested.clone(),
            1,
            0x20,
            110,
            Some(1_000),
            MycConnectionAdmissionPolicy::Trusted,
        ))
        .await
        .expect("trusted admission");
    assert!(matches!(trusted, MycConnectionAdmission::Admitted(_)));
    assert_eq!(
        trusted.record().expect("admission record").decision(),
        myc::MycConnectionDecision::Allowed
    );
    let trusted_connection = trusted
        .record()
        .expect("admission record")
        .connection()
        .expect("connection");
    assert_eq!(trusted_connection.status(), MycConnectionStatus::Active);
    assert_eq!(trusted_connection.granted_permissions(), &requested);
    let trusted_id = trusted_connection.id();
    assert_eq!(
        hex(trusted_id.as_bytes()),
        "08a11316dac6cf56849f1b7e6e9a50ea4b3e577ee39ea18440c33a1c2ec22671"
    );
    let trusted_replay = repository
        .admit_connection(&connection_request(
            trusted_operation,
            requested.clone(),
            1,
            0x21,
            111,
            Some(1_000),
            MycConnectionAdmissionPolicy::Trusted,
        ))
        .await
        .expect("trusted replay");
    assert!(matches!(
        trusted_replay,
        MycConnectionAdmission::ExactReplay(_)
    ));
    assert_eq!(
        trusted_replay
            .record()
            .expect("admission record")
            .connection()
            .expect("connection")
            .id(),
        trusted_id
    );

    let pending_operation = admit_request(
        &repository,
        client(),
        "connect-pending",
        0x12,
        MycSignerRequestMethod::Connect,
        0x13,
        120,
    )
    .await;
    let pending = repository
        .admit_connection(&connection_request(
            pending_operation,
            requested.clone(),
            2,
            0x22,
            121,
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
        ))
        .await
        .expect("pending admission");
    assert_eq!(
        pending.record().expect("admission record").decision(),
        myc::MycConnectionDecision::PendingApproval
    );
    let pending_id = pending
        .record()
        .expect("admission record")
        .connection()
        .expect("pending connection")
        .id();
    let granted = permission_set(&[MycConnectionPermission::Nip44Encrypt]);
    assert_eq!(
        repository
            .decide_pending_connection(
                pending_operation,
                pending_id,
                policy_generation(2),
                time(130),
                audit_correlation(0x6f),
                MycConnectionOperatorDecision::Approve {
                    granted_permissions: permission_set(&[MycConnectionPermission::Ping]),
                    authorized_until: Some(time(900)),
                },
            )
            .await
            .expect_err("operator cannot expand the configured ceiling")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    assert_eq!(
        repository
            .decide_pending_connection(
                pending_operation,
                pending_id,
                policy_generation(2),
                time(120),
                audit_correlation(0x70),
                MycConnectionOperatorDecision::Approve {
                    granted_permissions: granted.clone(),
                    authorized_until: Some(time(900)),
                },
            )
            .await
            .expect_err("operator decision cannot predate pending state")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let approved = repository
        .decide_pending_connection(
            pending_operation,
            pending_id,
            policy_generation(2),
            time(130),
            audit_correlation(0x71),
            MycConnectionOperatorDecision::Approve {
                granted_permissions: granted.clone(),
                authorized_until: Some(time(900)),
            },
        )
        .await
        .expect("operator approval");
    assert_eq!(approved.status(), MycConnectionStatus::Active);
    assert_eq!(approved.granted_permissions(), &granted);
    let approval_replay = repository
        .decide_pending_connection(
            pending_operation,
            pending_id,
            policy_generation(2),
            time(131),
            audit_correlation(0x71),
            MycConnectionOperatorDecision::Approve {
                granted_permissions: granted.clone(),
                authorized_until: Some(time(900)),
            },
        )
        .await
        .expect("approval replay");
    assert_eq!(approval_replay, approved);
    let admission_after_approval = repository
        .admit_connection(&connection_request(
            pending_operation,
            requested.clone(),
            2,
            0x23,
            132,
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
        ))
        .await
        .expect("admission replay after approval");
    assert!(matches!(
        admission_after_approval,
        MycConnectionAdmission::ExactReplay(_)
    ));
    assert_eq!(
        admission_after_approval
            .record()
            .expect("admission record")
            .decision(),
        myc::MycConnectionDecision::Allowed
    );

    let operator_denied_operation = admit_request(
        &repository,
        client(),
        "connect-operator-denied",
        0x16,
        MycSignerRequestMethod::Connect,
        0x17,
        135,
    )
    .await;
    let operator_pending = repository
        .admit_connection(&connection_request(
            operator_denied_operation,
            requested.clone(),
            2,
            0x27,
            136,
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
        ))
        .await
        .expect("operator-denied pending admission");
    let operator_denied_id = operator_pending
        .record()
        .expect("admission record")
        .connection()
        .expect("operator-denied connection")
        .id();
    let operator_denied = repository
        .decide_pending_connection(
            operator_denied_operation,
            operator_denied_id,
            policy_generation(2),
            time(137),
            audit_correlation(0x72),
            MycConnectionOperatorDecision::Deny,
        )
        .await
        .expect("operator denial");
    assert_eq!(operator_denied.status(), MycConnectionStatus::Denied);
    assert_eq!(
        repository
            .decide_pending_connection(
                operator_denied_operation,
                operator_denied_id,
                policy_generation(2),
                time(138),
                audit_correlation(0x72),
                MycConnectionOperatorDecision::Deny,
            )
            .await
            .expect("operator denial replay"),
        operator_denied
    );

    let denied_operation = admit_request(
        &repository,
        denied_client(),
        "connect-denied",
        0x14,
        MycSignerRequestMethod::Connect,
        0x15,
        140,
    )
    .await;
    let denied = repository
        .admit_connection(&connection_request(
            denied_operation,
            permission_set(&[MycConnectionPermission::Ping]),
            3,
            0x24,
            141,
            None,
            MycConnectionAdmissionPolicy::Denied,
        ))
        .await
        .expect("direct denial");
    assert_eq!(
        denied.record().expect("admission record").decision(),
        myc::MycConnectionDecision::Denied
    );
    assert!(
        denied
            .record()
            .expect("admission record")
            .connection()
            .is_none()
    );
    let denied_replay = repository
        .admit_connection(&connection_request(
            denied_operation,
            permission_set(&[MycConnectionPermission::Ping]),
            3,
            0x25,
            142,
            None,
            MycConnectionAdmissionPolicy::Denied,
        ))
        .await
        .expect("denial replay");
    assert!(matches!(
        denied_replay,
        MycConnectionAdmission::ExactReplay(_)
    ));
    assert!(
        denied_replay
            .record()
            .expect("admission record")
            .connection()
            .is_none()
    );

    let mismatch = repository
        .admit_connection(&connection_request(
            denied_operation,
            permission_set(&[MycConnectionPermission::Nip44Encrypt]),
            3,
            0x26,
            143,
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
        ))
        .await
        .expect_err("policy mismatch");
    assert_eq!(mismatch.kind(), MycStateRepositoryErrorKind::Binding);

    host.close().await.expect("host close");
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .read_only(true)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM connections")
            .fetch_one(&mut connection)
            .await
            .expect("connection count"),
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM nip46_request_decisions WHERE reason_code = 'policy_denied' AND connection_id IS NULL"
        )
        .fetch_one(&mut connection)
        .await
        .expect("direct-denial count"),
        1
    );
    connection.close().await.expect("inspection close");
}

#[tokio::test]
async fn configured_denial_precedes_saturated_unknown_client_rate_windows() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let configuration = std::str::from_utf8(CONFIG_EXAMPLE)
        .expect("UTF-8 configuration")
        .replacen(
            "[rate_limits.connection_admission]\nscope = \"global_and_relay\"\nwindow_ms = 60000\nmax_attempts = 10\nretention_ms = 3600000\nmaximum_tracked_subjects = 4096",
            "[rate_limits.connection_admission]\nscope = \"global_and_relay\"\nwindow_ms = 100\nmax_attempts = 1\nretention_ms = 200\nmaximum_tracked_subjects = 8",
            1,
        );
    let metadata = metadata_from_bytes(&runtime, configuration.as_bytes());
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let repository = host.repository();

    let first = admit_request(
        &repository,
        client(),
        "unknown-first",
        0xb0,
        MycSignerRequestMethod::Connect,
        0xb1,
        100,
    )
    .await;
    let second = admit_request(
        &repository,
        client(),
        "unknown-second",
        0xb2,
        MycSignerRequestMethod::Connect,
        0xb3,
        100,
    )
    .await;
    let denied = admit_request(
        &repository,
        denied_client(),
        "configured-denial",
        0xb4,
        MycSignerRequestMethod::Connect,
        0xb5,
        100,
    )
    .await;
    let trusted_first = admit_request(
        &repository,
        trusted_client(),
        "trusted-first",
        0xb9,
        MycSignerRequestMethod::Connect,
        0xba,
        202,
    )
    .await;
    let trusted_second = admit_request(
        &repository,
        trusted_client(),
        "trusted-second",
        0xbb,
        MycSignerRequestMethod::Connect,
        0xbc,
        202,
    )
    .await;
    let permissions = permission_set(&[MycConnectionPermission::Nip44Encrypt]);
    assert!(matches!(
        repository
            .admit_connection(&connection_request(
                first,
                permissions.clone(),
                1,
                0xb6,
                101,
                None,
                MycConnectionAdmissionPolicy::ExplicitApproval,
            ))
            .await
            .expect("first unknown admission"),
        MycConnectionAdmission::Admitted(_)
    ));
    assert!(matches!(
        repository
            .admit_connection(&connection_request(
                second,
                permissions,
                1,
                0xb7,
                101,
                None,
                MycConnectionAdmissionPolicy::ExplicitApproval,
            ))
            .await
            .expect("saturated unknown admission"),
        MycConnectionAdmission::RateLimited
    ));
    assert!(matches!(
        repository
            .admit_connection(&connection_request(
                trusted_first,
                permission_set(&[MycConnectionPermission::Nip44Encrypt]),
                1,
                0xbd,
                202,
                Some(1_000),
                MycConnectionAdmissionPolicy::Trusted,
            ))
            .await
            .expect("first trusted admission in the next window"),
        MycConnectionAdmission::Admitted(_)
    ));
    assert!(matches!(
        repository
            .admit_connection(&connection_request(
                trusted_second,
                permission_set(&[MycConnectionPermission::Nip44Encrypt]),
                1,
                0xbe,
                202,
                Some(1_000),
                MycConnectionAdmissionPolicy::Trusted,
            ))
            .await
            .expect("saturated trusted admission"),
        MycConnectionAdmission::RateLimited
    ));
    let direct = repository
        .admit_connection(&connection_request(
            denied,
            permission_set(&[MycConnectionPermission::Ping]),
            1,
            0xb8,
            101,
            None,
            MycConnectionAdmissionPolicy::Denied,
        ))
        .await
        .expect("configured denial bypasses unknown-client rate admission");
    assert_eq!(
        direct.record().expect("denial record").decision(),
        myc::MycConnectionDecision::Denied
    );
    assert!(
        direct
            .record()
            .expect("denial record")
            .connection()
            .is_none()
    );
    host.close().await.expect("host close");
}

#[tokio::test]
async fn challenge_authorization_expiry_and_terminal_replay_remain_exactly_bound() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable host");
    let repository = host.repository();

    let connect_operation = admit_request(
        &repository,
        trusted_client(),
        "connect-challenge",
        0x30,
        MycSignerRequestMethod::Connect,
        0x31,
        200,
    )
    .await;
    let connection = repository
        .admit_connection(&connection_request(
            connect_operation,
            permission_set(&[MycConnectionPermission::Nip44Encrypt]),
            7,
            0x32,
            201,
            Some(500),
            MycConnectionAdmissionPolicy::Trusted,
        ))
        .await
        .expect("connection")
        .record()
        .expect("admission record")
        .connection()
        .expect("active connection")
        .clone();

    let ping_operation = admit_request(
        &repository,
        trusted_client(),
        "ping-challenge",
        0x33,
        MycSignerRequestMethod::Ping,
        0x34,
        210,
    )
    .await;
    let invalid_lifetime = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x34; 32]),
        time(211),
        time(211),
    )
    .expect_err("invalid lifetime");
    assert_eq!(
        invalid_lifetime.kind(),
        MycConnectionStateErrorKind::InvalidChallengeLifetime
    );
    let client_selected_url = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://attacker.example/redirect").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x34; 32]),
        time(211),
        time(300),
    )
    .expect("structurally valid client-selected URL");
    assert_eq!(
        repository
            .issue_authorization_challenge(&client_selected_url)
            .await
            .expect_err("only configured operator URL is authoritative")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let excessive_pending_lifetime = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x34; 32]),
        time(211),
        time(900_212),
    )
    .expect("structurally valid excessive pending lifetime");
    assert_eq!(
        repository
            .issue_authorization_challenge(&excessive_pending_lifetime)
            .await
            .expect_err("configured pending lifetime is authoritative")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let challenge_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x35; 32]),
        time(211),
        time(300),
    )
    .expect("challenge request");
    let premature_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x34; 32]),
        time(209),
        time(300),
    )
    .expect("structurally valid premature request");
    assert_eq!(
        repository
            .issue_authorization_challenge(&premature_request)
            .await
            .expect_err("challenge cannot predate request admission")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    let challenge = repository
        .issue_authorization_challenge(&challenge_request)
        .await
        .expect("challenge");
    assert!(matches!(
        challenge,
        MycAuthorizationChallengeAdmission::Created(_)
    ));
    assert_eq!(
        challenge.record().expect("challenge record").state(),
        MycAuthorizationChallengeState::Pending
    );
    let challenge_id = challenge.record().expect("challenge record").id();
    assert_eq!(
        hex(challenge_id.as_bytes()),
        "9a85ce42301af50287626ddcf209a145a2742cf0ef178e44acf06108d1b86b29"
    );

    let replay_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x36; 32]),
        time(211),
        time(300),
    )
    .expect("replay request");
    let replay = repository
        .issue_authorization_challenge(&replay_request)
        .await
        .expect("challenge replay");
    assert!(matches!(
        replay,
        MycAuthorizationChallengeAdmission::ExactReplay(_)
    ));
    assert_eq!(
        replay.record().expect("challenge record").id(),
        challenge_id
    );

    assert_eq!(
        repository
            .authorize_challenge(
                challenge_id,
                connection.id(),
                ping_operation,
                policy_generation(7),
                time(210),
            )
            .await
            .expect_err("resolution cannot predate challenge issue")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );

    let authorized = repository
        .authorize_challenge(
            challenge_id,
            connection.id(),
            ping_operation,
            policy_generation(7),
            time(300),
        )
        .await
        .expect("authorization at exact deadline");
    assert_eq!(
        authorized.record().expect("authorization record").state(),
        MycAuthorizationChallengeState::Authorized
    );
    assert_eq!(
        authorized
            .record()
            .expect("authorization record")
            .resolved_at(),
        Some(time(300))
    );
    let terminal_replay = repository
        .authorize_challenge(
            challenge_id,
            connection.id(),
            ping_operation,
            policy_generation(7),
            time(400),
        )
        .await
        .expect("terminal replay");
    assert_eq!(
        terminal_replay.record().expect("authorization record"),
        authorized.record().expect("authorization record")
    );
    assert_eq!(
        repository
            .authorize_challenge(
                challenge_id,
                connection.id(),
                ping_operation,
                policy_generation(7),
                time(3_600_301),
            )
            .await
            .expect_err("authorized challenge lifetime is bounded by configuration")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );

    let deadline_operation = admit_request(
        &repository,
        trusted_client(),
        "ping-deadline",
        0x3a,
        MycSignerRequestMethod::Ping,
        0x3b,
        410,
    )
    .await;
    let deadline_request = MycAuthorizationChallengeRequest::new(
        deadline_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x3c; 32]),
        time(416),
        time(440),
    )
    .expect("deadline request");
    let deadline_challenge = repository
        .issue_authorization_challenge(&deadline_request)
        .await
        .expect("deadline challenge");
    let deadline_expired = repository
        .authorize_challenge(
            deadline_challenge.record().expect("challenge record").id(),
            connection.id(),
            deadline_operation,
            policy_generation(7),
            time(441),
        )
        .await
        .expect("challenge expiry");
    assert_eq!(
        deadline_expired
            .record()
            .expect("authorization record")
            .state(),
        MycAuthorizationChallengeState::Expired
    );

    let expiring_operation = admit_request(
        &repository,
        trusted_client(),
        "ping-expiring",
        0x37,
        MycSignerRequestMethod::Ping,
        0x38,
        450,
    )
    .await;
    let expiring_request = MycAuthorizationChallengeRequest::new(
        expiring_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://myc.example.test/auth/challenge").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x39; 32]),
        time(451),
        time(600),
    )
    .expect("expiring request");
    let expiring = repository
        .issue_authorization_challenge(&expiring_request)
        .await
        .expect("expiring challenge");
    let expired = repository
        .authorize_challenge(
            expiring.record().expect("challenge record").id(),
            connection.id(),
            expiring_operation,
            policy_generation(7),
            time(501),
        )
        .await
        .expect("connection-expired challenge");
    assert_eq!(
        expired.record().expect("authorization record").state(),
        MycAuthorizationChallengeState::Expired
    );

    let expired_connection = repository
        .expire_connection(
            connection.id(),
            policy_generation(7),
            time(501),
            audit_correlation(0x73),
        )
        .await
        .expect("connection expiry");
    assert_eq!(expired_connection.status(), MycConnectionStatus::Expired);
    assert_eq!(
        repository
            .expire_connection(
                connection.id(),
                policy_generation(7),
                time(502),
                audit_correlation(0x73),
            )
            .await
            .expect("expiry replay"),
        expired_connection
    );
    let challenge_replay_after_connection_expiry = repository
        .issue_authorization_challenge(&replay_request)
        .await
        .expect("challenge replay after connection expiry");
    assert!(matches!(
        challenge_replay_after_connection_expiry,
        MycAuthorizationChallengeAdmission::ExactReplay(_)
    ));
    assert_eq!(
        challenge_replay_after_connection_expiry
            .record()
            .expect("challenge record"),
        authorized.record().expect("authorization record")
    );

    let wrong_binding = repository
        .authorize_challenge(
            challenge_id,
            connection.id(),
            ping_operation,
            policy_generation(8),
            time(400),
        )
        .await
        .expect_err("wrong policy binding");
    assert_eq!(wrong_binding.kind(), MycStateRepositoryErrorKind::Binding);
    let rendered = format!(
        "{challenge:?} {:?} {wrong_binding} {wrong_binding:?}",
        challenge.record().expect("challenge record")
    );
    for secret in [
        "operator.example",
        "authorize",
        CLIENT_PUBLIC_KEY,
        "b0f43d00",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert!(Error::source(&wrong_binding).is_none());

    host.close().await.expect("host close");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopened host");
    let replay = host
        .repository()
        .authorize_challenge(
            challenge_id,
            connection.id(),
            ping_operation,
            policy_generation(7),
            time(700),
        )
        .await
        .expect("restart replay");
    assert_eq!(
        replay.record().expect("authorization record"),
        authorized.record().expect("authorization record")
    );
    host.close().await.expect("final close");
}

#[test]
fn connection_state_source_has_no_ambient_or_external_authority() {
    for forbidden in [
        "rand::",
        "getrandom",
        "std::time",
        "SystemTime",
        "tokio::spawn",
        "spawn_blocking",
        "SqlitePool",
        "SqliteConnection",
        "nostr_sdk",
        "reqwest",
        "relay::",
        "provider::",
    ] {
        assert!(
            !CONNECTION_SOURCE.contains(forbidden),
            "found forbidden connection-state authority `{forbidden}`"
        );
        assert!(
            !GOVERNANCE_SOURCE.contains(forbidden),
            "found forbidden governance-state authority `{forbidden}`"
        );
    }
    for required in [
        "ServiceSqliteTransaction",
        "from_injected_entropy",
        "policy_denied",
        "authorization_challenge_expired",
        "LIMIT 65",
    ] {
        assert!(
            CONNECTION_SOURCE.contains(required),
            "missing governed connection-state boundary `{required}`"
        );
    }
    assert!(GOVERNANCE_SOURCE.contains("ServiceSqliteTransaction"));
    assert!(GOVERNANCE_SOURCE.contains("LIMIT ?"));
    assert!(!GOVERNANCE_SOURCE.contains("SELECT *"));
}
