#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::{
    MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES, MYC_CONNECTION_PERMISSION_MAX_COUNT,
    MYC_STATE_SCHEMA_VERSION, MycAuthorizationChallengeAdmission, MycAuthorizationChallengeNonce,
    MycAuthorizationChallengeRequest, MycAuthorizationChallengeState, MycAuthorizationChallengeUrl,
    MycConfigProfile, MycConnectionAdmission, MycConnectionAdmissionPolicy,
    MycConnectionAdmissionRequest, MycConnectionNonce, MycConnectionOperatorDecision,
    MycConnectionPermission, MycConnectionPermissionSet, MycConnectionPolicyGeneration,
    MycConnectionStateErrorKind, MycConnectionStatus, MycConnectionTimeUnixMs,
    MycNip46ClientPublicKey, MycNip46EventId, MycNip46RequestId, MycRequestReceivedAtUnixMs,
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
const CLIENT_PUBLIC_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

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
    let configuration =
        parse_myc_config_v1(CONFIG_EXAMPLE, MycConfigProfile::RepoLocal).expect("configuration");
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
        "b44119fbac5985be8127ad1bf56d2950e6399427",
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

fn permission_set(permissions: &[MycConnectionPermission]) -> MycConnectionPermissionSet {
    MycConnectionPermissionSet::new(permissions).expect("permission set")
}

fn time(value: u64) -> MycConnectionTimeUnixMs {
    MycConnectionTimeUnixMs::new(value).expect("connection time")
}

fn policy_generation(value: u64) -> MycConnectionPolicyGeneration {
    MycConnectionPolicyGeneration::new(value).expect("policy generation")
}

async fn admit_request(
    repository: &MycStateRepository<'_>,
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
        client(),
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
        client(),
        permissions,
        policy_generation(generation),
        MycConnectionNonce::from_injected_entropy([nonce_byte; 32]),
        time(observed_at),
        authorized_until.map(time),
        policy,
    )
    .expect("connection request")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn connection_inputs_are_closed_bounded_canonical_and_redacted() {
    let maximum = (0..MYC_CONNECTION_PERMISSION_MAX_COUNT)
        .map(|kind| MycConnectionPermission::SignEvent(u16::try_from(kind).expect("kind")))
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
        .map(|kind| MycConnectionPermission::SignEvent(u16::try_from(kind).expect("kind")))
        .collect::<Vec<_>>();
    assert_eq!(
        MycConnectionPermissionSet::new(&excessive)
            .expect_err("excessive permissions")
            .kind(),
        MycConnectionStateErrorKind::InvalidPermissionSet
    );
    assert!(MycConnectionPermissionSet::new(&[]).is_ok());

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
        "connect-trusted",
        0x10,
        MycSignerRequestMethod::Connect,
        0x11,
        100,
    )
    .await;
    let requested = permission_set(&[
        MycConnectionPermission::Ping,
        MycConnectionPermission::SignEvent(1),
    ]);
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
        trusted.record().decision(),
        myc::MycConnectionDecision::Allowed
    );
    let trusted_connection = trusted.record().connection().expect("connection");
    assert_eq!(trusted_connection.status(), MycConnectionStatus::Active);
    assert_eq!(trusted_connection.granted_permissions(), &requested);
    let trusted_id = trusted_connection.id();
    assert_eq!(
        hex(trusted_id.as_bytes()),
        "8819838c497a75152f7c1cd80b8e3bd7836fb84e002e62280f657a5f74903c5c"
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
            .connection()
            .expect("connection")
            .id(),
        trusted_id
    );

    let pending_operation = admit_request(
        &repository,
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
        pending.record().decision(),
        myc::MycConnectionDecision::PendingApproval
    );
    let pending_id = pending
        .record()
        .connection()
        .expect("pending connection")
        .id();
    let granted = permission_set(&[MycConnectionPermission::Ping]);
    assert_eq!(
        repository
            .decide_pending_connection(
                pending_operation,
                pending_id,
                policy_generation(2),
                time(120),
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
        admission_after_approval.record().decision(),
        myc::MycConnectionDecision::Allowed
    );

    let operator_denied_operation = admit_request(
        &repository,
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
        .connection()
        .expect("operator-denied connection")
        .id();
    let operator_denied = repository
        .decide_pending_connection(
            operator_denied_operation,
            operator_denied_id,
            policy_generation(2),
            time(137),
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
                MycConnectionOperatorDecision::Deny,
            )
            .await
            .expect("operator denial replay"),
        operator_denied
    );

    let denied_operation = admit_request(
        &repository,
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
            requested.clone(),
            3,
            0x24,
            141,
            None,
            MycConnectionAdmissionPolicy::Denied,
        ))
        .await
        .expect("direct denial");
    assert_eq!(
        denied.record().decision(),
        myc::MycConnectionDecision::Denied
    );
    assert!(denied.record().connection().is_none());
    let denied_replay = repository
        .admit_connection(&connection_request(
            denied_operation,
            requested,
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
    assert!(denied_replay.record().connection().is_none());

    let mismatch = repository
        .admit_connection(&connection_request(
            denied_operation,
            permission_set(&[MycConnectionPermission::Ping]),
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
            permission_set(&[MycConnectionPermission::Ping]),
            7,
            0x32,
            201,
            Some(500),
            MycConnectionAdmissionPolicy::Trusted,
        ))
        .await
        .expect("connection")
        .record()
        .connection()
        .expect("active connection")
        .clone();

    let ping_operation = admit_request(
        &repository,
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
        MycAuthorizationChallengeUrl::new("https://operator.example/").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x34; 32]),
        time(211),
        time(211),
    )
    .expect_err("invalid lifetime");
    assert_eq!(
        invalid_lifetime.kind(),
        MycConnectionStateErrorKind::InvalidChallengeLifetime
    );
    let challenge_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://operator.example/authorize").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x35; 32]),
        time(211),
        time(300),
    )
    .expect("challenge request");
    let premature_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://operator.example/authorize").expect("URL"),
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
        challenge.record().state(),
        MycAuthorizationChallengeState::Pending
    );
    let challenge_id = challenge.record().id();
    assert_eq!(
        hex(challenge_id.as_bytes()),
        "b0f43d00c70db2bf058d461a2c1ac940ef52cfc76a4d271b7bbc89464fb25abb"
    );

    let replay_request = MycAuthorizationChallengeRequest::new(
        ping_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://operator.example/authorize").expect("URL"),
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
    assert_eq!(replay.record().id(), challenge_id);

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
        authorized.state(),
        MycAuthorizationChallengeState::Authorized
    );
    assert_eq!(authorized.resolved_at(), Some(time(300)));
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
    assert_eq!(terminal_replay, authorized);

    let deadline_operation = admit_request(
        &repository,
        "ping-deadline",
        0x3a,
        MycSignerRequestMethod::Ping,
        0x3b,
        215,
    )
    .await;
    let deadline_request = MycAuthorizationChallengeRequest::new(
        deadline_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://operator.example/deadline").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x3c; 32]),
        time(216),
        time(240),
    )
    .expect("deadline request");
    let deadline_challenge = repository
        .issue_authorization_challenge(&deadline_request)
        .await
        .expect("deadline challenge");
    let deadline_expired = repository
        .authorize_challenge(
            deadline_challenge.record().id(),
            connection.id(),
            deadline_operation,
            policy_generation(7),
            time(241),
        )
        .await
        .expect("challenge expiry");
    assert_eq!(
        deadline_expired.state(),
        MycAuthorizationChallengeState::Expired
    );

    let expiring_operation = admit_request(
        &repository,
        "ping-expiring",
        0x37,
        MycSignerRequestMethod::Ping,
        0x38,
        220,
    )
    .await;
    let expiring_request = MycAuthorizationChallengeRequest::new(
        expiring_operation,
        connection.id(),
        policy_generation(7),
        MycAuthorizationChallengeUrl::new("https://operator.example/expiry").expect("URL"),
        MycAuthorizationChallengeNonce::from_injected_entropy([0x39; 32]),
        time(221),
        time(600),
    )
    .expect("expiring request");
    let expiring = repository
        .issue_authorization_challenge(&expiring_request)
        .await
        .expect("expiring challenge");
    let expired = repository
        .authorize_challenge(
            expiring.record().id(),
            connection.id(),
            expiring_operation,
            policy_generation(7),
            time(501),
        )
        .await
        .expect("connection-expired challenge");
    assert_eq!(expired.state(), MycAuthorizationChallengeState::Expired);

    let expired_connection = repository
        .expire_connection(connection.id(), policy_generation(7), time(501))
        .await
        .expect("connection expiry");
    assert_eq!(expired_connection.status(), MycConnectionStatus::Expired);
    assert_eq!(
        repository
            .expire_connection(connection.id(), policy_generation(7), time(502))
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
        challenge_replay_after_connection_expiry.record(),
        &authorized
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
        challenge.record()
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
    assert_eq!(replay, authorized);
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
}
