//! Native test-only integration gate for RCLD-RSHR-080 wave 080-a.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use nostr::{
    EventBuilder, JsonUtil as _, Keys, Kind, Tag, Timestamp, UnsignedEvent as NostrUnsignedEvent,
    nips::{nip04, nip44},
};
use radroots_nostr_connect::{
    Method,
    message::{Request, RequestMessage, UnsignedEvent as ConnectUnsignedEvent},
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use serde_json::{Value, json};

use crate::{
    MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION, MYC_STATE_SCHEMA_VERSION, MycAuditCorrelationId,
    MycConfigDocumentV1, MycConfigProfile, MycConnectionAdmission, MycConnectionAdmissionPolicy,
    MycConnectionNonce, MycConnectionOperatorDecision, MycConnectionPermission,
    MycConnectionPermissionSet, MycConnectionPolicyGeneration, MycConnectionStatus,
    MycConnectionTimeUnixMs, MycLocalSignerUntrustedResponse, MycNip46AdmissionLimits,
    MycNip46AuthoredTimePolicy, MycNip46ObservedAtUnixSeconds, MycNip46WorkErrorKind,
    MycNip46WorkKind, MycPreparedNip46Request, MycProviderCapability, MycProviderDeadlineUnixMs,
    MycProviderResponseObservedAtUnixMs, MycProviderRole, MycRateRelayId,
    MycRequestReceivedAtUnixMs, MycSignerOperationNonce, MycSignerRequestAdmission,
    MycStateMetadata, MycStateRepository, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, admit_myc_nip46_event, initialize_myc_state, open_myc_state_read_write,
    parse_myc_cli_v1_from, parse_myc_config_v1, prepare_myc_nip46_decrypt_work,
    prepare_myc_nip46_request, prepare_myc_nip46_work,
    provider_local_signer::{
        LocalSignerResponse, LocalSignerUntrustedParts, WireCapability, WireProviderInstance,
        WireProviderResult, WireRole,
    },
    provider_verification::verify_protected_response_for_test,
    resolve_myc_runtime_context, verify_myc_nip46_event,
};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CORPUS: &str = include_str!("../contracts/services_hardening/nip46_wave_080_a.v1.json");
pub(crate) const OBSERVED_AT_SECONDS: u64 = 1_725_000_000;
pub(crate) const RECEIVED_AT_MS: u64 = 1_725_000_000_000;
pub(crate) const PROVIDER_DEADLINE_MS: u64 = RECEIVED_AT_MS + 120_000;

#[derive(Clone, Copy)]
pub(crate) enum Encryption {
    Nip04,
    Nip44V2,
}

pub(crate) fn keys(seed: u8) -> Keys {
    Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
}

fn configuration_source() -> String {
    CONFIG
        .replacen(
            "4444444444444444444444444444444444444444444444444444444444444444",
            &keys(2).public_key().to_hex(),
            1,
        )
        .replacen(
            "2222222222222222222222222222222222222222222222222222222222222222",
            &keys(3).public_key().to_hex(),
            1,
        )
        .replacen("max_attempts = 10", "max_attempts = 2", 1)
}

pub(crate) fn configuration() -> MycConfigDocumentV1 {
    parse_myc_config_v1(
        configuration_source().as_bytes(),
        MycConfigProfile::RepoLocal,
    )
    .expect("wave configuration")
}

pub(crate) fn runtime(root: &Path) -> crate::MycRuntimeContext {
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
    .expect("test invocation");
    resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

pub(crate) fn metadata(runtime: &crate::MycRuntimeContext) -> MycStateMetadata {
    MycStateMetadata::new(
        runtime,
        &configuration(),
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        RECEIVED_AT_MS,
    )
    .expect("state metadata")
}

pub(crate) fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at =
        MigrationAppliedAtUnixSeconds::new(OBSERVED_AT_SECONDS).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "d287d41c2cd97cd0e455445da90f22180029f089",
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

fn decrypt_work(
    config: &MycConfigDocumentV1,
    client: &Keys,
    request_id: &str,
    request: Request,
    encryption: Encryption,
    created_at: u64,
) -> (crate::MycNip46DecryptWork, Vec<u8>) {
    let transport_keys = keys(2);
    let message = RequestMessage::try_new(request_id.to_owned(), request).expect("request message");
    let plaintext = serde_json::to_vec(&message).expect("canonical request");
    let content = match encryption {
        Encryption::Nip04 => nip04::encrypt(
            client.secret_key(),
            &transport_keys.public_key(),
            &plaintext,
        )
        .expect("NIP-04 encryption"),
        Encryption::Nip44V2 => nip44::encrypt(
            client.secret_key(),
            &transport_keys.public_key(),
            &plaintext,
            nip44::Version::V2,
        )
        .expect("NIP-44 encryption"),
    };
    let event = EventBuilder::new(Kind::Custom(24_133), content)
        .tag(Tag::public_key(transport_keys.public_key()))
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(client)
        .expect("signed event");
    let wire = serde_json::to_vec(&event).expect("event wire");
    let limits = MycNip46AdmissionLimits::from_config(config).expect("admission limits");
    let verified = verify_myc_nip46_event(
        admit_myc_nip46_event(limits, &wire).expect("bounded event"),
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT_SECONDS).expect("observation"),
        MycNip46AuthoredTimePolicy::new(120, 120).expect("authored-time policy"),
    )
    .expect("verified event");
    let work = prepare_myc_nip46_decrypt_work(
        verified,
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("provider deadline"),
    )
    .expect("decrypt work");
    (work, plaintext)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepared_request(
    config: &MycConfigDocumentV1,
    client: &Keys,
    request_id: &str,
    request: Request,
    encryption: Encryption,
    created_at: u64,
    nonce: u8,
    received_at: u64,
) -> MycPreparedNip46Request {
    let (work, plaintext) =
        decrypt_work(config, client, request_id, request, encryption, created_at);
    let transport = config
        .provider_contract()
        .binding(MycProviderRole::Transport)
        .expect("transport binding");
    let response = verify_protected_response_for_test(transport, work.operation(), &plaintext)
        .expect("verified provider response");
    let decrypted = work
        .complete(
            response,
            MycNip46AdmissionLimits::from_config(config).expect("admission limits"),
        )
        .expect("decrypted request");
    prepare_myc_nip46_request(
        decrypted,
        MycSignerOperationNonce::from_injected_entropy([nonce; 32]),
        MycRequestReceivedAtUnixMs::new(received_at).expect("request time"),
    )
    .expect("prepared request")
}

pub(crate) fn connect_request() -> Request {
    Request::from_parts(
        Method::Connect,
        vec![
            keys(2).public_key().to_hex(),
            String::new(),
            "sign_event:kind:1".to_owned(),
        ],
    )
    .expect("connect request")
}

pub(crate) fn unsigned_sign_event() -> ConnectUnsignedEvent {
    let event = NostrUnsignedEvent::new(
        keys(3).public_key(),
        Timestamp::from_secs(OBSERVED_AT_SECONDS),
        Kind::TextNote,
        Vec::<Tag>::new(),
        "wave-080-a",
    );
    ConnectUnsignedEvent::from_json(&event.as_json()).expect("unsigned event")
}

pub(crate) fn permissions() -> MycConnectionPermissionSet {
    MycConnectionPermissionSet::new(&[MycConnectionPermission::SignEvent(1)]).expect("permissions")
}

pub(crate) fn connection_time(value: u64) -> MycConnectionTimeUnixMs {
    MycConnectionTimeUnixMs::new(value).expect("connection time")
}

pub(crate) fn untrusted_response(
    operation: &crate::MycProviderOperation,
    outer_correlation_id: String,
    result: WireProviderResult,
) -> MycLocalSignerUntrustedResponse {
    MycLocalSignerUntrustedResponse::from_parts(LocalSignerUntrustedParts {
        outer_correlation_id: outer_correlation_id.into_boxed_str(),
        response: LocalSignerResponse {
            contract_version: MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION,
            provider_instance: WireProviderInstance::from(operation.instance()),
            role: WireRole::from(operation.role()),
            operation_id: hex::encode(operation.operation_id().as_bytes()),
            correlation_id: hex::encode(operation.correlation_id().as_bytes()),
            absolute_deadline_unix_ms: operation.deadline().get(),
            expected_identity: operation.expected_identity().as_hex().to_owned(),
            capability: WireCapability::from(operation.input().capability()),
            result,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn admit_connect(
    repository: &MycStateRepository<'_>,
    config: &MycConfigDocumentV1,
    client_seed: u8,
    request_id: &str,
    created_at: u64,
    received_at: u64,
    nonce: u8,
    observed_at: u64,
) -> MycConnectionAdmission {
    let prepared = prepared_request(
        config,
        &keys(client_seed),
        request_id,
        connect_request(),
        Encryption::Nip44V2,
        created_at,
        nonce,
        received_at,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("durable request admission");
    let work = prepare_myc_nip46_work(
        prepared,
        admitted.record().clone(),
        None,
        config.provider_contract(),
        connection_time(observed_at),
        None,
    )
    .expect("connect work");
    let request = work
        .connection_admission_request(
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            MycConnectionNonce::from_injected_entropy([nonce.wrapping_add(1); 32]),
            connection_time(observed_at),
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
            MycRateRelayId::new("primary").expect("relay ID"),
        )
        .expect("connection admission request");
    repository
        .admit_connection(&request)
        .await
        .expect("connection admission")
}

#[test]
fn machine_corpus_freezes_the_complete_first_wave_gate() {
    let actual: Value = serde_json::from_str(CORPUS).expect("wave corpus");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.myc.nip46-wave-080-a.v1",
            "contract_version": 1,
            "steps": [141, 142, 143, 144, 145, 146],
            "positive_corpus": [
                "nip04_ping_full_pipeline",
                "nip44_ping_full_pipeline",
                "nip44_connect_durable_approval",
                "nip44_sign_event_provider_work"
            ],
            "negative_corpus": [
                "wrong_event_provider_response",
                "wrong_outer_provider_correlation",
                "late_provider_response",
                "wrong_provider_result_shape",
                "conflicting_request_id_reuse"
            ],
            "replay": {
                "exact_request": "idempotent_durable_record",
                "conflicting_request_id": "durable_conflicting_reuse",
                "cross_event_provider_response": "rejected_before_plaintext_admission"
            },
            "saturation": {
                "authority": "configured_connection_admission_rate_window",
                "configured_max_attempts": 2,
                "exact_boundary": "admitted",
                "just_over_boundary": "rate_limited_without_connection"
            },
            "integration_order": [
                "bounded_event",
                "cryptographic_event_verification",
                "provider_decrypt_work",
                "independent_provider_result_verification",
                "bounded_plaintext_request",
                "replay_binding",
                "durable_request_admission",
                "connection_authorization",
                "provider_work_construction"
            ],
            "authority": {
                "state": "existing_myc_state_repository",
                "sqlite": "existing_service_sqlite_transaction_runner",
                "time": "injected",
                "entropy": "injected",
                "provider_execution": "not_performed",
                "relay_io": "not_performed"
            },
            "gate": {
                "wave": "080-a",
                "complete_after_step": 146,
                "rcld_promotion_owner": 151
            },
            "nonclaims": [
                "response_commit",
                "outbox_creation",
                "relay_publication",
                "rcld_promotion",
                "nix",
                "oci"
            ]
        })
    );
}

#[test]
fn canonical_nip04_and_nip44_reach_the_same_typed_boundary() {
    let config = configuration();
    for (index, encryption) in [Encryption::Nip04, Encryption::Nip44V2]
        .into_iter()
        .enumerate()
    {
        let prepared = prepared_request(
            &config,
            &keys(1),
            &format!("positive-{index}"),
            Request::Ping,
            encryption,
            OBSERVED_AT_SECONDS + u64::try_from(index).expect("index"),
            u8::try_from(index + 1).expect("nonce"),
            RECEIVED_AT_MS + u64::try_from(index).expect("index"),
        );
        assert_eq!(prepared.method(), crate::MycSignerRequestMethod::Ping);
    }
}

#[test]
fn cross_event_provider_result_is_rejected_before_plaintext_admission() {
    let config = configuration();
    let client = keys(1);
    let (first, plaintext) = decrypt_work(
        &config,
        &client,
        "malicious-1",
        Request::Ping,
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 1,
    );
    let (second, _) = decrypt_work(
        &config,
        &client,
        "malicious-2",
        Request::Ping,
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 2,
    );
    let response = verify_protected_response_for_test(
        config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding"),
        first.operation(),
        &plaintext,
    )
    .expect("verified first response");
    assert_eq!(
        second
            .complete(
                response,
                MycNip46AdmissionLimits::from_config(&config).expect("limits"),
            )
            .expect_err("cross-event response")
            .kind(),
        MycNip46WorkErrorKind::InvalidBinding
    );
}

#[tokio::test]
async fn durable_replay_authorization_provider_and_saturation_gate_is_atomic() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let metadata = metadata(&runtime);
    let config = configuration();
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("state initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writable state");
    let repository = host.repository();

    let prepared = prepared_request(
        &config,
        &keys(10),
        "connect-primary",
        connect_request(),
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 10,
        10,
        RECEIVED_AT_MS + 10,
    );
    let admitted = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("new durable request");
    assert!(matches!(admitted, MycSignerRequestAdmission::Admitted(_)));
    let replay = repository
        .admit_signer_request(prepared.signer_request())
        .await
        .expect("exact replay");
    assert!(matches!(replay, MycSignerRequestAdmission::ExactReplay(_)));
    assert_eq!(
        replay.record().operation_id(),
        admitted.record().operation_id()
    );

    let connect_work = prepare_myc_nip46_work(
        prepared,
        admitted.record().clone(),
        None,
        config.provider_contract(),
        connection_time(RECEIVED_AT_MS + 1_000),
        None,
    )
    .expect("connect work");
    assert_eq!(connect_work.kind(), MycNip46WorkKind::Connect);
    let connection_request = connect_work
        .connection_admission_request(
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            MycConnectionNonce::from_injected_entropy([0x41; 32]),
            connection_time(RECEIVED_AT_MS + 1_000),
            None,
            MycConnectionAdmissionPolicy::ExplicitApproval,
            MycRateRelayId::new("primary").expect("relay ID"),
        )
        .expect("connection request");
    let pending = repository
        .admit_connection(&connection_request)
        .await
        .expect("pending connection");
    let pending_record = pending.record().expect("pending record");
    let pending_connection = pending_record.connection().expect("pending connection");
    assert_eq!(pending_connection.status(), MycConnectionStatus::Pending);
    let active = repository
        .decide_pending_connection(
            pending_record.operation_id(),
            pending_connection.id(),
            MycConnectionPolicyGeneration::new(1).expect("policy generation"),
            connection_time(RECEIVED_AT_MS + 2_000),
            MycAuditCorrelationId::new([0x42; 32]),
            MycConnectionOperatorDecision::Approve {
                granted_permissions: permissions(),
                authorized_until: Some(connection_time(RECEIVED_AT_MS + 100_000)),
            },
        )
        .await
        .expect("approved connection");
    assert_eq!(active.status(), MycConnectionStatus::Active);

    let sign_request = prepared_request(
        &config,
        &keys(10),
        "sign-primary",
        Request::SignEvent(unsigned_sign_event()),
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 11,
        11,
        RECEIVED_AT_MS + 11,
    );
    let sign_admission = repository
        .admit_signer_request(sign_request.signer_request())
        .await
        .expect("sign request admission");
    let sign_work = prepare_myc_nip46_work(
        sign_request,
        sign_admission.record().clone(),
        Some(active),
        config.provider_contract(),
        connection_time(RECEIVED_AT_MS + 3_000),
        Some(MycProviderDeadlineUnixMs::new(PROVIDER_DEADLINE_MS).expect("provider deadline")),
    )
    .expect("sign provider work");
    assert_eq!(sign_work.kind(), MycNip46WorkKind::Provider);
    let operation = sign_work.provider_operation().expect("provider operation");
    assert_eq!(
        operation.input().capability(),
        MycProviderCapability::SignEvent
    );

    let wrong_outer = untrusted_response(
        operation,
        "00".repeat(32),
        WireProviderResult::PublicIdentity {
            public_identity: operation.expected_identity().as_hex().to_owned(),
        },
    );
    assert_eq!(
        wrong_outer
            .verify(
                config
                    .provider_contract()
                    .binding(MycProviderRole::User)
                    .expect("user binding"),
                operation,
                MycProviderResponseObservedAtUnixMs::new(RECEIVED_AT_MS + 3_001)
                    .expect("response time"),
            )
            .expect_err("wrong outer correlation")
            .kind(),
        crate::MycProviderVerificationErrorKind::ResponseBinding
    );
    let late = untrusted_response(
        operation,
        hex::encode(operation.correlation_id().as_bytes()),
        WireProviderResult::PublicIdentity {
            public_identity: operation.expected_identity().as_hex().to_owned(),
        },
    );
    assert_eq!(
        late.verify(
            config
                .provider_contract()
                .binding(MycProviderRole::User)
                .expect("user binding"),
            operation,
            MycProviderResponseObservedAtUnixMs::new(PROVIDER_DEADLINE_MS + 1)
                .expect("late response time"),
        )
        .expect_err("late provider response")
        .kind(),
        crate::MycProviderVerificationErrorKind::LateResponse
    );
    let wrong_shape = untrusted_response(
        operation,
        hex::encode(operation.correlation_id().as_bytes()),
        WireProviderResult::PublicIdentity {
            public_identity: operation.expected_identity().as_hex().to_owned(),
        },
    );
    assert_eq!(
        wrong_shape
            .verify(
                config
                    .provider_contract()
                    .binding(MycProviderRole::User)
                    .expect("user binding"),
                operation,
                MycProviderResponseObservedAtUnixMs::new(RECEIVED_AT_MS + 3_001)
                    .expect("response time"),
            )
            .expect_err("wrong provider result shape")
            .kind(),
        crate::MycProviderVerificationErrorKind::ResultShape
    );

    let conflicting = prepared_request(
        &config,
        &keys(10),
        "sign-primary",
        Request::Ping,
        Encryption::Nip44V2,
        OBSERVED_AT_SECONDS + 12,
        12,
        RECEIVED_AT_MS + 12,
    );
    assert!(matches!(
        repository
            .admit_signer_request(conflicting.signer_request())
            .await
            .expect("conflict admission"),
        MycSignerRequestAdmission::ConflictingReuse(_)
    ));

    let exact_boundary = admit_connect(
        &repository,
        &config,
        11,
        "connect-boundary",
        OBSERVED_AT_SECONDS + 20,
        RECEIVED_AT_MS + 20,
        20,
        RECEIVED_AT_MS + 1_100,
    )
    .await;
    assert!(matches!(
        exact_boundary,
        MycConnectionAdmission::Admitted(_)
    ));
    let saturated = admit_connect(
        &repository,
        &config,
        12,
        "connect-saturated",
        OBSERVED_AT_SECONDS + 21,
        RECEIVED_AT_MS + 21,
        21,
        RECEIVED_AT_MS + 1_200,
    )
    .await;
    assert!(matches!(saturated, MycConnectionAdmission::RateLimited));
    assert!(saturated.record().is_none());

    host.close().await.expect("host close");
}
