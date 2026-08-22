#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    InstanceId, MYC_DETAILED_STATUS_MAX_UTF8_BYTES, MYC_STATUS_CACHE_CONTRACT_VERSION,
    MycConnectionCountsV1, MycIdentityHealthV1, MycIntegrityStateV1, MycOutboxStatusV1,
    MycPersistenceHealthV1, MycPersistenceStatusV1, MycProviderStatusV1, MycRelayTransportStatusV1,
    MycServicePhase, MycStatusBuildInfoV1, MycStatusBuildMode, MycStatusCommonV1,
    MycStatusConfigurationIdentityV1, MycStatusConfigurationSource, MycStatusErrorKind,
    MycStatusObservationV1, MycStatusReasonCode, MycStatusReasonCodes, MycStatusUnixSeconds,
    MycTransportHealthV1, myc_status_cache,
};

const CONTRACT: &str = include_str!("../contracts/services_hardening/status_cache.v1.json");
const SERVICE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const LIB_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn reasons(values: &[&str]) -> MycStatusReasonCodes {
    MycStatusReasonCodes::new(
        values
            .iter()
            .map(|value| MycStatusReasonCode::new(value).expect("reason code")),
    )
    .expect("reason codes")
}

fn build_info() -> MycStatusBuildInfoV1 {
    MycStatusBuildInfoV1::new(
        MycStatusBuildMode::Release,
        Some("0.1.0"),
        Some(SERVICE_REVISION),
        Some(LIB_REVISION),
        Some("1.97.1"),
        Some("x86_64-unknown-linux-gnu"),
        Some("service-host"),
    )
    .expect("build info")
}

fn identity(configured: bool, available: bool, reason: &[&str]) -> MycIdentityHealthV1 {
    MycIdentityHealthV1::new(configured, available, reasons(reason)).expect("identity health")
}

fn observation(
    phase: MycServicePhase,
    ready: bool,
    uptime_ms: u64,
    pending_connections: u64,
) -> MycStatusObservationV1 {
    let lifecycle_reasons = if phase == MycServicePhase::Degraded {
        reasons(&["required_relay_unavailable"])
    } else {
        MycStatusReasonCodes::empty()
    };
    let configuration = MycStatusConfigurationIdentityV1::new(
        "a".repeat(64),
        MycStatusConfigurationSource::ExplicitConfig,
    )
    .expect("configuration");
    let persistence = MycPersistenceStatusV1::new(
        MycPersistenceHealthV1::Ready,
        9,
        42,
        MycIntegrityStateV1::Verified,
        MycStatusReasonCodes::empty(),
    )
    .expect("persistence");
    let provider = MycProviderStatusV1::new(
        identity(true, true, &[]),
        identity(true, true, &[]),
        identity(false, false, &[]),
        MycStatusReasonCodes::empty(),
    )
    .expect("provider");
    let transport = MycRelayTransportStatusV1::new(
        if phase == MycServicePhase::Degraded {
            MycTransportHealthV1::Degraded
        } else {
            MycTransportHealthV1::Ready
        },
        phase != MycServicePhase::Degraded,
        2,
        if phase == MycServicePhase::Degraded {
            reasons(&["required_relay_unavailable"])
        } else {
            MycStatusReasonCodes::empty()
        },
    )
    .expect("transport");
    MycStatusObservationV1::new(
        MycStatusCommonV1::new(
            phase,
            ready,
            lifecycle_reasons,
            uptime_ms,
            build_info(),
            configuration,
            persistence,
        )
        .expect("common status"),
        provider,
        transport,
        MycConnectionCountsV1::new(pending_connections, 3, 1, 2),
        MycOutboxStatusV1::new(
            4,
            1,
            Some(MycStatusUnixSeconds::new(1_723_456_789).expect("outbox time")),
        ),
    )
}

#[test]
fn machine_contract_and_canonical_detailed_status_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("status contract");
    assert_eq!(contract["schema"], "radroots.myc.status-cache.v1");
    assert_eq!(
        contract["contract_version"],
        MYC_STATUS_CACHE_CONTRACT_VERSION
    );
    assert_eq!(contract["step"], 154);
    assert_eq!(
        contract["publication"]["capacity"],
        "one_latest_immutable_arc"
    );
    assert_eq!(contract["read"]["fresh_probe"], false);
    assert_eq!(
        contract["detailed_status"]["maximum_utf8_bytes"],
        MYC_DETAILED_STATUS_MAX_UTF8_BYTES
    );
    assert_eq!(
        contract["detailed_status"]["reason_codes"]
            .as_array()
            .expect("reason inventory")
            .iter()
            .map(|value| value.as_str().expect("reason"))
            .collect::<Vec<_>>(),
        [
            MycStatusReasonCode::IdentityUnavailable,
            MycStatusReasonCode::DatabaseSchemaMismatch,
            MycStatusReasonCode::DatabaseReadOnly,
            MycStatusReasonCode::DatabaseLowDisk,
            MycStatusReasonCode::RequiredRelayUnavailable,
            MycStatusReasonCode::SubscriberNotActive,
            MycStatusReasonCode::SignerProviderUnavailable,
            MycStatusReasonCode::OutboxInvariantFailed,
            MycStatusReasonCode::PublicationBacklogExceeded,
            MycStatusReasonCode::AdminListenerFailed,
            MycStatusReasonCode::OperationsListenerFailed,
            MycStatusReasonCode::ShutdownInProgress,
        ]
        .map(MycStatusReasonCode::as_str)
    );

    let (_publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Ready, true, 120_000, 5),
    )
    .expect("status cache");
    let snapshot = reader.snapshot();
    let wire = std::str::from_utf8(snapshot.detailed_status_json()).expect("status UTF-8");
    assert_eq!(
        wire,
        r#"{"contract_version":1,"service":"myc","instance":"primary","phase":"ready","ready":true,"uptime_millis":120000,"reason_codes":[],"build_info":{"version":"0.1.0","revision":"0123456789abcdef0123456789abcdef01234567","toolchain":"1.97.1","contract_versions":{"config":1,"state":9,"admin":1,"status":1,"provider":1}},"configuration":{"schema":"radroots.myc.config","schema_version":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":"explicit_config"},"persistence":{"health":"ready","schema_version":9,"generation":42,"integrity":"verified","reason_codes":[]},"provider":{"health":"ready","transport":{"configured":true,"available":true,"reason_codes":[]},"user":{"configured":true,"available":true,"reason_codes":[]},"discovery":{"configured":false,"available":false,"reason_codes":[]},"reason_codes":[]},"transport":{"health":"ready","required_relays_ready":true,"connected_relay_count":2,"reason_codes":[]},"myc":{"transport":{"configured":true,"available":true,"reason_codes":[]},"user":{"configured":true,"available":true,"reason_codes":[]},"discovery":{"configured":false,"available":false,"reason_codes":[]},"connection_counts":{"pending":5,"active":3,"denied":1,"expired":2},"outbox":{"pending":4,"unknown":1,"oldest_pending_at_utc":1723456789}}}"#
    );
    assert!(wire.len() < MYC_DETAILED_STATUS_MAX_UTF8_BYTES);
    for forbidden in [
        "secret",
        "credential",
        "private_key",
        "password",
        "filesystem_path",
        "relay_url",
        "raw_error",
    ] {
        assert!(!wire.contains(forbidden), "wire leaked `{forbidden}`");
    }
}

#[tokio::test]
async fn latest_publication_is_atomic_passive_and_retains_old_snapshots() {
    let (mut publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Starting, false, 0, 9),
    )
    .expect("status cache");
    let old = reader.snapshot();
    let old_pointer = old.detailed_status_json().as_ptr();
    for _ in 0..1_000 {
        let same = reader.snapshot();
        assert_eq!(same.detailed_status_json().as_ptr(), old_pointer);
        assert_eq!(same.phase(), MycServicePhase::Starting);
    }

    let mut changed = publisher.subscribe();
    publisher
        .publish(observation(MycServicePhase::Ready, true, 10, 2))
        .expect("ready publication");
    publisher
        .publish(observation(MycServicePhase::Degraded, true, 20, 1))
        .expect("degraded publication");

    let latest = changed.changed().await.expect("latest publication");
    assert_eq!(latest.phase(), MycServicePhase::Degraded);
    assert!(latest.is_ready());
    assert!(
        std::str::from_utf8(latest.detailed_status_json())
            .expect("status UTF-8")
            .contains("\"uptime_millis\":20")
    );
    assert_eq!(old.phase(), MycServicePhase::Starting);
    assert!(
        std::str::from_utf8(old.detailed_status_json())
            .expect("old UTF-8")
            .contains("\"uptime_millis\":0")
    );
}

#[tokio::test]
async fn illegal_transition_and_publisher_drop_preserve_the_last_valid_value() {
    let (mut publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Starting, false, 1, 0),
    )
    .expect("status cache");
    let before = reader.snapshot().detailed_status_json().to_vec();
    let error = publisher
        .publish(observation(MycServicePhase::Unready, false, 2, 0))
        .expect_err("illegal starting to unready transition");
    assert_eq!(error.kind(), MycStatusErrorKind::InvalidTransition);
    assert_eq!(reader.snapshot().detailed_status_json(), before);
    assert!(Error::source(&error).is_none());

    let mut dropped = publisher.subscribe();
    drop(publisher);
    let dropped_error = dropped.changed().await.expect_err("publisher dropped");
    assert_eq!(dropped_error.kind(), MycStatusErrorKind::PublisherDropped);
    assert_eq!(reader.snapshot().detailed_status_json(), before);
}

#[test]
fn closed_role_counts_time_and_safe_debug_bound_the_status_surface() {
    let counts = MycConnectionCountsV1::new(u64::MAX, 2, 3, 4);
    assert_eq!(counts.pending(), u64::MAX);
    assert_eq!(counts.active(), 2);
    assert_eq!(counts.denied(), 3);
    assert_eq!(counts.expired(), 4);
    assert_eq!(MycStatusUnixSeconds::new(0).expect("zero").get(), 0);
    assert_eq!(
        MycStatusUnixSeconds::new(i64::MAX as u64)
            .expect("maximum")
            .get(),
        i64::MAX as u64
    );
    assert_eq!(
        MycStatusUnixSeconds::new(i64::MAX as u64 + 1)
            .expect_err("over maximum")
            .kind(),
        MycStatusErrorKind::InvalidTime
    );

    let (publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Ready, true, 5, 0),
    )
    .expect("status cache");
    let rendered = format!("{publisher:?} {reader:?} {:?}", reader.snapshot());
    for forbidden in [
        SERVICE_REVISION,
        LIB_REVISION,
        "radroots.myc.config",
        "aaaaaaaaaaaaaaaa",
        "oldest_pending_at_utc",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn model_boundaries_fail_closed_before_publication() {
    assert_eq!(
        MycStatusReasonCode::new("")
            .expect_err("empty reason")
            .kind(),
        MycStatusErrorKind::InvalidReasonCode
    );
    assert_eq!(
        MycStatusReasonCode::new("secret_canary_value")
            .expect_err("unknown reason")
            .kind(),
        MycStatusErrorKind::InvalidReasonCode
    );
    let maximum = [
        MycStatusReasonCode::IdentityUnavailable,
        MycStatusReasonCode::DatabaseSchemaMismatch,
        MycStatusReasonCode::DatabaseReadOnly,
        MycStatusReasonCode::DatabaseLowDisk,
        MycStatusReasonCode::RequiredRelayUnavailable,
        MycStatusReasonCode::SubscriberNotActive,
        MycStatusReasonCode::SignerProviderUnavailable,
        MycStatusReasonCode::OutboxInvariantFailed,
        MycStatusReasonCode::PublicationBacklogExceeded,
        MycStatusReasonCode::AdminListenerFailed,
        MycStatusReasonCode::OperationsListenerFailed,
        MycStatusReasonCode::ShutdownInProgress,
    ];
    assert_eq!(
        MycStatusReasonCodes::new(maximum)
            .expect("maximum reasons")
            .as_slice()
            .len(),
        12
    );
    let mut infinite = std::iter::repeat(MycStatusReasonCode::IdentityUnavailable);
    assert_eq!(
        MycStatusReasonCodes::new(&mut infinite)
            .expect_err("bounded infinite iterator")
            .kind(),
        MycStatusErrorKind::TooManyReasonCodes
    );
    assert_eq!(
        infinite.next().expect("iterator retained"),
        MycStatusReasonCode::IdentityUnavailable
    );

    assert_eq!(
        MycStatusBuildInfoV1::new(
            MycStatusBuildMode::Release,
            Some("0.1.0"),
            None,
            Some(LIB_REVISION),
            Some("1.97.1"),
            Some("x86_64-unknown-linux-gnu"),
            Some("service-host"),
        )
        .expect_err("release revision required")
        .kind(),
        MycStatusErrorKind::InvalidBuildInfo
    );
    assert_eq!(
        MycStatusConfigurationIdentityV1::new(
            "A".repeat(64),
            MycStatusConfigurationSource::ExplicitConfig,
        )
        .expect_err("lowercase digest required")
        .kind(),
        MycStatusErrorKind::InvalidConfiguration
    );
    assert_eq!(
        MycPersistenceStatusV1::new(
            MycPersistenceHealthV1::Ready,
            0,
            0,
            MycIntegrityStateV1::Verified,
            MycStatusReasonCodes::empty(),
        )
        .expect_err("positive schema required")
        .kind(),
        MycStatusErrorKind::InvalidPersistence
    );

    let error = MycStatusCommonV1::new(
        MycServicePhase::Ready,
        false,
        MycStatusReasonCodes::empty(),
        0,
        build_info(),
        MycStatusConfigurationIdentityV1::new(
            "a".repeat(64),
            MycStatusConfigurationSource::ExplicitConfig,
        )
        .expect("configuration"),
        MycPersistenceStatusV1::new(
            MycPersistenceHealthV1::Ready,
            9,
            0,
            MycIntegrityStateV1::Verified,
            MycStatusReasonCodes::empty(),
        )
        .expect("persistence"),
    )
    .expect_err("ready phase requires readiness");
    assert_eq!(error.kind(), MycStatusErrorKind::InvalidLifecycle);
}

#[test]
fn provider_aggregate_and_optional_oldest_time_are_deterministic() {
    let ready = MycProviderStatusV1::new(
        identity(true, true, &[]),
        identity(true, true, &[]),
        identity(false, false, &[]),
        MycStatusReasonCodes::empty(),
    )
    .expect("ready provider");
    assert_eq!(ready.health(), myc::MycProviderHealthV1::Ready);

    let degraded = MycProviderStatusV1::new(
        identity(true, true, &[]),
        identity(true, true, &[]),
        identity(true, false, &["identity_unavailable"]),
        reasons(&["identity_unavailable"]),
    )
    .expect("degraded provider");
    assert_eq!(degraded.health(), myc::MycProviderHealthV1::Degraded);

    let unavailable = MycProviderStatusV1::new(
        identity(true, false, &["identity_unavailable"]),
        identity(true, true, &[]),
        identity(false, false, &[]),
        reasons(&["identity_unavailable"]),
    )
    .expect("unavailable provider");
    assert_eq!(unavailable.health(), myc::MycProviderHealthV1::Unavailable);

    let (_publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        MycStatusObservationV1::new(
            MycStatusCommonV1::new(
                MycServicePhase::Ready,
                true,
                MycStatusReasonCodes::empty(),
                1,
                build_info(),
                MycStatusConfigurationIdentityV1::new(
                    "a".repeat(64),
                    MycStatusConfigurationSource::ExplicitConfig,
                )
                .expect("configuration"),
                MycPersistenceStatusV1::new(
                    MycPersistenceHealthV1::Ready,
                    9,
                    0,
                    MycIntegrityStateV1::Verified,
                    MycStatusReasonCodes::empty(),
                )
                .expect("persistence"),
            )
            .expect("common status"),
            ready,
            MycRelayTransportStatusV1::new(
                MycTransportHealthV1::Ready,
                true,
                0,
                MycStatusReasonCodes::empty(),
            )
            .expect("transport"),
            MycConnectionCountsV1::default(),
            MycOutboxStatusV1::new(0, 0, None),
        ),
    )
    .expect("cache");
    let wire = std::str::from_utf8(reader.snapshot().detailed_status_json())
        .expect("status UTF-8")
        .to_owned();
    assert!(wire.contains("\"outbox\":{\"pending\":0,\"unknown\":0}"));
    assert!(!wire.contains("oldest_pending_at_utc"));
}
