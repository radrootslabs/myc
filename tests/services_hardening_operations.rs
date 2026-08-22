#![forbid(unsafe_code)]

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use myc::{
    InstanceId, MYC_LIVEZ_PATH, MYC_METRICS_PATH, MYC_OPERATIONS_CONTRACT_VERSION, MYC_READYZ_PATH,
    MycConfigProfile, MycConnectionCountsV1, MycIdentityHealthV1, MycIntegrityStateV1,
    MycOperationsCancellationToken, MycOperationsErrorKind, MycOperationsServer, MycOutboxStatusV1,
    MycPersistenceHealthV1, MycPersistenceStatusV1, MycProviderStatusV1, MycRelayTransportStatusV1,
    MycServicePhase, MycStatusBuildInfoV1, MycStatusBuildMode, MycStatusCommonV1,
    MycStatusConfigurationIdentityV1, MycStatusConfigurationSource, MycStatusObservationV1,
    MycStatusReasonCodes, MycTransportHealthV1, myc_status_cache, parse_myc_config_v1,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONTRACT: &str = include_str!("../contracts/services_hardening/tcp_operations.v1.json");
const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const SERVICE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const LIB_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";

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

fn identity(configured: bool, available: bool) -> MycIdentityHealthV1 {
    MycIdentityHealthV1::new(configured, available, MycStatusReasonCodes::empty())
        .expect("identity health")
}

fn observation(phase: MycServicePhase, ready: bool) -> MycStatusObservationV1 {
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
        identity(true, true),
        identity(true, true),
        identity(false, false),
        MycStatusReasonCodes::empty(),
    )
    .expect("provider");
    let transport = MycRelayTransportStatusV1::new(
        MycTransportHealthV1::Ready,
        true,
        2,
        MycStatusReasonCodes::empty(),
    )
    .expect("transport");
    MycStatusObservationV1::new(
        MycStatusCommonV1::new(
            phase,
            ready,
            MycStatusReasonCodes::empty(),
            1,
            build_info(),
            configuration,
            persistence,
        )
        .expect("common status"),
        provider,
        transport,
        MycConnectionCountsV1::default(),
        MycOutboxStatusV1::new(0, 0, None),
    )
}

fn available_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("ephemeral listener");
    listener.local_addr().expect("local address").port()
}

fn enabled_config(port: u16) -> String {
    CONFIG.replacen(
        "[operations]\nenabled = false",
        &format!(
            "[operations]\nenabled = true\nlisten = \"127.0.0.1:{port}\"\nbind_policy = \"loopback_only\"\n\n[operations.limits]\nheader_count = 16\nheader_bytes = 8192\nresponse_body_utf8_bytes = 4096\nconcurrent_connections = 4\nrequest_deadline_ms = 500\nidle_timeout_ms = 500"
        ),
        1,
    )
}

async fn raw_request(address: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("request write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read");
    response
}

fn response_text(response: &[u8]) -> &str {
    std::str::from_utf8(response).expect("response UTF-8")
}

#[test]
fn machine_contract_freezes_exact_routes_metrics_and_non_authority() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.myc.tcp-operations.v1");
    assert_eq!(
        contract["contract_version"],
        MYC_OPERATIONS_CONTRACT_VERSION
    );
    assert_eq!(contract["step"], 155);
    assert_eq!(
        contract["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .map(|route| route["path"].as_str().expect("route path"))
            .collect::<Vec<_>>(),
        [MYC_LIVEZ_PATH, MYC_READYZ_PATH, MYC_METRICS_PATH]
    );
    assert_eq!(contract["route_registration_extension"], false);
    assert_eq!(contract["metrics"]["high_cardinality_labels"], false);
    assert_eq!(contract["metrics"]["arbitrary_labels"], false);
}

#[tokio::test]
async fn exact_tcp_routes_use_only_latest_cached_lifecycle_and_metrics() {
    let config = parse_myc_config_v1(
        enabled_config(available_port()).as_bytes(),
        MycConfigProfile::Production,
    )
    .expect("enabled config");
    let (mut publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Ready, true),
    )
    .expect("status cache");
    let detail_pointer = reader.snapshot().detailed_status_json().as_ptr();
    let bound = MycOperationsServer::new(&config, &reader)
        .expect("operations server")
        .bind()
        .await
        .expect("bind");
    let address = bound.local_address();
    let cancellation = MycOperationsCancellationToken::new();
    let task = tokio::spawn(bound.serve(cancellation.clone()));

    let live = raw_request(address, b"GET /livez HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let ready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let metrics = raw_request(address, b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    assert!(response_text(&live).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response_text(&live).ends_with("live\n"));
    assert!(response_text(&ready).ends_with("ready\n"));
    assert!(response_text(&metrics).contains("# TYPE radroots_myc_service_phase gauge\n"));
    assert!(response_text(&metrics).contains("radroots_myc_service_phase{phase=\"ready\"} 1\n"));
    assert!(response_text(&metrics).contains("radroots_myc_service_ready 1\n"));

    for request in [
        &b"GET /status HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
        &b"GET /readyz?probe=1 HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
        &b"POST /metrics HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\n\r\n"[..],
        &b"GET /v1/status HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
    ] {
        let rejected = raw_request(address, request).await;
        assert!(response_text(&rejected).starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    publisher
        .publish(observation(MycServicePhase::Unready, false))
        .expect("unready publication");
    let unready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let metrics = raw_request(address, b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    assert!(response_text(&unready).starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response_text(&unready).ends_with("unready\n"));
    assert!(response_text(&metrics).contains("radroots_myc_service_phase{phase=\"unready\"} 1\n"));
    assert!(response_text(&metrics).contains("radroots_myc_service_ready 0\n"));
    assert_ne!(
        reader.snapshot().detailed_status_json().as_ptr(),
        detail_pointer
    );

    cancellation.cancel();
    assert_eq!(task.await.expect("serve task"), Ok(()));
}

#[tokio::test]
async fn disabled_invalid_and_bind_failures_are_typed_source_free_and_redacted() {
    let disabled = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::Production)
        .expect("disabled config");
    let (_, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(MycServicePhase::Ready, true),
    )
    .expect("status cache");
    let disabled_error =
        MycOperationsServer::new(&disabled, &reader).expect_err("disabled operations");
    assert_eq!(disabled_error.kind(), MycOperationsErrorKind::Disabled);
    assert_eq!(disabled_error.code(), "operations_disabled");
    assert!(Error::source(&disabled_error).is_none());

    let below_floor =
        enabled_config(available_port()).replace("header_bytes = 8192", "header_bytes = 8191");
    assert!(parse_myc_config_v1(below_floor.as_bytes(), MycConfigProfile::Production).is_err());

    let occupied =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("occupied listener");
    let port = occupied.local_addr().expect("occupied address").port();
    let config = parse_myc_config_v1(
        enabled_config(port).as_bytes(),
        MycConfigProfile::Production,
    )
    .expect("enabled config");
    let server = MycOperationsServer::new(&config, &reader).expect("server");
    assert!(!format!("{server:?}").contains(&port.to_string()));
    let bind_error = server.bind().await.expect_err("occupied bind");
    assert_eq!(bind_error.kind(), MycOperationsErrorKind::Bind);
    assert!(Error::source(&bind_error).is_none());
    assert!(!format!("{bind_error:?} {bind_error}").contains(&port.to_string()));
}
