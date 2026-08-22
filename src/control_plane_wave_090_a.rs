//! Native test-only integration gate for RCLD-RSHR-090 wave 090-a.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    InstanceId, MycBootstrapProfileV1, MycCliOfflineOperationV1, MycCliPrimaryAuthorityV1,
    MycConfigProfile, MycConnectionCountsV1, MycDoctorCheckDefinition, MycDoctorCheckId,
    MycDoctorFuture, MycDoctorObservation, MycDoctorProbe, MycIdentityHealthV1,
    MycIntegrityStateV1, MycLogRecord, MycOperationsCancellationToken, MycOperationsServer,
    MycOutboxStatusV1, MycPersistenceHealthV1, MycPersistenceStatusV1, MycProcessResult,
    MycProviderStatusV1, MycRelayTransportStatusV1, MycServicePhase, MycStatusBuildInfoV1,
    MycStatusBuildMode, MycStatusCommonV1, MycStatusConfigurationIdentityV1,
    MycStatusConfigurationSource, MycStatusObservationV1, MycStatusReasonCodes,
    MycTransportHealthV1, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    myc_status_cache, parse_myc_cli_v1_from, parse_myc_config_v1, plan_myc_cli_v1,
    resolve_myc_runtime_context, run_myc_doctor,
};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CORPUS: &str =
    include_str!("../contracts/services_hardening/control_plane_wave_090_a.v1.json");
const SERVICE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const LIB_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";

struct FixedProbe {
    observations: BTreeMap<MycDoctorCheckId, MycDoctorObservation>,
}

impl FixedProbe {
    fn all(observation: MycDoctorObservation) -> Self {
        Self {
            observations: crate::myc_doctor_check_definitions()
                .iter()
                .map(|definition| (definition.id(), observation))
                .collect(),
        }
    }

    fn with(mut self, id: MycDoctorCheckId, observation: MycDoctorObservation) -> Self {
        self.observations.insert(id, observation);
        self
    }
}

impl MycDoctorProbe for FixedProbe {
    fn probe(&self, definition: MycDoctorCheckDefinition) -> MycDoctorFuture<'_> {
        let observation = self.observations[&definition.id()];
        Box::pin(async move { observation })
    }
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

fn available_port() -> u16 {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

fn status_observation(phase: MycServicePhase, ready: bool) -> MycStatusObservationV1 {
    let empty = MycStatusReasonCodes::empty;
    let build = MycStatusBuildInfoV1::new(
        MycStatusBuildMode::Release,
        Some(env!("CARGO_PKG_VERSION")),
        Some(SERVICE_REVISION),
        Some(LIB_REVISION),
        Some("1.97.1"),
        Some("x86_64-unknown-linux-gnu"),
        Some("service-host"),
    )
    .expect("build info");
    let configuration = MycStatusConfigurationIdentityV1::new(
        "a".repeat(64),
        MycStatusConfigurationSource::ExplicitConfig,
    )
    .expect("configuration identity");
    let persistence = MycPersistenceStatusV1::new(
        MycPersistenceHealthV1::Ready,
        9,
        1,
        MycIntegrityStateV1::Verified,
        empty(),
    )
    .expect("persistence status");
    let identity = || MycIdentityHealthV1::new(true, true, empty()).expect("identity health");
    let provider = MycProviderStatusV1::new(identity(), identity(), identity(), empty())
        .expect("provider status");
    let transport = MycRelayTransportStatusV1::new(MycTransportHealthV1::Ready, true, 2, empty())
        .expect("transport status");
    MycStatusObservationV1::new(
        MycStatusCommonV1::new(phase, ready, empty(), 1, build, configuration, persistence)
            .expect("common status"),
        provider,
        transport,
        MycConnectionCountsV1::default(),
        MycOutboxStatusV1::default(),
    )
}

async fn raw_request(address: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("request write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read");
    String::from_utf8(response).expect("response UTF-8")
}

#[test]
fn machine_corpus_freezes_the_accumulated_wave_and_deferrals() {
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).expect("wave corpus");
    assert_eq!(corpus["schema"], "radroots.myc.control-plane-wave-090-a.v1");
    assert_eq!(corpus["contract_version"], 1);
    assert_eq!(
        corpus["steps"],
        serde_json::json!([152, 153, 154, 155, 156, 157])
    );
    assert_eq!(corpus["authority"]["cli_parse_count"], 1);
    assert_eq!(
        corpus["authority"]["tcp_routes"],
        serde_json::json!(["/livez", "/readyz", "/metrics"])
    );
    assert_eq!(corpus["gate"]["wave"], "090-a");
    assert_eq!(corpus["gate"]["complete_after_step"], 157);
    assert_eq!(corpus["gate"]["rcld_promotion_owner"], 162);
    assert!(
        corpus["nonclaims"]
            .as_array()
            .expect("nonclaims")
            .iter()
            .any(|value| value == "runtime_task_supervision")
    );
}

#[tokio::test]
async fn one_parse_runtime_doctor_and_diagnostics_share_the_exact_exit_contract() {
    let root = tempfile::tempdir().expect("temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root.path().to_str().expect("UTF-8 root"),
        "doctor",
    ])
    .expect("doctor CLI");
    assert_eq!(invocation.profile(), MycBootstrapProfileV1::RepoLocal);
    let plan = plan_myc_cli_v1(&invocation);
    assert_eq!(plan.primary_authority(), MycCliPrimaryAuthorityV1::Offline);
    assert_eq!(
        plan.offline_operation(),
        Some(MycCliOfflineOperationV1::Doctor)
    );
    let runtime = resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context");

    let pass = run_myc_doctor(&runtime, &FixedProbe::all(MycDoctorObservation::Pass))
        .await
        .expect("passing doctor");
    assert_eq!(pass.exit_code(), MycProcessResult::Success.exit_code_u8());

    let fail = run_myc_doctor(
        &runtime,
        &FixedProbe::all(MycDoctorObservation::Pass)
            .with(MycDoctorCheckId::WriterLock, MycDoctorObservation::Fail),
    )
    .await
    .expect("failing doctor report");
    assert_eq!(
        fail.exit_code(),
        MycProcessResult::DoctorRequiredCheckFailed.exit_code_u8()
    );
    assert_eq!(
        MycLogRecord::process_result(MycProcessResult::DoctorRequiredCheckFailed).to_string(),
        r#"{"schema":"radroots.myc.log.v1","contract_version":1,"service":"myc","level":"error","event":"process_result","code":"doctor_required_check_failed","exit_code":6}"#
    );

    let secret = "secret-private-key-path";
    let rejected = parse_myc_cli_v1_from(["myc", &format!("--credential={secret}")])
        .expect_err("ungoverned argument");
    assert!(!format!("{rejected:?} {rejected}").contains(secret));
}

#[tokio::test]
async fn live_status_and_operations_share_only_the_latest_passive_projection() {
    let live = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "service-host",
        "--instance",
        "primary",
        "status",
    ])
    .expect("live status CLI");
    let plan = plan_myc_cli_v1(&live);
    assert_eq!(
        plan.primary_authority(),
        MycCliPrimaryAuthorityV1::LiveUnixAdmin
    );
    assert_eq!(
        plan.offline_operation(),
        Some(MycCliOfflineOperationV1::StateReadOnly)
    );

    let config = parse_myc_config_v1(
        enabled_config(available_port()).as_bytes(),
        MycConfigProfile::Production,
    )
    .expect("operations configuration");
    let (mut publisher, reader) = myc_status_cache(
        InstanceId::new("primary").expect("instance"),
        status_observation(MycServicePhase::Unready, false),
    )
    .expect("status cache");
    let initial_detail = reader.snapshot().detailed_status_json().to_vec();
    let bound = MycOperationsServer::new(&config, &reader)
        .expect("operations server")
        .bind()
        .await
        .expect("operations bind");
    let address = bound.local_address();
    let cancellation = MycOperationsCancellationToken::new();
    let task = tokio::spawn(bound.serve(cancellation.clone()));

    let unready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let detailed = raw_request(
        address,
        b"GET /v1/status HTTP/1.1\r\nhost: localhost\r\n\r\n",
    )
    .await;
    assert!(unready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(detailed.starts_with("HTTP/1.1 404 Not Found\r\n"));

    publisher
        .publish(status_observation(MycServicePhase::Ready, true))
        .expect("ready publication");
    let ready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let metrics = raw_request(address, b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let query = raw_request(
        address,
        b"GET /readyz?probe=1 HTTP/1.1\r\nhost: localhost\r\n\r\n",
    )
    .await;
    assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(ready.ends_with("ready\n"));
    assert!(metrics.contains("radroots_myc_service_phase{phase=\"ready\"} 1\n"));
    assert!(metrics.contains("radroots_myc_service_ready 1\n"));
    assert!(query.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert_ne!(reader.snapshot().detailed_status_json(), initial_detail);

    cancellation.cancel();
    assert_eq!(task.await.expect("server join"), Ok(()));
}
