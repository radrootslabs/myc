#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    future::pending,
    sync::{Arc, Mutex},
};

use myc::{
    MYC_DOCTOR_CHECK_COUNT, MYC_DOCTOR_CONTRACT_VERSION, MYC_DOCTOR_REPORT_MAX_UTF8_BYTES,
    MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES, MycDoctorAggregateStatus, MycDoctorCheckDefinition,
    MycDoctorCheckId, MycDoctorCheckStatus, MycDoctorFuture, MycDoctorObservation, MycDoctorProbe,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, myc_doctor_check_definitions,
    parse_myc_cli_v1_from, resolve_myc_runtime_context, run_myc_doctor,
};
use sha2::{Digest, Sha256};

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

struct TestProbe {
    outcomes: BTreeMap<MycDoctorCheckId, MycDoctorObservation>,
    pending: Option<MycDoctorCheckId>,
    calls: Arc<Mutex<Vec<MycDoctorCheckId>>>,
}

impl TestProbe {
    fn all(outcome: MycDoctorObservation) -> Self {
        Self {
            outcomes: myc_doctor_check_definitions()
                .iter()
                .map(|definition| (definition.id(), outcome))
                .collect(),
            pending: None,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with(mut self, id: MycDoctorCheckId, outcome: MycDoctorObservation) -> Self {
        self.outcomes.insert(id, outcome);
        self
    }

    fn pending(mut self, id: MycDoctorCheckId) -> Self {
        self.pending = Some(id);
        self
    }
}

impl MycDoctorProbe for TestProbe {
    fn probe(&self, definition: MycDoctorCheckDefinition) -> MycDoctorFuture<'_> {
        let id = definition.id();
        self.calls.lock().expect("calls lock").push(id);
        if self.pending == Some(id) {
            return Box::pin(pending());
        }
        let outcome = self.outcomes[&id];
        Box::pin(async move { outcome })
    }
}

fn runtime() -> (tempfile::TempDir, myc::MycRuntimeContext) {
    let directory = tempfile::tempdir().expect("temporary root");
    let root = directory.path().to_str().expect("UTF-8 path");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root,
        "doctor",
    ])
    .expect("doctor invocation");
    let context = resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context");
    (directory, context)
}

#[test]
fn exact_inventory_matches_the_operator_contract() {
    let contract: serde_json::Value = serde_json::from_str(OPERATOR_CONTRACT).expect("contract");
    let doctor = contract["doctor"].as_object().expect("doctor");
    assert_eq!(
        doctor
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "aggregate_statuses",
            "checks",
            "contract_version",
            "detached_probe_work",
            "execution",
            "pass_requires_all_scope",
            "probe_future_cancellation",
            "raw_error_or_path_allowed",
            "report_max_utf8_bytes",
            "required_fail_or_timeout_exit",
            "required_skipped",
            "shared_schema",
            "statuses",
            "summary_max_utf8_bytes",
        ])
    );
    assert_eq!(MYC_DOCTOR_CONTRACT_VERSION, 1);
    assert_eq!(MYC_DOCTOR_CHECK_COUNT, 13);
    assert_eq!(MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES, 256);
    assert_eq!(MYC_DOCTOR_REPORT_MAX_UTF8_BYTES, 8_192);
    assert_eq!(doctor["execution"], "ordered");
    assert_eq!(doctor["pass_requires_all_scope"], true);
    assert_eq!(
        doctor["probe_future_cancellation"],
        "drop_stops_or_owns_cleanup"
    );
    assert_eq!(doctor["detached_probe_work"], false);
    assert_eq!(doctor["required_skipped"], "forbidden");
    assert_eq!(doctor["raw_error_or_path_allowed"], false);
    assert_eq!(doctor["required_fail_or_timeout_exit"], 6);

    let rows = doctor["checks"].as_array().expect("checks");
    assert_eq!(rows.len(), MYC_DOCTOR_CHECK_COUNT);
    for (definition, row) in myc_doctor_check_definitions().iter().zip(rows) {
        assert_eq!(row["id"], id_name(definition.id()));
        assert_eq!(row["required"], definition.required());
        assert_eq!(row["deadline_ms"], definition.deadline_ms());
        assert_eq!(
            row["remediation_code"],
            remediation_name(definition.remediation_code())
        );
        assert_eq!(
            row["scope"],
            serde_json::to_value(definition.scope()).expect("scope")
        );
    }
}

#[tokio::test]
async fn all_pass_is_canonical_bounded_and_exit_zero() {
    let (_directory, context) = runtime();
    let probe = TestProbe::all(MycDoctorObservation::Pass);
    let report = run_myc_doctor(&context, &probe).await.expect("report");
    assert_eq!(report.service(), "myc");
    assert_eq!(report.instance().as_str(), "primary");
    assert_eq!(report.status(), MycDoctorAggregateStatus::Pass);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.checks().len(), MYC_DOCTOR_CHECK_COUNT);
    assert!(
        report
            .checks()
            .iter()
            .all(|result| result.status() == MycDoctorCheckStatus::Pass)
    );
    assert_eq!(
        probe.calls.lock().expect("calls").len(),
        MYC_DOCTOR_CHECK_COUNT
    );

    let bytes = report.canonical_json();
    assert!(bytes.len() <= MYC_DOCTOR_REPORT_MAX_UTF8_BYTES);
    assert!(!bytes.contains(&b'\n'));
    let wire: serde_json::Value = serde_json::from_slice(bytes).expect("JSON");
    assert_eq!(wire["contract_version"], 1);
    assert_eq!(wire["service"], "myc");
    assert_eq!(wire["instance"], "primary");
    assert_eq!(wire["status"], "pass");
    assert_eq!(wire["checks"].as_array().expect("checks").len(), 13);
    assert!(String::from_utf8_lossy(bytes).starts_with(
        "{\"contract_version\":1,\"service\":\"myc\",\"instance\":\"primary\",\"status\":\"pass\",\"checks\":["
    ));
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "19d7b33a205ed26fa6cf8c0c77ada75cdea7a1e01bca45efa72f95c65ac645ce"
    );
}

#[tokio::test]
async fn optional_nonpass_is_degraded_but_successful() {
    let (_directory, context) = runtime();
    for outcome in [MycDoctorObservation::Fail, MycDoctorObservation::Skipped] {
        let probe =
            TestProbe::all(MycDoctorObservation::Pass).with(MycDoctorCheckId::ClockSkew, outcome);
        let report = run_myc_doctor(&context, &probe).await.expect("report");
        assert_eq!(report.status(), MycDoctorAggregateStatus::Degraded);
        assert_eq!(report.exit_code(), 0);
        assert_ne!(report.checks()[12].status(), MycDoctorCheckStatus::Pass);
    }
}

#[tokio::test]
async fn required_fail_and_skip_are_fail_closed() {
    let (_directory, context) = runtime();
    for outcome in [MycDoctorObservation::Fail, MycDoctorObservation::Skipped] {
        let probe =
            TestProbe::all(MycDoctorObservation::Pass).with(MycDoctorCheckId::WriterLock, outcome);
        let report = run_myc_doctor(&context, &probe).await.expect("report");
        assert_eq!(report.status(), MycDoctorAggregateStatus::Fail);
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.checks()[1].status(), MycDoctorCheckStatus::Fail);
    }
}

#[tokio::test]
async fn required_timeout_is_bounded_and_remaining_checks_continue_in_order() {
    let (_directory, context) = runtime();
    let probe =
        TestProbe::all(MycDoctorObservation::Pass).pending(MycDoctorCheckId::PathsPermissions);
    let report = run_myc_doctor(&context, &probe).await.expect("report");
    assert_eq!(report.status(), MycDoctorAggregateStatus::Fail);
    assert_eq!(report.exit_code(), 6);
    assert_eq!(report.checks()[0].status(), MycDoctorCheckStatus::Timeout);
    let calls = probe.calls.lock().expect("calls").clone();
    assert_eq!(
        calls,
        myc_doctor_check_definitions()
            .iter()
            .map(|definition| definition.id())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn report_debug_and_error_surface_retain_no_sensitive_values() {
    let directory = tempfile::tempdir().expect("temporary root");
    let root = directory.path().join("secret-root");
    let root = root.to_str().expect("UTF-8 path");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "secret-instance",
        "--repo-local-root",
        root,
        "doctor",
    ])
    .expect("doctor invocation");
    let context = resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context");
    let report = run_myc_doctor(&context, &TestProbe::all(MycDoctorObservation::Pass))
        .await
        .expect("report");
    let debug = format!("{report:?}");
    assert!(!debug.contains("secret-instance"));
    assert!(!debug.contains("secret-root"));
    for result in report.checks() {
        assert!(result.summary().len() <= MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    }

    let rendered = format!("{:?}", myc::MycDoctorErrorKind::OutputTooLarge);
    assert!(!rendered.contains("secret"));
}

fn id_name(id: MycDoctorCheckId) -> &'static str {
    match id {
        MycDoctorCheckId::PathsPermissions => "paths_permissions",
        MycDoctorCheckId::WriterLock => "writer_lock",
        MycDoctorCheckId::SqliteSchema => "sqlite_schema",
        MycDoctorCheckId::SqliteIntegrity => "sqlite_integrity",
        MycDoctorCheckId::SqliteFreeSpace => "sqlite_free_space",
        MycDoctorCheckId::IdentityBinding => "identity_binding",
        MycDoctorCheckId::SignerProvider => "signer_provider",
        MycDoctorCheckId::AdminBindPolicy => "admin_bind_policy",
        MycDoctorCheckId::OperationsBindPolicy => "operations_bind_policy",
        MycDoctorCheckId::NetworkPolicy => "network_policy",
        MycDoctorCheckId::RequiredRelays => "required_relays",
        MycDoctorCheckId::OutboxInvariants => "outbox_invariants",
        MycDoctorCheckId::ClockSkew => "clock_skew",
    }
}

fn remediation_name(code: myc::MycDoctorRemediationCode) -> &'static str {
    match code {
        myc::MycDoctorRemediationCode::CorrectPathPolicy => "correct_path_policy",
        myc::MycDoctorRemediationCode::ReleaseWriterLock => "release_writer_lock",
        myc::MycDoctorRemediationCode::RepairSchema => "repair_schema",
        myc::MycDoctorRemediationCode::RestoreVerifiedState => "restore_verified_state",
        myc::MycDoctorRemediationCode::FreeStateDiskSpace => "free_state_disk_space",
        myc::MycDoctorRemediationCode::RestoreIdentityBinding => "restore_identity_binding",
        myc::MycDoctorRemediationCode::RepairSignerProvider => "repair_signer_provider",
        myc::MycDoctorRemediationCode::CorrectAdminBindPolicy => "correct_admin_bind_policy",
        myc::MycDoctorRemediationCode::CorrectOperationsBindPolicy => {
            "correct_operations_bind_policy"
        }
        myc::MycDoctorRemediationCode::CorrectNetworkPolicy => "correct_network_policy",
        myc::MycDoctorRemediationCode::RestoreRequiredRelays => "restore_required_relays",
        myc::MycDoctorRemediationCode::RepairOutboxState => "repair_outbox_state",
        myc::MycDoctorRemediationCode::CorrectClock => "correct_clock",
    }
}
