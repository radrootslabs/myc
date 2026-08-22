#![forbid(unsafe_code)]

use std::process::Command;

use myc::{
    MYC_DIAGNOSTICS_CONTRACT_VERSION, MYC_LOG_RECORD_MAX_UTF8_BYTES, MycLogEvent, MycLogLevel,
    MycLogRecord, MycProcessResult, MycServicePhase,
};

const CONTRACT: &str = include_str!("../contracts/services_hardening/diagnostics.v1.json");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

fn process_results() -> [MycProcessResult; 7] {
    [
        MycProcessResult::Success,
        MycProcessResult::UnexpectedInternal,
        MycProcessResult::InputOrConfiguration,
        MycProcessResult::ServiceOrDependencyUnavailable,
        MycProcessResult::StateOrIdentityUnavailable,
        MycProcessResult::OperationRejectedOrConflict,
        MycProcessResult::DoctorRequiredCheckFailed,
    ]
}

#[test]
fn machine_contract_exit_inventory_matches_the_operator_contract_exactly() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    let operator: serde_json::Value =
        serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    assert_eq!(contract["schema"], "radroots.myc.diagnostics.v1");
    assert_eq!(
        contract["contract_version"],
        MYC_DIAGNOSTICS_CONTRACT_VERSION
    );
    assert_eq!(contract["step"], 156);
    assert_eq!(
        contract["log_record"]["maximum_utf8_bytes_excluding_newline"],
        MYC_LOG_RECORD_MAX_UTF8_BYTES
    );

    let diagnostics = contract["exit_codes"].as_array().expect("exit codes");
    let operator = operator["exit_codes"].as_array().expect("operator exits");
    assert_eq!(diagnostics.len(), operator.len());
    for ((result, diagnostic), operator) in
        process_results().into_iter().zip(diagnostics).zip(operator)
    {
        assert_eq!(diagnostic["code"], result.exit_code_u8());
        assert_eq!(diagnostic["name"], result.code());
        assert_eq!(diagnostic["code"], operator["code"]);
        assert_eq!(diagnostic["name"], operator["name"]);
    }
    assert_eq!(contract["public_error_policy"]["error_source"], "none");
    assert_eq!(contract["stream_policy"]["logs_and_diagnostics"], "stderr");
    assert_eq!(contract["stream_policy"]["file_logging"], false);
}

#[test]
fn process_lifecycle_task_and_signal_records_are_exact_and_bounded() {
    for result in process_results() {
        let record = MycLogRecord::process_result(result);
        let rendered = record.to_string();
        assert_eq!(record.event(), MycLogEvent::ProcessResult);
        assert_eq!(record.code(), result.code());
        assert_eq!(record.process_exit(), Some(result));
        assert!(rendered.len() <= MYC_LOG_RECORD_MAX_UTF8_BYTES);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).expect("record")["exit_code"],
            result.exit_code_u8()
        );
    }

    for (phase, level, code) in [
        (MycServicePhase::Starting, MycLogLevel::Info, "starting"),
        (MycServicePhase::Ready, MycLogLevel::Info, "ready"),
        (MycServicePhase::Degraded, MycLogLevel::Warn, "degraded"),
        (MycServicePhase::Unready, MycLogLevel::Warn, "unready"),
        (MycServicePhase::Stopping, MycLogLevel::Info, "stopping"),
        (MycServicePhase::Failed, MycLogLevel::Error, "failed"),
    ] {
        let record = MycLogRecord::lifecycle(phase);
        assert_eq!(record.level(), level);
        assert_eq!(record.event(), MycLogEvent::Lifecycle);
        assert_eq!(record.code(), code);
        assert_eq!(record.process_exit(), None);
        assert!(!record.to_string().contains("exit_code"));
    }

    for (record, event, code) in [
        (
            MycLogRecord::critical_task_failed(),
            MycLogEvent::CriticalTaskFailed,
            "critical_task_failed",
        ),
        (
            MycLogRecord::shutdown_requested(),
            MycLogEvent::ShutdownRequested,
            "first_signal",
        ),
        (
            MycLogRecord::shutdown_forced(),
            MycLogEvent::ShutdownForced,
            "second_signal",
        ),
    ] {
        assert_eq!(record.event(), event);
        assert_eq!(record.code(), code);
        assert!(record.to_string().len() <= MYC_LOG_RECORD_MAX_UTF8_BYTES);
    }
}

#[test]
fn binary_writes_only_fixed_json_diagnostics_to_stderr() {
    let canary = "secret-canary-private-key-path-sql-relay-url";
    let invalid = Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg(format!("--credential={canary}"))
        .output()
        .expect("invalid invocation");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    let invalid_stderr = String::from_utf8(invalid.stderr).expect("invalid stderr");
    assert_eq!(
        invalid_stderr,
        format!(
            "{}\n",
            MycLogRecord::process_result(MycProcessResult::InputOrConfiguration)
        )
    );
    assert!(!invalid_stderr.contains(canary));

    let unavailable = Command::new(env!("CARGO_BIN_EXE_myc"))
        .args(["--profile", "service-host", "--instance", "primary", "run"])
        .output()
        .expect("admitted invocation");
    assert_eq!(unavailable.status.code(), Some(3));
    assert!(unavailable.stdout.is_empty());
    assert_eq!(
        String::from_utf8(unavailable.stderr).expect("unavailable stderr"),
        format!(
            "{}\n",
            MycLogRecord::process_result(MycProcessResult::ServiceOrDependencyUnavailable)
        )
    );
}
