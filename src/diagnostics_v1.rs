//! Closed process-result and structured stderr diagnostic contract.

use core::fmt;
use std::process::ExitCode;

use crate::MycServicePhase;

/// Exact Myc diagnostics contract version.
pub const MYC_DIAGNOSTICS_CONTRACT_VERSION: u32 = 1;

/// Hard maximum for one canonical Myc structured log record, excluding newline.
pub const MYC_LOG_RECORD_MAX_UTF8_BYTES: usize = 512;

const LOG_SCHEMA: &str = "radroots.myc.log.v1";

/// Exact stable Myc process result and exit-code inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycProcessResult {
    Success,
    UnexpectedInternal,
    InputOrConfiguration,
    ServiceOrDependencyUnavailable,
    StateOrIdentityUnavailable,
    OperationRejectedOrConflict,
    DoctorRequiredCheckFailed,
}

impl MycProcessResult {
    #[must_use]
    pub const fn exit_code_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::UnexpectedInternal => 1,
            Self::InputOrConfiguration => 2,
            Self::ServiceOrDependencyUnavailable => 3,
            Self::StateOrIdentityUnavailable => 4,
            Self::OperationRejectedOrConflict => 5,
            Self::DoctorRequiredCheckFailed => 6,
        }
    }

    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.exit_code_u8())
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UnexpectedInternal => "unexpected_internal",
            Self::InputOrConfiguration => "input_or_configuration",
            Self::ServiceOrDependencyUnavailable => "service_or_dependency_unavailable",
            Self::StateOrIdentityUnavailable => "state_or_identity_unavailable",
            Self::OperationRejectedOrConflict => "operation_rejected_or_conflict",
            Self::DoctorRequiredCheckFailed => "doctor_required_check_failed",
        }
    }
}

/// Closed structured-log severity vocabulary admitted by Myc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl MycLogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Closed structured-log event vocabulary required by the current runtime plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycLogEvent {
    ProcessResult,
    Lifecycle,
    CriticalTaskFailed,
    ShutdownRequested,
    ShutdownForced,
}

impl MycLogEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessResult => "process_result",
            Self::Lifecycle => "lifecycle",
            Self::CriticalTaskFailed => "critical_task_failed",
            Self::ShutdownRequested => "shutdown_requested",
            Self::ShutdownForced => "shutdown_forced",
        }
    }
}

/// One sealed canonical structured log record containing only governed values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycLogRecord {
    level: MycLogLevel,
    event: MycLogEvent,
    code: &'static str,
    process_result: Option<MycProcessResult>,
}

impl MycLogRecord {
    /// Builds the exact terminal record for one governed process result.
    #[must_use]
    pub const fn process_result(result: MycProcessResult) -> Self {
        let level = match result {
            MycProcessResult::Success => MycLogLevel::Info,
            MycProcessResult::OperationRejectedOrConflict => MycLogLevel::Warn,
            MycProcessResult::UnexpectedInternal
            | MycProcessResult::InputOrConfiguration
            | MycProcessResult::ServiceOrDependencyUnavailable
            | MycProcessResult::StateOrIdentityUnavailable
            | MycProcessResult::DoctorRequiredCheckFailed => MycLogLevel::Error,
        };
        Self {
            level,
            event: MycLogEvent::ProcessResult,
            code: result.code(),
            process_result: Some(result),
        }
    }

    /// Builds the exact phase record from an already-published lifecycle value.
    #[must_use]
    pub const fn lifecycle(phase: MycServicePhase) -> Self {
        let (level, code) = match phase {
            MycServicePhase::Starting => (MycLogLevel::Info, "starting"),
            MycServicePhase::Ready => (MycLogLevel::Info, "ready"),
            MycServicePhase::Degraded => (MycLogLevel::Warn, "degraded"),
            MycServicePhase::Unready => (MycLogLevel::Warn, "unready"),
            MycServicePhase::Stopping => (MycLogLevel::Info, "stopping"),
            MycServicePhase::Failed => (MycLogLevel::Error, "failed"),
        };
        Self {
            level,
            event: MycLogEvent::Lifecycle,
            code,
            process_result: None,
        }
    }

    #[must_use]
    pub const fn critical_task_failed() -> Self {
        Self {
            level: MycLogLevel::Error,
            event: MycLogEvent::CriticalTaskFailed,
            code: "critical_task_failed",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn shutdown_requested() -> Self {
        Self {
            level: MycLogLevel::Info,
            event: MycLogEvent::ShutdownRequested,
            code: "first_signal",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn shutdown_forced() -> Self {
        Self {
            level: MycLogLevel::Error,
            event: MycLogEvent::ShutdownForced,
            code: "second_signal",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn level(&self) -> MycLogLevel {
        self.level
    }

    #[must_use]
    pub const fn event(&self) -> MycLogEvent {
        self.event
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn process_exit(&self) -> Option<MycProcessResult> {
        self.process_result
    }
}

impl fmt::Debug for MycLogRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycLogRecord")
            .field("level", &self.level)
            .field("event", &self.event)
            .field("code", &self.code)
            .field(
                "exit_code",
                &self.process_result.map(MycProcessResult::exit_code_u8),
            )
            .finish()
    }
}

impl fmt::Display for MycLogRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{{\"schema\":\"{LOG_SCHEMA}\",\"contract_version\":{MYC_DIAGNOSTICS_CONTRACT_VERSION},\"service\":\"myc\",\"level\":\"{}\",\"event\":\"{}\",\"code\":\"{}\"",
            self.level.as_str(),
            self.event.as_str(),
            self.code,
        )?;
        if let Some(result) = self.process_result {
            write!(formatter, ",\"exit_code\":{}", result.exit_code_u8())?;
        }
        formatter.write_str("}")
    }
}
