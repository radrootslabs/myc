//! Bounded active-doctor orchestration and safe structured evidence.

use core::{fmt, future::Future, pin::Pin, time::Duration};
use std::error::Error;

use radroots_runtime_paths::InstanceId;
use serde::Serialize;

use crate::MycRuntimeContext;

/// Myc doctor wire-contract version.
pub const MYC_DOCTOR_CONTRACT_VERSION: u32 = 1;
/// Exact number of governed Myc doctor checks.
pub const MYC_DOCTOR_CHECK_COUNT: usize = 13;
/// Maximum encoded size of one safe summary.
pub const MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES: usize = 256;
/// Maximum encoded size of the complete canonical doctor report.
pub const MYC_DOCTOR_REPORT_MAX_UTF8_BYTES: usize = 8_192;

const MYC_SERVICE: &str = "myc";
const DOCTOR_FAILURE_EXIT_CODE: u8 = 6;
const _: () = {
    assert!("check passed".len() <= MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("check failed".len() <= MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("check timed out".len() <= MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("optional check skipped".len() <= MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
};

/// The closed Myc doctor inventory.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MycDoctorCheckId {
    PathsPermissions,
    WriterLock,
    SqliteSchema,
    SqliteIntegrity,
    SqliteFreeSpace,
    IdentityBinding,
    SignerProvider,
    AdminBindPolicy,
    OperationsBindPolicy,
    NetworkPolicy,
    RequiredRelays,
    OutboxInvariants,
    ClockSkew,
}

impl MycDoctorCheckId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PathsPermissions => "paths_permissions",
            Self::WriterLock => "writer_lock",
            Self::SqliteSchema => "sqlite_schema",
            Self::SqliteIntegrity => "sqlite_integrity",
            Self::SqliteFreeSpace => "sqlite_free_space",
            Self::IdentityBinding => "identity_binding",
            Self::SignerProvider => "signer_provider",
            Self::AdminBindPolicy => "admin_bind_policy",
            Self::OperationsBindPolicy => "operations_bind_policy",
            Self::NetworkPolicy => "network_policy",
            Self::RequiredRelays => "required_relays",
            Self::OutboxInvariants => "outbox_invariants",
            Self::ClockSkew => "clock_skew",
        }
    }
}

/// Stable operator action associated with one doctor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDoctorRemediationCode {
    CorrectPathPolicy,
    ReleaseWriterLock,
    RepairSchema,
    RestoreVerifiedState,
    FreeStateDiskSpace,
    RestoreIdentityBinding,
    RepairSignerProvider,
    CorrectAdminBindPolicy,
    CorrectOperationsBindPolicy,
    CorrectNetworkPolicy,
    RestoreRequiredRelays,
    RepairOutboxState,
    CorrectClock,
}

impl MycDoctorRemediationCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CorrectPathPolicy => "correct_path_policy",
            Self::ReleaseWriterLock => "release_writer_lock",
            Self::RepairSchema => "repair_schema",
            Self::RestoreVerifiedState => "restore_verified_state",
            Self::FreeStateDiskSpace => "free_state_disk_space",
            Self::RestoreIdentityBinding => "restore_identity_binding",
            Self::RepairSignerProvider => "repair_signer_provider",
            Self::CorrectAdminBindPolicy => "correct_admin_bind_policy",
            Self::CorrectOperationsBindPolicy => "correct_operations_bind_policy",
            Self::CorrectNetworkPolicy => "correct_network_policy",
            Self::RestoreRequiredRelays => "restore_required_relays",
            Self::RepairOutboxState => "repair_outbox_state",
            Self::CorrectClock => "correct_clock",
        }
    }
}

/// Immutable authority for one check's requirement, deadline, and remediation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycDoctorCheckDefinition {
    id: MycDoctorCheckId,
    required: bool,
    deadline_ms: u64,
    remediation_code: MycDoctorRemediationCode,
    scope: &'static [&'static str],
}

impl MycDoctorCheckDefinition {
    const fn new(
        id: MycDoctorCheckId,
        required: bool,
        deadline_ms: u64,
        remediation_code: MycDoctorRemediationCode,
        scope: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            required,
            deadline_ms,
            remediation_code,
            scope,
        }
    }

    /// Returns the governed check identifier.
    #[must_use]
    pub const fn id(self) -> MycDoctorCheckId {
        self.id
    }

    /// Returns whether a non-pass result fails the doctor command.
    #[must_use]
    pub const fn required(self) -> bool {
        self.required
    }

    /// Returns the exact per-check deadline in milliseconds.
    #[must_use]
    pub const fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }

    /// Returns the fixed, safe operator remediation classification.
    #[must_use]
    pub const fn remediation_code(self) -> MycDoctorRemediationCode {
        self.remediation_code
    }

    /// Returns the exact safe evidence facets owned by this check.
    #[must_use]
    pub const fn scope(self) -> &'static [&'static str] {
        self.scope
    }
}

const CHECK_DEFINITIONS: [MycDoctorCheckDefinition; MYC_DOCTOR_CHECK_COUNT] = [
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::PathsPermissions,
        true,
        2_000,
        MycDoctorRemediationCode::CorrectPathPolicy,
        &["resolved_path_containment", "owner", "type", "mode"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::WriterLock,
        true,
        2_000,
        MycDoctorRemediationCode::ReleaseWriterLock,
        &["state_directory_binding", "writer_lock_state"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::SqliteSchema,
        true,
        5_000,
        MycDoctorRemediationCode::RepairSchema,
        &["metadata_identity", "migration_history", "schema_catalog"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::SqliteIntegrity,
        true,
        15_000,
        MycDoctorRemediationCode::RestoreVerifiedState,
        &["integrity_check", "foreign_key_check"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::SqliteFreeSpace,
        true,
        2_000,
        MycDoctorRemediationCode::FreeStateDiskSpace,
        &["state_filesystem_capacity", "minimum_free_bytes"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::IdentityBinding,
        true,
        2_000,
        MycDoctorRemediationCode::RestoreIdentityBinding,
        &[
            "envelope_contract",
            "credential_reference",
            "public_identity",
        ],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::SignerProvider,
        true,
        15_000,
        MycDoctorRemediationCode::RepairSignerProvider,
        &[
            "capability",
            "contract_version",
            "identity",
            "correlation",
            "deadline",
        ],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::AdminBindPolicy,
        true,
        2_000,
        MycDoctorRemediationCode::CorrectAdminBindPolicy,
        &["unix_socket_path", "socket_mode", "peer_authorization"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::OperationsBindPolicy,
        true,
        2_000,
        MycDoctorRemediationCode::CorrectOperationsBindPolicy,
        &["enabled_posture", "listen_address", "bind_policy"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::NetworkPolicy,
        true,
        2_000,
        MycDoctorRemediationCode::CorrectNetworkPolicy,
        &["dns_policy", "tls_policy", "relay_url_policy"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::RequiredRelays,
        true,
        15_000,
        MycDoctorRemediationCode::RestoreRequiredRelays,
        &[
            "required_read_relays",
            "required_write_relays",
            "connect_deadline",
        ],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::OutboxInvariants,
        true,
        5_000,
        MycDoctorRemediationCode::RepairOutboxState,
        &["claim_invariants", "retry_state", "exact_response_bytes"],
    ),
    MycDoctorCheckDefinition::new(
        MycDoctorCheckId::ClockSkew,
        false,
        5_000,
        MycDoctorRemediationCode::CorrectClock,
        &["wall_clock_skew"],
    ),
];

/// Returns the exact ordered doctor inventory.
#[must_use]
pub const fn myc_doctor_check_definitions()
-> &'static [MycDoctorCheckDefinition; MYC_DOCTOR_CHECK_COUNT] {
    &CHECK_DEFINITIONS
}

/// A closed result supplied by one bounded check implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDoctorObservation {
    Pass,
    Fail,
    Skipped,
}

/// Future returned by one doctor probe.
pub type MycDoctorFuture<'a> = Pin<Box<dyn Future<Output = MycDoctorObservation> + Send + 'a>>;

/// Executes each active check without receiving report-construction authority.
///
/// `Pass` is permitted only after every facet in [`MycDoctorCheckDefinition::scope`]
/// is proven. Implementations must be cancellation-safe: the returned future
/// owns its work, and dropping it at the deadline must not leave detached work
/// or mutation running.
pub trait MycDoctorProbe: Send + Sync {
    /// Runs one exact check. Raw errors, paths, and arbitrary summaries cannot
    /// cross this boundary.
    fn probe(&self, definition: MycDoctorCheckDefinition) -> MycDoctorFuture<'_>;
}

/// Stable status of one completed check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDoctorCheckStatus {
    Pass,
    Fail,
    Timeout,
    Skipped,
}

impl MycDoctorCheckStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Pass => "check passed",
            Self::Fail => "check failed",
            Self::Timeout => "check timed out",
            Self::Skipped => "optional check skipped",
        }
    }
}

/// Stable aggregate doctor status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDoctorAggregateStatus {
    Pass,
    Degraded,
    Fail,
}

impl MycDoctorAggregateStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Degraded => "degraded",
            Self::Fail => "fail",
        }
    }
}

/// One sealed structured doctor result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycDoctorCheckResult {
    definition: MycDoctorCheckDefinition,
    status: MycDoctorCheckStatus,
}

impl MycDoctorCheckResult {
    /// Returns the exact check definition.
    #[must_use]
    pub const fn definition(self) -> MycDoctorCheckDefinition {
        self.definition
    }

    /// Returns the admitted check status.
    #[must_use]
    pub const fn status(self) -> MycDoctorCheckStatus {
        self.status
    }

    /// Returns the fixed content-free summary.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        self.status.summary()
    }
}

/// Stable source-free doctor construction failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDoctorErrorKind {
    Encoding,
    OutputTooLarge,
}

impl MycDoctorErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::Encoding => "Myc doctor output encoding failed",
            Self::OutputTooLarge => "Myc doctor output exceeds its byte limit",
        }
    }
}

/// One redacted doctor construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycDoctorError {
    kind: MycDoctorErrorKind,
}

impl MycDoctorError {
    const fn new(kind: MycDoctorErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable error classification.
    #[must_use]
    pub const fn kind(self) -> MycDoctorErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycDoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDoctorError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycDoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycDoctorError {}

/// One immutable, bounded, canonical Myc doctor report.
///
/// Construction remains inside [`run_myc_doctor`]:
///
/// ```compile_fail
/// use myc::{MycDoctorAggregateStatus, MycDoctorReport};
///
/// let _ = MycDoctorReport {
///     instance: todo!(),
///     status: MycDoctorAggregateStatus::Pass,
///     checks: Box::new([]),
///     canonical_json: Box::new([]),
/// };
/// ```
pub struct MycDoctorReport {
    instance: InstanceId,
    status: MycDoctorAggregateStatus,
    checks: Box<[MycDoctorCheckResult]>,
    canonical_json: Box<[u8]>,
}

impl MycDoctorReport {
    /// Returns the fixed service identifier.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        MYC_SERVICE
    }

    /// Returns the validated instance identifier admitted into the report.
    #[must_use]
    pub const fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// Returns the aggregate result.
    #[must_use]
    pub const fn status(&self) -> MycDoctorAggregateStatus {
        self.status
    }

    /// Returns the ordered complete check inventory.
    #[must_use]
    pub fn checks(&self) -> &[MycDoctorCheckResult] {
        &self.checks
    }

    /// Returns exact compact UTF-8 JSON in the shared v1 field order.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Returns exit 6 only when a required check failed or timed out.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.status {
            MycDoctorAggregateStatus::Fail => DOCTOR_FAILURE_EXIT_CODE,
            MycDoctorAggregateStatus::Pass | MycDoctorAggregateStatus::Degraded => 0,
        }
    }
}

impl fmt::Debug for MycDoctorReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDoctorReport")
            .field("service", &MYC_SERVICE)
            .field("instance", &"[redacted]")
            .field("status", &self.status)
            .field("check_count", &self.checks.len())
            .field("canonical_json", &"[redacted]")
            .finish()
    }
}

/// Runs every governed check in exact contract order under its fixed deadline.
///
/// Probe implementations retain operation-specific filesystem, SQLite,
/// provider, listener, network, relay, and clock authority. This orchestrator
/// accepts only a closed result and cannot serialize their paths or raw errors.
pub async fn run_myc_doctor(
    context: &MycRuntimeContext,
    probe: &(impl MycDoctorProbe + ?Sized),
) -> Result<MycDoctorReport, MycDoctorError> {
    let mut checks = Vec::with_capacity(MYC_DOCTOR_CHECK_COUNT);
    for definition in CHECK_DEFINITIONS {
        let status = match tokio::time::timeout(
            Duration::from_millis(definition.deadline_ms),
            probe.probe(definition),
        )
        .await
        {
            Ok(MycDoctorObservation::Pass) => MycDoctorCheckStatus::Pass,
            Ok(MycDoctorObservation::Fail) => MycDoctorCheckStatus::Fail,
            Ok(MycDoctorObservation::Skipped) if !definition.required => {
                MycDoctorCheckStatus::Skipped
            }
            Ok(MycDoctorObservation::Skipped) => MycDoctorCheckStatus::Fail,
            Err(_) => MycDoctorCheckStatus::Timeout,
        };
        checks.push(MycDoctorCheckResult { definition, status });
    }
    let checks = checks.into_boxed_slice();
    let status = aggregate_status(&checks);
    let instance = context.context().instance().clone();
    let canonical_json = encode_report(&instance, status, &checks)?;

    Ok(MycDoctorReport {
        instance,
        status,
        checks,
        canonical_json,
    })
}

fn aggregate_status(checks: &[MycDoctorCheckResult]) -> MycDoctorAggregateStatus {
    if checks
        .iter()
        .any(|result| result.definition.required && result.status != MycDoctorCheckStatus::Pass)
    {
        MycDoctorAggregateStatus::Fail
    } else if checks
        .iter()
        .any(|result| result.status != MycDoctorCheckStatus::Pass)
    {
        MycDoctorAggregateStatus::Degraded
    } else {
        MycDoctorAggregateStatus::Pass
    }
}

#[derive(Serialize)]
struct DoctorWireReport<'a> {
    contract_version: u32,
    service: &'static str,
    instance: &'a str,
    status: &'static str,
    checks: Vec<DoctorWireCheck>,
}

#[derive(Serialize)]
struct DoctorWireCheck {
    id: &'static str,
    status: &'static str,
    required: bool,
    deadline_ms: u64,
    summary: &'static str,
    remediation_code: &'static str,
}

fn encode_report(
    instance: &InstanceId,
    status: MycDoctorAggregateStatus,
    checks: &[MycDoctorCheckResult],
) -> Result<Box<[u8]>, MycDoctorError> {
    let checks = checks
        .iter()
        .map(|result| DoctorWireCheck {
            id: result.definition.id.as_str(),
            status: result.status.as_str(),
            required: result.definition.required,
            deadline_ms: result.definition.deadline_ms,
            summary: result.status.summary(),
            remediation_code: result.definition.remediation_code.as_str(),
        })
        .collect();
    let encoded = serde_json::to_vec(&DoctorWireReport {
        contract_version: MYC_DOCTOR_CONTRACT_VERSION,
        service: MYC_SERVICE,
        instance: instance.as_str(),
        status: status.as_str(),
        checks,
    })
    .map_err(|_| MycDoctorError::new(MycDoctorErrorKind::Encoding))?;
    if encoded.len() > MYC_DOCTOR_REPORT_MAX_UTF8_BYTES {
        return Err(MycDoctorError::new(MycDoctorErrorKind::OutputTooLarge));
    }
    Ok(encoded.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{MycDoctorError, MycDoctorErrorKind};

    #[test]
    fn errors_are_source_free_and_content_free() {
        for kind in [
            MycDoctorErrorKind::Encoding,
            MycDoctorErrorKind::OutputTooLarge,
        ] {
            let error = MycDoctorError::new(kind);
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            for forbidden in ["/private", "secret", "relay", "sqlite"] {
                assert!(!rendered.to_ascii_lowercase().contains(forbidden));
            }
        }
    }
}
