//! Passive, latest-value Myc lifecycle and detailed-status publication.

use core::fmt;
use std::{error::Error, sync::Arc, time::Duration};

use radroots_service_host::{
    BoundedMetricsSnapshot, BuildInfo as HostBuildInfo,
    BuildInfoEnvironment as HostBuildInfoEnvironment, BuildMode as HostBuildMode,
    CachedServiceState, CachedServiceStatePublisher, CachedServiceStateReader, CommonMetricGroup,
    ConfigurationIdentity as HostConfigurationIdentity,
    ConfigurationSource as HostConfigurationSource, ContractVersions as HostContractVersions,
    InstanceId, IntegrityState as HostIntegrityState, MetricDescriptor, MetricKind, MetricLabel,
    MetricLabelKey, MetricName, MetricSample, MetricValue,
    PersistenceHealth as HostPersistenceHealth, PersistenceSummary as HostPersistenceSummary,
    Readiness as HostReadiness, ReasonCode as HostReasonCode, ReasonCodes as HostReasonCodes,
    ServiceId, ServiceOperationalState as HostServiceOperationalState,
    ServicePhase as HostServicePhase, ServiceStatus, ServiceStatusDetail,
    Sha256Digest as HostSha256Digest, StatusContractError, StatusEncodingError, StatusModelError,
    UptimeMillis as HostUptimeMillis, cached_service_state,
};
use serde::Serialize;

/// Exact version of the passive Myc status-cache contract.
pub const MYC_STATUS_CACHE_CONTRACT_VERSION: u32 = 1;

/// Maximum encoded byte length of one detailed Myc status response.
pub const MYC_DETAILED_STATUS_MAX_UTF8_BYTES: usize =
    radroots_service_host::SERVICE_STATUS_MAX_UTF8_BYTES;

/// Number of stable reason codes admitted by detailed Myc status.
pub const MYC_STATUS_REASON_CODE_COUNT: usize = 12;

/// One closed stable source-free status reason code.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycStatusReasonCode {
    IdentityUnavailable,
    DatabaseSchemaMismatch,
    DatabaseReadOnly,
    DatabaseLowDisk,
    RequiredRelayUnavailable,
    SubscriberNotActive,
    SignerProviderUnavailable,
    OutboxInvariantFailed,
    PublicationBacklogExceeded,
    AdminListenerFailed,
    OperationsListenerFailed,
    ShutdownInProgress,
}

impl MycStatusReasonCode {
    pub fn new(value: impl AsRef<str>) -> Result<Self, MycStatusError> {
        match value.as_ref() {
            "identity_unavailable" => Ok(Self::IdentityUnavailable),
            "database_schema_mismatch" => Ok(Self::DatabaseSchemaMismatch),
            "database_read_only" => Ok(Self::DatabaseReadOnly),
            "database_low_disk" => Ok(Self::DatabaseLowDisk),
            "required_relay_unavailable" => Ok(Self::RequiredRelayUnavailable),
            "subscriber_not_active" => Ok(Self::SubscriberNotActive),
            "signer_provider_unavailable" => Ok(Self::SignerProviderUnavailable),
            "outbox_invariant_failed" => Ok(Self::OutboxInvariantFailed),
            "publication_backlog_exceeded" => Ok(Self::PublicationBacklogExceeded),
            "admin_listener_failed" => Ok(Self::AdminListenerFailed),
            "operations_listener_failed" => Ok(Self::OperationsListenerFailed),
            "shutdown_in_progress" => Ok(Self::ShutdownInProgress),
            _ => Err(MycStatusError::new(MycStatusErrorKind::InvalidReasonCode)),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityUnavailable => "identity_unavailable",
            Self::DatabaseSchemaMismatch => "database_schema_mismatch",
            Self::DatabaseReadOnly => "database_read_only",
            Self::DatabaseLowDisk => "database_low_disk",
            Self::RequiredRelayUnavailable => "required_relay_unavailable",
            Self::SubscriberNotActive => "subscriber_not_active",
            Self::SignerProviderUnavailable => "signer_provider_unavailable",
            Self::OutboxInvariantFailed => "outbox_invariant_failed",
            Self::PublicationBacklogExceeded => "publication_backlog_exceeded",
            Self::AdminListenerFailed => "admin_listener_failed",
            Self::OperationsListenerFailed => "operations_listener_failed",
            Self::ShutdownInProgress => "shutdown_in_progress",
        }
    }
}

/// Canonically ordered, unique, bounded status reasons.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct MycStatusReasonCodes(Vec<MycStatusReasonCode>);

impl MycStatusReasonCodes {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn new(
        values: impl IntoIterator<Item = MycStatusReasonCode>,
    ) -> Result<Self, MycStatusError> {
        let mut bounded = Vec::with_capacity(MYC_STATUS_REASON_CODE_COUNT);
        for value in values.into_iter().take(MYC_STATUS_REASON_CODE_COUNT + 1) {
            if bounded.len() == MYC_STATUS_REASON_CODE_COUNT {
                return Err(MycStatusError::new(MycStatusErrorKind::TooManyReasonCodes));
            }
            bounded.push(value);
        }
        bounded.sort_unstable();
        bounded.dedup();
        Ok(Self(bounded))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[MycStatusReasonCode] {
        &self.0
    }

    fn into_host(self) -> Result<HostReasonCodes, MycStatusError> {
        let values = self
            .0
            .into_iter()
            .map(|value| HostReasonCode::new(value.as_str()).map_err(map_contract_error))
            .collect::<Result<Vec<_>, _>>()?;
        HostReasonCodes::new(values).map_err(map_contract_error)
    }
}

/// Closed common lifecycle phase used by the Myc public boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycServicePhase {
    Starting,
    Ready,
    Degraded,
    Unready,
    Stopping,
    Failed,
}

impl MycServicePhase {
    const fn into_host(self) -> HostServicePhase {
        match self {
            Self::Starting => HostServicePhase::Starting,
            Self::Ready => HostServicePhase::Ready,
            Self::Degraded => HostServicePhase::Degraded,
            Self::Unready => HostServicePhase::Unready,
            Self::Stopping => HostServicePhase::Stopping,
            Self::Failed => HostServicePhase::Failed,
        }
    }

    const fn from_host(value: HostServicePhase) -> Self {
        match value {
            HostServicePhase::Starting => Self::Starting,
            HostServicePhase::Ready => Self::Ready,
            HostServicePhase::Degraded => Self::Degraded,
            HostServicePhase::Unready => Self::Unready,
            HostServicePhase::Stopping => Self::Stopping,
            HostServicePhase::Failed => Self::Failed,
        }
    }
}

/// Build-metadata admission mode for Myc status identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStatusBuildMode {
    Development,
    Release,
}

/// Complete deterministic build identity retained behind the Myc boundary.
pub struct MycStatusBuildInfoV1 {
    inner: HostBuildInfo,
}

impl MycStatusBuildInfoV1 {
    /// Validates the complete build/source-lock identity with fixed Myc contracts.
    pub fn new(
        mode: MycStatusBuildMode,
        service_version: Option<&str>,
        service_commit: Option<&str>,
        lib_revision: Option<&str>,
        rust_version: Option<&str>,
        target: Option<&str>,
        feature_profile: Option<&str>,
    ) -> Result<Self, MycStatusError> {
        let contract_versions =
            HostContractVersions::new(1, crate::MYC_STATE_SCHEMA_VERSION, 1, 1, 1)
                .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidBuildInfo))?;
        HostBuildInfo::from_compile_time(
            match mode {
                MycStatusBuildMode::Development => HostBuildMode::Development,
                MycStatusBuildMode::Release => HostBuildMode::Release,
            },
            HostBuildInfoEnvironment {
                service_version,
                service_commit,
                lib_revision,
                rust_version,
                target,
                feature_profile,
                contract_versions,
            },
        )
        .map(|inner| Self { inner })
        .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidBuildInfo))
    }
}

impl fmt::Debug for MycStatusBuildInfoV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusBuildInfoV1([redacted])")
    }
}

/// Exact configuration-source vocabulary exposed by detailed status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStatusConfigurationSource {
    ExplicitConfig,
    DerivedRepoLocal,
}

/// Safe configuration identity retained behind the Myc boundary.
pub struct MycStatusConfigurationIdentityV1 {
    inner: HostConfigurationIdentity,
}

impl MycStatusConfigurationIdentityV1 {
    pub fn new(
        digest: impl AsRef<str>,
        source: MycStatusConfigurationSource,
    ) -> Result<Self, MycStatusError> {
        let service = ServiceId::new("myc")
            .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidConfiguration))?;
        let digest = HostSha256Digest::new(digest)
            .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidConfiguration))?;
        HostConfigurationIdentity::for_service(
            &service,
            digest,
            match source {
                MycStatusConfigurationSource::ExplicitConfig => {
                    HostConfigurationSource::ExplicitConfig
                }
                MycStatusConfigurationSource::DerivedRepoLocal => {
                    HostConfigurationSource::DerivedRepoLocal
                }
            },
        )
        .map(|inner| Self { inner })
        .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidConfiguration))
    }
}

impl fmt::Debug for MycStatusConfigurationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusConfigurationIdentityV1([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycPersistenceHealthV1 {
    Ready,
    ReadOnly,
    RepairRequired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycIntegrityStateV1 {
    Verified,
    VerificationRequired,
    Failed,
}

/// Validated persistence summary retained behind the Myc boundary.
pub struct MycPersistenceStatusV1 {
    inner: HostPersistenceSummary,
}

impl MycPersistenceStatusV1 {
    pub fn new(
        health: MycPersistenceHealthV1,
        schema_version: u32,
        generation: u64,
        integrity: MycIntegrityStateV1,
        reason_codes: MycStatusReasonCodes,
    ) -> Result<Self, MycStatusError> {
        let reason_codes = reason_codes.into_host()?;
        HostPersistenceSummary::new(
            match health {
                MycPersistenceHealthV1::Ready => HostPersistenceHealth::Ready,
                MycPersistenceHealthV1::ReadOnly => HostPersistenceHealth::ReadOnly,
                MycPersistenceHealthV1::RepairRequired => HostPersistenceHealth::RepairRequired,
                MycPersistenceHealthV1::Unavailable => HostPersistenceHealth::Unavailable,
            },
            schema_version,
            generation,
            match integrity {
                MycIntegrityStateV1::Verified => HostIntegrityState::Verified,
                MycIntegrityStateV1::VerificationRequired => {
                    HostIntegrityState::VerificationRequired
                }
                MycIntegrityStateV1::Failed => HostIntegrityState::Failed,
            },
            reason_codes,
        )
        .map(|inner| Self { inner })
        .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidPersistence))
    }
}

impl fmt::Debug for MycPersistenceStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycPersistenceStatusV1([redacted])")
    }
}

/// One validated Unix timestamp used only for the oldest pending outbox item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct MycStatusUnixSeconds(u64);

impl MycStatusUnixSeconds {
    /// Constructs a timestamp representable by SQLite and the frozen wire contract.
    pub fn new(value: u64) -> Result<Self, MycStatusError> {
        if value > i64::MAX as u64 {
            return Err(MycStatusError::new(MycStatusErrorKind::InvalidTime));
        }
        Ok(Self(value))
    }

    /// Returns exact whole Unix seconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Passive availability of one configured Myc identity role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MycIdentityHealthV1 {
    configured: bool,
    available: bool,
    reason_codes: MycStatusReasonCodes,
}

impl MycIdentityHealthV1 {
    /// Constructs one role observation, rejecting availability without configuration.
    pub fn new(
        configured: bool,
        available: bool,
        reason_codes: MycStatusReasonCodes,
    ) -> Result<Self, MycStatusError> {
        if available && !configured {
            return Err(MycStatusError::new(
                MycStatusErrorKind::InvalidIdentityHealth,
            ));
        }
        Ok(Self {
            configured,
            available,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.configured
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.available
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &MycStatusReasonCodes {
        &self.reason_codes
    }
}

/// Complete provider projection for the three fixed Myc identity roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MycProviderStatusV1 {
    health: MycProviderHealthV1,
    transport: MycIdentityHealthV1,
    user: MycIdentityHealthV1,
    discovery: MycIdentityHealthV1,
    reason_codes: MycStatusReasonCodes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycProviderHealthV1 {
    Ready,
    Degraded,
    Unavailable,
}

impl MycProviderStatusV1 {
    /// Derives aggregate provider health from the exact role inventory.
    pub fn new(
        transport: MycIdentityHealthV1,
        user: MycIdentityHealthV1,
        discovery: MycIdentityHealthV1,
        reason_codes: MycStatusReasonCodes,
    ) -> Result<Self, MycStatusError> {
        if !transport.configured || !user.configured {
            return Err(MycStatusError::new(
                MycStatusErrorKind::InvalidProviderState,
            ));
        }
        let health = if !transport.available || !user.available {
            MycProviderHealthV1::Unavailable
        } else if discovery.configured && !discovery.available {
            MycProviderHealthV1::Degraded
        } else {
            MycProviderHealthV1::Ready
        };
        Ok(Self {
            health,
            transport,
            user,
            discovery,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn health(&self) -> MycProviderHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn transport(&self) -> &MycIdentityHealthV1 {
        &self.transport
    }

    #[must_use]
    pub const fn user(&self) -> &MycIdentityHealthV1 {
        &self.user
    }

    #[must_use]
    pub const fn discovery(&self) -> &MycIdentityHealthV1 {
        &self.discovery
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &MycStatusReasonCodes {
        &self.reason_codes
    }
}

/// Passive relay-transport projection for detailed status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MycRelayTransportStatusV1 {
    health: MycTransportHealthV1,
    required_relays_ready: bool,
    connected_relay_count: u64,
    reason_codes: MycStatusReasonCodes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycTransportHealthV1 {
    Ready,
    Degraded,
    Unavailable,
}

impl MycRelayTransportStatusV1 {
    /// Constructs one transport observation, rejecting contradictory ready state.
    pub fn new(
        health: MycTransportHealthV1,
        required_relays_ready: bool,
        connected_relay_count: u64,
        reason_codes: MycStatusReasonCodes,
    ) -> Result<Self, MycStatusError> {
        if health == MycTransportHealthV1::Ready && !required_relays_ready {
            return Err(MycStatusError::new(
                MycStatusErrorKind::InvalidTransportState,
            ));
        }
        Ok(Self {
            health,
            required_relays_ready,
            connected_relay_count,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn health(&self) -> MycTransportHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn required_relays_ready(&self) -> bool {
        self.required_relays_ready
    }

    #[must_use]
    pub const fn connected_relay_count(&self) -> u64 {
        self.connected_relay_count
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &MycStatusReasonCodes {
        &self.reason_codes
    }
}

/// Exact closed connection-count vocabulary rendered as the safe-count map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MycConnectionCountsV1 {
    pending: u64,
    active: u64,
    denied: u64,
    expired: u64,
}

impl MycConnectionCountsV1 {
    #[must_use]
    pub const fn new(pending: u64, active: u64, denied: u64, expired: u64) -> Self {
        Self {
            pending,
            active,
            denied,
            expired,
        }
    }

    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }

    #[must_use]
    pub const fn active(self) -> u64 {
        self.active
    }

    #[must_use]
    pub const fn denied(self) -> u64 {
        self.denied
    }

    #[must_use]
    pub const fn expired(self) -> u64 {
        self.expired
    }
}

/// Passive outbox summary derived by an owning runtime task before publication.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MycOutboxStatusV1 {
    pending: u64,
    unknown: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_pending_at_utc: Option<MycStatusUnixSeconds>,
}

impl MycOutboxStatusV1 {
    #[must_use]
    pub const fn new(
        pending: u64,
        unknown: u64,
        oldest_pending_at_utc: Option<MycStatusUnixSeconds>,
    ) -> Self {
        Self {
            pending,
            unknown,
            oldest_pending_at_utc,
        }
    }

    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }

    #[must_use]
    pub const fn unknown(self) -> u64 {
        self.unknown
    }

    #[must_use]
    pub const fn oldest_pending_at_utc(self) -> Option<MycStatusUnixSeconds> {
        self.oldest_pending_at_utc
    }
}

#[derive(Serialize)]
struct MycStatusDetailV1 {
    transport: MycIdentityHealthV1,
    user: MycIdentityHealthV1,
    discovery: MycIdentityHealthV1,
    connection_counts: MycConnectionCountsV1,
    outbox: MycOutboxStatusV1,
}

impl ServiceStatusDetail for MycStatusDetailV1 {
    type Provider = MycProviderStatusV1;
    type Transport = MycRelayTransportStatusV1;

    const FIELD_NAME: &'static str = "myc";
}

/// Validated common fields shared by one detailed status publication.
///
/// Construction and publication perform validation and bounded encoding only.
/// They do not query SQLite, providers, relays, DNS, credentials, or the clock.
pub struct MycStatusCommonV1 {
    operational: HostServiceOperationalState,
    uptime: HostUptimeMillis,
    build: HostBuildInfo,
    configuration: HostConfigurationIdentity,
    persistence: HostPersistenceSummary,
}

impl MycStatusCommonV1 {
    /// Validates the common lifecycle and detailed-status envelope fields.
    pub fn new(
        phase: MycServicePhase,
        ready: bool,
        reason_codes: MycStatusReasonCodes,
        uptime_millis: u64,
        build: MycStatusBuildInfoV1,
        configuration: MycStatusConfigurationIdentityV1,
        persistence: MycPersistenceStatusV1,
    ) -> Result<Self, MycStatusError> {
        let operational = HostServiceOperationalState::new(
            phase.into_host(),
            if ready {
                HostReadiness::READY
            } else {
                HostReadiness::NOT_READY
            },
            reason_codes.into_host()?,
        )
        .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidLifecycle))?;
        let uptime = HostUptimeMillis::from_duration(Duration::from_millis(uptime_millis))
            .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidTime))?;
        Ok(Self {
            operational,
            uptime,
            build: build.inner,
            configuration: configuration.inner,
            persistence: persistence.inner,
        })
    }
}

impl fmt::Debug for MycStatusCommonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusCommonV1([redacted])")
    }
}

/// One complete, already-observed status publication input.
pub struct MycStatusObservationV1 {
    common: MycStatusCommonV1,
    provider: MycProviderStatusV1,
    transport: MycRelayTransportStatusV1,
    connection_counts: MycConnectionCountsV1,
    outbox: MycOutboxStatusV1,
}

impl MycStatusObservationV1 {
    #[must_use]
    pub fn new(
        common: MycStatusCommonV1,
        provider: MycProviderStatusV1,
        transport: MycRelayTransportStatusV1,
        connection_counts: MycConnectionCountsV1,
        outbox: MycOutboxStatusV1,
    ) -> Self {
        Self {
            common,
            provider,
            transport,
            connection_counts,
            outbox,
        }
    }

    fn into_cached(self, instance: &InstanceId) -> Result<PreparedMycStatus, MycStatusError> {
        let operational = self.common.operational.clone();
        let operations_metrics = bounded_operations_metrics(&operational)?;
        let detail = MycStatusDetailV1 {
            transport: self.provider.transport.clone(),
            user: self.provider.user.clone(),
            discovery: self.provider.discovery.clone(),
            connection_counts: self.connection_counts,
            outbox: self.outbox,
        };
        let service = ServiceId::new("myc")
            .map_err(|_| MycStatusError::new(MycStatusErrorKind::InvalidModel))?;
        let status = ServiceStatus::new(
            service,
            instance.clone(),
            self.common.operational,
            self.common.uptime,
            self.common.build,
            self.common.configuration,
            self.common.persistence,
            self.provider,
            self.transport,
            detail,
        )
        .map_err(map_model_error)?;
        let json = status.to_bounded_json().map_err(map_encoding_error)?;
        Ok(PreparedMycStatus {
            detail: CachedServiceState::new(
                operational.clone(),
                MycCachedStatus {
                    json: json.into_boxed_slice(),
                },
            ),
            operations: CachedServiceState::new(operational, operations_metrics),
        })
    }
}

impl fmt::Debug for MycStatusObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusObservationV1([redacted])")
    }
}

struct MycCachedStatus {
    json: Box<[u8]>,
}

struct PreparedMycStatus {
    detail: CachedServiceState<MycCachedStatus>,
    operations: CachedServiceState<BoundedMetricsSnapshot>,
}

fn bounded_operations_metrics(
    operational: &HostServiceOperationalState,
) -> Result<BoundedMetricsSnapshot, MycStatusError> {
    let phase_name = MetricName::new("radroots_myc_service_phase").map_err(map_metrics_error)?;
    let ready_name = MetricName::new("radroots_myc_service_ready").map_err(map_metrics_error)?;
    let descriptors = [
        MetricDescriptor::new(
            CommonMetricGroup::Phase,
            phase_name.clone(),
            "Current cached Myc service phase.",
            MetricKind::Gauge,
            [MetricLabelKey::Phase],
        )
        .map_err(map_metrics_error)?,
        MetricDescriptor::new(
            CommonMetricGroup::Phase,
            ready_name.clone(),
            "Current cached Myc readiness bit.",
            MetricKind::Gauge,
            [],
        )
        .map_err(map_metrics_error)?,
    ];
    let samples = [
        MetricSample::new(
            phase_name,
            MetricValue::Gauge(1),
            [MetricLabel::phase(operational.phase())],
        )
        .map_err(map_metrics_error)?,
        MetricSample::new(
            ready_name,
            MetricValue::Gauge(i64::from(operational.readiness().is_ready())),
            [],
        )
        .map_err(map_metrics_error)?,
    ];
    BoundedMetricsSnapshot::new(descriptors, samples).map_err(map_metrics_error)
}

fn map_metrics_error(_: radroots_service_host::MetricsContractError) -> MycStatusError {
    MycStatusError::new(MycStatusErrorKind::InvalidModel)
}

impl fmt::Debug for MycCachedStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycCachedStatus")
            .field("json_utf8_bytes", &self.json.len())
            .finish()
    }
}

/// Sole publication authority for one process-local Myc status cache.
///
/// This type deliberately does not implement `Clone`. A successful publish
/// atomically replaces the one retained snapshot. A failed encoding or illegal
/// lifecycle transition leaves the previous snapshot unchanged.
pub struct MycStatusPublisher {
    instance: InstanceId,
    inner: CachedServiceStatePublisher<MycCachedStatus>,
    operations: CachedServiceStatePublisher<BoundedMetricsSnapshot>,
}

impl MycStatusPublisher {
    /// Encodes one observation, publishes its passive operations projection,
    /// and then atomically replaces the detailed-status snapshot.
    pub fn publish(&mut self, next: MycStatusObservationV1) -> Result<(), MycStatusError> {
        let next = next.into_cached(&self.instance)?;
        self.operations
            .publish(next.operations)
            .map_err(map_contract_error)?;
        self.inner.publish(next.detail).map_err(map_contract_error)
    }

    /// Creates another passive reader without sharing publication authority.
    #[must_use]
    pub fn subscribe(&self) -> MycStatusReader {
        MycStatusReader {
            inner: self.inner.subscribe(),
            operations: self.operations.subscribe(),
        }
    }
}

impl fmt::Debug for MycStatusPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusPublisher([sealed])")
    }
}

/// Cloneable passive reader of the latest Myc lifecycle and detailed status.
pub struct MycStatusReader {
    inner: CachedServiceStateReader<MycCachedStatus>,
    operations: CachedServiceStateReader<BoundedMetricsSnapshot>,
}

impl Clone for MycStatusReader {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            operations: self.operations.clone(),
        }
    }
}

impl MycStatusReader {
    /// Returns the latest immutable snapshot without awaiting or probing.
    #[must_use]
    pub fn snapshot(&self) -> MycStatusSnapshot {
        MycStatusSnapshot {
            inner: self.inner.snapshot(),
        }
    }

    /// Waits for a later publication and returns the newest retained value.
    pub async fn changed(&mut self) -> Result<MycStatusSnapshot, MycStatusError> {
        self.inner
            .changed()
            .await
            .map(|inner| MycStatusSnapshot { inner })
            .map_err(|_| MycStatusError::new(MycStatusErrorKind::PublisherDropped))
    }

    pub(crate) fn operations_cache(&self) -> CachedServiceStateReader<BoundedMetricsSnapshot> {
        self.operations.clone()
    }
}

impl fmt::Debug for MycStatusReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStatusReader([passive])")
    }
}

/// One immutable point-in-time status snapshot backed by the retained cache `Arc`.
pub struct MycStatusSnapshot {
    inner: Arc<CachedServiceState<MycCachedStatus>>,
}

impl MycStatusSnapshot {
    #[must_use]
    pub fn phase(&self) -> MycServicePhase {
        MycServicePhase::from_host(self.inner.operational().phase())
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.operational().readiness().is_ready()
    }

    /// Returns the already-bounded canonical detailed-status JSON bytes.
    #[must_use]
    pub fn detailed_status_json(&self) -> &[u8] {
        &self.inner.metrics().json
    }
}

impl fmt::Debug for MycStatusSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStatusSnapshot")
            .field("phase", &self.phase())
            .field("ready", &self.is_ready())
            .field("json_utf8_bytes", &self.detailed_status_json().len())
            .finish()
    }
}

/// Creates the single-writer, one-latest-value Myc status cache.
pub fn myc_status_cache(
    instance: InstanceId,
    initial: MycStatusObservationV1,
) -> Result<(MycStatusPublisher, MycStatusReader), MycStatusError> {
    let initial = initial.into_cached(&instance)?;
    let (inner, reader) = cached_service_state(initial.detail);
    let (operations, operations_reader) = cached_service_state(initial.operations);
    Ok((
        MycStatusPublisher {
            instance,
            inner,
            operations,
        },
        MycStatusReader {
            inner: reader,
            operations: operations_reader,
        },
    ))
}

/// Stable source-free status failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStatusErrorKind {
    InvalidReasonCode,
    TooManyReasonCodes,
    InvalidLifecycle,
    InvalidBuildInfo,
    InvalidConfiguration,
    InvalidPersistence,
    InvalidIdentityHealth,
    InvalidProviderState,
    InvalidTransportState,
    InvalidTime,
    InvalidModel,
    Encoding,
    ResponseTooLarge,
    InvalidTransition,
    PublisherDropped,
}

impl MycStatusErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidReasonCode => "status_reason_code_invalid",
            Self::TooManyReasonCodes => "status_reason_count_exceeded",
            Self::InvalidLifecycle => "status_lifecycle_invalid",
            Self::InvalidBuildInfo => "status_build_info_invalid",
            Self::InvalidConfiguration => "status_configuration_invalid",
            Self::InvalidPersistence => "status_persistence_invalid",
            Self::InvalidIdentityHealth => "status_identity_health_invalid",
            Self::InvalidProviderState => "status_provider_state_invalid",
            Self::InvalidTransportState => "status_transport_state_invalid",
            Self::InvalidTime => "status_time_invalid",
            Self::InvalidModel => "status_model_invalid",
            Self::Encoding => "status_encoding_failed",
            Self::ResponseTooLarge => "status_response_too_large",
            Self::InvalidTransition => "status_transition_invalid",
            Self::PublisherDropped => "status_publisher_dropped",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidReasonCode => "Myc status reason code is invalid",
            Self::TooManyReasonCodes => "Myc status has too many reason codes",
            Self::InvalidLifecycle => "Myc lifecycle status is invalid",
            Self::InvalidBuildInfo => "Myc status build identity is invalid",
            Self::InvalidConfiguration => "Myc status configuration identity is invalid",
            Self::InvalidPersistence => "Myc persistence status is invalid",
            Self::InvalidIdentityHealth => "Myc identity health is invalid",
            Self::InvalidProviderState => "Myc provider status is invalid",
            Self::InvalidTransportState => "Myc transport status is invalid",
            Self::InvalidTime => "Myc status time is invalid",
            Self::InvalidModel => "Myc detailed status is invalid",
            Self::Encoding => "Myc detailed status encoding failed",
            Self::ResponseTooLarge => "Myc detailed status exceeds its byte limit",
            Self::InvalidTransition => "Myc lifecycle transition is invalid",
            Self::PublisherDropped => "Myc status publisher is unavailable",
        }
    }
}

/// One redacted source-free status failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStatusError {
    kind: MycStatusErrorKind,
}

impl MycStatusError {
    const fn new(kind: MycStatusErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycStatusErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStatusError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycStatusError {}

const fn map_model_error(_error: StatusModelError) -> MycStatusError {
    MycStatusError::new(MycStatusErrorKind::InvalidModel)
}

const fn map_encoding_error(error: StatusEncodingError) -> MycStatusError {
    match error {
        StatusEncodingError::EncodingFailed => MycStatusError::new(MycStatusErrorKind::Encoding),
        StatusEncodingError::ResponseTooLarge => {
            MycStatusError::new(MycStatusErrorKind::ResponseTooLarge)
        }
    }
}

const fn map_contract_error(_error: StatusContractError) -> MycStatusError {
    MycStatusError::new(MycStatusErrorKind::InvalidTransition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_status_inputs_fail_with_safe_source_free_errors() {
        assert_eq!(
            MycIdentityHealthV1::new(false, true, MycStatusReasonCodes::empty()),
            Err(MycStatusError::new(
                MycStatusErrorKind::InvalidIdentityHealth
            ))
        );
        let unavailable =
            MycIdentityHealthV1::new(true, false, MycStatusReasonCodes::empty()).unwrap();
        assert_eq!(
            MycProviderStatusV1::new(
                MycIdentityHealthV1::new(false, false, MycStatusReasonCodes::empty()).unwrap(),
                unavailable,
                MycIdentityHealthV1::new(false, false, MycStatusReasonCodes::empty()).unwrap(),
                MycStatusReasonCodes::empty(),
            ),
            Err(MycStatusError::new(
                MycStatusErrorKind::InvalidProviderState
            ))
        );
        assert_eq!(
            MycRelayTransportStatusV1::new(
                MycTransportHealthV1::Ready,
                false,
                0,
                MycStatusReasonCodes::empty(),
            ),
            Err(MycStatusError::new(
                MycStatusErrorKind::InvalidTransportState
            ))
        );
        assert_eq!(
            MycStatusUnixSeconds::new(i64::MAX as u64 + 1),
            Err(MycStatusError::new(MycStatusErrorKind::InvalidTime))
        );
        for kind in [
            MycStatusErrorKind::InvalidReasonCode,
            MycStatusErrorKind::TooManyReasonCodes,
            MycStatusErrorKind::InvalidLifecycle,
            MycStatusErrorKind::InvalidBuildInfo,
            MycStatusErrorKind::InvalidConfiguration,
            MycStatusErrorKind::InvalidPersistence,
            MycStatusErrorKind::InvalidIdentityHealth,
            MycStatusErrorKind::InvalidProviderState,
            MycStatusErrorKind::InvalidTransportState,
            MycStatusErrorKind::InvalidTime,
            MycStatusErrorKind::InvalidModel,
            MycStatusErrorKind::Encoding,
            MycStatusErrorKind::ResponseTooLarge,
            MycStatusErrorKind::InvalidTransition,
            MycStatusErrorKind::PublisherDropped,
        ] {
            let error = MycStatusError::new(kind);
            assert!(!error.code().is_empty());
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("source"));
        }
    }
}
