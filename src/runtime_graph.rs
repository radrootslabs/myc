//! Final native Myc daemon graph, readiness, reconnect, and bounded shutdown.

use core::{fmt, future::Future, future::pending, pin::Pin, time::Duration};
use std::{
    collections::VecDeque,
    error::Error,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use radroots_service_host::{
    EntropySource, GracefulShutdown, HostError, HostErrorKind, MetricValue, MonotonicClock,
    ProcessSignal, ProcessSignalAdapter, ProcessSignalFuture, ProcessSignalSource,
    ShutdownDisposition, ShutdownPhase, ShutdownPhaseFuture, ShutdownPhaseHandler,
    SupervisedTaskExitStatus, SystemEntropy, SystemMonotonicClock, SystemWallClock,
    TaskClassification, TaskMetadata, TaskName, TaskSupervisor, WallClock,
};
use radroots_service_sqlite::{
    BackupCreatedAtUnixMs, MigrationAppliedAtUnixSeconds, MigrationBuildIdentity,
};
use radroots_transport::{BoxSubscription, SubscriptionNext, source::SubscriptionCheckpoint};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::delivery_worker::{MycDeliveryExecutionEvidence, MycDeliveryWorker};
use crate::provider_executor::MycProviderExecutor;
use crate::runtime_nip46::{
    MycNip46DispatchErrorKind, MycRuntimeNip46AdmissionEvidence, MycRuntimeNip46Coordinator,
};
use crate::state_admin::AdminJournalOperationError;
use crate::state_connection::{
    MycAdminConnectionAction, apply_admin_challenge_authorize, apply_admin_challenge_require,
    apply_admin_connection_mutation,
};
use crate::state_discovery::{apply_admin_discovery_publish, prepare_discovery_signing_bytes};
use crate::state_governance::MycAdminAuditQuery;
use crate::transport_nostr_adapter::MycNostrIngressAdapter;
use crate::{
    MycAdminCancellationToken, MycAdminFuture, MycAdminHandler, MycAdminHandlerError,
    MycAdminHandlerErrorKind, MycAdminOperationAdmission, MycAdminOperationErrorKind,
    MycAdminOperationJournalPolicy, MycAdminOperationTimeUnixMs, MycAdminRequestDocument,
    MycAdminResponseDocument, MycAdminRoute, MycAdminServer, MycAuditCorrelationId, MycAuditKind,
    MycAuditOutcome, MycAuditPageLimit, MycAuthorizationChallengeId,
    MycAuthorizationChallengeNonce, MycAuthorizationChallengeRequest,
    MycAuthorizationChallengeState, MycAuthorizationChallengeUrl, MycBootstrapProfileV1,
    MycBoundAdminServer, MycBoundOperationsServer, MycConfigDocumentV1, MycConnectionCountsV1,
    MycConnectionId, MycConnectionPermission, MycConnectionPermissionSet,
    MycConnectionPolicyGeneration, MycConnectionStatus, MycConnectionTimeUnixMs,
    MycDeliveryAttemptNonce, MycDeliveryRecoveryEntropy, MycDeliveryTimeUnixMs,
    MycDiscoveryCommitRequest, MycIdentityHealthV1, MycOperationsCancellationToken,
    MycOperationsServer, MycOutboxStatusV1, MycPersistenceHealthV1, MycPersistenceStatusV1,
    MycProcessResult, MycProcessSignal, MycProcessSignalSource, MycProviderCorrelationId,
    MycProviderDeadlineUnixMs, MycProviderOperation, MycProviderOperationId,
    MycProviderOperationInput, MycProviderResponseObservedAtUnixMs, MycProviderRole,
    MycProviderStatusV1, MycRateLimitClass, MycRelayTransportStatusV1, MycRuntimeContext,
    MycServicePhase, MycSignerOperationId, MycStateHost, MycStatusBuildInfoV1, MycStatusBuildMode,
    MycStatusCommonV1, MycStatusConfigurationIdentityV1, MycStatusConfigurationSource,
    MycStatusObservationV1, MycStatusPublisher, MycStatusReader, MycStatusReasonCode,
    MycStatusReasonCodes, MycTaskCancellation, MycTransportHealthV1, myc_status_cache,
    open_myc_state_read_write_from_config,
};

const TASK_ADMIN_SERVER: &str = "admin_server";
const TASK_OPERATIONS_SERVER: &str = "operations_server";
const TASK_RELAY_INGRESS: &str = "relay_ingress";
const TASK_PROVIDER_DISPATCH: &str = "provider_dispatch";
const TASK_DELIVERY_OUTBOX: &str = "delivery_outbox";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MycDaemonErrorKind {
    State,
    Provider,
    Relay,
    Admin,
    Operations,
    Runtime,
}

struct MycDaemonError {
    kind: MycDaemonErrorKind,
}

impl MycDaemonError {
    const fn new(kind: MycDaemonErrorKind) -> Self {
        Self { kind }
    }

    const fn process_result(&self) -> MycProcessResult {
        match self.kind {
            MycDaemonErrorKind::State => MycProcessResult::StateOrIdentityUnavailable,
            MycDaemonErrorKind::Provider
            | MycDaemonErrorKind::Relay
            | MycDaemonErrorKind::Admin
            | MycDaemonErrorKind::Operations => MycProcessResult::ServiceOrDependencyUnavailable,
            MycDaemonErrorKind::Runtime => MycProcessResult::UnexpectedInternal,
        }
    }
}

impl fmt::Debug for MycDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDaemonError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc daemon failed")
    }
}

impl Error for MycDaemonError {}

struct HostSignalSource<S> {
    inner: S,
}

impl<S> HostSignalSource<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> ProcessSignalSource for HostSignalSource<S>
where
    S: MycProcessSignalSource,
{
    fn next_signal(&mut self) -> ProcessSignalFuture<'_> {
        Box::pin(async move {
            self.inner.next_signal().await.map(|signal| match signal {
                MycProcessSignal::Interrupt => ProcessSignal::Interrupt,
                #[cfg(unix)]
                MycProcessSignal::Terminate => ProcessSignal::Terminate,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealthEvent {
    Providers(bool),
    RequiredRelays(bool),
    StateChanged,
}

struct RuntimeHealth {
    providers: bool,
    required_relays: bool,
    operations: bool,
}

struct RuntimeIngressItem {
    raw_event: Box<[u8]>,
    relay_id: crate::MycRateRelayId,
    observed_at_unix_ms: u64,
}

struct RuntimeIngressSlot {
    index: usize,
    required: bool,
    checkpoints: Vec<SubscriptionCheckpoint>,
    state: RuntimeIngressSlotState,
    retry_delay_ms: u64,
}

enum RuntimeIngressSlotState {
    Active(BoxSubscription),
    Waiting,
    Connecting(
        Pin<
            Box<
                dyn Future<
                        Output = Result<
                            BoxSubscription,
                            crate::transport_nostr_adapter::MycRelayAdapterError,
                        >,
                    > + Send,
            >,
        >,
    ),
}

enum RuntimeIngressAction {
    Next(Result<SubscriptionNext, radroots_transport::Error>),
    Retry,
    Connected(Result<BoxSubscription, crate::transport_nostr_adapter::MycRelayAdapterError>),
}

impl RuntimeHealth {
    const fn ready(operations: bool) -> Self {
        Self {
            providers: true,
            required_relays: true,
            operations,
        }
    }

    fn observe(&mut self, event: HealthEvent) -> bool {
        match event {
            HealthEvent::Providers(value) => {
                let changed = self.providers != value;
                self.providers = value;
                changed
            }
            HealthEvent::RequiredRelays(value) => {
                let changed = self.required_relays != value;
                self.required_relays = value;
                changed
            }
            HealthEvent::StateChanged => true,
        }
    }
}

struct RuntimeStatusContext {
    runtime: MycRuntimeContext,
    configuration: Arc<MycConfigDocumentV1>,
    state: Arc<MycStateHost>,
    clock: SystemMonotonicClock,
    generation: u64,
    connection_counts: MycConnectionCountsV1,
    outbox: MycOutboxStatusV1,
}

impl RuntimeStatusContext {
    async fn refresh_state(&mut self) -> Result<(), MycDaemonError> {
        let connection_counts = self
            .state
            .repository()
            .read_runtime_connection_counts()
            .await
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?;
        let outbox = self
            .state
            .repository()
            .read_runtime_outbox_status()
            .await
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?;
        self.connection_counts = connection_counts;
        self.outbox = outbox;
        Ok(())
    }

    fn observation(
        &self,
        phase: MycServicePhase,
        health: &RuntimeHealth,
    ) -> Result<MycStatusObservationV1, MycDaemonError> {
        let ready = matches!(phase, MycServicePhase::Ready | MycServicePhase::Degraded)
            && health.providers
            && health.required_relays;
        let mut reasons = Vec::new();
        if !health.providers {
            reasons.push(MycStatusReasonCode::SignerProviderUnavailable);
        }
        if !health.required_relays {
            reasons.push(MycStatusReasonCode::RequiredRelayUnavailable);
            reasons.push(MycStatusReasonCode::SubscriberNotActive);
        }
        if !health.operations {
            reasons.push(MycStatusReasonCode::OperationsListenerFailed);
        }
        if phase == MycServicePhase::Stopping {
            reasons.push(MycStatusReasonCode::ShutdownInProgress);
        }
        let reasons = MycStatusReasonCodes::new(reasons)
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        let build = runtime_build_info()?;
        let configuration = MycStatusConfigurationIdentityV1::new(
            hex::encode(self.state.metadata().configuration_digest().as_bytes()),
            if self.runtime.profile() == MycBootstrapProfileV1::RepoLocal {
                MycStatusConfigurationSource::DerivedRepoLocal
            } else {
                MycStatusConfigurationSource::ExplicitConfig
            },
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        let persistence = MycPersistenceStatusV1::new(
            MycPersistenceHealthV1::Ready,
            self.state
                .metadata()
                .initial_database_metadata()
                .state_schema_version()
                .get(),
            self.generation,
            crate::MycIntegrityStateV1::Verified,
            MycStatusReasonCodes::empty(),
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        let common = MycStatusCommonV1::new(
            phase,
            ready,
            reasons.clone(),
            u64::try_from(
                self.clock
                    .now_monotonic()
                    .duration_since_origin()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
            build,
            configuration,
            persistence,
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        let identity = |configured: bool| {
            MycIdentityHealthV1::new(configured, configured && health.providers, reasons.clone())
        };
        let provider = MycProviderStatusV1::new(
            identity(true).map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?,
            identity(true).map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?,
            identity(
                self.configuration
                    .provider_contract()
                    .binding(MycProviderRole::Discovery)
                    .is_some(),
            )
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?,
            reasons.clone(),
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        let transport = MycRelayTransportStatusV1::new(
            if health.required_relays {
                MycTransportHealthV1::Ready
            } else {
                MycTransportHealthV1::Unavailable
            },
            health.required_relays,
            if health.required_relays {
                u64::try_from(self.configuration.relay_count()).unwrap_or(u64::MAX)
            } else {
                0
            },
            reasons,
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
        Ok(MycStatusObservationV1::new(
            common,
            provider,
            transport,
            self.connection_counts,
            self.outbox,
        ))
    }
}

struct RuntimeAdminHandler {
    state: Arc<MycStateHost>,
    configuration: Arc<MycConfigDocumentV1>,
    providers: Arc<MycProviderExecutor>,
    status: MycStatusReader,
    accepting_mutations: Arc<AtomicBool>,
    cursor_key: [u8; 32],
    health: mpsc::Sender<HealthEvent>,
}

impl RuntimeAdminHandler {
    async fn handle_inner(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        if request.route().is_mutation() && !self.accepting_mutations.load(Ordering::Acquire) {
            return Err(handler_error(MycAdminHandlerErrorKind::Unavailable));
        }
        match request.route() {
            MycAdminRoute::Status => MycAdminResponseDocument::from_canonical_bytes(
                request.route(),
                self.status.snapshot().detailed_status_json(),
            )
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal)),
            MycAdminRoute::EffectiveConfig => MycAdminResponseDocument::from_canonical_bytes(
                request.route(),
                self.configuration.effective().canonical_json().as_bytes(),
            )
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal)),
            MycAdminRoute::IdentityStatus | MycAdminRoute::IdentityPublic => {
                self.identity_response(request).await
            }
            MycAdminRoute::StateStatus => self.state_status(request).await,
            MycAdminRoute::StateBackup => self.backup(request).await,
            MycAdminRoute::MetricsSnapshot => self.metrics_snapshot(request),
            MycAdminRoute::ConnectionsList => self.connections(request).await,
            MycAdminRoute::AuditEvents => self.audit_events(request).await,
            MycAdminRoute::AuditSummary => self.audit_summary(request).await,
            MycAdminRoute::DiscoveryDesired => self.discovery_desired(request).await,
            MycAdminRoute::ConnectionApprove
            | MycAdminRoute::ConnectionReject
            | MycAdminRoute::ConnectionRevoke => self.connection_mutation(request).await,
            MycAdminRoute::ChallengeRequire => self.challenge_require(request).await,
            MycAdminRoute::ChallengeAuthorize => self.challenge_authorize(request).await,
            MycAdminRoute::DiscoveryRender
            | MycAdminRoute::DiscoveryRefresh
            | MycAdminRoute::DiscoveryPublish => self.discovery_mutation(request).await,
        }
    }

    async fn identity_response(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let model: Value = serde_json::from_slice(request.model_bytes())
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let role_name = model
            .pointer("/role")
            .and_then(Value::as_str)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let role = match role_name {
            "transport" => MycProviderRole::Transport,
            "user" => MycProviderRole::User,
            "discovery" => MycProviderRole::Discovery,
            _ => return Err(handler_error(MycAdminHandlerErrorKind::Internal)),
        };
        let binding = self.configuration.provider_contract().binding(role);
        let expected = match role {
            MycProviderRole::Transport => {
                Some(self.state.metadata().expected_identities().transport())
            }
            MycProviderRole::User => Some(self.state.metadata().expected_identities().user()),
            MycProviderRole::Discovery => self.state.metadata().expected_identities().discovery(),
        };
        let generation = u64::from(
            self.state
                .repository()
                .current_configuration_generation()
                .await
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
        );
        let value = if request.route() == MycAdminRoute::IdentityPublic {
            let expected =
                expected.ok_or_else(|| handler_error(MycAdminHandlerErrorKind::NotFound))?;
            json!({"generation":generation,"public_key":expected.as_hex(),"role":role_name})
        } else {
            let mut value = json!({
                "available": binding.is_some(),
                "configured": binding.is_some(),
                "generation": generation,
                "reason_codes": [],
                "role": role_name,
            });
            if let Some(binding) = binding {
                value["provider"] = Value::String(binding.kind().as_str().to_owned());
            }
            if let Some(expected) = expected {
                value["public_key"] = Value::String(expected.as_hex().to_owned());
            }
            value
        };
        response(request.route(), value)
    }

    async fn state_status(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let generation = self
            .state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        response(
            request.route(),
            json!({
                "backup_eligible": true,
                "generation": u64::from(generation),
                "integrity": "verified",
                "reason_codes": [],
                "schema_version": self.state.metadata().initial_database_metadata().state_schema_version().get(),
                "writer_lock": "held_by_daemon",
            }),
        )
    }

    async fn backup(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let now_seconds = SystemWallClock
            .now_utc()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?
            .get();
        let now_millis = now_seconds
            .checked_mul(1_000)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let prepared_at = MycAdminOperationTimeUnixMs::new(now_millis)
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let model: Value = serde_json::from_slice(request.model_bytes())
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let expected_generation = model
            .pointer("/expected_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let actual_generation = u64::from(
            self.state
                .repository()
                .current_configuration_generation()
                .await
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
        );
        if expected_generation != actual_generation {
            return Err(handler_error(MycAdminHandlerErrorKind::Conflict));
        }
        let prepared = match self
            .state
            .repository()
            .prepare_admin_operation(&request, prepared_at)
            .await
            .map_err(map_admin_journal_error)?
        {
            MycAdminOperationAdmission::ExactReplay(response) => return Ok(response),
            MycAdminOperationAdmission::Prepared(prepared) => prepared,
        };
        let target = model
            .pointer("/target_path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let manifest = self
            .state
            .capture_online_backup(
                &target,
                BackupCreatedAtUnixMs::new(now_millis)
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
            )
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let completed_at_seconds = SystemWallClock
            .now_utc()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?
            .get();
        let completed_at = MycAdminOperationTimeUnixMs::new(
            completed_at_seconds
                .checked_mul(1_000)
                .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let operation_id = request
            .operation_id()
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let response = response(
            request.route(),
            json!({
                "completed_at_utc": completed_at_seconds,
                "manifest_digest": hex::encode(manifest.digest().as_bytes()),
                "operation_id": operation_id,
                "snapshot_generation": actual_generation,
            }),
        )?;
        self.state
            .repository()
            .complete_admin_operation(
                &prepared,
                &response,
                completed_at,
                MycAdminOperationJournalPolicy::seven_days(),
            )
            .await
            .map_err(map_admin_journal_error)?;
        Ok(response)
    }

    fn metrics_snapshot(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let captured_at = SystemWallClock
            .now_utc()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?
            .get();
        let snapshot = self.status.operations_cache().snapshot();
        let mut metrics = serde_json::Map::new();
        for sample in snapshot.metrics().samples() {
            let mut key = sample.name().as_str().to_owned();
            for label in sample.labels() {
                key.push('_');
                key.push_str(label.value());
            }
            if !safe_metric_key(&key) {
                return Err(handler_error(MycAdminHandlerErrorKind::Internal));
            }
            let value = match sample.value() {
                MetricValue::Counter(value) => value,
                MetricValue::Gauge(value) => u64::try_from(value)
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
            };
            if metrics.insert(key, Value::from(value)).is_some() {
                return Err(handler_error(MycAdminHandlerErrorKind::Internal));
            }
        }
        response(
            request.route(),
            json!({"captured_at_utc":captured_at,"metrics":metrics}),
        )
    }

    async fn connections(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = model_u64(&model, "/limit")
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let status = model
            .pointer("/state")
            .and_then(Value::as_str)
            .map(|value| match value {
                "pending" => Ok(MycConnectionStatus::Pending),
                "approved" => Ok(MycConnectionStatus::Active),
                "rejected" => Ok(MycConnectionStatus::Denied),
                "revoked" => Ok(MycConnectionStatus::Expired),
                _ => Err(handler_error(MycAdminHandlerErrorKind::Internal)),
            })
            .transpose()?;
        let cursor = model
            .pointer("/cursor")
            .and_then(Value::as_str)
            .map(|value| decode_connection_cursor(value, status, &self.cursor_key))
            .transpose()?;
        let snapshot = match cursor.as_ref() {
            Some(cursor) => cursor.snapshot,
            None => connection_time_now_for_admin()?,
        };
        let before = cursor.map(|cursor| (cursor.before, cursor.id));
        let page = self
            .state
            .repository()
            .read_admin_connection_page(limit, status, snapshot, before)
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let items = page
            .items()
            .iter()
            .map(|record| {
                json!({
                    "client_public_key": record.client_public_key().as_hex(),
                    "connection_id": hex::encode(record.id().as_bytes()),
                    "created_at_utc": record.created_at().get() / 1_000,
                    "generation": record.policy_generation().get(),
                    "permissions": record.admin_permissions(),
                    "state": record.status().admin_state(),
                    "updated_at_utc": record.updated_at().get() / 1_000,
                })
            })
            .collect::<Vec<_>>();
        let mut value = json!({
            "items": items,
            "snapshot_generation": snapshot.get(),
        });
        if let Some((before, id)) = page.next() {
            value["next_cursor"] = Value::String(encode_connection_cursor(
                snapshot,
                before,
                id,
                status,
                &self.cursor_key,
            ));
        }
        response(request.route(), value)
    }

    async fn audit_events(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = model_u64(&model, "/limit")
            .and_then(|value| u16::try_from(value).ok())
            .and_then(|value| MycAuditPageLimit::new(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let from_ms = optional_seconds_as_millis(&model, "/from_utc", false)?;
        let to_ms = optional_seconds_as_millis(&model, "/to_utc", true)?;
        let kind = model
            .pointer("/kind")
            .and_then(Value::as_str)
            .map(|value| {
                MycAuditKind::parse(value)
                    .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
            })
            .transpose()?;
        let outcome = model
            .pointer("/outcome")
            .and_then(Value::as_str)
            .map(|value| {
                MycAuditOutcome::parse(value)
                    .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
            })
            .transpose()?;
        let query_digest = audit_query_digest(from_ms, to_ms, kind, outcome);
        let cursor = model
            .pointer("/cursor")
            .and_then(Value::as_str)
            .map(|value| decode_audit_cursor(value, query_digest, &self.cursor_key))
            .transpose()?;
        let page = self
            .state
            .repository()
            .read_admin_audit_page(
                MycAdminAuditQuery::new(
                    limit,
                    cursor.as_ref().map(|value| value.snapshot),
                    cursor.as_ref().map(|value| value.before),
                    from_ms,
                    to_ms,
                    kind,
                    outcome,
                )
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
            )
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let items = page
            .items()
            .iter()
            .map(|record| {
                json!({
                    "audit_id": format!("audit-{}", record.sequence()),
                    "correlation_id": hex::encode(record.correlation_id().as_bytes()),
                    "kind": record.kind().as_str(),
                    "occurred_at_utc": record.occurred_at().get() / 1_000,
                    "outcome": record.outcome().as_str(),
                    "reason_code": record.reason().as_str(),
                })
            })
            .collect::<Vec<_>>();
        let mut value = json!({
            "items": items,
            "snapshot_generation": page.snapshot_sequence(),
        });
        if let Some(before) = page.next_before_sequence() {
            value["next_cursor"] = Value::String(encode_audit_cursor(
                page.snapshot_sequence(),
                before,
                query_digest,
                &self.cursor_key,
            ));
        }
        response(request.route(), value)
    }

    async fn audit_summary(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let model = request_model(&request)?;
        let from = model_u64(&model, "/from_utc")
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let to = model_u64(&model, "/to_utc")
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let from_ms = seconds_as_millis(from, false)?;
        let to_ms = seconds_as_millis(to, true)?;
        let counts = self
            .state
            .repository()
            .read_admin_audit_summary(from_ms, to_ms)
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?
            .iter()
            .map(|(key, value)| (key.clone(), Value::from(*value)))
            .collect::<serde_json::Map<_, _>>();
        response(
            request.route(),
            json!({
                "counts": counts,
                "from_utc": from,
                "to_utc": to,
            }),
        )
    }

    async fn connection_mutation(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let route = request.route();
        let model = request_model(&request)?;
        let operation_id = request_operation_id(&request)?.to_owned();
        let connection_id =
            digest_id_parameter(&request, "connection_id").map(MycConnectionId::from_bytes)?;
        let generation = model_u64(&model, "/expected_generation")
            .and_then(|value| MycConnectionPolicyGeneration::new(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let observed_at = connection_time_now_for_admin()?;
        let correlation = admin_audit_correlation(&request);
        let action = match route {
            MycAdminRoute::ConnectionApprove => {
                let permissions = model
                    .pointer("/permissions")
                    .and_then(Value::as_str)
                    .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
                let permissions = if permissions.is_empty() {
                    Vec::new()
                } else {
                    permissions
                        .split(',')
                        .map(|value| {
                            MycConnectionPermission::parse(value)
                                .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                };
                let permissions = MycConnectionPermissionSet::new(&permissions)
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
                let authorized_until = self
                    .configuration
                    .normalized()
                    .pointer("/policy/challenges/enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    .then(|| {
                        let lifetime = configuration_integer(
                            &self.configuration,
                            "/policy/challenges/authorized_lifetime_ms",
                        )?;
                        let until = observed_at
                            .get()
                            .checked_add(lifetime)
                            .ok_or_else(|| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
                        MycConnectionTimeUnixMs::new(until)
                            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
                    })
                    .transpose()
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
                MycAdminConnectionAction::Approve {
                    permissions,
                    authorized_until,
                }
            }
            MycAdminRoute::ConnectionReject => MycAdminConnectionAction::Reject,
            MycAdminRoute::ConnectionRevoke => MycAdminConnectionAction::Revoke,
            _ => return Err(handler_error(MycAdminHandlerErrorKind::Internal)),
        };
        let completed_at = admin_operation_time(observed_at)?;
        self.state
            .repository()
            .execute_database_admin_operation(
                &request,
                completed_at,
                MycAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    Box::pin(async move {
                        let (before, after) = apply_admin_connection_mutation(
                            transaction,
                            connection_id,
                            generation,
                            observed_at,
                            correlation,
                            action,
                        )
                        .await?;
                        response(
                            route,
                            json!({
                                "connection_id": hex::encode(after.id().as_bytes()),
                                "current_state": after.status().admin_state(),
                                "generation": after.policy_generation().get(),
                                "operation_id": operation_id,
                                "previous_state": before.status().admin_state(),
                            }),
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .map_err(map_admin_journal_error)
    }

    async fn challenge_require(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let route = request.route();
        let model = request_model(&request)?;
        let connection_id = model
            .pointer("/connection_id")
            .and_then(Value::as_str)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
            .and_then(digest_id)
            .map(MycConnectionId::from_bytes)?;
        let operation_id = model
            .pointer("/request_identity")
            .and_then(Value::as_str)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
            .and_then(digest_id)
            .map(MycSignerOperationId::from_persisted)?;
        let generation = model_u64(&model, "/expected_policy_generation")
            .and_then(|value| MycConnectionPolicyGeneration::new(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let issued_at = connection_time_now_for_admin()?;
        let lifetime = configuration_integer(
            &self.configuration,
            "/policy/challenges/pending_lifetime_ms",
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let expires_at = MycConnectionTimeUnixMs::new(
            issued_at
                .get()
                .checked_add(lifetime)
                .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let url = self
            .configuration
            .normalized()
            .pointer("/policy/challenges/url")
            .and_then(Value::as_str)
            .and_then(|value| MycAuthorizationChallengeUrl::new(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let mut nonce = [0_u8; 32];
        SystemEntropy
            .fill_bytes(&mut nonce)
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let challenge = MycAuthorizationChallengeRequest::new(
            operation_id,
            connection_id,
            generation,
            url,
            MycAuthorizationChallengeNonce::from_injected_entropy(nonce),
            issued_at,
            expires_at,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        if !self
            .state
            .metadata()
            .admits_authorization_challenge_request(&challenge)
        {
            return Err(handler_error(MycAdminHandlerErrorKind::Conflict));
        }
        let rate = self
            .state
            .metadata()
            .governance_rate_policy(MycRateLimitClass::ChallengeCreation);
        let completed_at = admin_operation_time(issued_at)?;
        self.state
            .repository()
            .execute_database_admin_operation(
                &request,
                completed_at,
                MycAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    Box::pin(async move {
                        let record =
                            apply_admin_challenge_require(transaction, challenge, rate).await?;
                        response(
                            route,
                            json!({
                                "challenge_id": hex::encode(record.id().as_bytes()),
                                "challenge_url": record.url().as_str(),
                                "connection_id": hex::encode(record.connection_id().as_bytes()),
                                "expires_at_utc": record.expires_at().get() / 1_000,
                                "issued_at_utc": record.issued_at().get() / 1_000,
                                "request_identity": hex::encode(record.operation_id().as_bytes()),
                                "state": challenge_admin_state(record.state()),
                            }),
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .map_err(map_admin_journal_error)
    }

    async fn challenge_authorize(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let route = request.route();
        let model = request_model(&request)?;
        let challenge_id = digest_id_parameter(&request, "challenge_id")
            .map(MycAuthorizationChallengeId::from_bytes)?;
        let generation = model_u64(&model, "/expected_generation")
            .and_then(|value| MycConnectionPolicyGeneration::new(value).ok())
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let observed_at = connection_time_now_for_admin()?;
        let completed_at = admin_operation_time(observed_at)?;
        let operation_id = request_operation_id(&request)?.to_owned();
        let rate = self
            .state
            .metadata()
            .governance_rate_policy(MycRateLimitClass::ChallengeAuthorization);
        self.state
            .repository()
            .execute_database_admin_operation(
                &request,
                completed_at,
                MycAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    Box::pin(async move {
                        let record = apply_admin_challenge_authorize(
                            transaction,
                            challenge_id,
                            generation,
                            observed_at,
                            rate,
                        )
                        .await?;
                        response(
                            route,
                            json!({
                                "challenge_id": hex::encode(record.id().as_bytes()),
                                "generation": record.policy_generation().get(),
                                "operation_id": operation_id,
                                "request_identity": hex::encode(record.operation_id().as_bytes()),
                                "state": challenge_admin_state(record.state()),
                            }),
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .map_err(map_admin_journal_error)
    }

    async fn discovery_mutation(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let route = request.route();
        let model = request_model(&request)?;
        let expected_generation = model_u64(&model, "/expected_generation")
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let actual_generation = u64::from(
            self.state
                .repository()
                .current_configuration_generation()
                .await
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
        );
        if expected_generation != actual_generation {
            return Err(handler_error(MycAdminHandlerErrorKind::Conflict));
        }
        let now_seconds = SystemWallClock
            .now_utc()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?
            .get();
        let now_millis = now_seconds
            .checked_mul(1_000)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let prepared_at = MycAdminOperationTimeUnixMs::new(now_millis)
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let prepared = match self
            .state
            .repository()
            .prepare_admin_operation(&request, prepared_at)
            .await
            .map_err(map_admin_journal_error)?
        {
            MycAdminOperationAdmission::ExactReplay(response) => return Ok(response),
            MycAdminOperationAdmission::Prepared(prepared) => prepared,
        };
        let commit = self
            .prepare_discovery_commit(&request, now_seconds, now_millis)
            .await?;
        let completed_at = admin_operation_time(connection_time_now_for_admin()?)?;
        let operation_id = request_operation_id(&request)?.to_owned();
        match route {
            MycAdminRoute::DiscoveryRender => {
                let response = response(
                    route,
                    json!({
                        "document_digests": discovery_digests(&commit),
                        "generation": actual_generation,
                        "operation_id": operation_id,
                    }),
                )?;
                self.state
                    .repository()
                    .complete_admin_operation(
                        &prepared,
                        &response,
                        completed_at,
                        MycAdminOperationJournalPolicy::seven_days(),
                    )
                    .await
                    .map_err(map_admin_journal_error)?;
                Ok(response)
            }
            MycAdminRoute::DiscoveryRefresh => {
                let state = self
                    .state
                    .repository()
                    .read_discovery_publication_state()
                    .await
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
                let diff = if state
                    .as_ref()
                    .is_some_and(|state| state.desired_generation_id() == commit.generation_id())
                {
                    "in_sync"
                } else {
                    "drift"
                };
                let response = response(
                    route,
                    json!({
                        "diff_state": diff,
                        "generation": actual_generation,
                        "operation_id": operation_id,
                        "source_completion": "complete",
                    }),
                )?;
                self.state
                    .repository()
                    .complete_admin_operation(
                        &prepared,
                        &response,
                        completed_at,
                        MycAdminOperationJournalPolicy::seven_days(),
                    )
                    .await
                    .map_err(map_admin_journal_error)?;
                Ok(response)
            }
            MycAdminRoute::DiscoveryPublish => {
                let delivery_policy = self.state.metadata().delivery_policies().clone();
                let discovery_policy = self
                    .state
                    .metadata()
                    .discovery_policies()
                    .cloned()
                    .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
                self.state
                    .repository()
                    .complete_prepared_database_admin_operation(
                        &prepared,
                        completed_at,
                        MycAdminOperationJournalPolicy::seven_days(),
                        move |transaction| {
                            Box::pin(async move {
                                let admission = apply_admin_discovery_publish(
                                    transaction,
                                    &commit,
                                    &delivery_policy,
                                    &discovery_policy,
                                )
                                .await?;
                                let record = admission.record();
                                response(
                                    route,
                                    json!({
                                        "exact_bytes_digest": hex::encode(commit.event_digest().as_bytes()),
                                        "generation": actual_generation,
                                        "operation_id": operation_id,
                                        "target_count": u64::try_from(record.job().targets().len()).map_err(|_| AdminJournalOperationError::Binding)?,
                                        "workflow_id": hex::encode(record.job().id().as_bytes()),
                                    }),
                                )
                                .map_err(|_| AdminJournalOperationError::Binding)
                            })
                        },
                    )
                    .await
                    .map_err(map_admin_journal_error)
            }
            _ => Err(handler_error(MycAdminHandlerErrorKind::Internal)),
        }
    }

    async fn prepare_discovery_commit(
        &self,
        request: &MycAdminRequestDocument,
        now_seconds: u64,
        now_millis: u64,
    ) -> Result<MycDiscoveryCommitRequest, MycAdminHandlerError> {
        let unsigned = prepare_discovery_signing_bytes(self.state.metadata(), now_seconds)
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let binding = self
            .configuration
            .provider_contract()
            .binding(MycProviderRole::Discovery)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let timeout = configuration_integer(
            &self.configuration,
            "/transport/ingress/subscription_deadline_ms",
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let deadline = MycProviderDeadlineUnixMs::new(
            now_millis
                .checked_add(timeout)
                .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let operation = MycProviderOperation::new(
            binding,
            MycProviderOperationId::from_bytes(admin_identity(
                b"radroots.myc.admin.discovery.operation.v1\0",
                request_operation_id(request)?,
            )),
            MycProviderCorrelationId::from_bytes(admin_identity(
                b"radroots.myc.admin.discovery.correlation.v1\0",
                request.correlation_id(),
            )),
            deadline,
            MycProviderOperationInput::sign_event(&unsigned)
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let verified = self
            .providers
            .execute(
                operation,
                MycProviderResponseObservedAtUnixMs::new(now_millis)
                    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
                &MycTaskCancellation::uncancelled(),
            )
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?;
        let event = verified
            .signed_event_bytes()
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?;
        MycDiscoveryCommitRequest::new(
            self.state.metadata(),
            event,
            MycDeliveryTimeUnixMs::new(now_millis)
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
        )
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))
    }

    async fn discovery_desired(
        &self,
        request: MycAdminRequestDocument,
    ) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
        let generation = self
            .state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let enabled = self.state.metadata().discovery_policies().is_some();
        let publication = self
            .state
            .repository()
            .read_discovery_publication_state()
            .await
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
        let document = match publication.as_ref() {
            Some(publication) => self
                .state
                .repository()
                .read_discovery_document_for_job(publication.desired_job_id())
                .await
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?,
            None => None,
        };
        let mut digests = serde_json::Map::new();
        if let Some(document) = document {
            digests.insert(
                "handler_event".to_owned(),
                Value::String(hex::encode(document.event_digest().as_bytes())),
            );
            digests.insert(
                "nip05_projection".to_owned(),
                Value::String(hex::encode(document.nip05_projection_digest().as_bytes())),
            );
        }
        let publication_state = if !enabled {
            "disabled"
        } else if publication.as_ref().is_some_and(|state| {
            state.current_generation_id() == Some(state.desired_generation_id())
        }) {
            "delivered"
        } else {
            "pending"
        };
        response(
            request.route(),
            json!({
                "document_digests": digests,
                "enabled": enabled,
                "generation": u64::from(generation),
                "publication_state": publication_state,
            }),
        )
    }
}

impl MycAdminHandler for RuntimeAdminHandler {
    fn handle<'a>(&'a self, request: MycAdminRequestDocument) -> MycAdminFuture<'a> {
        let mutation = request.route().is_mutation();
        Box::pin(async move {
            let result = self.handle_inner(request).await;
            if mutation && result.is_ok() {
                let _ = self.health.try_send(HealthEvent::StateChanged);
            }
            result
        })
    }
}

struct ConnectionCursor {
    snapshot: MycConnectionTimeUnixMs,
    before: MycConnectionTimeUnixMs,
    id: MycConnectionId,
}

struct AuditCursor {
    snapshot: u64,
    before: u64,
}

fn request_model(request: &MycAdminRequestDocument) -> Result<Value, MycAdminHandlerError> {
    serde_json::from_slice(request.model_bytes())
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))
}

fn request_operation_id(request: &MycAdminRequestDocument) -> Result<&str, MycAdminHandlerError> {
    request
        .operation_id()
        .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
}

fn model_u64(model: &Value, pointer: &str) -> Option<u64> {
    model.pointer(pointer).and_then(Value::as_u64)
}

fn digest_id(value: &str) -> Result<[u8; 32], MycAdminHandlerError> {
    let mut bytes = [0_u8; 32];
    if value.len() != 64 || hex::decode_to_slice(value, &mut bytes).is_err() {
        return Err(handler_error(MycAdminHandlerErrorKind::NotFound));
    }
    Ok(bytes)
}

fn digest_id_parameter(
    request: &MycAdminRequestDocument,
    name: &str,
) -> Result<[u8; 32], MycAdminHandlerError> {
    request
        .parameter(name)
        .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::NotFound))
        .and_then(digest_id)
}

fn connection_time_now_for_admin() -> Result<MycConnectionTimeUnixMs, MycAdminHandlerError> {
    MycConnectionTimeUnixMs::new(
        SystemWallClock
            .now_utc()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::Unavailable))?
            .get()
            .checked_mul(1_000)
            .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))?,
    )
    .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))
}

fn admin_operation_time(
    time: MycConnectionTimeUnixMs,
) -> Result<MycAdminOperationTimeUnixMs, MycAdminHandlerError> {
    MycAdminOperationTimeUnixMs::new(time.get())
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))
}

fn admin_identity(domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn admin_audit_correlation(request: &MycAdminRequestDocument) -> MycAuditCorrelationId {
    MycAuditCorrelationId::new(admin_identity(
        b"radroots.myc.admin.audit_correlation.v1\0",
        request.correlation_id(),
    ))
}

const fn challenge_admin_state(state: MycAuthorizationChallengeState) -> &'static str {
    match state {
        MycAuthorizationChallengeState::Pending => "pending",
        MycAuthorizationChallengeState::Authorized => "authorized",
        MycAuthorizationChallengeState::Expired => "expired",
    }
}

fn discovery_digests(request: &MycDiscoveryCommitRequest) -> Value {
    json!({
        "desired": hex::encode(request.desired_digest().as_bytes()),
        "handler_event": hex::encode(request.event_digest().as_bytes()),
        "nip05_projection": hex::encode(request.projection_digest().as_bytes()),
    })
}

fn seconds_as_millis(seconds: u64, include_full_second: bool) -> Result<u64, MycAdminHandlerError> {
    seconds
        .checked_mul(1_000)
        .and_then(|value| {
            if include_full_second {
                value.checked_add(999)
            } else {
                Some(value)
            }
        })
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or_else(|| handler_error(MycAdminHandlerErrorKind::Internal))
}

fn optional_seconds_as_millis(
    model: &Value,
    pointer: &str,
    include_full_second: bool,
) -> Result<Option<u64>, MycAdminHandlerError> {
    model_u64(model, pointer)
        .map(|value| seconds_as_millis(value, include_full_second))
        .transpose()
}

const fn connection_state_code(status: Option<MycConnectionStatus>) -> u8 {
    match status {
        None => 0,
        Some(MycConnectionStatus::Pending) => 1,
        Some(MycConnectionStatus::Active) => 2,
        Some(MycConnectionStatus::Denied) => 3,
        Some(MycConnectionStatus::Expired) => 4,
    }
}

fn encode_connection_cursor(
    snapshot: MycConnectionTimeUnixMs,
    before: MycConnectionTimeUnixMs,
    id: MycConnectionId,
    status: Option<MycConnectionStatus>,
    key: &[u8; 32],
) -> String {
    let mut payload = Vec::with_capacity(83);
    payload.extend_from_slice(&[1, 1]);
    payload.extend_from_slice(&snapshot.get().to_be_bytes());
    payload.extend_from_slice(&before.get().to_be_bytes());
    payload.extend_from_slice(id.as_bytes());
    payload.push(connection_state_code(status));
    payload.extend_from_slice(&cursor_mac(key, &payload));
    URL_SAFE_NO_PAD.encode(payload)
}

fn decode_connection_cursor(
    encoded: &str,
    status: Option<MycConnectionStatus>,
    key: &[u8; 32],
) -> Result<ConnectionCursor, MycAdminHandlerError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?;
    if bytes.len() != 83
        || bytes[0..2] != [1, 1]
        || bytes[50] != connection_state_code(status)
        || !constant_time_equal(&bytes[51..], &cursor_mac(key, &bytes[..51]))
    {
        return Err(handler_error(MycAdminHandlerErrorKind::InvalidCursor));
    }
    let snapshot = MycConnectionTimeUnixMs::new(u64::from_be_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?,
    ))
    .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?;
    let before = MycConnectionTimeUnixMs::new(u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?,
    ))
    .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?;
    let id = MycConnectionId::from_bytes(
        bytes[18..50]
            .try_into()
            .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?,
    );
    Ok(ConnectionCursor {
        snapshot,
        before,
        id,
    })
}

fn audit_query_digest(
    from: Option<u64>,
    to: Option<u64>,
    kind: Option<MycAuditKind>,
    outcome: Option<MycAuditOutcome>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"radroots.myc.admin.audit_query.v1\0");
    hasher.update(from.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(to.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(
        kind.map(MycAuditKind::as_str)
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(
        outcome
            .map(MycAuditOutcome::as_str)
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.finalize().into()
}

fn encode_audit_cursor(
    snapshot: u64,
    before: u64,
    query_digest: [u8; 32],
    key: &[u8; 32],
) -> String {
    let mut payload = Vec::with_capacity(82);
    payload.extend_from_slice(&[1, 2]);
    payload.extend_from_slice(&snapshot.to_be_bytes());
    payload.extend_from_slice(&before.to_be_bytes());
    payload.extend_from_slice(&query_digest);
    payload.extend_from_slice(&cursor_mac(key, &payload));
    URL_SAFE_NO_PAD.encode(payload)
}

fn decode_audit_cursor(
    encoded: &str,
    query_digest: [u8; 32],
    key: &[u8; 32],
) -> Result<AuditCursor, MycAdminHandlerError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?;
    if bytes.len() != 82
        || bytes[0..2] != [1, 2]
        || bytes[18..50] != query_digest
        || !constant_time_equal(&bytes[50..], &cursor_mac(key, &bytes[..50]))
    {
        return Err(handler_error(MycAdminHandlerErrorKind::InvalidCursor));
    }
    Ok(AuditCursor {
        snapshot: u64::from_be_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?,
        ),
        before: u64::from_be_bytes(
            bytes[10..18]
                .try_into()
                .map_err(|_| handler_error(MycAdminHandlerErrorKind::InvalidCursor))?,
        ),
    })
}

fn cursor_mac(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"radroots.myc.admin.cursor.v1\0");
    hasher.update(key);
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(payload);
    hasher.finalize().into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn safe_metric_key(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

struct RuntimeShutdownHandler {
    accepting_mutations: Arc<AtomicBool>,
    state: Arc<MycStateHost>,
    status: MycStatusPublisher,
    status_context: RuntimeStatusContext,
    health: RuntimeHealth,
}

impl RuntimeShutdownHandler {
    fn publish(&mut self, phase: MycServicePhase) -> Result<(), HostError> {
        let observation = self
            .status_context
            .observation(phase, &self.health)
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        self.status
            .publish(observation)
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))
    }
}

impl ShutdownPhaseHandler for RuntimeShutdownHandler {
    fn enter(&mut self, phase: ShutdownPhase) -> ShutdownPhaseFuture<'_> {
        Box::pin(async move {
            match phase {
                ShutdownPhase::RejectNewMutations => {
                    self.accepting_mutations.store(false, Ordering::Release);
                    self.publish(MycServicePhase::Stopping)?;
                }
                ShutdownPhase::PersistRecoverableWork => {
                    self.state
                        .repository()
                        .verify_delivery_invariants()
                        .await
                        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
                }
                ShutdownPhase::CloseSqlite => {
                    self.state
                        .close()
                        .await
                        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
                }
                ShutdownPhase::CancelIngress
                | ShutdownPhase::DrainOperations
                | ShutdownPhase::CloseNetwork
                | ShutdownPhase::CloseSockets => {}
            }
            Ok(())
        })
    }
}

pub(crate) async fn run_myc_daemon<S>(
    runtime: MycRuntimeContext,
    configuration: MycConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
    signals: S,
) -> MycProcessResult
where
    S: MycProcessSignalSource + 'static,
{
    run_myc_daemon_inner(runtime, configuration, applied_at, build, signals)
        .await
        .unwrap_or_else(|error| error.process_result())
}

async fn run_myc_daemon_inner<S>(
    runtime: MycRuntimeContext,
    configuration: MycConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
    signals: S,
) -> Result<MycProcessResult, MycDaemonError>
where
    S: MycProcessSignalSource + 'static,
{
    let configuration = Arc::new(configuration);
    let state = Arc::new(
        open_myc_state_read_write_from_config(&runtime, &configuration, applied_at, build)
            .await
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?,
    );
    let now_millis = wall_time_millis()?;
    let mut recovery_entropy = [0_u8; 32];
    SystemEntropy
        .fill_bytes(&mut recovery_entropy)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    state
        .repository()
        .recover_delivery_state(
            MycDeliveryTimeUnixMs::new(now_millis)
                .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?,
            MycDeliveryRecoveryEntropy::from_injected_entropy(recovery_entropy),
        )
        .await
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?;
    state
        .repository()
        .verify_delivery_invariants()
        .await
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?;

    let startup_cancellation = MycTaskCancellation::uncancelled();
    let providers = Arc::new(
        MycProviderExecutor::open(&runtime, &configuration, &startup_cancellation)
            .await
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Provider))?,
    );
    let mut provider_seed = [0_u8; 32];
    SystemEntropy
        .fill_bytes(&mut provider_seed)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    providers
        .probe_all(now_millis, provider_seed, &startup_cancellation)
        .await
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Provider))?;
    let ingress_adapter = Arc::new(
        MycNostrIngressAdapter::from_configuration(&configuration)
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Relay))?,
    );
    let ingress_slots = open_initial_subscriptions(&ingress_adapter, &configuration).await?;

    let generation = u64::from(
        state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::State))?,
    );
    let mut status_context = RuntimeStatusContext {
        runtime: runtime.clone(),
        configuration: Arc::clone(&configuration),
        state: Arc::clone(&state),
        clock: SystemMonotonicClock::new(),
        generation,
        connection_counts: MycConnectionCountsV1::default(),
        outbox: MycOutboxStatusV1::default(),
    };
    status_context.refresh_state().await?;
    let operations_enabled = configuration
        .normalized()
        .pointer("/operations/enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let health = RuntimeHealth::ready(true);
    let (publisher, status_reader) = myc_status_cache(
        runtime.context().instance().clone(),
        status_context.observation(MycServicePhase::Starting, &health)?,
    )
    .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    let accepting_mutations = Arc::new(AtomicBool::new(true));
    let mut cursor_key = [0_u8; 32];
    SystemEntropy
        .fill_bytes(&mut cursor_key)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    let (health_tx, mut health_rx) = mpsc::channel(8);
    let admin_handler = Arc::new(RuntimeAdminHandler {
        state: Arc::clone(&state),
        configuration: Arc::clone(&configuration),
        providers: Arc::clone(&providers),
        status: status_reader.clone(),
        accepting_mutations: Arc::clone(&accepting_mutations),
        cursor_key,
        health: health_tx.clone(),
    });
    let admin = MycAdminServer::new(&configuration, admin_handler)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Admin))?
        .bind(&runtime)
        .await
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Admin))?;
    let operations = if operations_enabled {
        Some(
            MycOperationsServer::new(&configuration, &status_reader)
                .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Operations))?
                .bind()
                .await
                .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Operations))?,
        )
    } else {
        None
    };

    let mut shutdown_handler = RuntimeShutdownHandler {
        accepting_mutations,
        state: Arc::clone(&state),
        status: publisher,
        status_context,
        health,
    };
    let ingress_capacity = configuration_usize(&configuration, "/resource_limits/queues/ingress")?;
    let provider_capacity =
        configuration_usize(&configuration, "/resource_limits/queues/provider")?;
    let (ingress_tx, ingress_rx) = mpsc::channel(ingress_capacity);
    let mut supervisor = TaskSupervisor::new();
    spawn_admin(&mut supervisor, admin)?;
    if let Some(operations) = operations {
        spawn_operations(&mut supervisor, operations)?;
    }
    spawn_relay_ingress(
        &mut supervisor,
        ingress_adapter,
        ingress_slots,
        Arc::clone(&configuration),
        health_tx.clone(),
        ingress_tx,
    )?;
    spawn_provider_dispatch(
        &mut supervisor,
        Arc::clone(&providers),
        Arc::clone(&configuration),
        Arc::clone(&state),
        health_tx.clone(),
        ingress_rx,
        provider_capacity,
    )?;
    spawn_delivery_outbox(
        &mut supervisor,
        Arc::clone(&state),
        Arc::clone(&configuration),
        health_tx,
    )?;
    shutdown_handler
        .publish(MycServicePhase::Ready)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;

    let mut signals = ProcessSignalAdapter::new(HostSignalSource::new(signals));
    let signal_initiated = loop {
        tokio::select! {
            action = signals.next_action() => {
                match action {
                    Ok(action) if !action.forces_termination() => break true,
                    Ok(_) | Err(_) => break false,
                }
            }
            joined = supervisor.join_next() => {
                match joined {
                    Some(Ok(exit)) if exit.status() == SupervisedTaskExitStatus::OptionalFailure
                        || exit.metadata().name().as_str() == TASK_OPERATIONS_SERVER => {
                            shutdown_handler.health.operations = false;
                            shutdown_handler.publish(MycServicePhase::Degraded)
                                .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
                        }
                    Some(Ok(_)) | Some(Err(_)) | None => break false,
                }
            }
            event = health_rx.recv() => {
                let Some(event) = event else { break false; };
                if shutdown_handler.health.observe(event) {
                    if event == HealthEvent::StateChanged {
                        shutdown_handler.status_context.refresh_state().await?;
                    }
                    let phase = if shutdown_handler.health.providers
                        && shutdown_handler.health.required_relays {
                        if shutdown_handler.health.operations {
                            MycServicePhase::Ready
                        } else {
                            MycServicePhase::Degraded
                        }
                    } else {
                        MycServicePhase::Unready
                    };
                    shutdown_handler.publish(phase)
                        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
                }
            }
        }
    };
    let grace = Duration::from_millis(configuration_integer(
        &configuration,
        "/service/shutdown_grace_ms",
    )?);
    let mut shutdown = GracefulShutdown::new(grace)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    let clock = SystemMonotonicClock::new();
    let summary = if signal_initiated {
        shutdown
            .run(&clock, &mut supervisor, &mut shutdown_handler, async {
                let _ = signals.next_action().await;
            })
            .await
    } else {
        shutdown
            .run(
                &clock,
                &mut supervisor,
                &mut shutdown_handler,
                pending::<()>(),
            )
            .await
    }
    .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    if signal_initiated && summary.disposition() == ShutdownDisposition::Completed {
        Ok(MycProcessResult::Success)
    } else {
        Err(MycDaemonError::new(MycDaemonErrorKind::Runtime))
    }
}

fn spawn_admin(
    supervisor: &mut TaskSupervisor,
    server: MycBoundAdminServer,
) -> Result<(), MycDaemonError> {
    supervisor
        .spawn(task_metadata(TASK_ADMIN_SERVER, TaskClassification::Critical, ShutdownPhase::CloseSockets)?, move |cancellation| async move {
            let token = MycAdminCancellationToken::new();
            let serve_token = token.clone();
            let serve = server.serve(serve_token);
            tokio::pin!(serve);
            tokio::select! {
                result = serve.as_mut() => result.map_err(|error| HostError::with_source(HostErrorKind::AdminTransport, error)),
                () = cancellation.cancelled() => {
                    token.cancel();
                    serve.await.map_err(|error| HostError::with_source(HostErrorKind::AdminTransport, error))
                }
            }
        })
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn spawn_operations(
    supervisor: &mut TaskSupervisor,
    server: MycBoundOperationsServer,
) -> Result<(), MycDaemonError> {
    supervisor
        .spawn(task_metadata(TASK_OPERATIONS_SERVER, TaskClassification::Optional, ShutdownPhase::CloseSockets)?, move |cancellation| async move {
            let token = MycOperationsCancellationToken::new();
            let serve_token = token.clone();
            let serve = server.serve(serve_token);
            tokio::pin!(serve);
            tokio::select! {
                result = serve.as_mut() => result.map_err(|error| HostError::with_source(HostErrorKind::OperationsServe, error)),
                () = cancellation.cancelled() => {
                    token.cancel();
                    serve.await.map_err(|error| HostError::with_source(HostErrorKind::OperationsServe, error))
                }
            }
        })
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn spawn_relay_ingress(
    supervisor: &mut TaskSupervisor,
    adapter: Arc<MycNostrIngressAdapter>,
    slots: Vec<RuntimeIngressSlot>,
    configuration: Arc<MycConfigDocumentV1>,
    health: mpsc::Sender<HealthEvent>,
    ingress: mpsc::Sender<RuntimeIngressItem>,
) -> Result<(), MycDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_RELAY_INGRESS,
                TaskClassification::Critical,
                ShutdownPhase::CancelIngress,
            )?,
            move |cancellation| async move {
                run_relay_ingress(cancellation, adapter, slots, configuration, health, ingress)
                    .await
            },
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn spawn_provider_dispatch(
    supervisor: &mut TaskSupervisor,
    providers: Arc<MycProviderExecutor>,
    configuration: Arc<MycConfigDocumentV1>,
    state: Arc<MycStateHost>,
    health: mpsc::Sender<HealthEvent>,
    ingress: mpsc::Receiver<RuntimeIngressItem>,
    provider_capacity: usize,
) -> Result<(), MycDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_PROVIDER_DISPATCH,
                TaskClassification::Critical,
                ShutdownPhase::DrainOperations,
            )?,
            move |cancellation| async move {
                run_provider_dispatch(
                    cancellation,
                    configuration,
                    state,
                    providers,
                    health,
                    ingress,
                    provider_capacity,
                )
                .await
            },
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

async fn open_initial_subscriptions(
    adapter: &Arc<MycNostrIngressAdapter>,
    configuration: &MycConfigDocumentV1,
) -> Result<Vec<RuntimeIngressSlot>, MycDaemonError> {
    let initial =
        configuration_integer(configuration, "/transport/publish_retry/initial_backoff_ms")?;
    let mut slots = Vec::with_capacity(adapter.group_count());
    for index in 0..adapter.group_count() {
        let required = adapter
            .group_is_required(index)
            .ok_or_else(|| MycDaemonError::new(MycDaemonErrorKind::Relay))?;
        let duration =
            configuration_integer(configuration, "/transport/ingress/subscription_deadline_ms")?;
        let result = subscribe_ingress(Arc::clone(adapter), index, Vec::new(), duration).await;
        let state = match result {
            Ok(subscription) => RuntimeIngressSlotState::Active(subscription),
            Err(_) if required => return Err(MycDaemonError::new(MycDaemonErrorKind::Relay)),
            Err(_) => RuntimeIngressSlotState::Waiting,
        };
        slots.push(RuntimeIngressSlot {
            index,
            required,
            checkpoints: Vec::new(),
            state,
            retry_delay_ms: initial,
        });
    }
    if slots.is_empty()
        || slots
            .iter()
            .any(|slot| slot.required && !matches!(slot.state, RuntimeIngressSlotState::Active(_)))
    {
        return Err(MycDaemonError::new(MycDaemonErrorKind::Relay));
    }
    Ok(slots)
}

async fn subscribe_ingress(
    adapter: Arc<MycNostrIngressAdapter>,
    index: usize,
    checkpoints: Vec<SubscriptionCheckpoint>,
    subscription_duration_ms: u64,
) -> Result<BoxSubscription, crate::transport_nostr_adapter::MycRelayAdapterError> {
    let deadline = wall_time_millis()
        .ok()
        .and_then(|now| now.checked_add(subscription_duration_ms))
        .ok_or_else(|| {
            crate::transport_nostr_adapter::runtime_relay_adapter_error(
                crate::transport_nostr_adapter::MycRelayAdapterErrorKind::Configuration,
            )
        })?;
    adapter
        .subscribe(index, 1_000, deadline, &checkpoints)
        .await
}

async fn run_relay_ingress(
    cancellation: radroots_service_host::CancellationToken,
    adapter: Arc<MycNostrIngressAdapter>,
    mut slots: Vec<RuntimeIngressSlot>,
    configuration: Arc<MycConfigDocumentV1>,
    health: mpsc::Sender<HealthEvent>,
    ingress: mpsc::Sender<RuntimeIngressItem>,
) -> Result<(), HostError> {
    if slots.is_empty() || slots.len() > 2 {
        return Err(HostError::new(HostErrorKind::TaskFailure));
    }
    loop {
        if cancellation.is_cancelled() {
            cancel_ingress_slots(&mut slots).await;
            return Ok(());
        }
        let selected = if slots.len() == 1 {
            tokio::select! {
                () = cancellation.cancelled() => {
                    cancel_ingress_slots(&mut slots).await;
                    return Ok(());
                }
                action = poll_ingress_slot(&mut slots[0]) => (0, action),
            }
        } else {
            let (left, right) = slots.split_at_mut(1);
            tokio::select! {
                () = cancellation.cancelled() => {
                    cancel_ingress_slots(&mut slots).await;
                    return Ok(());
                }
                action = poll_ingress_slot(&mut left[0]) => (0, action),
                action = poll_ingress_slot(&mut right[0]) => (1, action),
            }
        };
        handle_ingress_action(
            selected.0,
            selected.1,
            &adapter,
            &configuration,
            &mut slots,
            &health,
            &ingress,
            &cancellation,
        )
        .await?;
    }
}

async fn poll_ingress_slot(slot: &mut RuntimeIngressSlot) -> RuntimeIngressAction {
    match &mut slot.state {
        RuntimeIngressSlotState::Active(subscription) => {
            RuntimeIngressAction::Next(subscription.next().await)
        }
        RuntimeIngressSlotState::Waiting => {
            tokio::time::sleep(Duration::from_millis(slot.retry_delay_ms)).await;
            RuntimeIngressAction::Retry
        }
        RuntimeIngressSlotState::Connecting(connecting) => {
            RuntimeIngressAction::Connected(connecting.await)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ingress_action(
    selected: usize,
    action: RuntimeIngressAction,
    adapter: &Arc<MycNostrIngressAdapter>,
    configuration: &MycConfigDocumentV1,
    slots: &mut [RuntimeIngressSlot],
    health: &mpsc::Sender<HealthEvent>,
    ingress: &mpsc::Sender<RuntimeIngressItem>,
    cancellation: &radroots_service_host::CancellationToken,
) -> Result<(), HostError> {
    let initial =
        configuration_integer(configuration, "/transport/publish_retry/initial_backoff_ms")
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let maximum =
        configuration_integer(configuration, "/transport/publish_retry/maximum_backoff_ms")
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    match action {
        RuntimeIngressAction::Next(Ok(SubscriptionNext::Event(event))) => {
            let observed = event.observed();
            let relay_id = adapter
                .relay_id(selected, observed.provenance().target())
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
            replace_checkpoint(&mut slots[selected].checkpoints, event.checkpoint().clone());
            let item = RuntimeIngressItem {
                raw_event: Box::from(observed.event().raw_json().as_bytes()),
                relay_id,
                observed_at_unix_ms: observed.provenance().observed_at_unix_ms(),
            };
            tokio::select! {
                result = ingress.send(item) => result.map_err(|_| HostError::new(HostErrorKind::TaskFailure))?,
                () = cancellation.cancelled() => return Ok(()),
            }
        }
        RuntimeIngressAction::Next(Ok(SubscriptionNext::End(end))) => {
            slots[selected].checkpoints = end.checkpoints().to_vec();
            slots[selected].state = RuntimeIngressSlotState::Waiting;
            send_required_relay_health(required_relays_ready(slots), health, cancellation).await?;
        }
        RuntimeIngressAction::Next(Err(_)) => {
            slots[selected].state = RuntimeIngressSlotState::Waiting;
            send_required_relay_health(required_relays_ready(slots), health, cancellation).await?;
        }
        RuntimeIngressAction::Retry => {
            let adapter = Arc::clone(adapter);
            let index = slots[selected].index;
            let checkpoints = slots[selected].checkpoints.clone();
            let duration =
                configuration_integer(configuration, "/transport/ingress/subscription_deadline_ms")
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
            slots[selected].state = RuntimeIngressSlotState::Connecting(Box::pin(async move {
                subscribe_ingress(adapter, index, checkpoints, duration).await
            }));
        }
        RuntimeIngressAction::Connected(Ok(subscription)) => {
            slots[selected].state = RuntimeIngressSlotState::Active(subscription);
            slots[selected].retry_delay_ms = initial;
            send_required_relay_health(required_relays_ready(slots), health, cancellation).await?;
        }
        RuntimeIngressAction::Connected(Err(_)) => {
            slots[selected].state = RuntimeIngressSlotState::Waiting;
            slots[selected].retry_delay_ms = slots[selected]
                .retry_delay_ms
                .saturating_mul(2)
                .min(maximum);
            send_required_relay_health(required_relays_ready(slots), health, cancellation).await?;
        }
    }
    Ok(())
}

fn replace_checkpoint(
    checkpoints: &mut Vec<SubscriptionCheckpoint>,
    checkpoint: SubscriptionCheckpoint,
) {
    if let Some(existing) = checkpoints
        .iter_mut()
        .find(|existing| existing.target() == checkpoint.target())
    {
        *existing = checkpoint;
    } else {
        checkpoints.push(checkpoint);
    }
}

fn required_relays_ready(slots: &[RuntimeIngressSlot]) -> bool {
    slots
        .iter()
        .all(|slot| !slot.required || matches!(slot.state, RuntimeIngressSlotState::Active(_)))
}

async fn send_required_relay_health(
    ready: bool,
    health: &mpsc::Sender<HealthEvent>,
    cancellation: &radroots_service_host::CancellationToken,
) -> Result<(), HostError> {
    tokio::select! {
        result = health.send(HealthEvent::RequiredRelays(ready)) => {
            result.map_err(|_| HostError::new(HostErrorKind::TaskFailure))
        }
        () = cancellation.cancelled() => Ok(()),
    }
}

async fn cancel_ingress_slots(slots: &mut [RuntimeIngressSlot]) {
    for slot in slots {
        if let RuntimeIngressSlotState::Active(subscription) = &mut slot.state {
            let _ = subscription.cancel().await;
        }
    }
}

async fn run_provider_dispatch(
    cancellation: radroots_service_host::CancellationToken,
    configuration: Arc<MycConfigDocumentV1>,
    state: Arc<MycStateHost>,
    providers: Arc<MycProviderExecutor>,
    health: mpsc::Sender<HealthEvent>,
    mut ingress: mpsc::Receiver<RuntimeIngressItem>,
    provider_capacity: usize,
) -> Result<(), HostError> {
    if provider_capacity == 0 {
        return Err(HostError::new(HostErrorKind::TaskFailure));
    }
    let coordinator = MycRuntimeNip46Coordinator::new(configuration.clone(), state, providers)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let task_cancellation = MycTaskCancellation::from_host(cancellation.clone());
    let initial = configuration_integer(
        &configuration,
        "/transport/publish_retry/initial_backoff_ms",
    )
    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let maximum = configuration_integer(
        &configuration,
        "/transport/publish_retry/maximum_backoff_ms",
    )
    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let mut queue = VecDeque::with_capacity(provider_capacity);
    loop {
        if queue.is_empty() {
            tokio::select! {
                item = ingress.recv() => match item {
                    Some(item) => queue.push_back(item),
                    None => return Err(HostError::new(HostErrorKind::TaskFailure)),
                },
                () = cancellation.cancelled() => return Ok(()),
            }
        }
        while queue.len() < provider_capacity {
            match ingress.try_recv() {
                Ok(item) => queue.push_back(item),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) if queue.is_empty() => {
                    return Err(HostError::new(HostErrorKind::TaskFailure));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        let item = queue.pop_front().expect("provider queue is nonempty");
        let admission_evidence = runtime_nip46_admission_evidence()
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        let mut retry = initial;
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            match coordinator
                .process(
                    &item.raw_event,
                    item.relay_id.clone(),
                    item.observed_at_unix_ms,
                    admission_evidence,
                    &task_cancellation,
                )
                .await
            {
                Ok(_) => {
                    let _ = health.try_send(HealthEvent::StateChanged);
                    send_provider_health(&health, true, &cancellation).await?;
                    break;
                }
                Err(error) if error.kind() == MycNip46DispatchErrorKind::Provider => {
                    send_provider_health(&health, false, &cancellation).await?;
                    tokio::select! {
                        () = cancellation.cancelled() => return Ok(()),
                        () = tokio::time::sleep(Duration::from_millis(retry)) => {}
                    }
                    retry = retry.saturating_mul(2).min(maximum);
                }
                Err(error) => {
                    return Err(HostError::with_source(HostErrorKind::TaskFailure, error));
                }
            }
        }
    }
}

fn runtime_nip46_admission_evidence() -> Result<MycRuntimeNip46AdmissionEvidence, MycDaemonError> {
    let mut request_nonce = [0_u8; 32];
    SystemEntropy
        .fill_bytes(&mut request_nonce)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?;
    MycRuntimeNip46AdmissionEvidence::new(request_nonce, wall_time_millis()?)
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

async fn send_provider_health(
    health: &mpsc::Sender<HealthEvent>,
    ready: bool,
    cancellation: &radroots_service_host::CancellationToken,
) -> Result<(), HostError> {
    tokio::select! {
        result = health.send(HealthEvent::Providers(ready)) => {
            result.map_err(|_| HostError::new(HostErrorKind::TaskFailure))
        }
        () = cancellation.cancelled() => Ok(()),
    }
}

fn spawn_delivery_outbox(
    supervisor: &mut TaskSupervisor,
    state: Arc<MycStateHost>,
    configuration: Arc<MycConfigDocumentV1>,
    health: mpsc::Sender<HealthEvent>,
) -> Result<(), MycDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_DELIVERY_OUTBOX,
                TaskClassification::Critical,
                ShutdownPhase::PersistRecoverableWork,
            )?,
            move |cancellation| async move {
                let worker = MycDeliveryWorker::from_configuration(&configuration)
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
                let task_cancellation = MycTaskCancellation::from_host(cancellation.clone());
                let idle = Duration::from_millis(
                    configuration_integer(
                        &configuration,
                        "/transport/publish_retry/initial_backoff_ms",
                    )
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?,
                );
                loop {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let now = wall_time_millis().map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?;
                    let now = MycDeliveryTimeUnixMs::new(now).map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?;
                    let next = state
                        .repository()
                        .next_ready_delivery_target(now)
                        .await
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                    let Some((job, relay)) = next else {
                        tokio::select! {
                            () = cancellation.cancelled() => return Ok(()),
                            () = tokio::time::sleep(idle) => continue,
                        }
                    };
                    let mut nonce = [0_u8; 32];
                    SystemEntropy.fill_bytes(&mut nonce).map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?;
                    let mut retry_entropy = [0_u8; 8];
                    SystemEntropy
                        .fill_bytes(&mut retry_entropy)
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                    let evidence = MycDeliveryExecutionEvidence {
                        claimed_at: now,
                        submitted_at: now,
                        observed_at: now,
                        retry_entropy,
                    };
                    worker
                        .run_one(
                            &state.repository(),
                            job,
                            &relay,
                            MycDeliveryAttemptNonce::from_injected_entropy(nonce),
                            evidence,
                            &task_cancellation,
                        )
                        .await
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                    let _ = health.try_send(HealthEvent::StateChanged);
                }
            },
        )
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn task_metadata(
    name: &'static str,
    classification: TaskClassification,
    phase: ShutdownPhase,
) -> Result<TaskMetadata, MycDaemonError> {
    TaskMetadata::new(
        TaskName::new(name).map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?,
        classification,
        Some(phase),
    )
    .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn runtime_build_info() -> Result<MycStatusBuildInfoV1, MycDaemonError> {
    let service_revision = option_env!("RADROOTS_SERVICE_REVISION");
    let lib_revision = option_env!("RADROOTS_LIB_REVISION");
    let rust_version = option_env!("RADROOTS_RUST_VERSION");
    let target = option_env!("RADROOTS_BUILD_TARGET");
    let mode = if service_revision.is_some()
        && lib_revision.is_some()
        && rust_version.is_some()
        && target.is_some()
    {
        MycStatusBuildMode::Release
    } else {
        MycStatusBuildMode::Development
    };
    MycStatusBuildInfoV1::new(
        mode,
        Some(env!("CARGO_PKG_VERSION")),
        service_revision,
        lib_revision,
        rust_version,
        target,
        Some("service-host"),
    )
    .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn wall_time_millis() -> Result<u64, MycDaemonError> {
    SystemWallClock
        .now_utc()
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))?
        .get()
        .checked_mul(1_000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn configuration_integer(
    configuration: &MycConfigDocumentV1,
    pointer: &str,
) -> Result<u64, MycDaemonError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn configuration_usize(
    configuration: &MycConfigDocumentV1,
    pointer: &str,
) -> Result<usize, MycDaemonError> {
    configuration_integer(configuration, pointer)?
        .try_into()
        .map_err(|_| MycDaemonError::new(MycDaemonErrorKind::Runtime))
}

fn response(
    route: MycAdminRoute,
    value: Value,
) -> Result<MycAdminResponseDocument, MycAdminHandlerError> {
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))?;
    MycAdminResponseDocument::from_canonical_bytes(route, &bytes)
        .map_err(|_| handler_error(MycAdminHandlerErrorKind::Internal))
}

const fn handler_error(kind: MycAdminHandlerErrorKind) -> MycAdminHandlerError {
    MycAdminHandlerError::new(kind)
}

const fn map_admin_journal_error(error: crate::MycAdminOperationError) -> MycAdminHandlerError {
    match error.kind() {
        MycAdminOperationErrorKind::OperationConflict => {
            handler_error(MycAdminHandlerErrorKind::OperationIdConflict)
        }
        MycAdminOperationErrorKind::OperationOutcomeUnknown
        | MycAdminOperationErrorKind::CommitOutcomeUnknown => {
            handler_error(MycAdminHandlerErrorKind::Conflict)
        }
        MycAdminOperationErrorKind::ResourceExhausted => {
            handler_error(MycAdminHandlerErrorKind::Unavailable)
        }
        MycAdminOperationErrorKind::InvalidMode
        | MycAdminOperationErrorKind::InvalidInput
        | MycAdminOperationErrorKind::Binding
        | MycAdminOperationErrorKind::Transaction => {
            handler_error(MycAdminHandlerErrorKind::Internal)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;

    #[test]
    fn exact_task_inventory_and_shutdown_phases_are_frozen() {
        let expected = [
            (
                TASK_ADMIN_SERVER,
                TaskClassification::Critical,
                ShutdownPhase::CloseSockets,
            ),
            (
                TASK_OPERATIONS_SERVER,
                TaskClassification::Optional,
                ShutdownPhase::CloseSockets,
            ),
            (
                TASK_RELAY_INGRESS,
                TaskClassification::Critical,
                ShutdownPhase::CancelIngress,
            ),
            (
                TASK_PROVIDER_DISPATCH,
                TaskClassification::Critical,
                ShutdownPhase::DrainOperations,
            ),
            (
                TASK_DELIVERY_OUTBOX,
                TaskClassification::Critical,
                ShutdownPhase::PersistRecoverableWork,
            ),
        ];
        for (name, classification, phase) in expected {
            let metadata = task_metadata(name, classification, phase).expect("task metadata");
            assert_eq!(metadata.name().as_str(), name);
            assert_eq!(metadata.classification(), classification);
            assert_eq!(metadata.shutdown_phase(), Some(phase));
        }
    }

    #[test]
    fn runtime_errors_are_safe_and_have_stable_exit_classes() {
        for (kind, result) in [
            (
                MycDaemonErrorKind::State,
                MycProcessResult::StateOrIdentityUnavailable,
            ),
            (
                MycDaemonErrorKind::Provider,
                MycProcessResult::ServiceOrDependencyUnavailable,
            ),
            (
                MycDaemonErrorKind::Relay,
                MycProcessResult::ServiceOrDependencyUnavailable,
            ),
            (
                MycDaemonErrorKind::Admin,
                MycProcessResult::ServiceOrDependencyUnavailable,
            ),
            (
                MycDaemonErrorKind::Operations,
                MycProcessResult::ServiceOrDependencyUnavailable,
            ),
            (
                MycDaemonErrorKind::Runtime,
                MycProcessResult::UnexpectedInternal,
            ),
        ] {
            let error = MycDaemonError::new(kind);
            assert_eq!(error.process_result(), result);
            assert_eq!(error.to_string(), "Myc daemon failed");
            assert!(Error::source(&error).is_none());
        }
    }

    #[test]
    fn backoff_inputs_are_bounded_by_the_admitted_configuration() {
        let configuration = crate::parse_myc_config_v1(
            include_bytes!("../contracts/services_hardening/config.v1.example.toml"),
            crate::MycConfigProfile::Production,
        )
        .expect("configuration");
        assert_eq!(
            configuration_integer(
                &configuration,
                "/transport/publish_retry/initial_backoff_ms"
            )
            .expect("initial"),
            250
        );
        assert_eq!(
            configuration_integer(
                &configuration,
                "/transport/publish_retry/maximum_backoff_ms"
            )
            .expect("maximum"),
            30_000
        );
    }

    #[test]
    fn admin_cursors_are_authenticated_query_bound_and_round_trip_exactly() {
        let key = [0x42; 32];
        let snapshot = MycConnectionTimeUnixMs::new(10_000).expect("snapshot");
        let before = MycConnectionTimeUnixMs::new(9_000).expect("before");
        let id = MycConnectionId::from_bytes([0x24; 32]);
        let encoded = encode_connection_cursor(
            snapshot,
            before,
            id,
            Some(MycConnectionStatus::Active),
            &key,
        );
        let decoded = decode_connection_cursor(&encoded, Some(MycConnectionStatus::Active), &key)
            .expect("connection cursor");
        assert_eq!(decoded.snapshot, snapshot);
        assert_eq!(decoded.before, before);
        assert_eq!(decoded.id, id);
        assert!(
            decode_connection_cursor(&encoded, Some(MycConnectionStatus::Denied), &key).is_err()
        );

        let query = audit_query_digest(
            Some(1_000),
            Some(9_999),
            Some(MycAuditKind::ChallengeAuthorization),
            Some(MycAuditOutcome::Succeeded),
        );
        let encoded = encode_audit_cursor(17, 11, query, &key);
        let decoded = decode_audit_cursor(&encoded, query, &key).expect("audit cursor");
        assert_eq!(decoded.snapshot, 17);
        assert_eq!(decoded.before, 11);
        let other_query = audit_query_digest(None, None, None, None);
        assert!(decode_audit_cursor(&encoded, other_query, &key).is_err());

        let mut tampered = URL_SAFE_NO_PAD.decode(&encoded).expect("cursor bytes");
        tampered[10] ^= 1;
        assert!(decode_audit_cursor(&URL_SAFE_NO_PAD.encode(tampered), query, &key).is_err());
    }

    #[test]
    fn admin_time_and_identity_helpers_are_bounded_and_domain_separated() {
        assert_eq!(seconds_as_millis(1, false).expect("start"), 1_000);
        assert_eq!(seconds_as_millis(1, true).expect("end"), 1_999);
        assert!(seconds_as_millis(u64::MAX, false).is_err());
        let value = "caller-01";
        let operation = admin_identity(b"operation\0", value);
        let correlation = admin_identity(b"correlation\0", value);
        assert_ne!(operation, correlation);
        assert!(!format!("{:?}", MycAuditCorrelationId::new(operation)).contains(value));
    }

    #[test]
    fn admin_metric_keys_are_closed_and_bounded() {
        for value in [
            "radroots_myc_service_ready",
            "radroots_myc_service_phase_starting",
            "radroots_myc_service_phase_degraded",
        ] {
            assert!(safe_metric_key(value));
        }
        for value in ["", "Uppercase", "hyphen-key", "path/key", "secret:key"] {
            assert!(!safe_metric_key(value));
        }
        assert!(safe_metric_key(&"x".repeat(64)));
        assert!(!safe_metric_key(&"x".repeat(65)));
    }

    #[tokio::test]
    async fn runtime_status_queries_real_connection_and_outbox_state() {
        let directory = tempfile::tempdir().expect("temporary root");
        let runtime = crate::nip46_wave_080_a::runtime(directory.path());
        fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
        fs::set_permissions(
            runtime.context().paths().state(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("state mode");
        let metadata = crate::nip46_wave_080_a::metadata(&runtime);
        let configuration = crate::nip46_wave_080_a::configuration();
        let (applied_at, build) = crate::nip46_wave_080_a::migration_evidence();
        crate::initialize_myc_state(&runtime, &metadata, applied_at, &build)
            .await
            .expect("initialize");
        let host = crate::open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
            .await
            .expect("host");
        let repository = host.repository();
        let empty = repository
            .read_runtime_connection_counts()
            .await
            .expect("empty connection counts");
        assert_eq!(empty, MycConnectionCountsV1::default());
        let pending = crate::nip46_wave_080_a::admit_connect(
            &repository,
            &configuration,
            20,
            "runtime-status-connect",
            crate::nip46_wave_080_a::OBSERVED_AT_SECONDS,
            crate::nip46_wave_080_a::RECEIVED_AT_MS,
            21,
            crate::nip46_wave_080_a::RECEIVED_AT_MS + 1,
        )
        .await;
        assert!(pending.record().is_some());
        let counts = repository
            .read_runtime_connection_counts()
            .await
            .expect("connection counts");
        assert_eq!(counts.pending(), 1);
        assert_eq!(counts.active(), 0);
        assert_eq!(counts.denied(), 0);
        assert_eq!(counts.expired(), 0);
        assert_eq!(
            repository
                .read_runtime_outbox_status()
                .await
                .expect("empty outbox"),
            MycOutboxStatusV1::default()
        );
        host.close().await.expect("close");

        let inspection = crate::open_myc_state_inspection(&runtime, &metadata)
            .await
            .expect("inspection");
        let repository = inspection.repository();
        assert_eq!(
            repository
                .read_runtime_outbox_status()
                .await
                .expect("inspection outbox"),
            MycOutboxStatusV1::default()
        );
        assert_eq!(
            repository
                .read_runtime_connection_counts()
                .await
                .expect("inspection connection counts")
                .pending(),
            1
        );
        inspection
            .inspect_integrity(
                radroots_service_sqlite::IntegrityCheckedAtUnixMs::new(1).expect("integrity time"),
            )
            .await
            .expect("inspection integrity");
        inspection.close().await.expect("inspection close");
    }
}
