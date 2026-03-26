pub mod server;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use radroots_nostr::prelude::{RadrootsNostrRelayStatus, RadrootsNostrRelayUrl};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerPublishWorkflowState,
    RadrootsNostrSignerRequestDecision,
};
use radroots_sql_core::{SqlExecutor, SqliteExecutor};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome};
use crate::config::{MycRuntimeAuditBackend, MycSignerStateBackend, MycTransportDeliveryPolicy};
use crate::custody::{MycActiveIdentity, MycIdentityStatusOutput};
use crate::discovery::MycDiscoveryContext;
use crate::error::MycError;
use crate::outbox::{MycDeliveryOutboxRecord, MycDeliveryOutboxStatus, now_unix_secs};
use crate::transport::MycTransportSnapshot;

const MYC_RELAY_PROBE_CONCURRENCY_LIMIT: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycRuntimeStatus {
    Healthy,
    Degraded,
    Unready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycRelayProbeAvailability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRelayProbe {
    pub relay_url: String,
    pub availability: MycRelayProbeAvailability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_status: Option<String>,
    pub connection_attempts: usize,
    pub successful_connections: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub queue_depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycTransportStatusOutput {
    pub enabled: bool,
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub configured_relay_count: usize,
    pub required_available_relays: usize,
    pub available_relay_count: usize,
    pub unavailable_relay_count: usize,
    pub delivery_policy: MycTransportDeliveryPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_quorum: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub relay_probes: Vec<MycRelayProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryRelayGroupStatusOutput {
    pub configured_relay_count: usize,
    pub available_relay_count: usize,
    pub unavailable_relay_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub relay_probes: Vec<MycRelayProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryStatusOutput {
    pub enabled: bool,
    pub status: MycRuntimeStatus,
    pub public_relays: MycDiscoveryRelayGroupStatusOutput,
    pub publish_relays: MycDiscoveryRelayGroupStatusOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycCustodyStatusOutput {
    pub signer: MycIdentityStatusOutput,
    pub user: MycIdentityStatusOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_app: Option<MycIdentityStatusOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycPersistenceStatusOutput {
    pub signer_state: MycSignerStatePersistenceStatusOutput,
    pub runtime_audit: MycRuntimeAuditPersistenceStatusOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDeliveryRecoveryStatusOutput {
    pub recorded_at_unix: u64,
    pub outcome: MycOperationAuditOutcome,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDeliveryOutboxStatusOutput {
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub path: PathBuf,
    pub exists: bool,
    pub total_job_count: usize,
    pub queued_job_count: usize,
    pub published_pending_finalize_job_count: usize,
    pub finalized_job_count: usize,
    pub failed_job_count: usize,
    pub unfinished_job_count: usize,
    pub critical_unfinished_job_count: usize,
    pub blocked_job_count: usize,
    pub critical_blocked_job_count: usize,
    pub stuck_after_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_unfinished_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_blocked_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_recovery: Option<MycDeliveryRecoveryStatusOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycSignerStatePersistenceStatusOutput {
    pub backend: MycSignerStateBackend,
    pub path: PathBuf,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite_schema: Option<MycSqliteSchemaStatusOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRuntimeAuditPersistenceStatusOutput {
    pub backend: MycRuntimeAuditBackend,
    pub path: PathBuf,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite_schema: Option<MycSqliteSchemaStatusOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycSqliteSchemaStatusOutput {
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_migration_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_migration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycStatusFullOutput {
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub reasons: Vec<String>,
    pub startup: crate::app::MycStartupSnapshot,
    pub custody: MycCustodyStatusOutput,
    pub persistence: MycPersistenceStatusOutput,
    pub delivery_outbox: MycDeliveryOutboxStatusOutput,
    pub transport: MycTransportStatusOutput,
    pub discovery: MycDiscoveryStatusOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycStatusSummaryOutput {
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub reasons: Vec<String>,
    pub instance_name: String,
    pub custody: MycCustodyStatusOutput,
    pub persistence: MycPersistenceStatusOutput,
    pub delivery_outbox: MycDeliveryOutboxStatusOutput,
    pub transport: MycTransportStatusOutput,
    pub discovery: MycDiscoveryStatusOutput,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MycAuditDecisionCounts {
    pub allowed: usize,
    pub denied: usize,
    pub challenged: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MycOperationOutcomeCounts {
    pub succeeded: usize,
    pub rejected: usize,
    pub restored: usize,
    pub unavailable: usize,
    pub missing: usize,
    pub matched: usize,
    pub drifted: usize,
    pub conflicted: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycMetricsSnapshot {
    pub signer_request_total: usize,
    pub signer_request_decisions: MycAuditDecisionCounts,
    pub runtime_operation_total: usize,
    pub runtime_operation_outcomes: MycOperationOutcomeCounts,
    pub runtime_operation_by_kind: BTreeMap<String, MycOperationOutcomeCounts>,
    pub runtime_aggregate_publish_rejection_count: usize,
    pub runtime_repair_success_count: usize,
    pub runtime_repair_rejection_count: usize,
    pub runtime_unavailable_count: usize,
    pub runtime_replay_restore_count: usize,
    pub delivery_recovery_success_count: usize,
    pub delivery_recovery_rejection_count: usize,
    pub delivery_outbox_total: usize,
    pub delivery_outbox_queued_count: usize,
    pub delivery_outbox_published_pending_finalize_count: usize,
    pub delivery_outbox_failed_count: usize,
    pub delivery_outbox_finalized_count: usize,
    pub delivery_outbox_unfinished_count: usize,
    pub delivery_outbox_critical_unfinished_count: usize,
    pub delivery_outbox_blocked_count: usize,
    pub delivery_outbox_critical_blocked_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycTransportStatusEvaluation {
    output: MycTransportStatusOutput,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycCustodyStatusEvaluation {
    output: MycCustodyStatusOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycPersistenceStatusEvaluation {
    output: MycPersistenceStatusOutput,
    reasons: Vec<String>,
    status: Option<MycRuntimeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycDeliveryOutboxStatusEvaluation {
    output: MycDeliveryOutboxStatusOutput,
    reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MycSqliteAppliedCountRow {
    applied_count: u64,
}

#[derive(Debug, Deserialize)]
struct MycSqliteNamedRow {
    name: String,
}

#[derive(Debug, Deserialize)]
struct MycSqliteJournalModeRow {
    journal_mode: String,
}

#[derive(Debug, Deserialize)]
struct MycSqliteStoreVersionRow {
    store_version: u64,
}

pub async fn collect_status_full(runtime: &MycRuntime) -> Result<MycStatusFullOutput, MycError> {
    let snapshot = runtime.snapshot();
    let custody = collect_custody_status(runtime)?;
    let persistence = collect_persistence_status(runtime);
    let delivery_outbox = collect_delivery_outbox_status(runtime)?;
    let transport = collect_transport_status(runtime).await?;
    let discovery = collect_discovery_status(runtime).await?;
    let mut status = combine_runtime_status(
        transport.output.status,
        if discovery.output.enabled {
            Some(discovery.output.status)
        } else {
            None
        },
    );
    let mut reasons = transport.reasons;
    reasons.extend(discovery.reasons);
    status = worse_runtime_status(status, delivery_outbox.output.status);
    reasons.extend(delivery_outbox.reasons.clone());
    if let Some(persistence_status) = persistence.status {
        status = worse_runtime_status(status, persistence_status);
    }
    reasons.extend(persistence.reasons.clone());
    if custody
        .output
        .discovery_app
        .as_ref()
        .is_some_and(|status_output| !status_output.resolved)
        && status != MycRuntimeStatus::Unready
    {
        status = MycRuntimeStatus::Degraded;
        reasons.push("discovery app identity could not be resolved".to_owned());
    }
    let ready = transport.output.ready && delivery_outbox.output.ready;
    Ok(MycStatusFullOutput {
        status,
        ready,
        reasons,
        startup: snapshot,
        custody: custody.output,
        persistence: persistence.output,
        delivery_outbox: delivery_outbox.output,
        transport: transport.output,
        discovery: discovery.output,
    })
}

pub async fn collect_status_summary(
    runtime: &MycRuntime,
) -> Result<MycStatusSummaryOutput, MycError> {
    let full = collect_status_full(runtime).await?;
    Ok(MycStatusSummaryOutput {
        status: full.status,
        ready: full.ready,
        reasons: full.reasons,
        instance_name: full.startup.instance_name,
        custody: full.custody,
        persistence: full.persistence,
        delivery_outbox: full.delivery_outbox,
        transport: MycTransportStatusOutput {
            relay_probes: Vec::new(),
            ..full.transport
        },
        discovery: MycDiscoveryStatusOutput {
            enabled: full.discovery.enabled,
            status: full.discovery.status,
            public_relays: MycDiscoveryRelayGroupStatusOutput {
                relay_probes: Vec::new(),
                ..full.discovery.public_relays
            },
            publish_relays: MycDiscoveryRelayGroupStatusOutput {
                relay_probes: Vec::new(),
                ..full.discovery.publish_relays
            },
        },
    })
}

fn collect_custody_status(runtime: &MycRuntime) -> Result<MycCustodyStatusEvaluation, MycError> {
    let signer = runtime
        .signer_context()
        .signer_identity_provider()
        .resolved_status(runtime.signer_identity());
    let user = runtime
        .signer_context()
        .user_identity_provider()
        .resolved_status(runtime.user_identity());
    let discovery_app = if runtime.config().discovery.enabled {
        match runtime.config().discovery.app_identity_source() {
            Some(source) => Some(
                crate::custody::MycIdentityProvider::from_source("discovery app", source)?
                    .probe_status(),
            ),
            None => Some(
                runtime
                    .signer_context()
                    .signer_identity_provider()
                    .resolved_status(runtime.signer_identity())
                    .with_inherited_from("signer"),
            ),
        }
    } else {
        None
    };

    Ok(MycCustodyStatusEvaluation {
        output: MycCustodyStatusOutput {
            signer,
            user,
            discovery_app,
        },
    })
}

fn collect_persistence_status(runtime: &MycRuntime) -> MycPersistenceStatusEvaluation {
    let signer_state_backend = runtime.config().persistence.signer_state_backend;
    let runtime_audit_backend = runtime.config().persistence.runtime_audit_backend;
    let signer_state = MycSignerStatePersistenceStatusOutput {
        backend: signer_state_backend,
        path: runtime.paths().signer_state_path.clone(),
        exists: runtime.paths().signer_state_path.exists(),
        sqlite_schema: match signer_state_backend {
            MycSignerStateBackend::JsonFile => None,
            MycSignerStateBackend::Sqlite => Some(inspect_signer_state_sqlite_schema(
                runtime.paths().signer_state_path.as_path(),
            )),
        },
    };
    let runtime_audit = MycRuntimeAuditPersistenceStatusOutput {
        backend: runtime_audit_backend,
        path: runtime.paths().runtime_audit_path.clone(),
        exists: runtime.paths().runtime_audit_path.exists(),
        sqlite_schema: match runtime_audit_backend {
            MycRuntimeAuditBackend::JsonlFile => None,
            MycRuntimeAuditBackend::Sqlite => Some(inspect_runtime_audit_sqlite_schema(
                runtime.paths().runtime_audit_path.as_path(),
            )),
        },
    };

    let mut reasons = Vec::new();
    if signer_state
        .sqlite_schema
        .as_ref()
        .is_some_and(|schema| !schema.ready)
    {
        reasons.push(format!(
            "signer-state sqlite schema at {} is not ready",
            signer_state.path.display()
        ));
    }
    if runtime_audit
        .sqlite_schema
        .as_ref()
        .is_some_and(|schema| !schema.ready)
    {
        reasons.push(format!(
            "runtime-audit sqlite schema at {} is not ready",
            runtime_audit.path.display()
        ));
    }
    let status = if reasons.is_empty() {
        None
    } else {
        Some(MycRuntimeStatus::Degraded)
    };

    MycPersistenceStatusEvaluation {
        output: MycPersistenceStatusOutput {
            signer_state,
            runtime_audit,
        },
        reasons,
        status,
    }
}

pub fn collect_metrics(runtime: &MycRuntime) -> Result<MycMetricsSnapshot, MycError> {
    let manager = runtime.signer_manager()?;
    let signer_request_audit = manager.list_audit_records()?;
    let runtime_operation_audit = runtime.operation_audit_store().list_all()?;
    let outbox_status = collect_delivery_outbox_status(runtime)?;

    let mut signer_request_decisions = MycAuditDecisionCounts::default();
    for record in &signer_request_audit {
        match record.decision {
            RadrootsNostrSignerRequestDecision::Allowed => signer_request_decisions.allowed += 1,
            RadrootsNostrSignerRequestDecision::Denied => signer_request_decisions.denied += 1,
            RadrootsNostrSignerRequestDecision::Challenged => {
                signer_request_decisions.challenged += 1;
            }
        }
    }

    let mut runtime_operation_outcomes = MycOperationOutcomeCounts::default();
    let mut runtime_operation_by_kind = BTreeMap::new();
    let mut runtime_aggregate_publish_rejection_count = 0;
    let mut runtime_repair_success_count = 0;
    let mut runtime_repair_rejection_count = 0;
    let mut runtime_unavailable_count = 0;
    let mut runtime_replay_restore_count = 0;
    let mut delivery_recovery_success_count = 0;
    let mut delivery_recovery_rejection_count = 0;
    for record in &runtime_operation_audit {
        increment_outcome_counts(&mut runtime_operation_outcomes, record.outcome);
        increment_outcome_counts(
            runtime_operation_by_kind
                .entry(operation_kind_label(record.operation))
                .or_default(),
            record.outcome,
        );
        if is_aggregate_publish_operation(record.operation)
            && record.outcome == MycOperationAuditOutcome::Rejected
        {
            runtime_aggregate_publish_rejection_count += 1;
        }
        if record.operation == MycOperationAuditKind::DiscoveryHandlerRepair {
            match record.outcome {
                MycOperationAuditOutcome::Succeeded => runtime_repair_success_count += 1,
                MycOperationAuditOutcome::Rejected => runtime_repair_rejection_count += 1,
                _ => {}
            }
        }
        if record.outcome == MycOperationAuditOutcome::Unavailable {
            runtime_unavailable_count += 1;
        }
        if record.operation == MycOperationAuditKind::AuthReplayRestore
            && record.outcome == MycOperationAuditOutcome::Restored
        {
            runtime_replay_restore_count += 1;
        }
        if record.operation == MycOperationAuditKind::DeliveryRecovery {
            match record.outcome {
                MycOperationAuditOutcome::Succeeded => delivery_recovery_success_count += 1,
                MycOperationAuditOutcome::Rejected => delivery_recovery_rejection_count += 1,
                _ => {}
            }
        }
    }

    Ok(MycMetricsSnapshot {
        signer_request_total: signer_request_audit.len(),
        signer_request_decisions,
        runtime_operation_total: runtime_operation_audit.len(),
        runtime_operation_outcomes,
        runtime_operation_by_kind,
        runtime_aggregate_publish_rejection_count,
        runtime_repair_success_count,
        runtime_repair_rejection_count,
        runtime_unavailable_count,
        runtime_replay_restore_count,
        delivery_recovery_success_count,
        delivery_recovery_rejection_count,
        delivery_outbox_total: outbox_status.output.total_job_count,
        delivery_outbox_queued_count: outbox_status.output.queued_job_count,
        delivery_outbox_published_pending_finalize_count: outbox_status
            .output
            .published_pending_finalize_job_count,
        delivery_outbox_failed_count: outbox_status.output.failed_job_count,
        delivery_outbox_finalized_count: outbox_status.output.finalized_job_count,
        delivery_outbox_unfinished_count: outbox_status.output.unfinished_job_count,
        delivery_outbox_critical_unfinished_count: outbox_status
            .output
            .critical_unfinished_job_count,
        delivery_outbox_blocked_count: outbox_status.output.blocked_job_count,
        delivery_outbox_critical_blocked_count: outbox_status.output.critical_blocked_job_count,
    })
}

pub fn render_metrics_text(snapshot: &MycMetricsSnapshot) -> String {
    let mut lines = Vec::new();
    push_counter(
        &mut lines,
        "myc_signer_request_total",
        snapshot.signer_request_total,
    );
    push_labeled_counter(
        &mut lines,
        "myc_signer_request_decision_total",
        "decision",
        "allowed",
        snapshot.signer_request_decisions.allowed,
    );
    push_labeled_counter(
        &mut lines,
        "myc_signer_request_decision_total",
        "decision",
        "denied",
        snapshot.signer_request_decisions.denied,
    );
    push_labeled_counter(
        &mut lines,
        "myc_signer_request_decision_total",
        "decision",
        "challenged",
        snapshot.signer_request_decisions.challenged,
    );

    push_counter(
        &mut lines,
        "myc_runtime_operation_total",
        snapshot.runtime_operation_total,
    );
    push_outcome_counters(
        &mut lines,
        "myc_runtime_operation_outcome_total",
        &snapshot.runtime_operation_outcomes,
    );
    for (kind, counts) in &snapshot.runtime_operation_by_kind {
        push_outcome_counters_with_extra_label(
            &mut lines,
            "myc_runtime_operation_kind_total",
            "kind",
            kind,
            counts,
        );
    }
    push_counter(
        &mut lines,
        "myc_runtime_aggregate_publish_rejection_total",
        snapshot.runtime_aggregate_publish_rejection_count,
    );
    push_counter(
        &mut lines,
        "myc_runtime_repair_success_total",
        snapshot.runtime_repair_success_count,
    );
    push_counter(
        &mut lines,
        "myc_runtime_repair_rejection_total",
        snapshot.runtime_repair_rejection_count,
    );
    push_counter(
        &mut lines,
        "myc_runtime_unavailable_total",
        snapshot.runtime_unavailable_count,
    );
    push_counter(
        &mut lines,
        "myc_runtime_replay_restore_total",
        snapshot.runtime_replay_restore_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_recovery_success_total",
        snapshot.delivery_recovery_success_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_recovery_rejection_total",
        snapshot.delivery_recovery_rejection_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_total",
        snapshot.delivery_outbox_total,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_queued_total",
        snapshot.delivery_outbox_queued_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_published_pending_finalize_total",
        snapshot.delivery_outbox_published_pending_finalize_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_failed_total",
        snapshot.delivery_outbox_failed_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_finalized_total",
        snapshot.delivery_outbox_finalized_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_unfinished_total",
        snapshot.delivery_outbox_unfinished_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_critical_unfinished_total",
        snapshot.delivery_outbox_critical_unfinished_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_blocked_total",
        snapshot.delivery_outbox_blocked_count,
    );
    push_counter(
        &mut lines,
        "myc_delivery_outbox_critical_blocked_total",
        snapshot.delivery_outbox_critical_blocked_count,
    );

    lines.join("\n")
}

pub fn increment_outcome_counts(
    counts: &mut MycOperationOutcomeCounts,
    outcome: MycOperationAuditOutcome,
) {
    match outcome {
        MycOperationAuditOutcome::Succeeded => counts.succeeded += 1,
        MycOperationAuditOutcome::Rejected => counts.rejected += 1,
        MycOperationAuditOutcome::Restored => counts.restored += 1,
        MycOperationAuditOutcome::Unavailable => counts.unavailable += 1,
        MycOperationAuditOutcome::Missing => counts.missing += 1,
        MycOperationAuditOutcome::Matched => counts.matched += 1,
        MycOperationAuditOutcome::Drifted => counts.drifted += 1,
        MycOperationAuditOutcome::Conflicted => counts.conflicted += 1,
        MycOperationAuditOutcome::Skipped => counts.skipped += 1,
    }
}

pub fn operation_kind_label(kind: MycOperationAuditKind) -> String {
    match kind {
        MycOperationAuditKind::DeliveryRecovery => "delivery_recovery".to_owned(),
        MycOperationAuditKind::ListenerResponsePublish => "listener_response_publish".to_owned(),
        MycOperationAuditKind::ConnectAcceptPublish => "connect_accept_publish".to_owned(),
        MycOperationAuditKind::AuthReplayPublish => "auth_replay_publish".to_owned(),
        MycOperationAuditKind::AuthReplayRestore => "auth_replay_restore".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerFetch => "discovery_handler_fetch".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerPublish => "discovery_handler_publish".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerCompare => "discovery_handler_compare".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerRefresh => "discovery_handler_refresh".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerRepair => "discovery_handler_repair".to_owned(),
    }
}

pub fn is_aggregate_publish_operation(kind: MycOperationAuditKind) -> bool {
    matches!(
        kind,
        MycOperationAuditKind::ListenerResponsePublish
            | MycOperationAuditKind::ConnectAcceptPublish
            | MycOperationAuditKind::AuthReplayPublish
            | MycOperationAuditKind::DiscoveryHandlerPublish
    )
}

async fn collect_transport_status(
    runtime: &MycRuntime,
) -> Result<MycTransportStatusEvaluation, MycError> {
    let snapshot = runtime.snapshot().transport;
    if !snapshot.enabled {
        return Ok(MycTransportStatusEvaluation {
            output: MycTransportStatusOutput {
                enabled: false,
                status: MycRuntimeStatus::Unready,
                ready: false,
                configured_relay_count: 0,
                required_available_relays: 0,
                available_relay_count: 0,
                unavailable_relay_count: 0,
                delivery_policy: snapshot.delivery_policy,
                delivery_quorum: snapshot.delivery_quorum,
                relay_probes: Vec::new(),
            },
            reasons: vec!["transport is disabled".to_owned()],
        });
    }

    let Some(transport) = runtime.transport() else {
        return Ok(MycTransportStatusEvaluation {
            output: MycTransportStatusOutput {
                enabled: true,
                status: MycRuntimeStatus::Unready,
                ready: false,
                configured_relay_count: 0,
                required_available_relays: 0,
                available_relay_count: 0,
                unavailable_relay_count: 0,
                delivery_policy: snapshot.delivery_policy,
                delivery_quorum: snapshot.delivery_quorum,
                relay_probes: Vec::new(),
            },
            reasons: vec!["transport is enabled but no transport client was prepared".to_owned()],
        });
    };

    let relay_probes = probe_relays(
        runtime.signer_identity(),
        transport.relays(),
        transport.connect_timeout_secs(),
    )
    .await?;
    let available_relay_count = relay_probes
        .iter()
        .filter(|probe| probe.availability == MycRelayProbeAvailability::Available)
        .count();
    let configured_relay_count = relay_probes.len();
    let unavailable_relay_count = configured_relay_count.saturating_sub(available_relay_count);
    let required_available_relays =
        required_available_relays(&snapshot, configured_relay_count).unwrap_or(usize::MAX);
    let ready = available_relay_count >= required_available_relays;
    let status = if !ready {
        MycRuntimeStatus::Unready
    } else if unavailable_relay_count > 0 {
        MycRuntimeStatus::Degraded
    } else {
        MycRuntimeStatus::Healthy
    };
    let mut reasons = Vec::new();
    if !ready {
        reasons.push(format!(
            "transport availability {available_relay_count}/{} does not satisfy delivery policy {}",
            configured_relay_count,
            snapshot.delivery_policy.as_str()
        ));
    } else if unavailable_relay_count > 0 {
        reasons.push(format!(
            "{unavailable_relay_count} transport relay(s) are unavailable"
        ));
    }

    Ok(MycTransportStatusEvaluation {
        output: MycTransportStatusOutput {
            enabled: true,
            status,
            ready,
            configured_relay_count,
            required_available_relays,
            available_relay_count,
            unavailable_relay_count,
            delivery_policy: snapshot.delivery_policy,
            delivery_quorum: snapshot.delivery_quorum,
            relay_probes,
        },
        reasons,
    })
}

struct MycDiscoveryStatusEvaluation {
    output: MycDiscoveryStatusOutput,
    reasons: Vec<String>,
}

async fn collect_discovery_status(
    runtime: &MycRuntime,
) -> Result<MycDiscoveryStatusEvaluation, MycError> {
    if !runtime.config().discovery.enabled {
        return Ok(MycDiscoveryStatusEvaluation {
            output: MycDiscoveryStatusOutput {
                enabled: false,
                status: MycRuntimeStatus::Healthy,
                public_relays: MycDiscoveryRelayGroupStatusOutput {
                    configured_relay_count: 0,
                    available_relay_count: 0,
                    unavailable_relay_count: 0,
                    relay_probes: Vec::new(),
                },
                publish_relays: MycDiscoveryRelayGroupStatusOutput {
                    configured_relay_count: 0,
                    available_relay_count: 0,
                    unavailable_relay_count: 0,
                    relay_probes: Vec::new(),
                },
            },
            reasons: Vec::new(),
        });
    }

    let context = MycDiscoveryContext::from_runtime(runtime)?;
    let public_relays = runtime
        .config()
        .discovery
        .resolved_public_relays(&runtime.config().transport)?;
    let public_relays = probe_relays(
        context.app_identity(),
        public_relays.as_slice(),
        context.connect_timeout_secs(),
    )
    .await?;
    let publish_relays = probe_relays(
        context.app_identity(),
        context.publish_relays(),
        context.connect_timeout_secs(),
    )
    .await?;
    let public_group = summarize_discovery_relay_group(public_relays);
    let publish_group = summarize_discovery_relay_group(publish_relays);

    let status =
        if public_group.unavailable_relay_count > 0 || publish_group.unavailable_relay_count > 0 {
            MycRuntimeStatus::Degraded
        } else {
            MycRuntimeStatus::Healthy
        };
    let mut reasons = Vec::new();
    if public_group.unavailable_relay_count > 0 {
        reasons.push(format!(
            "{} discovery public relay(s) are unavailable",
            public_group.unavailable_relay_count
        ));
    }
    if publish_group.unavailable_relay_count > 0 {
        reasons.push(format!(
            "{} discovery publish relay(s) are unavailable",
            publish_group.unavailable_relay_count
        ));
    }

    Ok(MycDiscoveryStatusEvaluation {
        output: MycDiscoveryStatusOutput {
            enabled: true,
            status,
            public_relays: public_group,
            publish_relays: publish_group,
        },
        reasons,
    })
}

fn summarize_discovery_relay_group(
    relay_probes: Vec<MycRelayProbe>,
) -> MycDiscoveryRelayGroupStatusOutput {
    let configured_relay_count = relay_probes.len();
    let available_relay_count = relay_probes
        .iter()
        .filter(|probe| probe.availability == MycRelayProbeAvailability::Available)
        .count();
    let unavailable_relay_count = configured_relay_count.saturating_sub(available_relay_count);
    MycDiscoveryRelayGroupStatusOutput {
        configured_relay_count,
        available_relay_count,
        unavailable_relay_count,
        relay_probes,
    }
}

fn collect_delivery_outbox_status(
    runtime: &MycRuntime,
) -> Result<MycDeliveryOutboxStatusEvaluation, MycError> {
    let outbox_records = runtime.delivery_outbox_store().list_all()?;
    let workflow_by_id = runtime
        .signer_manager()?
        .list_publish_workflows()?
        .into_iter()
        .map(|workflow| (workflow.workflow_id.to_string(), workflow))
        .collect::<BTreeMap<_, _>>();
    let now_unix = now_unix_secs();
    let stuck_after_secs = delivery_outbox_stuck_after_secs(runtime);
    let path = runtime.paths().delivery_outbox_path.clone();
    let exists = path.exists();
    let mut queued_job_count = 0usize;
    let mut published_pending_finalize_job_count = 0usize;
    let mut finalized_job_count = 0usize;
    let mut failed_job_count = 0usize;
    let mut unfinished_job_count = 0usize;
    let mut critical_unfinished_job_count = 0usize;
    let mut blocked_job_count = 0usize;
    let mut critical_blocked_job_count = 0usize;
    let mut oldest_unfinished_age_secs = None;
    let mut oldest_blocked_age_secs = None;

    for record in &outbox_records {
        match record.status {
            MycDeliveryOutboxStatus::Queued => queued_job_count += 1,
            MycDeliveryOutboxStatus::PublishedPendingFinalize => {
                published_pending_finalize_job_count += 1;
            }
            MycDeliveryOutboxStatus::Finalized => finalized_job_count += 1,
            MycDeliveryOutboxStatus::Failed => failed_job_count += 1,
        }

        if !is_delivery_outbox_unfinished(record) {
            continue;
        }

        unfinished_job_count += 1;
        if is_critical_delivery_outbox_job(record) {
            critical_unfinished_job_count += 1;
        }
        let age_secs = delivery_outbox_record_age_secs(record, now_unix);
        oldest_unfinished_age_secs =
            Some(oldest_unfinished_age_secs.map_or(age_secs, |current: u64| current.max(age_secs)));

        if let Some(is_critical) = classify_blocked_delivery_outbox_record(
            record,
            &workflow_by_id,
            age_secs,
            stuck_after_secs,
        ) {
            blocked_job_count += 1;
            if is_critical {
                critical_blocked_job_count += 1;
            }
            oldest_blocked_age_secs = Some(
                oldest_blocked_age_secs.map_or(age_secs, |current: u64| current.max(age_secs)),
            );
        }
    }

    let last_recovery = latest_delivery_recovery_status(runtime)?;
    let mut reasons = Vec::new();
    if !exists {
        reasons.push(format!(
            "delivery outbox persistence file at {} is missing",
            path.display()
        ));
    }
    if critical_blocked_job_count > 0 {
        reasons.push(format!(
            "{critical_blocked_job_count} critical delivery outbox job(s) are blocked"
        ));
    }
    let noncritical_blocked_job_count =
        blocked_job_count.saturating_sub(critical_blocked_job_count);
    if noncritical_blocked_job_count > 0 {
        reasons.push(format!(
            "{noncritical_blocked_job_count} non-critical delivery outbox job(s) are blocked"
        ));
    }

    let (status, ready) = if !exists || critical_blocked_job_count > 0 {
        (MycRuntimeStatus::Unready, false)
    } else if blocked_job_count > 0 {
        (MycRuntimeStatus::Degraded, true)
    } else {
        (MycRuntimeStatus::Healthy, true)
    };

    Ok(MycDeliveryOutboxStatusEvaluation {
        output: MycDeliveryOutboxStatusOutput {
            status,
            ready,
            path,
            exists,
            total_job_count: outbox_records.len(),
            queued_job_count,
            published_pending_finalize_job_count,
            finalized_job_count,
            failed_job_count,
            unfinished_job_count,
            critical_unfinished_job_count,
            blocked_job_count,
            critical_blocked_job_count,
            stuck_after_secs,
            oldest_unfinished_age_secs,
            oldest_blocked_age_secs,
            last_recovery,
        },
        reasons,
    })
}

fn latest_delivery_recovery_status(
    runtime: &MycRuntime,
) -> Result<Option<MycDeliveryRecoveryStatusOutput>, MycError> {
    let latest = runtime
        .operation_audit_store()
        .list_all()?
        .into_iter()
        .filter(|record| record.operation == MycOperationAuditKind::DeliveryRecovery)
        .max_by_key(|record| record.recorded_at_unix);
    Ok(latest.map(|record| MycDeliveryRecoveryStatusOutput {
        recorded_at_unix: record.recorded_at_unix,
        outcome: record.outcome,
        summary: record.relay_outcome_summary,
    }))
}

fn delivery_outbox_stuck_after_secs(runtime: &MycRuntime) -> u64 {
    let transport = &runtime.config().transport;
    let mut total_millis = transport
        .connect_timeout_secs
        .saturating_mul(1000)
        .saturating_mul(transport.publish_max_attempts as u64);
    for completed_attempt in 1..transport.publish_max_attempts {
        total_millis =
            total_millis.saturating_add(delivery_outbox_backoff_millis(runtime, completed_attempt));
    }
    total_millis.saturating_add(999) / 1000
}

fn delivery_outbox_backoff_millis(runtime: &MycRuntime, completed_attempt_number: usize) -> u64 {
    let transport = &runtime.config().transport;
    let exponent = completed_attempt_number.saturating_sub(1) as u32;
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let scaled = transport
        .publish_initial_backoff_millis
        .saturating_mul(multiplier);
    scaled.min(transport.publish_max_backoff_millis)
}

fn is_delivery_outbox_unfinished(record: &MycDeliveryOutboxRecord) -> bool {
    matches!(
        record.status,
        MycDeliveryOutboxStatus::Queued | MycDeliveryOutboxStatus::PublishedPendingFinalize
    )
}

fn is_critical_delivery_outbox_job(record: &MycDeliveryOutboxRecord) -> bool {
    record.kind != crate::outbox::MycDeliveryOutboxKind::DiscoveryHandlerPublish
}

fn delivery_outbox_record_age_secs(record: &MycDeliveryOutboxRecord, now_unix: u64) -> u64 {
    now_unix.saturating_sub(record.updated_at_unix)
}

fn classify_blocked_delivery_outbox_record(
    record: &MycDeliveryOutboxRecord,
    workflow_by_id: &BTreeMap<String, RadrootsNostrSignerPublishWorkflowRecord>,
    age_secs: u64,
    stuck_after_secs: u64,
) -> Option<bool> {
    if !is_delivery_outbox_unfinished(record) {
        return None;
    }

    let is_critical = is_critical_delivery_outbox_job(record);
    match record.kind {
        crate::outbox::MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
            if record.signer_publish_workflow_id.is_some() {
                return Some(false);
            }
        }
        crate::outbox::MycDeliveryOutboxKind::ConnectAcceptPublish
        | crate::outbox::MycDeliveryOutboxKind::AuthReplayPublish => {
            if record.signer_publish_workflow_id.is_none() {
                return Some(true);
            }
        }
        crate::outbox::MycDeliveryOutboxKind::ListenerResponsePublish => {}
    }

    if let Some(workflow_id) = record.signer_publish_workflow_id.as_ref() {
        let Some(workflow) = workflow_by_id.get(workflow_id.as_str()) else {
            return Some(is_critical);
        };
        let expected_state = match record.status {
            MycDeliveryOutboxStatus::Queued => {
                RadrootsNostrSignerPublishWorkflowState::PendingPublish
            }
            MycDeliveryOutboxStatus::PublishedPendingFinalize => {
                RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize
            }
            MycDeliveryOutboxStatus::Finalized | MycDeliveryOutboxStatus::Failed => {
                return None;
            }
        };
        if workflow.state != expected_state {
            return Some(is_critical);
        }
    }

    if age_secs > stuck_after_secs {
        return Some(is_critical);
    }

    None
}

fn combine_runtime_status(
    transport_status: MycRuntimeStatus,
    discovery_status: Option<MycRuntimeStatus>,
) -> MycRuntimeStatus {
    let mut status = transport_status;
    if let Some(discovery_status) = discovery_status {
        status = worse_runtime_status(status, discovery_status);
    }
    status
}

fn worse_runtime_status(left: MycRuntimeStatus, right: MycRuntimeStatus) -> MycRuntimeStatus {
    use MycRuntimeStatus::{Degraded, Healthy, Unready};
    match (left, right) {
        (Unready, _) | (_, Unready) => Unready,
        (Degraded, _) | (_, Degraded) => Degraded,
        _ => Healthy,
    }
}

fn required_available_relays(
    snapshot: &MycTransportSnapshot,
    configured_relay_count: usize,
) -> Result<usize, MycError> {
    match snapshot.delivery_policy {
        MycTransportDeliveryPolicy::Any => Ok(1),
        MycTransportDeliveryPolicy::All => Ok(configured_relay_count),
        MycTransportDeliveryPolicy::Quorum => snapshot.delivery_quorum.ok_or_else(|| {
            MycError::InvalidConfig(
                "transport.delivery_quorum must be set when transport.delivery_policy is `quorum`"
                    .to_owned(),
            )
        }),
    }
}

async fn probe_relays(
    identity: &MycActiveIdentity,
    relays: &[RadrootsNostrRelayUrl],
    connect_timeout_secs: u64,
) -> Result<Vec<MycRelayProbe>, MycError> {
    let relay_count = relays.len();
    if relay_count == 0 {
        return Ok(Vec::new());
    }

    let mut pending = relays
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<_>>()
        .into_iter();
    let mut join_set = JoinSet::new();
    let max_concurrency = relay_count.min(MYC_RELAY_PROBE_CONCURRENCY_LIMIT);

    while join_set.len() < max_concurrency {
        let Some((relay_index, relay)) = pending.next() else {
            break;
        };
        let identity = identity.clone();
        join_set.spawn(async move {
            let probe = probe_relay(identity, relay.clone(), connect_timeout_secs).await;
            (relay_index, probe)
        });
    }

    let mut probes = std::iter::repeat_with(|| None)
        .take(relay_count)
        .collect::<Vec<Option<MycRelayProbe>>>();

    while let Some(joined) = join_set.join_next().await {
        let (relay_index, probe_result) = joined.map_err(|error| {
            MycError::InvalidOperation(format!("relay probe task failed: {error}"))
        })?;
        probes[relay_index] = Some(probe_result?);
        while join_set.len() < max_concurrency {
            let Some((relay_index, relay)) = pending.next() else {
                break;
            };
            let identity = identity.clone();
            join_set.spawn(async move {
                let probe = probe_relay(identity, relay.clone(), connect_timeout_secs).await;
                (relay_index, probe)
            });
        }
    }

    probes
        .into_iter()
        .map(|probe| {
            probe.ok_or_else(|| MycError::InvalidOperation("missing relay probe result".to_owned()))
        })
        .collect()
}

async fn probe_relay(
    identity: MycActiveIdentity,
    relay: RadrootsNostrRelayUrl,
    connect_timeout_secs: u64,
) -> Result<MycRelayProbe, MycError> {
    let relay_url = relay.to_string();
    let client = identity.nostr_client_owned();
    client
        .add_relay(relay.as_str())
        .await
        .map_err(MycError::from)?;

    match client
        .try_connect_relay(relay.as_str(), Duration::from_secs(connect_timeout_secs))
        .await
    {
        Ok(_) => {
            let relays = client.relays().await;
            let relay_state = relays.get(&relay).ok_or_else(|| {
                MycError::InvalidOperation(format!(
                    "connected relay `{relay_url}` did not appear in the relay map"
                ))
            })?;
            Ok(MycRelayProbe {
                relay_url,
                availability: MycRelayProbeAvailability::Available,
                relay_status: Some(relay_status_label(relay_state.status())),
                connection_attempts: relay_state.stats().attempts(),
                successful_connections: relay_state.stats().success(),
                latency_ms: relay_state
                    .stats()
                    .latency()
                    .map(|duration| duration.as_millis() as u64),
                queue_depth: relay_state.queue(),
                error: None,
            })
        }
        Err(error) => Ok(MycRelayProbe {
            relay_url,
            availability: MycRelayProbeAvailability::Unavailable,
            relay_status: None,
            connection_attempts: 0,
            successful_connections: 0,
            latency_ms: None,
            queue_depth: 0,
            error: Some(error.to_string()),
        }),
    }
}

fn relay_status_label(status: RadrootsNostrRelayStatus) -> String {
    status.to_string().to_ascii_lowercase()
}

fn inspect_signer_state_sqlite_schema(path: &Path) -> MycSqliteSchemaStatusOutput {
    inspect_sqlite_schema(
        path,
        Some("SELECT store_version FROM signer_store_metadata WHERE singleton_id = 1"),
    )
}

fn inspect_runtime_audit_sqlite_schema(path: &Path) -> MycSqliteSchemaStatusOutput {
    inspect_sqlite_schema(path, None)
}

fn inspect_sqlite_schema(
    path: &Path,
    store_version_sql: Option<&str>,
) -> MycSqliteSchemaStatusOutput {
    let outcome = (|| -> Result<MycSqliteSchemaStatusOutput, String> {
        if !path.exists() {
            return Err("sqlite persistence file is missing".to_owned());
        }
        let executor = SqliteExecutor::open(path).map_err(|error| error.to_string())?;
        let applied_count = query_sqlite_rows::<MycSqliteAppliedCountRow>(
            &executor,
            "SELECT COUNT(*) AS applied_count FROM __migrations",
        )?
        .into_iter()
        .next()
        .ok_or_else(|| "sqlite migrations query returned no rows".to_owned())?
        .applied_count;
        let latest_migration = query_sqlite_rows::<MycSqliteNamedRow>(
            &executor,
            "SELECT name FROM __migrations ORDER BY rowid DESC LIMIT 1",
        )?
        .into_iter()
        .next()
        .map(|row| row.name);
        let journal_mode =
            query_sqlite_rows::<MycSqliteJournalModeRow>(&executor, "PRAGMA journal_mode")?
                .into_iter()
                .next()
                .ok_or_else(|| "sqlite journal mode query returned no rows".to_owned())?
                .journal_mode;
        let store_version = if let Some(sql) = store_version_sql {
            query_sqlite_rows::<MycSqliteStoreVersionRow>(&executor, sql)?
                .into_iter()
                .next()
                .map(|row| {
                    u32::try_from(row.store_version)
                        .map_err(|_| "sqlite store_version is out of range".to_owned())
                })
                .transpose()?
        } else {
            None
        };

        Ok(MycSqliteSchemaStatusOutput {
            ready: true,
            applied_migration_count: Some(applied_count as usize),
            latest_migration,
            journal_mode: Some(journal_mode),
            store_version,
            error: None,
        })
    })();

    match outcome {
        Ok(output) => output,
        Err(error) => MycSqliteSchemaStatusOutput {
            ready: false,
            applied_migration_count: None,
            latest_migration: None,
            journal_mode: None,
            store_version: None,
            error: Some(error),
        },
    }
}

fn query_sqlite_rows<T>(executor: &SqliteExecutor, sql: &str) -> Result<Vec<T>, String>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = executor
        .query_raw(sql, "[]")
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&raw).map_err(|error| error.to_string())
}

fn push_counter(lines: &mut Vec<String>, name: &str, value: usize) {
    lines.push(format!("{name} {value}"));
}

fn push_labeled_counter(
    lines: &mut Vec<String>,
    name: &str,
    label_key: &str,
    label_value: &str,
    value: usize,
) {
    lines.push(format!(r#"{name}{{{label_key}="{label_value}"}} {value}"#));
}

fn push_outcome_counters(lines: &mut Vec<String>, name: &str, counts: &MycOperationOutcomeCounts) {
    push_labeled_counter(lines, name, "outcome", "succeeded", counts.succeeded);
    push_labeled_counter(lines, name, "outcome", "rejected", counts.rejected);
    push_labeled_counter(lines, name, "outcome", "restored", counts.restored);
    push_labeled_counter(lines, name, "outcome", "unavailable", counts.unavailable);
    push_labeled_counter(lines, name, "outcome", "missing", counts.missing);
    push_labeled_counter(lines, name, "outcome", "matched", counts.matched);
    push_labeled_counter(lines, name, "outcome", "drifted", counts.drifted);
    push_labeled_counter(lines, name, "outcome", "conflicted", counts.conflicted);
    push_labeled_counter(lines, name, "outcome", "skipped", counts.skipped);
}

fn push_outcome_counters_with_extra_label(
    lines: &mut Vec<String>,
    name: &str,
    extra_label_key: &str,
    extra_label_value: &str,
    counts: &MycOperationOutcomeCounts,
) {
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "succeeded",
        counts.succeeded,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "rejected",
        counts.rejected,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "restored",
        counts.restored,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "unavailable",
        counts.unavailable,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "missing",
        counts.missing,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "matched",
        counts.matched,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "drifted",
        counts.drifted,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "conflicted",
        counts.conflicted,
    );
    push_labeled_counter_pair(
        lines,
        name,
        extra_label_key,
        extra_label_value,
        "outcome",
        "skipped",
        counts.skipped,
    );
}

fn push_labeled_counter_pair(
    lines: &mut Vec<String>,
    name: &str,
    first_key: &str,
    first_value: &str,
    second_key: &str,
    second_value: &str,
    value: usize,
) {
    lines.push(format!(
        r#"{name}{{{first_key}="{first_value}",{second_key}="{second_value}"}} {value}"#
    ));
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::{
        MycMetricsSnapshot, MycOperationOutcomeCounts, MycRuntimeStatus,
        inspect_runtime_audit_sqlite_schema, render_metrics_text, worse_runtime_status,
    };
    use crate::app::MycRuntimePaths;
    use crate::config::MycRuntimeAuditBackend;

    #[test]
    fn runtime_status_prefers_the_worst_state() {
        assert_eq!(
            worse_runtime_status(MycRuntimeStatus::Healthy, MycRuntimeStatus::Degraded),
            MycRuntimeStatus::Degraded
        );
        assert_eq!(
            worse_runtime_status(MycRuntimeStatus::Healthy, MycRuntimeStatus::Unready),
            MycRuntimeStatus::Unready
        );
        assert_eq!(
            worse_runtime_status(MycRuntimeStatus::Degraded, MycRuntimeStatus::Healthy),
            MycRuntimeStatus::Degraded
        );
    }

    #[test]
    fn metrics_text_renderer_is_deterministic() {
        let metrics = MycMetricsSnapshot {
            signer_request_total: 3,
            signer_request_decisions: super::MycAuditDecisionCounts {
                allowed: 1,
                denied: 1,
                challenged: 1,
            },
            runtime_operation_total: 2,
            runtime_operation_outcomes: MycOperationOutcomeCounts {
                succeeded: 1,
                rejected: 1,
                ..MycOperationOutcomeCounts::default()
            },
            runtime_operation_by_kind: BTreeMap::from([(
                "listener_response_publish".to_owned(),
                MycOperationOutcomeCounts {
                    succeeded: 1,
                    ..MycOperationOutcomeCounts::default()
                },
            )]),
            runtime_aggregate_publish_rejection_count: 1,
            runtime_repair_success_count: 0,
            runtime_repair_rejection_count: 0,
            runtime_unavailable_count: 0,
            runtime_replay_restore_count: 0,
            delivery_recovery_success_count: 1,
            delivery_recovery_rejection_count: 0,
            delivery_outbox_total: 2,
            delivery_outbox_queued_count: 1,
            delivery_outbox_published_pending_finalize_count: 0,
            delivery_outbox_failed_count: 1,
            delivery_outbox_finalized_count: 0,
            delivery_outbox_unfinished_count: 1,
            delivery_outbox_critical_unfinished_count: 1,
            delivery_outbox_blocked_count: 0,
            delivery_outbox_critical_blocked_count: 0,
        };

        let rendered = render_metrics_text(&metrics);

        assert!(rendered.contains("myc_signer_request_total 3"));
        assert!(rendered.contains(
            r#"myc_runtime_operation_kind_total{kind="listener_response_publish",outcome="succeeded"} 1"#
        ));
        assert!(rendered.contains("myc_delivery_recovery_success_total 1"));
        assert!(rendered.contains("myc_delivery_outbox_total 2"));
    }

    #[test]
    fn runtime_audit_sqlite_schema_status_reports_missing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let status = inspect_runtime_audit_sqlite_schema(
            MycRuntimePaths::runtime_audit_path_for_backend(
                PathBuf::from(temp.path()).as_path(),
                MycRuntimeAuditBackend::Sqlite,
            )
            .as_path(),
        );

        assert!(!status.ready);
        assert_eq!(
            status.error.as_deref(),
            Some("sqlite persistence file is missing")
        );
    }
}
