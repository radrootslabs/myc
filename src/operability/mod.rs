pub mod server;

use std::collections::BTreeMap;
use std::time::Duration;

use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrRelayStatus, RadrootsNostrRelayUrl,
};
use radroots_nostr_signer::prelude::RadrootsNostrSignerRequestDecision;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome};
use crate::config::MycTransportDeliveryPolicy;
use crate::discovery::MycDiscoveryContext;
use crate::error::MycError;
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
pub struct MycStatusFullOutput {
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub reasons: Vec<String>,
    pub startup: crate::app::MycStartupSnapshot,
    pub transport: MycTransportStatusOutput,
    pub discovery: MycDiscoveryStatusOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycStatusSummaryOutput {
    pub status: MycRuntimeStatus,
    pub ready: bool,
    pub reasons: Vec<String>,
    pub instance_name: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycTransportStatusEvaluation {
    output: MycTransportStatusOutput,
    reasons: Vec<String>,
}

pub async fn collect_status_full(runtime: &MycRuntime) -> Result<MycStatusFullOutput, MycError> {
    let snapshot = runtime.snapshot();
    let transport = collect_transport_status(runtime).await?;
    let discovery = collect_discovery_status(runtime).await?;
    let mut reasons = transport.reasons;
    reasons.extend(discovery.reasons);
    let status = combine_runtime_status(
        transport.output.status,
        if discovery.output.enabled {
            Some(discovery.output.status)
        } else {
            None
        },
    );
    let ready = transport.output.ready;
    Ok(MycStatusFullOutput {
        status,
        ready,
        reasons,
        startup: snapshot,
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

pub fn collect_metrics(runtime: &MycRuntime) -> Result<MycMetricsSnapshot, MycError> {
    let manager = runtime.signer_manager()?;
    let signer_request_audit = manager.list_audit_records()?;
    let runtime_operation_audit = runtime.operation_audit_store().list_all()?;

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
    identity: &RadrootsIdentity,
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
        let identity = (*identity).clone();
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
            let identity = (*identity).clone();
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
    identity: RadrootsIdentity,
    relay: RadrootsNostrRelayUrl,
    connect_timeout_secs: u64,
) -> Result<MycRelayProbe, MycError> {
    let relay_url = relay.to_string();
    let client = RadrootsNostrClient::from_identity_owned(identity);
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

    use super::{
        MycMetricsSnapshot, MycOperationOutcomeCounts, MycRuntimeStatus, render_metrics_text,
        worse_runtime_status,
    };

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
        };

        let rendered = render_metrics_text(&metrics);

        assert!(rendered.contains("myc_signer_request_total 3"));
        assert!(rendered.contains(
            r#"myc_runtime_operation_kind_total{kind="listener_response_publish",outcome="succeeded"} 1"#
        ));
    }
}
