//! Exact source-locked Nostr delivery adapter owned by the Myc runtime.

use core::{fmt, future::Future, pin::Pin};
use std::{collections::BTreeMap, error::Error};

use radroots_event_codec::Codec;
use radroots_transport::{
    EventSource, EventSubscriber, FetchRequest, Target, TargetSet,
    outcome::{DeliveryOutcomeKind, FetchTargetState},
    policy::{SatisfactionClass, SatisfactionPolicy, TargetPolicy},
    sink::{DeliveryPayload, DeliveryRequest, DeliveryTargetReceipt},
    source::{
        BoxSubscription, FetchBounds, FetchSelector, SubscriptionBounds, SubscriptionCheckpoint,
        SubscriptionRequest,
    },
    target::TargetFingerprint,
};
use radroots_transport_nostr::{
    Config, NostrTransport, PreparedDelivery, RelayAccess, RelayEndpoint, RelayProfile,
    RelayProfileKind, RelayUrlPolicy,
};

use crate::{MycConfigDocumentV1, MycConfigProfile, MycDeliveryRelayId, MycRateRelayId};

const NIP46_RPC_KIND: u32 = 24_133;

pub(crate) type RelayExecutionFuture<'a> = Pin<
    Box<dyn Future<Output = Result<MycRelayExecutionOutcome, MycRelayAdapterError>> + Send + 'a>,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycRelayAdapterErrorKind {
    Configuration,
    Target,
    Payload,
    Preparation,
    Execution,
}

pub(crate) struct MycRelayAdapterError {
    kind: MycRelayAdapterErrorKind,
}

impl MycRelayAdapterError {
    #[cfg(test)]
    pub(crate) const fn kind(&self) -> MycRelayAdapterErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycRelayAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRelayAdapterError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycRelayAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc relay adapter failed")
    }
}

impl Error for MycRelayAdapterError {}

const fn adapter_error(kind: MycRelayAdapterErrorKind) -> MycRelayAdapterError {
    MycRelayAdapterError { kind }
}

pub(crate) const fn runtime_relay_adapter_error(
    kind: MycRelayAdapterErrorKind,
) -> MycRelayAdapterError {
    adapter_error(kind)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MycRelayExecutionOutcome {
    Accepted,
    Rejected,
    TransportFailed,
    UnknownAcknowledgement,
}

pub(crate) struct MycPreparedRelayDelivery {
    transport: NostrTransport,
    prepared: PreparedDelivery,
}

impl fmt::Debug for MycPreparedRelayDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycPreparedRelayDelivery([redacted])")
    }
}

pub(crate) trait MycRelayAdapter: Send + Sync {
    type Prepared: Send;

    fn prepare(
        &self,
        relay_id: &MycDeliveryRelayId,
        request_id: String,
        exact_event_bytes: &[u8],
        deadline_unix_ms: u64,
    ) -> Result<Self::Prepared, MycRelayAdapterError>;

    fn execute<'a>(&'a self, prepared: Self::Prepared) -> RelayExecutionFuture<'a>;
}

pub(crate) struct MycNostrDeliveryAdapter {
    targets: BTreeMap<MycDeliveryRelayId, RelayTarget>,
}

struct RelayTarget {
    transport: NostrTransport,
    target: Target,
}

/// One exact source-locked subscription group owned by the sole ingress task.
pub(crate) struct MycNostrIngressAdapter {
    groups: Box<[IngressGroup]>,
}

struct IngressGroup {
    transport: NostrTransport,
    targets: TargetSet,
    relay_ids: BTreeMap<TargetFingerprint, MycRateRelayId>,
    required: bool,
    request_id: &'static str,
}

impl MycNostrIngressAdapter {
    pub(crate) fn from_configuration(
        configuration: &MycConfigDocumentV1,
    ) -> Result<Self, MycRelayAdapterError> {
        let relays = configuration
            .normalized()
            .pointer("/relays")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        let connect_timeout =
            configuration_integer(configuration, "/transport/connect_deadline_ms")?;
        let request_timeout =
            configuration_integer(configuration, "/transport/ingress/subscription_deadline_ms")?;
        let mut public = Vec::new();
        let mut public_targets = Vec::new();
        let mut public_ids = BTreeMap::new();
        let mut public_required = false;
        let mut local = Vec::new();
        let mut local_targets = Vec::new();
        let mut local_ids = BTreeMap::new();
        let mut local_required = false;
        for relay in relays.iter().filter(|relay| {
            relay.pointer("/read").and_then(serde_json::Value::as_bool) == Some(true)
        }) {
            let id = relay
                .pointer("/id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| MycRateRelayId::new(value).ok())
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let url = relay
                .pointer("/url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let required = relay
                .pointer("/required")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let target = Target::nostr_relay(url)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
            let fingerprint = target.fingerprint().clone();
            let (kind, policy) = if url.starts_with("wss://") {
                (RelayProfileKind::Public, RelayUrlPolicy::Public)
            } else if configuration.profile() == MycConfigProfile::RepoLocal
                && url.starts_with("ws://")
            {
                (RelayProfileKind::Simulator, RelayUrlPolicy::Local)
            } else {
                return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
            };
            let endpoint = RelayEndpoint::new(url, policy, RelayAccess::ReadOnly)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            match kind {
                RelayProfileKind::Public => {
                    public.push(endpoint);
                    public_targets.push(target);
                    public_required |= required;
                    if public_ids.insert(fingerprint, id).is_some() {
                        return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
                    }
                }
                RelayProfileKind::Simulator => {
                    local.push(endpoint);
                    local_targets.push(target);
                    local_required |= required;
                    if local_ids.insert(fingerprint, id).is_some() {
                        return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
                    }
                }
                RelayProfileKind::Device => {
                    return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
                }
                _ => return Err(adapter_error(MycRelayAdapterErrorKind::Configuration)),
            }
        }
        let mut groups = Vec::with_capacity(2);
        add_ingress_group(
            &mut groups,
            RelayProfileKind::Public,
            public,
            public_targets,
            public_ids,
            public_required,
            connect_timeout,
            request_timeout,
            "myc-runtime-public",
        )?;
        add_ingress_group(
            &mut groups,
            RelayProfileKind::Simulator,
            local,
            local_targets,
            local_ids,
            local_required,
            connect_timeout,
            request_timeout,
            "myc-runtime-local",
        )?;
        if groups.is_empty() || groups.len() > 2 || !groups.iter().any(|group| group.required) {
            return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
        }
        Ok(Self {
            groups: groups.into_boxed_slice(),
        })
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn group_is_required(&self, index: usize) -> Option<bool> {
        self.groups.get(index).map(|group| group.required)
    }

    pub(crate) async fn subscribe(
        &self,
        index: usize,
        event_limit: u16,
        deadline_unix_ms: u64,
        checkpoints: &[SubscriptionCheckpoint],
    ) -> Result<BoxSubscription, MycRelayAdapterError> {
        let group = self
            .groups
            .get(index)
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        let selector = FetchSelector::all()
            .with_kinds(vec![NIP46_RPC_KIND])
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        let request = SubscriptionRequest::new(
            group.request_id,
            group.targets.clone(),
            SubscriptionBounds::new(event_limit, deadline_unix_ms)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?,
        )
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?
        .with_selector(selector)
        .with_checkpoints(checkpoints.iter().cloned())
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        group
            .transport
            .subscribe(request)
            .await
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Execution))
    }

    pub(crate) fn relay_id(
        &self,
        index: usize,
        target: &TargetFingerprint,
    ) -> Result<MycRateRelayId, MycRelayAdapterError> {
        self.groups
            .get(index)
            .and_then(|group| group.relay_ids.get(target))
            .cloned()
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Target))
    }
}

#[allow(clippy::too_many_arguments)]
fn add_ingress_group(
    groups: &mut Vec<IngressGroup>,
    kind: RelayProfileKind,
    endpoints: Vec<RelayEndpoint>,
    targets: Vec<Target>,
    relay_ids: BTreeMap<TargetFingerprint, MycRateRelayId>,
    required: bool,
    connect_timeout: u64,
    request_timeout: u64,
    request_id: &'static str,
) -> Result<(), MycRelayAdapterError> {
    if targets.is_empty() {
        return Ok(());
    }
    let transport = build_transport(kind, endpoints, connect_timeout, request_timeout)?
        .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
    let targets =
        TargetSet::new(targets).map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
    if targets.len() != relay_ids.len() {
        return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
    }
    groups.push(IngressGroup {
        transport,
        targets,
        relay_ids,
        required,
        request_id,
    });
    Ok(())
}

impl MycNostrDeliveryAdapter {
    pub(crate) fn from_configuration(
        configuration: &MycConfigDocumentV1,
    ) -> Result<Self, MycRelayAdapterError> {
        let relays = configuration
            .normalized()
            .pointer("/relays")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        let connect_timeout =
            configuration_integer(configuration, "/transport/connect_deadline_ms")?;
        let request_timeout = configuration_integer(
            configuration,
            "/transport/publish_retry/attempt_deadline_ms",
        )?;
        let mut public = Vec::new();
        let mut local = Vec::new();
        let mut definitions = Vec::with_capacity(relays.len());
        for relay in relays {
            let id = relay
                .pointer("/id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| MycDeliveryRelayId::new(value).ok())
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let url = relay
                .pointer("/url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let read = relay
                .pointer("/read")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let write = relay
                .pointer("/write")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let access = if write {
                RelayAccess::ReadWrite
            } else if read {
                RelayAccess::ReadOnly
            } else {
                return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
            };
            let (kind, policy) = if url.starts_with("wss://") {
                (RelayProfileKind::Public, RelayUrlPolicy::Public)
            } else if configuration.profile() == MycConfigProfile::RepoLocal
                && url.starts_with("ws://")
            {
                (RelayProfileKind::Simulator, RelayUrlPolicy::Local)
            } else {
                return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
            };
            let endpoint = RelayEndpoint::new(url, policy, access)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            match kind {
                RelayProfileKind::Public => public.push(endpoint),
                RelayProfileKind::Simulator => local.push(endpoint),
                RelayProfileKind::Device => {
                    return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
                }
                _ => return Err(adapter_error(MycRelayAdapterErrorKind::Configuration)),
            }
            definitions.push((id, url.to_owned(), kind));
        }
        let public_transport = build_transport(
            RelayProfileKind::Public,
            public,
            connect_timeout,
            request_timeout,
        )?;
        let local_transport = build_transport(
            RelayProfileKind::Simulator,
            local,
            connect_timeout,
            request_timeout,
        )?;
        let mut targets = BTreeMap::new();
        for (id, url, kind) in definitions {
            let transport = match kind {
                RelayProfileKind::Public => public_transport.clone(),
                RelayProfileKind::Simulator => local_transport.clone(),
                RelayProfileKind::Device => None,
                _ => None,
            }
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let target = Target::nostr_relay(url)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
            if targets
                .insert(id, RelayTarget { transport, target })
                .is_some()
            {
                return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
            }
        }
        if targets.is_empty() {
            return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
        }
        Ok(Self { targets })
    }

    pub(crate) async fn probe_required_relays(
        configuration: &MycConfigDocumentV1,
        deadline_unix_ms: u64,
    ) -> Result<(), MycRelayAdapterError> {
        let relays = configuration
            .normalized()
            .pointer("/relays")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
        let connect_timeout =
            configuration_integer(configuration, "/transport/connect_deadline_ms")?;
        let request_timeout = configuration_integer(
            configuration,
            "/transport/publish_retry/attempt_deadline_ms",
        )?;
        let mut public = Vec::new();
        let mut public_targets = Vec::new();
        let mut local = Vec::new();
        let mut local_targets = Vec::new();
        for relay in relays.iter().filter(|relay| {
            relay
                .pointer("/required")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }) {
            let url = relay
                .pointer("/url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            let target = Target::nostr_relay(url)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
            let (kind, policy) = if url.starts_with("wss://") {
                (RelayProfileKind::Public, RelayUrlPolicy::Public)
            } else if configuration.profile() == MycConfigProfile::RepoLocal
                && url.starts_with("ws://")
            {
                (RelayProfileKind::Simulator, RelayUrlPolicy::Local)
            } else {
                return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
            };
            let endpoint = RelayEndpoint::new(url, policy, RelayAccess::ReadOnly)
                .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
            match kind {
                RelayProfileKind::Public => {
                    public.push(endpoint);
                    public_targets.push(target);
                }
                RelayProfileKind::Simulator => {
                    local.push(endpoint);
                    local_targets.push(target);
                }
                RelayProfileKind::Device => {
                    return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
                }
                _ => return Err(adapter_error(MycRelayAdapterErrorKind::Configuration)),
            }
        }
        if public_targets.is_empty() && local_targets.is_empty() {
            return Err(adapter_error(MycRelayAdapterErrorKind::Configuration));
        }
        probe_group(
            RelayProfileKind::Public,
            public,
            public_targets,
            connect_timeout,
            request_timeout,
            deadline_unix_ms,
            "myc-doctor-public",
        )
        .await?;
        probe_group(
            RelayProfileKind::Simulator,
            local,
            local_targets,
            connect_timeout,
            request_timeout,
            deadline_unix_ms,
            "myc-doctor-local",
        )
        .await
    }
}

async fn probe_group(
    kind: RelayProfileKind,
    endpoints: Vec<RelayEndpoint>,
    targets: Vec<Target>,
    connect_timeout: u64,
    request_timeout: u64,
    deadline_unix_ms: u64,
    request_id: &'static str,
) -> Result<(), MycRelayAdapterError> {
    if targets.is_empty() {
        return Ok(());
    }
    let transport = build_transport(kind, endpoints, connect_timeout, request_timeout)?
        .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
    let target_set =
        TargetSet::new(targets).map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
    let selector = FetchSelector::all()
        .with_since_unix_seconds(u64::MAX)
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
    let request = FetchRequest::new(
        request_id,
        target_set,
        FetchBounds::new(1, deadline_unix_ms)
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?,
    )
    .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?
    .with_selector(selector);
    let page = transport
        .fetch(request)
        .await
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Execution))?;
    if page.target_outcomes().is_empty()
        || page.target_outcomes().iter().any(|outcome| {
            !matches!(
                outcome.state(),
                FetchTargetState::Complete | FetchTargetState::Partial
            )
        })
    {
        return Err(adapter_error(MycRelayAdapterErrorKind::Execution));
    }
    Ok(())
}

impl MycRelayAdapter for MycNostrDeliveryAdapter {
    type Prepared = MycPreparedRelayDelivery;

    fn prepare(
        &self,
        relay_id: &MycDeliveryRelayId,
        request_id: String,
        exact_event_bytes: &[u8],
        deadline_unix_ms: u64,
    ) -> Result<Self::Prepared, MycRelayAdapterError> {
        let binding = self
            .targets
            .get(relay_id)
            .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Target))?;
        let raw = core::str::from_utf8(exact_event_bytes)
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Payload))?;
        let signed = Codec::decode_signed_event(raw)
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Payload))?;
        if signed.raw_json().as_bytes() != exact_event_bytes {
            return Err(adapter_error(MycRelayAdapterErrorKind::Payload));
        }
        let targets = TargetSet::new(vec![binding.target.clone()])
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Target))?;
        let request = DeliveryRequest::new(
            request_id,
            DeliveryPayload::new(signed),
            targets,
            SatisfactionPolicy::new(SatisfactionClass::Accepted, TargetPolicy::all()),
            deadline_unix_ms,
        )
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Preparation))?;
        let prepared = binding
            .transport
            .prepare_delivery(request)
            .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Preparation))?;
        Ok(MycPreparedRelayDelivery {
            transport: binding.transport.clone(),
            prepared,
        })
    }

    fn execute<'a>(&'a self, prepared: Self::Prepared) -> RelayExecutionFuture<'a> {
        Box::pin(async move {
            let MycPreparedRelayDelivery {
                transport,
                prepared,
            } = prepared;
            match transport.execute_prepared_delivery(prepared).await {
                Err(_) => Ok(MycRelayExecutionOutcome::UnknownAcknowledgement),
                Ok(receipt) => classify_receipt(receipt.target_receipts()),
            }
        })
    }
}

fn classify_receipt(
    receipts: &[DeliveryTargetReceipt],
) -> Result<MycRelayExecutionOutcome, MycRelayAdapterError> {
    let [receipt] = receipts else {
        return Err(adapter_error(MycRelayAdapterErrorKind::Execution));
    };
    Ok(match receipt.outcome().kind() {
        DeliveryOutcomeKind::Accepted | DeliveryOutcomeKind::Delivered => {
            MycRelayExecutionOutcome::Accepted
        }
        DeliveryOutcomeKind::Rejected => MycRelayExecutionOutcome::Rejected,
        DeliveryOutcomeKind::Unavailable | DeliveryOutcomeKind::Failed => {
            MycRelayExecutionOutcome::TransportFailed
        }
    })
}

fn build_transport(
    kind: RelayProfileKind,
    endpoints: Vec<RelayEndpoint>,
    connect_timeout: u64,
    request_timeout: u64,
) -> Result<Option<NostrTransport>, MycRelayAdapterError> {
    if endpoints.is_empty() {
        return Ok(None);
    }
    let maximum_connections = endpoints.len().min(8);
    let profile = RelayProfile::explicit(kind, endpoints)
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
    let config = Config::from_profile(profile)
        .with_timeouts(connect_timeout, request_timeout, connect_timeout)
        .and_then(|config| config.with_max_connections(maximum_connections))
        .map_err(|_| adapter_error(MycRelayAdapterErrorKind::Configuration))?;
    Ok(Some(NostrTransport::new(config)))
}

fn configuration_integer(
    configuration: &MycConfigDocumentV1,
    pointer: &str,
) -> Result<u64, MycRelayAdapterError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| adapter_error(MycRelayAdapterErrorKind::Configuration))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use nostr::{EventBuilder, JsonUtil as _, Keys};
    use radroots_transport::{
        outcome::{DeliveryOutcome, Retryability},
        sink::DeliveryTargetReceipt,
    };

    use super::*;
    use crate::{MycConfigProfile, parse_myc_config_v1};

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn receipt(outcome: DeliveryOutcome) -> DeliveryTargetReceipt {
        DeliveryTargetReceipt::attempted(
            Target::nostr_relay("wss://relay.example.test/").expect("target"),
            outcome,
        )
    }

    #[test]
    fn receipt_classification_preserves_all_four_durable_outcomes() {
        for (outcome, expected) in [
            (
                DeliveryOutcome::accepted(),
                MycRelayExecutionOutcome::Accepted,
            ),
            (
                DeliveryOutcome::delivered(),
                MycRelayExecutionOutcome::Accepted,
            ),
            (
                DeliveryOutcome::rejected(),
                MycRelayExecutionOutcome::Rejected,
            ),
            (
                DeliveryOutcome::unavailable(),
                MycRelayExecutionOutcome::TransportFailed,
            ),
            (
                DeliveryOutcome::failed(Retryability::Retryable).expect("failed"),
                MycRelayExecutionOutcome::TransportFailed,
            ),
        ] {
            assert_eq!(classify_receipt(&[receipt(outcome)]).unwrap(), expected);
        }
        assert!(classify_receipt(&[]).is_err());
        assert!(
            classify_receipt(&[
                receipt(DeliveryOutcome::accepted()),
                receipt(DeliveryOutcome::accepted()),
            ])
            .is_err()
        );
    }

    #[test]
    fn exact_config_builds_without_network_io_and_errors_are_redacted() {
        let configuration = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("configuration");
        let adapter = MycNostrDeliveryAdapter::from_configuration(&configuration)
            .expect("offline adapter construction");
        assert_eq!(adapter.targets.len(), 2);
        let signing_keys = Keys::parse(&format!("02{}", "00".repeat(31))).expect("test keys");
        let event = EventBuilder::text_note("exact committed payload")
            .sign_with_keys(&signing_keys)
            .expect("signed event");
        let exact = event.as_json();
        let relay = MycDeliveryRelayId::new("primary").expect("relay");
        let prepared = adapter
            .prepare(&relay, "offline-prepare".to_owned(), exact.as_bytes(), 1)
            .expect("offline prepared delivery");
        assert_eq!(
            format!("{prepared:?}"),
            "MycPreparedRelayDelivery([redacted])"
        );
        for kind in [
            MycRelayAdapterErrorKind::Configuration,
            MycRelayAdapterErrorKind::Target,
            MycRelayAdapterErrorKind::Payload,
            MycRelayAdapterErrorKind::Preparation,
            MycRelayAdapterErrorKind::Execution,
        ] {
            let error = adapter_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.source().is_none());
            assert!(!format!("{error} {error:?}").contains("relay.example"));
        }
    }
}
