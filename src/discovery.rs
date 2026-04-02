use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrError, RadrootsNostrEvent,
    RadrootsNostrFilter, RadrootsNostrKind, RadrootsNostrMetadata, RadrootsNostrRelayUrl,
    radroots_nostr_build_application_handler_event, radroots_nostr_filter_tag,
    radroots_nostr_metadata_has_fields, radroots_nostr_tag_first_value,
};
use radroots_nostr_connect::prelude::{RadrootsNostrConnectBunkerUri, RadrootsNostrConnectUri};
use radroots_nostr_signer::prelude::RadrootsNostrSignerRequestId;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::config::MycDiscoveryMetadataConfig;
use crate::custody::{MycActiveIdentity, MycIdentityProvider};
use crate::error::MycError;
use crate::outbox::{MycDeliveryOutboxKind, MycDeliveryOutboxRecord};
use crate::transport::{MycNostrTransport, MycPublishOutcome, MycRelayPublishResult};

const NIP46_RPC_KIND: u32 = 24_133;
const DISCOVERY_BUNDLE_VERSION: u32 = 1;
const DISCOVERY_BUNDLE_MANIFEST_FILE_NAME: &str = "bundle.json";
const DISCOVERY_BUNDLE_NIP89_FILE_NAME: &str = "nip89-handler.json";
const DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH: &str = ".well-known/nostr.json";
const DISCOVERY_RELAY_FETCH_CONCURRENCY_LIMIT: usize = 8;

#[derive(Clone)]
pub struct MycDiscoveryContext {
    app_identity: MycActiveIdentity,
    signer_identity: MycActiveIdentity,
    domain: String,
    handler_identifier: String,
    public_relays: Vec<RadrootsNostrRelayUrl>,
    publish_relays: Vec<RadrootsNostrRelayUrl>,
    nostrconnect_url: Option<String>,
    metadata: Option<RadrootsNostrMetadata>,
    nip05_output_path: Option<PathBuf>,
    connect_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycNip05Document {
    pub names: BTreeMap<String, String>,
    pub nip46: MycNip05DocumentSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycNip05DocumentSection {
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostrconnect_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRenderedNip05Output {
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<PathBuf>,
    pub document: MycNip05Document,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRenderedNip89Output {
    pub author_public_key_hex: String,
    pub signer_public_key_hex: String,
    pub publish_relays: Vec<String>,
    pub event: RadrootsNostrEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycPublishedNip89Output {
    pub author_public_key_hex: String,
    pub signer_public_key_hex: String,
    pub publish_relays: Vec<String>,
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub relay_outcome_summary: String,
    pub relay_results: Vec<MycRelayPublishResult>,
    pub event: RadrootsNostrEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycDiscoveryRepairOutcome {
    Repaired,
    Failed,
    Unchanged,
    Skipped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryRepairSummary {
    pub repaired: usize,
    pub failed: usize,
    pub unchanged: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryRelayRepairResult {
    pub relay_url: String,
    pub outcome: MycDiscoveryRepairOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycDiscoveryLiveStatus {
    Missing,
    Matched,
    Drifted,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycNormalizedNip89Handler {
    pub author_public_key_hex: String,
    pub kinds: Vec<u32>,
    pub identifier: String,
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostrconnect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RadrootsNostrMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycLiveNip89Event {
    pub event_id_hex: String,
    pub created_at_unix: u64,
    pub source_relays: Vec<String>,
    pub handler: MycNormalizedNip89Handler,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycLiveNip89Group {
    pub handler: MycNormalizedNip89Handler,
    pub source_relays: Vec<String>,
    pub events: Vec<MycLiveNip89Event>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycLiveNip89RelayState {
    pub relay_url: String,
    pub fetch_status: MycDiscoveryRelayFetchStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetch_error: Option<String>,
    pub live_groups: Vec<MycLiveNip89Group>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycDiscoveryRelayFetchStatus {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryRelayState {
    pub relay_url: String,
    pub fetch_status: MycDiscoveryRelayFetchStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetch_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_status: Option<MycDiscoveryLiveStatus>,
    pub differing_fields: Vec<String>,
    pub live_groups: Vec<MycLiveNip89Group>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryRelaySummary {
    pub total_relays: usize,
    pub unavailable_relays: Vec<String>,
    pub missing_relays: Vec<String>,
    pub matched_relays: Vec<String>,
    pub drifted_relays: Vec<String>,
    pub conflicted_relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycFetchedLiveNip89Output {
    pub author_public_key_hex: String,
    pub publish_relays: Vec<String>,
    pub handler_identifier: String,
    pub live_groups: Vec<MycLiveNip89Group>,
    pub relay_states: Vec<MycLiveNip89RelayState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryDiffOutput {
    pub status: MycDiscoveryLiveStatus,
    pub local_handler: MycNormalizedNip89Handler,
    pub live_groups: Vec<MycLiveNip89Group>,
    pub relay_states: Vec<MycDiscoveryRelayState>,
    pub relay_summary: MycDiscoveryRelaySummary,
    pub differing_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRefreshedNip89Output {
    pub attempt_id: String,
    pub status: MycDiscoveryLiveStatus,
    pub force: bool,
    pub differing_fields: Vec<String>,
    pub live_groups: Vec<MycLiveNip89Group>,
    pub relay_states: Vec<MycDiscoveryRelayState>,
    pub relay_summary: MycDiscoveryRelaySummary,
    pub repair_summary: MycDiscoveryRepairSummary,
    pub repair_results: Vec<MycDiscoveryRelayRepairResult>,
    pub remaining_repair_relays: Vec<String>,
    pub published: Option<MycPublishedNip89Output>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycDiscoveryRefreshPlan {
    selected_relays: Vec<RadrootsNostrRelayUrl>,
    planned_repair_relays: Vec<String>,
}

#[derive(Debug, Clone)]
struct MycSourcedLiveNip89Event {
    source_relay: String,
    event: RadrootsNostrEvent,
}

#[derive(Debug, Clone)]
struct MycFetchedLiveNip89State {
    live_groups: Vec<MycLiveNip89Group>,
    relay_states: Vec<MycLiveNip89RelayState>,
}

#[derive(Debug)]
struct MycRelayFetchTaskOutput {
    relay_index: usize,
    relay_events: Vec<MycSourcedLiveNip89Event>,
    relay_state: MycLiveNip89RelayState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycNip89HandlerDocument {
    pub kinds: Vec<u32>,
    pub identifier: String,
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostrconnect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RadrootsNostrMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycDiscoveryBundleManifest {
    pub version: u32,
    pub domain: String,
    pub author_public_key_hex: String,
    pub signer_public_key_hex: String,
    pub public_relays: Vec<String>,
    pub publish_relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostrconnect_url: Option<String>,
    pub nip05_relative_path: String,
    pub nip89_relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDiscoveryBundleOutput {
    pub output_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub nip05_path: PathBuf,
    pub nip89_handler_path: PathBuf,
    pub manifest: MycDiscoveryBundleManifest,
    pub nip05_document: MycNip05Document,
    pub nip89_handler: MycNip89HandlerDocument,
}

impl MycDiscoveryContext {
    pub fn from_runtime(runtime: &MycRuntime) -> Result<Self, MycError> {
        let discovery = &runtime.config().discovery;
        if !discovery.enabled {
            return Err(MycError::InvalidOperation(
                "discovery.enabled must be true to use discovery commands".to_owned(),
            ));
        }

        let app_identity = match discovery.app_identity_source() {
            Some(source) => MycIdentityProvider::from_source(
                "discovery app",
                source,
                Duration::from_secs(runtime.config().custody.external_command_timeout_secs),
            )?
            .load_active_identity()?,
            None => runtime.signer_identity().clone(),
        };
        let public_relays = discovery.resolved_public_relays(&runtime.config().transport)?;
        let publish_relays = discovery.resolved_publish_relays(&runtime.config().transport)?;
        let nostrconnect_url = discovery
            .nostrconnect_url_template
            .as_deref()
            .map(|template| {
                render_nostrconnect_url(template, runtime.signer_identity(), &public_relays)
            })
            .transpose()?;

        Ok(Self {
            app_identity,
            signer_identity: runtime.signer_identity().clone(),
            domain: discovery.domain.clone().ok_or_else(|| {
                MycError::InvalidConfig(
                    "discovery.domain must be set when discovery.enabled is true".to_owned(),
                )
            })?,
            handler_identifier: discovery.handler_identifier.clone(),
            public_relays,
            publish_relays,
            nostrconnect_url,
            metadata: build_metadata(&discovery.metadata),
            nip05_output_path: discovery.nip05_output_path.clone(),
            connect_timeout_secs: runtime.config().transport.connect_timeout_secs,
        })
    }

    pub fn app_identity(&self) -> &MycActiveIdentity {
        &self.app_identity
    }

    pub fn signer_identity(&self) -> &MycActiveIdentity {
        &self.signer_identity
    }

    pub fn domain(&self) -> &str {
        self.domain.as_str()
    }

    pub fn handler_identifier(&self) -> &str {
        self.handler_identifier.as_str()
    }

    pub fn publish_relays(&self) -> &[RadrootsNostrRelayUrl] {
        self.publish_relays.as_slice()
    }

    pub fn connect_timeout_secs(&self) -> u64 {
        self.connect_timeout_secs
    }

    pub fn nip05_output_path(&self) -> Option<&Path> {
        self.nip05_output_path.as_deref()
    }

    pub fn render_nip05_document(&self) -> MycNip05Document {
        let mut names = BTreeMap::new();
        names.insert("_".to_owned(), self.app_identity.public_key_hex());
        MycNip05Document {
            names,
            nip46: MycNip05DocumentSection {
                relays: self.public_relays.iter().map(ToString::to_string).collect(),
                nostrconnect_url: self.nostrconnect_url.clone(),
            },
        }
    }

    pub fn render_nip05_json_pretty(&self) -> Result<String, MycError> {
        Ok(serde_json::to_string_pretty(&self.render_nip05_document())?)
    }

    pub fn render_nip05_output(&self, output_path: Option<PathBuf>) -> MycRenderedNip05Output {
        MycRenderedNip05Output {
            domain: self.domain.clone(),
            output_path,
            document: self.render_nip05_document(),
        }
    }

    pub fn write_nip05_document(
        &self,
        output_path: impl AsRef<Path>,
    ) -> Result<MycRenderedNip05Output, MycError> {
        let output_path = output_path.as_ref().to_path_buf();
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| MycError::DiscoveryIo {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let json = self.render_nip05_json_pretty()?;
        fs::write(&output_path, json).map_err(|source| MycError::DiscoveryIo {
            path: output_path.clone(),
            source,
        })?;
        Ok(self.render_nip05_output(Some(output_path)))
    }

    pub fn render_nip89_output(&self) -> Result<MycRenderedNip89Output, MycError> {
        let event = self.build_signed_handler_event()?;
        Ok(MycRenderedNip89Output {
            author_public_key_hex: self.app_identity.public_key_hex(),
            signer_public_key_hex: self.signer_identity.public_key_hex(),
            publish_relays: self
                .publish_relays
                .iter()
                .map(ToString::to_string)
                .collect(),
            event,
        })
    }

    pub fn render_nip89_handler_document(&self) -> MycNip89HandlerDocument {
        MycNip89HandlerDocument {
            kinds: vec![NIP46_RPC_KIND],
            identifier: self.handler_identifier.clone(),
            relays: self.public_relays.iter().map(ToString::to_string).collect(),
            nostrconnect_url: self.nostrconnect_url.clone(),
            metadata: self.metadata.clone(),
        }
    }

    pub fn render_normalized_nip89_handler(&self) -> MycNormalizedNip89Handler {
        MycNormalizedNip89Handler {
            author_public_key_hex: self.app_identity.public_key_hex(),
            kinds: vec![NIP46_RPC_KIND],
            identifier: self.handler_identifier.clone(),
            relays: normalize_string_list(
                self.public_relays.iter().map(ToString::to_string).collect(),
            ),
            nostrconnect_url: normalize_optional_string(self.nostrconnect_url.clone()),
            metadata: normalize_metadata(self.metadata.clone()),
        }
    }

    pub fn render_bundle_manifest(&self) -> MycDiscoveryBundleManifest {
        MycDiscoveryBundleManifest {
            version: DISCOVERY_BUNDLE_VERSION,
            domain: self.domain.clone(),
            author_public_key_hex: self.app_identity.public_key_hex(),
            signer_public_key_hex: self.signer_identity.public_key_hex(),
            public_relays: self.public_relays.iter().map(ToString::to_string).collect(),
            publish_relays: self
                .publish_relays
                .iter()
                .map(ToString::to_string)
                .collect(),
            nostrconnect_url: self.nostrconnect_url.clone(),
            nip05_relative_path: DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH.to_owned(),
            nip89_relative_path: DISCOVERY_BUNDLE_NIP89_FILE_NAME.to_owned(),
        }
    }

    pub fn build_signed_handler_event(&self) -> Result<RadrootsNostrEvent, MycError> {
        let builder = radroots_nostr_build_application_handler_event(&self.build_handler_spec())?;
        self.app_identity
            .sign_event_builder(builder, "NIP-89 application handler")
    }

    pub fn write_bundle(
        &self,
        output_dir: impl AsRef<Path>,
    ) -> Result<MycDiscoveryBundleOutput, MycError> {
        let output_dir = output_dir.as_ref().to_path_buf();
        let staged_output_dir = prepare_staged_output_dir(&output_dir)?;

        let manifest = self.render_bundle_manifest();
        let nip05_document = self.render_nip05_document();
        let nip89_handler = self.render_nip89_handler_document();
        let manifest_path = staged_output_dir.join(DISCOVERY_BUNDLE_MANIFEST_FILE_NAME);
        let nip05_path = staged_output_dir.join(DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH);
        let nip89_handler_path = staged_output_dir.join(DISCOVERY_BUNDLE_NIP89_FILE_NAME);

        write_pretty_json(&manifest_path, &manifest)?;
        write_pretty_json(&nip05_path, &nip05_document)?;
        write_pretty_json(&nip89_handler_path, &nip89_handler)?;
        replace_directory_atomically(&staged_output_dir, &output_dir)?;
        verify_bundle(&output_dir)
    }

    fn build_handler_spec(&self) -> RadrootsNostrApplicationHandlerSpec {
        let mut spec = RadrootsNostrApplicationHandlerSpec::new(vec![NIP46_RPC_KIND]);
        spec.identifier = Some(self.handler_identifier.clone());
        spec.metadata = self.metadata.clone();
        spec.relays = self.public_relays.iter().map(ToString::to_string).collect();
        spec.nostrconnect_url = self.nostrconnect_url.clone();
        spec
    }
}

pub fn render_nip05_output(
    runtime: &MycRuntime,
    output_path: Option<&Path>,
) -> Result<MycRenderedNip05Output, MycError> {
    let context = MycDiscoveryContext::from_runtime(runtime)?;
    match output_path {
        Some(path) => context.write_nip05_document(path),
        None => Ok(context.render_nip05_output(None)),
    }
}

pub async fn publish_nip89_event(
    runtime: &MycRuntime,
) -> Result<MycPublishedNip89Output, MycError> {
    let context = MycDiscoveryContext::from_runtime(runtime)?;
    publish_nip89_event_to_relays(runtime, &context, context.publish_relays(), None).await
}

async fn publish_nip89_event_to_relays(
    runtime: &MycRuntime,
    context: &MycDiscoveryContext,
    relays: &[RadrootsNostrRelayUrl],
    attempt_id: Option<&str>,
) -> Result<MycPublishedNip89Output, MycError> {
    let event = context.build_signed_handler_event()?;
    let event_id = event.id.to_hex();
    let outbox_record =
        build_discovery_outbox_record(event.clone(), relays, event_id.as_str(), attempt_id)?;
    if let Err(error) = runtime.delivery_outbox_store().enqueue(&outbox_record) {
        record_discovery_publish_local_failure(
            runtime,
            relays.len(),
            event_id.as_str(),
            attempt_id,
            error.to_string(),
        );
        return Err(error);
    }
    let publish_outcome = match MycNostrTransport::publish_event_once(
        context.app_identity(),
        relays,
        &runtime.config().transport,
        "discovery handler publish",
        &event,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let error = mark_discovery_outbox_publish_failed(runtime, &outbox_record, error);
            record_discovery_publish_failure(
                runtime,
                relays.len(),
                event_id.as_str(),
                attempt_id,
                &error,
            );
            return Err(error);
        }
    };
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_published_pending_finalize(&outbox_record.job_id, publish_outcome.attempt_count)
    {
        record_discovery_post_publish_failure(
            runtime,
            event_id.as_str(),
            attempt_id,
            &publish_outcome,
            format!("failed to persist discovery outbox published state: {error}"),
        );
        return Err(error);
    }
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_finalized(&outbox_record.job_id)
    {
        record_discovery_post_publish_failure(
            runtime,
            event_id.as_str(),
            attempt_id,
            &publish_outcome,
            format!("failed to finalize discovery outbox job: {error}"),
        );
        return Err(error);
    }

    record_discovery_publish_success(runtime, event_id.as_str(), attempt_id, &publish_outcome);

    Ok(MycPublishedNip89Output {
        author_public_key_hex: context.app_identity().public_key_hex(),
        signer_public_key_hex: context.signer_identity().public_key_hex(),
        publish_relays: relays.iter().map(ToString::to_string).collect(),
        relay_count: publish_outcome.relay_count,
        acknowledged_relay_count: publish_outcome.acknowledged_relay_count,
        relay_outcome_summary: publish_outcome.relay_outcome_summary,
        relay_results: publish_outcome.relay_results,
        event,
    })
}

pub async fn fetch_live_nip89(runtime: &MycRuntime) -> Result<MycFetchedLiveNip89Output, MycError> {
    let context = MycDiscoveryContext::from_runtime(runtime)?;
    let fetched = fetch_live_nip89_state_for_runtime(runtime, &context, None).await?;
    Ok(MycFetchedLiveNip89Output {
        author_public_key_hex: context.app_identity().public_key_hex(),
        publish_relays: context
            .publish_relays()
            .iter()
            .map(ToString::to_string)
            .collect(),
        handler_identifier: context.handler_identifier().to_owned(),
        live_groups: fetched.live_groups,
        relay_states: fetched.relay_states,
    })
}

pub async fn diff_live_nip89(runtime: &MycRuntime) -> Result<MycDiscoveryDiffOutput, MycError> {
    let context = MycDiscoveryContext::from_runtime(runtime)?;
    let local_handler = context.render_normalized_nip89_handler();
    let fetched = fetch_live_nip89_state_for_runtime(runtime, &context, None).await?;
    let relay_states = build_relay_diffs(&local_handler, &fetched.relay_states);
    let relay_summary = summarize_relay_diffs(&relay_states);
    let live_groups = fetched.live_groups;
    let (status, differing_fields) = compare_live_handler(&local_handler, &live_groups);
    Ok(MycDiscoveryDiffOutput {
        status,
        local_handler,
        live_groups,
        relay_states,
        relay_summary,
        differing_fields,
    })
}

pub async fn refresh_nip89(
    runtime: &MycRuntime,
    force: bool,
) -> Result<MycRefreshedNip89Output, MycError> {
    let context = MycDiscoveryContext::from_runtime(runtime)?;
    let attempt_id = RadrootsNostrSignerRequestId::new_v7().into_string();
    let configured_publish_relays = relay_urls_to_strings(context.publish_relays());
    let local_handler = context.render_normalized_nip89_handler();
    let fetched = match fetch_live_nip89_state_for_runtime(
        runtime,
        &context,
        Some(attempt_id.as_str()),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(MycError::DiscoveryFetchUnavailable {
            relay_count,
            details,
        }) => {
            runtime.record_operation_audit(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Unavailable,
                    None,
                    None,
                    relay_count,
                    0,
                    details.clone(),
                )
                .with_attempt_id(attempt_id.clone())
                .with_blocked_relays("all_relays_unavailable", configured_publish_relays.clone()),
            );
            return Err(MycError::DiscoveryFetchUnavailable {
                relay_count,
                details,
            }
            .with_discovery_refresh_attempt_id(attempt_id));
        }
        Err(error) => {
            return Err(error.with_discovery_refresh_attempt_id(attempt_id));
        }
    };
    let relay_states = build_relay_diffs(&local_handler, &fetched.relay_states);
    let relay_summary = summarize_relay_diffs(&relay_states);
    let live_groups = fetched.live_groups;
    let (status, differing_fields) = compare_live_handler(&local_handler, &live_groups);
    let relay_count = context.publish_relays().len();
    let compare_request_id = latest_live_event_id(&live_groups);
    let compare_summary =
        describe_compare_status(status, &differing_fields, &live_groups, &relay_summary);
    let blocked_refresh_plan = build_refresh_plan(&context, &relay_states, true)
        .map_err(|error| error.with_discovery_refresh_attempt_id(attempt_id.clone()))?;

    runtime.record_operation_audit(
        &MycOperationAuditRecord::new(
            MycOperationAuditKind::DiscoveryHandlerCompare,
            compare_status_to_audit_outcome(status),
            None,
            compare_request_id,
            relay_count,
            relay_count.saturating_sub(relay_summary.unavailable_relays.len()),
            compare_summary,
        )
        .with_attempt_id(attempt_id.clone()),
    );

    if !relay_summary.unavailable_relays.is_empty() && !force {
        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRefresh,
                MycOperationAuditOutcome::Unavailable,
                None,
                compare_request_id,
                relay_count,
                relay_count.saturating_sub(relay_summary.unavailable_relays.len()),
                format!(
                    "discovery relays were unavailable; rerun refresh with --force to override: {}",
                    relay_summary.unavailable_relays.join(", ")
                ),
            )
            .with_attempt_id(attempt_id.clone())
            .with_planned_repair_relays(blocked_refresh_plan.planned_repair_relays.clone())
            .with_blocked_relays(
                "unavailable_relays",
                relay_summary.unavailable_relays.clone(),
            ),
        );
        return Err(
            MycError::InvalidOperation(format!(
                "one or more discovery relays were unavailable; rerun `discovery refresh-nip89 --force` to override: {}",
                relay_summary.unavailable_relays.join(", ")
            ))
            .with_discovery_refresh_attempt_id(attempt_id),
        );
    }

    if !relay_summary.conflicted_relays.is_empty() && !force {
        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRefresh,
                MycOperationAuditOutcome::Conflicted,
                None,
                compare_request_id,
                relay_count,
                relay_count.saturating_sub(relay_summary.unavailable_relays.len()),
                "live discovery handler state is conflicted; rerun refresh with --force to override"
                    .to_owned(),
            )
            .with_attempt_id(attempt_id.clone())
            .with_planned_repair_relays(blocked_refresh_plan.planned_repair_relays.clone())
            .with_blocked_relays(
                "conflicted_relays",
                relay_summary.conflicted_relays.clone(),
            ),
        );
        return Err(
            MycError::InvalidOperation(
                "live discovery handler state is conflicted; rerun `discovery refresh-nip89 --force` to override"
                    .to_owned(),
            )
            .with_discovery_refresh_attempt_id(attempt_id),
        );
    }

    let refresh_plan = build_refresh_plan(&context, &relay_states, force)
        .map_err(|error| error.with_discovery_refresh_attempt_id(attempt_id.clone()))?;
    let refresh_relays = refresh_plan.selected_relays;
    let refresh_relay_urls = relay_urls_to_strings(&refresh_relays);

    if refresh_relays.is_empty() {
        let repair_results = build_repair_results(&context, &relay_states, &[], None, None);
        let repair_summary = summarize_repair_results(&repair_results);
        record_refresh_repair_audit(
            runtime,
            compare_request_id.map(ToOwned::to_owned),
            attempt_id.as_str(),
            &repair_results,
        );
        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRefresh,
                MycOperationAuditOutcome::Skipped,
                None,
                compare_request_id,
                relay_count,
                relay_count.saturating_sub(relay_summary.unavailable_relays.len()),
                "local discovery handler already matches live state".to_owned(),
            )
            .with_attempt_id(attempt_id.clone())
            .with_planned_repair_relays(refresh_relay_urls.clone()),
        );
        return Ok(MycRefreshedNip89Output {
            attempt_id,
            status,
            force,
            differing_fields,
            live_groups,
            relay_states,
            relay_summary,
            repair_summary,
            repair_results,
            remaining_repair_relays: Vec::new(),
            published: None,
        });
    }

    match publish_nip89_event_to_relays(
        runtime,
        &context,
        &refresh_relays,
        Some(attempt_id.as_str()),
    )
    .await
    {
        Ok(published) => {
            let published_event_id = published.event.id.to_hex();
            let repair_results = build_repair_results(
                &context,
                &relay_states,
                &refresh_relays,
                Some(published.relay_results.as_slice()),
                None,
            );
            record_refresh_repair_audit(
                runtime,
                Some(published_event_id.clone()),
                attempt_id.as_str(),
                &repair_results,
            );
            let repair_summary = summarize_repair_results(&repair_results);
            let remaining_repair_relays = remaining_repair_relays(&repair_results);
            runtime.record_operation_audit(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Succeeded,
                    None,
                    Some(published_event_id.as_str()),
                    published.relay_count,
                    published.acknowledged_relay_count,
                    format!(
                        "refresh completed with {} repaired, {} failed, {} unchanged, {} skipped",
                        repair_summary.repaired,
                        repair_summary.failed,
                        repair_summary.unchanged,
                        repair_summary.skipped
                    ),
                )
                .with_attempt_id(attempt_id.clone())
                .with_planned_repair_relays(refresh_relay_urls.clone()),
            );
            return Ok(MycRefreshedNip89Output {
                attempt_id,
                status,
                force,
                differing_fields,
                live_groups,
                relay_states,
                relay_summary,
                repair_summary,
                repair_results,
                remaining_repair_relays,
                published: Some(published),
            });
        }
        Err(error) => {
            let repair_results =
                build_repair_results(&context, &relay_states, &refresh_relays, None, Some(&error));
            let repair_summary = summarize_repair_results(&repair_results);
            record_refresh_repair_audit(runtime, None, attempt_id.as_str(), &repair_results);
            runtime.record_operation_audit(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    compare_request_id,
                    relay_count,
                    relay_states
                        .iter()
                        .filter(|relay_state| {
                            relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Available
                        })
                        .count(),
                    format!(
                        "refresh failed with {} repaired, {} failed, {} unchanged, {} skipped",
                        repair_summary.repaired,
                        repair_summary.failed,
                        repair_summary.unchanged,
                        repair_summary.skipped
                    ),
                )
                .with_attempt_id(attempt_id.clone())
                .with_planned_repair_relays(refresh_relay_urls.clone()),
            );
            return Err(error.with_discovery_refresh_attempt_id(attempt_id));
        }
    }
}

fn build_discovery_outbox_record(
    event: RadrootsNostrEvent,
    relays: &[RadrootsNostrRelayUrl],
    event_id: &str,
    attempt_id: Option<&str>,
) -> Result<MycDeliveryOutboxRecord, MycError> {
    let mut record = MycDeliveryOutboxRecord::new(
        MycDeliveryOutboxKind::DiscoveryHandlerPublish,
        event,
        relays.to_vec(),
    )?
    .with_request_id(event_id.to_owned());
    if let Some(attempt_id) = attempt_id {
        record = record.with_attempt_id(attempt_id.to_owned());
    }
    Ok(record)
}

fn mark_discovery_outbox_publish_failed(
    runtime: &MycRuntime,
    outbox_record: &MycDeliveryOutboxRecord,
    error: MycError,
) -> MycError {
    let publish_attempt_count = error.publish_attempt_count().unwrap_or_default();
    let summary = publish_failure_summary(&error);
    match runtime.delivery_outbox_store().mark_failed(
        &outbox_record.job_id,
        publish_attempt_count,
        &summary,
    ) {
        Ok(_) => error,
        Err(outbox_error) => MycError::InvalidOperation(format!(
            "{error}; additionally failed to persist discovery publish failure to the outbox: {outbox_error}"
        )),
    }
}

fn record_discovery_publish_local_failure(
    runtime: &MycRuntime,
    relay_count: usize,
    event_id: &str,
    attempt_id: Option<&str>,
    summary: impl Into<String>,
) {
    let mut record = MycOperationAuditRecord::new(
        MycOperationAuditKind::DiscoveryHandlerPublish,
        MycOperationAuditOutcome::Rejected,
        None,
        Some(event_id),
        relay_count,
        0,
        summary.into(),
    );
    if let Some(attempt_id) = attempt_id {
        record = record.with_attempt_id(attempt_id);
    }
    runtime.record_operation_audit(&record);
}

fn record_discovery_publish_failure(
    runtime: &MycRuntime,
    relay_count: usize,
    event_id: &str,
    attempt_id: Option<&str>,
    error: &MycError,
) {
    let mut record = MycOperationAuditRecord::new(
        MycOperationAuditKind::DiscoveryHandlerPublish,
        MycOperationAuditOutcome::Rejected,
        None,
        Some(event_id),
        error
            .publish_rejection_counts()
            .map(|(publish_relay_count, _)| publish_relay_count)
            .unwrap_or(relay_count),
        error
            .publish_rejection_counts()
            .map(|(_, acknowledged)| acknowledged)
            .unwrap_or_default(),
        publish_failure_summary(error),
    );
    if let (Some(delivery_policy), Some(required_acknowledged_relay_count), Some(attempt_count)) = (
        error.publish_delivery_policy(),
        error.publish_required_acknowledged_relay_count(),
        error.publish_attempt_count(),
    ) {
        record = record.with_delivery_details(
            delivery_policy,
            required_acknowledged_relay_count,
            attempt_count,
        );
    }
    if let Some(attempt_id) = attempt_id {
        record = record.with_attempt_id(attempt_id);
    }
    runtime.record_operation_audit(&record);
}

fn record_discovery_post_publish_failure(
    runtime: &MycRuntime,
    event_id: &str,
    attempt_id: Option<&str>,
    publish_outcome: &MycPublishOutcome,
    summary: impl Into<String>,
) {
    let mut record = MycOperationAuditRecord::new(
        MycOperationAuditKind::DiscoveryHandlerPublish,
        MycOperationAuditOutcome::Rejected,
        None,
        Some(event_id),
        publish_outcome.relay_count,
        publish_outcome.acknowledged_relay_count,
        summary.into(),
    )
    .with_delivery_details(
        publish_outcome.delivery_policy,
        publish_outcome.required_acknowledged_relay_count,
        publish_outcome.attempt_count,
    );
    if let Some(attempt_id) = attempt_id {
        record = record.with_attempt_id(attempt_id);
    }
    runtime.record_operation_audit(&record);
}

fn record_discovery_publish_success(
    runtime: &MycRuntime,
    event_id: &str,
    attempt_id: Option<&str>,
    publish_outcome: &MycPublishOutcome,
) {
    let mut record = MycOperationAuditRecord::new(
        MycOperationAuditKind::DiscoveryHandlerPublish,
        MycOperationAuditOutcome::Succeeded,
        None,
        Some(event_id),
        publish_outcome.relay_count,
        publish_outcome.acknowledged_relay_count,
        publish_outcome.relay_outcome_summary.clone(),
    )
    .with_delivery_details(
        publish_outcome.delivery_policy,
        publish_outcome.required_acknowledged_relay_count,
        publish_outcome.attempt_count,
    );
    if let Some(attempt_id) = attempt_id {
        record = record.with_attempt_id(attempt_id);
    }
    runtime.record_operation_audit(&record);
}

fn publish_failure_summary(error: &MycError) -> String {
    error
        .publish_rejection_details()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| error.to_string())
}

fn build_refresh_plan(
    context: &MycDiscoveryContext,
    relay_states: &[MycDiscoveryRelayState],
    force: bool,
) -> Result<MycDiscoveryRefreshPlan, MycError> {
    let selected_relays = select_refresh_relays(context, relay_states, force)?;
    Ok(MycDiscoveryRefreshPlan {
        selected_relays: selected_relays.clone(),
        planned_repair_relays: relay_urls_to_strings(&selected_relays),
    })
}

fn relay_urls_to_strings(relays: &[RadrootsNostrRelayUrl]) -> Vec<String> {
    relays.iter().map(ToString::to_string).collect()
}

fn select_refresh_relays(
    context: &MycDiscoveryContext,
    relay_states: &[MycDiscoveryRelayState],
    force: bool,
) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
    if context.publish_relays().len() != relay_states.len() {
        return Err(MycError::InvalidOperation(
            "discovery relay state count did not match configured publish relay count".to_owned(),
        ));
    }

    let mut repair_relays = Vec::new();
    let mut matched_relays = Vec::new();

    for (relay, relay_state) in context.publish_relays().iter().zip(relay_states.iter()) {
        if relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable {
            continue;
        }

        match relay_state.live_status {
            Some(MycDiscoveryLiveStatus::Missing | MycDiscoveryLiveStatus::Drifted) => {
                repair_relays.push(relay.clone());
            }
            Some(MycDiscoveryLiveStatus::Conflicted) => {
                if force {
                    repair_relays.push(relay.clone());
                }
            }
            Some(MycDiscoveryLiveStatus::Matched) => {
                matched_relays.push(relay.clone());
            }
            None => {}
        }
    }

    if repair_relays.is_empty() && force {
        Ok(matched_relays)
    } else {
        Ok(repair_relays)
    }
}

fn build_repair_results(
    context: &MycDiscoveryContext,
    relay_states: &[MycDiscoveryRelayState],
    refresh_relays: &[RadrootsNostrRelayUrl],
    publish_results: Option<&[MycRelayPublishResult]>,
    publish_error: Option<&MycError>,
) -> Vec<MycDiscoveryRelayRepairResult> {
    let selected_relays = refresh_relays
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let publish_results_by_relay = publish_results
        .unwrap_or_default()
        .iter()
        .map(|result| (result.relay_url.clone(), result))
        .collect::<BTreeMap<_, _>>();
    let rejected_relays = publish_error
        .and_then(MycError::publish_rejected_relays)
        .unwrap_or_default()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    context
        .publish_relays()
        .iter()
        .zip(relay_states.iter())
        .map(|(relay, relay_state)| {
            let relay_url = relay.to_string();
            if selected_relays.contains(&relay_url) {
                if let Some(result) = publish_results_by_relay.get(&relay_url) {
                    return MycDiscoveryRelayRepairResult {
                        relay_url,
                        outcome: if result.acknowledged {
                            MycDiscoveryRepairOutcome::Repaired
                        } else {
                            MycDiscoveryRepairOutcome::Failed
                        },
                        detail: result.detail.clone(),
                    };
                }

                if rejected_relays.contains(&relay_url) {
                    return MycDiscoveryRelayRepairResult {
                        relay_url,
                        outcome: MycDiscoveryRepairOutcome::Failed,
                        detail: Some(
                            publish_error
                                .and_then(MycError::publish_rejection_details)
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| "targeted refresh publish failed".to_owned()),
                        ),
                    };
                }

                return MycDiscoveryRelayRepairResult {
                    relay_url,
                    outcome: MycDiscoveryRepairOutcome::Failed,
                    detail: Some("no relay publish result was reported".to_owned()),
                };
            }

            if relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable {
                return MycDiscoveryRelayRepairResult {
                    relay_url,
                    outcome: MycDiscoveryRepairOutcome::Skipped,
                    detail: relay_state.fetch_error.clone(),
                };
            }

            match relay_state.live_status {
                Some(MycDiscoveryLiveStatus::Matched) => MycDiscoveryRelayRepairResult {
                    relay_url,
                    outcome: MycDiscoveryRepairOutcome::Unchanged,
                    detail: None,
                },
                _ => MycDiscoveryRelayRepairResult {
                    relay_url,
                    outcome: MycDiscoveryRepairOutcome::Skipped,
                    detail: None,
                },
            }
        })
        .collect()
}

fn remaining_repair_relays(repair_results: &[MycDiscoveryRelayRepairResult]) -> Vec<String> {
    repair_results
        .iter()
        .filter(|result| result.outcome == MycDiscoveryRepairOutcome::Failed)
        .map(|result| result.relay_url.clone())
        .collect()
}

fn summarize_repair_results(
    repair_results: &[MycDiscoveryRelayRepairResult],
) -> MycDiscoveryRepairSummary {
    let mut summary = MycDiscoveryRepairSummary::default();
    for result in repair_results {
        match result.outcome {
            MycDiscoveryRepairOutcome::Repaired => summary.repaired += 1,
            MycDiscoveryRepairOutcome::Failed => summary.failed += 1,
            MycDiscoveryRepairOutcome::Unchanged => summary.unchanged += 1,
            MycDiscoveryRepairOutcome::Skipped => summary.skipped += 1,
        }
    }
    summary
}

fn record_refresh_repair_audit(
    runtime: &MycRuntime,
    request_id: Option<String>,
    attempt_id: &str,
    repair_results: &[MycDiscoveryRelayRepairResult],
) {
    for result in repair_results {
        let (outcome, acknowledged_relay_count) = match result.outcome {
            MycDiscoveryRepairOutcome::Repaired => (MycOperationAuditOutcome::Succeeded, 1),
            MycDiscoveryRepairOutcome::Failed => (MycOperationAuditOutcome::Rejected, 0),
            MycDiscoveryRepairOutcome::Unchanged => (MycOperationAuditOutcome::Matched, 0),
            MycDiscoveryRepairOutcome::Skipped => (MycOperationAuditOutcome::Skipped, 0),
        };

        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRepair,
                outcome,
                None,
                request_id.as_deref(),
                1,
                acknowledged_relay_count,
                result
                    .detail
                    .clone()
                    .unwrap_or_else(|| result.relay_url.clone()),
            )
            .with_attempt_id(attempt_id)
            .with_relay_url(result.relay_url.clone()),
        );
    }
}

async fn fetch_live_nip89_state_for_runtime(
    runtime: &MycRuntime,
    context: &MycDiscoveryContext,
    attempt_id: Option<&str>,
) -> Result<MycFetchedLiveNip89State, MycError> {
    match fetch_live_nip89_state(context).await {
        Ok(fetched) => {
            let unavailable_relays = fetched
                .relay_states
                .iter()
                .filter(|relay_state| {
                    relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable
                })
                .collect::<Vec<_>>();
            if !unavailable_relays.is_empty() {
                let mut record = MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerFetch,
                    MycOperationAuditOutcome::Unavailable,
                    None,
                    latest_live_event_id(&fetched.live_groups),
                    fetched.relay_states.len(),
                    fetched.relay_states.len() - unavailable_relays.len(),
                    summarize_unavailable_relays(&fetched.relay_states),
                );
                if let Some(attempt_id) = attempt_id {
                    record = record.with_attempt_id(attempt_id);
                }
                runtime.record_operation_audit(&record);
            }
            Ok(fetched)
        }
        Err(MycError::DiscoveryFetchUnavailable {
            relay_count,
            details,
        }) => {
            let mut record = MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerFetch,
                MycOperationAuditOutcome::Unavailable,
                None,
                None,
                relay_count,
                0,
                details.clone(),
            );
            if let Some(attempt_id) = attempt_id {
                record = record.with_attempt_id(attempt_id);
            }
            runtime.record_operation_audit(&record);
            Err(MycError::DiscoveryFetchUnavailable {
                relay_count,
                details,
            })
        }
        Err(error) => Err(error),
    }
}

pub fn verify_bundle(output_dir: impl AsRef<Path>) -> Result<MycDiscoveryBundleOutput, MycError> {
    let output_dir = output_dir.as_ref().to_path_buf();
    let manifest_path = output_dir.join(DISCOVERY_BUNDLE_MANIFEST_FILE_NAME);
    let manifest = read_json_file::<MycDiscoveryBundleManifest>(&manifest_path)?;
    let nip05_path = output_dir.join(&manifest.nip05_relative_path);
    let nip05_document = read_json_file::<MycNip05Document>(&nip05_path)?;
    let nip89_handler_path = output_dir.join(&manifest.nip89_relative_path);
    let nip89_handler = read_json_file::<MycNip89HandlerDocument>(&nip89_handler_path)?;

    let bundle = MycDiscoveryBundleOutput {
        output_dir,
        manifest_path,
        nip05_path,
        nip89_handler_path,
        manifest,
        nip05_document,
        nip89_handler,
    };
    bundle.validate()?;
    Ok(bundle)
}

async fn fetch_live_nip89_state(
    context: &MycDiscoveryContext,
) -> Result<MycFetchedLiveNip89State, MycError> {
    let relay_count = context.publish_relays().len();
    let mut pending = context
        .publish_relays()
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<_>>()
        .into_iter();
    let mut join_set = JoinSet::new();
    let max_concurrency = relay_count.min(DISCOVERY_RELAY_FETCH_CONCURRENCY_LIMIT);

    while join_set.len() < max_concurrency {
        let Some((relay_index, relay)) = pending.next() else {
            break;
        };
        spawn_live_nip89_relay_fetch(&mut join_set, context.clone(), relay_index, relay);
    }

    let mut fetched = std::iter::repeat_with(|| None)
        .take(relay_count)
        .collect::<Vec<Option<MycRelayFetchTaskOutput>>>();

    while let Some(joined) = join_set.join_next().await {
        let output = joined.map_err(|error| {
            MycError::InvalidOperation(format!("discovery relay fetch task failed: {error}"))
        })??;
        let relay_index = output.relay_index;
        fetched[relay_index] = Some(output);

        while join_set.len() < max_concurrency {
            let Some((relay_index, relay)) = pending.next() else {
                break;
            };
            spawn_live_nip89_relay_fetch(&mut join_set, context.clone(), relay_index, relay);
        }
    }

    let mut relay_states = Vec::with_capacity(relay_count);
    let mut all_events = Vec::new();
    for fetched_relay in fetched {
        let fetched_relay = fetched_relay.ok_or_else(|| {
            MycError::InvalidOperation("missing discovery relay fetch result".to_owned())
        })?;
        all_events.extend(fetched_relay.relay_events.into_iter());
        relay_states.push(fetched_relay.relay_state);
    }

    let available_relay_count = relay_states
        .iter()
        .filter(|relay_state| relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Available)
        .count();
    if available_relay_count == 0 {
        return Err(MycError::DiscoveryFetchUnavailable {
            relay_count: relay_states.len(),
            details: summarize_unavailable_relays(&relay_states),
        });
    }

    Ok(MycFetchedLiveNip89State {
        live_groups: group_live_nip89_events(all_events)?,
        relay_states,
    })
}

fn spawn_live_nip89_relay_fetch(
    join_set: &mut JoinSet<Result<MycRelayFetchTaskOutput, MycError>>,
    context: MycDiscoveryContext,
    relay_index: usize,
    relay: RadrootsNostrRelayUrl,
) {
    join_set.spawn(async move { fetch_live_nip89_relay_state(&context, relay_index, relay).await });
}

async fn fetch_live_nip89_relay_state(
    context: &MycDiscoveryContext,
    relay_index: usize,
    relay: RadrootsNostrRelayUrl,
) -> Result<MycRelayFetchTaskOutput, MycError> {
    let relay_url = relay.to_string();
    match fetch_live_nip89_events_for_relay(context, &relay).await {
        Ok(relay_events) => {
            let live_groups = group_live_nip89_events(relay_events.clone())?;
            Ok(MycRelayFetchTaskOutput {
                relay_index,
                relay_events,
                relay_state: MycLiveNip89RelayState {
                    relay_url,
                    fetch_status: MycDiscoveryRelayFetchStatus::Available,
                    fetch_error: None,
                    live_groups,
                },
            })
        }
        Err(error) => Ok(MycRelayFetchTaskOutput {
            relay_index,
            relay_events: Vec::new(),
            relay_state: MycLiveNip89RelayState {
                relay_url,
                fetch_status: MycDiscoveryRelayFetchStatus::Unavailable,
                fetch_error: Some(error.to_string()),
                live_groups: Vec::new(),
            },
        }),
    }
}

async fn fetch_live_nip89_events_for_relay(
    context: &MycDiscoveryContext,
    relay: &RadrootsNostrRelayUrl,
) -> Result<Vec<MycSourcedLiveNip89Event>, MycError> {
    let client = context.app_identity().nostr_client();
    let _ = client.add_relay(relay.as_str()).await?;
    client
        .try_connect_relay(
            relay.as_str(),
            Duration::from_secs(context.connect_timeout_secs()),
        )
        .await
        .map_err(RadrootsNostrError::from)?;

    let mut filter = RadrootsNostrFilter::new()
        .author(context.app_identity().public_key())
        .kind(RadrootsNostrKind::Custom(31_990));
    filter = radroots_nostr_filter_tag(filter, "d", vec![context.handler_identifier().to_owned()])?;
    filter = radroots_nostr_filter_tag(filter, "k", vec![NIP46_RPC_KIND.to_string()])?;

    let mut events = client
        .fetch_events(filter, Duration::from_secs(context.connect_timeout_secs()))
        .await?;
    events.sort_by(|left, right| {
        left.created_at
            .as_secs()
            .cmp(&right.created_at.as_secs())
            .then_with(|| left.id.to_hex().cmp(&right.id.to_hex()))
    });
    Ok(events
        .into_iter()
        .map(|event| MycSourcedLiveNip89Event {
            source_relay: relay.to_string(),
            event,
        })
        .collect())
}

fn compare_live_handler(
    local_handler: &MycNormalizedNip89Handler,
    live_groups: &[MycLiveNip89Group],
) -> (MycDiscoveryLiveStatus, Vec<String>) {
    if live_groups.is_empty() {
        return (
            MycDiscoveryLiveStatus::Missing,
            vec!["live_groups".to_owned()],
        );
    }
    if live_groups.len() > 1 {
        return (
            MycDiscoveryLiveStatus::Conflicted,
            vec!["live_groups".to_owned()],
        );
    }

    let live_group = &live_groups[0];

    let mut differing_fields = Vec::new();
    if live_group.handler.author_public_key_hex != local_handler.author_public_key_hex {
        differing_fields.push("author_public_key_hex".to_owned());
    }
    if live_group.handler.kinds != local_handler.kinds {
        differing_fields.push("kinds".to_owned());
    }
    if live_group.handler.identifier != local_handler.identifier {
        differing_fields.push("identifier".to_owned());
    }
    if live_group.handler.relays != local_handler.relays {
        differing_fields.push("relays".to_owned());
    }
    if live_group.handler.nostrconnect_url != local_handler.nostrconnect_url {
        differing_fields.push("nostrconnect_url".to_owned());
    }
    if live_group.handler.metadata != local_handler.metadata {
        differing_fields.push("metadata".to_owned());
    }

    if differing_fields.is_empty() {
        (MycDiscoveryLiveStatus::Matched, differing_fields)
    } else {
        (MycDiscoveryLiveStatus::Drifted, differing_fields)
    }
}

fn compare_status_to_audit_outcome(status: MycDiscoveryLiveStatus) -> MycOperationAuditOutcome {
    match status {
        MycDiscoveryLiveStatus::Missing => MycOperationAuditOutcome::Missing,
        MycDiscoveryLiveStatus::Matched => MycOperationAuditOutcome::Matched,
        MycDiscoveryLiveStatus::Drifted => MycOperationAuditOutcome::Drifted,
        MycDiscoveryLiveStatus::Conflicted => MycOperationAuditOutcome::Conflicted,
    }
}

fn describe_compare_status(
    status: MycDiscoveryLiveStatus,
    differing_fields: &[String],
    live_groups: &[MycLiveNip89Group],
    relay_summary: &MycDiscoveryRelaySummary,
) -> String {
    let base = match status {
        MycDiscoveryLiveStatus::Missing => {
            "no live NIP-89 handler was found for the configured discovery identity".to_owned()
        }
        MycDiscoveryLiveStatus::Matched => {
            "local discovery handler matches the latest live NIP-89 handler".to_owned()
        }
        MycDiscoveryLiveStatus::Drifted => format!(
            "local discovery handler differs from live state in: {}",
            differing_fields.join(", ")
        ),
        MycDiscoveryLiveStatus::Conflicted => format!(
            "found {} conflicting live NIP-89 handler states across {} events (matched relays: {}, drifted relays: {}, missing relays: {}, conflicted relays: {})",
            live_groups.len(),
            live_groups
                .iter()
                .map(|group| group.events.len())
                .sum::<usize>(),
            relay_summary.matched_relays.len(),
            relay_summary.drifted_relays.len(),
            relay_summary.missing_relays.len(),
            relay_summary.conflicted_relays.len(),
        ),
    };

    if relay_summary.unavailable_relays.is_empty() {
        base
    } else {
        format!(
            "{base}; unavailable relays: {}",
            relay_summary.unavailable_relays.join(", ")
        )
    }
}

fn normalize_live_nip89_handler(
    event: &RadrootsNostrEvent,
) -> Result<MycNormalizedNip89Handler, MycError> {
    if event.kind != RadrootsNostrKind::Custom(31_990) {
        return Err(MycError::InvalidDiscoveryEvent(format!(
            "expected kind 31990 but found kind {}",
            event.kind.as_u16()
        )));
    }

    let identifier = event
        .tags
        .iter()
        .find_map(|tag| radroots_nostr_tag_first_value(tag, "d"))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            MycError::InvalidDiscoveryEvent(
                "live handler event is missing a non-empty `d` tag".to_owned(),
            )
        })?;

    let mut kinds = event
        .tags
        .iter()
        .filter_map(|tag| radroots_nostr_tag_first_value(tag, "k"))
        .map(|value| {
            value.parse::<u32>().map_err(|error| {
                MycError::InvalidDiscoveryEvent(format!(
                    "failed to parse live handler kind `{value}`: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if kinds.is_empty() {
        return Err(MycError::InvalidDiscoveryEvent(
            "live handler event is missing `k` tags".to_owned(),
        ));
    }
    kinds.sort_unstable();
    kinds.dedup();

    let relays = normalize_string_list(
        event
            .tags
            .iter()
            .filter_map(|tag| radroots_nostr_tag_first_value(tag, "relay"))
            .collect(),
    );
    let nostrconnect_url = normalize_optional_string(
        event
            .tags
            .iter()
            .find_map(|tag| radroots_nostr_tag_first_value(tag, "nostrconnect_url")),
    );
    let metadata = if event.content.trim().is_empty() {
        None
    } else {
        Some(
            serde_json::from_str::<RadrootsNostrMetadata>(&event.content).map_err(|error| {
                MycError::InvalidDiscoveryEvent(format!(
                    "failed to parse live handler metadata: {error}"
                ))
            })?,
        )
    };

    Ok(MycNormalizedNip89Handler {
        author_public_key_hex: event.pubkey.to_hex(),
        kinds,
        identifier,
        relays,
        nostrconnect_url,
        metadata: normalize_metadata(metadata),
    })
}

fn group_live_nip89_events(
    events: Vec<MycSourcedLiveNip89Event>,
) -> Result<Vec<MycLiveNip89Group>, MycError> {
    let mut groups = Vec::<MycLiveNip89Group>::new();
    for sourced_event in events {
        let handler = normalize_live_nip89_handler(&sourced_event.event)?;
        let source_relay = sourced_event.source_relay;
        let live_event = MycLiveNip89Event {
            event_id_hex: sourced_event.event.id.to_hex(),
            created_at_unix: sourced_event.event.created_at.as_secs(),
            source_relays: vec![source_relay.clone()],
            handler: handler.clone(),
        };
        if let Some(existing_group) = groups.iter_mut().find(|group| group.handler == handler) {
            if let Some(existing_event) = existing_group
                .events
                .iter_mut()
                .find(|event| event.event_id_hex == live_event.event_id_hex)
            {
                existing_event.source_relays = normalize_string_list(
                    existing_event
                        .source_relays
                        .iter()
                        .cloned()
                        .chain(std::iter::once(source_relay.clone()))
                        .collect(),
                );
            } else {
                existing_group.events.push(live_event);
            }
            existing_group.source_relays = normalize_string_list(
                existing_group
                    .source_relays
                    .iter()
                    .cloned()
                    .chain(std::iter::once(source_relay))
                    .collect(),
            );
        } else {
            groups.push(MycLiveNip89Group {
                handler: handler.clone(),
                source_relays: vec![source_relay],
                events: vec![live_event],
            });
        }
    }

    for group in &mut groups {
        group.source_relays = normalize_string_list(group.source_relays.clone());
        group.events.sort_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.event_id_hex.cmp(&right.event_id_hex))
        });
        for event in &mut group.events {
            event.source_relays = normalize_string_list(event.source_relays.clone());
        }
    }

    groups.sort_by(|left, right| {
        latest_group_sort_key(right)
            .cmp(&latest_group_sort_key(left))
            .then_with(|| left.handler.identifier.cmp(&right.handler.identifier))
            .then_with(|| {
                left.handler
                    .author_public_key_hex
                    .cmp(&right.handler.author_public_key_hex)
            })
    });

    Ok(groups)
}

fn build_relay_diffs(
    local_handler: &MycNormalizedNip89Handler,
    relay_states: &[MycLiveNip89RelayState],
) -> Vec<MycDiscoveryRelayState> {
    relay_states
        .iter()
        .map(|relay_state| {
            let (live_status, differing_fields) =
                if relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable {
                    (None, Vec::new())
                } else {
                    let (status, differing_fields) =
                        compare_live_handler(local_handler, &relay_state.live_groups);
                    (Some(status), differing_fields)
                };
            MycDiscoveryRelayState {
                relay_url: relay_state.relay_url.clone(),
                fetch_status: relay_state.fetch_status,
                fetch_error: relay_state.fetch_error.clone(),
                live_status,
                differing_fields,
                live_groups: relay_state.live_groups.clone(),
            }
        })
        .collect()
}

fn summarize_relay_diffs(relay_states: &[MycDiscoveryRelayState]) -> MycDiscoveryRelaySummary {
    let mut summary = MycDiscoveryRelaySummary {
        total_relays: relay_states.len(),
        ..MycDiscoveryRelaySummary::default()
    };

    for relay_state in relay_states {
        if relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable {
            summary
                .unavailable_relays
                .push(relay_state.relay_url.clone());
            continue;
        }
        match relay_state.live_status {
            Some(MycDiscoveryLiveStatus::Missing) => {
                summary.missing_relays.push(relay_state.relay_url.clone())
            }
            Some(MycDiscoveryLiveStatus::Matched) => {
                summary.matched_relays.push(relay_state.relay_url.clone())
            }
            Some(MycDiscoveryLiveStatus::Drifted) => {
                summary.drifted_relays.push(relay_state.relay_url.clone())
            }
            Some(MycDiscoveryLiveStatus::Conflicted) => summary
                .conflicted_relays
                .push(relay_state.relay_url.clone()),
            None => {}
        }
    }

    summary
}

fn summarize_unavailable_relays(relay_states: &[MycLiveNip89RelayState]) -> String {
    let unavailable = relay_states
        .iter()
        .filter(|relay_state| relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Unavailable)
        .map(|relay_state| {
            let details = relay_state
                .fetch_error
                .as_deref()
                .unwrap_or("unknown relay fetch failure");
            format!("{}: {details}", relay_state.relay_url)
        })
        .collect::<Vec<_>>();

    if unavailable.is_empty() {
        "all configured discovery relays were available".to_owned()
    } else {
        format!("unavailable discovery relays: {}", unavailable.join("; "))
    }
}

fn latest_group_sort_key(group: &MycLiveNip89Group) -> (u64, &str) {
    group
        .events
        .last()
        .map(|event| (event.created_at_unix, event.event_id_hex.as_str()))
        .unwrap_or((0, ""))
}

fn latest_live_event_id(live_groups: &[MycLiveNip89Group]) -> Option<&str> {
    live_groups
        .first()
        .and_then(|group| group.events.last())
        .map(|event| event.event_id_hex.as_str())
}

fn build_metadata(config: &MycDiscoveryMetadataConfig) -> Option<RadrootsNostrMetadata> {
    let mut metadata = RadrootsNostrMetadata::default();
    metadata.name = sanitize_optional_string(config.name.as_deref());
    metadata.display_name = sanitize_optional_string(config.display_name.as_deref());
    metadata.about = sanitize_optional_string(config.about.as_deref());
    metadata.website = sanitize_optional_string(config.website.as_deref());
    metadata.picture = sanitize_optional_string(config.picture.as_deref());
    if metadata.name.is_none()
        && metadata.display_name.is_none()
        && metadata.about.is_none()
        && metadata.website.is_none()
        && metadata.picture.is_none()
    {
        return None;
    }
    Some(metadata)
}

fn sanitize_optional_string(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    sanitize_optional_string(value.as_deref())
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .filter_map(|value| normalize_optional_string(Some(value)))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn normalize_metadata(metadata: Option<RadrootsNostrMetadata>) -> Option<RadrootsNostrMetadata> {
    let mut metadata = metadata?;
    metadata.name = sanitize_optional_string(metadata.name.as_deref());
    metadata.display_name = sanitize_optional_string(metadata.display_name.as_deref());
    metadata.about = sanitize_optional_string(metadata.about.as_deref());
    metadata.website = sanitize_optional_string(metadata.website.as_deref());
    metadata.picture = sanitize_optional_string(metadata.picture.as_deref());
    if !radroots_nostr_metadata_has_fields(&metadata) {
        return None;
    }
    Some(metadata)
}

fn write_pretty_json<T>(path: &Path, value: &T) -> Result<(), MycError>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| MycError::DiscoveryIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    let encoded = serde_json::to_string_pretty(value)?;
    fs::write(path, encoded).map_err(|source| MycError::DiscoveryIo {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn read_json_file<T>(path: &Path) -> Result<T, MycError>
where
    T: serde::de::DeserializeOwned,
{
    let encoded = fs::read_to_string(path).map_err(|source| MycError::DiscoveryIo {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&encoded).map_err(|source| MycError::DiscoveryParse {
        path: path.to_path_buf(),
        source,
    })
}

fn prepare_staged_output_dir(output_dir: &Path) -> Result<PathBuf, MycError> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| MycError::DiscoveryIo {
        path: parent.to_path_buf(),
        source,
    })?;

    let bundle_name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("discovery");
    let staged_output_dir = parent.join(format!(
        ".{bundle_name}.staging-{}-{}",
        std::process::id(),
        now_unix_nanos()
    ));
    remove_path_if_exists(&staged_output_dir)?;
    fs::create_dir_all(&staged_output_dir).map_err(|source| MycError::DiscoveryIo {
        path: staged_output_dir.clone(),
        source,
    })?;
    Ok(staged_output_dir)
}

fn replace_directory_atomically(
    staged_output_dir: &Path,
    output_dir: &Path,
) -> Result<(), MycError> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let bundle_name = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("discovery");
    let backup_dir = parent.join(format!(
        ".{bundle_name}.backup-{}-{}",
        std::process::id(),
        now_unix_nanos()
    ));
    let had_existing_output = output_dir.exists();

    if had_existing_output {
        remove_path_if_exists(&backup_dir)?;
        fs::rename(output_dir, &backup_dir).map_err(|source| MycError::DiscoveryIo {
            path: output_dir.to_path_buf(),
            source,
        })?;
    }

    match fs::rename(staged_output_dir, output_dir) {
        Ok(()) => {
            if had_existing_output {
                remove_path_if_exists(&backup_dir)?;
            }
            Ok(())
        }
        Err(source) => {
            let staged_cleanup_result = remove_path_if_exists(staged_output_dir);
            if had_existing_output && !output_dir.exists() {
                let _ = fs::rename(&backup_dir, output_dir);
            }
            if let Err(cleanup_error) = staged_cleanup_result {
                return Err(MycError::InvalidDiscoveryBundle(format!(
                    "failed to swap staged bundle into place: {source}; additionally failed to clean staged output: {cleanup_error}"
                )));
            }
            Err(MycError::DiscoveryIo {
                path: output_dir.to_path_buf(),
                source,
            })
        }
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), MycError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(MycError::DiscoveryIo {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(|source| MycError::DiscoveryIo {
            path: path.to_path_buf(),
            source,
        })?;
    } else {
        fs::remove_file(path).map_err(|source| MycError::DiscoveryIo {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_nanos()
}

impl MycDiscoveryBundleOutput {
    fn validate(&self) -> Result<(), MycError> {
        if self.manifest.version != DISCOVERY_BUNDLE_VERSION {
            return Err(MycError::InvalidDiscoveryBundle(format!(
                "unsupported bundle version `{}`",
                self.manifest.version
            )));
        }
        if self.manifest.domain.trim().is_empty() {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle domain must not be empty".to_owned(),
            ));
        }
        if self.manifest.author_public_key_hex.trim().is_empty()
            || self.manifest.signer_public_key_hex.trim().is_empty()
        {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle author and signer pubkeys must not be empty".to_owned(),
            ));
        }
        if self.manifest.nip05_relative_path != DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH {
            return Err(MycError::InvalidDiscoveryBundle(format!(
                "bundle manifest nip05_relative_path must be `{DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH}`"
            )));
        }
        if self.manifest.nip89_relative_path != DISCOVERY_BUNDLE_NIP89_FILE_NAME {
            return Err(MycError::InvalidDiscoveryBundle(format!(
                "bundle manifest nip89_relative_path must be `{DISCOVERY_BUNDLE_NIP89_FILE_NAME}`"
            )));
        }
        if self.nip05_path != self.output_dir.join(&self.manifest.nip05_relative_path) {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle nip05 path does not match the manifest".to_owned(),
            ));
        }
        if self.nip89_handler_path != self.output_dir.join(&self.manifest.nip89_relative_path) {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle NIP-89 handler path does not match the manifest".to_owned(),
            ));
        }
        if self.nip05_document.names.get("_").map(String::as_str)
            != Some(self.manifest.author_public_key_hex.as_str())
        {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle nip05 names._ does not match the manifest author pubkey".to_owned(),
            ));
        }
        if self.nip05_document.nip46.relays != self.manifest.public_relays {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle nip05 relays do not match the manifest public relays".to_owned(),
            ));
        }
        if self.nip05_document.nip46.nostrconnect_url != self.manifest.nostrconnect_url {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle nip05 nostrconnect_url does not match the manifest".to_owned(),
            ));
        }
        if self.nip89_handler.kinds != vec![NIP46_RPC_KIND] {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle NIP-89 handler kinds must be [24133]".to_owned(),
            ));
        }
        if self.nip89_handler.identifier.trim().is_empty() {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle NIP-89 handler identifier must not be empty".to_owned(),
            ));
        }
        if self.nip89_handler.relays != self.manifest.public_relays {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle NIP-89 handler relays do not match the manifest public relays".to_owned(),
            ));
        }
        if self.nip89_handler.nostrconnect_url != self.manifest.nostrconnect_url {
            return Err(MycError::InvalidDiscoveryBundle(
                "bundle NIP-89 handler nostrconnect_url does not match the manifest".to_owned(),
            ));
        }
        Ok(())
    }
}

fn render_nostrconnect_url(
    template: &str,
    signer_identity: &MycActiveIdentity,
    public_relays: &[RadrootsNostrRelayUrl],
) -> Result<String, MycError> {
    let bunker_uri = RadrootsNostrConnectUri::Bunker(RadrootsNostrConnectBunkerUri {
        remote_signer_public_key: signer_identity.public_key(),
        relays: public_relays.to_vec(),
        secret: None,
    })
    .to_string();
    let encoded_bunker_uri: String =
        url::form_urlencoded::byte_serialize(bunker_uri.as_bytes()).collect();
    let rendered = template.replace("<nostrconnect>", &encoded_bunker_uri);
    nostr::Url::parse(&rendered).map_err(|error| {
        MycError::InvalidOperation(format!(
            "failed to render discovery.nostrconnect_url_template: {error}"
        ))
    })?;
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use nostr::JsonUtil;
    use radroots_identity::RadrootsIdentity;

    use crate::config::MycConfig;

    use super::{MycDiscoveryContext, build_metadata, verify_bundle, write_pretty_json};
    use crate::MycError;
    use crate::app::MycRuntime;

    fn write_identity(path: &Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime() -> MycRuntime {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(&temp).join("state");
        config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
        config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
        config.discovery.enabled = true;
        config.discovery.domain = Some("signer.example.com".to_owned());
        config.discovery.handler_identifier = "myc".to_owned();
        config.discovery.public_relays = vec!["wss://relay.example.com".to_owned()];
        config.discovery.publish_relays = vec!["wss://publish.example.com".to_owned()];
        config.discovery.nostrconnect_url_template =
            Some("https://signer.example.com/connect?uri=<nostrconnect>".to_owned());
        config.discovery.nip05_output_path =
            Some(PathBuf::from(&temp).join("public/.well-known/nostr.json"));
        config.discovery.metadata.name = Some("myc".to_owned());
        config.discovery.metadata.about = Some("remote signer".to_owned());
        config.discovery.app_identity_path = Some(PathBuf::from(&temp).join("app.json"));
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        write_identity(
            config
                .discovery
                .app_identity_path
                .as_ref()
                .expect("app identity path"),
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        MycRuntime::bootstrap(config).expect("runtime")
    }

    #[test]
    fn build_metadata_ignores_blank_fields() {
        let mut metadata = crate::config::MycDiscoveryMetadataConfig::default();
        metadata.name = Some("   ".to_owned());
        metadata.about = Some(" ready ".to_owned());

        let built = build_metadata(&metadata).expect("metadata");

        assert!(built.name.is_none());
        assert_eq!(built.about.as_deref(), Some("ready"));
    }

    #[test]
    fn render_nip05_document_matches_appendix_shape() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");

        let document = context.render_nip05_document();

        assert_eq!(document.names.len(), 1);
        assert_eq!(
            document.names.get("_"),
            Some(&context.app_identity().public_key_hex())
        );
        assert_eq!(
            document.nip46.relays,
            vec!["wss://relay.example.com".to_owned()]
        );
        assert!(
            document
                .nip46
                .nostrconnect_url
                .as_deref()
                .expect("nostrconnect url")
                .contains("bunker%3A%2F%2F")
        );
    }

    #[test]
    fn render_signed_nip89_event_uses_app_identity_author() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");

        let output = context.render_nip89_output().expect("rendered nip89");

        assert_eq!(
            output.author_public_key_hex,
            context.app_identity().public_key_hex()
        );
        assert_eq!(
            output.signer_public_key_hex,
            context.signer_identity().public_key_hex()
        );
        assert_eq!(output.event.pubkey, context.app_identity().public_key());
        assert_eq!(output.event.kind.as_u16(), 31_990);
        let event_json = output.event.as_json();
        assert!(event_json.contains("\"24133\""));
        assert!(event_json.contains("\"nostrconnect_url\""));
    }

    #[test]
    fn write_nip05_document_writes_pretty_json_artifact() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");
        let output_path = context
            .nip05_output_path()
            .expect("configured output path")
            .to_path_buf();

        let output = context
            .write_nip05_document(&output_path)
            .expect("write nip05 document");

        let written = fs::read_to_string(&output_path).expect("read output");
        assert_eq!(output.output_path.as_deref(), Some(output_path.as_path()));
        assert!(written.contains("\"names\""));
        assert!(written.contains("\"nip46\""));
        assert!(written.contains(&context.app_identity().public_key_hex()));
    }

    #[test]
    fn write_bundle_writes_deterministic_artifacts() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");
        let bundle_dir = runtime.paths().state_dir.join("bundle");

        let first = context
            .write_bundle(&bundle_dir)
            .expect("first bundle write");
        let manifest_first = fs::read_to_string(&first.manifest_path).expect("manifest");
        let nip05_first = fs::read_to_string(&first.nip05_path).expect("nip05");
        let nip89_first = fs::read_to_string(&first.nip89_handler_path).expect("nip89");

        let second = context
            .write_bundle(&bundle_dir)
            .expect("second bundle write");
        let manifest_second = fs::read_to_string(&second.manifest_path).expect("manifest");
        let nip05_second = fs::read_to_string(&second.nip05_path).expect("nip05");
        let nip89_second = fs::read_to_string(&second.nip89_handler_path).expect("nip89");

        assert_eq!(first.manifest.version, 1);
        assert_eq!(first.manifest.nip05_relative_path, ".well-known/nostr.json");
        assert_eq!(first.manifest.nip89_relative_path, "nip89-handler.json");
        assert_eq!(first.nip05_path, bundle_dir.join(".well-known/nostr.json"));
        assert_eq!(
            first.nip89_handler_path,
            bundle_dir.join("nip89-handler.json")
        );
        assert_eq!(manifest_first, manifest_second);
        assert_eq!(nip05_first, nip05_second);
        assert_eq!(nip89_first, nip89_second);
    }

    #[test]
    fn write_bundle_replaces_existing_directory_without_leaving_stale_files() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");
        let bundle_dir = runtime.paths().state_dir.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create old bundle dir");
        fs::write(bundle_dir.join("stale.txt"), "stale").expect("write stale file");

        let bundle = context.write_bundle(&bundle_dir).expect("write bundle");

        assert_eq!(bundle.output_dir, bundle_dir);
        assert!(!bundle.output_dir.join("stale.txt").exists());
        assert!(bundle.manifest_path.exists());
        assert!(bundle.nip05_path.exists());
        assert!(bundle.nip89_handler_path.exists());
    }

    #[test]
    fn verify_bundle_rejects_tampered_nip05_author() {
        let runtime = runtime();
        let context = MycDiscoveryContext::from_runtime(&runtime).expect("discovery context");
        let bundle_dir = runtime.paths().state_dir.join("bundle");
        let bundle = context.write_bundle(&bundle_dir).expect("write bundle");
        let mut tampered = bundle.nip05_document.clone();
        tampered.names.insert("_".to_owned(), "deadbeef".to_owned());
        write_pretty_json(&bundle.nip05_path, &tampered).expect("rewrite tampered nip05");

        let error = verify_bundle(&bundle_dir).expect_err("bundle should be invalid");

        assert!(matches!(error, MycError::InvalidDiscoveryBundle(_)));
        assert!(
            error
                .to_string()
                .contains("bundle nip05 names._ does not match the manifest author pubkey")
        );
    }
}
