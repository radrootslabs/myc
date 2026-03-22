use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrEvent, RadrootsNostrMetadata,
    RadrootsNostrRelayUrl, radroots_nostr_build_application_handler_event,
};
use radroots_nostr_connect::prelude::{RadrootsNostrConnectBunkerUri, RadrootsNostrConnectUri};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::config::MycDiscoveryMetadataConfig;
use crate::error::MycError;
use crate::transport::MycNostrTransport;

const NIP46_RPC_KIND: u32 = 24_133;
const DISCOVERY_BUNDLE_VERSION: u32 = 1;
const DISCOVERY_BUNDLE_MANIFEST_FILE_NAME: &str = "bundle.json";
const DISCOVERY_BUNDLE_NIP89_FILE_NAME: &str = "nip89-handler.json";
const DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH: &str = ".well-known/nostr.json";

#[derive(Clone)]
pub struct MycDiscoveryContext {
    app_identity: RadrootsIdentity,
    signer_identity: RadrootsIdentity,
    domain: String,
    handler_identifier: String,
    public_relays: Vec<RadrootsNostrRelayUrl>,
    publish_relays: Vec<RadrootsNostrRelayUrl>,
    nostrconnect_url: Option<String>,
    metadata: Option<RadrootsNostrMetadata>,
    nip05_output_path: Option<PathBuf>,
    connect_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycNip05Document {
    pub names: BTreeMap<String, String>,
    pub nip46: MycNip05DocumentSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub event: RadrootsNostrEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycNip89HandlerDocument {
    pub kinds: Vec<u32>,
    pub identifier: String,
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostrconnect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RadrootsNostrMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

        let app_identity_path = discovery
            .app_identity_path
            .clone()
            .unwrap_or_else(|| runtime.paths().signer_identity_path.clone());
        let app_identity = RadrootsIdentity::load_from_path_auto(&app_identity_path)?;
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

    pub fn app_identity(&self) -> &RadrootsIdentity {
        &self.app_identity
    }

    pub fn signer_identity(&self) -> &RadrootsIdentity {
        &self.signer_identity
    }

    pub fn domain(&self) -> &str {
        self.domain.as_str()
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
        builder
            .sign_with_keys(self.app_identity.keys())
            .map_err(|error| {
                MycError::InvalidOperation(format!(
                    "failed to sign NIP-89 application handler event: {error}"
                ))
            })
    }

    pub fn write_bundle(
        &self,
        output_dir: impl AsRef<Path>,
    ) -> Result<MycDiscoveryBundleOutput, MycError> {
        let output_dir = output_dir.as_ref().to_path_buf();
        fs::create_dir_all(&output_dir).map_err(|source| MycError::DiscoveryIo {
            path: output_dir.clone(),
            source,
        })?;

        let manifest = self.render_bundle_manifest();
        let nip05_document = self.render_nip05_document();
        let nip89_handler = self.render_nip89_handler_document();
        let manifest_path = output_dir.join(DISCOVERY_BUNDLE_MANIFEST_FILE_NAME);
        let nip05_path = output_dir.join(DISCOVERY_BUNDLE_NIP05_RELATIVE_PATH);
        let nip89_handler_path = output_dir.join(DISCOVERY_BUNDLE_NIP89_FILE_NAME);

        write_pretty_json(&manifest_path, &manifest)?;
        write_pretty_json(&nip05_path, &nip05_document)?;
        write_pretty_json(&nip89_handler_path, &nip89_handler)?;

        Ok(MycDiscoveryBundleOutput {
            output_dir,
            manifest_path,
            nip05_path,
            nip89_handler_path,
            manifest,
            nip05_document,
            nip89_handler,
        })
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
    let event = context.build_signed_handler_event()?;
    let event_id = event.id.to_hex();
    let publish_outcome = match MycNostrTransport::publish_event_once(
        context.app_identity(),
        context.publish_relays(),
        context.connect_timeout_secs(),
        &event,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            runtime.record_operation_audit(&MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerPublish,
                MycOperationAuditOutcome::Rejected,
                None,
                Some(event_id.as_str()),
                error
                    .publish_rejection_counts()
                    .map(|(relay_count, _)| relay_count)
                    .unwrap_or(context.publish_relays().len()),
                error
                    .publish_rejection_counts()
                    .map(|(_, acknowledged)| acknowledged)
                    .unwrap_or_default(),
                error
                    .publish_rejection_details()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| error.to_string()),
            ));
            return Err(error);
        }
    };

    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        MycOperationAuditKind::DiscoveryHandlerPublish,
        MycOperationAuditOutcome::Succeeded,
        None,
        Some(event_id.as_str()),
        publish_outcome.relay_count,
        publish_outcome.acknowledged_relay_count,
        publish_outcome.relay_outcome_summary.clone(),
    ));

    Ok(MycPublishedNip89Output {
        author_public_key_hex: context.app_identity().public_key_hex(),
        signer_public_key_hex: context.signer_identity().public_key_hex(),
        publish_relays: context
            .publish_relays()
            .iter()
            .map(ToString::to_string)
            .collect(),
        relay_count: publish_outcome.relay_count,
        acknowledged_relay_count: publish_outcome.acknowledged_relay_count,
        relay_outcome_summary: publish_outcome.relay_outcome_summary,
        event,
    })
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

fn render_nostrconnect_url(
    template: &str,
    signer_identity: &RadrootsIdentity,
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

    use super::{MycDiscoveryContext, build_metadata};
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
}
