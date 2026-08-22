//! Durable discovery desired/current state and exact committed publication bytes.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::state_delivery::{
    DeliveryOperationError, MycDeliveryArtifactDigest, MycDeliveryJobId, MycDeliveryJobRecord,
    MycDeliveryJobStatus, MycDeliverySource, MycDeliveryTimeUnixMs, create_job,
};
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::{MycExpectedIdentities, MycStateMetadata};
use nostr::RelayUrl as RadrootsNostrRelayUrl;
use radroots_nostr::event::{
    Event as RadrootsNostrEvent, Kind as RadrootsNostrKind, Metadata as RadrootsNostrMetadata,
};

/// Maximum exact signed-event bytes admitted from the configured event bound.
pub const MYC_DISCOVERY_DOCUMENT_MAX_BYTES: usize = 524_288;
/// Maximum deterministic NIP-05 projection input bytes.
pub const MYC_NIP05_PROJECTION_MAX_BYTES: usize = 524_288;
/// Maximum deterministic offline NIP-05 document bytes.
pub const MYC_NIP05_DOCUMENT_MAX_BYTES: usize = 524_288;

const NIP46_RPC_KIND: u32 = 24_133;
const NIP89_HANDLER_KIND: u16 = 31_990;
const DESIRED_DIGEST_DOMAIN: &[u8] = b"radroots.myc.discovery_desired.v1\0";
const GENERATION_ID_DOMAIN: &[u8] = b"radroots.myc.discovery_generation.v1\0";

const READ_STATE_SQL: &str = r#"SELECT
    CASE WHEN typeof(desired_generation_id) = 'blob' AND length(desired_generation_id) = 32
        THEN desired_generation_id ELSE NULL END AS desired_generation_id,
    CASE WHEN typeof(desired_job_id) = 'blob' AND length(desired_job_id) = 32
        THEN desired_job_id ELSE NULL END AS desired_job_id,
    typeof(current_generation_id) AS current_generation_id_type,
    CASE WHEN typeof(current_generation_id) = 'blob' AND length(current_generation_id) = 32
        THEN current_generation_id ELSE NULL END AS current_generation_id,
    typeof(current_job_id) AS current_job_id_type,
    CASE WHEN typeof(current_job_id) = 'blob' AND length(current_job_id) = 32
        THEN current_job_id ELSE NULL END AS current_job_id,
    updated_at_unix_ms
FROM discovery_publication_state
WHERE singleton = 1
LIMIT 2"#;

const READ_DOCUMENT_BY_GENERATION_SQL: &str = r#"SELECT
    CASE WHEN typeof(generation_id) = 'blob' AND length(generation_id) = 32
        THEN generation_id ELSE NULL END AS generation_id,
    CASE WHEN typeof(event_id) = 'blob' AND length(event_id) = 32
        THEN event_id ELSE NULL END AS event_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(event_bytes) = 'blob' AND length(event_bytes) BETWEEN 1 AND 524288
        THEN event_bytes ELSE NULL END AS event_bytes,
    CASE WHEN typeof(nip05_projection_sha256) = 'blob'
            AND length(nip05_projection_sha256) = 32
        THEN nip05_projection_sha256 ELSE NULL END AS nip05_projection_sha256,
    CASE WHEN typeof(nip05_projection_bytes) = 'blob'
            AND length(nip05_projection_bytes) BETWEEN 1 AND 524288
        THEN nip05_projection_bytes ELSE NULL END AS nip05_projection_bytes
FROM discovery_documents
WHERE generation_id = ?
LIMIT 2"#;

const READ_DESIRED_SQL: &str = r#"SELECT
    CASE WHEN typeof(generation_id) = 'blob' AND length(generation_id) = 32
        THEN generation_id ELSE NULL END AS generation_id,
    CASE WHEN typeof(normalized_config_sha256) = 'blob'
            AND length(normalized_config_sha256) = 32
        THEN normalized_config_sha256 ELSE NULL END AS normalized_config_sha256,
    CASE WHEN typeof(desired_sha256) = 'blob' AND length(desired_sha256) = 32
        THEN desired_sha256 ELSE NULL END AS desired_sha256,
    created_at_unix_ms
FROM discovery_desired_state
WHERE generation_id = ?
LIMIT 2"#;

const READ_JOB_SQL: &str = r#"SELECT status
FROM delivery_jobs
WHERE job_id = ? AND source_kind = 'discovery_handler' AND source_id = ?
LIMIT 2"#;

const INSERT_DESIRED_SQL: &str = r#"INSERT INTO discovery_desired_state (
    generation_id, normalized_config_sha256, desired_sha256, created_at_unix_ms
) VALUES (?, ?, ?, ?)"#;

const INSERT_DOCUMENT_SQL: &str = r#"INSERT INTO discovery_documents (
    generation_id, event_id, event_sha256, event_bytes,
    nip05_projection_sha256, nip05_projection_bytes
) VALUES (?, ?, ?, ?, ?, ?)"#;

const INSERT_STATE_SQL: &str = r#"INSERT INTO discovery_publication_state (
    singleton, desired_generation_id, desired_job_id, current_generation_id,
    current_job_id, updated_at_unix_ms
) VALUES (1, ?, ?, NULL, NULL, ?)"#;

const REPLACE_DESIRED_SQL: &str = r#"UPDATE discovery_publication_state
SET desired_generation_id = ?, desired_job_id = ?, updated_at_unix_ms = ?
WHERE singleton = 1 AND updated_at_unix_ms <= ?
    AND desired_generation_id = ? AND desired_job_id = ?"#;

const PROMOTE_CURRENT_SQL: &str = r#"UPDATE discovery_publication_state
SET current_generation_id = desired_generation_id,
    current_job_id = desired_job_id,
    updated_at_unix_ms = ?
WHERE singleton = 1 AND desired_generation_id = ? AND desired_job_id = ?
    AND updated_at_unix_ms <= ?
    AND (current_generation_id IS NULL OR current_generation_id != desired_generation_id
        OR current_job_id IS NULL OR current_job_id != desired_job_id)"#;

/// Stable source-free construction and admission failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycDiscoveryStateErrorKind {
    Disabled,
    TooLarge,
    InvalidProjection,
    InvalidEvent,
    IdentityMismatch,
}

impl MycDiscoveryStateErrorKind {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "discovery_state_disabled",
            Self::TooLarge => "discovery_state_too_large",
            Self::InvalidProjection => "discovery_projection_invalid",
            Self::InvalidEvent => "discovery_event_invalid",
            Self::IdentityMismatch => "discovery_identity_mismatch",
        }
    }
}

/// Source-free failure at the discovery-state boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycDiscoveryStateError {
    kind: MycDiscoveryStateErrorKind,
}

impl MycDiscoveryStateError {
    const fn new(kind: MycDiscoveryStateErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycDiscoveryStateErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycDiscoveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycDiscoveryStateErrorKind::Disabled => "discovery state is not enabled",
            MycDiscoveryStateErrorKind::TooLarge => "discovery state exceeds its configured bound",
            MycDiscoveryStateErrorKind::InvalidProjection => {
                "discovery projection inputs are invalid"
            }
            MycDiscoveryStateErrorKind::InvalidEvent => "discovery event is invalid",
            MycDiscoveryStateErrorKind::IdentityMismatch => {
                "discovery event identity does not match configuration"
            }
        })
    }
}

impl fmt::Debug for MycDiscoveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDiscoveryStateError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycDiscoveryStateError {}

macro_rules! redacted_id {
    ($name:ident, $debug:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($debug)
            }
        }
    };
}

redacted_id!(
    MycDiscoveryGenerationId,
    "MycDiscoveryGenerationId([redacted])"
);
redacted_id!(
    MycDiscoveryDocumentDigest,
    "MycDiscoveryDocumentDigest([redacted])"
);
redacted_id!(
    MycNip05ProjectionDigest,
    "MycNip05ProjectionDigest([redacted])"
);
redacted_id!(MycNip05DocumentDigest, "MycNip05DocumentDigest([redacted])");

/// Explicit discovery generation selected for an offline NIP-05 export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip05ExportSelection {
    Desired,
    Current,
}

/// Canonical offline NIP-05/NIP-46 document derived from verified state.
#[derive(Clone, PartialEq, Eq)]
pub struct MycNip05Document {
    selection: MycNip05ExportSelection,
    domain: Box<str>,
    digest: MycNip05DocumentDigest,
    bytes: Box<[u8]>,
}

impl MycNip05Document {
    #[must_use]
    pub const fn selection(&self) -> MycNip05ExportSelection {
        self.selection
    }

    /// Returns the configured domain associated with this explicit export.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the exact compact UTF-8 JSON bytes to export.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 identity of the exact export bytes.
    #[must_use]
    pub const fn digest(&self) -> MycNip05DocumentDigest {
        self.digest
    }
}

impl fmt::Debug for MycNip05Document {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip05Document")
            .field("selection", &self.selection)
            .field("domain", &"[redacted]")
            .field("bytes", &"[redacted]")
            .field("digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MycDiscoveryPolicies {
    domain: Box<str>,
    handler_identifier: Box<str>,
    author_public_key: Box<str>,
    public_relays: Box<[Box<str>]>,
    nostrconnect_url: Option<Box<str>>,
    metadata_json: Box<str>,
    event_max_bytes: usize,
}

impl MycDiscoveryPolicies {
    pub(crate) fn from_normalized(
        normalized: &serde_json::Value,
        identities: &MycExpectedIdentities,
    ) -> Result<Option<Self>, MycDiscoveryStateError> {
        let discovery = normalized
            .pointer("/discovery")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        let enabled = discovery
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        if !enabled {
            return Ok(None);
        }
        let author = identities.discovery().ok_or_else(|| {
            MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::IdentityMismatch)
        })?;
        let string = |name: &str| {
            discovery
                .get(name)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
                })
        };
        let public_ids = discovery
            .get("public_relay_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        let relay_map = normalized
            .pointer("/relays")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?
            .iter()
            .map(|relay| {
                let id = relay.pointer("/id").and_then(serde_json::Value::as_str)?;
                let url = relay.pointer("/url").and_then(serde_json::Value::as_str)?;
                Some((id, url))
            })
            .collect::<Option<BTreeMap<_, _>>>()
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        let public_relays = public_ids
            .iter()
            .map(|id| {
                let id = id.as_str()?;
                let url = *relay_map.get(id)?;
                RadrootsNostrRelayUrl::parse(url).ok()?;
                Some(Box::<str>::from(url))
            })
            .collect::<Option<Vec<_>>>()
            .filter(|relays| !relays.is_empty())
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?
            .into_boxed_slice();
        let metadata = discovery
            .get("metadata")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        let optional = |name: &str| {
            metadata
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        };
        let metadata = RadrootsNostrMetadata {
            name: optional("name"),
            display_name: optional("display_name"),
            about: optional("about"),
            website: optional("website"),
            picture: optional("picture"),
            ..RadrootsNostrMetadata::default()
        };
        let metadata_json = if metadata.name.is_none()
            && metadata.display_name.is_none()
            && metadata.about.is_none()
            && metadata.website.is_none()
            && metadata.picture.is_none()
        {
            Box::<str>::from("")
        } else {
            serde_json::to_string(&metadata)
                .map_err(|_| {
                    MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
                })?
                .into_boxed_str()
        };
        let template = discovery
            .get("nostrconnect_url_template")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        let signer = identities.user().as_hex();
        let nostrconnect_url = template
            .map(|template| render_nostrconnect_url(template, signer, &public_relays))
            .transpose()?
            .map(String::into_boxed_str);
        let event_max_bytes = normalized
            .pointer("/resource_limits/events/wire_bytes")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=MYC_DISCOVERY_DOCUMENT_MAX_BYTES).contains(value))
            .ok_or_else(|| {
                MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection)
            })?;
        Ok(Some(Self {
            domain: string("domain")?.into(),
            handler_identifier: string("handler_identifier")?.into(),
            author_public_key: author.as_hex().into(),
            public_relays,
            nostrconnect_url,
            metadata_json,
            event_max_bytes,
        }))
    }
}

impl fmt::Debug for MycDiscoveryPolicies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDiscoveryPolicies")
            .field("relay_count", &self.public_relays.len())
            .field("values", &"[redacted]")
            .finish()
    }
}

/// Exact signature-verified discovery generation prepared outside SQLite.
pub struct MycDiscoveryCommitRequest {
    generation_id: MycDiscoveryGenerationId,
    desired_digest: MycDiscoveryDocumentDigest,
    configuration_digest: [u8; 32],
    event_id: [u8; 32],
    event_digest: MycDeliveryArtifactDigest,
    event_bytes: Box<[u8]>,
    projection_digest: MycNip05ProjectionDigest,
    projection_bytes: Box<[u8]>,
    created_at: MycDeliveryTimeUnixMs,
}

impl MycDiscoveryCommitRequest {
    /// Validates exact canonical event bytes, signature, identity, NIP-89 semantics, and bounds.
    pub fn new(
        metadata: &MycStateMetadata,
        event_bytes: &[u8],
        created_at: MycDeliveryTimeUnixMs,
    ) -> Result<Self, MycDiscoveryStateError> {
        let policy = metadata
            .discovery_policies()
            .ok_or_else(|| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::Disabled))?;
        if event_bytes.is_empty() || event_bytes.len() > policy.event_max_bytes {
            return Err(MycDiscoveryStateError::new(
                MycDiscoveryStateErrorKind::TooLarge,
            ));
        }
        let event: RadrootsNostrEvent = serde_json::from_slice(event_bytes)
            .map_err(|_| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidEvent))?;
        let canonical = serde_json::to_vec(&event)
            .map_err(|_| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidEvent))?;
        if canonical != event_bytes || event.verify().is_err() {
            return Err(MycDiscoveryStateError::new(
                MycDiscoveryStateErrorKind::InvalidEvent,
            ));
        }
        validate_event(&event, policy)?;
        let projection_bytes = projection_bytes(policy)?;
        if projection_bytes.is_empty() || projection_bytes.len() > MYC_NIP05_PROJECTION_MAX_BYTES {
            return Err(MycDiscoveryStateError::new(
                MycDiscoveryStateErrorKind::TooLarge,
            ));
        }
        let event_digest_bytes: [u8; 32] = Sha256::digest(event_bytes).into();
        let projection_digest_bytes: [u8; 32] = Sha256::digest(&projection_bytes).into();
        let configuration_digest = *metadata.configuration_digest().as_bytes();
        let mut desired_hasher = Sha256::new();
        desired_hasher.update(DESIRED_DIGEST_DOMAIN);
        desired_hasher.update(configuration_digest);
        desired_hasher.update(event_digest_bytes);
        desired_hasher.update(projection_digest_bytes);
        let desired_digest_bytes: [u8; 32] = desired_hasher.finalize().into();
        let mut generation_hasher = Sha256::new();
        generation_hasher.update(GENERATION_ID_DOMAIN);
        generation_hasher.update(desired_digest_bytes);
        let generation_id = MycDiscoveryGenerationId(generation_hasher.finalize().into());
        Ok(Self {
            generation_id,
            desired_digest: MycDiscoveryDocumentDigest(desired_digest_bytes),
            configuration_digest,
            event_id: *event.id.as_bytes(),
            event_digest: MycDeliveryArtifactDigest::from_bytes(event_digest_bytes),
            event_bytes: event_bytes.into(),
            projection_digest: MycNip05ProjectionDigest(projection_digest_bytes),
            projection_bytes: projection_bytes.into_boxed_slice(),
            created_at,
        })
    }

    /// Returns the deterministic desired-state generation identity.
    #[must_use]
    pub const fn generation_id(&self) -> MycDiscoveryGenerationId {
        self.generation_id
    }

    /// Returns the exact digest binding normalized configuration, event, and projection inputs.
    #[must_use]
    pub const fn desired_digest(&self) -> MycDiscoveryDocumentDigest {
        self.desired_digest
    }

    fn owned(&self) -> Self {
        Self {
            generation_id: self.generation_id,
            desired_digest: self.desired_digest,
            configuration_digest: self.configuration_digest,
            event_id: self.event_id,
            event_digest: self.event_digest,
            event_bytes: self.event_bytes.clone(),
            projection_digest: self.projection_digest,
            projection_bytes: self.projection_bytes.clone(),
            created_at: self.created_at,
        }
    }
}

impl fmt::Debug for MycDiscoveryCommitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDiscoveryCommitRequest([redacted])")
    }
}

/// Immutable exact document bytes retained for a discovery generation.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDiscoveryDocumentRecord {
    generation_id: MycDiscoveryGenerationId,
    event_id: [u8; 32],
    event_digest: MycDeliveryArtifactDigest,
    event_bytes: Box<[u8]>,
    projection_digest: MycNip05ProjectionDigest,
    projection_bytes: Box<[u8]>,
}

impl MycDiscoveryDocumentRecord {
    #[must_use]
    pub const fn generation_id(&self) -> MycDiscoveryGenerationId {
        self.generation_id
    }

    /// Returns the sole exact publishable event bytes.
    #[must_use]
    pub fn event_bytes(&self) -> &[u8] {
        &self.event_bytes
    }

    /// Returns deterministic NIP-05 projection inputs, not a hosted response.
    #[must_use]
    pub fn nip05_projection_bytes(&self) -> &[u8] {
        &self.projection_bytes
    }

    #[must_use]
    pub const fn event_digest(&self) -> MycDeliveryArtifactDigest {
        self.event_digest
    }

    /// Returns the verified NIP-01 event identity.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Returns the exact digest of the deterministic NIP-05 projection inputs.
    #[must_use]
    pub const fn nip05_projection_digest(&self) -> MycNip05ProjectionDigest {
        self.projection_digest
    }
}

impl fmt::Debug for MycDiscoveryDocumentRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDiscoveryDocumentRecord")
            .field("event_bytes", &"[redacted]")
            .field("nip05_projection_bytes", &"[redacted]")
            .finish()
    }
}

/// Current desired and proven-delivered discovery generations.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDiscoveryPublicationState {
    desired_generation_id: MycDiscoveryGenerationId,
    desired_job_id: MycDeliveryJobId,
    current_generation_id: Option<MycDiscoveryGenerationId>,
    current_job_id: Option<MycDeliveryJobId>,
    updated_at: MycDeliveryTimeUnixMs,
}

impl MycDiscoveryPublicationState {
    #[must_use]
    pub const fn desired_generation_id(&self) -> MycDiscoveryGenerationId {
        self.desired_generation_id
    }
    #[must_use]
    pub const fn desired_job_id(&self) -> MycDeliveryJobId {
        self.desired_job_id
    }
    #[must_use]
    pub const fn current_generation_id(&self) -> Option<MycDiscoveryGenerationId> {
        self.current_generation_id
    }
    #[must_use]
    pub const fn current_job_id(&self) -> Option<MycDeliveryJobId> {
        self.current_job_id
    }
}

impl fmt::Debug for MycDiscoveryPublicationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDiscoveryPublicationState")
            .field("has_current", &self.current_generation_id.is_some())
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Atomic result of one discovery desired-state commit.
#[derive(Clone, PartialEq, Eq)]
pub struct MycDiscoveryCommitRecord {
    state: MycDiscoveryPublicationState,
    document: MycDiscoveryDocumentRecord,
    job: MycDeliveryJobRecord,
}

impl MycDiscoveryCommitRecord {
    #[must_use]
    pub const fn state(&self) -> &MycDiscoveryPublicationState {
        &self.state
    }
    #[must_use]
    pub const fn document(&self) -> &MycDiscoveryDocumentRecord {
        &self.document
    }
    #[must_use]
    pub const fn job(&self) -> &MycDeliveryJobRecord {
        &self.job
    }
}

impl fmt::Debug for MycDiscoveryCommitRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycDiscoveryCommitRecord([redacted])")
    }
}

/// Created or exact replay outcome of one atomic discovery commit.
#[derive(Clone, PartialEq, Eq)]
pub enum MycDiscoveryCommitAdmission {
    Created(MycDiscoveryCommitRecord),
    ExactReplay(MycDiscoveryCommitRecord),
}

impl MycDiscoveryCommitAdmission {
    #[must_use]
    pub const fn record(&self) -> &MycDiscoveryCommitRecord {
        match self {
            Self::Created(record) | Self::ExactReplay(record) => record,
        }
    }
}

impl fmt::Debug for MycDiscoveryCommitAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Created(_) => "MycDiscoveryCommitAdmission::Created([redacted])",
            Self::ExactReplay(_) => "MycDiscoveryCommitAdmission::ExactReplay([redacted])",
        })
    }
}

impl MycStateRepository<'_> {
    /// Atomically commits desired state, exact documents, targets, and initial delivery evidence.
    pub async fn commit_discovery_desired_state(
        &self,
        request: &MycDiscoveryCommitRequest,
    ) -> Result<MycDiscoveryCommitAdmission, MycStateRepositoryError> {
        let request = request.owned();
        let expected = PersistedMetadata::from(self.expected());
        let delivery_policy = self.expected().delivery_policies().clone();
        let discovery_policy = self.expected().discovery_policies().cloned();
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let discovery_policy = discovery_policy
                        .as_ref()
                        .ok_or(DiscoveryOperationError::Binding)?;
                    commit_desired(transaction, &request, &delivery_policy, discovery_policy).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads the bounded desired/current discovery state, when configured and committed.
    pub async fn read_discovery_publication_state(
        &self,
    ) -> Result<Option<MycDiscoveryPublicationState>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    read_state(transaction).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads exact committed bytes for one discovery delivery job.
    pub async fn read_discovery_document_for_job(
        &self,
        job_id: MycDeliveryJobId,
    ) -> Result<Option<MycDiscoveryDocumentRecord>, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        let policy = self.expected().discovery_policies().cloned();
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let generation = discovery_generation_for_job(transaction, job_id).await?;
                    match (generation, policy.as_ref()) {
                        (Some(generation), Some(policy)) => {
                            read_document(transaction, generation, policy).await
                        }
                        (Some(_), None) => Err(DiscoveryOperationError::Binding),
                        (None, _) => Ok(None),
                    }
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Advances current state only from the current desired job's proven-delivered evidence.
    pub async fn promote_delivered_discovery_state(
        &self,
        job_id: MycDeliveryJobId,
        observed_at: MycDeliveryTimeUnixMs,
    ) -> Result<MycDiscoveryPublicationState, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    promote_current(transaction, job_id, observed_at).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Renders an explicit desired or proven-current NIP-05 document offline.
    ///
    /// This performs only verified state reads. It does not host, write, or
    /// publish the returned bytes and is valid through an inspection host.
    pub async fn render_offline_nip05(
        &self,
        selection: MycNip05ExportSelection,
    ) -> Result<MycNip05Document, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        let policy = self.expected().discovery_policies().cloned();
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let policy = policy.as_ref().ok_or(DiscoveryOperationError::Binding)?;
                    let state = read_state(transaction)
                        .await?
                        .ok_or(DiscoveryOperationError::Binding)?;
                    let generation = match selection {
                        MycNip05ExportSelection::Desired => state.desired_generation_id,
                        MycNip05ExportSelection::Current => state
                            .current_generation_id
                            .ok_or(DiscoveryOperationError::Binding)?,
                    };
                    let document = read_document(transaction, generation, policy)
                        .await?
                        .ok_or(DiscoveryOperationError::Binding)?;
                    render_nip05(selection, &document)
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoveryOperationError {
    Binding,
    Storage,
}

impl From<DeliveryOperationError> for DiscoveryOperationError {
    fn from(error: DeliveryOperationError) -> Self {
        match error {
            DeliveryOperationError::Binding => Self::Binding,
            DeliveryOperationError::Storage => Self::Storage,
        }
    }
}

async fn verify_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), DiscoveryOperationError> {
    require_expected_metadata(transaction, expected)
        .await
        .map_err(|error| match error {
            RepositoryOperationError::Binding => DiscoveryOperationError::Binding,
            RepositoryOperationError::Storage => DiscoveryOperationError::Storage,
        })
}

async fn commit_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycDiscoveryCommitRequest,
    delivery_policy: &crate::state_delivery::MycDeliveryPolicies,
    discovery_policy: &MycDiscoveryPolicies,
) -> Result<MycDiscoveryCommitAdmission, DiscoveryOperationError> {
    let existing_desired = read_desired(transaction, request.generation_id).await?;
    let existing_document =
        read_document(transaction, request.generation_id, discovery_policy).await?;
    let exact_existing = match (&existing_desired, &existing_document) {
        (Some(desired), Some(document)) => {
            desired.configuration_digest == request.configuration_digest
                && desired.desired_digest == request.desired_digest
                && desired.created_at == request.created_at
                && exact_document(document, request)
        }
        (None, None) => false,
        _ => return Err(DiscoveryOperationError::Binding),
    };
    if existing_desired.is_some() && !exact_existing {
        return Err(DiscoveryOperationError::Binding);
    }
    if existing_desired.is_none() {
        insert_desired(transaction, request).await?;
        insert_document(transaction, request).await?;
    }
    let source = MycDeliverySource::discovery_handler(*request.generation_id.as_bytes());
    let job = create_job(
        transaction,
        source,
        request.event_digest,
        request.created_at,
        delivery_policy,
    )
    .await?;
    let job_record = job.record().clone();
    let prior = read_state(transaction).await?;
    let exact_pointer = prior.as_ref().is_some_and(|state| {
        state.desired_generation_id == request.generation_id
            && state.desired_job_id == job_record.id()
    });
    let created = existing_desired.is_none();
    match prior {
        None => {
            let result = sqlx::query(INSERT_STATE_SQL)
                .bind(request.generation_id.as_bytes().as_slice())
                .bind(job_record.id().as_bytes().as_slice())
                .bind(request.created_at.sqlite_value())
                .execute(&mut *transaction)
                .await
                .map_err(|_| DiscoveryOperationError::Storage)?;
            require_one(result.rows_affected())?;
        }
        Some(state) if exact_pointer => {
            if !exact_existing {
                return Err(DiscoveryOperationError::Binding);
            }
            let document = existing_document.ok_or(DiscoveryOperationError::Binding)?;
            return Ok(MycDiscoveryCommitAdmission::ExactReplay(
                MycDiscoveryCommitRecord {
                    state,
                    document,
                    job: job_record,
                },
            ));
        }
        Some(state) => {
            if request.created_at <= state.updated_at {
                return Err(DiscoveryOperationError::Binding);
            }
            let result = sqlx::query(REPLACE_DESIRED_SQL)
                .bind(request.generation_id.as_bytes().as_slice())
                .bind(job_record.id().as_bytes().as_slice())
                .bind(request.created_at.sqlite_value())
                .bind(request.created_at.sqlite_value())
                .bind(state.desired_generation_id.as_bytes().as_slice())
                .bind(state.desired_job_id.as_bytes().as_slice())
                .execute(&mut *transaction)
                .await
                .map_err(|_| DiscoveryOperationError::Storage)?;
            require_one(result.rows_affected())?;
        }
    }
    let state = read_state(transaction)
        .await?
        .ok_or(DiscoveryOperationError::Binding)?;
    let document = read_document(transaction, request.generation_id, discovery_policy)
        .await?
        .ok_or(DiscoveryOperationError::Binding)?;
    let record = MycDiscoveryCommitRecord {
        state,
        document,
        job: job_record,
    };
    if created {
        Ok(MycDiscoveryCommitAdmission::Created(record))
    } else {
        Err(DiscoveryOperationError::Binding)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DesiredRecord {
    configuration_digest: [u8; 32],
    desired_digest: MycDiscoveryDocumentDigest,
    created_at: MycDeliveryTimeUnixMs,
}

async fn insert_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycDiscoveryCommitRequest,
) -> Result<(), DiscoveryOperationError> {
    let result = sqlx::query(INSERT_DESIRED_SQL)
        .bind(request.generation_id.as_bytes().as_slice())
        .bind(request.configuration_digest.as_slice())
        .bind(request.desired_digest.as_bytes().as_slice())
        .bind(request.created_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    require_one(result.rows_affected())
}

async fn insert_document(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycDiscoveryCommitRequest,
) -> Result<(), DiscoveryOperationError> {
    let result = sqlx::query(INSERT_DOCUMENT_SQL)
        .bind(request.generation_id.as_bytes().as_slice())
        .bind(request.event_id.as_slice())
        .bind(request.event_digest.as_bytes().as_slice())
        .bind(request.event_bytes.as_ref())
        .bind(request.projection_digest.as_bytes().as_slice())
        .bind(request.projection_bytes.as_ref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    require_one(result.rows_affected())
}

async fn read_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    generation: MycDiscoveryGenerationId,
) -> Result<Option<DesiredRecord>, DiscoveryOperationError> {
    let rows = sqlx::query(READ_DESIRED_SQL)
        .bind(generation.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(DiscoveryOperationError::Binding);
    }
    rows.first()
        .map(|row| {
            if blob32(row, "generation_id")? != *generation.as_bytes() {
                return Err(DiscoveryOperationError::Binding);
            }
            Ok(DesiredRecord {
                configuration_digest: blob32(row, "normalized_config_sha256")?,
                desired_digest: MycDiscoveryDocumentDigest(blob32(row, "desired_sha256")?),
                created_at: time(row, "created_at_unix_ms")?,
            })
        })
        .transpose()
}

async fn read_document(
    transaction: &mut ServiceSqliteTransaction<'_>,
    generation: MycDiscoveryGenerationId,
    policy: &MycDiscoveryPolicies,
) -> Result<Option<MycDiscoveryDocumentRecord>, DiscoveryOperationError> {
    let rows = sqlx::query(READ_DOCUMENT_BY_GENERATION_SQL)
        .bind(generation.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(DiscoveryOperationError::Binding);
    }
    rows.first()
        .map(|row| parse_document(row, policy))
        .transpose()
}

pub(crate) async fn verify_document_for_delivery_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job: &MycDeliveryJobRecord,
    policy: Option<&MycDiscoveryPolicies>,
) -> Result<(), DeliveryOperationError> {
    if job.source_kind() != crate::state_delivery::MycDeliverySourceKind::DiscoveryHandler {
        return Err(DeliveryOperationError::Binding);
    }
    let generation = discovery_generation_for_job(transaction, job.id())
        .await
        .map_err(|error| match error {
            DiscoveryOperationError::Binding => DeliveryOperationError::Binding,
            DiscoveryOperationError::Storage => DeliveryOperationError::Storage,
        })?
        .ok_or(DeliveryOperationError::Binding)?;
    if generation.as_bytes() != job.source_id() {
        return Err(DeliveryOperationError::Binding);
    }
    let document = read_document(
        transaction,
        generation,
        policy.ok_or(DeliveryOperationError::Binding)?,
    )
    .await
    .map_err(|error| match error {
        DiscoveryOperationError::Binding => DeliveryOperationError::Binding,
        DiscoveryOperationError::Storage => DeliveryOperationError::Storage,
    })?
    .ok_or(DeliveryOperationError::Binding)?;
    (document.event_digest() == job.artifact_digest())
        .then_some(())
        .ok_or(DeliveryOperationError::Binding)
}

fn parse_document(
    row: &sqlx::sqlite::SqliteRow,
    policy: &MycDiscoveryPolicies,
) -> Result<MycDiscoveryDocumentRecord, DiscoveryOperationError> {
    let generation_id = MycDiscoveryGenerationId(blob32(row, "generation_id")?);
    let event_id = blob32(row, "event_id")?;
    let event_digest = MycDeliveryArtifactDigest::from_bytes(blob32(row, "event_sha256")?);
    let event_bytes = bounded_blob(row, "event_bytes", MYC_DISCOVERY_DOCUMENT_MAX_BYTES)?;
    let projection_digest = MycNip05ProjectionDigest(blob32(row, "nip05_projection_sha256")?);
    let stored_projection_bytes = bounded_blob(
        row,
        "nip05_projection_bytes",
        MYC_NIP05_PROJECTION_MAX_BYTES,
    )?;
    let actual_event_digest: [u8; 32] = Sha256::digest(&event_bytes).into();
    let actual_projection_digest: [u8; 32] = Sha256::digest(&stored_projection_bytes).into();
    let event: RadrootsNostrEvent =
        serde_json::from_slice(&event_bytes).map_err(|_| DiscoveryOperationError::Binding)?;
    let canonical = serde_json::to_vec(&event).map_err(|_| DiscoveryOperationError::Binding)?;
    let expected_projection =
        projection_bytes(policy).map_err(|_| DiscoveryOperationError::Binding)?;
    if actual_event_digest != *event_digest.as_bytes()
        || actual_projection_digest != *projection_digest.as_bytes()
        || canonical.as_slice() != event_bytes.as_ref()
        || event.verify().is_err()
        || event.id.as_bytes() != &event_id
        || validate_event(&event, policy).is_err()
        || expected_projection.as_slice() != stored_projection_bytes.as_ref()
    {
        return Err(DiscoveryOperationError::Binding);
    }
    Ok(MycDiscoveryDocumentRecord {
        generation_id,
        event_id,
        event_digest,
        event_bytes,
        projection_digest,
        projection_bytes: stored_projection_bytes,
    })
}

async fn read_state(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<Option<MycDiscoveryPublicationState>, DiscoveryOperationError> {
    let rows = sqlx::query(READ_STATE_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(DiscoveryOperationError::Binding);
    }
    rows.first().map(parse_state).transpose()
}

fn parse_state(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<MycDiscoveryPublicationState, DiscoveryOperationError> {
    let current_generation_id =
        optional_blob32(row, "current_generation_id", "current_generation_id_type")?
            .map(MycDiscoveryGenerationId);
    let current_job_id = optional_blob32(row, "current_job_id", "current_job_id_type")?
        .map(MycDeliveryJobId::from_persisted);
    if current_generation_id.is_some() != current_job_id.is_some() {
        return Err(DiscoveryOperationError::Binding);
    }
    Ok(MycDiscoveryPublicationState {
        desired_generation_id: MycDiscoveryGenerationId(blob32(row, "desired_generation_id")?),
        desired_job_id: MycDeliveryJobId::from_persisted(blob32(row, "desired_job_id")?),
        current_generation_id,
        current_job_id,
        updated_at: time(row, "updated_at_unix_ms")?,
    })
}

async fn discovery_generation_for_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
) -> Result<Option<MycDiscoveryGenerationId>, DiscoveryOperationError> {
    let rows = sqlx::query(
        "SELECT source_id FROM delivery_jobs \
         WHERE job_id = ? AND source_kind = 'discovery_handler' LIMIT 2",
    )
    .bind(job_id.as_bytes().as_slice())
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| DiscoveryOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(DiscoveryOperationError::Binding);
    }
    rows.first()
        .map(|row| blob32(row, "source_id").map(MycDiscoveryGenerationId))
        .transpose()
}

async fn promote_current(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<MycDiscoveryPublicationState, DiscoveryOperationError> {
    let state = read_state(transaction)
        .await?
        .ok_or(DiscoveryOperationError::Binding)?;
    if state.desired_job_id != job_id || observed_at < state.updated_at {
        return Err(DiscoveryOperationError::Binding);
    }
    let rows = sqlx::query(READ_JOB_SQL)
        .bind(job_id.as_bytes().as_slice())
        .bind(state.desired_generation_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    if rows.len() != 1
        || rows[0]
            .try_get::<&str, _>("status")
            .ok()
            .and_then(MycDeliveryJobStatus::parse)
            != Some(MycDeliveryJobStatus::Delivered)
    {
        return Err(DiscoveryOperationError::Binding);
    }
    if state.current_generation_id == Some(state.desired_generation_id)
        && state.current_job_id == Some(state.desired_job_id)
    {
        return Ok(state);
    }
    let result = sqlx::query(PROMOTE_CURRENT_SQL)
        .bind(observed_at.sqlite_value())
        .bind(state.desired_generation_id.as_bytes().as_slice())
        .bind(job_id.as_bytes().as_slice())
        .bind(observed_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DiscoveryOperationError::Storage)?;
    require_one(result.rows_affected())?;
    read_state(transaction)
        .await?
        .ok_or(DiscoveryOperationError::Binding)
}

pub(crate) async fn promote_current_if_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    job_id: MycDeliveryJobId,
    observed_at: MycDeliveryTimeUnixMs,
) -> Result<bool, DeliveryOperationError> {
    let Some(state) = read_state(transaction).await.map_err(|error| match error {
        DiscoveryOperationError::Binding => DeliveryOperationError::Binding,
        DiscoveryOperationError::Storage => DeliveryOperationError::Storage,
    })?
    else {
        return Err(DeliveryOperationError::Binding);
    };
    if state.desired_job_id != job_id {
        return Ok(false);
    }
    promote_current(transaction, job_id, observed_at)
        .await
        .map_err(|error| match error {
            DiscoveryOperationError::Binding => DeliveryOperationError::Binding,
            DiscoveryOperationError::Storage => DeliveryOperationError::Storage,
        })?;
    Ok(true)
}

fn exact_document(
    record: &MycDiscoveryDocumentRecord,
    request: &MycDiscoveryCommitRequest,
) -> bool {
    record.generation_id == request.generation_id
        && record.event_id == request.event_id
        && record.event_digest == request.event_digest
        && record.event_bytes.as_ref() == request.event_bytes.as_ref()
        && record.projection_digest == request.projection_digest
        && record.projection_bytes.as_ref() == request.projection_bytes.as_ref()
}

fn validate_event(
    event: &RadrootsNostrEvent,
    policy: &MycDiscoveryPolicies,
) -> Result<(), MycDiscoveryStateError> {
    if event.pubkey.to_hex() != policy.author_public_key.as_ref() {
        return Err(MycDiscoveryStateError::new(
            MycDiscoveryStateErrorKind::IdentityMismatch,
        ));
    }
    if event.kind != RadrootsNostrKind::Custom(NIP89_HANDLER_KIND) {
        return Err(MycDiscoveryStateError::new(
            MycDiscoveryStateErrorKind::InvalidEvent,
        ));
    }
    let mut expected_tags = vec![
        vec!["d".to_owned(), policy.handler_identifier.to_string()],
        vec!["k".to_owned(), NIP46_RPC_KIND.to_string()],
    ];
    expected_tags.extend(
        policy
            .public_relays
            .iter()
            .map(|relay| vec!["relay".to_owned(), relay.to_string()]),
    );
    if let Some(url) = policy.nostrconnect_url.as_ref() {
        expected_tags.push(vec!["nostrconnect_url".to_owned(), url.to_string()]);
    }
    let actual_tags = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect::<Vec<_>>();
    if actual_tags != expected_tags || event.content != policy.metadata_json.as_ref() {
        return Err(MycDiscoveryStateError::new(
            MycDiscoveryStateErrorKind::InvalidEvent,
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct Nip05Projection<'a> {
    schema: &'static str,
    schema_version: u32,
    domain: &'a str,
    name: &'static str,
    public_key: &'a str,
    relays: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nostrconnect_url: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Nip05ProjectionInput {
    schema: Box<str>,
    schema_version: u32,
    domain: Box<str>,
    name: Box<str>,
    public_key: Box<str>,
    relays: Box<[Box<str>]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nostrconnect_url: Option<Box<str>>,
}

#[derive(Serialize)]
struct Nip05Names<'a> {
    #[serde(rename = "_")]
    root: &'a str,
}

#[derive(Serialize)]
struct Nip46Discovery<'a> {
    relays: &'a [Box<str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    nostrconnect_url: Option<&'a str>,
}

#[derive(Serialize)]
struct Nip05Output<'a> {
    names: Nip05Names<'a>,
    nip46: Nip46Discovery<'a>,
}

fn render_nip05(
    selection: MycNip05ExportSelection,
    document: &MycDiscoveryDocumentRecord,
) -> Result<MycNip05Document, DiscoveryOperationError> {
    let input: Nip05ProjectionInput = serde_json::from_slice(document.nip05_projection_bytes())
        .map_err(|_| DiscoveryOperationError::Binding)?;
    let canonical = serde_json::to_vec(&input).map_err(|_| DiscoveryOperationError::Binding)?;
    let valid_public_key = input.public_key.len() == 64
        && input
            .public_key
            .as_bytes()
            .iter()
            .all(u8::is_ascii_hexdigit)
        && !input
            .public_key
            .as_bytes()
            .iter()
            .any(u8::is_ascii_uppercase);
    let unique_relays = input
        .relays
        .iter()
        .map(Box::as_ref)
        .collect::<BTreeSet<_>>();
    let valid_relays = (1..=32).contains(&input.relays.len())
        && input
            .relays
            .iter()
            .all(|relay| RadrootsNostrRelayUrl::parse(relay).is_ok())
        && unique_relays.len() == input.relays.len();
    let valid_url = input
        .nostrconnect_url
        .as_deref()
        .is_none_or(|url| nostr::Url::parse(url).is_ok());
    if canonical.as_slice() != document.nip05_projection_bytes()
        || input.schema.as_ref() != "radroots.myc.nip05-projection-input.v1"
        || input.schema_version != 1
        || input.domain.is_empty()
        || input.domain.len() > 253
        || input.name.as_ref() != "_"
        || !valid_public_key
        || !valid_relays
        || !valid_url
    {
        return Err(DiscoveryOperationError::Binding);
    }
    let bytes = serde_json::to_vec(&Nip05Output {
        names: Nip05Names {
            root: &input.public_key,
        },
        nip46: Nip46Discovery {
            relays: &input.relays,
            nostrconnect_url: input.nostrconnect_url.as_deref(),
        },
    })
    .map_err(|_| DiscoveryOperationError::Binding)?;
    if bytes.is_empty() || bytes.len() > MYC_NIP05_DOCUMENT_MAX_BYTES {
        return Err(DiscoveryOperationError::Binding);
    }
    Ok(MycNip05Document {
        selection,
        domain: input.domain,
        digest: MycNip05DocumentDigest(Sha256::digest(&bytes).into()),
        bytes: bytes.into_boxed_slice(),
    })
}

fn projection_bytes(policy: &MycDiscoveryPolicies) -> Result<Vec<u8>, MycDiscoveryStateError> {
    serde_json::to_vec(&Nip05Projection {
        schema: "radroots.myc.nip05-projection-input.v1",
        schema_version: 1,
        domain: &policy.domain,
        name: "_",
        public_key: &policy.author_public_key,
        relays: policy.public_relays.iter().map(AsRef::as_ref).collect(),
        nostrconnect_url: policy.nostrconnect_url.as_deref(),
    })
    .map_err(|_| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection))
}

fn render_nostrconnect_url(
    template: &str,
    signer_public_key: &str,
    public_relays: &[Box<str>],
) -> Result<String, MycDiscoveryStateError> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for relay in public_relays {
        serializer.append_pair("relay", relay);
    }
    let bunker_uri = format!("bunker://{signer_public_key}?{}", serializer.finish());
    let bunker_uri = radroots_nostr_connect::uri::Uri::parse(&bunker_uri)
        .map_err(|_| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection))?
        .to_string();
    let encoded: String = url::form_urlencoded::byte_serialize(bunker_uri.as_bytes()).collect();
    let rendered = template.replace("<nostrconnect>", &encoded);
    nostr::Url::parse(&rendered)
        .map_err(|_| MycDiscoveryStateError::new(MycDiscoveryStateErrorKind::InvalidProjection))?;
    Ok(rendered)
}

fn bounded_blob(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    maximum: usize,
) -> Result<Box<[u8]>, DiscoveryOperationError> {
    let value = row
        .try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| DiscoveryOperationError::Binding)?
        .ok_or(DiscoveryOperationError::Binding)?;
    if value.is_empty() || value.len() > maximum {
        return Err(DiscoveryOperationError::Binding);
    }
    Ok(value.into_boxed_slice())
}

fn blob32(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], DiscoveryOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| DiscoveryOperationError::Binding)?
        .ok_or(DiscoveryOperationError::Binding)?
        .try_into()
        .map_err(|_| DiscoveryOperationError::Binding)
}

fn optional_blob32(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<[u8; 32]>, DiscoveryOperationError> {
    match row
        .try_get::<&str, _>(type_column)
        .map_err(|_| DiscoveryOperationError::Binding)?
    {
        "null" => Ok(None),
        "blob" => blob32(row, column).map(Some),
        _ => Err(DiscoveryOperationError::Binding),
    }
}

fn time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycDeliveryTimeUnixMs, DiscoveryOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| DiscoveryOperationError::Binding)?;
    u64::try_from(value)
        .ok()
        .and_then(|value| MycDeliveryTimeUnixMs::new(value).ok())
        .ok_or(DiscoveryOperationError::Binding)
}

fn require_one(rows: u64) -> Result<(), DiscoveryOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(DiscoveryOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<DiscoveryOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(DiscoveryOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(DiscoveryOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
