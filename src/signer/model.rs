use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::error::RadrootsNostrSignerError;
use hex::encode as hex_encode;
use nostr::{PublicKey, RelayUrl};
use radroots_nostr_connect::{
    Method, Permission, message::RequestMessage, permission::Permissions, uri::ClientMetadata,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use url::Url;
use uuid::Uuid;

pub const RADROOTS_NOSTR_SIGNER_STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RadrootsNostrSignerConnectionId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RadrootsNostrSignerRequestId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RadrootsNostrSignerWorkflowId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrSignerApprovalRequirement {
    NotRequired,
    ExplicitUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrSignerApprovalState {
    NotRequired,
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrSignerConnectionStatus {
    Pending,
    Active,
    Rejected,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadrootsNostrSignerPublishWorkflowKind {
    ConnectSecretFinalization,
    AuthReplayFinalization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadrootsNostrSignerPublishWorkflowState {
    PendingPublish,
    PublishedPendingFinalize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrSignerRequestDecision {
    Allowed,
    Denied,
    Challenged,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrSignerAuthState {
    #[default]
    NotRequired,
    Pending,
    Authorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadrootsNostrSignerSecretDigestAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsNostrSignerConnectSecretHash {
    pub algorithm: RadrootsNostrSignerSecretDigestAlgorithm,
    pub digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RadrootsNostrSignerAuthChallenge {
    pub auth_url: String,
    pub required_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsNostrSignerPendingRequest {
    pub request_message: RequestMessage,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct RadrootsNostrSignerAuthorizationOutcome {
    pub connection: RadrootsNostrSignerConnectionRecord,
    pub pending_request: Option<RadrootsNostrSignerPendingRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsNostrSignerPermissionGrant {
    #[serde(
        serialize_with = "serialize_permission",
        deserialize_with = "deserialize_permission"
    )]
    pub permission: Permission,
    pub granted_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct RadrootsNostrSignerConnectionDraft {
    pub client_public_key: PublicKey,
    pub user_identity: PublicIdentity,
    pub connect_secret: Option<String>,
    pub client_metadata: Option<ClientMetadata>,
    pub requested_permissions: Permissions,
    pub relays: Vec<RelayUrl>,
    pub approval_requirement: RadrootsNostrSignerApprovalRequirement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrSignerConnectionRecord {
    pub connection_id: RadrootsNostrSignerConnectionId,
    pub client_public_key: PublicKey,
    pub signer_identity: PublicIdentity,
    pub user_identity: PublicIdentity,
    #[serde(
        default,
        alias = "connect_secret",
        deserialize_with = "deserialize_connect_secret_hash_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub connect_secret_hash: Option<RadrootsNostrSignerConnectSecretHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_secret_consumed_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
    pub requested_permissions: Permissions,
    #[serde(default)]
    pub granted_permissions: Vec<RadrootsNostrSignerPermissionGrant>,
    #[serde(default)]
    pub relays: Vec<RelayUrl>,
    pub approval_requirement: RadrootsNostrSignerApprovalRequirement,
    pub approval_state: RadrootsNostrSignerApprovalState,
    #[serde(default)]
    pub auth_state: RadrootsNostrSignerAuthState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_challenge: Option<RadrootsNostrSignerAuthChallenge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_request: Option<RadrootsNostrSignerPendingRequest>,
    pub status: RadrootsNostrSignerConnectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_authenticated_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_request_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsNostrSignerRequestAuditRecord {
    pub request_id: RadrootsNostrSignerRequestId,
    pub connection_id: RadrootsNostrSignerConnectionId,
    pub method: Method,
    pub decision: RadrootsNostrSignerRequestDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsNostrSignerPublishWorkflowRecord {
    pub workflow_id: RadrootsNostrSignerWorkflowId,
    pub connection_id: RadrootsNostrSignerConnectionId,
    pub kind: RadrootsNostrSignerPublishWorkflowKind,
    pub state: RadrootsNostrSignerPublishWorkflowState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_request: Option<RadrootsNostrSignerPendingRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at_unix: Option<u64>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrSignerStoreState {
    pub version: u32,
    pub signer_identity: Option<PublicIdentity>,
    pub connections: Vec<RadrootsNostrSignerConnectionRecord>,
    pub audit_records: Vec<RadrootsNostrSignerRequestAuditRecord>,
    #[serde(default)]
    pub publish_workflows: Vec<RadrootsNostrSignerPublishWorkflowRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RadrootsNostrSignerConnectSecretHashRepr {
    Hash(RadrootsNostrSignerConnectSecretHash),
    LegacyPlaintext(String),
}

impl RadrootsNostrSignerConnectionId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, RadrootsNostrSignerError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RadrootsNostrSignerError::InvalidConnectionId(
                value.to_owned(),
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RadrootsNostrSignerConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for RadrootsNostrSignerConnectionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for RadrootsNostrSignerConnectionId {
    type Err = RadrootsNostrSignerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl RadrootsNostrSignerRequestId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, RadrootsNostrSignerError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RadrootsNostrSignerError::InvalidRequestId(value.to_owned()));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl RadrootsNostrSignerWorkflowId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, RadrootsNostrSignerError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RadrootsNostrSignerError::InvalidWorkflowId(
                value.to_owned(),
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RadrootsNostrSignerWorkflowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for RadrootsNostrSignerWorkflowId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for RadrootsNostrSignerWorkflowId {
    type Err = RadrootsNostrSignerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for RadrootsNostrSignerRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for RadrootsNostrSignerRequestId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for RadrootsNostrSignerRequestId {
    type Err = RadrootsNostrSignerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl RadrootsNostrSignerConnectSecretHash {
    pub fn from_secret(secret: &str) -> Option<Self> {
        normalize_optional_string(secret).map(|normalized| {
            let mut hasher = Sha256::new();
            hasher.update(normalized.as_bytes());
            Self {
                algorithm: RadrootsNostrSignerSecretDigestAlgorithm::Sha256,
                digest_hex: hex_encode(hasher.finalize()),
            }
        })
    }

    pub fn matches_secret(&self, secret: &str) -> bool {
        Self::from_secret(secret).as_ref() == Some(self)
    }

    fn normalize(self) -> Result<Self, String> {
        let digest_hex = self.digest_hex.trim().to_ascii_lowercase();
        if digest_hex.len() != 64 || !digest_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("invalid connect secret digest".into());
        }
        Ok(Self {
            algorithm: self.algorithm,
            digest_hex,
        })
    }
}

impl RadrootsNostrSignerAuthChallenge {
    pub fn new(auth_url: &str, required_at_unix: u64) -> Result<Self, RadrootsNostrSignerError> {
        let auth_url = normalize_optional_string(auth_url)
            .ok_or_else(|| RadrootsNostrSignerError::InvalidAuthUrl(auth_url.to_owned()))?;
        let auth_url: String = Url::parse(&auth_url)
            .map_err(|_| RadrootsNostrSignerError::InvalidAuthUrl(auth_url.clone()))?
            .into();
        Ok(Self {
            auth_url,
            required_at_unix,
            authorized_at_unix: None,
        })
    }

    pub fn mark_authorized(&mut self, authorized_at_unix: u64) {
        self.authorized_at_unix = Some(authorized_at_unix);
    }
}

impl<'de> Deserialize<'de> for RadrootsNostrSignerAuthChallenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawAuthChallenge {
            auth_url: String,
            required_at_unix: u64,
            #[serde(default)]
            authorized_at_unix: Option<u64>,
        }

        let raw = RawAuthChallenge::deserialize(deserializer)?;
        let mut challenge =
            Self::new(&raw.auth_url, raw.required_at_unix).map_err(serde::de::Error::custom)?;
        challenge.authorized_at_unix = raw.authorized_at_unix;
        Ok(challenge)
    }
}

impl RadrootsNostrSignerPendingRequest {
    pub fn new(
        request_message: RequestMessage,
        created_at_unix: u64,
    ) -> Result<Self, RadrootsNostrSignerError> {
        let normalized_id = RadrootsNostrSignerRequestId::parse(&request_message.id)?;
        Ok(Self {
            request_message: RequestMessage::new(normalized_id.as_str(), request_message.request),
            created_at_unix,
        })
    }

    pub fn request_message(&self) -> RequestMessage {
        self.request_message.clone()
    }

    pub fn request_id(&self) -> RadrootsNostrSignerRequestId {
        RadrootsNostrSignerRequestId::parse(&self.request_message.id)
            .expect("pending request ids are validated on construction")
    }
}

impl RadrootsNostrSignerAuthorizationOutcome {
    pub fn new(
        connection: RadrootsNostrSignerConnectionRecord,
        pending_request: Option<RadrootsNostrSignerPendingRequest>,
    ) -> Self {
        Self {
            connection,
            pending_request,
        }
    }
}

impl RadrootsNostrSignerPermissionGrant {
    pub fn new(permission: Permission, granted_at_unix: u64) -> Self {
        Self {
            permission,
            granted_at_unix,
        }
    }
}

impl RadrootsNostrSignerConnectionDraft {
    pub fn new(client_public_key: PublicKey, user_identity: PublicIdentity) -> Self {
        Self {
            client_public_key,
            user_identity,
            connect_secret: None,
            client_metadata: None,
            requested_permissions: Permissions::default(),
            relays: Vec::new(),
            approval_requirement: RadrootsNostrSignerApprovalRequirement::NotRequired,
        }
    }

    pub fn with_connect_secret(mut self, connect_secret: impl Into<String>) -> Self {
        self.connect_secret = Some(connect_secret.into());
        self
    }

    pub fn with_requested_permissions(mut self, requested_permissions: Permissions) -> Self {
        self.requested_permissions = requested_permissions;
        self
    }

    pub fn with_client_metadata(mut self, client_metadata: ClientMetadata) -> Self {
        self.client_metadata = Some(client_metadata);
        self
    }

    pub fn with_relays(mut self, relays: Vec<RelayUrl>) -> Self {
        self.relays = relays;
        self
    }

    pub fn with_approval_requirement(
        mut self,
        approval_requirement: RadrootsNostrSignerApprovalRequirement,
    ) -> Self {
        self.approval_requirement = approval_requirement;
        self
    }
}

impl RadrootsNostrSignerConnectionRecord {
    pub fn new(
        connection_id: RadrootsNostrSignerConnectionId,
        signer_identity: PublicIdentity,
        draft: RadrootsNostrSignerConnectionDraft,
        created_at_unix: u64,
    ) -> Self {
        let (approval_state, status) = match draft.approval_requirement {
            RadrootsNostrSignerApprovalRequirement::NotRequired => (
                RadrootsNostrSignerApprovalState::NotRequired,
                RadrootsNostrSignerConnectionStatus::Active,
            ),
            RadrootsNostrSignerApprovalRequirement::ExplicitUser => (
                RadrootsNostrSignerApprovalState::Pending,
                RadrootsNostrSignerConnectionStatus::Pending,
            ),
        };

        Self {
            connection_id,
            client_public_key: draft.client_public_key,
            signer_identity,
            user_identity: draft.user_identity,
            connect_secret_hash: draft
                .connect_secret
                .as_deref()
                .and_then(RadrootsNostrSignerConnectSecretHash::from_secret),
            connect_secret_consumed_at_unix: None,
            client_metadata: draft.client_metadata,
            requested_permissions: draft.requested_permissions,
            granted_permissions: Vec::new(),
            relays: draft.relays,
            approval_requirement: draft.approval_requirement,
            approval_state,
            auth_state: RadrootsNostrSignerAuthState::NotRequired,
            auth_challenge: None,
            pending_request: None,
            status,
            status_reason: None,
            created_at_unix,
            updated_at_unix: created_at_unix,
            last_authenticated_at_unix: None,
            last_request_at_unix: None,
        }
    }

    pub fn granted_permissions(&self) -> Permissions {
        self.granted_permissions
            .iter()
            .map(|grant| grant.permission.clone())
            .collect::<Vec<_>>()
            .into()
    }

    pub fn effective_permissions(&self) -> Permissions {
        let granted_permissions = self.granted_permissions();
        if !granted_permissions.is_empty() {
            granted_permissions
        } else if self.approval_state == RadrootsNostrSignerApprovalState::NotRequired {
            self.requested_permissions.clone()
        } else {
            Permissions::default()
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            RadrootsNostrSignerConnectionStatus::Rejected
                | RadrootsNostrSignerConnectionStatus::Revoked
        )
    }

    pub fn connect_secret_is_consumed(&self) -> bool {
        self.connect_secret_hash.is_some() && self.connect_secret_consumed_at_unix.is_some()
    }

    pub fn touch_updated(&mut self, updated_at_unix: u64) {
        self.updated_at_unix = updated_at_unix;
    }

    pub fn mark_authenticated(&mut self, authenticated_at_unix: u64) {
        self.last_authenticated_at_unix = Some(authenticated_at_unix);
        self.updated_at_unix = authenticated_at_unix;
    }

    pub fn mark_request(&mut self, request_at_unix: u64) {
        self.last_request_at_unix = Some(request_at_unix);
        self.updated_at_unix = request_at_unix;
    }

    pub fn mark_connect_secret_consumed(&mut self, consumed_at_unix: u64) {
        if self.connect_secret_hash.is_none() || self.connect_secret_consumed_at_unix.is_some() {
            return;
        }
        self.connect_secret_consumed_at_unix = Some(consumed_at_unix);
        self.updated_at_unix = consumed_at_unix;
    }

    pub fn require_auth_challenge(&mut self, auth_challenge: RadrootsNostrSignerAuthChallenge) {
        self.auth_state = RadrootsNostrSignerAuthState::Pending;
        self.auth_challenge = Some(auth_challenge.clone());
        self.pending_request = None;
        self.updated_at_unix = auth_challenge.required_at_unix;
    }

    pub fn set_pending_request(&mut self, pending_request: RadrootsNostrSignerPendingRequest) {
        self.pending_request = Some(pending_request.clone());
        self.updated_at_unix = pending_request.created_at_unix;
    }

    pub fn authorize_auth_challenge(
        &mut self,
        authorized_at_unix: u64,
    ) -> Option<RadrootsNostrSignerPendingRequest> {
        self.auth_state = RadrootsNostrSignerAuthState::Authorized;
        if let Some(auth_challenge) = self.auth_challenge.as_mut() {
            auth_challenge.mark_authorized(authorized_at_unix);
        }
        self.last_authenticated_at_unix = Some(authorized_at_unix);
        self.updated_at_unix = authorized_at_unix;
        self.pending_request.take()
    }

    pub fn restore_pending_auth_challenge(
        &mut self,
        pending_request: RadrootsNostrSignerPendingRequest,
        restored_at_unix: u64,
    ) {
        self.auth_state = RadrootsNostrSignerAuthState::Pending;
        if let Some(auth_challenge) = self.auth_challenge.as_mut() {
            let previous_authorized_at_unix = auth_challenge.authorized_at_unix.take();
            if self.last_authenticated_at_unix == previous_authorized_at_unix {
                self.last_authenticated_at_unix = None;
            }
        }
        self.pending_request = Some(pending_request);
        self.updated_at_unix = restored_at_unix;
    }
}

impl RadrootsNostrSignerRequestAuditRecord {
    pub fn new(
        request_id: RadrootsNostrSignerRequestId,
        connection_id: RadrootsNostrSignerConnectionId,
        method: Method,
        decision: RadrootsNostrSignerRequestDecision,
        message: Option<String>,
        created_at_unix: u64,
    ) -> Self {
        Self {
            request_id,
            connection_id,
            method,
            decision,
            message,
            created_at_unix,
        }
    }
}

impl RadrootsNostrSignerPublishWorkflowRecord {
    pub fn new_connect_secret_finalization(
        connection_id: RadrootsNostrSignerConnectionId,
        created_at_unix: u64,
    ) -> Self {
        Self {
            workflow_id: RadrootsNostrSignerWorkflowId::new_v7(),
            connection_id,
            kind: RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization,
            state: RadrootsNostrSignerPublishWorkflowState::PendingPublish,
            pending_request: None,
            authorized_at_unix: None,
            created_at_unix,
            updated_at_unix: created_at_unix,
        }
    }

    pub fn new_auth_replay_finalization(
        connection_id: RadrootsNostrSignerConnectionId,
        pending_request: RadrootsNostrSignerPendingRequest,
        authorized_at_unix: u64,
    ) -> Self {
        Self {
            workflow_id: RadrootsNostrSignerWorkflowId::new_v7(),
            connection_id,
            kind: RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization,
            state: RadrootsNostrSignerPublishWorkflowState::PendingPublish,
            pending_request: Some(pending_request),
            authorized_at_unix: Some(authorized_at_unix),
            created_at_unix: authorized_at_unix,
            updated_at_unix: authorized_at_unix,
        }
    }

    pub fn mark_published(&mut self, updated_at_unix: u64) {
        self.state = RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize;
        self.updated_at_unix = updated_at_unix;
    }
}

impl Default for RadrootsNostrSignerStoreState {
    fn default() -> Self {
        Self {
            version: RADROOTS_NOSTR_SIGNER_STORE_VERSION,
            signer_identity: None,
            connections: Vec::new(),
            audit_records: Vec::new(),
            publish_workflows: Vec::new(),
        }
    }
}

fn serialize_permission<S>(permission: &Permission, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&permission.to_string())
}

fn deserialize_permission<'de, D>(deserializer: D) -> Result<Permission, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

fn deserialize_connect_secret_hash_option<'de, D>(
    deserializer: D,
) -> Result<Option<RadrootsNostrSignerConnectSecretHash>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<RadrootsNostrSignerConnectSecretHashRepr>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(RadrootsNostrSignerConnectSecretHashRepr::Hash(hash)) => {
            hash.normalize().map(Some).map_err(serde::de::Error::custom)
        }
        Some(RadrootsNostrSignerConnectSecretHashRepr::LegacyPlaintext(secret)) => {
            Ok(RadrootsNostrSignerConnectSecretHash::from_secret(&secret))
        }
    }
}

fn normalize_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
    use crate::signer::test_support::{
        api_primary_https, fixture_alice_identity, fixture_bob_identity, fixture_carol_public_key,
        primary_relay, synthetic_public_identity, synthetic_public_key,
    };
    use nostr::PublicKey;
    use serde_json::json;
    use std::str::FromStr;
    use tempfile::tempdir;

    fn public_identity(index: u32) -> PublicIdentity {
        synthetic_public_identity(index)
    }

    fn public_key(index: u32) -> PublicKey {
        synthetic_public_key(index)
    }

    fn request_message(id: &str) -> RequestMessage {
        RequestMessage::new(id, radroots_nostr_connect::Request::Ping)
    }

    #[test]
    fn connection_and_request_ids_parse_and_display() {
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-1").expect("connection");
        let request_id = RadrootsNostrSignerRequestId::parse("req-1").expect("request");
        let workflow_id = RadrootsNostrSignerWorkflowId::parse("wf-1").expect("workflow");

        assert_eq!(connection_id.as_str(), "conn-1");
        assert_eq!(request_id.as_str(), "req-1");
        assert_eq!(workflow_id.as_str(), "wf-1");
        assert_eq!(connection_id.as_ref(), "conn-1");
        assert_eq!(request_id.as_ref(), "req-1");
        assert_eq!(workflow_id.as_ref(), "wf-1");
        assert_eq!(connection_id.to_string(), "conn-1");
        assert_eq!(request_id.to_string(), "req-1");
        assert_eq!(workflow_id.to_string(), "wf-1");
        assert_eq!(connection_id.clone().into_string(), "conn-1");
        assert_eq!(request_id.clone().into_string(), "req-1");
        assert_eq!(workflow_id.clone().into_string(), "wf-1");

        let parsed_connection =
            RadrootsNostrSignerConnectionId::from_str("conn-1").expect("from_str connection");
        let parsed_request =
            RadrootsNostrSignerRequestId::from_str("req-1").expect("from_str request");
        let parsed_workflow =
            RadrootsNostrSignerWorkflowId::from_str("wf-1").expect("from_str workflow");
        assert_eq!(parsed_connection, connection_id);
        assert_eq!(parsed_request, request_id);
        assert_eq!(parsed_workflow, workflow_id);
    }

    #[test]
    fn generated_ids_are_non_empty() {
        let connection_id = RadrootsNostrSignerConnectionId::new_v7();
        let request_id = RadrootsNostrSignerRequestId::new_v7();
        let workflow_id = RadrootsNostrSignerWorkflowId::new_v7();

        assert!(!connection_id.as_ref().is_empty());
        assert!(!request_id.as_ref().is_empty());
        assert!(!workflow_id.as_ref().is_empty());
    }

    #[test]
    fn ids_reject_empty_values() {
        let connection_err =
            RadrootsNostrSignerConnectionId::parse("   ").expect_err("empty connection");
        let request_err = RadrootsNostrSignerRequestId::parse("").expect_err("empty request");
        let workflow_err = RadrootsNostrSignerWorkflowId::parse(" ").expect_err("empty workflow");

        assert!(connection_err.to_string().contains("invalid connection id"));
        assert!(request_err.to_string().contains("invalid request id"));
        assert!(workflow_err.to_string().contains("invalid workflow id"));
    }

    #[test]
    fn connection_draft_builders_apply_values() {
        let permission = Permission::with_parameter(Method::SignEvent, "kind:1");
        let relay = primary_relay();
        let metadata = ClientMetadata {
            requested_permissions: Permissions::default(),
            name: Some("Example Client".into()),
            url: None,
            image: None,
        };
        let draft = RadrootsNostrSignerConnectionDraft::new(
            fixture_carol_public_key(),
            fixture_bob_identity(),
        )
        .with_connect_secret(" secret ")
        .with_client_metadata(metadata.clone())
        .with_requested_permissions(vec![permission.clone()].into())
        .with_relays(vec![relay.clone()])
        .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::ExplicitUser);

        assert_eq!(draft.connect_secret.as_deref(), Some(" secret "));
        assert_eq!(draft.client_metadata.as_ref(), Some(&metadata));
        assert_eq!(draft.requested_permissions.as_slice(), &[permission]);
        assert_eq!(draft.relays, vec![relay]);
        assert_eq!(
            draft.approval_requirement,
            RadrootsNostrSignerApprovalRequirement::ExplicitUser
        );
    }

    #[test]
    fn connection_record_defaults_follow_approval_requirement_and_tracking_helpers() {
        let signer_identity = fixture_alice_identity();
        let user_identity = fixture_bob_identity();
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-1").expect("id");
        let draft =
            RadrootsNostrSignerConnectionDraft::new(fixture_carol_public_key(), user_identity)
                .with_connect_secret(" secret ")
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::ExplicitUser);
        let mut record =
            RadrootsNostrSignerConnectionRecord::new(connection_id, signer_identity, draft, 10);

        assert_eq!(record.status, RadrootsNostrSignerConnectionStatus::Pending);
        assert_eq!(
            record.approval_state,
            RadrootsNostrSignerApprovalState::Pending
        );
        assert_eq!(record.auth_state, RadrootsNostrSignerAuthState::NotRequired);
        assert!(
            record
                .connect_secret_hash
                .as_ref()
                .expect("connect secret hash")
                .matches_secret("secret")
        );
        assert!(!record.connect_secret_is_consumed());
        assert!(!record.is_terminal());

        record.touch_updated(12);
        record.mark_authenticated(14);
        record.mark_request(16);
        record.mark_connect_secret_consumed(17);
        record.require_auth_challenge(
            RadrootsNostrSignerAuthChallenge::new(
                format!("{}/path", api_primary_https()).as_str(),
                18,
            )
            .expect("auth challenge"),
        );
        record.set_pending_request(
            RadrootsNostrSignerPendingRequest::new(request_message("req-1"), 20)
                .expect("pending request"),
        );
        let replay = record.authorize_auth_challenge(22).expect("replay");
        let no_challenge_replay = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::parse("conn-1b").expect("id"),
            public_identity(0x9),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x10), public_identity(0x11)),
            24,
        )
        .authorize_auth_challenge(25);

        assert_eq!(record.updated_at_unix, 22);
        assert_eq!(record.connect_secret_consumed_at_unix, Some(17));
        assert!(record.connect_secret_is_consumed());
        assert_eq!(record.auth_state, RadrootsNostrSignerAuthState::Authorized);
        assert_eq!(
            record
                .auth_challenge
                .as_ref()
                .expect("auth challenge")
                .authorized_at_unix,
            Some(22)
        );
        assert!(record.pending_request.is_none());
        assert_eq!(record.last_authenticated_at_unix, Some(22));
        assert_eq!(record.last_request_at_unix, Some(16));
        assert_eq!(replay.request_id().as_str(), "req-1");
        assert!(no_challenge_replay.is_none());

        record.restore_pending_auth_challenge(replay, 23);

        assert_eq!(record.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert_eq!(
            record
                .auth_challenge
                .as_ref()
                .expect("restored challenge")
                .authorized_at_unix,
            None
        );
        assert_eq!(record.last_authenticated_at_unix, None);
        assert_eq!(record.updated_at_unix, 23);
        assert_eq!(
            record
                .pending_request
                .as_ref()
                .expect("restored pending request")
                .request_id()
                .as_str(),
            "req-1"
        );
    }

    #[test]
    fn connection_record_noop_consumption_and_restore_paths_preserve_state() {
        let mut no_secret_record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::parse("conn-no-secret").expect("id"),
            public_identity(0x12),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x13), public_identity(0x14)),
            30,
        );
        let no_secret_updated_at = no_secret_record.updated_at_unix;
        assert!(!no_secret_record.connect_secret_is_consumed());

        no_secret_record.mark_connect_secret_consumed(31);

        assert_eq!(no_secret_record.connect_secret_consumed_at_unix, None);
        assert_eq!(no_secret_record.updated_at_unix, no_secret_updated_at);
        assert!(!no_secret_record.connect_secret_is_consumed());

        let restored_without_challenge =
            RadrootsNostrSignerPendingRequest::new(request_message("req-no-challenge"), 32)
                .expect("pending request");
        no_secret_record.last_authenticated_at_unix = Some(29);
        no_secret_record.restore_pending_auth_challenge(restored_without_challenge.clone(), 33);

        assert_eq!(no_secret_record.last_authenticated_at_unix, Some(29));
        assert_eq!(
            no_secret_record.pending_request.as_ref(),
            Some(&restored_without_challenge)
        );
        assert_eq!(no_secret_record.updated_at_unix, 33);

        let mut restored_record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::parse("conn-restore-preserve").expect("id"),
            public_identity(0x15),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x16), public_identity(0x17)),
            40,
        );
        restored_record.require_auth_challenge(
            RadrootsNostrSignerAuthChallenge::new(
                format!("{}/preserve", api_primary_https()).as_str(),
                41,
            )
            .expect("auth challenge"),
        );
        restored_record.set_pending_request(
            RadrootsNostrSignerPendingRequest::new(request_message("req-preserve"), 42)
                .expect("pending request"),
        );
        let replay = restored_record
            .authorize_auth_challenge(43)
            .expect("authorize challenge");
        restored_record.last_authenticated_at_unix = Some(99);

        restored_record.restore_pending_auth_challenge(replay.clone(), 44);

        assert_eq!(
            restored_record.auth_state,
            RadrootsNostrSignerAuthState::Pending
        );
        assert_eq!(restored_record.last_authenticated_at_unix, Some(99));
        assert_eq!(
            restored_record
                .auth_challenge
                .as_ref()
                .expect("restored challenge")
                .authorized_at_unix,
            None
        );
        assert_eq!(restored_record.pending_request.as_ref(), Some(&replay));
        assert_eq!(restored_record.updated_at_unix, 44);
    }

    #[test]
    fn granted_permissions_and_request_audit_build_correctly() {
        let permission = Permission::new(Method::Ping);
        let grant = RadrootsNostrSignerPermissionGrant::new(permission.clone(), 42);
        let mut record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::parse("conn-2").expect("id"),
            public_identity(0x6),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x7), public_identity(0x8)),
            20,
        );
        record.granted_permissions = vec![grant];
        let audit = RadrootsNostrSignerRequestAuditRecord::new(
            RadrootsNostrSignerRequestId::parse("req-2").expect("request"),
            RadrootsNostrSignerConnectionId::parse("conn-2").expect("id"),
            Method::Ping,
            RadrootsNostrSignerRequestDecision::Allowed,
            Some("ok".into()),
            25,
        );

        assert_eq!(record.granted_permissions().as_slice(), &[permission]);
        assert_eq!(audit.message.as_deref(), Some("ok"));
        assert_eq!(audit.created_at_unix, 25);

        let json = serde_json::to_string(&record.granted_permissions[0]).expect("serialize grant");
        let decoded: RadrootsNostrSignerPermissionGrant =
            serde_json::from_str(&json).expect("deserialize grant");
        assert_eq!(decoded.permission, Permission::new(Method::Ping));
    }

    #[test]
    fn publish_workflow_records_cover_connect_secret_and_auth_replay_lifecycle() {
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-workflow").expect("id");
        let pending_request =
            RadrootsNostrSignerPendingRequest::new(request_message("req-workflow"), 41)
                .expect("pending request");

        let connect_secret =
            RadrootsNostrSignerPublishWorkflowRecord::new_connect_secret_finalization(
                connection_id.clone(),
                40,
            );
        assert_eq!(
            connect_secret.kind,
            RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization
        );
        assert_eq!(
            connect_secret.state,
            RadrootsNostrSignerPublishWorkflowState::PendingPublish
        );
        assert!(connect_secret.pending_request.is_none());
        assert!(connect_secret.authorized_at_unix.is_none());

        let mut auth_replay =
            RadrootsNostrSignerPublishWorkflowRecord::new_auth_replay_finalization(
                connection_id,
                pending_request.clone(),
                42,
            );
        assert_eq!(
            auth_replay.kind,
            RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization
        );
        assert_eq!(
            auth_replay.state,
            RadrootsNostrSignerPublishWorkflowState::PendingPublish
        );
        assert_eq!(auth_replay.pending_request, Some(pending_request));
        assert_eq!(auth_replay.authorized_at_unix, Some(42));

        auth_replay.mark_published(43);
        assert_eq!(
            auth_replay.state,
            RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize
        );
        assert_eq!(auth_replay.updated_at_unix, 43);
    }

    #[test]
    fn effective_permissions_prefers_grants_then_auto_requested_then_empty() {
        let requested: Permissions = vec![Permission::new(Method::Nip04Encrypt)].into();
        let auto_record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            public_identity(0x31),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x32), public_identity(0x33))
                .with_requested_permissions(requested.clone()),
            1,
        );
        assert_eq!(auto_record.effective_permissions(), requested);

        let mut granted_record = auto_record.clone();
        granted_record.granted_permissions = vec![RadrootsNostrSignerPermissionGrant::new(
            Permission::new(Method::Ping),
            2,
        )];
        assert_eq!(
            granted_record.effective_permissions(),
            vec![Permission::new(Method::Ping)].into()
        );

        let mut approved_without_grants = auto_record;
        approved_without_grants.approval_state = RadrootsNostrSignerApprovalState::Approved;
        assert!(approved_without_grants.effective_permissions().is_empty());
    }

    #[test]
    fn permission_serde_helpers_round_trip_through_wrapper() {
        #[derive(Debug, Serialize, Deserialize)]
        struct PermissionWrapper {
            #[serde(
                serialize_with = "serialize_permission",
                deserialize_with = "deserialize_permission"
            )]
            permission: Permission,
        }

        let wrapper = PermissionWrapper {
            permission: Permission::with_parameter(Method::SignEvent, "kind:1"),
        };

        let json = serde_json::to_vec_pretty(&wrapper).expect("serialize wrapper");
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("permission.json");
        std::fs::write(&path, &json).expect("write permission");
        let file = std::fs::File::open(&path).expect("open permission");
        let reader = std::io::BufReader::new(file);
        let decoded: PermissionWrapper =
            serde_json::from_reader(reader).expect("deserialize wrapper");

        assert_eq!(decoded.permission, wrapper.permission);

        let value = serde_json::to_value(&wrapper).expect("serialize wrapper to value");
        let decoded_from_value: PermissionWrapper =
            serde_json::from_value(value).expect("deserialize wrapper from value");
        assert_eq!(decoded_from_value.permission, wrapper.permission);

        let invalid = serde_json::from_str::<PermissionWrapper>(r#"{"permission":1}"#)
            .expect_err("invalid permission type");
        assert!(invalid.to_string().contains("invalid type"));

        let invalid_from_value =
            serde_json::from_value::<PermissionWrapper>(json!({ "permission": 1 }))
                .expect_err("invalid permission type from value");
        assert!(invalid_from_value.to_string().contains("invalid type"));

        let invalid_path = temp.path().join("invalid-permission.json");
        std::fs::write(&invalid_path, br#"{"permission":1}"#).expect("write invalid permission");
        let invalid_file = std::fs::File::open(&invalid_path).expect("open invalid permission");
        let invalid_reader = std::io::BufReader::new(invalid_file);
        let invalid_from_reader = serde_json::from_reader::<_, PermissionWrapper>(invalid_reader)
            .expect_err("invalid permission type from reader");
        assert!(invalid_from_reader.to_string().contains("invalid type"));
    }

    #[test]
    fn connect_secret_hash_and_pending_request_helpers_validate_inputs() {
        let hash =
            RadrootsNostrSignerConnectSecretHash::from_secret(" secret ").expect("secret hash");
        assert!(hash.matches_secret("secret"));
        assert!(!hash.matches_secret("other"));
        assert!(RadrootsNostrSignerConnectSecretHash::from_secret("   ").is_none());

        let pending = RadrootsNostrSignerPendingRequest::new(request_message("req-2"), 30)
            .expect("pending request");
        assert_eq!(pending.request_id().as_str(), "req-2");
        assert_eq!(pending.request_message().id, "req-2");

        let invalid_pending = RadrootsNostrSignerPendingRequest::new(request_message("   "), 30)
            .expect_err("invalid pending request id");
        assert!(invalid_pending.to_string().contains("invalid request id"));

        let auth_url = format!(" {} ", api_primary_https());
        let challenge =
            RadrootsNostrSignerAuthChallenge::new(auth_url.as_str(), 31).expect("challenge");
        assert_eq!(challenge.auth_url, format!("{}/", api_primary_https()));

        let invalid_challenge =
            RadrootsNostrSignerAuthChallenge::new("not-a-url", 31).expect_err("invalid challenge");
        assert!(invalid_challenge.to_string().contains("invalid auth url"));

        let empty_challenge =
            RadrootsNostrSignerAuthChallenge::new("   ", 31).expect_err("empty challenge");
        assert!(empty_challenge.to_string().contains("invalid auth url"));
    }

    #[test]
    fn auth_challenge_deserialize_rejects_invalid_urls_across_entrypoints() {
        let invalid_json = json!({
            "auth_url": "   ",
            "required_at_unix": 44
        });

        let invalid_from_value =
            serde_json::from_value::<RadrootsNostrSignerAuthChallenge>(invalid_json.clone())
                .expect_err("invalid auth challenge from value");
        assert!(invalid_from_value.to_string().contains("invalid auth url"));

        let invalid_from_str =
            serde_json::from_str::<RadrootsNostrSignerAuthChallenge>(&invalid_json.to_string())
                .expect_err("invalid auth challenge from str");
        assert!(invalid_from_str.to_string().contains("invalid auth url"));

        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("invalid-auth-challenge.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&invalid_json).expect("serialize invalid auth challenge"),
        )
        .expect("write invalid auth challenge");
        let file = std::fs::File::open(&path).expect("open invalid auth challenge");
        let reader = std::io::BufReader::new(file);
        let invalid_from_reader =
            serde_json::from_reader::<_, RadrootsNostrSignerAuthChallenge>(reader)
                .expect_err("invalid auth challenge from reader");
        assert!(invalid_from_reader.to_string().contains("invalid auth url"));

        let invalid_shape_json = json!({
            "auth_url": 1,
            "required_at_unix": 44
        });
        let invalid_shape_from_value =
            serde_json::from_value::<RadrootsNostrSignerAuthChallenge>(invalid_shape_json.clone())
                .expect_err("invalid auth challenge shape from value");
        assert!(
            invalid_shape_from_value
                .to_string()
                .contains("invalid type")
        );

        let invalid_shape_from_str = serde_json::from_str::<RadrootsNostrSignerAuthChallenge>(
            &invalid_shape_json.to_string(),
        )
        .expect_err("invalid auth challenge shape from str");
        assert!(invalid_shape_from_str.to_string().contains("invalid type"));

        let invalid_shape_path = temp.path().join("invalid-auth-challenge-shape.json");
        std::fs::write(
            &invalid_shape_path,
            serde_json::to_vec(&invalid_shape_json)
                .expect("serialize invalid auth challenge shape"),
        )
        .expect("write invalid auth challenge shape");
        let invalid_shape_file =
            std::fs::File::open(&invalid_shape_path).expect("open invalid auth challenge shape");
        let invalid_shape_reader = std::io::BufReader::new(invalid_shape_file);
        let invalid_shape_from_reader =
            serde_json::from_reader::<_, RadrootsNostrSignerAuthChallenge>(invalid_shape_reader)
                .expect_err("invalid auth challenge shape from reader");
        assert!(
            invalid_shape_from_reader
                .to_string()
                .contains("invalid type")
        );
    }

    #[test]
    fn connection_record_serde_migrates_legacy_connect_secret_and_validates_new_fields() {
        let record_json = json!({
            "connection_id": "conn-legacy",
            "client_public_key": public_key(0x9).to_hex(),
            "signer_identity": public_identity(0x10),
            "user_identity": public_identity(0x11),
            "connect_secret": " legacy-secret ",
            "requested_permissions": "",
            "granted_permissions": [],
            "relays": [],
            "approval_requirement": "NotRequired",
            "approval_state": "NotRequired",
            "status": "Active",
            "status_reason": null,
            "created_at_unix": 1,
            "updated_at_unix": 1,
            "last_authenticated_at_unix": null,
            "last_request_at_unix": null
        });

        let decoded_without_secret: RadrootsNostrSignerConnectionRecord =
            serde_json::from_value(json!({
                "connection_id": "conn-no-secret",
                "client_public_key": public_key(0x8).to_hex(),
                "signer_identity": public_identity(0x7),
                "user_identity": public_identity(0x6),
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 0,
                "updated_at_unix": 0,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect("deserialize record without secret");
        assert!(decoded_without_secret.connect_secret_hash.is_none());
        assert!(decoded_without_secret.client_metadata.is_none());
        assert!(
            decoded_without_secret
                .connect_secret_consumed_at_unix
                .is_none()
        );

        let decoded_with_null_secret: RadrootsNostrSignerConnectionRecord =
            serde_json::from_value(json!({
                "connection_id": "conn-null-secret",
                "client_public_key": public_key(0x5).to_hex(),
                "signer_identity": public_identity(0x4),
                "user_identity": public_identity(0x3),
                "connect_secret_hash": null,
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 0,
                "updated_at_unix": 0,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect("deserialize record with null secret");
        assert!(decoded_with_null_secret.connect_secret_hash.is_none());
        assert!(
            decoded_with_null_secret
                .connect_secret_consumed_at_unix
                .is_none()
        );

        let decoded: RadrootsNostrSignerConnectionRecord =
            serde_json::from_value(record_json).expect("deserialize legacy record");
        assert!(
            decoded
                .connect_secret_hash
                .as_ref()
                .expect("connect secret hash")
                .matches_secret("legacy-secret")
        );

        let encoded = serde_json::to_value(&decoded).expect("serialize record");
        assert!(encoded.get("connect_secret").is_none());
        assert!(encoded.get("connect_secret_hash").is_some());
        assert!(encoded.get("connect_secret_consumed_at_unix").is_none());
        assert_eq!(
            encoded
                .get("auth_state")
                .and_then(serde_json::Value::as_str),
            Some("NotRequired")
        );

        let valid_hash = RadrootsNostrSignerConnectSecretHash::from_secret("explicit-secret")
            .expect("valid hash");
        let decoded_new_format: RadrootsNostrSignerConnectionRecord =
            serde_json::from_value(json!({
                "connection_id": "conn-new",
                "client_public_key": public_key(0x15).to_hex(),
                "signer_identity": public_identity(0x16),
                "user_identity": public_identity(0x17),
                "connect_secret_hash": {
                    "algorithm": "sha256",
                    "digest_hex": valid_hash.digest_hex
                },
                "connect_secret_consumed_at_unix": 23,
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 3,
                "updated_at_unix": 3,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect("deserialize new-format record");
        assert!(
            decoded_new_format
                .connect_secret_hash
                .as_ref()
                .expect("new-format hash")
                .matches_secret("explicit-secret")
        );
        assert_eq!(decoded_new_format.connect_secret_consumed_at_unix, Some(23));
        assert!(decoded_new_format.connect_secret_is_consumed());

        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("connection-record.json");
        let reader_json = json!({
            "connection_id": "conn-reader",
            "client_public_key": public_key(0x21).to_hex(),
            "signer_identity": public_identity(0x22),
            "user_identity": public_identity(0x23),
            "connect_secret_hash": {
                "algorithm": "sha256",
                "digest_hex": RadrootsNostrSignerConnectSecretHash::from_secret("reader-secret")
                    .expect("reader hash")
                    .digest_hex
            },
            "requested_permissions": "",
            "granted_permissions": [],
            "relays": [],
            "approval_requirement": "NotRequired",
            "approval_state": "NotRequired",
            "auth_state": "Pending",
            "auth_challenge": {
                "auth_url": format!("{}/reader", api_primary_https()),
                "required_at_unix": 5
            },
            "status": "Active",
            "created_at_unix": 5,
            "updated_at_unix": 5,
            "last_authenticated_at_unix": null,
            "last_request_at_unix": null
        });
        std::fs::write(
            &path,
            serde_json::to_vec(&reader_json).expect("serialize reader json"),
        )
        .expect("write reader json");
        let file = std::fs::File::open(&path).expect("open reader json");
        let reader = std::io::BufReader::new(file);
        let decoded_from_reader: RadrootsNostrSignerConnectionRecord =
            serde_json::from_reader(reader).expect("deserialize reader record");
        assert!(
            decoded_from_reader
                .connect_secret_hash
                .as_ref()
                .expect("reader hash")
                .matches_secret("reader-secret")
        );
        assert_eq!(
            decoded_from_reader
                .auth_challenge
                .as_ref()
                .expect("reader auth challenge")
                .auth_url,
            format!("{}/reader", api_primary_https())
        );

        let invalid_hash_json = json!({
            "connection_id": "conn-invalid",
            "client_public_key": public_key(0x12).to_hex(),
            "signer_identity": public_identity(0x13),
            "user_identity": public_identity(0x14),
            "connect_secret_hash": {
                "algorithm": "sha256",
                "digest_hex": "not-hex"
            },
            "requested_permissions": "",
            "granted_permissions": [],
            "relays": [],
            "approval_requirement": "NotRequired",
            "approval_state": "NotRequired",
            "status": "Active",
            "auth_state": "Authorized",
            "auth_challenge": {
                "auth_url": api_primary_https(),
                "required_at_unix": 2
            },
            "status_reason": null,
            "created_at_unix": 2,
            "updated_at_unix": 2,
            "last_authenticated_at_unix": null,
            "last_request_at_unix": null
        });
        let invalid_hash =
            serde_json::from_value::<RadrootsNostrSignerConnectionRecord>(invalid_hash_json)
                .expect_err("invalid hash");
        assert!(
            invalid_hash
                .to_string()
                .contains("invalid connect secret digest")
        );

        let invalid_nonhex_hash =
            serde_json::from_value::<RadrootsNostrSignerConnectionRecord>(json!({
                "connection_id": "conn-invalid-nonhex",
                "client_public_key": public_key(0x18).to_hex(),
                "signer_identity": public_identity(0x19),
                "user_identity": public_identity(0x20),
                "connect_secret_hash": {
                    "algorithm": "sha256",
                    "digest_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                },
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 4,
                "updated_at_unix": 4,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect_err("invalid nonhex hash");
        assert!(
            invalid_nonhex_hash
                .to_string()
                .contains("invalid connect secret digest")
        );

        let invalid_connect_secret_hash_type =
            serde_json::from_value::<RadrootsNostrSignerConnectionRecord>(json!({
                "connection_id": "conn-invalid-type",
                "client_public_key": public_key(0x24).to_hex(),
                "signer_identity": public_identity(0x25),
                "user_identity": public_identity(0x26),
                "connect_secret_hash": 7,
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 6,
                "updated_at_unix": 6,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect_err("invalid connect secret hash type");
        assert!(!invalid_connect_secret_hash_type.to_string().is_empty());

        let invalid_connect_secret_hash_path = temp.path().join("invalid-connect-secret-type.json");
        std::fs::write(
            &invalid_connect_secret_hash_path,
            serde_json::to_vec(&json!({
                "connection_id": "conn-invalid-type-reader",
                "client_public_key": public_key(0x27).to_hex(),
                "signer_identity": public_identity(0x28),
                "user_identity": public_identity(0x29),
                "connect_secret_hash": 9,
                "requested_permissions": "",
                "granted_permissions": [],
                "relays": [],
                "approval_requirement": "NotRequired",
                "approval_state": "NotRequired",
                "status": "Active",
                "created_at_unix": 7,
                "updated_at_unix": 7,
                "last_authenticated_at_unix": null,
                "last_request_at_unix": null
            }))
            .expect("serialize invalid connect secret hash type"),
        )
        .expect("write invalid connect secret hash type");
        let invalid_connect_secret_hash_file =
            std::fs::File::open(&invalid_connect_secret_hash_path)
                .expect("open invalid connect secret hash type");
        let invalid_connect_secret_hash_reader =
            std::io::BufReader::new(invalid_connect_secret_hash_file);
        let invalid_connect_secret_hash_from_reader = serde_json::from_reader::<
            _,
            RadrootsNostrSignerConnectionRecord,
        >(invalid_connect_secret_hash_reader)
        .expect_err("invalid connect secret hash type from reader");
        assert!(
            !invalid_connect_secret_hash_from_reader
                .to_string()
                .is_empty()
        );
    }

    #[test]
    fn store_state_default_is_empty() {
        let state = RadrootsNostrSignerStoreState::default();
        assert_eq!(state.version, RADROOTS_NOSTR_SIGNER_STORE_VERSION);
        assert!(state.signer_identity.is_none());
        assert!(state.connections.is_empty());
        assert!(state.audit_records.is_empty());
    }
}
