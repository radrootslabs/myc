use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::capability::{
    RadrootsNostrLocalSignerAvailability, RadrootsNostrLocalSignerCapability,
    RadrootsNostrRemoteSessionSignerCapability, RadrootsNostrSignerCapability,
};
use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::evaluation::{
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerRequestEvaluation,
    RadrootsNostrSignerSessionLookup,
};
use crate::signer::manager::RadrootsNostrSignerManager;
use crate::signer::model::{
    RadrootsNostrSignerAuthorizationOutcome, RadrootsNostrSignerConnectionDraft,
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerConnectionStatus, RadrootsNostrSignerPendingRequest,
    RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerRequestAuditRecord,
    RadrootsNostrSignerRequestDecision, RadrootsNostrSignerWorkflowId,
};
use nostr::{Event, Keys, PublicKey, RelayUrl, UnsignedEvent};
use radroots_identity::PublicKey as IdentityPublicKey;
use radroots_nostr_connect::{Method, Request, message::RequestMessage, permission::Permissions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrSignerBackendCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_signer: Option<RadrootsNostrLocalSignerCapability>,
    #[serde(default)]
    pub remote_sessions: Vec<RadrootsNostrRemoteSessionSignerCapability>,
}

/// Result of signing an externally supplied unsigned Nostr event.
///
/// This low-level protocol result does not establish Radroots typed-authoring
/// validity for the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrSignerSignOutput {
    pub signer: RadrootsNostrSignerCapability,
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
pub enum RadrootsNostrSignerPublishTransition {
    Begun(RadrootsNostrSignerPublishWorkflowRecord),
    MarkedPublished(RadrootsNostrSignerPublishWorkflowRecord),
    Finalized {
        workflow_id: RadrootsNostrSignerWorkflowId,
        connection: Box<RadrootsNostrSignerConnectionRecord>,
    },
    Cancelled(RadrootsNostrSignerPublishWorkflowRecord),
}

pub trait RadrootsNostrSignerBackend: Send + Sync {
    fn signer_identity(&self) -> Result<Option<PublicIdentity>, RadrootsNostrSignerError>;

    fn set_signer_identity(
        &self,
        signer_identity: PublicIdentity,
    ) -> Result<(), RadrootsNostrSignerError>;

    fn capabilities(
        &self,
    ) -> Result<RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerError>;

    fn list_connections(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError>;

    fn get_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError>;

    fn list_publish_workflows(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError>;

    fn get_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError>;

    fn find_connections_by_client_public_key(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError>;

    fn find_connection_by_connect_secret(
        &self,
        connect_secret: &str,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError>;

    fn lookup_session(
        &self,
        client_public_key: &PublicKey,
        connect_secret: Option<&str>,
    ) -> Result<RadrootsNostrSignerSessionLookup, RadrootsNostrSignerError>;

    fn evaluate_connect_request(
        &self,
        client_public_key: PublicKey,
        request: Request,
    ) -> Result<RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerError>;

    fn register_connection(
        &self,
        draft: RadrootsNostrSignerConnectionDraft,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn set_granted_permissions(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn approve_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn reject_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn revoke_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn update_relays(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        relays: Vec<RelayUrl>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn require_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        auth_url: &str,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn set_pending_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn authorize_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerAuthorizationOutcome, RadrootsNostrSignerError>;

    fn restore_pending_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        pending_request: RadrootsNostrSignerPendingRequest,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn begin_connect_secret_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError>;

    fn begin_auth_replay_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError>;

    fn mark_publish_workflow_published(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError>;

    fn finalize_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError>;

    fn cancel_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError>;

    fn mark_authenticated(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn mark_connect_secret_consumed(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError>;

    fn evaluate_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError>;

    fn evaluate_auth_replay_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError>;

    fn record_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_id: &str,
        method: Method,
        decision: RadrootsNostrSignerRequestDecision,
        message: Option<String>,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerError>;

    /// Signs an externally supplied unsigned Nostr event.
    ///
    /// This is a low-level interoperability boundary used by generic signer
    /// protocols. It does not validate or confer a Radroots product-authoring
    /// contract; product events must use their typed authoring boundary.
    fn sign_unsigned_event(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<RadrootsNostrSignerSignOutput, RadrootsNostrSignerError>;
}

#[derive(Clone)]
pub struct RadrootsNostrEmbeddedSignerBackend {
    manager: RadrootsNostrSignerManager,
    signer_keys: Keys,
    signer_identity: PublicIdentity,
}

impl RadrootsNostrSignerBackendCapabilities {
    pub fn new(
        local_signer: Option<RadrootsNostrLocalSignerCapability>,
        remote_sessions: Vec<RadrootsNostrRemoteSessionSignerCapability>,
    ) -> Self {
        Self {
            local_signer,
            remote_sessions,
        }
    }

    pub fn all_signers(&self) -> Vec<RadrootsNostrSignerCapability> {
        let mut signers = Vec::new();
        if let Some(local_signer) = self.local_signer.clone() {
            signers.push(RadrootsNostrSignerCapability::LocalAccount(Box::new(
                local_signer,
            )));
        }
        signers.extend(
            self.remote_sessions
                .iter()
                .cloned()
                .map(Box::new)
                .map(RadrootsNostrSignerCapability::RemoteSession),
        );
        signers
    }
}

impl RadrootsNostrSignerSignOutput {
    pub fn new(signer: RadrootsNostrSignerCapability, event: Event) -> Self {
        Self { signer, event }
    }
}

impl RadrootsNostrSignerPublishTransition {
    pub fn begun(workflow: RadrootsNostrSignerPublishWorkflowRecord) -> Self {
        Self::Begun(workflow)
    }

    pub fn marked_published(workflow: RadrootsNostrSignerPublishWorkflowRecord) -> Self {
        Self::MarkedPublished(workflow)
    }

    pub fn finalized(
        workflow_id: RadrootsNostrSignerWorkflowId,
        connection: RadrootsNostrSignerConnectionRecord,
    ) -> Self {
        Self::Finalized {
            workflow_id,
            connection: Box::new(connection),
        }
    }

    pub fn cancelled(workflow: RadrootsNostrSignerPublishWorkflowRecord) -> Self {
        Self::Cancelled(workflow)
    }

    pub fn workflow(&self) -> Option<&RadrootsNostrSignerPublishWorkflowRecord> {
        match self {
            Self::Begun(workflow) | Self::MarkedPublished(workflow) | Self::Cancelled(workflow) => {
                Some(workflow)
            }
            Self::Finalized { .. } => None,
        }
    }

    pub fn finalized_connection(&self) -> Option<&RadrootsNostrSignerConnectionRecord> {
        match self {
            Self::Finalized { connection, .. } => Some(connection.as_ref()),
            _ => None,
        }
    }
}

impl RadrootsNostrEmbeddedSignerBackend {
    pub fn new(
        manager: RadrootsNostrSignerManager,
        signer_keys: Keys,
    ) -> Result<Self, RadrootsNostrSignerError> {
        let signer_identity = public_identity_from_keys(&signer_keys)?;
        let existing_identity = manager.signer_identity()?;
        if let Some(existing_identity) = existing_identity {
            if !same_public_identity_key(&existing_identity, &signer_identity) {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "embedded signer identity does not match signer manager identity".into(),
                ));
            }
        } else {
            manager.set_signer_identity(signer_identity.clone())?;
        }

        Ok(Self {
            manager,
            signer_keys,
            signer_identity,
        })
    }

    pub fn new_in_memory(signer_keys: Keys) -> Result<Self, RadrootsNostrSignerError> {
        Self::new(RadrootsNostrSignerManager::new_in_memory(), signer_keys)
    }

    pub fn manager(&self) -> &RadrootsNostrSignerManager {
        &self.manager
    }

    pub fn local_keys(&self) -> &Keys {
        &self.signer_keys
    }

    fn local_signer_capability(&self) -> RadrootsNostrLocalSignerCapability {
        let public_identity = self.signer_identity.clone();
        RadrootsNostrLocalSignerCapability::new(
            public_identity.id.to_final().into(),
            public_identity,
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        )
    }
}

impl RadrootsNostrSignerBackend for RadrootsNostrEmbeddedSignerBackend {
    fn signer_identity(&self) -> Result<Option<PublicIdentity>, RadrootsNostrSignerError> {
        self.manager.signer_identity()
    }

    fn set_signer_identity(
        &self,
        signer_identity: PublicIdentity,
    ) -> Result<(), RadrootsNostrSignerError> {
        self.manager.set_signer_identity(signer_identity)
    }

    fn capabilities(
        &self,
    ) -> Result<RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerError> {
        let mut remote_sessions = Vec::new();
        for record in self.manager.list_connections()? {
            if record.status == RadrootsNostrSignerConnectionStatus::Active {
                remote_sessions.push(RadrootsNostrRemoteSessionSignerCapability::from(&record));
            }
        }
        Ok(RadrootsNostrSignerBackendCapabilities::new(
            Some(self.local_signer_capability()),
            remote_sessions,
        ))
    }

    fn list_connections(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager.list_connections()
    }

    fn get_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager.get_connection(connection_id)
    }

    fn list_publish_workflows(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        self.manager.list_publish_workflows()
    }

    fn get_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        self.manager.get_publish_workflow(workflow_id)
    }

    fn find_connections_by_client_public_key(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager
            .find_connections_by_client_public_key(client_public_key)
    }

    fn find_connection_by_connect_secret(
        &self,
        connect_secret: &str,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager
            .find_connection_by_connect_secret(connect_secret)
    }

    fn lookup_session(
        &self,
        client_public_key: &PublicKey,
        connect_secret: Option<&str>,
    ) -> Result<RadrootsNostrSignerSessionLookup, RadrootsNostrSignerError> {
        self.manager
            .lookup_session(client_public_key, connect_secret)
    }

    fn evaluate_connect_request(
        &self,
        client_public_key: PublicKey,
        request: Request,
    ) -> Result<RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerError> {
        self.manager
            .evaluate_connect_request(client_public_key, request)
    }

    fn register_connection(
        &self,
        draft: RadrootsNostrSignerConnectionDraft,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.register_connection(draft)
    }

    fn set_granted_permissions(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager
            .set_granted_permissions(connection_id, granted_permissions)
    }

    fn approve_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager
            .approve_connection(connection_id, granted_permissions)
    }

    fn reject_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.reject_connection(connection_id, reason)
    }

    fn revoke_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.revoke_connection(connection_id, reason)
    }

    fn update_relays(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        relays: Vec<RelayUrl>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.update_relays(connection_id, relays)
    }

    fn require_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        auth_url: &str,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.require_auth_challenge(connection_id, auth_url)
    }

    fn set_pending_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager
            .set_pending_request(connection_id, request_message)
    }

    fn authorize_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerAuthorizationOutcome, RadrootsNostrSignerError> {
        self.manager.authorize_auth_challenge(connection_id)
    }

    fn restore_pending_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        pending_request: RadrootsNostrSignerPendingRequest,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager
            .restore_pending_auth_challenge(connection_id, pending_request)
    }

    fn begin_connect_secret_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let workflow = self
            .manager
            .begin_connect_secret_publish_finalization(connection_id)?;
        Ok(RadrootsNostrSignerPublishTransition::begun(workflow))
    }

    fn begin_auth_replay_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let workflow = self
            .manager
            .begin_auth_replay_publish_finalization(connection_id)?;
        Ok(RadrootsNostrSignerPublishTransition::begun(workflow))
    }

    fn mark_publish_workflow_published(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let workflow = self.manager.mark_publish_workflow_published(workflow_id)?;
        Ok(RadrootsNostrSignerPublishTransition::marked_published(
            workflow,
        ))
    }

    fn finalize_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let connection = self.manager.finalize_publish_workflow(workflow_id)?;
        Ok(RadrootsNostrSignerPublishTransition::finalized(
            workflow_id.clone(),
            connection,
        ))
    }

    fn cancel_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let workflow = self.manager.cancel_publish_workflow(workflow_id)?;
        Ok(RadrootsNostrSignerPublishTransition::cancelled(workflow))
    }

    fn mark_authenticated(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.mark_authenticated(connection_id)
    }

    fn mark_connect_secret_consumed(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager.mark_connect_secret_consumed(connection_id)
    }

    fn evaluate_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        self.manager
            .evaluate_request(connection_id, request_message)
    }

    fn evaluate_auth_replay_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        self.manager
            .evaluate_auth_replay_publish_workflow(workflow_id)
    }

    fn record_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_id: &str,
        method: Method,
        decision: RadrootsNostrSignerRequestDecision,
        message: Option<String>,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerError> {
        self.manager
            .record_request(connection_id, request_id, method, decision, message)
    }

    fn sign_unsigned_event(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<RadrootsNostrSignerSignOutput, RadrootsNostrSignerError> {
        let event = unsigned_event.sign_with_keys(&self.signer_keys)?;
        Ok(RadrootsNostrSignerSignOutput::new(
            RadrootsNostrSignerCapability::LocalAccount(Box::new(self.local_signer_capability())),
            event,
        ))
    }
}

fn same_public_identity_key(left: &PublicIdentity, right: &PublicIdentity) -> bool {
    left.id() == right.id() && left.public_key() == right.public_key()
}

fn public_identity_from_keys(keys: &Keys) -> Result<PublicIdentity, RadrootsNostrSignerError> {
    let public_key = IdentityPublicKey::from_hex(&keys.public_key().to_hex()).map_err(|error| {
        RadrootsNostrSignerError::InvalidState(format!(
            "embedded signer public key is invalid: {error}"
        ))
    })?;
    PublicIdentity::from_final_public_key(public_key).map_err(|error| {
        RadrootsNostrSignerError::InvalidState(format!(
            "embedded signer public key is invalid: {error}"
        ))
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RadrootsNostrEmbeddedSignerBackend, RadrootsNostrSignerBackend,
        RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerPublishTransition,
        same_public_identity_key,
    };
    use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
    use crate::signer::error::RadrootsNostrSignerError;
    use crate::signer::evaluation::{
        RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectProposal,
        RadrootsNostrSignerRequestAction, RadrootsNostrSignerSessionLookup,
    };
    use crate::signer::manager::RadrootsNostrSignerManager;
    use crate::signer::model::{
        RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerConnectionDraft,
        RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerConnectionStatus,
        RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerRequestDecision,
        RadrootsNostrSignerStoreState, RadrootsNostrSignerWorkflowId,
    };
    use crate::signer::store::RadrootsNostrSignerStore;
    use crate::signer::test_support::{
        fixture_bob_identity, primary_relay, secondary_relay, synthetic_keys,
        synthetic_public_identity, synthetic_public_key,
    };
    use nostr::{EventBuilder, EventId, Keys, Kind};
    use radroots_nostr_connect::{Method, Permission, Request, message::RequestMessage};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU8, Ordering};

    fn embedded_identity(index: u32) -> Keys {
        synthetic_keys(index)
    }

    fn embedded_public_identity(keys: &Keys) -> PublicIdentity {
        PublicIdentity::new(keys.public_key()).expect("identity public key")
    }

    fn expect_registration_required(
        evaluation: RadrootsNostrSignerConnectEvaluation,
    ) -> RadrootsNostrSignerConnectProposal {
        match evaluation {
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => proposal,
            other => panic!("unexpected connect evaluation: {other:?}"),
        }
    }

    fn expect_lookup_connection(
        lookup: RadrootsNostrSignerSessionLookup,
    ) -> RadrootsNostrSignerConnectionRecord {
        match lookup {
            RadrootsNostrSignerSessionLookup::Connection(found) => *found,
            other => panic!("unexpected session lookup: {other:?}"),
        }
    }

    fn expect_begun_workflow_id(
        transition: RadrootsNostrSignerPublishTransition,
    ) -> RadrootsNostrSignerWorkflowId {
        match transition {
            RadrootsNostrSignerPublishTransition::Begun(workflow) => workflow.workflow_id,
            other => panic!("unexpected begin transition: {other:?}"),
        }
    }

    fn expect_finalized_transition(
        transition: RadrootsNostrSignerPublishTransition,
    ) -> (
        RadrootsNostrSignerWorkflowId,
        RadrootsNostrSignerConnectionRecord,
    ) {
        match transition {
            RadrootsNostrSignerPublishTransition::Finalized {
                workflow_id,
                connection,
            } => (workflow_id, *connection),
            other => panic!("unexpected finalize transition: {other:?}"),
        }
    }

    struct StubBackend {
        signer_identity: Option<PublicIdentity>,
        signer_identity_error: Option<&'static str>,
        sign_error_message: Option<&'static str>,
    }

    #[derive(Default)]
    struct ToggleSaveStore {
        state: RwLock<RadrootsNostrSignerStoreState>,
        mode: AtomicU8,
    }

    impl ToggleSaveStore {
        fn set_mode(&self, mode: u8) {
            self.mode.store(mode, Ordering::SeqCst);
        }
    }

    impl RadrootsNostrSignerStore for ToggleSaveStore {
        fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
            let guard = self.state.read().map_err(|_| {
                RadrootsNostrSignerError::Store("toggle store lock poisoned".into())
            })?;
            Ok(guard.clone())
        }

        fn save(
            &self,
            state: &RadrootsNostrSignerStoreState,
        ) -> Result<(), RadrootsNostrSignerError> {
            match self.mode.load(Ordering::SeqCst) {
                1 => Err(RadrootsNostrSignerError::Store("save failed".into())),
                2 => panic!("toggle save panic"),
                _ => {
                    let mut guard = self.state.write().map_err(|_| {
                        RadrootsNostrSignerError::Store("toggle store lock poisoned".into())
                    })?;
                    *guard = state.clone();
                    Ok(())
                }
            }
        }
    }

    impl RadrootsNostrSignerBackend for StubBackend {
        fn signer_identity(&self) -> Result<Option<PublicIdentity>, RadrootsNostrSignerError> {
            if let Some(message) = self.signer_identity_error {
                return Err(RadrootsNostrSignerError::InvalidState(message.into()));
            }
            Ok(self.signer_identity.clone())
        }

        fn set_signer_identity(
            &self,
            _signer_identity: PublicIdentity,
        ) -> Result<(), RadrootsNostrSignerError> {
            unreachable!("set_signer_identity not used in tests")
        }

        fn capabilities(
            &self,
        ) -> Result<RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerError> {
            unreachable!("capabilities not used in tests")
        }

        fn list_connections(
            &self,
        ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
            unreachable!("list_connections not used in tests")
        }

        fn get_connection(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
            unreachable!("get_connection not used in tests")
        }

        fn list_publish_workflows(
            &self,
        ) -> Result<Vec<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError>
        {
            unreachable!("list_publish_workflows not used in tests")
        }

        fn get_publish_workflow(
            &self,
            _workflow_id: &RadrootsNostrSignerWorkflowId,
        ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError>
        {
            unreachable!("get_publish_workflow not used in tests")
        }

        fn find_connections_by_client_public_key(
            &self,
            _client_public_key: &nostr::PublicKey,
        ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
            unreachable!("find_connections_by_client_public_key not used in tests")
        }

        fn find_connection_by_connect_secret(
            &self,
            _connect_secret: &str,
        ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
            unreachable!("find_connection_by_connect_secret not used in tests")
        }

        fn lookup_session(
            &self,
            _client_public_key: &nostr::PublicKey,
            _connect_secret: Option<&str>,
        ) -> Result<RadrootsNostrSignerSessionLookup, RadrootsNostrSignerError> {
            unreachable!("lookup_session not used in tests")
        }

        fn evaluate_connect_request(
            &self,
            _client_public_key: nostr::PublicKey,
            _request: Request,
        ) -> Result<RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerError> {
            unreachable!("evaluate_connect_request not used in tests")
        }

        fn register_connection(
            &self,
            _draft: RadrootsNostrSignerConnectionDraft,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("register_connection not used in tests")
        }

        fn set_granted_permissions(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _granted_permissions: radroots_nostr_connect::permission::Permissions,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("set_granted_permissions not used in tests")
        }

        fn approve_connection(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _granted_permissions: radroots_nostr_connect::permission::Permissions,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("approve_connection not used in tests")
        }

        fn reject_connection(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _reason: Option<String>,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("reject_connection not used in tests")
        }

        fn revoke_connection(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _reason: Option<String>,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("revoke_connection not used in tests")
        }

        fn update_relays(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _relays: Vec<nostr::RelayUrl>,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("update_relays not used in tests")
        }

        fn require_auth_challenge(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _auth_url: &str,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("require_auth_challenge not used in tests")
        }

        fn set_pending_request(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _request_message: RequestMessage,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("set_pending_request not used in tests")
        }

        fn authorize_auth_challenge(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<
            crate::signer::model::RadrootsNostrSignerAuthorizationOutcome,
            RadrootsNostrSignerError,
        > {
            unreachable!("authorize_auth_challenge not used in tests")
        }

        fn restore_pending_auth_challenge(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _pending_request: crate::signer::model::RadrootsNostrSignerPendingRequest,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("restore_pending_auth_challenge not used in tests")
        }

        fn begin_connect_secret_publish_finalization(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
            unreachable!("begin_connect_secret_publish_finalization not used in tests")
        }

        fn begin_auth_replay_publish_finalization(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
            unreachable!("begin_auth_replay_publish_finalization not used in tests")
        }

        fn mark_publish_workflow_published(
            &self,
            _workflow_id: &RadrootsNostrSignerWorkflowId,
        ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
            unreachable!("mark_publish_workflow_published not used in tests")
        }

        fn finalize_publish_workflow(
            &self,
            _workflow_id: &RadrootsNostrSignerWorkflowId,
        ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
            unreachable!("finalize_publish_workflow not used in tests")
        }

        fn cancel_publish_workflow(
            &self,
            _workflow_id: &RadrootsNostrSignerWorkflowId,
        ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
            unreachable!("cancel_publish_workflow not used in tests")
        }

        fn mark_authenticated(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("mark_authenticated not used in tests")
        }

        fn mark_connect_secret_consumed(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
        ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
            unreachable!("mark_connect_secret_consumed not used in tests")
        }

        fn evaluate_request(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _request_message: RequestMessage,
        ) -> Result<
            crate::signer::evaluation::RadrootsNostrSignerRequestEvaluation,
            RadrootsNostrSignerError,
        > {
            unreachable!("evaluate_request not used in tests")
        }

        fn evaluate_auth_replay_publish_workflow(
            &self,
            _workflow_id: &RadrootsNostrSignerWorkflowId,
        ) -> Result<
            crate::signer::evaluation::RadrootsNostrSignerRequestEvaluation,
            RadrootsNostrSignerError,
        > {
            unreachable!("evaluate_auth_replay_publish_workflow not used in tests")
        }

        fn record_request(
            &self,
            _connection_id: &crate::signer::model::RadrootsNostrSignerConnectionId,
            _request_id: &str,
            _method: Method,
            _decision: RadrootsNostrSignerRequestDecision,
            _message: Option<String>,
        ) -> Result<
            crate::signer::model::RadrootsNostrSignerRequestAuditRecord,
            RadrootsNostrSignerError,
        > {
            unreachable!("record_request not used in tests")
        }

        fn sign_unsigned_event(
            &self,
            _unsigned_event: nostr::UnsignedEvent,
        ) -> Result<super::RadrootsNostrSignerSignOutput, RadrootsNostrSignerError> {
            match self.sign_error_message {
                Some(message) => Err(RadrootsNostrSignerError::InvalidState(message.into())),
                None => unreachable!("sign_unsigned_event success path not used in tests"),
            }
        }
    }

    #[test]
    fn embedded_backend_bootstraps_signer_identity_and_capabilities() {
        let identity = embedded_identity(0x90);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");

        let signer_identity = backend
            .signer_identity()
            .expect("signer identity")
            .expect("present");
        assert_eq!(signer_identity, embedded_public_identity(&identity));

        let capabilities = backend.capabilities().expect("capabilities");
        let local = capabilities.local_signer.clone().expect("local signer");
        assert_eq!(local.public_identity, embedded_public_identity(&identity));
        assert!(local.is_secret_backed());
        assert!(capabilities.remote_sessions.is_empty());
        assert_eq!(capabilities.all_signers().len(), 1);
        let manager_identity = backend
            .manager()
            .signer_identity()
            .expect("manager signer identity")
            .expect("stored signer identity");
        assert!(same_public_identity_key(
            &manager_identity,
            &embedded_public_identity(&identity)
        ));
        assert_eq!(backend.local_keys().public_key(), identity.public_key());
    }

    #[test]
    fn embedded_backend_rejects_mismatched_manager_identity() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(fixture_bob_identity())
            .expect("set signer identity");

        let error = match RadrootsNostrEmbeddedSignerBackend::new(manager, embedded_identity(0x91))
        {
            Ok(_) => panic!("mismatched identity"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("embedded signer identity does not match")
        );
    }

    #[test]
    fn embedded_backend_accepts_matching_manager_identity_and_setter_delegate() {
        let identity = embedded_identity(0x97);
        let manager = RadrootsNostrSignerManager::new_in_memory();
        let public_identity = embedded_public_identity(&identity);
        manager
            .set_signer_identity(public_identity.clone())
            .expect("prime manager identity");

        let backend = RadrootsNostrEmbeddedSignerBackend::new(manager, identity.clone())
            .expect("matching embedded backend");
        let backend_trait: &dyn RadrootsNostrSignerBackend = &backend;

        assert_eq!(backend.local_keys().public_key(), identity.public_key());
        assert!(same_public_identity_key(
            backend_trait
                .signer_identity()
                .expect("signer identity")
                .as_ref()
                .expect("present"),
            &public_identity
        ));

        backend_trait
            .set_signer_identity(public_identity.clone())
            .expect("delegate set signer identity");
        let manager_identity = backend
            .manager()
            .signer_identity()
            .expect("manager signer identity")
            .expect("stored signer identity");
        assert!(same_public_identity_key(
            &manager_identity,
            &public_identity
        ));
    }

    #[test]
    fn backend_source_does_not_accept_raw_event_builders() {
        let production_source = include_str!("backend.rs")
            .split("\n#[cfg(test)]")
            .next()
            .expect("production backend source");

        assert!(!production_source.contains(concat!("fn sign_event_", "builder")));
    }

    #[test]
    fn external_unsigned_signing_propagates_backend_errors() {
        let backend = StubBackend {
            signer_identity: None,
            signer_identity_error: None,
            sign_error_message: Some("stub interop signing failure"),
        };
        let unsigned_event =
            EventBuilder::new(Kind::TextNote, "external interop").build(synthetic_public_key(0xaa));

        let error = backend
            .sign_unsigned_event(unsigned_event)
            .expect_err("external unsigned signing failure");

        assert!(error.to_string().contains("stub interop signing failure"));
    }

    #[test]
    fn capabilities_only_include_active_remote_sessions() {
        let identity = embedded_identity(0xac);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let backend_trait: &dyn RadrootsNostrSignerBackend = &backend;

        let active = backend_trait
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                synthetic_public_key(0xad),
                synthetic_public_identity(0xae),
            ))
            .expect("register active");

        let pending = backend_trait
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    synthetic_public_key(0xaf),
                    synthetic_public_identity(0xb0),
                )
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::ExplicitUser),
            )
            .expect("register pending");
        let rejected = backend_trait
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                synthetic_public_key(0xb1),
                synthetic_public_identity(0xb2),
            ))
            .expect("register rejected");
        backend_trait
            .reject_connection(&rejected.connection_id, Some("rejected".into()))
            .expect("reject connection");

        let capabilities = backend_trait.capabilities().expect("capabilities");
        assert_eq!(capabilities.remote_sessions.len(), 1);
        assert_eq!(
            capabilities.remote_sessions[0].connection_id,
            active.connection_id
        );
        assert_ne!(
            capabilities.remote_sessions[0].connection_id,
            pending.connection_id
        );
    }

    #[test]
    fn embedded_backend_propagates_missing_publish_targets() {
        let identity = embedded_identity(0xb3);
        let backend =
            RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity).expect("embedded backend");
        let backend_trait: &dyn RadrootsNostrSignerBackend = &backend;

        let missing_connection_id =
            crate::signer::model::RadrootsNostrSignerConnectionId::parse("conn-backend-missing")
                .expect("connection id");
        let missing_workflow_id =
            RadrootsNostrSignerWorkflowId::parse("wf-backend-missing").expect("workflow id");

        assert!(
            backend_trait
                .begin_connect_secret_publish_finalization(&missing_connection_id)
                .expect_err("missing connect workflow")
                .to_string()
                .contains("connection not found")
        );
        assert!(
            backend_trait
                .begin_auth_replay_publish_finalization(&missing_connection_id)
                .expect_err("missing auth workflow")
                .to_string()
                .contains("connection not found")
        );
        assert!(
            backend_trait
                .mark_publish_workflow_published(&missing_workflow_id)
                .expect_err("missing published workflow")
                .to_string()
                .contains("publish workflow not found")
        );
        assert!(
            backend_trait
                .finalize_publish_workflow(&missing_workflow_id)
                .expect_err("missing finalized workflow")
                .to_string()
                .contains("publish workflow not found")
        );
        assert!(
            backend_trait
                .cancel_publish_workflow(&missing_workflow_id)
                .expect_err("missing cancelled workflow")
                .to_string()
                .contains("publish workflow not found")
        );
    }

    #[test]
    fn embedded_backend_reports_manager_read_and_save_failures() {
        let save_fail_store = Arc::new(ToggleSaveStore::default());
        save_fail_store.set_mode(1);
        let save_fail_manager =
            RadrootsNostrSignerManager::new(save_fail_store).expect("save-fail manager");
        let err = match RadrootsNostrEmbeddedSignerBackend::new(
            save_fail_manager,
            embedded_identity(0xb4),
        ) {
            Ok(_) => panic!("expected save failure"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("save failed"));

        let poisoned_store = Arc::new(ToggleSaveStore::default());
        let poisoned_manager =
            RadrootsNostrSignerManager::new(poisoned_store.clone()).expect("poison manager");
        let backend = RadrootsNostrEmbeddedSignerBackend::new(
            poisoned_manager.clone(),
            embedded_identity(0xb5),
        )
        .expect("embedded backend");
        poisoned_store.set_mode(2);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = backend
                    .manager()
                    .set_signer_identity(fixture_bob_identity());
            }))
            .is_err()
        );

        let err = backend.capabilities().expect_err("poisoned capabilities");
        assert!(err.to_string().contains("signer state lock poisoned"));

        let err = match RadrootsNostrEmbeddedSignerBackend::new(
            poisoned_manager,
            embedded_identity(0xb5),
        ) {
            Ok(_) => panic!("expected poisoned new failure"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("signer state lock poisoned"));
    }

    #[test]
    fn embedded_backend_sign_unsigned_event_rejects_invalid_precomputed_id() {
        let identity = embedded_identity(0xb6);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let backend_trait: &dyn RadrootsNostrSignerBackend = &backend;

        let mut unsigned_event =
            EventBuilder::new(Kind::TextNote, "hello").build(identity.public_key());
        unsigned_event.id = Some(EventId::all_zeros());
        let err = backend_trait
            .sign_unsigned_event(unsigned_event)
            .expect_err("invalid precomputed id");
        assert!(err.to_string().starts_with("sign error:"));
    }

    #[test]
    fn embedded_backend_trait_delegates_connect_and_publish_workflow_methods() {
        let identity = embedded_identity(0x92);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let backend: &dyn RadrootsNostrSignerBackend = &backend;

        let evaluation = backend
            .evaluate_connect_request(
                synthetic_public_key(0x93),
                Request::Connect {
                    remote_signer_public_key: embedded_public_identity(&identity).public_key(),
                    secret: Some("connect-secret".into()),
                    requested_permissions: vec![Permission::new(Method::Ping)].into(),
                    client_metadata: None,
                },
            )
            .expect("connect evaluation");
        let proposal = expect_registration_required(evaluation);
        let connection = backend
            .register_connection(
                proposal
                    .into_connection_draft(synthetic_public_identity(0x94))
                    .with_relays(vec![primary_relay()]),
            )
            .expect("register connection");

        let capabilities = backend.capabilities().expect("capabilities");
        assert_eq!(capabilities.remote_sessions.len(), 1);

        let begun = backend
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");
        let workflow_id = expect_begun_workflow_id(begun.clone());
        assert_eq!(
            begun.workflow().expect("begun workflow").connection_id,
            connection.connection_id
        );

        let published = backend
            .mark_publish_workflow_published(&workflow_id)
            .expect("mark published");
        assert!(matches!(
            published,
            RadrootsNostrSignerPublishTransition::MarkedPublished(_)
        ));

        let finalized = backend
            .finalize_publish_workflow(&workflow_id)
            .expect("finalize workflow");
        let (finalized_workflow_id, finalized_connection) = expect_finalized_transition(finalized);
        assert_eq!(finalized_workflow_id, workflow_id);
        assert!(finalized_connection.connect_secret_is_consumed());

        let audit = backend
            .record_request(
                &connection.connection_id,
                "req-1",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Allowed,
                None,
            )
            .expect("record request");
        assert_eq!(audit.method, Method::Ping);
    }

    #[test]
    fn embedded_backend_delegates_lookup_state_and_auth_workflow_methods() {
        let identity = embedded_identity(0xa0);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let backend_trait: &dyn RadrootsNostrSignerBackend = &backend;

        let connect_evaluation = backend_trait
            .evaluate_connect_request(
                synthetic_public_key(0xa1),
                Request::Connect {
                    remote_signer_public_key: embedded_public_identity(&identity).public_key(),
                    secret: Some("connect-secret-2".into()),
                    requested_permissions: vec![Permission::new(Method::Ping)].into(),
                    client_metadata: None,
                },
            )
            .expect("connect evaluation");
        let connect_proposal = expect_registration_required(connect_evaluation);
        let connection = backend_trait
            .register_connection(
                connect_proposal
                    .into_connection_draft(synthetic_public_identity(0xa2))
                    .with_relays(vec![primary_relay()]),
            )
            .expect("register connect-secret connection");

        assert_eq!(backend_trait.list_connections().expect("list").len(), 1);
        assert_eq!(
            backend_trait
                .get_connection(&connection.connection_id)
                .expect("get connection")
                .expect("stored connection")
                .connection_id,
            connection.connection_id
        );
        assert_eq!(
            backend_trait
                .find_connections_by_client_public_key(&connection.client_public_key)
                .expect("find by client key")
                .len(),
            1
        );
        assert_eq!(
            backend_trait
                .find_connection_by_connect_secret("connect-secret-2")
                .expect("find by secret")
                .expect("stored by secret")
                .connection_id,
            connection.connection_id
        );
        let looked_up = expect_lookup_connection(
            backend_trait
                .lookup_session(&connection.client_public_key, Some("connect-secret-2"))
                .expect("lookup session"),
        );
        assert_eq!(looked_up.connection_id, connection.connection_id);

        let with_relays = backend_trait
            .update_relays(
                &connection.connection_id,
                vec![primary_relay(), secondary_relay()],
            )
            .expect("update relays");
        assert_eq!(with_relays.relays.len(), 2);

        let evaluation = backend_trait
            .evaluate_request(
                &connection.connection_id,
                RequestMessage::new("req-ping", Request::Ping),
            )
            .expect("evaluate request");
        assert!(matches!(
            evaluation.action,
            RadrootsNostrSignerRequestAction::Allowed { .. }
        ));

        let authenticated = backend_trait
            .mark_authenticated(&connection.connection_id)
            .expect("mark authenticated");
        assert!(authenticated.last_authenticated_at_unix.is_some());

        let pending_connection = backend_trait
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    synthetic_public_key(0xab),
                    synthetic_public_identity(0xac),
                )
                .with_requested_permissions(vec![Permission::new(Method::Ping)].into())
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::ExplicitUser),
            )
            .expect("register pending connection");
        let granted_permissions: radroots_nostr_connect::permission::Permissions =
            vec![Permission::new(Method::Ping)].into();
        let granted = backend_trait
            .set_granted_permissions(
                &pending_connection.connection_id,
                granted_permissions.clone(),
            )
            .expect("set granted permissions");
        assert_eq!(granted.connection_id, pending_connection.connection_id);

        let approved = backend_trait
            .approve_connection(&pending_connection.connection_id, granted_permissions)
            .expect("approve connection");
        assert_eq!(approved.status, RadrootsNostrSignerConnectionStatus::Active);

        let begun = backend_trait
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin connect workflow");
        let workflow = begun.workflow().expect("begun workflow").clone();
        assert!(begun.finalized_connection().is_none());
        assert_eq!(
            backend_trait
                .list_publish_workflows()
                .expect("list publish workflows")
                .len(),
            1
        );
        assert_eq!(
            backend_trait
                .get_publish_workflow(&workflow.workflow_id)
                .expect("get publish workflow")
                .expect("stored workflow")
                .workflow_id,
            workflow.workflow_id
        );

        let published = backend_trait
            .mark_publish_workflow_published(&workflow.workflow_id)
            .expect("mark publish workflow");
        assert_eq!(
            published
                .workflow()
                .expect("published workflow")
                .workflow_id,
            workflow.workflow_id
        );

        let finalized = backend_trait
            .finalize_publish_workflow(&workflow.workflow_id)
            .expect("finalize workflow");
        assert!(finalized.workflow().is_none());
        assert_eq!(
            finalized
                .finalized_connection()
                .expect("finalized connection")
                .connection_id,
            connection.connection_id
        );

        let audit = backend_trait
            .record_request(
                &connection.connection_id,
                "req-audit",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Allowed,
                None,
            )
            .expect("record request");
        assert_eq!(audit.connection_id, connection.connection_id);

        let consumed_connection = backend_trait
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    synthetic_public_key(0xa3),
                    synthetic_public_identity(0xa4),
                )
                .with_connect_secret("manual-secret"),
            )
            .expect("register consumed connection");
        let consumed = backend_trait
            .mark_connect_secret_consumed(&consumed_connection.connection_id)
            .expect("mark connect secret consumed");
        assert!(consumed.connect_secret_is_consumed());

        let rejected = backend_trait
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                synthetic_public_key(0xa5),
                synthetic_public_identity(0xa6),
            ))
            .expect("register rejected connection");
        let rejected = backend_trait
            .reject_connection(&rejected.connection_id, Some("rejected".into()))
            .expect("reject connection");
        assert_eq!(
            rejected.status,
            RadrootsNostrSignerConnectionStatus::Rejected
        );

        let auth_connection = backend_trait
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    synthetic_public_key(0xa7),
                    synthetic_public_identity(0xa8),
                )
                .with_requested_permissions(vec![Permission::new(Method::Ping)].into()),
            )
            .expect("register auth connection");
        backend_trait
            .require_auth_challenge(
                &auth_connection.connection_id,
                "https://api.example.com/auth",
            )
            .expect("require auth challenge");
        let pending = backend_trait
            .set_pending_request(
                &auth_connection.connection_id,
                RequestMessage::new("req-auth-replay", Request::Ping),
            )
            .expect("set pending request");
        assert!(pending.pending_request.is_some());
        let authorized = backend_trait
            .authorize_auth_challenge(&auth_connection.connection_id)
            .expect("authorize auth challenge");
        let pending_request = authorized.pending_request.expect("pending request");
        let restored = backend_trait
            .restore_pending_auth_challenge(&auth_connection.connection_id, pending_request.clone())
            .expect("restore pending auth challenge");
        assert_eq!(restored.pending_request.as_ref(), Some(&pending_request));

        let auth_workflow = backend_trait
            .begin_auth_replay_publish_finalization(&auth_connection.connection_id)
            .expect("begin auth replay")
            .workflow()
            .expect("auth replay workflow")
            .clone();
        let replay_evaluation = backend_trait
            .evaluate_auth_replay_publish_workflow(&auth_workflow.workflow_id)
            .expect("evaluate auth replay workflow");
        assert_eq!(
            replay_evaluation.connection.connection_id,
            auth_connection.connection_id
        );
        let cancelled = backend_trait
            .cancel_publish_workflow(&auth_workflow.workflow_id)
            .expect("cancel auth workflow");
        assert_eq!(
            cancelled
                .workflow()
                .expect("cancelled workflow")
                .workflow_id,
            auth_workflow.workflow_id
        );

        let revoked = backend_trait
            .revoke_connection(&auth_connection.connection_id, Some("revoked".into()))
            .expect("revoke connection");
        assert_eq!(revoked.status, RadrootsNostrSignerConnectionStatus::Revoked);
    }

    #[test]
    fn embedded_backend_signs_external_unsigned_event_with_local_capability() {
        let identity = embedded_identity(0x95);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let output =
            <RadrootsNostrEmbeddedSignerBackend as RadrootsNostrSignerBackend>::sign_unsigned_event(
                &backend,
                EventBuilder::new(Kind::TextNote, "hello").build(identity.public_key()),
            )
            .expect("sign external unsigned event");

        assert_eq!(output.event.pubkey, identity.public_key());
        let local = output.signer.local_account().expect("local signer");
        assert_eq!(local.public_identity, embedded_public_identity(&identity));
        assert!(local.is_secret_backed());
    }

    #[test]
    fn embedded_backend_can_prepare_and_cancel_auth_replay_workflow() {
        let identity = embedded_identity(0x96);
        let backend = RadrootsNostrEmbeddedSignerBackend::new_in_memory(identity.clone())
            .expect("embedded backend");
        let backend: &dyn RadrootsNostrSignerBackend = &backend;

        let connection = backend
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    synthetic_public_key(0x97),
                    synthetic_public_identity(0x98),
                )
                .with_requested_permissions(vec![Permission::new(Method::Ping)].into()),
            )
            .expect("register connection");
        backend
            .require_auth_challenge(&connection.connection_id, "https://api.example.com/auth")
            .expect("require auth");
        backend
            .set_pending_request(
                &connection.connection_id,
                RequestMessage::new("req-auth", Request::Ping),
            )
            .expect("set pending request");

        let begun = backend
            .begin_auth_replay_publish_finalization(&connection.connection_id)
            .expect("begin auth replay");
        let workflow_id = begun
            .workflow()
            .expect("begun auth replay workflow")
            .workflow_id
            .clone();

        let cancelled = backend
            .cancel_publish_workflow(&workflow_id)
            .expect("cancel workflow");
        assert!(matches!(
            cancelled,
            RadrootsNostrSignerPublishTransition::Cancelled(_)
        ));
    }

    #[test]
    fn backend_capabilities_all_signers_supports_remote_only_and_identity_comparison() {
        let remote = crate::signer::capability::RadrootsNostrRemoteSessionSignerCapability::new(
            crate::signer::model::RadrootsNostrSignerConnectionId::new_v7(),
            synthetic_public_identity(0xb0),
            synthetic_public_identity(0xb1),
        );
        let capabilities = RadrootsNostrSignerBackendCapabilities::new(None, vec![remote.clone()]);

        assert_eq!(
            capabilities.all_signers(),
            vec![
                crate::signer::capability::RadrootsNostrSignerCapability::RemoteSession(Box::new(
                    remote,
                ))
            ]
        );

        let valid_identity = synthetic_public_identity(0xb2);
        assert!(same_public_identity_key(&valid_identity, &valid_identity));
        let valid_identity_with_different_hex = synthetic_public_identity(0xb3);
        assert!(!same_public_identity_key(
            &valid_identity,
            &valid_identity_with_different_hex
        ));
    }

    #[test]
    fn backend_test_helpers_reject_unexpected_variants() {
        let connection = RadrootsNostrSignerConnectionRecord::new(
            crate::signer::model::RadrootsNostrSignerConnectionId::new_v7(),
            synthetic_public_identity(0xb4),
            RadrootsNostrSignerConnectionDraft::new(
                synthetic_public_key(0xb5),
                synthetic_public_identity(0xb6),
            ),
            1,
        );
        let workflow = RadrootsNostrSignerPublishWorkflowRecord::new_connect_secret_finalization(
            connection.connection_id.clone(),
            1,
        );

        assert!(
            std::panic::catch_unwind(|| {
                expect_registration_required(
                    RadrootsNostrSignerConnectEvaluation::ExistingConnection(Box::new(
                        connection.clone(),
                    )),
                )
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                expect_lookup_connection(RadrootsNostrSignerSessionLookup::None)
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                expect_begun_workflow_id(RadrootsNostrSignerPublishTransition::cancelled(
                    workflow.clone(),
                ))
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                expect_finalized_transition(RadrootsNostrSignerPublishTransition::begun(workflow))
            })
            .is_err()
        );
    }
}
