use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::evaluation::{
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectProposal,
    RadrootsNostrSignerRequestAction, RadrootsNostrSignerRequestEvaluation,
    RadrootsNostrSignerSessionLookup, request_allowed_by_permissions,
    required_permission_for_request, response_hint_for_request,
};
use crate::signer::model::{
    RADROOTS_NOSTR_SIGNER_STORE_VERSION, RadrootsNostrSignerApprovalRequirement,
    RadrootsNostrSignerApprovalState, RadrootsNostrSignerAuthChallenge,
    RadrootsNostrSignerAuthState, RadrootsNostrSignerAuthorizationOutcome,
    RadrootsNostrSignerConnectSecretHash, RadrootsNostrSignerConnectionDraft,
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerConnectionStatus, RadrootsNostrSignerPendingRequest,
    RadrootsNostrSignerPermissionGrant, RadrootsNostrSignerPublishWorkflowKind,
    RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerPublishWorkflowState,
    RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestDecision,
    RadrootsNostrSignerRequestId, RadrootsNostrSignerStoreState, RadrootsNostrSignerWorkflowId,
};
use crate::signer::store::{RadrootsNostrMemorySignerStore, RadrootsNostrSignerStore};
use nostr::{PublicKey, RelayUrl};
use radroots_nostr_connect::{
    Method, Request, message::RequestMessage, permission::Permissions, uri::ClientMetadata,
};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct RadrootsNostrSignerManager {
    store: Arc<dyn RadrootsNostrSignerStore>,
    state: Arc<RwLock<RadrootsNostrSignerStoreState>>,
}

impl RadrootsNostrSignerManager {
    pub fn new_in_memory() -> Self {
        Self {
            store: Arc::new(RadrootsNostrMemorySignerStore::new()),
            state: Arc::new(RwLock::new(RadrootsNostrSignerStoreState::default())),
        }
    }

    pub fn new(store: Arc<dyn RadrootsNostrSignerStore>) -> Result<Self, RadrootsNostrSignerError> {
        let state = store.load()?;
        if state.version != RADROOTS_NOSTR_SIGNER_STORE_VERSION {
            return Err(RadrootsNostrSignerError::InvalidState(format!(
                "unsupported signer schema version {}",
                state.version
            )));
        }

        Ok(Self {
            store,
            state: Arc::new(RwLock::new(state)),
        })
    }

    pub fn signer_identity(&self) -> Result<Option<PublicIdentity>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard.signer_identity.clone())
    }

    pub fn set_signer_identity(
        &self,
        signer_identity: PublicIdentity,
    ) -> Result<(), RadrootsNostrSignerError> {
        validate_public_identity(&signer_identity)?;
        self.update_state(|state| {
            state.signer_identity = Some(signer_identity);
            Ok(())
        })
    }

    pub fn list_connections(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard.connections.clone())
    }

    pub fn get_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard
            .connections
            .iter()
            .find(|record| &record.connection_id == connection_id)
            .cloned())
    }

    pub fn list_publish_workflows(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard.publish_workflows.clone())
    }

    pub fn get_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard
            .publish_workflows
            .iter()
            .find(|record| &record.workflow_id == workflow_id)
            .cloned())
    }

    pub fn find_connections_by_client_public_key(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard
            .connections
            .iter()
            .filter(|record| &record.client_public_key == client_public_key)
            .cloned()
            .collect())
    }

    pub fn find_connection_by_connect_secret(
        &self,
        connect_secret: &str,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        let Some(connect_secret_hash) =
            RadrootsNostrSignerConnectSecretHash::from_secret(connect_secret)
        else {
            return Ok(None);
        };

        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard
            .connections
            .iter()
            .find(|record| {
                record.connect_secret_hash.as_ref() == Some(&connect_secret_hash)
                    && (!record.is_terminal() || record.connect_secret_is_consumed())
            })
            .cloned())
    }

    pub fn lookup_session(
        &self,
        client_public_key: &PublicKey,
        connect_secret: Option<&str>,
    ) -> Result<RadrootsNostrSignerSessionLookup, RadrootsNostrSignerError> {
        if let Some(connect_secret) = connect_secret
            && let Some(connection) = self.find_connection_by_connect_secret(connect_secret)?
        {
            if &connection.client_public_key != client_public_key {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "connect secret is bound to a different client public key".into(),
                ));
            }
            return Ok(RadrootsNostrSignerSessionLookup::Connection(Box::new(
                connection,
            )));
        }

        let mut matches = self.find_connections_by_client_public_key(client_public_key)?;
        matches.retain(|record| !record.is_terminal());
        Ok(match matches.len() {
            0 => RadrootsNostrSignerSessionLookup::None,
            1 => RadrootsNostrSignerSessionLookup::Connection(Box::new(matches.remove(0))),
            _ => RadrootsNostrSignerSessionLookup::Ambiguous(matches),
        })
    }

    pub fn evaluate_connect_request(
        &self,
        client_public_key: PublicKey,
        request: Request,
    ) -> Result<RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerError> {
        let Request::Connect {
            remote_signer_public_key,
            secret,
            requested_permissions,
            client_metadata,
        } = request
        else {
            return Err(RadrootsNostrSignerError::InvalidState(
                "connect evaluation requires a connect request".into(),
            ));
        };

        let remote_signer_public_key =
            radroots_nostr::key::public_key_to_nostr(remote_signer_public_key)?;
        let (connect_secret, existing_connection) =
            self.resolve_connect_request_context(remote_signer_public_key, secret)?;
        if let Some(connection) = existing_connection {
            if connection.client_public_key != client_public_key {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "connect secret is bound to a different client public key".into(),
                ));
            }
            return Ok(RadrootsNostrSignerConnectEvaluation::ExistingConnection(
                Box::new(connection),
            ));
        }

        Ok(RadrootsNostrSignerConnectEvaluation::RegistrationRequired(
            RadrootsNostrSignerConnectProposal {
                client_public_key,
                connect_secret,
                client_metadata: client_metadata.map(normalize_client_metadata).transpose()?,
                requested_permissions: normalize_permissions(requested_permissions),
            },
        ))
    }

    pub fn list_audit_records(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerRequestAuditRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard.audit_records.clone())
    }

    pub fn audit_records_for_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Vec<RadrootsNostrSignerRequestAuditRecord>, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        Ok(guard
            .audit_records
            .iter()
            .filter(|record| &record.connection_id == connection_id)
            .cloned()
            .collect())
    }

    pub fn register_connection(
        &self,
        draft: RadrootsNostrSignerConnectionDraft,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let signer_identity = state
                .signer_identity
                .clone()
                .ok_or(RadrootsNostrSignerError::MissingSignerIdentity)?;
            validate_public_identity(&signer_identity)?;
            validate_public_identity(&draft.user_identity)?;

            let connect_secret_hash = draft
                .connect_secret
                .as_deref()
                .and_then(RadrootsNostrSignerConnectSecretHash::from_secret);
            if let Some(secret_hash) = connect_secret_hash.as_ref()
                && state.connections.iter().any(|record| {
                    record.connect_secret_hash.as_ref() == Some(secret_hash)
                        && (!record.is_terminal() || record.connect_secret_is_consumed())
                })
            {
                return Err(RadrootsNostrSignerError::ConnectSecretAlreadyInUse);
            }

            if state.connections.iter().any(|record| {
                !record.is_terminal()
                    && record.client_public_key == draft.client_public_key
                    && record.user_identity.id() == draft.user_identity.id()
            }) {
                return Err(RadrootsNostrSignerError::ConnectionAlreadyExists {
                    client_public_key: draft.client_public_key.to_hex(),
                    user_identity_id: draft.user_identity.id().to_string(),
                });
            }

            let created_at_unix = now_unix_secs();
            let record = RadrootsNostrSignerConnectionRecord::new(
                RadrootsNostrSignerConnectionId::new_v7(),
                signer_identity,
                RadrootsNostrSignerConnectionDraft {
                    client_public_key: draft.client_public_key,
                    user_identity: draft.user_identity,
                    connect_secret: draft.connect_secret,
                    client_metadata: draft
                        .client_metadata
                        .map(normalize_client_metadata)
                        .transpose()?,
                    requested_permissions: normalize_permissions(draft.requested_permissions),
                    relays: normalize_relays(draft.relays),
                    approval_requirement: draft.approval_requirement,
                },
                created_at_unix,
            );
            state.connections.push(record.clone());
            Ok(record)
        })
    }

    pub fn set_granted_permissions(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let updated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot update granted permissions for {} connection",
                    status_label(record.status)
                )));
            }

            let granted_permissions = normalize_permissions(granted_permissions);
            validate_granted_permissions(&record.requested_permissions, &granted_permissions)?;
            record.granted_permissions = granted_permissions
                .as_slice()
                .iter()
                .cloned()
                .map(|permission| {
                    RadrootsNostrSignerPermissionGrant::new(permission, updated_at_unix)
                })
                .collect();
            record.touch_updated(updated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn approve_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: Permissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let updated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.approval_requirement != RadrootsNostrSignerApprovalRequirement::ExplicitUser {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "approval not required for connection".into(),
                ));
            }
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot approve {} connection",
                    status_label(record.status)
                )));
            }

            let granted_permissions = normalize_permissions(granted_permissions);
            validate_granted_permissions(&record.requested_permissions, &granted_permissions)?;
            record.granted_permissions = granted_permissions
                .as_slice()
                .iter()
                .cloned()
                .map(|permission| {
                    RadrootsNostrSignerPermissionGrant::new(permission, updated_at_unix)
                })
                .collect();
            record.approval_state = RadrootsNostrSignerApprovalState::Approved;
            record.status = RadrootsNostrSignerConnectionStatus::Active;
            record.status_reason = None;
            record.touch_updated(updated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn reject_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let updated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot reject {} connection",
                    status_label(record.status)
                )));
            }

            record.approval_state = RadrootsNostrSignerApprovalState::Rejected;
            record.status = RadrootsNostrSignerConnectionStatus::Rejected;
            record.status_reason = normalize_optional_string(reason);
            record.touch_updated(updated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn revoke_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let updated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.status == RadrootsNostrSignerConnectionStatus::Revoked {
                return Ok(record.clone());
            }

            record.status = RadrootsNostrSignerConnectionStatus::Revoked;
            record.status_reason = normalize_optional_string(reason);
            record.touch_updated(updated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn update_relays(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        relays: Vec<RelayUrl>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let updated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot update relays for {} connection",
                    status_label(record.status)
                )));
            }

            record.relays = normalize_relays(relays);
            record.touch_updated(updated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn require_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        auth_url: impl AsRef<str>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let required_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot require auth for {} connection",
                    status_label(record.status)
                )));
            }

            let challenge =
                RadrootsNostrSignerAuthChallenge::new(auth_url.as_ref(), required_at_unix)?;
            record.require_auth_challenge(challenge);
            Ok(record.clone())
        })
    }

    pub fn set_pending_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot set pending request for {} connection",
                    status_label(record.status)
                )));
            }
            if record.auth_state != RadrootsNostrSignerAuthState::Pending {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge not pending for connection".into(),
                ));
            }

            let pending_request =
                RadrootsNostrSignerPendingRequest::new(request_message, now_unix_secs())?;
            record.set_pending_request(pending_request);
            Ok(record.clone())
        })
    }

    pub fn authorize_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerAuthorizationOutcome, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot authorize auth challenge for {} connection",
                    status_label(record.status)
                )));
            }
            if record.auth_state != RadrootsNostrSignerAuthState::Pending {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge not pending for connection".into(),
                ));
            }

            let pending_request = record.authorize_auth_challenge(now_unix_secs());
            Ok(RadrootsNostrSignerAuthorizationOutcome::new(
                record.clone(),
                pending_request,
            ))
        })
    }

    pub fn restore_pending_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        pending_request: RadrootsNostrSignerPendingRequest,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let restored_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot restore auth challenge for {} connection",
                    status_label(record.status)
                )));
            }
            if record.auth_state != RadrootsNostrSignerAuthState::Authorized {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge not authorized for connection".into(),
                ));
            }
            if record.auth_challenge.is_none() {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge missing for connection".into(),
                ));
            }

            record.restore_pending_auth_challenge(pending_request, restored_at_unix);
            Ok(record.clone())
        })
    }

    pub fn begin_connect_secret_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let connection_index = find_connection_index(state, connection_id)?;
            let record = &state.connections[connection_index];
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot begin connect secret finalization for {} connection",
                    status_label(record.status)
                )));
            }
            if record.connect_secret_hash.is_none() {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "connection does not have a connect secret".into(),
                ));
            }
            if record.connect_secret_is_consumed() {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "connect secret already consumed for connection".into(),
                ));
            }
            ensure_no_active_publish_workflow(
                state,
                connection_id,
                RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization,
            )?;

            let workflow =
                RadrootsNostrSignerPublishWorkflowRecord::new_connect_secret_finalization(
                    connection_id.clone(),
                    now_unix_secs(),
                );
            state.publish_workflows.push(workflow.clone());
            Ok(workflow)
        })
    }

    pub fn begin_auth_replay_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let authorized_at_unix = now_unix_secs();
            let connection_index = find_connection_index(state, connection_id)?;
            let record = &state.connections[connection_index];
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot begin auth replay finalization for {} connection",
                    status_label(record.status)
                )));
            }
            if record.auth_state != RadrootsNostrSignerAuthState::Pending {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge not pending for connection".into(),
                ));
            }
            if record.auth_challenge.is_none() {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge missing for connection".into(),
                ));
            }
            let pending_request = record.pending_request.clone().ok_or_else(|| {
                RadrootsNostrSignerError::InvalidState(
                    "pending request missing for auth replay finalization".into(),
                )
            })?;
            ensure_no_active_publish_workflow(
                state,
                connection_id,
                RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization,
            )?;

            let workflow = RadrootsNostrSignerPublishWorkflowRecord::new_auth_replay_finalization(
                connection_id.clone(),
                pending_request,
                authorized_at_unix,
            );
            state.publish_workflows.push(workflow.clone());
            Ok(workflow)
        })
    }

    pub fn mark_publish_workflow_published(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let workflow = find_publish_workflow_mut(state, workflow_id)?;
            workflow.mark_published(now_unix_secs());
            Ok(workflow.clone())
        })
    }

    pub fn finalize_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let workflow_index = find_publish_workflow_index(state, workflow_id)?;
            let workflow = state.publish_workflows[workflow_index].clone();
            if workflow.state != RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "publish workflow has not reached published state".into(),
                ));
            }

            let record = find_connection_mut(state, &workflow.connection_id)?;
            let finalized = match workflow.kind {
                RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization => {
                    if record.connect_secret_hash.is_none() {
                        return Err(RadrootsNostrSignerError::InvalidState(
                            "connection does not have a connect secret".into(),
                        ));
                    }
                    if record.connect_secret_is_consumed() {
                        return Err(RadrootsNostrSignerError::InvalidState(
                            "connect secret already consumed for connection".into(),
                        ));
                    }
                    record.mark_connect_secret_consumed(now_unix_secs());
                    record.clone()
                }
                RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization => {
                    if record.auth_state != RadrootsNostrSignerAuthState::Pending {
                        return Err(RadrootsNostrSignerError::InvalidState(
                            "auth challenge not pending for connection".into(),
                        ));
                    }
                    if record.auth_challenge.is_none() {
                        return Err(RadrootsNostrSignerError::InvalidState(
                            "auth challenge missing for connection".into(),
                        ));
                    }
                    let expected_pending_request =
                        workflow.pending_request.clone().ok_or_else(|| {
                            RadrootsNostrSignerError::InvalidState(
                                "auth replay workflow missing pending request".into(),
                            )
                        })?;
                    if record.pending_request.as_ref() != Some(&expected_pending_request) {
                        return Err(RadrootsNostrSignerError::InvalidState(
                            "pending request does not match auth replay workflow".into(),
                        ));
                    }
                    let authorized_at_unix = workflow.authorized_at_unix.ok_or_else(|| {
                        RadrootsNostrSignerError::InvalidState(
                            "auth replay workflow missing authorized timestamp".into(),
                        )
                    })?;
                    let replay = record.authorize_auth_challenge(authorized_at_unix);
                    debug_assert_eq!(
                        replay.as_ref(),
                        Some(&expected_pending_request),
                        "auth replay finalization returned unexpected pending request"
                    );
                    record.clone()
                }
            };

            state.publish_workflows.remove(workflow_index);
            Ok(finalized)
        })
    }

    pub fn cancel_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let workflow_index = find_publish_workflow_index(state, workflow_id)?;
            Ok(state.publish_workflows.remove(workflow_index))
        })
    }

    pub fn mark_authenticated(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let authenticated_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            record.mark_authenticated(authenticated_at_unix);
            Ok(record.clone())
        })
    }

    pub fn mark_connect_secret_consumed(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let consumed_at_unix = now_unix_secs();
            let record = find_connection_mut(state, connection_id)?;
            if record.connect_secret_hash.is_none() {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "connection does not have a connect secret".into(),
                ));
            }
            record.mark_connect_secret_consumed(consumed_at_unix);
            Ok(record.clone())
        })
    }

    pub fn evaluate_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        if matches!(request_message.request, Request::Connect { .. }) {
            return Err(RadrootsNostrSignerError::InvalidState(
                "connect requests must be evaluated via evaluate_connect_request".into(),
            ));
        }

        self.update_state_with(|state| {
            let request_at_unix = now_unix_secs();
            let request_id = RadrootsNostrSignerRequestId::parse(&request_message.id)?;
            let record = find_connection_mut(state, connection_id)?;
            let method = request_message.request.method();
            let action = evaluate_request_action(record, &request_message, request_at_unix)?;
            record.mark_request(request_at_unix);

            let audit = RadrootsNostrSignerRequestAuditRecord::new(
                request_id.clone(),
                connection_id.clone(),
                method.clone(),
                request_decision(&action),
                action.audit_message(),
                request_at_unix,
            );
            let connection = record.clone();
            state.audit_records.push(audit.clone());

            Ok(RadrootsNostrSignerRequestEvaluation {
                request_id,
                method,
                connection,
                audit,
                action,
            })
        })
    }

    pub fn evaluate_auth_replay_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let request_at_unix = now_unix_secs();
            let workflow = state
                .publish_workflows
                .iter()
                .find(|record| &record.workflow_id == workflow_id)
                .cloned()
                .ok_or_else(|| {
                    RadrootsNostrSignerError::PublishWorkflowNotFound(workflow_id.to_string())
                })?;
            if workflow.kind != RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "publish workflow is not an auth replay finalization".into(),
                ));
            }

            let pending_request = workflow.pending_request.clone().ok_or_else(|| {
                RadrootsNostrSignerError::InvalidState(
                    "auth replay workflow missing pending request".into(),
                )
            })?;
            let request_message = pending_request.request_message();
            let request_id = pending_request.request_id();
            let method = request_message.request.method();

            let record = find_connection_mut(state, &workflow.connection_id)?;
            if record.is_terminal() {
                return Err(RadrootsNostrSignerError::InvalidState(format!(
                    "cannot evaluate auth replay workflow for {} connection",
                    status_label(record.status)
                )));
            }
            if record.auth_state != RadrootsNostrSignerAuthState::Pending {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "auth challenge not pending for connection".into(),
                ));
            }
            if record.pending_request.as_ref() != Some(&pending_request) {
                return Err(RadrootsNostrSignerError::InvalidState(
                    "pending request does not match auth replay workflow".into(),
                ));
            }

            let mut effective_connection = record.clone();
            effective_connection.auth_state = RadrootsNostrSignerAuthState::Authorized;
            effective_connection.pending_request = None;
            if let Some(auth_challenge) = effective_connection.auth_challenge.as_mut() {
                auth_challenge.authorized_at_unix = workflow.authorized_at_unix;
            }
            let request = &request_message;
            let action =
                evaluate_request_action(&mut effective_connection, request, request_at_unix)?;
            effective_connection.mark_request(request_at_unix);
            record.mark_request(request_at_unix);

            let audit = RadrootsNostrSignerRequestAuditRecord::new(
                request_id.clone(),
                workflow.connection_id.clone(),
                method.clone(),
                request_decision(&action),
                action.audit_message(),
                request_at_unix,
            );
            replace_or_insert_auth_replay_audit(state, audit.clone())?;

            Ok(RadrootsNostrSignerRequestEvaluation {
                request_id,
                method,
                connection: effective_connection,
                audit,
                action,
            })
        })
    }

    pub fn record_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_id: impl AsRef<str>,
        method: Method,
        decision: RadrootsNostrSignerRequestDecision,
        message: Option<String>,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            let created_at_unix = now_unix_secs();
            let request_id = RadrootsNostrSignerRequestId::parse(request_id.as_ref())?;
            let record = find_connection_mut(state, connection_id)?;
            record.mark_request(created_at_unix);

            let audit = RadrootsNostrSignerRequestAuditRecord::new(
                request_id,
                connection_id.clone(),
                method,
                decision,
                normalize_optional_string(message),
                created_at_unix,
            );
            state.audit_records.push(audit.clone());
            Ok(audit)
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn update_state(
        &self,
        update: impl FnOnce(&mut RadrootsNostrSignerStoreState) -> Result<(), RadrootsNostrSignerError>,
    ) -> Result<(), RadrootsNostrSignerError> {
        self.update_state_with(|state| {
            update(state)?;
            Ok(())
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn update_state_with<T>(
        &self,
        update: impl FnOnce(&mut RadrootsNostrSignerStoreState) -> Result<T, RadrootsNostrSignerError>,
    ) -> Result<T, RadrootsNostrSignerError> {
        let mut guard = self
            .state
            .write()
            .map_err(|_| RadrootsNostrSignerError::Store("signer state lock poisoned".into()))?;
        let mut next = guard.clone();
        let value = update(&mut next)?;
        self.store.save(&next)?;
        *guard = next;
        Ok(value)
    }

    fn resolve_connect_request_context(
        &self,
        remote_signer_public_key: PublicKey,
        secret: Option<String>,
    ) -> Result<
        (Option<String>, Option<RadrootsNostrSignerConnectionRecord>),
        RadrootsNostrSignerError,
    > {
        let signer_identity = self
            .signer_identity()?
            .ok_or(RadrootsNostrSignerError::MissingSignerIdentity)?;
        let signer_public_key = parse_identity_public_key(&signer_identity)?;
        if remote_signer_public_key != signer_public_key {
            return Err(RadrootsNostrSignerError::InvalidState(
                "remote signer public key mismatch".into(),
            ));
        }

        let connect_secret = normalize_optional_string(secret);
        let existing_connection =
            self.find_connection_by_connect_secret(connect_secret.as_deref().unwrap_or_default())?;
        Ok((connect_secret, existing_connection))
    }
}

fn find_connection_mut<'a>(
    state: &'a mut RadrootsNostrSignerStoreState,
    connection_id: &RadrootsNostrSignerConnectionId,
) -> Result<&'a mut RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
    state
        .connections
        .iter_mut()
        .find(|record| &record.connection_id == connection_id)
        .ok_or_else(|| RadrootsNostrSignerError::ConnectionNotFound(connection_id.to_string()))
}

fn find_connection_index(
    state: &RadrootsNostrSignerStoreState,
    connection_id: &RadrootsNostrSignerConnectionId,
) -> Result<usize, RadrootsNostrSignerError> {
    for (index, record) in state.connections.iter().enumerate() {
        if &record.connection_id == connection_id {
            return Ok(index);
        }
    }
    Err(RadrootsNostrSignerError::ConnectionNotFound(
        connection_id.to_string(),
    ))
}

fn find_publish_workflow_index(
    state: &RadrootsNostrSignerStoreState,
    workflow_id: &RadrootsNostrSignerWorkflowId,
) -> Result<usize, RadrootsNostrSignerError> {
    state
        .publish_workflows
        .iter()
        .position(|record| &record.workflow_id == workflow_id)
        .ok_or_else(|| RadrootsNostrSignerError::PublishWorkflowNotFound(workflow_id.to_string()))
}

fn find_publish_workflow_mut<'a>(
    state: &'a mut RadrootsNostrSignerStoreState,
    workflow_id: &RadrootsNostrSignerWorkflowId,
) -> Result<&'a mut RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
    state
        .publish_workflows
        .iter_mut()
        .find(|record| &record.workflow_id == workflow_id)
        .ok_or_else(|| RadrootsNostrSignerError::PublishWorkflowNotFound(workflow_id.to_string()))
}

fn ensure_no_active_publish_workflow(
    state: &RadrootsNostrSignerStoreState,
    connection_id: &RadrootsNostrSignerConnectionId,
    kind: RadrootsNostrSignerPublishWorkflowKind,
) -> Result<(), RadrootsNostrSignerError> {
    if state
        .publish_workflows
        .iter()
        .any(|record| &record.connection_id == connection_id && record.kind == kind)
    {
        return Err(RadrootsNostrSignerError::InvalidState(format!(
            "publish workflow already active for {}",
            publish_workflow_kind_label(kind)
        )));
    }
    Ok(())
}

fn validate_public_identity(_identity: &PublicIdentity) -> Result<(), RadrootsNostrSignerError> {
    Ok(())
}

fn validate_granted_permissions(
    requested_permissions: &Permissions,
    granted_permissions: &Permissions,
) -> Result<(), RadrootsNostrSignerError> {
    if requested_permissions.is_empty() {
        return Ok(());
    }

    let requested = requested_permissions.as_slice();
    if let Some(permission) = granted_permissions
        .as_slice()
        .iter()
        .find(|permission| !requested.contains(permission))
    {
        return Err(RadrootsNostrSignerError::InvalidGrantedPermission(
            permission.to_string(),
        ));
    }
    Ok(())
}

fn evaluate_request_action(
    record: &mut RadrootsNostrSignerConnectionRecord,
    request_message: &RequestMessage,
    request_at_unix: u64,
) -> Result<RadrootsNostrSignerRequestAction, RadrootsNostrSignerError> {
    if record.is_terminal() {
        return Ok(RadrootsNostrSignerRequestAction::Denied {
            reason: format!("connection is {}", status_label(record.status)),
        });
    }
    if record.status != RadrootsNostrSignerConnectionStatus::Active {
        return Ok(RadrootsNostrSignerRequestAction::Denied {
            reason: format!("connection is {}", status_label(record.status)),
        });
    }
    if record.auth_state == RadrootsNostrSignerAuthState::Pending {
        let auth_challenge =
            record
                .auth_challenge
                .clone()
                .ok_or(RadrootsNostrSignerError::InvalidState(
                    "auth challenge missing for pending auth state".into(),
                ))?;
        let pending_request =
            RadrootsNostrSignerPendingRequest::new(request_message.clone(), request_at_unix)?;
        record.set_pending_request(pending_request.clone());
        return Ok(RadrootsNostrSignerRequestAction::Challenged {
            auth_challenge,
            pending_request,
        });
    }

    let effective_permissions = record.effective_permissions();
    if !request_allowed_by_permissions(&effective_permissions, &request_message.request) {
        return Ok(RadrootsNostrSignerRequestAction::Denied {
            reason: format!("unauthorized {}", request_message.request.method()),
        });
    }

    Ok(RadrootsNostrSignerRequestAction::Allowed {
        required_permission: required_permission_for_request(&request_message.request),
        response_hint: response_hint_for_request(record, &request_message.request)?,
    })
}

fn normalize_permissions(permissions: Permissions) -> Permissions {
    let mut permissions = permissions.into_vec();
    permissions.sort();
    permissions.dedup();
    permissions.into()
}

fn normalize_client_metadata(
    mut metadata: ClientMetadata,
) -> Result<ClientMetadata, RadrootsNostrSignerError> {
    metadata.requested_permissions = Permissions::default();
    Ok(metadata.normalized()?)
}

fn normalize_relays(relays: Vec<RelayUrl>) -> Vec<RelayUrl> {
    let mut relays = relays;
    relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relays.dedup_by(|left, right| left.as_str() == right.as_str());
    relays
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn status_label(status: RadrootsNostrSignerConnectionStatus) -> &'static str {
    match status {
        RadrootsNostrSignerConnectionStatus::Pending => "pending",
        RadrootsNostrSignerConnectionStatus::Active => "active",
        RadrootsNostrSignerConnectionStatus::Rejected => "rejected",
        RadrootsNostrSignerConnectionStatus::Revoked => "revoked",
    }
}

fn publish_workflow_kind_label(kind: RadrootsNostrSignerPublishWorkflowKind) -> &'static str {
    match kind {
        RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization => {
            "connect_secret_finalization"
        }
        RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization => {
            "auth_replay_finalization"
        }
    }
}

fn request_decision(
    action: &RadrootsNostrSignerRequestAction,
) -> RadrootsNostrSignerRequestDecision {
    match action {
        RadrootsNostrSignerRequestAction::Allowed { .. } => {
            RadrootsNostrSignerRequestDecision::Allowed
        }
        RadrootsNostrSignerRequestAction::Denied { .. } => {
            RadrootsNostrSignerRequestDecision::Denied
        }
        RadrootsNostrSignerRequestAction::Challenged { .. } => {
            RadrootsNostrSignerRequestDecision::Challenged
        }
    }
}

fn parse_identity_public_key(
    identity: &PublicIdentity,
) -> Result<PublicKey, RadrootsNostrSignerError> {
    PublicKey::from_hex(&identity.public_key().to_hex()).map_err(|_| {
        RadrootsNostrSignerError::InvalidState("identity public key is invalid".into())
    })
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn replace_or_insert_auth_replay_audit(
    state: &mut RadrootsNostrSignerStoreState,
    replacement: RadrootsNostrSignerRequestAuditRecord,
) -> Result<(), RadrootsNostrSignerError> {
    let Some(existing) = state
        .audit_records
        .iter_mut()
        .find(|record| record.request_id == replacement.request_id)
    else {
        state.audit_records.push(replacement);
        return Ok(());
    };
    if existing.connection_id != replacement.connection_id || existing.method != replacement.method
    {
        return Err(RadrootsNostrSignerError::InvalidState(
            "auth replay audit does not match the original request".into(),
        ));
    }
    *existing = replacement;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
    use crate::signer::evaluation::{
        RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerRequestAction,
        RadrootsNostrSignerRequestResponseHint, RadrootsNostrSignerSessionLookup,
    };
    use crate::signer::store::RadrootsNostrSignerStore;
    use crate::signer::test_support::{
        api_primary_https, fixture_alice_identity, primary_relay, secondary_relay,
        synthetic_public_identity, synthetic_public_key, tertiary_relay,
    };
    use nostr::{PublicKey, Timestamp};
    use radroots_nostr_connect::{Permission, message::UnsignedEvent as ConnectUnsignedEvent};
    use serde_json::json;
    use std::sync::Arc;
    use std::thread;

    fn public_identity(index: u32) -> PublicIdentity {
        synthetic_public_identity(index)
    }

    fn public_key(index: u32) -> PublicKey {
        synthetic_public_key(index)
    }

    fn connect_public_key(public_key: PublicKey) -> radroots_identity::PublicKey {
        radroots_nostr::key::public_key_from_nostr(public_key).expect("identity public key")
    }

    fn permission(method: Method, parameter: Option<&str>) -> Permission {
        match parameter {
            Some(parameter) => Permission::with_parameter(method, parameter),
            None => Permission::new(method),
        }
    }

    fn request_message(id: &str) -> RequestMessage {
        RequestMessage::new(id, radroots_nostr_connect::Request::Ping)
    }

    fn request_message_with_request(id: &str, request: Request) -> RequestMessage {
        RequestMessage::new(id, request)
    }

    fn unsigned_event(kind: u16) -> ConnectUnsignedEvent {
        ConnectUnsignedEvent::from_json(
            &json!({
                "pubkey": public_key(0xa1).to_hex(),
                "created_at": Timestamp::from(1).as_secs(),
                "kind": kind,
                "tags": [],
                "content": "hello"
            })
            .to_string(),
        )
        .expect("unsigned event")
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_connection_lookup(
        lookup: RadrootsNostrSignerSessionLookup,
    ) -> RadrootsNostrSignerConnectionRecord {
        match lookup {
            RadrootsNostrSignerSessionLookup::Connection(found) => *found,
            other => panic!("unexpected lookup result: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_ambiguous_lookup(
        lookup: RadrootsNostrSignerSessionLookup,
    ) -> Vec<RadrootsNostrSignerConnectionRecord> {
        match lookup {
            RadrootsNostrSignerSessionLookup::Ambiguous(found) => found,
            other => panic!("unexpected ambiguous lookup result: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_existing_connect(
        evaluation: RadrootsNostrSignerConnectEvaluation,
    ) -> RadrootsNostrSignerConnectionRecord {
        match evaluation {
            RadrootsNostrSignerConnectEvaluation::ExistingConnection(found) => *found,
            other => panic!("unexpected existing connect result: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_registration_connect(
        evaluation: RadrootsNostrSignerConnectEvaluation,
    ) -> crate::signer::evaluation::RadrootsNostrSignerConnectProposal {
        match evaluation {
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => proposal,
            other => panic!("unexpected registration connect result: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_none_lookup(lookup: RadrootsNostrSignerSessionLookup) {
        match lookup {
            RadrootsNostrSignerSessionLookup::None => {}
            other => panic!("unexpected non-empty lookup result: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_allowed_user_public_key(action: &RadrootsNostrSignerRequestAction) {
        match action {
            RadrootsNostrSignerRequestAction::Allowed {
                required_permission: None,
                response_hint: RadrootsNostrSignerRequestResponseHint::UserPublicKey(_),
            } => {}
            other => panic!("unexpected allowed pubkey action: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_allowed_without_response_hint(action: &RadrootsNostrSignerRequestAction) {
        match action {
            RadrootsNostrSignerRequestAction::Allowed {
                required_permission: Some(_),
                response_hint: RadrootsNostrSignerRequestResponseHint::None,
            } => {}
            other => panic!("unexpected allowed no-hint action: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_challenged_action(action: &RadrootsNostrSignerRequestAction) {
        match action {
            RadrootsNostrSignerRequestAction::Challenged { .. } => {}
            other => panic!("unexpected challenged action: {other:?}"),
        }
    }

    fn poison_manager_state(manager: &RadrootsNostrSignerManager) {
        let shared = manager.state.clone();
        let _ = thread::spawn(move || {
            let _guard = shared.write().expect("write");
            panic!("poison signer state");
        })
        .join();
    }

    fn assert_same_public_identity(left: &PublicIdentity, right: &PublicIdentity) {
        assert_eq!(left, right);
    }

    fn assert_same_connection(
        left: &RadrootsNostrSignerConnectionRecord,
        right: &RadrootsNostrSignerConnectionRecord,
    ) {
        assert_eq!(left.connection_id, right.connection_id);
        assert_eq!(left.client_public_key, right.client_public_key);
        assert_same_public_identity(&left.signer_identity, &right.signer_identity);
        assert_same_public_identity(&left.user_identity, &right.user_identity);
        assert_eq!(left.connect_secret_hash, right.connect_secret_hash);
        assert_eq!(
            left.connect_secret_consumed_at_unix,
            right.connect_secret_consumed_at_unix
        );
        assert_eq!(left.requested_permissions, right.requested_permissions);
        assert_eq!(left.granted_permissions, right.granted_permissions);
        assert_eq!(left.relays, right.relays);
        assert_eq!(left.approval_requirement, right.approval_requirement);
        assert_eq!(left.approval_state, right.approval_state);
        assert_eq!(left.auth_state, right.auth_state);
        assert_eq!(left.auth_challenge, right.auth_challenge);
        assert_eq!(left.pending_request, right.pending_request);
        assert_eq!(left.status, right.status);
        assert_eq!(left.status_reason, right.status_reason);
        assert_eq!(left.created_at_unix, right.created_at_unix);
        assert_eq!(left.updated_at_unix, right.updated_at_unix);
        assert_eq!(
            left.last_authenticated_at_unix,
            right.last_authenticated_at_unix
        );
        assert_eq!(left.last_request_at_unix, right.last_request_at_unix);
    }

    struct LoadErrorStore;

    impl RadrootsNostrSignerStore for LoadErrorStore {
        fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
            Err(RadrootsNostrSignerError::Store("store load failed".into()))
        }

        fn save(
            &self,
            _state: &RadrootsNostrSignerStoreState,
        ) -> Result<(), RadrootsNostrSignerError> {
            Ok(())
        }
    }

    struct SaveErrorStore {
        state: RwLock<RadrootsNostrSignerStoreState>,
    }

    impl SaveErrorStore {
        fn new(state: RadrootsNostrSignerStoreState) -> Self {
            Self {
                state: RwLock::new(state),
            }
        }
    }

    impl RadrootsNostrSignerStore for SaveErrorStore {
        fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
            self.state
                .read()
                .map(|guard| guard.clone())
                .map_err(|_| RadrootsNostrSignerError::Store("save error store poisoned".into()))
        }

        fn save(
            &self,
            _state: &RadrootsNostrSignerStoreState,
        ) -> Result<(), RadrootsNostrSignerError> {
            Err(RadrootsNostrSignerError::Store("store save failed".into()))
        }
    }

    #[test]
    fn auth_replay_audit_replacement_rejects_identity_mismatches() {
        let audit = |connection_id: &str, method: Method| {
            RadrootsNostrSignerRequestAuditRecord::new(
                RadrootsNostrSignerRequestId::parse("req-auth-replay").expect("request id"),
                RadrootsNostrSignerConnectionId::parse(connection_id).expect("connection id"),
                method,
                RadrootsNostrSignerRequestDecision::Allowed,
                None,
                1,
            )
        };
        let mut state = RadrootsNostrSignerStoreState::default();
        replace_or_insert_auth_replay_audit(&mut state, audit("conn-auth-replay", Method::Ping))
            .expect("insert audit");
        replace_or_insert_auth_replay_audit(&mut state, audit("conn-auth-replay", Method::Ping))
            .expect("replace matching audit");

        for replacement in [
            audit("conn-other", Method::Ping),
            audit("conn-auth-replay", Method::Logout),
        ] {
            let error = replace_or_insert_auth_replay_audit(&mut state, replacement)
                .expect_err("reject mismatched audit");
            assert!(
                error
                    .to_string()
                    .contains("auth replay audit does not match the original request")
            );
        }
    }

    #[test]
    fn manager_new_in_memory_and_invalid_schema_paths() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        assert!(
            manager
                .signer_identity()
                .expect("signer identity")
                .is_none()
        );

        let load_error_store = Arc::new(LoadErrorStore);
        load_error_store
            .save(&RadrootsNostrSignerStoreState::default())
            .expect("load error store save");
        let load_result = RadrootsNostrSignerManager::new(load_error_store);
        assert!(load_result.is_err());
        let err = match load_result {
            Ok(_) => panic!("load error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("store load failed"));

        let store = Arc::new(RadrootsNostrMemorySignerStore::new());
        let state = RadrootsNostrSignerStoreState {
            version: 2,
            ..Default::default()
        };
        store.save(&state).expect("save");
        let version_result = RadrootsNostrSignerManager::new(store);
        assert!(version_result.is_err());
        let err = match version_result {
            Ok(_) => panic!("invalid version"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("unsupported signer schema version")
        );
    }

    #[test]
    fn set_signer_identity_persists_invariant_checked_value() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        let signer_identity = fixture_alice_identity();
        manager
            .set_signer_identity(signer_identity.clone())
            .expect("set signer");

        let loaded = manager
            .signer_identity()
            .expect("identity")
            .expect("loaded");
        assert_same_public_identity(&loaded, &signer_identity);
    }

    #[test]
    fn register_connection_requires_signer_identity_and_normalizes_inputs() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        let err = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x3),
                public_identity(0x4),
            ))
            .expect_err("missing signer");
        assert!(err.to_string().contains("missing signer identity"));

        manager
            .set_signer_identity(public_identity(0x5))
            .expect("set signer");

        let sign_event = permission(Method::SignEvent, Some("kind:1"));
        let ping = permission(Method::Ping, None);
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x6), public_identity(0x7))
                    .with_connect_secret(" secret ")
                    .with_requested_permissions(
                        vec![sign_event.clone(), ping.clone(), sign_event.clone()].into(),
                    )
                    .with_relays(vec![primary_relay(), secondary_relay(), secondary_relay()]),
            )
            .expect("register");

        assert!(
            record
                .connect_secret_hash
                .as_ref()
                .expect("connect secret hash")
                .matches_secret("secret")
        );
        assert_eq!(record.status, RadrootsNostrSignerConnectionStatus::Active);
        assert_eq!(
            record.approval_state,
            RadrootsNostrSignerApprovalState::NotRequired
        );
        assert_eq!(record.auth_state, RadrootsNostrSignerAuthState::NotRequired);
        assert_eq!(record.requested_permissions.as_slice(), &[ping, sign_event]);
        assert_eq!(record.relays, vec![secondary_relay(), primary_relay()]);
    }

    #[test]
    fn register_connection_normalizes_display_only_client_metadata() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(fixture_alice_identity())
            .expect("set signer identity");
        let requested_permissions = vec![permission(Method::Ping, None)].into();
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x90), public_identity(0x91))
                    .with_requested_permissions(requested_permissions)
                    .with_client_metadata(ClientMetadata {
                        requested_permissions: vec![permission(Method::Nip44Encrypt, None)].into(),
                        name: Some(" Example Client ".into()),
                        url: Some("https://client.example.com".into()),
                        image: None,
                    }),
            )
            .expect("register metadata connection");

        let metadata = record.client_metadata.expect("stored client metadata");
        assert_eq!(metadata.name.as_deref(), Some("Example Client"));
        assert_eq!(metadata.url.as_deref(), Some("https://client.example.com/"));
        assert!(metadata.requested_permissions.is_empty());
        assert_eq!(
            record.requested_permissions.as_slice(),
            &[permission(Method::Ping, None)]
        );
    }

    #[test]
    fn register_connection_enforces_identity_and_uniqueness_rules() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x8))
            .expect("set signer");

        let user_identity = public_identity(0x9);
        let client_public_key = public_key(0x10);
        let pending = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(client_public_key, user_identity.clone())
                    .with_connect_secret("shared-secret")
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register");
        assert_eq!(pending.status, RadrootsNostrSignerConnectionStatus::Pending);

        let duplicate_connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(client_public_key, user_identity)
                    .with_connect_secret("other-secret"),
            )
            .expect_err("duplicate connection");
        assert!(
            duplicate_connection
                .to_string()
                .contains("connection already exists")
        );

        let duplicate_secret = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x11), public_identity(0x12))
                    .with_connect_secret("shared-secret"),
            )
            .expect_err("duplicate secret");
        assert!(
            duplicate_secret
                .to_string()
                .contains("connect secret already in use")
        );
    }

    #[test]
    fn manager_query_helpers_find_connections() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x15))
            .expect("set signer");

        let client_public_key = public_key(0x16);
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(client_public_key, public_identity(0x17))
                    .with_connect_secret("lookup-secret"),
            )
            .expect("register");

        let by_id = manager
            .get_connection(&record.connection_id)
            .expect("get connection");
        let by_client = manager
            .find_connections_by_client_public_key(&client_public_key)
            .expect("find by client");
        let by_secret = manager
            .find_connection_by_connect_secret(" lookup-secret ")
            .expect("find by secret");
        let empty_secret = manager
            .find_connection_by_connect_secret("   ")
            .expect("empty secret");
        let all_connections = manager.list_connections().expect("list connections");

        assert_same_connection(&by_id.expect("by id"), &record);
        assert_eq!(by_client.len(), 1);
        assert_same_connection(&by_client[0], &record);
        assert_same_connection(&by_secret.expect("by secret"), &record);
        assert!(empty_secret.is_none());
        assert_eq!(all_connections.len(), 1);
        assert_same_connection(&all_connections[0], &record);
    }

    #[test]
    fn granted_permissions_and_approval_enforce_subset_rules() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x18))
            .expect("set signer");
        let requested = vec![
            permission(Method::SignEvent, Some("kind:1")),
            permission(Method::Ping, None),
        ];
        let granted = vec![requested[1].clone()];
        let invalid = vec![permission(Method::Nip44Encrypt, Some("kind:1"))];
        let pending = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x19), public_identity(0x20))
                    .with_requested_permissions(requested.clone().into())
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register");

        let invalid_set = manager
            .set_granted_permissions(&pending.connection_id, invalid.clone().into())
            .expect_err("invalid set grants");
        assert!(
            invalid_set
                .to_string()
                .contains("invalid granted permission")
        );

        let set_grants = manager
            .set_granted_permissions(&pending.connection_id, granted.clone().into())
            .expect("set grants");
        assert_eq!(
            set_grants.granted_permissions().as_slice(),
            granted.as_slice()
        );
        assert_eq!(
            set_grants.status,
            RadrootsNostrSignerConnectionStatus::Pending
        );

        let approved = manager
            .approve_connection(&pending.connection_id, granted.clone().into())
            .expect("approve");
        assert_eq!(approved.status, RadrootsNostrSignerConnectionStatus::Active);
        assert_eq!(
            approved.approval_state,
            RadrootsNostrSignerApprovalState::Approved
        );
        assert_eq!(
            approved.granted_permissions().as_slice(),
            granted.as_slice()
        );

        let reapprove = manager
            .approve_connection(&pending.connection_id, granted.into())
            .expect("reapprove active");
        assert_eq!(
            reapprove.status,
            RadrootsNostrSignerConnectionStatus::Active
        );

        let auto = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x21),
                public_identity(0x22),
            ))
            .expect("register auto");
        let err = manager
            .approve_connection(&auto.connection_id, Permissions::default())
            .expect_err("approval not required");
        assert!(err.to_string().contains("approval not required"));

        let terminal_pending = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x40), public_identity(0x41))
                    .with_connect_secret("terminal-secret")
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register terminal");
        manager
            .reject_connection(&terminal_pending.connection_id, Some("terminal".into()))
            .expect("reject terminal");
        let terminal_approve = manager
            .approve_connection(
                &terminal_pending.connection_id,
                vec![requested[0].clone()].into(),
            )
            .expect_err("approve rejected");
        assert!(
            terminal_approve
                .to_string()
                .contains("cannot approve rejected connection")
        );

        let unrestricted = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x23),
                public_identity(0x24),
            ))
            .expect("register unrestricted");
        let unrestricted_grants = manager
            .set_granted_permissions(&unrestricted.connection_id, invalid.into())
            .expect("unrestricted grants");
        assert_eq!(unrestricted_grants.granted_permissions.len(), 1);
    }

    #[test]
    fn reject_revoke_and_relay_updates_cover_terminal_paths() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x25))
            .expect("set signer");
        let rejected = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x26), public_identity(0x27))
                    .with_connect_secret("shared-secret")
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register reject");
        let rejected = manager
            .reject_connection(&rejected.connection_id, Some("denied".into()))
            .expect("reject");
        assert_eq!(
            rejected.status,
            RadrootsNostrSignerConnectionStatus::Rejected
        );
        assert_eq!(rejected.status_reason.as_deref(), Some("denied"));

        let reject_err = manager
            .reject_connection(&rejected.connection_id, None)
            .expect_err("reject terminal");
        assert!(
            reject_err
                .to_string()
                .contains("cannot reject rejected connection")
        );

        let relay_err = manager
            .update_relays(&rejected.connection_id, vec![primary_relay()])
            .expect_err("update rejected");
        assert!(
            relay_err
                .to_string()
                .contains("cannot update relays for rejected connection")
        );
        let rejected_lookup = manager
            .find_connection_by_connect_secret("shared-secret")
            .expect("lookup rejected secret");
        assert!(rejected_lookup.is_none());

        let active = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x28),
                public_identity(0x29),
            ))
            .expect("register active");
        let active = manager
            .update_relays(
                &active.connection_id,
                vec![tertiary_relay(), secondary_relay(), secondary_relay()],
            )
            .expect("update relays");
        assert_eq!(active.relays, vec![secondary_relay(), tertiary_relay()]);

        let revoked = manager
            .revoke_connection(&active.connection_id, Some("manual".into()))
            .expect("revoke");
        assert_eq!(revoked.status, RadrootsNostrSignerConnectionStatus::Revoked);
        assert_eq!(revoked.status_reason.as_deref(), Some("manual"));

        let revoke_again = manager
            .revoke_connection(&active.connection_id, None)
            .expect("revoke twice idempotently");
        assert_eq!(
            revoke_again.status,
            RadrootsNostrSignerConnectionStatus::Revoked
        );
        assert_eq!(revoke_again.status_reason.as_deref(), Some("manual"));
        assert_eq!(revoke_again.updated_at_unix, revoked.updated_at_unix);

        let grants_err = manager
            .set_granted_permissions(
                &active.connection_id,
                vec![permission(Method::Ping, None)].into(),
            )
            .expect_err("update grants revoked");
        assert!(
            grants_err
                .to_string()
                .contains("cannot update granted permissions for revoked connection")
        );

        let require_auth_err = manager
            .require_auth_challenge(&active.connection_id, api_primary_https())
            .expect_err("require auth revoked");
        assert!(
            require_auth_err
                .to_string()
                .contains("cannot require auth for revoked connection")
        );

        let pending_request_err = manager
            .set_pending_request(&active.connection_id, request_message("req-terminal"))
            .expect_err("pending request revoked");
        assert!(
            pending_request_err
                .to_string()
                .contains("cannot set pending request for revoked connection")
        );

        let authorize_auth_err = manager
            .authorize_auth_challenge(&active.connection_id)
            .expect_err("authorize auth revoked");
        assert!(
            authorize_auth_err
                .to_string()
                .contains("cannot authorize auth challenge for revoked connection")
        );
    }

    #[test]
    fn authentication_and_request_audit_paths_are_recorded() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x30))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x31),
                public_identity(0x32),
            ))
            .expect("register");

        let authenticated = manager
            .mark_authenticated(&record.connection_id)
            .expect("auth");
        assert!(authenticated.last_authenticated_at_unix.is_some());

        let consumed = manager
            .mark_connect_secret_consumed(&record.connection_id)
            .expect_err("consume missing secret");
        assert!(
            consumed
                .to_string()
                .contains("connection does not have a connect secret")
        );

        let audit = manager
            .record_request(
                &record.connection_id,
                " request-1 ",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Challenged,
                Some(" challenge ".into()),
            )
            .expect("record request");
        assert_eq!(audit.request_id.as_str(), "request-1");
        assert_eq!(audit.message.as_deref(), Some("challenge"));

        let blank_message_audit = manager
            .record_request(
                &record.connection_id,
                "request-2",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Denied,
                Some("   ".into()),
            )
            .expect("record blank message");
        assert!(blank_message_audit.message.is_none());

        let all_audits = manager.list_audit_records().expect("list audits");
        let connection_audits = manager
            .audit_records_for_connection(&record.connection_id)
            .expect("connection audits");
        let stored = manager
            .get_connection(&record.connection_id)
            .expect("get")
            .expect("stored");
        assert_eq!(all_audits, vec![audit.clone(), blank_message_audit.clone()]);
        assert_eq!(connection_audits, vec![audit, blank_message_audit]);
        assert!(stored.last_request_at_unix.is_some());

        let request_err = manager
            .record_request(
                &record.connection_id,
                "   ",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Denied,
                None,
            )
            .expect_err("invalid request id");
        assert!(request_err.to_string().contains("invalid request id"));
    }

    #[test]
    fn auth_challenge_and_pending_request_state_are_persisted_and_replayed() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x34))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x35),
                public_identity(0x36),
            ))
            .expect("register");

        let required = manager
            .require_auth_challenge(
                &record.connection_id,
                format!(" {}/flow ", api_primary_https()).as_str(),
            )
            .expect("require auth");
        assert_eq!(required.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert_eq!(
            required
                .auth_challenge
                .as_ref()
                .expect("auth challenge")
                .auth_url,
            format!("{}/flow", api_primary_https())
        );
        assert!(required.pending_request.is_none());

        let pending = manager
            .set_pending_request(&record.connection_id, request_message(" req-auth "))
            .expect("set pending request");
        assert_eq!(
            pending
                .pending_request
                .as_ref()
                .expect("pending request")
                .request_id()
                .as_str(),
            "req-auth"
        );

        let authorized = manager
            .authorize_auth_challenge(&record.connection_id)
            .expect("authorize");
        assert_eq!(
            authorized.connection.auth_state,
            RadrootsNostrSignerAuthState::Authorized
        );
        assert!(authorized.connection.last_authenticated_at_unix.is_some());
        assert!(authorized.connection.pending_request.is_none());
        assert_eq!(
            authorized
                .pending_request
                .as_ref()
                .expect("replayed request")
                .request_message()
                .id,
            "req-auth"
        );
        assert_eq!(
            authorized
                .connection
                .auth_challenge
                .as_ref()
                .expect("authorized challenge")
                .authorized_at_unix,
            authorized.connection.last_authenticated_at_unix
        );

        let invalid_url = manager
            .require_auth_challenge(&record.connection_id, "not-a-url")
            .expect_err("invalid auth url");
        assert!(invalid_url.to_string().contains("invalid auth url"));

        let no_pending_auth = manager
            .set_pending_request(&record.connection_id, request_message("req-again"))
            .expect_err("pending request without auth challenge");
        assert!(
            no_pending_auth
                .to_string()
                .contains("auth challenge not pending for connection")
        );

        let no_authorize = manager
            .authorize_auth_challenge(&record.connection_id)
            .expect_err("authorize without pending auth challenge");
        assert!(
            no_authorize
                .to_string()
                .contains("auth challenge not pending for connection")
        );
    }

    #[test]
    fn restored_authorized_auth_challenge_requeues_pending_request() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x134))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x135),
                public_identity(0x136),
            ))
            .expect("register");

        manager
            .require_auth_challenge(
                &record.connection_id,
                format!("{}/flow", api_primary_https()).as_str(),
            )
            .expect("require auth");
        manager
            .set_pending_request(&record.connection_id, request_message("req-replay"))
            .expect("set pending");

        let authorized = manager
            .authorize_auth_challenge(&record.connection_id)
            .expect("authorize");
        let pending_request = authorized.pending_request.expect("pending request");

        let restored = manager
            .restore_pending_auth_challenge(&record.connection_id, pending_request.clone())
            .expect("restore pending challenge");
        assert_eq!(restored.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert_eq!(
            restored
                .auth_challenge
                .as_ref()
                .expect("challenge")
                .authorized_at_unix,
            None
        );
        assert!(restored.last_authenticated_at_unix.is_none());
        assert_eq!(
            restored
                .pending_request
                .as_ref()
                .expect("pending request")
                .request_id()
                .as_str(),
            pending_request.request_id().as_str()
        );
    }

    #[test]
    fn connect_secret_consumption_persists_and_remains_idempotent() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x37))
            .expect("set signer");
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x38), public_identity(0x39))
                    .with_connect_secret("one-shot-secret"),
            )
            .expect("register");

        let consumed = manager
            .mark_connect_secret_consumed(&record.connection_id)
            .expect("consume secret");
        assert!(consumed.connect_secret_is_consumed());
        assert!(consumed.connect_secret_consumed_at_unix.is_some());

        let consumed_again = manager
            .mark_connect_secret_consumed(&record.connection_id)
            .expect("consume secret again");
        assert_eq!(
            consumed_again.connect_secret_consumed_at_unix,
            consumed.connect_secret_consumed_at_unix
        );

        let found = manager
            .find_connection_by_connect_secret("one-shot-secret")
            .expect("find consumed secret")
            .expect("stored secret");
        assert!(found.connect_secret_is_consumed());
        assert_eq!(
            found.connect_secret_consumed_at_unix,
            consumed.connect_secret_consumed_at_unix
        );
    }

    #[test]
    fn connect_secret_publish_workflow_is_persisted_and_finalized() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x237))
            .expect("set signer");
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x238), public_identity(0x239))
                    .with_connect_secret("workflow-secret"),
            )
            .expect("register");

        let workflow = manager
            .begin_connect_secret_publish_finalization(&record.connection_id)
            .expect("begin workflow");
        assert_eq!(
            workflow.kind,
            RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization
        );
        assert_eq!(
            workflow.state,
            RadrootsNostrSignerPublishWorkflowState::PendingPublish
        );
        assert!(workflow.pending_request.is_none());
        assert!(
            !manager
                .get_connection(&record.connection_id)
                .expect("get")
                .expect("stored")
                .connect_secret_is_consumed()
        );
        assert_eq!(
            manager.list_publish_workflows().expect("list workflows"),
            vec![workflow.clone()]
        );

        let published = manager
            .mark_publish_workflow_published(&workflow.workflow_id)
            .expect("mark published");
        assert_eq!(
            published.state,
            RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize
        );

        let finalized = manager
            .finalize_publish_workflow(&workflow.workflow_id)
            .expect("finalize workflow");
        assert!(finalized.connect_secret_is_consumed());
        assert!(
            manager
                .list_publish_workflows()
                .expect("list workflows")
                .is_empty()
        );
        assert!(
            manager
                .find_connection_by_connect_secret("workflow-secret")
                .expect("find secret")
                .expect("stored")
                .connect_secret_is_consumed()
        );
    }

    #[test]
    fn auth_replay_publish_workflow_is_persisted_and_finalized() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x23a))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x23b),
                public_identity(0x23c),
            ))
            .expect("register");

        manager
            .require_auth_challenge(
                &record.connection_id,
                format!("{}/flow", api_primary_https()).as_str(),
            )
            .expect("require auth");
        let pending = manager
            .set_pending_request(&record.connection_id, request_message("req-auth-workflow"))
            .expect("set pending");
        let pending_request = pending.pending_request.expect("pending request");

        let workflow = manager
            .begin_auth_replay_publish_finalization(&record.connection_id)
            .expect("begin auth replay workflow");
        assert_eq!(
            workflow.kind,
            RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization
        );
        assert_eq!(workflow.pending_request.as_ref(), Some(&pending_request));
        assert!(workflow.authorized_at_unix.is_some());

        let stored_before_publish = manager
            .get_connection(&record.connection_id)
            .expect("get")
            .expect("stored");
        assert_eq!(
            stored_before_publish.auth_state,
            RadrootsNostrSignerAuthState::Pending
        );
        assert_eq!(
            stored_before_publish.pending_request.as_ref(),
            Some(&pending_request)
        );

        manager
            .mark_publish_workflow_published(&workflow.workflow_id)
            .expect("mark published");
        let finalized = manager
            .finalize_publish_workflow(&workflow.workflow_id)
            .expect("finalize auth replay");
        assert_eq!(
            finalized.auth_state,
            RadrootsNostrSignerAuthState::Authorized
        );
        assert!(finalized.pending_request.is_none());
        assert_eq!(
            finalized
                .auth_challenge
                .as_ref()
                .expect("challenge")
                .authorized_at_unix,
            workflow.authorized_at_unix
        );
        assert_eq!(
            finalized.last_authenticated_at_unix,
            workflow.authorized_at_unix
        );
        assert!(
            manager
                .list_publish_workflows()
                .expect("list workflows")
                .is_empty()
        );
    }

    #[test]
    fn canceling_auth_replay_publish_workflow_preserves_pending_request() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x23d))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x23e),
                public_identity(0x23f),
            ))
            .expect("register");

        manager
            .require_auth_challenge(
                &record.connection_id,
                format!("{}/flow", api_primary_https()).as_str(),
            )
            .expect("require auth");
        let pending = manager
            .set_pending_request(&record.connection_id, request_message("req-auth-cancel"))
            .expect("set pending");
        let pending_request = pending.pending_request.expect("pending request");

        let workflow = manager
            .begin_auth_replay_publish_finalization(&record.connection_id)
            .expect("begin auth replay workflow");
        let canceled = manager
            .cancel_publish_workflow(&workflow.workflow_id)
            .expect("cancel workflow");
        assert_eq!(canceled.workflow_id, workflow.workflow_id);

        let stored = manager
            .get_connection(&record.connection_id)
            .expect("get")
            .expect("stored");
        assert_eq!(stored.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert_eq!(stored.pending_request.as_ref(), Some(&pending_request));
        assert!(
            manager
                .list_publish_workflows()
                .expect("list workflows")
                .is_empty()
        );
    }

    #[test]
    fn evaluate_auth_replay_publish_workflow_uses_authorized_view_without_mutating_state() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x240))
            .expect("set signer");
        let record = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x241),
                public_identity(0x242),
            ))
            .expect("register");

        manager
            .set_granted_permissions(
                &record.connection_id,
                vec!["get_public_key".parse().expect("permission")].into(),
            )
            .expect("grant permissions");
        manager
            .require_auth_challenge(
                &record.connection_id,
                format!("{}/flow", api_primary_https()).as_str(),
            )
            .expect("require auth");
        let challenged = manager
            .evaluate_request(
                &record.connection_id,
                RequestMessage::new("req-auth-preview", Request::GetPublicKey),
            )
            .expect("evaluate challenged request");
        assert_eq!(
            challenged.audit.decision,
            RadrootsNostrSignerRequestDecision::Challenged
        );
        let pending_request = challenged
            .connection
            .pending_request
            .expect("pending request");

        let workflow = manager
            .begin_auth_replay_publish_finalization(&record.connection_id)
            .expect("begin auth replay workflow");
        let evaluation = manager
            .evaluate_auth_replay_publish_workflow(&workflow.workflow_id)
            .expect("evaluate auth replay workflow");

        assert_eq!(
            evaluation.request_id.as_str(),
            pending_request.request_id().as_str()
        );
        assert_eq!(
            evaluation.connection.auth_state,
            RadrootsNostrSignerAuthState::Authorized
        );
        assert!(evaluation.connection.pending_request.is_none());
        assert!(matches!(
            evaluation.action,
            RadrootsNostrSignerRequestAction::Allowed { .. }
        ));

        let stored = manager
            .get_connection(&record.connection_id)
            .expect("get")
            .expect("stored");
        assert_eq!(stored.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert_eq!(stored.pending_request.as_ref(), Some(&pending_request));
        let audits = manager.list_audit_records().expect("list audits");
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].request_id.as_str(), "req-auth-preview");
        assert_eq!(
            audits[0].decision,
            RadrootsNostrSignerRequestDecision::Allowed
        );
    }

    #[test]
    fn publish_workflow_duplicate_and_missing_paths_are_rejected() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x240))
            .expect("set signer");
        let record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x241), public_identity(0x242))
                    .with_connect_secret("duplicate-secret"),
            )
            .expect("register");

        let workflow = manager
            .begin_connect_secret_publish_finalization(&record.connection_id)
            .expect("begin workflow");
        let duplicate = manager
            .begin_connect_secret_publish_finalization(&record.connection_id)
            .expect_err("duplicate workflow");
        assert!(
            duplicate
                .to_string()
                .contains("publish workflow already active")
        );

        let missing_workflow_id = RadrootsNostrSignerWorkflowId::parse("wf-missing").expect("id");
        let missing_mark = manager
            .mark_publish_workflow_published(&missing_workflow_id)
            .expect_err("missing mark");
        let missing_finalize = manager
            .finalize_publish_workflow(&missing_workflow_id)
            .expect_err("missing finalize");
        let missing_cancel = manager
            .cancel_publish_workflow(&missing_workflow_id)
            .expect_err("missing cancel");

        for err in [missing_mark, missing_finalize, missing_cancel] {
            assert!(err.to_string().contains("publish workflow not found"));
        }

        let unpublished_finalize = manager
            .finalize_publish_workflow(&workflow.workflow_id)
            .expect_err("unpublished finalize");
        assert!(
            unpublished_finalize
                .to_string()
                .contains("publish workflow has not reached published state")
        );
    }

    #[test]
    fn publish_workflow_entrypoints_reject_invalid_connection_states() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x300))
            .expect("set signer");
        let missing_connection_id =
            RadrootsNostrSignerConnectionId::parse("conn-missing-publish").expect("connection id");
        let restore_pending_request =
            RadrootsNostrSignerPendingRequest::new(request_message("req-restore-invalid"), 61)
                .expect("pending request");

        let missing_restore_err = manager
            .restore_pending_auth_challenge(&missing_connection_id, restore_pending_request.clone())
            .expect_err("missing restore connection");
        assert!(
            missing_restore_err
                .to_string()
                .contains("connection not found")
        );

        let terminal_restore = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x301),
                public_identity(0x302),
            ))
            .expect("register terminal restore");
        manager
            .reject_connection(&terminal_restore.connection_id, Some("closed".into()))
            .expect("reject terminal restore");
        let terminal_restore_err = manager
            .restore_pending_auth_challenge(
                &terminal_restore.connection_id,
                restore_pending_request.clone(),
            )
            .expect_err("terminal restore error");
        assert!(
            terminal_restore_err
                .to_string()
                .contains("cannot restore auth challenge for rejected connection")
        );

        let unauthorized_restore = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x303),
                public_identity(0x304),
            ))
            .expect("register unauthorized restore");
        let unauthorized_restore_err = manager
            .restore_pending_auth_challenge(
                &unauthorized_restore.connection_id,
                restore_pending_request.clone(),
            )
            .expect_err("unauthorized restore error");
        assert!(
            unauthorized_restore_err
                .to_string()
                .contains("auth challenge not authorized for connection")
        );

        let missing_challenge_restore = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x305),
                public_identity(0x306),
            ))
            .expect("register missing challenge restore");
        manager
            .require_auth_challenge(
                &missing_challenge_restore.connection_id,
                format!("{}/restore", api_primary_https()).as_str(),
            )
            .expect("require auth");
        manager
            .set_pending_request(
                &missing_challenge_restore.connection_id,
                request_message("req-restore-missing-challenge"),
            )
            .expect("set pending");
        let replay = manager
            .authorize_auth_challenge(&missing_challenge_restore.connection_id)
            .expect("authorize")
            .pending_request
            .expect("pending request");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == missing_challenge_restore.connection_id)
                .expect("stored connection");
            record.auth_challenge = None;
        }
        let missing_challenge_restore_err = manager
            .restore_pending_auth_challenge(&missing_challenge_restore.connection_id, replay)
            .expect_err("missing challenge restore error");
        assert!(
            missing_challenge_restore_err
                .to_string()
                .contains("auth challenge missing for connection")
        );

        let terminal_connect = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x307), public_identity(0x308))
                    .with_connect_secret("terminal-connect-secret"),
            )
            .expect("register terminal connect");
        manager
            .reject_connection(&terminal_connect.connection_id, Some("closed".into()))
            .expect("reject terminal connect");
        let terminal_connect_err = manager
            .begin_connect_secret_publish_finalization(&terminal_connect.connection_id)
            .expect_err("terminal connect workflow");
        assert!(
            terminal_connect_err
                .to_string()
                .contains("cannot begin connect secret finalization for rejected connection")
        );

        let no_secret_connect = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x309),
                public_identity(0x30a),
            ))
            .expect("register no secret connect");
        let no_secret_connect_err = manager
            .begin_connect_secret_publish_finalization(&no_secret_connect.connection_id)
            .expect_err("missing secret workflow");
        assert!(
            no_secret_connect_err
                .to_string()
                .contains("connection does not have a connect secret")
        );

        let consumed_connect = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x30b), public_identity(0x30c))
                    .with_connect_secret("consumed-connect-secret"),
            )
            .expect("register consumed connect");
        manager
            .mark_connect_secret_consumed(&consumed_connect.connection_id)
            .expect("consume connect secret");
        let consumed_connect_err = manager
            .begin_connect_secret_publish_finalization(&consumed_connect.connection_id)
            .expect_err("consumed secret workflow");
        assert!(
            consumed_connect_err
                .to_string()
                .contains("connect secret already consumed for connection")
        );

        let missing_mark_consumed_err = manager
            .mark_connect_secret_consumed(&missing_connection_id)
            .expect_err("missing mark connect secret consumed");
        assert!(
            missing_mark_consumed_err
                .to_string()
                .contains("connection not found")
        );

        let terminal_auth = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x30d),
                public_identity(0x30e),
            ))
            .expect("register terminal auth");
        manager
            .reject_connection(&terminal_auth.connection_id, Some("closed".into()))
            .expect("reject terminal auth");
        let terminal_auth_err = manager
            .begin_auth_replay_publish_finalization(&terminal_auth.connection_id)
            .expect_err("terminal auth workflow");
        assert!(
            terminal_auth_err
                .to_string()
                .contains("cannot begin auth replay finalization for rejected connection")
        );

        let not_pending_auth = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x30f),
                public_identity(0x310),
            ))
            .expect("register not pending auth");
        let not_pending_auth_err = manager
            .begin_auth_replay_publish_finalization(&not_pending_auth.connection_id)
            .expect_err("not pending auth workflow");
        assert!(
            not_pending_auth_err
                .to_string()
                .contains("auth challenge not pending for connection")
        );

        let missing_challenge_auth = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x311),
                public_identity(0x312),
            ))
            .expect("register missing challenge auth");
        manager
            .require_auth_challenge(
                &missing_challenge_auth.connection_id,
                format!("{}/auth-missing-challenge", api_primary_https()).as_str(),
            )
            .expect("require auth");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == missing_challenge_auth.connection_id)
                .expect("stored connection");
            record.auth_challenge = None;
        }
        let missing_challenge_auth_err = manager
            .begin_auth_replay_publish_finalization(&missing_challenge_auth.connection_id)
            .expect_err("missing challenge auth workflow");
        assert!(
            missing_challenge_auth_err
                .to_string()
                .contains("auth challenge missing for connection")
        );

        let missing_pending_auth = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x313),
                public_identity(0x314),
            ))
            .expect("register missing pending auth");
        manager
            .require_auth_challenge(
                &missing_pending_auth.connection_id,
                format!("{}/auth-missing-pending", api_primary_https()).as_str(),
            )
            .expect("require auth");
        let missing_pending_auth_err = manager
            .begin_auth_replay_publish_finalization(&missing_pending_auth.connection_id)
            .expect_err("missing pending auth workflow");
        assert!(
            missing_pending_auth_err
                .to_string()
                .contains("pending request missing for auth replay finalization")
        );

        let duplicate_auth = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x315),
                public_identity(0x316),
            ))
            .expect("register duplicate auth");
        manager
            .require_auth_challenge(
                &duplicate_auth.connection_id,
                format!("{}/auth-duplicate", api_primary_https()).as_str(),
            )
            .expect("require auth");
        manager
            .set_pending_request(
                &duplicate_auth.connection_id,
                request_message("req-auth-duplicate"),
            )
            .expect("set pending");
        manager
            .begin_auth_replay_publish_finalization(&duplicate_auth.connection_id)
            .expect("begin auth workflow");
        let duplicate_auth_err = manager
            .begin_auth_replay_publish_finalization(&duplicate_auth.connection_id)
            .expect_err("duplicate auth workflow");
        assert!(
            duplicate_auth_err
                .to_string()
                .contains("publish workflow already active for auth_replay_finalization")
        );
    }

    #[test]
    fn publish_workflow_finalize_and_evaluate_reject_corrupted_states() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x320))
            .expect("set signer");

        let missing_workflow_id =
            RadrootsNostrSignerWorkflowId::parse("wf-evaluate-missing").expect("workflow id");
        let missing_evaluate_err = manager
            .evaluate_auth_replay_publish_workflow(&missing_workflow_id)
            .expect_err("missing workflow evaluate");
        assert!(
            missing_evaluate_err
                .to_string()
                .contains("publish workflow not found")
        );

        let connect_kind_record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x321), public_identity(0x322))
                    .with_connect_secret("evaluate-connect-kind"),
            )
            .expect("register connect kind");
        let connect_kind_workflow = manager
            .begin_connect_secret_publish_finalization(&connect_kind_record.connection_id)
            .expect("begin connect workflow");
        let wrong_kind_err = manager
            .evaluate_auth_replay_publish_workflow(&connect_kind_workflow.workflow_id)
            .expect_err("wrong workflow kind");
        assert!(
            wrong_kind_err
                .to_string()
                .contains("publish workflow is not an auth replay finalization")
        );

        let connect_missing_secret_record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x323), public_identity(0x324))
                    .with_connect_secret("missing-secret-finalize"),
            )
            .expect("register connect missing secret");
        let connect_missing_secret_workflow = manager
            .begin_connect_secret_publish_finalization(&connect_missing_secret_record.connection_id)
            .expect("begin connect missing secret workflow");
        manager
            .mark_publish_workflow_published(&connect_missing_secret_workflow.workflow_id)
            .expect("mark connect missing secret workflow");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == connect_missing_secret_record.connection_id)
                .expect("stored connection");
            record.connect_secret_hash = None;
            record.connect_secret_consumed_at_unix = None;
        }
        let connect_missing_secret_err = manager
            .finalize_publish_workflow(&connect_missing_secret_workflow.workflow_id)
            .expect_err("missing connect secret finalize");
        assert!(
            connect_missing_secret_err
                .to_string()
                .contains("connection does not have a connect secret")
        );

        let connect_consumed_record = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x325), public_identity(0x326))
                    .with_connect_secret("consumed-secret-finalize"),
            )
            .expect("register connect consumed");
        let connect_consumed_workflow = manager
            .begin_connect_secret_publish_finalization(&connect_consumed_record.connection_id)
            .expect("begin connect consumed workflow");
        manager
            .mark_publish_workflow_published(&connect_consumed_workflow.workflow_id)
            .expect("mark connect consumed workflow");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == connect_consumed_record.connection_id)
                .expect("stored connection");
            record.connect_secret_consumed_at_unix = Some(88);
        }
        let connect_consumed_err = manager
            .finalize_publish_workflow(&connect_consumed_workflow.workflow_id)
            .expect_err("consumed connect secret finalize");
        assert!(
            connect_consumed_err
                .to_string()
                .contains("connect secret already consumed for connection")
        );

        let start_auth_replay_workflow = |suffix: u32,
                                          request_id: &str|
         -> (
            RadrootsNostrSignerConnectionRecord,
            RadrootsNostrSignerPublishWorkflowRecord,
            RadrootsNostrSignerPendingRequest,
        ) {
            let record = manager
                .register_connection(RadrootsNostrSignerConnectionDraft::new(
                    public_key(0x330 + suffix),
                    public_identity(0x340 + suffix),
                ))
                .expect("register auth workflow");
            manager
                .require_auth_challenge(
                    &record.connection_id,
                    format!("{}/auth-workflow-{suffix}", api_primary_https()).as_str(),
                )
                .expect("require auth");
            let pending = manager
                .set_pending_request(&record.connection_id, request_message(request_id))
                .expect("set pending");
            let pending_request = pending.pending_request.expect("pending request");
            let workflow = manager
                .begin_auth_replay_publish_finalization(&record.connection_id)
                .expect("begin auth workflow");
            (record, workflow, pending_request)
        };

        let (missing_pending_record, missing_pending_workflow, _) =
            start_auth_replay_workflow(0, "req-eval-missing-pending");
        {
            let mut state = manager.state.write().expect("write");
            let workflow = state
                .publish_workflows
                .iter_mut()
                .find(|workflow| workflow.workflow_id == missing_pending_workflow.workflow_id)
                .expect("stored workflow");
            workflow.pending_request = None;
        }
        let missing_pending_eval_err = manager
            .evaluate_auth_replay_publish_workflow(&missing_pending_workflow.workflow_id)
            .expect_err("missing pending evaluate");
        assert!(
            missing_pending_eval_err
                .to_string()
                .contains("auth replay workflow missing pending request")
        );
        {
            let mut state = manager.state.write().expect("write");
            state
                .publish_workflows
                .retain(|workflow| workflow.workflow_id != missing_pending_workflow.workflow_id);
            state
                .connections
                .retain(|record| record.connection_id != missing_pending_record.connection_id);
        }

        let (missing_challenge_eval_record, missing_challenge_eval_workflow, pending_request) =
            start_auth_replay_workflow(1, "req-eval-no-challenge");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == missing_challenge_eval_record.connection_id)
                .expect("stored connection");
            record.auth_challenge = None;
        }
        let evaluation = manager
            .evaluate_auth_replay_publish_workflow(&missing_challenge_eval_workflow.workflow_id)
            .expect("evaluate without challenge");
        assert_eq!(
            evaluation.request_id.as_str(),
            pending_request.request_id().as_str()
        );
        assert_eq!(
            evaluation.connection.auth_state,
            RadrootsNostrSignerAuthState::Authorized
        );
        assert!(evaluation.connection.pending_request.is_none());

        let (terminal_eval_record, terminal_eval_workflow, _) =
            start_auth_replay_workflow(2, "req-eval-terminal");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == terminal_eval_record.connection_id)
                .expect("stored connection");
            record.status = RadrootsNostrSignerConnectionStatus::Rejected;
        }
        let terminal_eval_err = manager
            .evaluate_auth_replay_publish_workflow(&terminal_eval_workflow.workflow_id)
            .expect_err("terminal evaluate");
        assert!(
            terminal_eval_err
                .to_string()
                .contains("cannot evaluate auth replay workflow for rejected connection")
        );

        let (not_pending_eval_record, not_pending_eval_workflow, _) =
            start_auth_replay_workflow(3, "req-eval-not-pending");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == not_pending_eval_record.connection_id)
                .expect("stored connection");
            record.auth_state = RadrootsNostrSignerAuthState::Authorized;
        }
        let not_pending_eval_err = manager
            .evaluate_auth_replay_publish_workflow(&not_pending_eval_workflow.workflow_id)
            .expect_err("not pending evaluate");
        assert!(
            not_pending_eval_err
                .to_string()
                .contains("auth challenge not pending for connection")
        );

        let (mismatch_eval_record, mismatch_eval_workflow, _) =
            start_auth_replay_workflow(4, "req-eval-mismatch");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == mismatch_eval_record.connection_id)
                .expect("stored connection");
            record.pending_request = Some(
                RadrootsNostrSignerPendingRequest::new(
                    request_message("req-eval-mismatch-other"),
                    77,
                )
                .expect("mismatched pending request"),
            );
        }
        let mismatch_eval_err = manager
            .evaluate_auth_replay_publish_workflow(&mismatch_eval_workflow.workflow_id)
            .expect_err("mismatch evaluate");
        assert!(
            mismatch_eval_err
                .to_string()
                .contains("pending request does not match auth replay workflow")
        );

        let start_published_auth_workflow = |suffix: u32, request_id: &str| {
            let (record, workflow, pending_request) =
                start_auth_replay_workflow(suffix, request_id);
            let published = manager
                .mark_publish_workflow_published(&workflow.workflow_id)
                .expect("mark published");
            (record, published, pending_request)
        };

        let (auth_not_pending_record, auth_not_pending_workflow, _) =
            start_published_auth_workflow(5, "req-finalize-not-pending");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == auth_not_pending_record.connection_id)
                .expect("stored connection");
            record.auth_state = RadrootsNostrSignerAuthState::Authorized;
        }
        let auth_not_pending_err = manager
            .finalize_publish_workflow(&auth_not_pending_workflow.workflow_id)
            .expect_err("not pending finalize");
        assert!(
            auth_not_pending_err
                .to_string()
                .contains("auth challenge not pending for connection")
        );

        let (missing_connection_finalize_record, missing_connection_finalize_workflow, _) =
            start_published_auth_workflow(11, "req-finalize-missing-connection");
        {
            let mut state = manager.state.write().expect("write");
            let workflow = state
                .publish_workflows
                .iter_mut()
                .find(|workflow| {
                    workflow.workflow_id == missing_connection_finalize_workflow.workflow_id
                })
                .expect("stored workflow");
            workflow.connection_id =
                RadrootsNostrSignerConnectionId::parse("conn-finalize-missing")
                    .expect("connection id");
        }
        let missing_connection_finalize_err = manager
            .finalize_publish_workflow(&missing_connection_finalize_workflow.workflow_id)
            .expect_err("missing connection finalize");
        assert!(
            missing_connection_finalize_err
                .to_string()
                .contains("connection not found")
        );
        {
            let mut state = manager.state.write().expect("write");
            state.publish_workflows.retain(|workflow| {
                workflow.workflow_id != missing_connection_finalize_workflow.workflow_id
            });
            state.connections.retain(|record| {
                record.connection_id != missing_connection_finalize_record.connection_id
            });
        }

        let (auth_missing_challenge_record, auth_missing_challenge_workflow, _) =
            start_published_auth_workflow(6, "req-finalize-missing-challenge");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == auth_missing_challenge_record.connection_id)
                .expect("stored connection");
            record.auth_challenge = None;
        }
        let auth_missing_challenge_err = manager
            .finalize_publish_workflow(&auth_missing_challenge_workflow.workflow_id)
            .expect_err("missing challenge finalize");
        assert!(
            auth_missing_challenge_err
                .to_string()
                .contains("auth challenge missing for connection")
        );

        let (workflow_missing_pending_record, workflow_missing_pending_workflow, _) =
            start_published_auth_workflow(7, "req-finalize-workflow-missing-pending");
        {
            let mut state = manager.state.write().expect("write");
            let workflow = state
                .publish_workflows
                .iter_mut()
                .find(|workflow| {
                    workflow.workflow_id == workflow_missing_pending_workflow.workflow_id
                })
                .expect("stored workflow");
            workflow.pending_request = None;
        }
        let workflow_missing_pending_err = manager
            .finalize_publish_workflow(&workflow_missing_pending_workflow.workflow_id)
            .expect_err("workflow missing pending finalize");
        assert!(
            workflow_missing_pending_err
                .to_string()
                .contains("auth replay workflow missing pending request")
        );
        {
            let mut state = manager.state.write().expect("write");
            state.publish_workflows.retain(|workflow| {
                workflow.workflow_id != workflow_missing_pending_workflow.workflow_id
            });
            state.connections.retain(|record| {
                record.connection_id != workflow_missing_pending_record.connection_id
            });
        }

        let (mismatch_finalize_record, mismatch_finalize_workflow, _) =
            start_published_auth_workflow(8, "req-finalize-mismatch");
        {
            let mut state = manager.state.write().expect("write");
            let record = state
                .connections
                .iter_mut()
                .find(|record| record.connection_id == mismatch_finalize_record.connection_id)
                .expect("stored connection");
            record.pending_request = Some(
                RadrootsNostrSignerPendingRequest::new(
                    request_message("req-finalize-mismatch-other"),
                    78,
                )
                .expect("mismatched pending request"),
            );
        }
        let mismatch_finalize_err = manager
            .finalize_publish_workflow(&mismatch_finalize_workflow.workflow_id)
            .expect_err("mismatch finalize");
        assert!(
            mismatch_finalize_err
                .to_string()
                .contains("pending request does not match auth replay workflow")
        );

        let (missing_authorized_record, missing_authorized_workflow, _) =
            start_published_auth_workflow(9, "req-finalize-missing-authorized");
        {
            let mut state = manager.state.write().expect("write");
            let workflow = state
                .publish_workflows
                .iter_mut()
                .find(|workflow| workflow.workflow_id == missing_authorized_workflow.workflow_id)
                .expect("stored workflow");
            workflow.authorized_at_unix = None;
        }
        let missing_authorized_err = manager
            .finalize_publish_workflow(&missing_authorized_workflow.workflow_id)
            .expect_err("missing authorized finalize");
        assert!(
            missing_authorized_err
                .to_string()
                .contains("auth replay workflow missing authorized timestamp")
        );
        {
            let mut state = manager.state.write().expect("write");
            state
                .publish_workflows
                .retain(|workflow| workflow.workflow_id != missing_authorized_workflow.workflow_id);
            state
                .connections
                .retain(|record| record.connection_id != missing_authorized_record.connection_id);
        }

        let (missing_connection_eval_record, missing_connection_eval_workflow, _) =
            start_auth_replay_workflow(12, "req-eval-missing-connection");
        {
            let mut state = manager.state.write().expect("write");
            let workflow = state
                .publish_workflows
                .iter_mut()
                .find(|workflow| {
                    workflow.workflow_id == missing_connection_eval_workflow.workflow_id
                })
                .expect("stored workflow");
            workflow.connection_id =
                RadrootsNostrSignerConnectionId::parse("conn-evaluate-missing")
                    .expect("connection id");
        }
        let missing_connection_eval_err = manager
            .evaluate_auth_replay_publish_workflow(&missing_connection_eval_workflow.workflow_id)
            .expect_err("missing connection evaluate");
        assert!(
            missing_connection_eval_err
                .to_string()
                .contains("connection not found")
        );
        {
            let mut state = manager.state.write().expect("write");
            state.publish_workflows.retain(|workflow| {
                workflow.workflow_id != missing_connection_eval_workflow.workflow_id
            });
            state.connections.retain(|record| {
                record.connection_id != missing_connection_eval_record.connection_id
            });
        }
    }

    #[test]
    fn manager_reports_missing_connections_and_save_failures() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        let missing_id = RadrootsNostrSignerConnectionId::parse("missing").expect("id");
        let missing_get = manager.get_connection(&missing_id).expect("missing get");
        assert!(missing_get.is_none());

        let mark_err = manager
            .mark_authenticated(&missing_id)
            .expect_err("missing auth");
        assert!(mark_err.to_string().contains("connection not found"));

        let save_error_store =
            Arc::new(SaveErrorStore::new(RadrootsNostrSignerStoreState::default()));
        let loaded_state = save_error_store.load().expect("load save error store");
        assert_eq!(loaded_state.version, RADROOTS_NOSTR_SIGNER_STORE_VERSION);
        let manager = RadrootsNostrSignerManager::new(save_error_store).expect("manager");
        let err = manager
            .set_signer_identity(public_identity(0x33))
            .expect_err("save error");
        assert!(err.to_string().contains("store save failed"));

        let signer_identity = public_identity(0x243);
        let connection = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::parse("conn-save-error").expect("id"),
            signer_identity.clone(),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x244), public_identity(0x245))
                .with_connect_secret("save-error-secret"),
            1,
        );
        let manager = RadrootsNostrSignerManager::new(Arc::new(SaveErrorStore::new(
            RadrootsNostrSignerStoreState {
                version: RADROOTS_NOSTR_SIGNER_STORE_VERSION,
                signer_identity: Some(signer_identity),
                connections: vec![connection.clone()],
                audit_records: Vec::new(),
                publish_workflows: Vec::new(),
            },
        )))
        .expect("manager with preloaded state");
        let workflow_err = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect_err("workflow save error");
        assert!(workflow_err.to_string().contains("store save failed"));
    }

    #[test]
    fn mutation_methods_cover_remaining_error_paths() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x51))
            .expect("set signer");

        let missing_id = RadrootsNostrSignerConnectionId::parse("missing-2").expect("id");
        let missing_permissions: Permissions = vec![permission(Method::Ping, None)].into();

        let missing_grants = manager
            .set_granted_permissions(&missing_id, missing_permissions.clone())
            .expect_err("missing grants");
        let missing_approve = manager
            .approve_connection(&missing_id, Permissions::default())
            .expect_err("missing approve");
        let missing_reject = manager
            .reject_connection(&missing_id, None)
            .expect_err("missing reject");
        let missing_revoke = manager
            .revoke_connection(&missing_id, None)
            .expect_err("missing revoke");
        let missing_relays = manager
            .update_relays(&missing_id, vec![primary_relay()])
            .expect_err("missing relays");
        let missing_require_auth = manager
            .require_auth_challenge(&missing_id, api_primary_https())
            .expect_err("missing require auth");
        let missing_pending_request = manager
            .set_pending_request(&missing_id, request_message("req-missing-2"))
            .expect_err("missing pending request");
        let missing_begin_connect_workflow = manager
            .begin_connect_secret_publish_finalization(&missing_id)
            .expect_err("missing connect workflow");
        let missing_begin_auth_workflow = manager
            .begin_auth_replay_publish_finalization(&missing_id)
            .expect_err("missing auth workflow");
        let missing_authorize_auth = manager
            .authorize_auth_challenge(&missing_id)
            .expect_err("missing authorize auth");
        let missing_request = manager
            .record_request(
                &missing_id,
                "req-missing",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Denied,
                None,
            )
            .expect_err("missing request");

        for err in [
            missing_grants,
            missing_approve,
            missing_reject,
            missing_revoke,
            missing_relays,
            missing_require_auth,
            missing_pending_request,
            missing_begin_connect_workflow,
            missing_begin_auth_workflow,
            missing_authorize_auth,
            missing_request,
        ] {
            assert!(err.to_string().contains("connection not found"));
        }

        let requested = vec![permission(Method::Ping, None)];
        let pending = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x52), public_identity(0x53))
                    .with_requested_permissions(requested.into())
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register pending");
        let invalid_approve = manager
            .approve_connection(
                &pending.connection_id,
                vec![permission(Method::Nip44Encrypt, Some("kind:1"))].into(),
            )
            .expect_err("invalid approve grants");
        assert!(
            invalid_approve
                .to_string()
                .contains("invalid granted permission")
        );

        let auth_required = manager
            .require_auth_challenge(&pending.connection_id, api_primary_https())
            .expect("require auth");
        assert_eq!(
            auth_required.auth_state,
            RadrootsNostrSignerAuthState::Pending
        );

        let invalid_pending_request = manager
            .set_pending_request(&pending.connection_id, request_message("   "))
            .expect_err("invalid pending request id");
        assert!(
            invalid_pending_request
                .to_string()
                .contains("invalid request id")
        );

        let update_state_err = manager
            .update_state(|_| Err(RadrootsNostrSignerError::InvalidState("manual".into())))
            .expect_err("update_state error");
        assert!(update_state_err.to_string().contains("manual"));
    }

    #[test]
    fn manager_reports_poisoned_state_lock() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        poison_manager_state(&manager);

        let identity = manager.signer_identity().expect_err("poisoned read");
        assert!(identity.to_string().contains("signer state lock poisoned"));
    }

    #[test]
    fn read_helpers_report_poisoned_state_lock() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        poison_manager_state(&manager);

        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-1").expect("id");
        let client_public_key = public_key(0x47);

        let get_err = manager
            .get_connection(&connection_id)
            .expect_err("poisoned get");
        let list_err = manager.list_connections().expect_err("poisoned list");
        let audit_list_err = manager
            .list_audit_records()
            .expect_err("poisoned audit list");
        let audit_for_connection_err = manager
            .audit_records_for_connection(&connection_id)
            .expect_err("poisoned audit connection");
        let workflow_list_err = manager
            .list_publish_workflows()
            .expect_err("poisoned workflow list");
        let workflow_get_err = manager
            .get_publish_workflow(&RadrootsNostrSignerWorkflowId::parse("wf-poison").expect("id"))
            .expect_err("poisoned workflow get");
        let find_secret_err = manager
            .find_connection_by_connect_secret("secret")
            .expect_err("poisoned secret lookup");
        let find_client_err = manager
            .find_connections_by_client_public_key(&client_public_key)
            .expect_err("poisoned client lookup");
        let lookup_secret_err = manager
            .lookup_session(&client_public_key, Some("secret"))
            .expect_err("poisoned session secret lookup");
        let lookup_client_err = manager
            .lookup_session(&client_public_key, None)
            .expect_err("poisoned session client lookup");

        for err in [
            get_err,
            list_err,
            audit_list_err,
            audit_for_connection_err,
            workflow_list_err,
            workflow_get_err,
            find_secret_err,
            find_client_err,
            lookup_secret_err,
            lookup_client_err,
        ] {
            assert!(err.to_string().contains("signer state lock poisoned"));
        }
    }

    #[test]
    fn evaluate_connect_request_reports_poisoned_state_lock() {
        let store = Arc::new(RadrootsNostrMemorySignerStore::new());
        let signer_identity = public_identity(0x57);
        let state = RadrootsNostrSignerStoreState {
            signer_identity: Some(signer_identity.clone()),
            ..Default::default()
        };
        store.save(&state).expect("save state");

        let manager = RadrootsNostrSignerManager::new(store).expect("manager");
        poison_manager_state(&manager);

        let err = manager
            .evaluate_connect_request(
                public_key(0x58),
                Request::Connect {
                    remote_signer_public_key: signer_identity.public_key(),
                    secret: Some("secret".into()),
                    requested_permissions: Permissions::default(),
                    client_metadata: None,
                },
            )
            .expect_err("poisoned connect evaluation");
        assert!(err.to_string().contains("signer state lock poisoned"));
    }

    #[test]
    fn mutation_helpers_report_poisoned_state_lock() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        poison_manager_state(&manager);

        let signer_identity = public_identity(0x48);
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-2").expect("id");
        let workflow_id = RadrootsNostrSignerWorkflowId::parse("wf-2").expect("id");
        let connect_draft =
            RadrootsNostrSignerConnectionDraft::new(public_key(0x49), public_identity(0x50));

        let set_signer_err = manager
            .set_signer_identity(signer_identity)
            .expect_err("poisoned set signer");
        let register_err = manager
            .register_connection(connect_draft)
            .expect_err("poisoned register");
        let grants_err = manager
            .set_granted_permissions(&connection_id, vec![permission(Method::Ping, None)].into())
            .expect_err("poisoned set grants");
        let approve_err = manager
            .approve_connection(&connection_id, Permissions::default())
            .expect_err("poisoned approve");
        let reject_err = manager
            .reject_connection(&connection_id, Some("reason".into()))
            .expect_err("poisoned reject");
        let revoke_err = manager
            .revoke_connection(&connection_id, Some("reason".into()))
            .expect_err("poisoned revoke");
        let update_relays_err = manager
            .update_relays(&connection_id, vec![primary_relay()])
            .expect_err("poisoned relays");
        let require_auth_err = manager
            .require_auth_challenge(&connection_id, api_primary_https())
            .expect_err("poisoned require auth");
        let set_pending_request_err = manager
            .set_pending_request(&connection_id, request_message("req-2"))
            .expect_err("poisoned set pending request");
        let authorize_auth_err = manager
            .authorize_auth_challenge(&connection_id)
            .expect_err("poisoned authorize auth");
        let begin_connect_workflow_err = manager
            .begin_connect_secret_publish_finalization(&connection_id)
            .expect_err("poisoned connect workflow");
        let begin_auth_workflow_err = manager
            .begin_auth_replay_publish_finalization(&connection_id)
            .expect_err("poisoned auth workflow");
        let mark_workflow_err = manager
            .mark_publish_workflow_published(&workflow_id)
            .expect_err("poisoned mark workflow");
        let finalize_workflow_err = manager
            .finalize_publish_workflow(&workflow_id)
            .expect_err("poisoned finalize workflow");
        let cancel_workflow_err = manager
            .cancel_publish_workflow(&workflow_id)
            .expect_err("poisoned cancel workflow");
        let auth_err = manager
            .mark_authenticated(&connection_id)
            .expect_err("poisoned auth");
        let request_err = manager
            .record_request(
                &connection_id,
                "req-1",
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Allowed,
                None,
            )
            .expect_err("poisoned request");

        for err in [
            set_signer_err,
            register_err,
            grants_err,
            approve_err,
            reject_err,
            revoke_err,
            update_relays_err,
            require_auth_err,
            set_pending_request_err,
            authorize_auth_err,
            begin_connect_workflow_err,
            begin_auth_workflow_err,
            mark_workflow_err,
            finalize_workflow_err,
            cancel_workflow_err,
            auth_err,
            request_err,
        ] {
            assert!(err.to_string().contains("signer state lock poisoned"));
        }
    }

    #[test]
    fn save_error_store_reports_poisoned_load_lock() {
        let store = SaveErrorStore::new(RadrootsNostrSignerStoreState::default());
        let shared = Arc::new(store);
        let poison = shared.clone();
        let _ = thread::spawn(move || {
            let _guard = poison.state.write().expect("write");
            panic!("poison save error store");
        })
        .join();

        let err = shared.load().expect_err("poisoned load");
        assert!(err.to_string().contains("save error store poisoned"));
    }

    #[test]
    fn helpers_cover_status_labels_and_consumed_secret_reuse_rules() {
        assert_eq!(
            status_label(RadrootsNostrSignerConnectionStatus::Pending),
            "pending"
        );
        assert_eq!(
            status_label(RadrootsNostrSignerConnectionStatus::Active),
            "active"
        );
        assert_eq!(
            status_label(RadrootsNostrSignerConnectionStatus::Rejected),
            "rejected"
        );
        assert_eq!(
            status_label(RadrootsNostrSignerConnectionStatus::Revoked),
            "revoked"
        );

        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x42))
            .expect("set signer");

        let initial = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x43), public_identity(0x44))
                    .with_connect_secret("reusable-secret")
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register initial");
        manager
            .reject_connection(&initial.connection_id, Some("closed".into()))
            .expect("reject initial");

        let reused = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x45), public_identity(0x46))
                    .with_connect_secret("reusable-secret"),
            )
            .expect("register reused secret");

        assert!(
            reused
                .connect_secret_hash
                .as_ref()
                .expect("connect secret hash")
                .matches_secret("reusable-secret")
        );

        let consumed = manager
            .mark_connect_secret_consumed(&reused.connection_id)
            .expect("consume secret");
        assert!(consumed.connect_secret_is_consumed());
        manager
            .reject_connection(&reused.connection_id, Some("closed".into()))
            .expect("reject consumed");

        let blocked_reuse = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x47), public_identity(0x48))
                    .with_connect_secret("reusable-secret"),
            )
            .expect_err("block consumed secret reuse");
        assert!(matches!(
            blocked_reuse,
            RadrootsNostrSignerError::ConnectSecretAlreadyInUse
        ));
    }

    #[test]
    fn session_lookup_and_connect_evaluation_cover_new_paths() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        let signer_identity = public_identity(0x60);
        let signer_public_key =
            PublicKey::from_hex(&signer_identity.public_key().to_hex()).expect("signer public key");
        manager
            .set_signer_identity(signer_identity)
            .expect("set signer");

        let client_public_key = public_key(0x61);
        let primary = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(client_public_key, public_identity(0x62))
                    .with_connect_secret("connect-secret"),
            )
            .expect("register primary");

        let single_lookup = manager
            .lookup_session(&client_public_key, None)
            .expect("lookup single");
        assert_same_connection(&expect_connection_lookup(single_lookup), &primary);

        let secret_lookup = manager
            .lookup_session(&client_public_key, Some("connect-secret"))
            .expect("lookup by secret");
        assert_same_connection(&expect_connection_lookup(secret_lookup), &primary);
        let missing_secret_lookup = manager
            .lookup_session(&client_public_key, Some("missing-secret"))
            .expect("lookup missing secret");
        assert_same_connection(&expect_connection_lookup(missing_secret_lookup), &primary);

        let second = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(client_public_key, public_identity(0x63))
                    .with_connect_secret("second-secret"),
            )
            .expect("register second");

        let ambiguous_by_missing_secret = manager
            .lookup_session(&client_public_key, Some("missing-secret"))
            .expect("lookup missing secret after second");
        let found = expect_ambiguous_lookup(ambiguous_by_missing_secret);
        assert_eq!(found.len(), 2);
        assert_same_connection(&found[0], &primary);
        assert_same_connection(&found[1], &second);
        let ambiguous_lookup = manager
            .lookup_session(&client_public_key, None)
            .expect("lookup ambiguous");
        let found = expect_ambiguous_lookup(ambiguous_lookup);
        assert_eq!(found.len(), 2);
        assert_same_connection(&found[0], &primary);
        assert_same_connection(&found[1], &second);

        let mismatch_secret = manager
            .lookup_session(&public_key(0x64), Some("connect-secret"))
            .expect_err("secret mismatch");
        assert!(
            mismatch_secret
                .to_string()
                .contains("different client public key")
        );

        let none_lookup = manager
            .lookup_session(&public_key(0x65), None)
            .expect("lookup none");
        expect_none_lookup(none_lookup);

        let non_connect_err = manager
            .evaluate_connect_request(client_public_key, Request::Ping)
            .expect_err("non-connect evaluation");
        assert!(
            non_connect_err
                .to_string()
                .contains("connect evaluation requires a connect request")
        );

        let missing_signer_err = RadrootsNostrSignerManager::new_in_memory()
            .evaluate_connect_request(
                client_public_key,
                Request::Connect {
                    remote_signer_public_key: connect_public_key(signer_public_key),
                    secret: None,
                    requested_permissions: Permissions::default(),
                    client_metadata: None,
                },
            )
            .expect_err("missing signer");
        assert_eq!(missing_signer_err.to_string(), "missing signer identity");

        let signer_mismatch_err = manager
            .evaluate_connect_request(
                client_public_key,
                Request::Connect {
                    remote_signer_public_key: connect_public_key(public_key(0x66)),
                    secret: None,
                    requested_permissions: Permissions::default(),
                    client_metadata: None,
                },
            )
            .expect_err("signer mismatch");
        assert!(
            signer_mismatch_err
                .to_string()
                .contains("remote signer public key mismatch")
        );

        let existing_connect = manager
            .evaluate_connect_request(
                client_public_key,
                Request::Connect {
                    remote_signer_public_key: connect_public_key(signer_public_key),
                    secret: Some(" connect-secret ".into()),
                    requested_permissions: vec![
                        permission(Method::Ping, None),
                        permission(Method::Ping, None),
                    ]
                    .into(),
                    client_metadata: None,
                },
            )
            .expect("existing connect request");
        assert_same_connection(&expect_existing_connect(existing_connect), &primary);

        let registration_connect = manager
            .evaluate_connect_request(
                public_key(0x67),
                Request::Connect {
                    remote_signer_public_key: connect_public_key(signer_public_key),
                    secret: Some(" fresh-secret ".into()),
                    requested_permissions: vec![
                        permission(Method::Ping, None),
                        permission(Method::SignEvent, Some("kind:1")),
                        permission(Method::Ping, None),
                    ]
                    .into(),
                    client_metadata: Some(ClientMetadata {
                        requested_permissions: vec![permission(Method::Nip44Encrypt, None)].into(),
                        name: Some(" Example Client ".into()),
                        url: Some("https://client.example.com".into()),
                        image: None,
                    }),
                },
            )
            .expect("registration connect request");
        let proposal = expect_registration_connect(registration_connect);
        assert_eq!(proposal.client_public_key, public_key(0x67));
        assert_eq!(proposal.connect_secret.as_deref(), Some("fresh-secret"));
        let metadata = proposal.client_metadata.as_ref().expect("client metadata");
        assert_eq!(metadata.name.as_deref(), Some("Example Client"));
        assert_eq!(metadata.url.as_deref(), Some("https://client.example.com/"));
        assert!(metadata.requested_permissions.is_empty());
        assert_eq!(
            proposal.requested_permissions.as_slice(),
            &[
                permission(Method::Ping, None),
                permission(Method::SignEvent, Some("kind:1")),
            ]
        );

        let existing_secret_mismatch = manager
            .evaluate_connect_request(
                public_key(0x68),
                Request::Connect {
                    remote_signer_public_key: connect_public_key(signer_public_key),
                    secret: Some("connect-secret".into()),
                    requested_permissions: Permissions::default(),
                    client_metadata: None,
                },
            )
            .expect_err("existing secret mismatch");
        assert!(
            existing_secret_mismatch
                .to_string()
                .contains("different client public key")
        );
    }

    #[test]
    fn evaluate_request_covers_allowed_denied_and_challenged_paths() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x71))
            .expect("set signer");

        let active = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x72), public_identity(0x73))
                    .with_requested_permissions(
                        vec![permission(Method::SignEvent, Some("kind:1"))].into(),
                    ),
            )
            .expect("register active");

        let get_public_key = manager
            .evaluate_request(
                &active.connection_id,
                request_message_with_request("req-get", Request::GetPublicKey),
            )
            .expect("evaluate get_public_key");
        expect_allowed_user_public_key(&get_public_key.action);
        assert_eq!(
            get_public_key.audit.decision,
            RadrootsNostrSignerRequestDecision::Allowed
        );
        assert!(get_public_key.denied_reason().is_none());

        let allowed_sign = manager
            .evaluate_request(
                &active.connection_id,
                request_message_with_request("req-sign-1", Request::SignEvent(unsigned_event(1))),
            )
            .expect("evaluate sign allowed");
        expect_allowed_without_response_hint(&allowed_sign.action);

        let denied_sign = manager
            .evaluate_request(
                &active.connection_id,
                request_message_with_request("req-sign-2", Request::SignEvent(unsigned_event(2))),
            )
            .expect("evaluate sign denied");
        assert_eq!(denied_sign.denied_reason(), Some("unauthorized sign_event"));
        assert_eq!(
            denied_sign.audit.decision,
            RadrootsNostrSignerRequestDecision::Denied
        );

        let pending = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(public_key(0x74), public_identity(0x75))
                    .with_approval_requirement(
                        RadrootsNostrSignerApprovalRequirement::ExplicitUser,
                    ),
            )
            .expect("register pending");
        let pending_eval = manager
            .evaluate_request(&pending.connection_id, request_message("req-pending"))
            .expect("evaluate pending");
        assert_eq!(pending_eval.denied_reason(), Some("connection is pending"));

        let challenged = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x76),
                public_identity(0x77),
            ))
            .expect("register challenged");
        manager
            .require_auth_challenge(&challenged.connection_id, api_primary_https())
            .expect("require auth challenge");
        let challenged_eval = manager
            .evaluate_request(&challenged.connection_id, request_message("req-auth"))
            .expect("evaluate challenged");
        expect_challenged_action(&challenged_eval.action);
        assert_eq!(
            challenged_eval.audit.decision,
            RadrootsNostrSignerRequestDecision::Challenged
        );
        assert_eq!(
            challenged_eval
                .connection
                .pending_request
                .as_ref()
                .expect("pending request")
                .request_id()
                .as_str(),
            "req-auth"
        );

        let rejected = manager
            .reject_connection(&challenged.connection_id, Some("closed".into()))
            .expect("reject challenged");
        let rejected_eval = manager
            .evaluate_request(&rejected.connection_id, request_message("req-rejected"))
            .expect("evaluate rejected");
        assert_eq!(
            rejected_eval.denied_reason(),
            Some("connection is rejected")
        );

        let connect_eval_err = manager
            .evaluate_request(
                &active.connection_id,
                request_message_with_request(
                    "req-connect",
                    Request::Connect {
                        remote_signer_public_key: connect_public_key(active.client_public_key),
                        secret: None,
                        requested_permissions: Permissions::default(),
                        client_metadata: None,
                    },
                ),
            )
            .expect_err("connect through evaluate_request");
        assert!(
            connect_eval_err
                .to_string()
                .contains("evaluate_connect_request")
        );
    }

    #[test]
    fn evaluate_request_reports_invalid_corrupted_auth_state() {
        let store = Arc::new(RadrootsNostrMemorySignerStore::new());
        let signer_identity = public_identity(0x78);
        let mut state = RadrootsNostrSignerStoreState {
            signer_identity: Some(signer_identity.clone()),
            ..Default::default()
        };
        let mut record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            signer_identity,
            RadrootsNostrSignerConnectionDraft::new(public_key(0x79), public_identity(0x80)),
            1,
        );
        record.auth_state = RadrootsNostrSignerAuthState::Pending;
        record.auth_challenge = None;
        state.connections.push(record.clone());
        store.save(&state).expect("save corrupted auth state");

        let manager = RadrootsNostrSignerManager::new(store).expect("manager");
        let err = manager
            .evaluate_request(&record.connection_id, request_message("req-corrupt"))
            .expect_err("corrupted auth evaluation");
        assert!(err.to_string().contains("auth challenge missing"));
    }

    #[test]
    fn evaluate_request_reports_invalid_request_id_and_missing_connection() {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(public_identity(0x81))
            .expect("set signer");

        let active = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                public_key(0x82),
                public_identity(0x83),
            ))
            .expect("register active");

        let invalid_request_id = manager
            .evaluate_request(
                &active.connection_id,
                request_message_with_request("   ", Request::Ping),
            )
            .expect_err("invalid request id");
        assert!(
            invalid_request_id
                .to_string()
                .contains("invalid request id")
        );

        let missing_connection = manager
            .evaluate_request(
                &RadrootsNostrSignerConnectionId::new_v7(),
                request_message("req-missing"),
            )
            .expect_err("missing connection");
        assert!(
            missing_connection
                .to_string()
                .contains("connection not found")
        );
    }

    #[test]
    fn evaluate_request_action_reports_pending_request_and_response_hint_errors() {
        let mut pending_record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            public_identity(0x84),
            RadrootsNostrSignerConnectionDraft::new(public_key(0x85), public_identity(0x86)),
            1,
        );
        pending_record.status = RadrootsNostrSignerConnectionStatus::Active;
        pending_record.auth_state = RadrootsNostrSignerAuthState::Pending;
        pending_record.auth_challenge =
            Some(RadrootsNostrSignerAuthChallenge::new(api_primary_https(), 1).expect("challenge"));
        let invalid_pending = evaluate_request_action(
            &mut pending_record,
            &request_message_with_request("   ", Request::Ping),
            1,
        )
        .expect_err("invalid pending request");
        assert!(invalid_pending.to_string().contains("invalid request id"));
    }
}
