use nostr::{PublicKey, RelayUrl, UnsignedEvent};
use radroots_identity::RadrootsIdentityPublic;
use radroots_nostr_connect::prelude::{
    RadrootsNostrConnectMethod, RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
    RadrootsNostrConnectRequestMessage,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrLocalSignerAvailability, RadrootsNostrLocalSignerCapability,
    RadrootsNostrRemoteSessionSignerCapability, RadrootsNostrSignerAuthorizationOutcome,
    RadrootsNostrSignerBackend, RadrootsNostrSignerBackendCapabilities,
    RadrootsNostrSignerCapability, RadrootsNostrSignerConnectEvaluation,
    RadrootsNostrSignerConnectionDraft, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerConnectionStatus,
    RadrootsNostrSignerError, RadrootsNostrSignerManager, RadrootsNostrSignerPendingRequest,
    RadrootsNostrSignerPublishTransition, RadrootsNostrSignerPublishWorkflowRecord,
    RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestDecision,
    RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerSessionLookup,
    RadrootsNostrSignerSignOutput, RadrootsNostrSignerWorkflowId,
};

use crate::app::MycSignerContext;
use crate::error::MycError;

#[derive(Clone)]
pub struct MycSignerBackend {
    signer: MycSignerContext,
}

impl MycSignerBackend {
    pub fn new(signer: MycSignerContext) -> Self {
        Self { signer }
    }

    fn manager(&self) -> Result<RadrootsNostrSignerManager, RadrootsNostrSignerError> {
        self.signer
            .load_signer_manager()
            .map_err(convert_runtime_signer_error)
    }

    fn configured_signer_identity(&self) -> RadrootsIdentityPublic {
        self.signer.signer_public_identity()
    }

    fn local_signer_capability(&self) -> RadrootsNostrLocalSignerCapability {
        let public_identity = self.configured_signer_identity();
        RadrootsNostrLocalSignerCapability::new(
            public_identity.id.clone(),
            public_identity,
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        )
    }
}

impl RadrootsNostrSignerBackend for MycSignerBackend {
    fn signer_identity(&self) -> Result<Option<RadrootsIdentityPublic>, RadrootsNostrSignerError> {
        Ok(Some(self.configured_signer_identity()))
    }

    fn set_signer_identity(
        &self,
        signer_identity: RadrootsIdentityPublic,
    ) -> Result<(), RadrootsNostrSignerError> {
        let configured = self.configured_signer_identity();
        if configured.id != signer_identity.id
            || configured.public_key_hex != signer_identity.public_key_hex
            || configured.public_key_npub != signer_identity.public_key_npub
        {
            return Err(RadrootsNostrSignerError::InvalidState(format!(
                "runtime-backed myc signer backend cannot switch signer identity from `{}` to `{}`",
                configured.id, signer_identity.id
            )));
        }
        self.manager()?.set_signer_identity(signer_identity)
    }

    fn capabilities(
        &self,
    ) -> Result<RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerError> {
        let remote_sessions = self
            .manager()?
            .list_connections()?
            .into_iter()
            .filter(|record| record.status == RadrootsNostrSignerConnectionStatus::Active)
            .map(|record| RadrootsNostrRemoteSessionSignerCapability::from(&record))
            .collect();
        Ok(RadrootsNostrSignerBackendCapabilities::new(
            Some(self.local_signer_capability()),
            remote_sessions,
        ))
    }

    fn list_connections(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager()?.list_connections()
    }

    fn get_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager()?.get_connection(connection_id)
    }

    fn list_publish_workflows(
        &self,
    ) -> Result<Vec<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        self.manager()?.list_publish_workflows()
    }

    fn get_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, RadrootsNostrSignerError> {
        self.manager()?.get_publish_workflow(workflow_id)
    }

    fn find_connections_by_client_public_key(
        &self,
        client_public_key: &PublicKey,
    ) -> Result<Vec<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager()?
            .find_connections_by_client_public_key(client_public_key)
    }

    fn find_connection_by_connect_secret(
        &self,
        connect_secret: &str,
    ) -> Result<Option<RadrootsNostrSignerConnectionRecord>, RadrootsNostrSignerError> {
        self.manager()?
            .find_connection_by_connect_secret(connect_secret)
    }

    fn lookup_session(
        &self,
        client_public_key: &PublicKey,
        connect_secret: Option<&str>,
    ) -> Result<RadrootsNostrSignerSessionLookup, RadrootsNostrSignerError> {
        self.manager()?
            .lookup_session(client_public_key, connect_secret)
    }

    fn evaluate_connect_request(
        &self,
        client_public_key: PublicKey,
        request: RadrootsNostrConnectRequest,
    ) -> Result<RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerError> {
        self.manager()?
            .evaluate_connect_request(client_public_key, request)
    }

    fn register_connection(
        &self,
        draft: RadrootsNostrSignerConnectionDraft,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.register_connection(draft)
    }

    fn set_granted_permissions(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: RadrootsNostrConnectPermissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?
            .set_granted_permissions(connection_id, granted_permissions)
    }

    fn approve_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        granted_permissions: RadrootsNostrConnectPermissions,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?
            .approve_connection(connection_id, granted_permissions)
    }

    fn reject_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.reject_connection(connection_id, reason)
    }

    fn revoke_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        reason: Option<String>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.revoke_connection(connection_id, reason)
    }

    fn update_relays(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        relays: Vec<RelayUrl>,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.update_relays(connection_id, relays)
    }

    fn require_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        auth_url: &str,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?
            .require_auth_challenge(connection_id, auth_url)
    }

    fn set_pending_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?
            .set_pending_request(connection_id, request_message)
    }

    fn authorize_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerAuthorizationOutcome, RadrootsNostrSignerError> {
        self.manager()?.authorize_auth_challenge(connection_id)
    }

    fn restore_pending_auth_challenge(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        pending_request: RadrootsNostrSignerPendingRequest,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?
            .restore_pending_auth_challenge(connection_id, pending_request)
    }

    fn begin_connect_secret_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        self.manager()?
            .begin_connect_secret_publish_finalization(connection_id)
            .map(RadrootsNostrSignerPublishTransition::begun)
    }

    fn begin_auth_replay_publish_finalization(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        self.manager()?
            .begin_auth_replay_publish_finalization(connection_id)
            .map(RadrootsNostrSignerPublishTransition::begun)
    }

    fn mark_publish_workflow_published(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        self.manager()?
            .mark_publish_workflow_published(workflow_id)
            .map(RadrootsNostrSignerPublishTransition::marked_published)
    }

    fn finalize_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        let connection = self.manager()?.finalize_publish_workflow(workflow_id)?;
        Ok(RadrootsNostrSignerPublishTransition::finalized(
            workflow_id.clone(),
            connection,
        ))
    }

    fn cancel_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerPublishTransition, RadrootsNostrSignerError> {
        self.manager()?
            .cancel_publish_workflow(workflow_id)
            .map(RadrootsNostrSignerPublishTransition::cancelled)
    }

    fn mark_authenticated(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.mark_authenticated(connection_id)
    }

    fn mark_connect_secret_consumed(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        self.manager()?.mark_connect_secret_consumed(connection_id)
    }

    fn evaluate_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        self.manager()?
            .evaluate_request(connection_id, request_message)
    }

    fn evaluate_auth_replay_publish_workflow(
        &self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Result<RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerError> {
        self.manager()?
            .evaluate_auth_replay_publish_workflow(workflow_id)
    }

    fn record_request(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        request_id: &str,
        method: RadrootsNostrConnectMethod,
        decision: RadrootsNostrSignerRequestDecision,
        message: Option<String>,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerError> {
        self.manager()?
            .record_request(connection_id, request_id, method, decision, message)
    }

    fn sign_unsigned_event(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<RadrootsNostrSignerSignOutput, RadrootsNostrSignerError> {
        let event = self
            .signer
            .signer_identity()
            .sign_unsigned_event(unsigned_event, "myc signer backend event")
            .map_err(|error| RadrootsNostrSignerError::Sign(error.to_string()))?;
        Ok(RadrootsNostrSignerSignOutput::new(
            RadrootsNostrSignerCapability::LocalAccount(self.local_signer_capability()),
            event,
        ))
    }
}

fn convert_runtime_signer_error(error: MycError) -> RadrootsNostrSignerError {
    match error {
        MycError::SignerState(source) => source,
        other => RadrootsNostrSignerError::InvalidState(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nostr::Keys;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_signer::prelude::{
        RadrootsNostrSignerBackend, RadrootsNostrSignerConnectionDraft,
    };

    use crate::app::MycRuntime;
    use crate::config::MycConfig;

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity");
        crate::identity_storage::store_encrypted_identity(path, &identity).expect("save identity");
    }

    fn test_runtime() -> MycRuntime {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(&temp).join("state");
        config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
        config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        MycRuntime::bootstrap(config).expect("runtime")
    }

    #[test]
    fn runtime_backed_backend_projects_local_and_remote_capabilities() {
        let runtime = test_runtime();
        let backend = runtime.signer_backend();

        let initial = backend.capabilities().expect("capabilities");
        assert!(
            initial
                .local_signer
                .expect("local signer capability")
                .is_secret_backed()
        );
        assert!(initial.remote_sessions.is_empty());

        let connection = backend
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                Keys::generate().public_key(),
                runtime.user_public_identity(),
            ))
            .expect("register connection");

        let capabilities = backend.capabilities().expect("capabilities after approval");
        assert_eq!(capabilities.remote_sessions.len(), 1);
        assert_eq!(
            capabilities.remote_sessions[0].connection_id,
            connection.connection_id
        );
    }

    #[test]
    fn runtime_backed_backend_rejects_signer_identity_drift() {
        let runtime = test_runtime();
        let backend = runtime.signer_backend();
        let other_identity = RadrootsIdentity::generate().to_public();

        let error = backend
            .set_signer_identity(other_identity)
            .expect_err("identity drift should be rejected");

        assert!(error.to_string().contains("cannot switch signer identity"));
    }
}
