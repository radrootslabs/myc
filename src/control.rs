use std::str::FromStr;

use radroots_nostr_connect::prelude::{
    RadrootsNostrConnectPermission, RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
    RadrootsNostrConnectResponse, RadrootsNostrConnectUri,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthorizationOutcome,
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerPendingRequest, RadrootsNostrSignerRequestId,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::error::MycError;
use crate::transport::{MycNip46Handler, MycNostrTransport, MycPublishOutcome};

#[derive(Debug, Serialize)]
pub struct MycAuthorizedReplayOutput {
    pub connection: RadrootsNostrSignerConnectionRecord,
    pub replayed_request_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MycAcceptedConnectionOutput {
    pub connection: RadrootsNostrSignerConnectionRecord,
    pub response_request_id: String,
    pub response_relays: Vec<String>,
}

pub async fn authorize_auth_challenge(
    runtime: &MycRuntime,
    connection_id: &RadrootsNostrSignerConnectionId,
) -> Result<MycAuthorizedReplayOutput, MycError> {
    let outcome = runtime
        .signer_manager()?
        .authorize_auth_challenge(connection_id)?;
    let replayed_request_id = replay_authorized_request(runtime, &outcome).await?;
    Ok(MycAuthorizedReplayOutput {
        connection: outcome.connection,
        replayed_request_id,
    })
}

pub async fn accept_client_uri(
    runtime: &MycRuntime,
    uri: &str,
) -> Result<MycAcceptedConnectionOutput, MycError> {
    let Some(transport) = runtime.transport() else {
        return Err(MycError::InvalidOperation(
            "transport.enabled must be true to accept client nostrconnect URIs".to_owned(),
        ));
    };
    let preferred_relays = transport.relays().to_vec();
    if preferred_relays.is_empty() {
        return Err(MycError::InvalidOperation(
            "transport.relays must not be empty to accept client nostrconnect URIs".to_owned(),
        ));
    }

    let client_uri = match RadrootsNostrConnectUri::parse(uri)? {
        RadrootsNostrConnectUri::Client(client_uri) => client_uri,
        RadrootsNostrConnectUri::Bunker(_) => {
            return Err(MycError::InvalidOperation(
                "connect accept requires a nostrconnect:// client URI".to_owned(),
            ));
        }
    };

    let request = RadrootsNostrConnectRequest::Connect {
        remote_signer_public_key: runtime.signer_identity().public_key(),
        secret: Some(client_uri.secret.clone()),
        requested_permissions: client_uri.metadata.requested_permissions.clone(),
    };
    let manager = runtime.signer_manager()?;
    let connection = match manager.evaluate_connect_request(client_uri.client_public_key, request)? {
        radroots_nostr_signer::prelude::RadrootsNostrSignerConnectEvaluation::ExistingConnection(
            connection,
        ) => {
            if connection.connect_secret_is_consumed() {
                return Err(MycError::InvalidOperation(
                    "connect secret has already been consumed by a successful connection"
                        .to_owned(),
                ));
            }
            connection
        }
        radroots_nostr_signer::prelude::RadrootsNostrSignerConnectEvaluation::RegistrationRequired(
            proposal,
        ) => {
            let draft = proposal
                .into_connection_draft(runtime.user_public_identity())
                .with_relays(preferred_relays.clone())
                .with_approval_requirement(runtime.signer_context().connection_approval_requirement());
            let connection = manager.register_connection(draft)?;
            if runtime.signer_context().connection_approval_requirement()
                == RadrootsNostrSignerApprovalRequirement::NotRequired
            {
                let _ = manager.set_granted_permissions(
                    &connection.connection_id,
                    connection.requested_permissions.clone(),
                )?;
            }
            connection
        }
    };

    let handler = MycNip46Handler::new(runtime.signer_context(), preferred_relays.clone());
    let response_request_id = RadrootsNostrSignerRequestId::new_v7().into_string();
    let event = handler.build_response_event(
        client_uri.client_public_key,
        response_request_id.clone(),
        RadrootsNostrConnectResponse::ConnectSecretEcho(client_uri.secret),
    )?;
    let response_relays = merge_relays(&client_uri.relays, &preferred_relays);
    let publish_outcome = match MycNostrTransport::publish_once(
        runtime.signer_identity(),
        &response_relays,
        transport.connect_timeout_secs(),
        event,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            runtime.record_operation_audit(&MycOperationAuditRecord::new(
                MycOperationAuditKind::ConnectAcceptPublish,
                MycOperationAuditOutcome::Rejected,
                Some(&connection.connection_id),
                Some(response_request_id.as_str()),
                response_relays.len(),
                error
                    .publish_rejection_counts()
                    .map(|(_, acknowledged)| acknowledged)
                    .unwrap_or_default(),
                publish_failure_summary(&error),
            ));
            return Err(error);
        }
    };
    record_publish_audit(
        runtime,
        MycOperationAuditKind::ConnectAcceptPublish,
        MycOperationAuditOutcome::Succeeded,
        Some(&connection.connection_id),
        Some(response_request_id.as_str()),
        &publish_outcome,
    );
    let _ = manager.mark_connect_secret_consumed(&connection.connection_id)?;

    Ok(MycAcceptedConnectionOutput {
        connection: runtime
            .signer_manager()?
            .list_connections()?
            .into_iter()
            .find(|record| record.connection_id == connection.connection_id)
            .ok_or_else(|| {
                MycError::InvalidOperation("accepted connection was not persisted".to_owned())
            })?,
        response_request_id,
        response_relays: response_relays.iter().map(ToString::to_string).collect(),
    })
}

pub fn parse_permission_values(
    values: &[String],
) -> Result<RadrootsNostrConnectPermissions, MycError> {
    let mut permissions = Vec::new();
    for value in values {
        for fragment in value.split(',') {
            let trimmed = fragment.trim();
            if trimmed.is_empty() {
                continue;
            }
            permissions.push(RadrootsNostrConnectPermission::from_str(trimmed)?);
        }
    }
    permissions.sort();
    permissions.dedup();
    Ok(permissions.into())
}

async fn replay_authorized_request(
    runtime: &MycRuntime,
    outcome: &RadrootsNostrSignerAuthorizationOutcome,
) -> Result<Option<String>, MycError> {
    let Some(pending_request) = outcome.pending_request.clone() else {
        return Ok(None);
    };
    let transport = match runtime.transport() {
        Some(transport) => transport,
        None => {
            let error = MycError::InvalidOperation(
                "transport.enabled must be true to replay authorized requests".to_owned(),
            );
            return Err(restore_pending_auth_challenge_on_error(
                runtime,
                &outcome.connection.connection_id,
                pending_request,
                error,
            ));
        }
    };
    let handler = MycNip46Handler::new(runtime.signer_context(), transport.relays().to_vec());
    let handled_request = match handler.handle_request(
        outcome.connection.client_public_key,
        pending_request.request_message.clone(),
    ) {
        Ok(handled_request) => handled_request,
        Err(error) => {
            return Err(restore_pending_auth_challenge_on_error(
                runtime,
                &outcome.connection.connection_id,
                pending_request,
                error,
            ));
        }
    };
    let Some((response, _, consume_connect_secret_for)) = handled_request.into_publish_parts()
    else {
        let error = MycError::InvalidOperation(
            "authorized auth replay did not produce a response".to_owned(),
        );
        return Err(restore_pending_auth_challenge_on_error(
            runtime,
            &outcome.connection.connection_id,
            pending_request,
            error,
        ));
    };
    let event = match handler.build_response_event(
        outcome.connection.client_public_key,
        pending_request.request_message.id.clone(),
        response,
    ) {
        Ok(event) => event,
        Err(error) => {
            return Err(restore_pending_auth_challenge_on_error(
                runtime,
                &outcome.connection.connection_id,
                pending_request,
                error,
            ));
        }
    };
    let publish_relays = if outcome.connection.relays.is_empty() {
        transport.relays().to_vec()
    } else {
        outcome.connection.relays.clone()
    };
    let publish_outcome = match MycNostrTransport::publish_once(
        runtime.signer_identity(),
        &publish_relays,
        transport.connect_timeout_secs(),
        event,
    )
    .await
    {
        Ok(publish_outcome) => publish_outcome,
        Err(error) => {
            runtime.record_operation_audit(&MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayPublish,
                MycOperationAuditOutcome::Rejected,
                Some(&outcome.connection.connection_id),
                Some(pending_request.request_message.id.as_str()),
                publish_relays.len(),
                error
                    .publish_rejection_counts()
                    .map(|(_, acknowledged)| acknowledged)
                    .unwrap_or_default(),
                publish_failure_summary(&error),
            ));
            return Err(restore_pending_auth_challenge_on_error(
                runtime,
                &outcome.connection.connection_id,
                pending_request,
                error,
            ));
        }
    };
    record_publish_audit(
        runtime,
        MycOperationAuditKind::AuthReplayPublish,
        MycOperationAuditOutcome::Succeeded,
        Some(&outcome.connection.connection_id),
        Some(pending_request.request_message.id.as_str()),
        &publish_outcome,
    );
    if let Some(connection_id) = consume_connect_secret_for {
        runtime
            .signer_manager()?
            .mark_connect_secret_consumed(&connection_id)?;
    }
    Ok(Some(pending_request.request_message.id.clone()))
}

fn restore_pending_auth_challenge_on_error(
    runtime: &MycRuntime,
    connection_id: &RadrootsNostrSignerConnectionId,
    pending_request: RadrootsNostrSignerPendingRequest,
    error: MycError,
) -> MycError {
    let summary = publish_failure_summary(&error);
    let request_id = pending_request.request_message.id.clone();
    match runtime.signer_manager().and_then(|manager| {
        manager
            .restore_pending_auth_challenge(connection_id, pending_request.clone())
            .map_err(Into::into)
    }) {
        Ok(_) => {
            runtime.record_operation_audit(&MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayRestore,
                MycOperationAuditOutcome::Restored,
                Some(connection_id),
                Some(request_id.as_str()),
                error
                    .publish_rejection_counts()
                    .map(|(relay_count, _)| relay_count)
                    .unwrap_or_default(),
                error
                    .publish_rejection_counts()
                    .map(|(_, acknowledged)| acknowledged)
                    .unwrap_or_default(),
                format!("restored pending auth challenge after replay failure: {summary}"),
            ));
            error
        }
        Err(restore_error) => MycError::InvalidOperation(format!(
            "{error}; additionally failed to restore pending auth challenge: {restore_error}"
        )),
    }
}

fn record_publish_audit(
    runtime: &MycRuntime,
    operation: MycOperationAuditKind,
    outcome: MycOperationAuditOutcome,
    connection_id: Option<&RadrootsNostrSignerConnectionId>,
    request_id: Option<&str>,
    publish_outcome: &MycPublishOutcome,
) {
    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        operation,
        outcome,
        connection_id,
        request_id,
        publish_outcome.relay_count,
        publish_outcome.acknowledged_relay_count,
        publish_outcome.relay_outcome_summary.clone(),
    ));
}

fn publish_failure_summary(error: &MycError) -> String {
    error
        .publish_rejection_details()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| error.to_string())
}

fn merge_relays(
    primary: &[nostr::RelayUrl],
    secondary: &[nostr::RelayUrl],
) -> Vec<nostr::RelayUrl> {
    let mut relays = primary.to_vec();
    relays.extend_from_slice(secondary);
    relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relays.dedup_by(|left, right| left.as_str() == right.as_str());
    relays
}
