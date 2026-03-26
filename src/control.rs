use std::str::FromStr;

use radroots_nostr_connect::prelude::{
    RadrootsNostrConnectPermission, RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
    RadrootsNostrConnectResponse, RadrootsNostrConnectUri,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerRequestId,
    RadrootsNostrSignerWorkflowId,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::error::MycError;
use crate::outbox::{MycDeliveryOutboxKind, MycDeliveryOutboxRecord};
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
    let manager = runtime.signer_manager()?;
    let connection = manager.get_connection(connection_id)?.ok_or_else(|| {
        MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
    })?;
    runtime
        .signer_context()
        .policy()
        .ensure_authorize_auth_challenge_allowed(&connection)?;
    let workflow = manager.begin_auth_replay_publish_finalization(connection_id)?;
    let replayed_request_id =
        replay_authorized_request(runtime, &connection.connection_id, &workflow.workflow_id)
            .await?;
    let connection = runtime
        .signer_manager()?
        .get_connection(connection_id)?
        .ok_or_else(|| {
            MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
        })?;
    Ok(MycAuthorizedReplayOutput {
        connection,
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
    let Some(approval_requirement) = runtime
        .signer_context()
        .policy()
        .approval_requirement_for_client(&client_uri.client_public_key)
    else {
        return Err(MycError::InvalidOperation(
            "client public key denied by policy".to_owned(),
        ));
    };
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
            if runtime
                .signer_context()
                .policy()
                .approval_requirement_for_client(&connection.client_public_key)
                .is_none()
            {
                return Err(MycError::InvalidOperation(
                    "client public key denied by policy".to_owned(),
                ));
            }
            connection
        }
        radroots_nostr_signer::prelude::RadrootsNostrSignerConnectEvaluation::RegistrationRequired(
            proposal,
        ) => {
            let requested_permissions = runtime
                .signer_context()
                .policy()
                .filtered_requested_permissions(&proposal.requested_permissions);
            let draft = proposal
                .into_connection_draft(runtime.user_public_identity())
                .with_requested_permissions(requested_permissions)
                .with_relays(preferred_relays.clone())
                .with_approval_requirement(approval_requirement);
            let connection = manager.register_connection(draft)?;
            if approval_requirement
                == RadrootsNostrSignerApprovalRequirement::NotRequired
            {
                let granted_permissions = runtime
                    .signer_context()
                    .policy()
                    .auto_granted_permissions(&connection.requested_permissions);
                let _ = manager.set_granted_permissions(
                    &connection.connection_id,
                    granted_permissions,
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
    let workflow = manager.begin_connect_secret_publish_finalization(&connection.connection_id)?;
    let event = match runtime
        .signer_identity()
        .sign_event_builder(event, "connect accept response")
    {
        Ok(event) => event,
        Err(error) => {
            return Err(cancel_connect_accept_workflow_on_error(
                runtime,
                &workflow.workflow_id,
                MycError::InvalidOperation(format!(
                    "failed to sign connect accept response event: {error}"
                )),
            ));
        }
    };
    let outbox_record = match build_control_outbox_record(
        MycDeliveryOutboxKind::ConnectAcceptPublish,
        event.clone(),
        &response_relays,
        Some(&connection.connection_id),
        Some(response_request_id.as_str()),
        Some(&workflow.workflow_id),
    ) {
        Ok(record) => record,
        Err(error) => {
            return Err(cancel_connect_accept_workflow_on_error(
                runtime,
                &workflow.workflow_id,
                error,
            ));
        }
    };
    if let Err(error) = runtime.delivery_outbox_store().enqueue(&outbox_record) {
        return Err(cancel_connect_accept_workflow_on_error(
            runtime,
            &workflow.workflow_id,
            error,
        ));
    }
    let publish_outcome = match MycNostrTransport::publish_event_once(
        runtime.signer_identity(),
        &response_relays,
        &runtime.config().transport,
        "connect accept response publish",
        &event,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let error = mark_outbox_publish_failed(runtime, &outbox_record, error);
            runtime.record_operation_audit(&record_publish_failure(
                MycOperationAuditKind::ConnectAcceptPublish,
                Some(&connection.connection_id),
                Some(response_request_id.as_str()),
                response_relays.len(),
                &error,
            ));
            return Err(cancel_connect_accept_workflow_on_error(
                runtime,
                &workflow.workflow_id,
                error,
            ));
        }
    };
    if let Err(error) = manager.mark_publish_workflow_published(&workflow.workflow_id) {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::ConnectAcceptPublish,
            Some(&connection.connection_id),
            Some(response_request_id.as_str()),
            &publish_outcome,
            format!("failed to mark connect-accept publish workflow as published: {error}"),
        );
        return Err(error.into());
    }
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_published_pending_finalize(&outbox_record.job_id, publish_outcome.attempt_count)
    {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::ConnectAcceptPublish,
            Some(&connection.connection_id),
            Some(response_request_id.as_str()),
            &publish_outcome,
            format!("failed to persist connect-accept outbox published state: {error}"),
        );
        return Err(error);
    }
    if let Err(error) = manager.finalize_publish_workflow(&workflow.workflow_id) {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::ConnectAcceptPublish,
            Some(&connection.connection_id),
            Some(response_request_id.as_str()),
            &publish_outcome,
            format!("failed to finalize connect-accept publish workflow: {error}"),
        );
        return Err(error.into());
    }
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_finalized(&outbox_record.job_id)
    {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::ConnectAcceptPublish,
            Some(&connection.connection_id),
            Some(response_request_id.as_str()),
            &publish_outcome,
            format!("failed to finalize connect-accept outbox job: {error}"),
        );
        return Err(error);
    }
    record_publish_audit(
        runtime,
        MycOperationAuditKind::ConnectAcceptPublish,
        MycOperationAuditOutcome::Succeeded,
        Some(&connection.connection_id),
        Some(response_request_id.as_str()),
        &publish_outcome,
    );

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
    connection_id: &RadrootsNostrSignerConnectionId,
    workflow_id: &RadrootsNostrSignerWorkflowId,
) -> Result<Option<String>, MycError> {
    let manager = runtime.signer_manager()?;
    let workflow = manager.get_publish_workflow(workflow_id)?.ok_or_else(|| {
        MycError::InvalidOperation(format!("publish workflow `{workflow_id}` was not found"))
    })?;
    let Some(pending_request) = workflow.pending_request.clone() else {
        return Ok(None);
    };
    let transport = match runtime.transport() {
        Some(transport) => transport,
        None => {
            let error = MycError::InvalidOperation(
                "transport.enabled must be true to replay authorized requests".to_owned(),
            );
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error,
            ));
        }
    };
    let handler = MycNip46Handler::new(runtime.signer_context(), transport.relays().to_vec());
    let evaluation = match manager.evaluate_auth_replay_publish_workflow(workflow_id) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error.into(),
            ));
        }
    };
    let handled_request = match handler
        .handle_authorized_request_evaluation(pending_request.request_message.clone(), evaluation)
    {
        Ok(handled_request) => handled_request,
        Err(error) => {
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error,
            ));
        }
    };
    let Some((response, _, consume_connect_secret_for)) = handled_request.into_publish_parts()
    else {
        let error = MycError::InvalidOperation(
            "authorized auth replay did not produce a response".to_owned(),
        );
        return Err(cancel_auth_replay_workflow_on_error(
            runtime,
            connection_id,
            workflow_id,
            Some(&pending_request.request_message.id),
            error,
        ));
    };
    if consume_connect_secret_for.is_some() {
        return Err(cancel_auth_replay_workflow_on_error(
            runtime,
            connection_id,
            workflow_id,
            Some(&pending_request.request_message.id),
            MycError::InvalidOperation(
                "auth replay unexpectedly requested connect-secret finalization".to_owned(),
            ),
        ));
    }
    let event = match handler.build_response_event(
        manager
            .get_connection(connection_id)?
            .ok_or_else(|| {
                MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
            })?
            .client_public_key,
        pending_request.request_message.id.clone(),
        response,
    ) {
        Ok(event) => event,
        Err(error) => {
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error,
            ));
        }
    };
    let connection = manager.get_connection(connection_id)?.ok_or_else(|| {
        MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
    })?;
    let event = match runtime
        .signer_identity()
        .sign_event_builder(event, "authorized auth replay response")
    {
        Ok(event) => event,
        Err(error) => {
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                MycError::InvalidOperation(format!(
                    "failed to sign authorized auth replay response event: {error}"
                )),
            ));
        }
    };
    let publish_relays = if connection.relays.is_empty() {
        transport.relays().to_vec()
    } else {
        connection.relays.clone()
    };
    let outbox_record = match build_control_outbox_record(
        MycDeliveryOutboxKind::AuthReplayPublish,
        event.clone(),
        &publish_relays,
        Some(connection_id),
        Some(&pending_request.request_message.id),
        Some(workflow_id),
    ) {
        Ok(record) => record,
        Err(error) => {
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error,
            ));
        }
    };
    if let Err(error) = runtime.delivery_outbox_store().enqueue(&outbox_record) {
        return Err(cancel_auth_replay_workflow_on_error(
            runtime,
            connection_id,
            workflow_id,
            Some(&pending_request.request_message.id),
            error,
        ));
    }
    let publish_outcome = match MycNostrTransport::publish_event_once(
        runtime.signer_identity(),
        &publish_relays,
        &runtime.config().transport,
        "authorized auth replay publish",
        &event,
    )
    .await
    {
        Ok(publish_outcome) => publish_outcome,
        Err(error) => {
            let error = mark_outbox_publish_failed(runtime, &outbox_record, error);
            runtime.record_operation_audit(&record_publish_failure(
                MycOperationAuditKind::AuthReplayPublish,
                Some(connection_id),
                Some(pending_request.request_message.id.as_str()),
                publish_relays.len(),
                &error,
            ));
            return Err(cancel_auth_replay_workflow_on_error(
                runtime,
                connection_id,
                workflow_id,
                Some(&pending_request.request_message.id),
                error,
            ));
        }
    };
    if let Err(error) = manager.mark_publish_workflow_published(workflow_id) {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::AuthReplayPublish,
            Some(connection_id),
            Some(pending_request.request_message.id.as_str()),
            &publish_outcome,
            format!("failed to mark auth replay publish workflow as published: {error}"),
        );
        return Err(error.into());
    }
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_published_pending_finalize(&outbox_record.job_id, publish_outcome.attempt_count)
    {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::AuthReplayPublish,
            Some(connection_id),
            Some(pending_request.request_message.id.as_str()),
            &publish_outcome,
            format!("failed to persist auth replay outbox published state: {error}"),
        );
        return Err(error);
    }
    if let Err(error) = manager.finalize_publish_workflow(workflow_id) {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::AuthReplayPublish,
            Some(connection_id),
            Some(pending_request.request_message.id.as_str()),
            &publish_outcome,
            format!("failed to finalize auth replay publish workflow: {error}"),
        );
        return Err(error.into());
    }
    if let Err(error) = runtime
        .delivery_outbox_store()
        .mark_finalized(&outbox_record.job_id)
    {
        record_post_publish_failure(
            runtime,
            MycOperationAuditKind::AuthReplayPublish,
            Some(connection_id),
            Some(pending_request.request_message.id.as_str()),
            &publish_outcome,
            format!("failed to finalize auth replay outbox job: {error}"),
        );
        return Err(error);
    }
    record_publish_audit(
        runtime,
        MycOperationAuditKind::AuthReplayPublish,
        MycOperationAuditOutcome::Succeeded,
        Some(connection_id),
        Some(pending_request.request_message.id.as_str()),
        &publish_outcome,
    );
    Ok(Some(pending_request.request_message.id.clone()))
}

fn cancel_auth_replay_workflow_on_error(
    runtime: &MycRuntime,
    connection_id: &RadrootsNostrSignerConnectionId,
    workflow_id: &RadrootsNostrSignerWorkflowId,
    request_id: Option<&str>,
    error: MycError,
) -> MycError {
    let summary = publish_failure_summary(&error);
    match runtime.signer_manager().and_then(|manager| {
        manager
            .cancel_publish_workflow(workflow_id)
            .map_err(Into::into)
    }) {
        Ok(_) => {
            let mut record = MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayRestore,
                MycOperationAuditOutcome::Restored,
                Some(connection_id),
                request_id,
                error
                    .publish_rejection_counts()
                    .map(|(relay_count, _)| relay_count)
                    .unwrap_or_default(),
                error
                    .publish_rejection_counts()
                    .map(|(_, acknowledged)| acknowledged)
                    .unwrap_or_default(),
                format!("preserved pending auth challenge after replay failure: {summary}"),
            );
            if let (
                Some(delivery_policy),
                Some(required_acknowledged_relay_count),
                Some(attempt_count),
            ) = (
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
            runtime.record_operation_audit(&record);
            error
        }
        Err(restore_error) => MycError::InvalidOperation(format!(
            "{error}; additionally failed to cancel auth replay publish workflow: {restore_error}"
        )),
    }
}

fn cancel_connect_accept_workflow_on_error(
    runtime: &MycRuntime,
    workflow_id: &RadrootsNostrSignerWorkflowId,
    error: MycError,
) -> MycError {
    match runtime.signer_manager().and_then(|manager| {
        manager
            .cancel_publish_workflow(workflow_id)
            .map(|_| ())
            .map_err(Into::into)
    }) {
        Ok(()) => error,
        Err(cancel_error) => MycError::InvalidOperation(format!(
            "{error}; additionally failed to cancel connect-accept publish workflow: {cancel_error}"
        )),
    }
}

fn build_control_outbox_record(
    kind: MycDeliveryOutboxKind,
    event: radroots_nostr::prelude::RadrootsNostrEvent,
    relay_urls: &[nostr::RelayUrl],
    connection_id: Option<&RadrootsNostrSignerConnectionId>,
    request_id: Option<&str>,
    workflow_id: Option<&RadrootsNostrSignerWorkflowId>,
) -> Result<MycDeliveryOutboxRecord, MycError> {
    let relay_urls = relay_urls.to_vec();
    let mut record = MycDeliveryOutboxRecord::new(kind, event, relay_urls)?;
    if let Some(connection_id) = connection_id {
        record = record.with_connection_id(connection_id);
    }
    if let Some(request_id) = request_id {
        record = record.with_request_id(request_id.to_owned());
    }
    if let Some(workflow_id) = workflow_id {
        record = record.with_signer_publish_workflow_id(workflow_id);
    }
    Ok(record)
}

fn mark_outbox_publish_failed(
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
            "{error}; additionally failed to persist publish failure to the delivery outbox: {outbox_error}"
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
    runtime.record_operation_audit(
        &MycOperationAuditRecord::new(
            operation,
            outcome,
            connection_id,
            request_id,
            publish_outcome.relay_count,
            publish_outcome.acknowledged_relay_count,
            publish_outcome.relay_outcome_summary.clone(),
        )
        .with_delivery_details(
            publish_outcome.delivery_policy,
            publish_outcome.required_acknowledged_relay_count,
            publish_outcome.attempt_count,
        ),
    );
}

fn record_post_publish_failure(
    runtime: &MycRuntime,
    operation: MycOperationAuditKind,
    connection_id: Option<&RadrootsNostrSignerConnectionId>,
    request_id: Option<&str>,
    publish_outcome: &MycPublishOutcome,
    summary: impl Into<String>,
) {
    runtime.record_operation_audit(
        &MycOperationAuditRecord::new(
            operation,
            MycOperationAuditOutcome::Rejected,
            connection_id,
            request_id,
            publish_outcome.relay_count,
            publish_outcome.acknowledged_relay_count,
            summary.into(),
        )
        .with_delivery_details(
            publish_outcome.delivery_policy,
            publish_outcome.required_acknowledged_relay_count,
            publish_outcome.attempt_count,
        ),
    );
}

fn publish_failure_summary(error: &MycError) -> String {
    error
        .publish_rejection_details()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| error.to_string())
}

fn record_publish_failure(
    operation: MycOperationAuditKind,
    connection_id: Option<&RadrootsNostrSignerConnectionId>,
    request_id: Option<&str>,
    relay_count: usize,
    error: &MycError,
) -> MycOperationAuditRecord {
    let mut record = MycOperationAuditRecord::new(
        operation,
        MycOperationAuditOutcome::Rejected,
        connection_id,
        request_id,
        relay_count,
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
    record
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

#[cfg(test)]
mod tests {
    use super::{accept_client_uri, authorize_auth_challenge};
    use crate::app::MycRuntime;
    use crate::config::{MycConfig, MycConnectionApproval};
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_connect::prelude::{
        RadrootsNostrConnectClientMetadata, RadrootsNostrConnectClientUri, RadrootsNostrConnectUri,
    };
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime_with_config<F>(approval: MycConnectionApproval, configure: F) -> MycRuntime
    where
        F: FnOnce(&mut MycConfig),
    {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(&temp).join("state");
        config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
        config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
        config.policy.connection_approval = approval;
        config.transport.enabled = true;
        config.transport.relays = vec!["ws://127.0.0.1:65500".to_owned()];
        configure(&mut config);
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

    #[tokio::test(flavor = "current_thread")]
    async fn authorize_auth_challenge_rejects_expired_pending_challenge() {
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.auth_pending_ttl_secs = 1;
        });
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionDraft::new(
                    nostr::Keys::generate().public_key(),
                    runtime.user_public_identity(),
                ),
            )
            .expect("register connection");
        manager
            .require_auth_challenge(&connection.connection_id, "https://auth.example")
            .expect("require auth challenge");

        thread::sleep(Duration::from_secs(2));

        let error = authorize_auth_challenge(&runtime, &connection.connection_id)
            .await
            .expect_err("expired auth challenge should be rejected");
        assert!(error.to_string().contains("auth challenge expired"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accept_client_uri_rejects_denied_client_pubkeys() {
        let denied_identity = RadrootsIdentity::from_secret_key_str(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .expect("identity");
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.denied_client_pubkeys = vec![denied_identity.public_key().to_hex()];
        });
        let uri = RadrootsNostrConnectUri::Client(RadrootsNostrConnectClientUri {
            client_public_key: denied_identity.public_key(),
            relays: vec![nostr::RelayUrl::parse("ws://127.0.0.1:65500").expect("relay")],
            secret: "client-secret".to_owned(),
            metadata: RadrootsNostrConnectClientMetadata::default(),
        })
        .to_string();

        let error = accept_client_uri(&runtime, &uri)
            .await
            .expect_err("denied client should be rejected");
        assert!(
            error
                .to_string()
                .contains("client public key denied by policy")
        );
    }
}
