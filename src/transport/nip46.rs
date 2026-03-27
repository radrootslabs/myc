use std::future::Future;

use radroots_nostr::prelude::{
    RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter, RadrootsNostrKind,
    RadrootsNostrPublicKey, RadrootsNostrRelayPoolNotification, RadrootsNostrRelayUrl,
    RadrootsNostrTag, RadrootsNostrTimestamp, radroots_nostr_filter_tag, radroots_nostr_kind,
};
use radroots_nostr_connect::prelude::{
    RADROOTS_NOSTR_CONNECT_RPC_KIND, RadrootsNostrConnectRequest,
    RadrootsNostrConnectRequestMessage, RadrootsNostrConnectResponse,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerRequestAction,
    RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerRequestResponseHint,
    RadrootsNostrSignerSessionLookup, RadrootsNostrSignerWorkflowId,
};
use tokio::sync::broadcast;

use crate::app::MycSignerContext;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::error::MycError;
use crate::outbox::{MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycDeliveryOutboxStore};
use crate::transport::MycNostrTransport;
use std::sync::Arc;

#[derive(Clone)]
pub struct MycNip46Handler {
    signer: MycSignerContext,
    relays: Vec<RadrootsNostrRelayUrl>,
}

pub struct MycNip46Service {
    handler: MycNip46Handler,
    transport: MycNostrTransport,
    delivery_outbox_store: Arc<dyn MycDeliveryOutboxStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MycNip46HandledRequest {
    Respond {
        response: RadrootsNostrConnectResponse,
        connection_id: Option<RadrootsNostrSignerConnectionId>,
        consume_connect_secret_for: Option<RadrootsNostrSignerConnectionId>,
    },
    Ignore,
}

enum MycPreparedRequestEvaluation {
    Denied(String),
    Evaluation(RadrootsNostrSignerRequestEvaluation),
}

impl MycNip46Handler {
    pub fn new(signer: MycSignerContext, relays: Vec<RadrootsNostrRelayUrl>) -> Self {
        Self { signer, relays }
    }

    pub fn filter(&self) -> Result<RadrootsNostrFilter, MycError> {
        let filter = RadrootsNostrFilter::new()
            .kind(RadrootsNostrKind::Custom(RADROOTS_NOSTR_CONNECT_RPC_KIND))
            .since(RadrootsNostrTimestamp::now());
        radroots_nostr_filter_tag(
            filter,
            "p",
            vec![self.signer.signer_public_identity().public_key_hex],
        )
        .map_err(Into::into)
    }

    pub fn parse_request_event(
        &self,
        event: &RadrootsNostrEvent,
    ) -> Result<RadrootsNostrConnectRequestMessage, MycError> {
        let decrypted = self
            .signer
            .signer_identity()
            .nip44_decrypt(&event.pubkey, &event.content)?;
        serde_json::from_str(&decrypted)
            .map_err(radroots_nostr_connect::prelude::RadrootsNostrConnectError::from)
            .map_err(Into::into)
    }

    pub fn build_response_event(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_id: impl Into<String>,
        response: RadrootsNostrConnectResponse,
    ) -> Result<RadrootsNostrEventBuilder, MycError> {
        let envelope = response.into_envelope(request_id.into())?;
        let payload = serde_json::to_string(&envelope)
            .map_err(|err| MycError::Nip46Encrypt(err.to_string()))?;
        let ciphertext = self
            .signer
            .signer_identity()
            .nip44_encrypt(&client_public_key, payload)?;

        Ok(RadrootsNostrEventBuilder::new(
            radroots_nostr_kind(RADROOTS_NOSTR_CONNECT_RPC_KIND),
            ciphertext,
        )
        .tags(vec![RadrootsNostrTag::public_key(client_public_key)]))
    }

    pub(crate) fn handle_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<MycNip46HandledRequest, MycError> {
        match request_message.request.clone() {
            RadrootsNostrConnectRequest::Connect { secret, .. } => {
                self.handle_connect_request(client_public_key, request_message.request, secret)
            }
            RadrootsNostrConnectRequest::SignEvent(unsigned_event) => {
                self.handle_sign_event_request(client_public_key, request_message, unsigned_event)
            }
            RadrootsNostrConnectRequest::Nip04Encrypt { .. }
            | RadrootsNostrConnectRequest::Nip04Decrypt { .. }
            | RadrootsNostrConnectRequest::Nip44Encrypt { .. }
            | RadrootsNostrConnectRequest::Nip44Decrypt { .. } => {
                self.handle_crypto_request(client_public_key, request_message)
            }
            RadrootsNostrConnectRequest::GetPublicKey
            | RadrootsNostrConnectRequest::Ping
            | RadrootsNostrConnectRequest::SwitchRelays => {
                self.handle_base_request(client_public_key, request_message)
            }
            _ => Ok(MycNip46HandledRequest::respond(
                RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!(
                        "method `{}` is not implemented yet",
                        request_message.request.method()
                    ),
                },
            )),
        }
    }

    #[cfg(test)]
    fn handle_request_response(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        match self.handle_request(client_public_key, request_message)? {
            MycNip46HandledRequest::Respond { response, .. } => Ok(response),
            MycNip46HandledRequest::Ignore => Err(MycError::InvalidOperation(
                "request was ignored without a response".to_owned(),
            )),
        }
    }

    fn handle_connect_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request: RadrootsNostrConnectRequest,
        secret: Option<String>,
    ) -> Result<MycNip46HandledRequest, MycError> {
        let manager = self.signer.load_signer_manager()?;
        let connect_decision = self.signer.policy().connect_decision(&client_public_key);
        if let Some(connect_secret) = secret.as_deref() {
            if let Some(connection) = manager.find_connection_by_connect_secret(connect_secret)? {
                if connection.connect_secret_is_consumed() {
                    tracing::debug!(
                        connection_id = %connection.connection_id,
                        "ignoring reused consumed NIP-46 connect secret"
                    );
                    return Ok(MycNip46HandledRequest::Ignore);
                }
            }
        }
        if !matches!(connect_decision, crate::policy::MycConnectDecision::Deny) {
            if let Some(reason) = self
                .signer
                .policy()
                .connect_rate_limit_denied_reason(&client_public_key)
            {
                return Ok(MycNip46HandledRequest::respond(
                    RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: reason,
                    },
                ));
            }
        }
        let evaluation = manager.evaluate_connect_request(client_public_key, request)?;

        match evaluation {
            RadrootsNostrSignerConnectEvaluation::ExistingConnection(connection) => {
                if secret.is_some() && connection.connect_secret_is_consumed() {
                    tracing::debug!(
                        connection_id = %connection.connection_id,
                        "ignoring reused consumed NIP-46 connect secret"
                    );
                    return Ok(MycNip46HandledRequest::Ignore);
                }
                if matches!(connect_decision, crate::policy::MycConnectDecision::Deny) {
                    return Ok(MycNip46HandledRequest::respond(
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: "client public key denied by policy".to_owned(),
                        },
                    ));
                }
                Ok(connect_response_outcome(&connection, secret))
            }
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => {
                let requested_permissions = self
                    .signer
                    .policy()
                    .filtered_requested_permissions(&proposal.requested_permissions);
                let Some(approval_requirement) = self
                    .signer
                    .policy()
                    .approval_requirement_for_client(&client_public_key)
                else {
                    return Ok(MycNip46HandledRequest::respond(
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: "client public key denied by policy".to_owned(),
                        },
                    ));
                };
                let draft = proposal
                    .into_connection_draft(self.signer.user_public_identity())
                    .with_requested_permissions(requested_permissions)
                    .with_relays(self.relays.clone())
                    .with_approval_requirement(approval_requirement);
                let connection = manager.register_connection(draft)?;
                if approval_requirement
                    == radroots_nostr_signer::prelude::RadrootsNostrSignerApprovalRequirement::NotRequired
                {
                    let granted_permissions = self
                        .signer
                        .policy()
                        .auto_granted_permissions(&connection.requested_permissions);
                    let _ = manager.set_granted_permissions(
                        &connection.connection_id,
                        granted_permissions,
                    )?;
                }
                Ok(connect_response_outcome(&connection, secret))
            }
        }
    }

    fn handle_base_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<MycNip46HandledRequest, MycError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => return Ok(MycNip46HandledRequest::respond(response)),
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            MycPreparedRequestEvaluation::Denied(reason) => {
                Ok(MycNip46HandledRequest::respond_for_connection(
                    Some(connection.connection_id.clone()),
                    RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: reason,
                    },
                ))
            }
            MycPreparedRequestEvaluation::Evaluation(evaluation) => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    ))
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    ))
                }
                RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                    response_from_hint(&evaluation.connection, response_hint).map(|response| {
                        MycNip46HandledRequest::respond_for_connection(
                            Some(evaluation.connection.connection_id.clone()),
                            response,
                        )
                    })
                }
            },
        }
    }

    fn handle_sign_event_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
        unsigned_event: nostr::UnsignedEvent,
    ) -> Result<MycNip46HandledRequest, MycError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => return Ok(MycNip46HandledRequest::respond(response)),
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            MycPreparedRequestEvaluation::Denied(reason) => {
                Ok(MycNip46HandledRequest::respond_for_connection(
                    Some(connection.connection_id.clone()),
                    RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: reason,
                    },
                ))
            }
            MycPreparedRequestEvaluation::Evaluation(evaluation) => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    ))
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    ))
                }
                RadrootsNostrSignerRequestAction::Allowed { .. } => {
                    self.sign_event_response(unsigned_event).map(|response| {
                        MycNip46HandledRequest::respond_for_connection(
                            Some(connection.connection_id.clone()),
                            response,
                        )
                    })
                }
            },
        }
    }

    fn handle_crypto_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<MycNip46HandledRequest, MycError> {
        let request = request_message.request.clone();
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => return Ok(MycNip46HandledRequest::respond(response)),
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            MycPreparedRequestEvaluation::Denied(reason) => {
                Ok(MycNip46HandledRequest::respond_for_connection(
                    Some(connection.connection_id.clone()),
                    RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: reason,
                    },
                ))
            }
            MycPreparedRequestEvaluation::Evaluation(evaluation) => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    ))
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    Ok(MycNip46HandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    ))
                }
                RadrootsNostrSignerRequestAction::Allowed { .. } => {
                    self.crypto_response(request).map(|response| {
                        MycNip46HandledRequest::respond_for_connection(
                            Some(connection.connection_id.clone()),
                            response,
                        )
                    })
                }
            },
        }
    }

    pub(crate) fn handle_authorized_request_evaluation(
        &self,
        request_message: RadrootsNostrConnectRequestMessage,
        evaluation: RadrootsNostrSignerRequestEvaluation,
    ) -> Result<MycNip46HandledRequest, MycError> {
        let connection_id = Some(evaluation.connection.connection_id.clone());
        Ok(match request_message.request.clone() {
            RadrootsNostrConnectRequest::SignEvent(unsigned_event) => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    )
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    )
                }
                RadrootsNostrSignerRequestAction::Allowed { .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        self.sign_event_response(unsigned_event)?,
                    )
                }
            },
            RadrootsNostrConnectRequest::Nip04Encrypt { .. }
            | RadrootsNostrConnectRequest::Nip04Decrypt { .. }
            | RadrootsNostrConnectRequest::Nip44Encrypt { .. }
            | RadrootsNostrConnectRequest::Nip44Decrypt { .. } => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    )
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    )
                }
                RadrootsNostrSignerRequestAction::Allowed { .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        self.crypto_response(request_message.request)?,
                    )
                }
            },
            RadrootsNostrConnectRequest::GetPublicKey
            | RadrootsNostrConnectRequest::Ping
            | RadrootsNostrConnectRequest::SwitchRelays => match evaluation.action {
                RadrootsNostrSignerRequestAction::Denied { reason } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::Error {
                            result: None,
                            error: reason,
                        },
                    )
                }
                RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                    )
                }
                RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                    MycNip46HandledRequest::respond_for_connection(
                        connection_id,
                        response_from_hint(&evaluation.connection, response_hint)?,
                    )
                }
            },
            other => MycNip46HandledRequest::respond_for_connection(
                connection_id,
                RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("method `{}` is not implemented yet", other.method()),
                },
            ),
        })
    }

    fn evaluate_request_with_policy(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<MycPreparedRequestEvaluation, MycError> {
        let manager = self.signer.load_signer_manager()?;
        if let Some(reason) =
            self.signer
                .policy()
                .prepare_request(&manager, connection, &request_message)?
        {
            let reason = self.signer.policy().record_policy_denied_request(
                &manager,
                connection,
                &request_message,
                reason,
            )?;
            return Ok(MycPreparedRequestEvaluation::Denied(reason));
        }

        Ok(MycPreparedRequestEvaluation::Evaluation(
            manager.evaluate_request(&connection.connection_id, request_message)?,
        ))
    }

    fn lookup_connection(
        &self,
        client_public_key: RadrootsNostrPublicKey,
    ) -> Result<Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrConnectResponse>, MycError>
    {
        Ok(
            match self
                .signer
                .load_signer_manager()?
                .lookup_session(&client_public_key, None)?
            {
                RadrootsNostrSignerSessionLookup::Connection(connection) => Ok(connection),
                RadrootsNostrSignerSessionLookup::None => {
                    Err(RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: "unauthorized".to_owned(),
                    })
                }
                RadrootsNostrSignerSessionLookup::Ambiguous(_) => {
                    Err(RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: "ambiguous client sessions".to_owned(),
                    })
                }
            },
        )
    }

    fn sign_event_response(
        &self,
        unsigned_event: nostr::UnsignedEvent,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        let user_public_key = self.signer.user_identity().public_key();
        if unsigned_event.pubkey != user_public_key {
            return Ok(RadrootsNostrConnectResponse::Error {
                result: None,
                error: "sign_event pubkey does not match the managed user identity".to_owned(),
            });
        }

        match self
            .signer
            .user_identity()
            .sign_unsigned_event(unsigned_event, "managed user sign_event")
        {
            Ok(event) => Ok(RadrootsNostrConnectResponse::SignedEvent(event)),
            Err(error) => Ok(RadrootsNostrConnectResponse::Error {
                result: None,
                error: format!("failed to sign event: {error}"),
            }),
        }
    }

    fn crypto_response(
        &self,
        request: RadrootsNostrConnectRequest,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        Ok(match request {
            RadrootsNostrConnectRequest::Nip04Encrypt {
                public_key,
                plaintext,
            } => match self
                .signer
                .user_identity()
                .nip04_encrypt(&public_key, plaintext)
            {
                Ok(ciphertext) => RadrootsNostrConnectResponse::Nip04Encrypt(ciphertext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip04 encrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip04Decrypt {
                public_key,
                ciphertext,
            } => match self
                .signer
                .user_identity()
                .nip04_decrypt(&public_key, ciphertext)
            {
                Ok(plaintext) => RadrootsNostrConnectResponse::Nip04Decrypt(plaintext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip04 decrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip44Encrypt {
                public_key,
                plaintext,
            } => match self
                .signer
                .user_identity()
                .nip44_encrypt(&public_key, plaintext)
            {
                Ok(ciphertext) => RadrootsNostrConnectResponse::Nip44Encrypt(ciphertext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip44 encrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip44Decrypt {
                public_key,
                ciphertext,
            } => match self
                .signer
                .user_identity()
                .nip44_decrypt(&public_key, ciphertext)
            {
                Ok(plaintext) => RadrootsNostrConnectResponse::Nip44Decrypt(plaintext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip44 decrypt failed: {error}"),
                },
            },
            other => RadrootsNostrConnectResponse::Error {
                result: None,
                error: format!("request `{}` is not a crypto method", other.method()),
            },
        })
    }
}

impl MycNip46Service {
    pub fn new(
        signer: MycSignerContext,
        transport: MycNostrTransport,
        delivery_outbox_store: Arc<dyn MycDeliveryOutboxStore>,
    ) -> Self {
        let handler = MycNip46Handler::new(signer, transport.relays().to_vec());
        Self {
            handler,
            transport,
            delivery_outbox_store,
        }
    }

    pub async fn run(&self) -> Result<(), MycError> {
        self.run_until(std::future::pending()).await
    }

    pub async fn run_until<F>(&self, shutdown: F) -> Result<(), MycError>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        self.transport.connect().await?;

        let filter = self.handler.filter()?;
        let mut notifications = self.transport.client().notifications();
        let subscription = self.transport.client().subscribe(filter, None).await?;
        tracing::info!(
            subscription_id = %subscription.val,
            relay_count = self.transport.relays().len(),
            "myc NIP-46 listener subscribed"
        );

        loop {
            let notification = tokio::select! {
                _ = &mut shutdown => return Ok(()),
                notification = notifications.recv() => {
                    match notification {
                        Ok(notification) => notification,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            return Err(MycError::Nip46ListenerClosed);
                        }
                    }
                }
            };
            let RadrootsNostrRelayPoolNotification::Event { event, .. } = notification else {
                continue;
            };
            let event = *event;
            if event.kind != RadrootsNostrKind::Custom(RADROOTS_NOSTR_CONNECT_RPC_KIND) {
                continue;
            }

            let request_message = match self.handler.parse_request_event(&event) {
                Ok(message) => message,
                Err(error) => {
                    tracing::warn!(error = %error, "discarding invalid NIP-46 request event");
                    continue;
                }
            };

            let request_id = request_message.id.clone();
            let handled_request = match self.handler.handle_request(event.pubkey, request_message) {
                Ok(handled_request) => handled_request,
                Err(error) => {
                    tracing::warn!(error = %error, "failed to handle NIP-46 request");
                    MycNip46HandledRequest::respond(RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: error.to_string(),
                    })
                }
            };
            let Some((response, connection_id, consume_connect_secret_for)) =
                handled_request.into_publish_parts()
            else {
                tracing::debug!(
                    request_id = %request_id,
                    client_public_key = %event.pubkey,
                    "ignoring NIP-46 request without response"
                );
                continue;
            };

            let response_event =
                self.handler
                    .build_response_event(event.pubkey, request_id.as_str(), response)?;
            let response_event = match self
                .handler
                .signer
                .signer_identity()
                .sign_event_builder(response_event, "NIP-46 response")
            {
                Ok(event) => event,
                Err(error) => {
                    self.record_listener_publish_local_rejection(
                        connection_id.as_ref(),
                        request_id.as_str(),
                        format!("failed to sign NIP-46 response event: {error}"),
                    );
                    continue;
                }
            };

            let mut workflow_id = None;
            if let Some(connect_connection_id) = consume_connect_secret_for.as_ref() {
                let manager = match self.handler.signer.load_signer_manager() {
                    Ok(manager) => manager,
                    Err(error) => {
                        self.record_listener_publish_local_rejection(
                            connection_id.as_ref(),
                            request_id.as_str(),
                            error.to_string(),
                        );
                        continue;
                    }
                };
                match manager.begin_connect_secret_publish_finalization(connect_connection_id) {
                    Ok(workflow) => workflow_id = Some(workflow.workflow_id),
                    Err(error) => {
                        self.record_listener_publish_local_rejection(
                            connection_id.as_ref(),
                            request_id.as_str(),
                            format!(
                                "failed to begin connect-secret publish finalization workflow: {error}"
                            ),
                        );
                        continue;
                    }
                }
            }

            let outbox_record = match self.build_listener_outbox_record(
                response_event.clone(),
                connection_id.as_ref(),
                request_id.as_str(),
                workflow_id.as_ref(),
            ) {
                Ok(record) => record,
                Err(error) => {
                    let error = self
                        .cancel_listener_publish_workflow_if_needed(workflow_id.as_ref(), error);
                    self.record_listener_publish_local_rejection(
                        connection_id.as_ref(),
                        request_id.as_str(),
                        error.to_string(),
                    );
                    continue;
                }
            };
            if let Err(error) = self.delivery_outbox_store.enqueue(&outbox_record) {
                let error =
                    self.cancel_listener_publish_workflow_if_needed(workflow_id.as_ref(), error);
                self.record_listener_publish_local_rejection(
                    connection_id.as_ref(),
                    request_id.as_str(),
                    error.to_string(),
                );
                continue;
            }
            let publish_outcome = match self
                .transport
                .publish_event("NIP-46 response publish", &response_event)
                .await
            {
                Ok(publish_outcome) => publish_outcome,
                Err(error) => {
                    let mut error = self.record_listener_outbox_failure(&outbox_record, error);
                    error = self
                        .cancel_listener_publish_workflow_if_needed(workflow_id.as_ref(), error);
                    self.record_listener_publish_error(
                        connection_id.as_ref(),
                        request_id.as_str(),
                        &error,
                    );
                    continue;
                }
            };
            if let Some(workflow_id) = workflow_id.as_ref() {
                let manager = match self.handler.signer.load_signer_manager() {
                    Ok(manager) => manager,
                    Err(error) => {
                        self.record_listener_publish_post_publish_failure(
                            connection_id.as_ref(),
                            request_id.as_str(),
                            &publish_outcome,
                            format!(
                                "failed to load signer manager for publish finalization: {error}"
                            ),
                        );
                        continue;
                    }
                };
                if let Err(error) = manager.mark_publish_workflow_published(workflow_id) {
                    self.record_listener_publish_post_publish_failure(
                        connection_id.as_ref(),
                        request_id.as_str(),
                        &publish_outcome,
                        format!("failed to mark signer publish workflow as published: {error}"),
                    );
                    continue;
                }
            }
            if let Err(error) = self.delivery_outbox_store.mark_published_pending_finalize(
                &outbox_record.job_id,
                publish_outcome.attempt_count,
            ) {
                self.record_listener_publish_post_publish_failure(
                    connection_id.as_ref(),
                    request_id.as_str(),
                    &publish_outcome,
                    format!("failed to persist delivery outbox published state: {error}"),
                );
                continue;
            }
            if let Some(workflow_id) = workflow_id.as_ref() {
                let manager = match self.handler.signer.load_signer_manager() {
                    Ok(manager) => manager,
                    Err(error) => {
                        self.record_listener_publish_post_publish_failure(
                            connection_id.as_ref(),
                            request_id.as_str(),
                            &publish_outcome,
                            format!("failed to load signer manager for publish workflow finalization: {error}"),
                        );
                        continue;
                    }
                };
                if let Err(error) = manager.finalize_publish_workflow(workflow_id) {
                    self.record_listener_publish_post_publish_failure(
                        connection_id.as_ref(),
                        request_id.as_str(),
                        &publish_outcome,
                        format!("failed to finalize signer publish workflow: {error}"),
                    );
                    continue;
                }
            }
            if let Err(error) = self
                .delivery_outbox_store
                .mark_finalized(&outbox_record.job_id)
            {
                self.record_listener_publish_post_publish_failure(
                    connection_id.as_ref(),
                    request_id.as_str(),
                    &publish_outcome,
                    format!("failed to finalize delivery outbox job: {error}"),
                );
                continue;
            }
            self.record_listener_publish_success(
                connection_id.as_ref(),
                request_id.as_str(),
                &publish_outcome,
            );
        }
    }

    fn build_listener_outbox_record(
        &self,
        response_event: RadrootsNostrEvent,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: &str,
        workflow_id: Option<&RadrootsNostrSignerWorkflowId>,
    ) -> Result<MycDeliveryOutboxRecord, MycError> {
        let mut record = MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            response_event,
            self.transport.relays().to_vec(),
        )?
        .with_request_id(request_id.to_owned());
        if let Some(connection_id) = connection_id {
            record = record.with_connection_id(connection_id);
        }
        if let Some(workflow_id) = workflow_id {
            record = record.with_signer_publish_workflow_id(workflow_id);
        }
        Ok(record)
    }

    fn cancel_listener_publish_workflow_if_needed(
        &self,
        workflow_id: Option<&RadrootsNostrSignerWorkflowId>,
        error: MycError,
    ) -> MycError {
        let Some(workflow_id) = workflow_id else {
            return error;
        };
        match self
            .handler
            .signer
            .load_signer_manager()
            .and_then(|manager| {
                manager
                    .cancel_publish_workflow(workflow_id)
                    .map(|_| ())
                    .map_err(Into::into)
            }) {
            Ok(()) => error,
            Err(cancel_error) => MycError::InvalidOperation(format!(
                "{error}; additionally failed to cancel listener publish workflow: {cancel_error}"
            )),
        }
    }

    fn record_listener_outbox_failure(
        &self,
        outbox_record: &MycDeliveryOutboxRecord,
        error: MycError,
    ) -> MycError {
        let publish_attempt_count = error.publish_attempt_count().unwrap_or_default();
        let failure_summary = error
            .publish_rejection_details()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| error.to_string());
        match self.delivery_outbox_store.mark_failed(
            &outbox_record.job_id,
            publish_attempt_count,
            &failure_summary,
        ) {
            Ok(_) => error,
            Err(outbox_error) => MycError::InvalidOperation(format!(
                "{error}; additionally failed to persist listener publish failure to the outbox: {outbox_error}"
            )),
        }
    }

    fn record_listener_publish_local_rejection(
        &self,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: &str,
        summary: impl Into<String>,
    ) {
        self.handler
            .signer
            .record_operation_audit(&MycOperationAuditRecord::new(
                MycOperationAuditKind::ListenerResponsePublish,
                MycOperationAuditOutcome::Rejected,
                connection_id,
                Some(request_id),
                self.transport.relays().len(),
                0,
                summary.into(),
            ));
    }

    fn record_listener_publish_error(
        &self,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: &str,
        error: &MycError,
    ) {
        let mut record = MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Rejected,
            connection_id,
            Some(request_id),
            error
                .publish_rejection_counts()
                .map(|(relay_count, _)| relay_count)
                .unwrap_or(self.transport.relays().len()),
            error
                .publish_rejection_counts()
                .map(|(_, acknowledged)| acknowledged)
                .unwrap_or_default(),
            error
                .publish_rejection_details()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| error.to_string()),
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
        self.handler.signer.record_operation_audit(&record);
    }

    fn record_listener_publish_post_publish_failure(
        &self,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: &str,
        publish_outcome: &crate::transport::MycPublishOutcome,
        summary: impl Into<String>,
    ) {
        self.handler.signer.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::ListenerResponsePublish,
                MycOperationAuditOutcome::Rejected,
                connection_id,
                Some(request_id),
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

    fn record_listener_publish_success(
        &self,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: &str,
        publish_outcome: &crate::transport::MycPublishOutcome,
    ) {
        self.handler.signer.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::ListenerResponsePublish,
                MycOperationAuditOutcome::Succeeded,
                connection_id,
                Some(request_id),
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
}

impl MycNip46HandledRequest {
    fn respond(response: RadrootsNostrConnectResponse) -> Self {
        Self::respond_for_connection(None, response)
    }

    fn respond_for_connection(
        connection_id: Option<RadrootsNostrSignerConnectionId>,
        response: RadrootsNostrConnectResponse,
    ) -> Self {
        Self::Respond {
            response,
            connection_id,
            consume_connect_secret_for: None,
        }
    }

    pub(crate) fn into_publish_parts(
        self,
    ) -> Option<(
        RadrootsNostrConnectResponse,
        Option<RadrootsNostrSignerConnectionId>,
        Option<RadrootsNostrSignerConnectionId>,
    )> {
        match self {
            Self::Respond {
                response,
                connection_id,
                consume_connect_secret_for,
            } => Some((response, connection_id, consume_connect_secret_for)),
            Self::Ignore => None,
        }
    }
}

fn connect_response(secret: Option<String>) -> RadrootsNostrConnectResponse {
    match secret {
        Some(secret) => RadrootsNostrConnectResponse::ConnectSecretEcho(secret),
        None => RadrootsNostrConnectResponse::ConnectAcknowledged,
    }
}

fn connect_response_outcome(
    connection: &RadrootsNostrSignerConnectionRecord,
    secret: Option<String>,
) -> MycNip46HandledRequest {
    let consume_connect_secret_for = secret.as_ref().map(|_| connection.connection_id.clone());
    MycNip46HandledRequest::Respond {
        response: connect_response(secret),
        connection_id: Some(connection.connection_id.clone()),
        consume_connect_secret_for,
    }
}

fn response_from_hint(
    connection: &RadrootsNostrSignerConnectionRecord,
    hint: RadrootsNostrSignerRequestResponseHint,
) -> Result<RadrootsNostrConnectResponse, MycError> {
    Ok(match hint {
        RadrootsNostrSignerRequestResponseHint::Pong => RadrootsNostrConnectResponse::Pong,
        RadrootsNostrSignerRequestResponseHint::UserPublicKey(public_key) => {
            RadrootsNostrConnectResponse::UserPublicKey(public_key)
        }
        RadrootsNostrSignerRequestResponseHint::RelayList(relays) => {
            if relays == connection.relays {
                RadrootsNostrConnectResponse::RelayList(relays)
            } else {
                RadrootsNostrConnectResponse::RelayList(connection.relays.clone())
            }
        }
        RadrootsNostrSignerRequestResponseHint::None => RadrootsNostrConnectResponse::Error {
            result: None,
            error: "request evaluation did not provide a response hint".to_owned(),
        },
    })
}

#[cfg(test)]
mod tests {
    use nostr::nips::nip04;
    use nostr::nips::nip44;
    use nostr::nips::nip44::Version;
    use nostr::{EventBuilder, Keys, PublicKey, SecretKey, Timestamp, UnsignedEvent};
    use radroots_nostr::prelude::{RadrootsNostrTag, radroots_nostr_kind};
    use radroots_nostr_connect::prelude::{
        RADROOTS_NOSTR_CONNECT_RPC_KIND, RadrootsNostrConnectMethod,
        RadrootsNostrConnectPermission, RadrootsNostrConnectRequest,
        RadrootsNostrConnectRequestMessage, RadrootsNostrConnectResponse,
        RadrootsNostrConnectResponseEnvelope,
    };
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionRecord;
    use serde_json::json;

    use crate::app::MycRuntime;
    use crate::config::{MycConfig, MycConnectionApproval};

    use super::{MycNip46HandledRequest, MycNip46Handler};

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        radroots_identity::RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime() -> MycRuntime {
        runtime_with_config(MycConnectionApproval::NotRequired, |_| {})
    }

    fn runtime_with_config<F>(approval: MycConnectionApproval, configure: F) -> MycRuntime
    where
        F: FnOnce(&mut MycConfig),
    {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.join("state");
        config.paths.signer_identity_path = temp.join("signer.json");
        config.paths.user_identity_path = temp.join("user.json");
        config.policy.connection_approval = approval;
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 15;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];
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

    fn runtime_with_explicit_approval() -> MycRuntime {
        runtime_with_config(MycConnectionApproval::ExplicitUser, |_| {})
    }

    fn handler(runtime: &MycRuntime) -> MycNip46Handler {
        MycNip46Handler::new(
            runtime.signer_context(),
            runtime.transport().expect("transport").relays().to_vec(),
        )
    }

    fn client_keys() -> Keys {
        client_keys_from_hex("3333333333333333333333333333333333333333333333333333333333333333")
    }

    fn client_keys_from_hex(secret_key: &str) -> Keys {
        let secret = SecretKey::from_hex(secret_key).expect("secret");
        Keys::new(secret)
    }

    fn request_event(
        handler: &MycNip46Handler,
        request: RadrootsNostrConnectRequestMessage,
    ) -> nostr::Event {
        request_event_with_client_keys(handler, request, &client_keys())
    }

    fn request_event_with_client_keys(
        handler: &MycNip46Handler,
        request: RadrootsNostrConnectRequestMessage,
        client_keys: &Keys,
    ) -> nostr::Event {
        let payload = serde_json::to_string(&request).expect("serialize request");
        let ciphertext = nip44::encrypt(
            client_keys.secret_key(),
            &PublicKey::parse(
                handler
                    .signer
                    .signer_public_identity()
                    .public_key_hex
                    .as_str(),
            )
            .expect("signer pubkey"),
            payload,
            Version::V2,
        )
        .expect("encrypt");
        EventBuilder::new(
            radroots_nostr_kind(RADROOTS_NOSTR_CONNECT_RPC_KIND),
            ciphertext,
        )
        .tags(vec![RadrootsNostrTag::public_key(
            handler.signer.signer_identity().public_key(),
        )])
        .sign_with_keys(client_keys)
        .expect("sign request")
    }

    fn sign_event_permission(kind: u16) -> RadrootsNostrConnectPermission {
        RadrootsNostrConnectPermission::with_parameter(
            RadrootsNostrConnectMethod::SignEvent,
            format!("kind:{kind}"),
        )
    }

    fn unsigned_event(pubkey: PublicKey, kind: u16, content: &str) -> UnsignedEvent {
        serde_json::from_value(json!({
            "pubkey": pubkey.to_hex(),
            "created_at": Timestamp::from(1).as_secs(),
            "kind": kind,
            "tags": [],
            "content": content
        }))
        .expect("unsigned event")
    }

    fn connect_with_permissions(
        handler: &MycNip46Handler,
        runtime: &MycRuntime,
        requested_permissions: Vec<RadrootsNostrConnectPermission>,
    ) {
        handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: requested_permissions.into(),
                    },
                ),
            )
            .expect("connect");
    }

    fn connection_for(
        runtime: &MycRuntime,
        client_public_key: PublicKey,
    ) -> RadrootsNostrSignerConnectionRecord {
        runtime
            .signer_manager()
            .expect("manager")
            .find_connections_by_client_public_key(&client_public_key)
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection")
    }

    #[test]
    fn parse_and_build_nip46_envelopes_roundtrip() {
        let runtime = runtime();
        let handler = handler(&runtime);
        let request =
            RadrootsNostrConnectRequestMessage::new("req-1", RadrootsNostrConnectRequest::Ping);
        let event = request_event(&handler, request.clone());

        let parsed = handler.parse_request_event(&event).expect("parse request");
        assert_eq!(parsed, request);

        let response_builder = handler
            .build_response_event(event.pubkey, "req-1", RadrootsNostrConnectResponse::Pong)
            .expect("response builder");
        let response_event = runtime
            .signer_identity()
            .sign_event_builder(response_builder, "test response")
            .expect("sign response");
        let decrypted = nip44::decrypt(
            client_keys().secret_key(),
            &runtime.signer_identity().public_key(),
            &response_event.content,
        )
        .expect("decrypt response");
        let envelope: RadrootsNostrConnectResponseEnvelope =
            serde_json::from_str(&decrypted).expect("parse envelope");
        let parsed = RadrootsNostrConnectResponse::from_envelope(
            &RadrootsNostrConnectRequest::Ping.method(),
            envelope,
        )
        .expect("parse response");
        assert_eq!(parsed, RadrootsNostrConnectResponse::Pong);
    }

    #[test]
    fn connect_registers_client_and_echoes_secret() {
        let runtime = runtime();
        let handler = handler(&runtime);
        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: Some("s3cr3t".to_owned()),
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("connect response");

        assert_eq!(
            response,
            RadrootsNostrConnectResponse::ConnectSecretEcho("s3cr3t".to_owned())
        );
        let connections = runtime
            .signer_manager()
            .expect("manager")
            .list_connections()
            .expect("connections");
        assert_eq!(connections.len(), 1);
        assert_eq!(
            connections[0].user_identity.id.to_string(),
            runtime.user_public_identity().id.to_string()
        );
        assert_eq!(connections[0].relays.len(), 1);
    }

    #[test]
    fn denied_clients_are_rejected_without_registration() {
        let denied_client_keys = client_keys_from_hex(
            "4444444444444444444444444444444444444444444444444444444444444444",
        );
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.denied_client_pubkeys = vec![denied_client_keys.public_key().to_hex()];
        });
        let handler = handler(&runtime);

        let response = handler
            .handle_request_response(
                denied_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("connect response");

        assert_eq!(
            response,
            RadrootsNostrConnectResponse::Error {
                result: None,
                error: "client public key denied by policy".to_owned(),
            }
        );
        assert!(
            runtime
                .signer_manager()
                .expect("manager")
                .list_connections()
                .expect("connections")
                .is_empty()
        );
    }

    #[test]
    fn existing_unconsumed_connect_secret_can_still_retry_after_failed_publish() {
        let runtime = runtime();
        let handler = handler(&runtime);

        let first = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-1",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: Some("s3cr3t".to_owned()),
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("first connect response");
        let second = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-2",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: Some("s3cr3t".to_owned()),
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("second connect response");

        assert_eq!(
            first,
            RadrootsNostrConnectResponse::ConnectSecretEcho("s3cr3t".to_owned())
        );
        assert_eq!(second, first);
    }

    #[test]
    fn consumed_connect_secret_is_ignored_on_reuse() {
        let runtime = runtime();
        let handler = handler(&runtime);
        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: Some("s3cr3t".to_owned()),
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("connect response");
        assert_eq!(
            response,
            RadrootsNostrConnectResponse::ConnectSecretEcho("s3cr3t".to_owned())
        );

        let connection = runtime
            .signer_manager()
            .expect("manager")
            .list_connections()
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection");
        runtime
            .signer_manager()
            .expect("manager")
            .mark_connect_secret_consumed(&connection.connection_id)
            .expect("consume connect secret");

        let ignored = handler
            .handle_request(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-reused",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: Some("s3cr3t".to_owned()),
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("ignored response");

        assert_eq!(ignored, MycNip46HandledRequest::Ignore);
        let connections = runtime
            .signer_manager()
            .expect("manager")
            .list_connections()
            .expect("connections");
        assert_eq!(connections.len(), 1);
        assert!(connections[0].connect_secret_is_consumed());
    }

    #[test]
    fn connect_requests_are_throttled_after_configured_limit() {
        let runtime = runtime_with_config(MycConnectionApproval::NotRequired, |config| {
            config.policy.connect_rate_limit_window_secs = Some(1);
            config.policy.connect_rate_limit_max_attempts = Some(1);
        });
        let handler = handler(&runtime);

        let first = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-1",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("first connect response");
        assert_eq!(first, RadrootsNostrConnectResponse::ConnectAcknowledged);

        let second = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-2",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("second connect response");
        assert!(matches!(
            second,
            RadrootsNostrConnectResponse::Error { error, .. }
                if error.contains("connect attempts throttled by policy")
        ));

        let connection = connection_for(&runtime, client_keys().public_key());
        runtime
            .signer_manager()
            .expect("manager")
            .revoke_connection(&connection.connection_id, Some("test reset".to_owned()))
            .expect("revoke connection");

        std::thread::sleep(std::time::Duration::from_secs(2));

        let third = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect-3",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("third connect response");
        assert_eq!(third, RadrootsNostrConnectResponse::ConnectAcknowledged);
    }

    #[test]
    fn connect_preserves_pending_status_when_explicit_approval_is_required() {
        let runtime = runtime_with_explicit_approval();
        let handler = handler(&runtime);

        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![sign_event_permission(1)].into(),
                    },
                ),
            )
            .expect("connect response");

        assert_eq!(response, RadrootsNostrConnectResponse::ConnectAcknowledged);
        let connection = runtime
            .signer_manager()
            .expect("manager")
            .list_connections()
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection");
        assert_eq!(
            connection.status,
            radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionStatus::Pending
        );
        assert_eq!(
            connection.approval_state,
            radroots_nostr_signer::prelude::RadrootsNostrSignerApprovalState::Pending
        );
        assert!(connection.granted_permissions().as_slice().is_empty());
    }

    #[test]
    fn trusted_clients_auto_grant_only_policy_allowed_permissions() {
        let trusted_client_keys = client_keys_from_hex(
            "4545454545454545454545454545454545454545454545454545454545454545",
        );
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.trusted_client_pubkeys = vec![trusted_client_keys.public_key().to_hex()];
            config.policy.permission_ceiling = vec![
                RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Encrypt),
                sign_event_permission(1),
            ]
            .into();
            config.policy.allowed_sign_event_kinds = vec![1];
        });
        let handler = handler(&runtime);

        let response = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![
                            RadrootsNostrConnectPermission::new(
                                RadrootsNostrConnectMethod::Nip04Encrypt,
                            ),
                            RadrootsNostrConnectPermission::new(
                                RadrootsNostrConnectMethod::SignEvent,
                            ),
                            sign_event_permission(7),
                        ]
                        .into(),
                    },
                ),
            )
            .expect("connect response");

        assert_eq!(response, RadrootsNostrConnectResponse::ConnectAcknowledged);
        let connection = connection_for(&runtime, trusted_client_keys.public_key());
        assert_eq!(
            connection.granted_permissions().to_string(),
            "sign_event:kind:1,nip04_encrypt"
        );
        assert_eq!(
            connection.requested_permissions.to_string(),
            "sign_event:kind:1,nip04_encrypt"
        );
    }

    #[test]
    fn trusted_client_requires_auth_again_after_authorized_ttl() {
        let trusted_client_keys = client_keys_from_hex(
            "5656565656565656565656565656565656565656565656565656565656565656",
        );
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.trusted_client_pubkeys = vec![trusted_client_keys.public_key().to_hex()];
            config.policy.permission_ceiling = vec![sign_event_permission(1)].into();
            config.policy.allowed_sign_event_kinds = vec![1];
            config.policy.auth_url = Some("https://auth.example/challenge".to_owned());
            config.policy.auth_authorized_ttl_secs = Some(1);
        });
        let handler = handler(&runtime);

        let _ = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![sign_event_permission(1)].into(),
                    },
                ),
            )
            .expect("connect");

        let first = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "first",
                    )),
                ),
            )
            .expect("first sign request");
        assert_eq!(
            first,
            RadrootsNostrConnectResponse::AuthUrl("https://auth.example/challenge".to_owned())
        );

        let connection = connection_for(&runtime, trusted_client_keys.public_key());
        runtime
            .signer_manager()
            .expect("manager")
            .authorize_auth_challenge(&connection.connection_id)
            .expect("authorize auth challenge");

        let second = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-2",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "second",
                    )),
                ),
            )
            .expect("second sign request");
        assert!(matches!(
            second,
            RadrootsNostrConnectResponse::SignedEvent(_)
        ));

        std::thread::sleep(std::time::Duration::from_secs(2));

        let third = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-3",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "third",
                    )),
                ),
            )
            .expect("third sign request");
        assert_eq!(
            third,
            RadrootsNostrConnectResponse::AuthUrl("https://auth.example/challenge".to_owned())
        );
    }

    #[test]
    fn trusted_client_requires_auth_again_after_inactivity() {
        let trusted_client_keys = client_keys_from_hex(
            "5757575757575757575757575757575757575757575757575757575757575757",
        );
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.trusted_client_pubkeys = vec![trusted_client_keys.public_key().to_hex()];
            config.policy.permission_ceiling = vec![sign_event_permission(1)].into();
            config.policy.allowed_sign_event_kinds = vec![1];
            config.policy.auth_url = Some("https://auth.example/challenge".to_owned());
            config.policy.reauth_after_inactivity_secs = Some(1);
        });
        let handler = handler(&runtime);

        let _ = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![sign_event_permission(1)].into(),
                    },
                ),
            )
            .expect("connect");

        let first = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "first",
                    )),
                ),
            )
            .expect("first sign request");
        assert_eq!(
            first,
            RadrootsNostrConnectResponse::AuthUrl("https://auth.example/challenge".to_owned())
        );

        let connection = connection_for(&runtime, trusted_client_keys.public_key());
        runtime
            .signer_manager()
            .expect("manager")
            .authorize_auth_challenge(&connection.connection_id)
            .expect("authorize auth challenge");

        std::thread::sleep(std::time::Duration::from_secs(2));

        let second = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-2",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "second",
                    )),
                ),
            )
            .expect("second sign request");
        assert_eq!(
            second,
            RadrootsNostrConnectResponse::AuthUrl("https://auth.example/challenge".to_owned())
        );
    }

    #[test]
    fn trusted_client_auth_challenge_reissue_is_throttled() {
        let trusted_client_keys = client_keys_from_hex(
            "5858585858585858585858585858585858585858585858585858585858585858",
        );
        let runtime = runtime_with_config(MycConnectionApproval::ExplicitUser, |config| {
            config.policy.trusted_client_pubkeys = vec![trusted_client_keys.public_key().to_hex()];
            config.policy.permission_ceiling = vec![sign_event_permission(1)].into();
            config.policy.allowed_sign_event_kinds = vec![1];
            config.policy.auth_url = Some("https://auth.example/challenge".to_owned());
            config.policy.auth_pending_ttl_secs = 1;
            config.policy.auth_challenge_rate_limit_window_secs = Some(60);
            config.policy.auth_challenge_rate_limit_max_attempts = Some(1);
        });
        let handler = handler(&runtime);

        let _ = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![sign_event_permission(1)].into(),
                    },
                ),
            )
            .expect("connect");

        let first = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "first",
                    )),
                ),
            )
            .expect("first sign request");
        assert_eq!(
            first,
            RadrootsNostrConnectResponse::AuthUrl("https://auth.example/challenge".to_owned())
        );

        std::thread::sleep(std::time::Duration::from_secs(2));

        let second = handler
            .handle_request_response(
                trusted_client_keys.public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign-2",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "second",
                    )),
                ),
            )
            .expect("second sign request");
        assert!(matches!(
            second,
            RadrootsNostrConnectResponse::Error { error, .. }
                if error.contains("auth challenge issuance throttled by policy")
        ));
    }

    #[test]
    fn base_methods_return_spec_results_after_connect() {
        let runtime = runtime();
        let handler = handler(&runtime);
        handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![RadrootsNostrConnectPermission::new(
                            RadrootsNostrConnectMethod::SwitchRelays,
                        )]
                        .into(),
                    },
                ),
            )
            .expect("connect");

        let public_key = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-pubkey",
                    RadrootsNostrConnectRequest::GetPublicKey,
                ),
            )
            .expect("get public key");
        assert_eq!(
            public_key,
            RadrootsNostrConnectResponse::UserPublicKey(runtime.user_identity().public_key())
        );

        let pong = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-ping",
                    RadrootsNostrConnectRequest::Ping,
                ),
            )
            .expect("ping");
        assert_eq!(pong, RadrootsNostrConnectResponse::Pong);

        let relays = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-switch",
                    RadrootsNostrConnectRequest::SwitchRelays,
                ),
            )
            .expect("switch relays");
        assert_eq!(
            relays,
            RadrootsNostrConnectResponse::RelayList(
                runtime.transport().expect("transport").relays().to_vec()
            )
        );
    }

    #[test]
    fn new_connections_preserve_requested_permissions_without_expansion() {
        let runtime = runtime();
        let handler = handler(&runtime);
        handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: vec![sign_event_permission(1)].into(),
                    },
                ),
            )
            .expect("connect");

        let connection = runtime
            .signer_manager()
            .expect("manager")
            .list_connections()
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection");
        assert_eq!(
            connection.granted_permissions().as_slice(),
            &[sign_event_permission(1)]
        );
    }

    #[test]
    fn sign_event_returns_signed_event_for_managed_user_key() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(&handler, &runtime, vec![sign_event_permission(1)]);

        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "hello world",
                    )),
                ),
            )
            .expect("sign event");

        let RadrootsNostrConnectResponse::SignedEvent(event) = response else {
            panic!("unexpected sign_event response");
        };
        assert_eq!(event.pubkey, runtime.user_identity().public_key());
        assert_eq!(event.kind.as_u16(), 1);
        assert_eq!(event.content, "hello world");
        assert!(event.verify_signature());
    }

    #[test]
    fn sign_event_is_denied_without_permission() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(&handler, &runtime, Vec::new());

        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        runtime.user_identity().public_key(),
                        1,
                        "hello world",
                    )),
                ),
            )
            .expect("sign event");

        assert_eq!(
            response,
            RadrootsNostrConnectResponse::Error {
                result: None,
                error: "unauthorized sign_event".to_owned(),
            }
        );
    }

    #[test]
    fn sign_event_rejects_pubkey_mismatch() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(&handler, &runtime, vec![sign_event_permission(1)]);

        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-sign",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(
                        client_keys().public_key(),
                        1,
                        "hello world",
                    )),
                ),
            )
            .expect("sign event");

        assert_eq!(
            response,
            RadrootsNostrConnectResponse::Error {
                result: None,
                error: "sign_event pubkey does not match the managed user identity".to_owned(),
            }
        );
    }

    #[test]
    fn nip04_encrypt_and_decrypt_roundtrip_on_managed_user_identity() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(
            &handler,
            &runtime,
            vec![
                RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Encrypt),
                RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Decrypt),
            ],
        );

        let encrypt_response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-nip04-encrypt",
                    RadrootsNostrConnectRequest::Nip04Encrypt {
                        public_key: client_keys().public_key(),
                        plaintext: "hello from myc".to_owned(),
                    },
                ),
            )
            .expect("nip04 encrypt");
        let RadrootsNostrConnectResponse::Nip04Encrypt(ciphertext) = encrypt_response else {
            panic!("unexpected nip04 encrypt response");
        };
        assert_eq!(
            nip04::decrypt(
                client_keys().secret_key(),
                &runtime.user_identity().public_key(),
                ciphertext.clone(),
            )
            .expect("client decrypt"),
            "hello from myc"
        );

        let client_ciphertext = nip04::encrypt(
            client_keys().secret_key(),
            &runtime.user_identity().public_key(),
            "hello to myc",
        )
        .expect("client encrypt");
        let decrypt_response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-nip04-decrypt",
                    RadrootsNostrConnectRequest::Nip04Decrypt {
                        public_key: client_keys().public_key(),
                        ciphertext: client_ciphertext,
                    },
                ),
            )
            .expect("nip04 decrypt");
        assert_eq!(
            decrypt_response,
            RadrootsNostrConnectResponse::Nip04Decrypt("hello to myc".to_owned())
        );
    }

    #[test]
    fn nip44_encrypt_and_decrypt_roundtrip_on_managed_user_identity() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(
            &handler,
            &runtime,
            vec![
                RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip44Encrypt),
                RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip44Decrypt),
            ],
        );

        let encrypt_response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-nip44-encrypt",
                    RadrootsNostrConnectRequest::Nip44Encrypt {
                        public_key: client_keys().public_key(),
                        plaintext: "hello from myc".to_owned(),
                    },
                ),
            )
            .expect("nip44 encrypt");
        let RadrootsNostrConnectResponse::Nip44Encrypt(ciphertext) = encrypt_response else {
            panic!("unexpected nip44 encrypt response");
        };
        assert_eq!(
            nip44::decrypt(
                client_keys().secret_key(),
                &runtime.user_identity().public_key(),
                ciphertext.clone(),
            )
            .expect("client decrypt"),
            "hello from myc"
        );

        let client_ciphertext = nip44::encrypt(
            client_keys().secret_key(),
            &runtime.user_identity().public_key(),
            "hello to myc",
            Version::V2,
        )
        .expect("client encrypt");
        let decrypt_response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-nip44-decrypt",
                    RadrootsNostrConnectRequest::Nip44Decrypt {
                        public_key: client_keys().public_key(),
                        ciphertext: client_ciphertext,
                    },
                ),
            )
            .expect("nip44 decrypt");
        assert_eq!(
            decrypt_response,
            RadrootsNostrConnectResponse::Nip44Decrypt("hello to myc".to_owned())
        );
    }

    #[test]
    fn nip04_decrypt_is_denied_without_matching_permission() {
        let runtime = runtime();
        let handler = handler(&runtime);
        connect_with_permissions(
            &handler,
            &runtime,
            vec![RadrootsNostrConnectPermission::new(
                RadrootsNostrConnectMethod::Nip04Encrypt,
            )],
        );

        let response = handler
            .handle_request_response(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-nip04-decrypt",
                    RadrootsNostrConnectRequest::Nip04Decrypt {
                        public_key: client_keys().public_key(),
                        ciphertext: "invalid".to_owned(),
                    },
                ),
            )
            .expect("nip04 decrypt");

        assert_eq!(
            response,
            RadrootsNostrConnectResponse::Error {
                result: None,
                error: "unauthorized nip04_decrypt".to_owned(),
            }
        );
    }
}
