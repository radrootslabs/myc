use nostr::nips::nip04;
use nostr::nips::nip44;
use nostr::nips::nip44::Version;
use radroots_nostr::prelude::{
    RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter, RadrootsNostrKind,
    RadrootsNostrPublicKey, RadrootsNostrRelayPoolNotification, RadrootsNostrRelayUrl,
    RadrootsNostrTag, RadrootsNostrTimestamp, radroots_nostr_filter_tag, radroots_nostr_kind,
};
use radroots_nostr_connect::prelude::{
    RADROOTS_NOSTR_CONNECT_RPC_KIND, RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
    RadrootsNostrConnectRequestMessage, RadrootsNostrConnectResponse,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerRequestAction,
    RadrootsNostrSignerRequestResponseHint, RadrootsNostrSignerSessionLookup,
};
use tokio::sync::broadcast;

use crate::app::MycSignerContext;
use crate::error::MycError;
use crate::transport::MycNostrTransport;

#[derive(Clone)]
pub struct MycNip46Handler {
    signer: MycSignerContext,
    relays: Vec<RadrootsNostrRelayUrl>,
}

pub struct MycNip46Service {
    handler: MycNip46Handler,
    transport: MycNostrTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MycNip46HandledRequest {
    Respond {
        response: RadrootsNostrConnectResponse,
        consume_connect_secret_for: Option<RadrootsNostrSignerConnectionId>,
    },
    Ignore,
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
        let decrypted = nip44::decrypt(
            self.signer.signer_identity().keys().secret_key(),
            &event.pubkey,
            &event.content,
        )
        .map_err(|err| MycError::Nip46Decrypt(err.to_string()))?;
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
        let ciphertext = nip44::encrypt(
            self.signer.signer_identity().keys().secret_key(),
            &client_public_key,
            payload,
            Version::V2,
        )
        .map_err(|err| MycError::Nip46Encrypt(err.to_string()))?;

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
                Ok(connect_response_outcome(&connection, secret))
            }
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => {
                let draft = proposal
                    .into_connection_draft(self.signer.user_public_identity())
                    .with_relays(self.relays.clone())
                    .with_approval_requirement(self.signer.connection_approval_requirement());
                let connection = manager.register_connection(draft)?;
                if self.signer.connection_approval_requirement()
                    == radroots_nostr_signer::prelude::RadrootsNostrSignerApprovalRequirement::NotRequired
                {
                    let granted_permissions =
                        grant_permissions_for_new_connection(connection.requested_permissions.clone());
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

        let manager = self.signer.load_signer_manager()?;
        let evaluation = manager.evaluate_request(&connection.connection_id, request_message)?;

        match evaluation.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => Ok(
                MycNip46HandledRequest::respond(RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: reason,
                }),
            ),
            RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                Ok(MycNip46HandledRequest::respond(
                    RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                ))
            }
            RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                response_from_hint(&evaluation.connection, response_hint)
                    .map(MycNip46HandledRequest::respond)
            }
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

        let manager = self.signer.load_signer_manager()?;
        let evaluation = manager.evaluate_request(&connection.connection_id, request_message)?;

        match evaluation.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => Ok(
                MycNip46HandledRequest::respond(RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: reason,
                }),
            ),
            RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                Ok(MycNip46HandledRequest::respond(
                    RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                ))
            }
            RadrootsNostrSignerRequestAction::Allowed { .. } => self
                .sign_event_response(unsigned_event)
                .map(MycNip46HandledRequest::respond),
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

        let manager = self.signer.load_signer_manager()?;
        let evaluation = manager.evaluate_request(&connection.connection_id, request_message)?;

        match evaluation.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => Ok(
                MycNip46HandledRequest::respond(RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: reason,
                }),
            ),
            RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
                Ok(MycNip46HandledRequest::respond(
                    RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
                ))
            }
            RadrootsNostrSignerRequestAction::Allowed { .. } => self
                .crypto_response(request)
                .map(MycNip46HandledRequest::respond),
        }
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

        match unsigned_event.sign_with_keys(self.signer.user_identity().keys()) {
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
        let user_secret_key = self.signer.user_identity().keys().secret_key();
        Ok(match request {
            RadrootsNostrConnectRequest::Nip04Encrypt {
                public_key,
                plaintext,
            } => match nip04::encrypt(user_secret_key, &public_key, plaintext) {
                Ok(ciphertext) => RadrootsNostrConnectResponse::Nip04Encrypt(ciphertext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip04 encrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip04Decrypt {
                public_key,
                ciphertext,
            } => match nip04::decrypt(user_secret_key, &public_key, ciphertext) {
                Ok(plaintext) => RadrootsNostrConnectResponse::Nip04Decrypt(plaintext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip04 decrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip44Encrypt {
                public_key,
                plaintext,
            } => match nip44::encrypt(user_secret_key, &public_key, plaintext, Version::V2) {
                Ok(ciphertext) => RadrootsNostrConnectResponse::Nip44Encrypt(ciphertext),
                Err(error) => RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: format!("nip44 encrypt failed: {error}"),
                },
            },
            RadrootsNostrConnectRequest::Nip44Decrypt {
                public_key,
                ciphertext,
            } => match nip44::decrypt(user_secret_key, &public_key, ciphertext) {
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
    pub fn new(signer: MycSignerContext, transport: MycNostrTransport) -> Self {
        let handler = MycNip46Handler::new(signer, transport.relays().to_vec());
        Self { handler, transport }
    }

    pub async fn run(&self) -> Result<(), MycError> {
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
            let notification = match notifications.recv().await {
                Ok(notification) => notification,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(MycError::Nip46ListenerClosed);
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
            let Some((response, consume_connect_secret_for)) = handled_request.into_publish_parts()
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
                    .build_response_event(event.pubkey, request_id, response)?;
            if let Err(error) = self
                .transport
                .client()
                .send_event_builder(response_event)
                .await
            {
                tracing::warn!(error = %error, "failed to publish NIP-46 response");
                continue;
            }
            if let Some(connection_id) = consume_connect_secret_for {
                if let Err(error) = self
                    .handler
                    .signer
                    .load_signer_manager()?
                    .mark_connect_secret_consumed(&connection_id)
                {
                    tracing::warn!(
                        error = %error,
                        connection_id = %connection_id,
                        "failed to persist consumed NIP-46 connect secret"
                    );
                }
            }
        }
    }
}

impl MycNip46HandledRequest {
    fn respond(response: RadrootsNostrConnectResponse) -> Self {
        Self::Respond {
            response,
            consume_connect_secret_for: None,
        }
    }

    pub(crate) fn into_publish_parts(
        self,
    ) -> Option<(
        RadrootsNostrConnectResponse,
        Option<RadrootsNostrSignerConnectionId>,
    )> {
        match self {
            Self::Respond {
                response,
                consume_connect_secret_for,
            } => Some((response, consume_connect_secret_for)),
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
        consume_connect_secret_for,
    }
}

fn grant_permissions_for_new_connection(
    requested_permissions: RadrootsNostrConnectPermissions,
) -> RadrootsNostrConnectPermissions {
    let mut granted = requested_permissions.into_vec();
    granted.sort();
    granted.dedup();
    granted.into()
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
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.join("state");
        config.paths.signer_identity_path = temp.join("signer.json");
        config.paths.user_identity_path = temp.join("user.json");
        config.policy.connection_approval = MycConnectionApproval::NotRequired;
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 15;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];
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
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.join("state");
        config.paths.signer_identity_path = temp.join("signer.json");
        config.paths.user_identity_path = temp.join("user.json");
        config.policy.connection_approval = MycConnectionApproval::ExplicitUser;
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 15;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];
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

    fn handler(runtime: &MycRuntime) -> MycNip46Handler {
        MycNip46Handler::new(
            runtime.signer_context(),
            runtime.transport().expect("transport").relays().to_vec(),
        )
    }

    fn client_keys() -> Keys {
        let secret =
            SecretKey::from_hex("3333333333333333333333333333333333333333333333333333333333333333")
                .expect("secret");
        Keys::new(secret)
    }

    fn request_event(
        handler: &MycNip46Handler,
        request: RadrootsNostrConnectRequestMessage,
    ) -> nostr::Event {
        let client_keys = client_keys();
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
        .sign_with_keys(&client_keys)
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
        let response_event = response_builder
            .sign_with_keys(runtime.signer_identity().keys())
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
