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
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerRequestAction, RadrootsNostrSignerRequestResponseHint,
    RadrootsNostrSignerSessionLookup,
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

    pub fn handle_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        match request_message.request.clone() {
            RadrootsNostrConnectRequest::Connect { secret, .. } => {
                self.handle_connect_request(client_public_key, request_message.request, secret)
            }
            RadrootsNostrConnectRequest::SignEvent(unsigned_event) => {
                self.handle_sign_event_request(client_public_key, request_message, unsigned_event)
            }
            RadrootsNostrConnectRequest::GetPublicKey
            | RadrootsNostrConnectRequest::Ping
            | RadrootsNostrConnectRequest::SwitchRelays => {
                self.handle_base_request(client_public_key, request_message)
            }
            _ => Ok(RadrootsNostrConnectResponse::Error {
                result: None,
                error: format!(
                    "method `{}` is not implemented yet",
                    request_message.request.method()
                ),
            }),
        }
    }

    fn handle_connect_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request: RadrootsNostrConnectRequest,
        secret: Option<String>,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        let evaluation = self
            .signer
            .signer_manager()
            .evaluate_connect_request(client_public_key, request)?;

        match evaluation {
            RadrootsNostrSignerConnectEvaluation::ExistingConnection(_) => {
                Ok(connect_response(secret))
            }
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => {
                let draft = proposal
                    .into_connection_draft(self.signer.user_public_identity())
                    .with_relays(self.relays.clone());
                let connection = self.signer.signer_manager().register_connection(draft)?;
                let granted_permissions =
                    grant_permissions_for_new_connection(connection.requested_permissions.clone());
                let _ = self
                    .signer
                    .signer_manager()
                    .set_granted_permissions(&connection.connection_id, granted_permissions)?;
                Ok(connect_response(secret))
            }
        }
    }

    fn handle_base_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => return Ok(response),
        };

        let evaluation = self
            .signer
            .signer_manager()
            .evaluate_request(&connection.connection_id, request_message)?;

        match evaluation.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => {
                Ok(RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: reason,
                })
            }
            RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => Ok(
                RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
            ),
            RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                response_from_hint(&evaluation.connection, response_hint)
            }
        }
    }

    fn handle_sign_event_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RadrootsNostrConnectRequestMessage,
        unsigned_event: nostr::UnsignedEvent,
    ) -> Result<RadrootsNostrConnectResponse, MycError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => return Ok(response),
        };

        let evaluation = self
            .signer
            .signer_manager()
            .evaluate_request(&connection.connection_id, request_message)?;

        match evaluation.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => {
                Ok(RadrootsNostrConnectResponse::Error {
                    result: None,
                    error: reason,
                })
            }
            RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => Ok(
                RadrootsNostrConnectResponse::AuthUrl(auth_challenge.auth_url),
            ),
            RadrootsNostrSignerRequestAction::Allowed { .. } => {
                self.sign_event_response(unsigned_event)
            }
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
                .signer_manager()
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
            let response = match self.handler.handle_request(event.pubkey, request_message) {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(error = %error, "failed to handle NIP-46 request");
                    RadrootsNostrConnectResponse::Error {
                        result: None,
                        error: error.to_string(),
                    }
                }
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
            }
        }
    }
}

fn connect_response(secret: Option<String>) -> RadrootsNostrConnectResponse {
    match secret {
        Some(secret) => RadrootsNostrConnectResponse::ConnectSecretEcho(secret),
        None => RadrootsNostrConnectResponse::ConnectAcknowledged,
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
    use crate::config::MycConfig;

    use super::MycNip46Handler;

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        radroots_identity::RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime() -> MycRuntime {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
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
            .handle_request(
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
    fn base_methods_return_spec_results_after_connect() {
        let runtime = runtime();
        let handler = handler(&runtime);
        handler
            .handle_request(
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
            .handle_request(
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
            .handle_request(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-ping",
                    RadrootsNostrConnectRequest::Ping,
                ),
            )
            .expect("ping");
        assert_eq!(pong, RadrootsNostrConnectResponse::Pong);

        let relays = handler
            .handle_request(
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
            .handle_request(
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
        handler
            .handle_request(
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

        let response = handler
            .handle_request(
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
        handler
            .handle_request(
                client_keys().public_key(),
                RadrootsNostrConnectRequestMessage::new(
                    "req-connect",
                    RadrootsNostrConnectRequest::Connect {
                        remote_signer_public_key: runtime.signer_identity().public_key(),
                        secret: None,
                        requested_permissions: Default::default(),
                    },
                ),
            )
            .expect("connect");

        let response = handler
            .handle_request(
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
        handler
            .handle_request(
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

        let response = handler
            .handle_request(
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
}
