use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use nostr::{
    JsonUtil, UnsignedEvent,
    filter::{Alphabet, SingleLetterTag},
};
use nostr::{PublicKey as RadrootsNostrPublicKey, RelayUrl as RadrootsNostrRelayUrl};
use radroots_nostr::event::Event as RadrootsNostrEvent;
use radroots_nostr::event::GenericBuilder;
use radroots_nostr::event::Kind as RadrootsNostrKind;
use radroots_nostr::event::Timestamp as RadrootsNostrTimestamp;
use radroots_nostr::filter::Filter as RadrootsNostrFilter;
use radroots_nostr::tag::Tag as RadrootsNostrTag;
use radroots_nostr_connect::{
    Error as ConnectError, Request, Response,
    message::{
        RPC_KIND, RequestMessage, SignedEvent as ConnectSignedEvent,
        UnsignedEvent as ConnectUnsignedEvent,
    },
    permission::Permissions,
};

use crate::signer::backend::RadrootsNostrSignerBackend;
use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::evaluation::{
    RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerRequestAction,
    RadrootsNostrSignerRequestEvaluation, RadrootsNostrSignerRequestResponseHint,
    RadrootsNostrSignerSessionLookup,
};
use crate::signer::model::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerRequestAuditRecord,
    RadrootsNostrSignerRequestDecision,
};

/// Cryptographic operations required by the external NIP-46 protocol.
///
/// NIP-46 `sign_event` accepts caller-supplied unsigned Nostr events. Signing
/// one is protocol interoperability only and does not establish a Radroots
/// typed product-authoring contract.
pub trait RadrootsNostrSignerNip46Signer: Clone + Send + Sync {
    fn signer_public_key_hex(&self) -> String;
    fn decrypt_request(
        &self,
        client_public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
    fn encrypt_response(
        &self,
        client_public_key: &RadrootsNostrPublicKey,
        payload: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
    fn user_identity(&self) -> PublicIdentity;
    /// Signs a caller-supplied NIP-46 unsigned event without claiming typed
    /// Radroots product authoring.
    fn sign_user_event(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<RadrootsNostrEvent, RadrootsNostrSignerError>;
    fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
    fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
    fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
    fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, RadrootsNostrSignerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadrootsNostrSignerNip46ConnectDecision {
    Allow,
    RequireApproval,
    Deny,
}

pub trait RadrootsNostrSignerNip46Policy<B: RadrootsNostrSignerBackend>:
    Clone + Send + Sync
{
    fn connect_decision(
        &self,
        client_public_key: &RadrootsNostrPublicKey,
    ) -> RadrootsNostrSignerNip46ConnectDecision;

    fn connect_rate_limit_denied_reason(
        &self,
        client_public_key: &RadrootsNostrPublicKey,
    ) -> Option<String>;

    fn approval_requirement_for_client(
        &self,
        client_public_key: &RadrootsNostrPublicKey,
    ) -> Option<RadrootsNostrSignerApprovalRequirement>;

    fn filtered_requested_permissions(&self, requested_permissions: &Permissions) -> Permissions;

    fn auto_granted_permissions(&self, requested_permissions: &Permissions) -> Permissions;

    fn prepare_request(
        &self,
        backend: &B,
        connection: &RadrootsNostrSignerConnectionRecord,
        request_message: &RequestMessage,
    ) -> Result<Option<String>, RadrootsNostrSignerError>;
}

#[derive(Clone)]
pub struct RadrootsNostrSignerNip46Codec<S> {
    signer: S,
}

#[derive(Clone)]
pub struct RadrootsNostrSignerNip46Handler<B, P, S> {
    backend: B,
    policy: P,
    relays: Vec<RadrootsNostrRelayUrl>,
    codec: RadrootsNostrSignerNip46Codec<S>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadrootsNostrSignerHandledRequest {
    Respond {
        response: Box<Response>,
        connection_id: Option<RadrootsNostrSignerConnectionId>,
        consume_connect_secret_for: Option<RadrootsNostrSignerConnectionId>,
    },
    Ignore,
}

#[derive(Debug, Clone)]
pub struct RadrootsNostrSignerHandledRequestOutcome {
    pub handled_request: RadrootsNostrSignerHandledRequest,
    pub audit: Option<RadrootsNostrSignerRequestAuditRecord>,
}

enum RadrootsNostrSignerPreparedRequestEvaluation {
    Denied {
        reason: String,
        audit: RadrootsNostrSignerRequestAuditRecord,
    },
    Evaluation(Box<RadrootsNostrSignerRequestEvaluation>),
}

impl<S: RadrootsNostrSignerNip46Signer> RadrootsNostrSignerNip46Codec<S> {
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    pub fn filter(&self) -> Result<RadrootsNostrFilter, RadrootsNostrSignerError> {
        let filter = RadrootsNostrFilter::new()
            .kind(RadrootsNostrKind::Custom(RPC_KIND))
            .since(RadrootsNostrTimestamp::now());
        Ok(filter.custom_tags(
            SingleLetterTag::lowercase(Alphabet::P),
            vec![self.signer.signer_public_key_hex()],
        ))
    }

    pub fn parse_request_event(
        &self,
        event: &RadrootsNostrEvent,
    ) -> Result<RequestMessage, RadrootsNostrSignerError> {
        let decrypted = self.signer.decrypt_request(&event.pubkey, &event.content)?;
        Ok(serde_json::from_str(&decrypted).map_err(ConnectError::from)?)
    }

    pub fn build_response_event(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_id: impl Into<String>,
        response: Response,
    ) -> Result<GenericBuilder, RadrootsNostrSignerError> {
        let envelope = response.into_envelope(request_id.into())?;
        let payload = serde_json::to_string(&envelope).map_err(ConnectError::from)?;
        let ciphertext = self.signer.encrypt_response(&client_public_key, &payload)?;

        Ok(
            GenericBuilder::new(RadrootsNostrKind::Custom(RPC_KIND), ciphertext)
                .tags(vec![RadrootsNostrTag::public_key(client_public_key)]),
        )
    }

    /// Produces a NIP-46 response for an externally supplied unsigned event.
    ///
    /// A successful response proves only protocol signing. It does not confer
    /// a Radroots typed-authoring or product-admission claim.
    pub fn sign_event_response(
        &self,
        unsigned_event: UnsignedEvent,
    ) -> Result<Response, RadrootsNostrSignerError> {
        let unsigned_event = ConnectUnsignedEvent::from_json(&unsigned_event.as_json())?;
        Ok(self.sign_event_response_value(unsigned_event))
    }

    fn sign_event_response_value(&self, unsigned_event: ConnectUnsignedEvent) -> Response {
        let unsigned_event = match serde_json::from_str::<UnsignedEvent>(&unsigned_event.as_json())
        {
            Ok(unsigned_event) => unsigned_event,
            Err(error) => {
                return Response::Error {
                    result: None,
                    error: format!("invalid sign_event payload: {error}"),
                };
            }
        };
        let user_public_key = self.signer.user_identity().public_key().to_hex();
        if unsigned_event.pubkey.to_hex() != user_public_key {
            return Response::Error {
                result: None,
                error: "sign_event pubkey does not match the managed user identity".to_owned(),
            };
        }

        match self.signer.sign_user_event(unsigned_event) {
            Ok(event) => match ConnectSignedEvent::from_json(&event.as_json()) {
                Ok(event) => Response::SignedEvent(event),
                Err(error) => Response::Error {
                    result: None,
                    error: format!("failed to encode signed event: {error}"),
                },
            },
            Err(error) => Response::Error {
                result: None,
                error: format!("failed to sign event: {error}"),
            },
        }
    }

    pub fn crypto_response(&self, request: Request) -> Result<Response, RadrootsNostrSignerError> {
        Ok(self.crypto_response_value(request))
    }

    fn crypto_response_value(&self, request: Request) -> Response {
        match request {
            Request::Nip04Encrypt {
                public_key,
                plaintext,
            } => match nostr_public_key(public_key)
                .and_then(|public_key| self.signer.nip04_encrypt(&public_key, &plaintext))
            {
                Ok(ciphertext) => Response::Nip04Encrypt(ciphertext),
                Err(error) => Response::Error {
                    result: None,
                    error: format!("nip04 encrypt failed: {error}"),
                },
            },
            Request::Nip04Decrypt {
                public_key,
                ciphertext,
            } => match nostr_public_key(public_key)
                .and_then(|public_key| self.signer.nip04_decrypt(&public_key, &ciphertext))
            {
                Ok(plaintext) => Response::Nip04Decrypt(plaintext),
                Err(error) => Response::Error {
                    result: None,
                    error: format!("nip04 decrypt failed: {error}"),
                },
            },
            Request::Nip44Encrypt {
                public_key,
                plaintext,
            } => match nostr_public_key(public_key)
                .and_then(|public_key| self.signer.nip44_encrypt(&public_key, &plaintext))
            {
                Ok(ciphertext) => Response::Nip44Encrypt(ciphertext),
                Err(error) => Response::Error {
                    result: None,
                    error: format!("nip44 encrypt failed: {error}"),
                },
            },
            Request::Nip44Decrypt {
                public_key,
                ciphertext,
            } => match nostr_public_key(public_key)
                .and_then(|public_key| self.signer.nip44_decrypt(&public_key, &ciphertext))
            {
                Ok(plaintext) => Response::Nip44Decrypt(plaintext),
                Err(error) => Response::Error {
                    result: None,
                    error: format!("nip44 decrypt failed: {error}"),
                },
            },
            other => Response::Error {
                result: None,
                error: format!("request `{}` is not a crypto method", other.method()),
            },
        }
    }
}

impl<B, P, S> RadrootsNostrSignerNip46Handler<B, P, S>
where
    B: RadrootsNostrSignerBackend + Clone,
    P: RadrootsNostrSignerNip46Policy<B>,
    S: RadrootsNostrSignerNip46Signer,
{
    pub fn new(backend: B, policy: P, relays: Vec<RadrootsNostrRelayUrl>, signer: S) -> Self {
        Self {
            backend,
            policy,
            relays,
            codec: RadrootsNostrSignerNip46Codec::new(signer),
        }
    }

    pub fn filter(&self) -> Result<RadrootsNostrFilter, RadrootsNostrSignerError> {
        self.codec.filter()
    }

    pub fn parse_request_event(
        &self,
        event: &RadrootsNostrEvent,
    ) -> Result<RequestMessage, RadrootsNostrSignerError> {
        self.codec.parse_request_event(event)
    }

    pub fn build_response_event(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_id: impl Into<String>,
        response: Response,
    ) -> Result<GenericBuilder, RadrootsNostrSignerError> {
        self.codec
            .build_response_event(client_public_key, request_id, response)
    }

    pub fn handle_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        match request_message.request.clone() {
            Request::Connect { secret, .. } => {
                self.handle_connect_request(client_public_key, request_message.request, secret)
            }
            Request::SignEvent(unsigned_event) => {
                self.handle_sign_event_request(client_public_key, request_message, unsigned_event)
            }
            Request::Nip04Encrypt { .. }
            | Request::Nip04Decrypt { .. }
            | Request::Nip44Encrypt { .. }
            | Request::Nip44Decrypt { .. } => {
                self.handle_crypto_request(client_public_key, request_message)
            }
            Request::GetPublicKey
            | Request::GetSessionCapability
            | Request::Ping
            | Request::SwitchRelays => self.handle_base_request(client_public_key, request_message),
            _ => Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                RadrootsNostrSignerHandledRequest::respond(Response::Error {
                    result: None,
                    error: format!(
                        "method `{}` is not implemented yet",
                        request_message.request.method()
                    ),
                }),
                None,
            )),
        }
    }

    pub fn handle_authorized_request_evaluation(
        &self,
        request_message: RequestMessage,
        evaluation: RadrootsNostrSignerRequestEvaluation,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        let audit = evaluation.audit.clone();
        let handled_request = self.handled_request_for_evaluation(request_message, evaluation)?;
        Ok(RadrootsNostrSignerHandledRequestOutcome::new(
            handled_request,
            Some(audit),
        ))
    }

    fn handle_connect_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request: Request,
        secret: Option<String>,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        let connect_decision = self.policy.connect_decision(&client_public_key);
        if let Some(connect_secret) = secret.as_deref()
            && let Some(connection) = self
                .backend
                .find_connection_by_connect_secret(connect_secret)?
            && connection.connect_secret_is_consumed()
        {
            return Ok(RadrootsNostrSignerHandledRequestOutcome::ignore());
        }
        if !matches!(
            connect_decision,
            RadrootsNostrSignerNip46ConnectDecision::Deny
        ) && let Some(reason) = self
            .policy
            .connect_rate_limit_denied_reason(&client_public_key)
        {
            return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(
                Response::Error {
                    result: None,
                    error: reason,
                },
            ));
        }

        let evaluation = self
            .backend
            .evaluate_connect_request(client_public_key, request)?;

        match evaluation {
            RadrootsNostrSignerConnectEvaluation::ExistingConnection(connection) => {
                if matches!(
                    connect_decision,
                    RadrootsNostrSignerNip46ConnectDecision::Deny
                ) {
                    return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(
                        Response::Error {
                            result: None,
                            error: "client public key denied by policy".to_owned(),
                        },
                    ));
                }
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    connect_response_outcome(&connection, secret),
                    None,
                ))
            }
            RadrootsNostrSignerConnectEvaluation::RegistrationRequired(proposal) => {
                let requested_permissions = self
                    .policy
                    .filtered_requested_permissions(&proposal.requested_permissions);
                let Some(approval_requirement) = self
                    .policy
                    .approval_requirement_for_client(&client_public_key)
                else {
                    return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(
                        Response::Error {
                            result: None,
                            error: "client public key denied by policy".to_owned(),
                        },
                    ));
                };
                let draft = proposal
                    .into_connection_draft(self.codec.signer.user_identity())
                    .with_requested_permissions(requested_permissions)
                    .with_relays(self.relays.clone())
                    .with_approval_requirement(approval_requirement);
                let connection = self.backend.register_connection(draft)?;
                if approval_requirement == RadrootsNostrSignerApprovalRequirement::NotRequired {
                    let granted_permissions = self
                        .policy
                        .auto_granted_permissions(&connection.requested_permissions);
                    let _ = self
                        .backend
                        .set_granted_permissions(&connection.connection_id, granted_permissions)?;
                }
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    connect_response_outcome(&connection, secret),
                    None,
                ))
            }
        }
    }

    fn handle_base_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => {
                return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(response));
            }
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            RadrootsNostrSignerPreparedRequestEvaluation::Denied { reason, audit } => {
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    RadrootsNostrSignerHandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        Response::Error {
                            result: None,
                            error: reason,
                        },
                    ),
                    Some(audit),
                ))
            }
            RadrootsNostrSignerPreparedRequestEvaluation::Evaluation(evaluation) => {
                let evaluation = *evaluation;
                let audit = evaluation.audit.clone();
                let response_hint = match &evaluation.action {
                    RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                        Some(response_hint.clone())
                    }
                    _ => None,
                };
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    handled_request_for_action(&evaluation.connection, evaluation.action, || {
                        Ok(response_from_hint(
                            &evaluation.connection,
                            response_hint.expect("allowed action carries response hint"),
                        ))
                    })?,
                    Some(audit),
                ))
            }
        }
    }

    fn handle_sign_event_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RequestMessage,
        unsigned_event: ConnectUnsignedEvent,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => {
                return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(response));
            }
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            RadrootsNostrSignerPreparedRequestEvaluation::Denied { reason, audit } => {
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    RadrootsNostrSignerHandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        Response::Error {
                            result: None,
                            error: reason,
                        },
                    ),
                    Some(audit),
                ))
            }
            RadrootsNostrSignerPreparedRequestEvaluation::Evaluation(evaluation) => {
                let evaluation = *evaluation;
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    self.handled_request_for_authorized_action(
                        &evaluation.connection,
                        evaluation.action,
                        || Ok(self.codec.sign_event_response_value(unsigned_event)),
                    )?,
                    Some(evaluation.audit),
                ))
            }
        }
    }

    fn handle_crypto_request(
        &self,
        client_public_key: RadrootsNostrPublicKey,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerHandledRequestOutcome, RadrootsNostrSignerError> {
        let request = request_message.request.clone();
        let connection = match self.lookup_connection(client_public_key)? {
            Ok(connection) => connection,
            Err(response) => {
                return Ok(RadrootsNostrSignerHandledRequestOutcome::respond(response));
            }
        };

        match self.evaluate_request_with_policy(&connection, request_message)? {
            RadrootsNostrSignerPreparedRequestEvaluation::Denied { reason, audit } => {
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    RadrootsNostrSignerHandledRequest::respond_for_connection(
                        Some(connection.connection_id.clone()),
                        Response::Error {
                            result: None,
                            error: reason,
                        },
                    ),
                    Some(audit),
                ))
            }
            RadrootsNostrSignerPreparedRequestEvaluation::Evaluation(evaluation) => {
                let evaluation = *evaluation;
                Ok(RadrootsNostrSignerHandledRequestOutcome::new(
                    self.handled_request_for_authorized_action(
                        &evaluation.connection,
                        evaluation.action,
                        || Ok(self.codec.crypto_response_value(request)),
                    )?,
                    Some(evaluation.audit),
                ))
            }
        }
    }

    fn handled_request_for_evaluation(
        &self,
        request_message: RequestMessage,
        evaluation: RadrootsNostrSignerRequestEvaluation,
    ) -> Result<RadrootsNostrSignerHandledRequest, RadrootsNostrSignerError> {
        match request_message.request.clone() {
            Request::SignEvent(unsigned_event) => self.handled_request_for_authorized_action(
                &evaluation.connection,
                evaluation.action,
                || Ok(self.codec.sign_event_response_value(unsigned_event)),
            ),
            Request::Nip04Encrypt { .. }
            | Request::Nip04Decrypt { .. }
            | Request::Nip44Encrypt { .. }
            | Request::Nip44Decrypt { .. } => self.handled_request_for_authorized_action(
                &evaluation.connection,
                evaluation.action,
                || Ok(self.codec.crypto_response_value(request_message.request)),
            ),
            Request::GetPublicKey
            | Request::GetSessionCapability
            | Request::Ping
            | Request::SwitchRelays => {
                let response_hint = match &evaluation.action {
                    RadrootsNostrSignerRequestAction::Allowed { response_hint, .. } => {
                        Some(response_hint.clone())
                    }
                    _ => None,
                };
                self.handled_request_for_authorized_action(
                    &evaluation.connection,
                    evaluation.action,
                    || {
                        Ok(response_from_hint(
                            &evaluation.connection,
                            response_hint.expect("allowed action carries response hint"),
                        ))
                    },
                )
            }
            other => Ok(RadrootsNostrSignerHandledRequest::respond_for_connection(
                Some(evaluation.connection.connection_id.clone()),
                Response::Error {
                    result: None,
                    error: format!("method `{}` is not implemented yet", other.method()),
                },
            )),
        }
    }

    fn handled_request_for_authorized_action<F>(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
        action: RadrootsNostrSignerRequestAction,
        on_allowed: F,
    ) -> Result<RadrootsNostrSignerHandledRequest, RadrootsNostrSignerError>
    where
        F: FnOnce() -> Result<Response, RadrootsNostrSignerError>,
    {
        handled_request_for_action(connection, action, on_allowed)
    }

    fn evaluate_request_with_policy(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
        request_message: RequestMessage,
    ) -> Result<RadrootsNostrSignerPreparedRequestEvaluation, RadrootsNostrSignerError> {
        if let Some(reason) =
            self.policy
                .prepare_request(&self.backend, connection, &request_message)?
        {
            let audit = self.backend.record_request(
                &connection.connection_id,
                &request_message.id,
                request_message.request.method(),
                RadrootsNostrSignerRequestDecision::Denied,
                Some(reason.clone()),
            )?;
            return Ok(RadrootsNostrSignerPreparedRequestEvaluation::Denied { reason, audit });
        }

        Ok(RadrootsNostrSignerPreparedRequestEvaluation::Evaluation(
            Box::new(
                self.backend
                    .evaluate_request(&connection.connection_id, request_message)?,
            ),
        ))
    }

    fn lookup_connection(
        &self,
        client_public_key: RadrootsNostrPublicKey,
    ) -> Result<Result<RadrootsNostrSignerConnectionRecord, Response>, RadrootsNostrSignerError>
    {
        Ok(
            match self.backend.lookup_session(&client_public_key, None)? {
                RadrootsNostrSignerSessionLookup::Connection(connection) => Ok(*connection),
                RadrootsNostrSignerSessionLookup::None => Err(Response::Error {
                    result: None,
                    error: "unauthorized".to_owned(),
                }),
                RadrootsNostrSignerSessionLookup::Ambiguous(_) => Err(Response::Error {
                    result: None,
                    error: "ambiguous client sessions".to_owned(),
                }),
            },
        )
    }
}

impl RadrootsNostrSignerHandledRequest {
    pub fn respond(response: Response) -> Self {
        Self::respond_for_connection(None, response)
    }

    pub fn respond_for_connection(
        connection_id: Option<RadrootsNostrSignerConnectionId>,
        response: Response,
    ) -> Self {
        Self::Respond {
            response: Box::new(response),
            connection_id,
            consume_connect_secret_for: None,
        }
    }

    pub fn into_publish_parts(
        self,
    ) -> Option<(
        Response,
        Option<RadrootsNostrSignerConnectionId>,
        Option<RadrootsNostrSignerConnectionId>,
    )> {
        match self {
            Self::Respond {
                response,
                connection_id,
                consume_connect_secret_for,
            } => Some((*response, connection_id, consume_connect_secret_for)),
            Self::Ignore => None,
        }
    }
}

impl RadrootsNostrSignerHandledRequestOutcome {
    pub fn new(
        handled_request: RadrootsNostrSignerHandledRequest,
        audit: Option<RadrootsNostrSignerRequestAuditRecord>,
    ) -> Self {
        Self {
            handled_request,
            audit,
        }
    }

    pub fn respond(response: Response) -> Self {
        Self::new(RadrootsNostrSignerHandledRequest::respond(response), None)
    }

    pub fn ignore() -> Self {
        Self::new(RadrootsNostrSignerHandledRequest::Ignore, None)
    }
}

pub fn connect_response_outcome(
    connection: &RadrootsNostrSignerConnectionRecord,
    secret: Option<String>,
) -> RadrootsNostrSignerHandledRequest {
    let consume_connect_secret_for = secret.as_ref().map(|_| connection.connection_id.clone());
    RadrootsNostrSignerHandledRequest::Respond {
        response: Box::new(match secret {
            Some(secret) => Response::ConnectSecretEcho(secret),
            None => Response::ConnectAcknowledged,
        }),
        connection_id: Some(connection.connection_id.clone()),
        consume_connect_secret_for,
    }
}

pub fn response_from_hint(
    connection: &RadrootsNostrSignerConnectionRecord,
    hint: RadrootsNostrSignerRequestResponseHint,
) -> Response {
    match hint {
        RadrootsNostrSignerRequestResponseHint::Pong => Response::Pong,
        RadrootsNostrSignerRequestResponseHint::UserPublicKey(public_key) => {
            Response::UserPublicKey(public_key)
        }
        RadrootsNostrSignerRequestResponseHint::RemoteSessionCapability(capability) => {
            Response::RemoteSessionCapability(capability)
        }
        RadrootsNostrSignerRequestResponseHint::RelayList(relays) => match connection
            .relays
            .iter()
            .map(|relay| radroots_nostr_connect::uri::RelayUrl::parse(&relay.to_string()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(connection_relays) if relays == connection_relays => Response::RelayList(relays),
            Ok(connection_relays) => Response::RelayList(connection_relays),
            Err(error) => Response::Error {
                result: None,
                error: format!("invalid connection relay state: {error}"),
            },
        },
        RadrootsNostrSignerRequestResponseHint::None => Response::Error {
            result: None,
            error: "request evaluation did not provide a response hint".to_owned(),
        },
    }
}

fn nostr_public_key(
    public_key: radroots_identity::PublicKey,
) -> Result<RadrootsNostrPublicKey, RadrootsNostrSignerError> {
    radroots_nostr::key::public_key_to_nostr(public_key).map_err(Into::into)
}

pub fn handled_request_for_action<F>(
    connection: &RadrootsNostrSignerConnectionRecord,
    action: RadrootsNostrSignerRequestAction,
    on_allowed: F,
) -> Result<RadrootsNostrSignerHandledRequest, RadrootsNostrSignerError>
where
    F: FnOnce() -> Result<Response, RadrootsNostrSignerError>,
{
    Ok(match action {
        RadrootsNostrSignerRequestAction::Denied { reason } => {
            RadrootsNostrSignerHandledRequest::respond_for_connection(
                Some(connection.connection_id.clone()),
                Response::Error {
                    result: None,
                    error: reason,
                },
            )
        }
        RadrootsNostrSignerRequestAction::Challenged { auth_challenge, .. } => {
            RadrootsNostrSignerHandledRequest::respond_for_connection(
                Some(connection.connection_id.clone()),
                Response::AuthUrl(auth_challenge.auth_url),
            )
        }
        RadrootsNostrSignerRequestAction::Allowed { .. } => {
            RadrootsNostrSignerHandledRequest::respond_for_connection(
                Some(connection.connection_id.clone()),
                on_allowed()?,
            )
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RadrootsNostrSignerHandledRequest, RadrootsNostrSignerHandledRequestOutcome,
        RadrootsNostrSignerNip46ConnectDecision, RadrootsNostrSignerNip46Handler,
        RadrootsNostrSignerNip46Policy, RadrootsNostrSignerNip46Signer,
    };
    use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
    use crate::signer::backend::{RadrootsNostrEmbeddedSignerBackend, RadrootsNostrSignerBackend};
    use crate::signer::error::RadrootsNostrSignerError;
    use crate::signer::evaluation::{
        RadrootsNostrSignerRequestAction, RadrootsNostrSignerRequestResponseHint,
    };
    use crate::signer::manager::RadrootsNostrSignerManager;
    use crate::signer::model::{
        RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthChallenge,
        RadrootsNostrSignerAuthState, RadrootsNostrSignerConnectionDraft,
        RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerPendingRequest,
        RadrootsNostrSignerStoreState,
    };
    use crate::signer::store::RadrootsNostrSignerStore;
    use crate::signer::test_support::{
        fixture_alice_identity, fixture_carol_public_key, primary_relay,
    };
    use nostr::PublicKey as RadrootsNostrPublicKey;
    use nostr::{JsonUtil, Keys, SecretKey, Timestamp, UnsignedEvent};
    use radroots_identity::PublicKey as IdentityPublicKey;
    use radroots_nostr::event::Event as RadrootsNostrEvent;
    use radroots_nostr::event::GenericBuilder;
    use radroots_nostr::event::Kind as RadrootsNostrKind;
    use radroots_nostr::tag::TagKind as RadrootsNostrTagKind;
    use radroots_nostr_connect::uri::RelayUrl as ConnectRelayUrl;
    use radroots_nostr_connect::{
        Method, Permission, Request, Response,
        message::{
            RPC_KIND, RemoteSessionCapability, RequestMessage,
            UnsignedEvent as ConnectUnsignedEvent,
        },
        permission::Permissions,
    };
    use std::sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone)]
    struct TestSigner {
        signer_identity: Keys,
        user_identity: Keys,
        sign_events: bool,
        fail_crypto: bool,
    }

    #[derive(Clone)]
    struct TestPolicy {
        connect_decision: RadrootsNostrSignerNip46ConnectDecision,
        rate_limit_reason: Option<&'static str>,
        approval_requirement: Option<RadrootsNostrSignerApprovalRequirement>,
        prepare_denial: Option<&'static str>,
    }

    #[derive(Clone, Default)]
    struct ToggleSaveStore {
        state: Arc<RwLock<RadrootsNostrSignerStoreState>>,
        fail_saves: Arc<AtomicBool>,
    }

    impl RadrootsNostrSignerStore for ToggleSaveStore {
        fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
            self.state
                .read()
                .map(|state| state.clone())
                .map_err(|_| RadrootsNostrSignerError::Store("test store lock poisoned".into()))
        }

        fn save(
            &self,
            state: &RadrootsNostrSignerStoreState,
        ) -> Result<(), RadrootsNostrSignerError> {
            if self.fail_saves.load(Ordering::SeqCst) {
                return Err(RadrootsNostrSignerError::Store(
                    "test store save failure".into(),
                ));
            }
            self.state
                .write()
                .map(|mut stored| *stored = state.clone())
                .map_err(|_| RadrootsNostrSignerError::Store("test store lock poisoned".into()))
        }
    }

    impl Default for TestPolicy {
        fn default() -> Self {
            Self {
                connect_decision: RadrootsNostrSignerNip46ConnectDecision::Allow,
                rate_limit_reason: None,
                approval_requirement: Some(RadrootsNostrSignerApprovalRequirement::NotRequired),
                prepare_denial: None,
            }
        }
    }

    impl RadrootsNostrSignerNip46Signer for TestSigner {
        fn signer_public_key_hex(&self) -> String {
            self.signer_identity.public_key().to_hex()
        }

        fn decrypt_request(
            &self,
            _client_public_key: &RadrootsNostrPublicKey,
            ciphertext: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            Ok(ciphertext.to_owned())
        }

        fn encrypt_response(
            &self,
            _client_public_key: &RadrootsNostrPublicKey,
            payload: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            Ok(payload.to_owned())
        }

        fn user_identity(&self) -> PublicIdentity {
            public_identity_from_keys(&self.user_identity)
        }

        fn sign_user_event(
            &self,
            unsigned_event: UnsignedEvent,
        ) -> Result<RadrootsNostrEvent, RadrootsNostrSignerError> {
            if self.sign_events {
                return unsigned_event
                    .sign_with_keys(&self.user_identity)
                    .map_err(|error| RadrootsNostrSignerError::Sign(error.to_string()));
            }
            Err(RadrootsNostrSignerError::Sign(
                "test signer does not sign events".to_owned(),
            ))
        }

        fn nip04_encrypt(
            &self,
            _public_key: &RadrootsNostrPublicKey,
            plaintext: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            if self.fail_crypto {
                return Err(RadrootsNostrSignerError::Sign(
                    "test crypto failure".to_owned(),
                ));
            }
            Ok(plaintext.to_owned())
        }

        fn nip04_decrypt(
            &self,
            _public_key: &RadrootsNostrPublicKey,
            ciphertext: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            if self.fail_crypto {
                return Err(RadrootsNostrSignerError::Sign(
                    "test crypto failure".to_owned(),
                ));
            }
            Ok(ciphertext.to_owned())
        }

        fn nip44_encrypt(
            &self,
            _public_key: &RadrootsNostrPublicKey,
            plaintext: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            if self.fail_crypto {
                return Err(RadrootsNostrSignerError::Sign(
                    "test crypto failure".to_owned(),
                ));
            }
            Ok(plaintext.to_owned())
        }

        fn nip44_decrypt(
            &self,
            _public_key: &RadrootsNostrPublicKey,
            ciphertext: &str,
        ) -> Result<String, RadrootsNostrSignerError> {
            if self.fail_crypto {
                return Err(RadrootsNostrSignerError::Sign(
                    "test crypto failure".to_owned(),
                ));
            }
            Ok(ciphertext.to_owned())
        }
    }

    impl<B: RadrootsNostrSignerBackend> RadrootsNostrSignerNip46Policy<B> for TestPolicy {
        fn connect_decision(
            &self,
            _client_public_key: &RadrootsNostrPublicKey,
        ) -> RadrootsNostrSignerNip46ConnectDecision {
            self.connect_decision
        }

        fn connect_rate_limit_denied_reason(
            &self,
            _client_public_key: &RadrootsNostrPublicKey,
        ) -> Option<String> {
            self.rate_limit_reason.map(ToOwned::to_owned)
        }

        fn approval_requirement_for_client(
            &self,
            _client_public_key: &RadrootsNostrPublicKey,
        ) -> Option<RadrootsNostrSignerApprovalRequirement> {
            self.approval_requirement
        }

        fn filtered_requested_permissions(
            &self,
            requested_permissions: &Permissions,
        ) -> Permissions {
            requested_permissions.clone()
        }

        fn auto_granted_permissions(&self, requested_permissions: &Permissions) -> Permissions {
            requested_permissions.clone()
        }

        fn prepare_request(
            &self,
            _backend: &B,
            _connection: &crate::signer::model::RadrootsNostrSignerConnectionRecord,
            _request_message: &RequestMessage,
        ) -> Result<Option<String>, RadrootsNostrSignerError> {
            Ok(self.prepare_denial.map(ToOwned::to_owned))
        }
    }

    fn test_signer() -> TestSigner {
        test_signer_with_options(false, false)
    }

    fn keys_from_secret(secret_key_hex: &str) -> Keys {
        Keys::new(SecretKey::from_hex(secret_key_hex).expect("secret key"))
    }

    fn public_identity_from_keys(keys: &Keys) -> PublicIdentity {
        PublicIdentity::new(keys.public_key()).expect("identity public key")
    }

    fn connect_public_key(public_key: RadrootsNostrPublicKey) -> IdentityPublicKey {
        radroots_nostr::key::public_key_from_nostr(public_key).expect("identity public key")
    }

    fn connect_relay(relay: nostr::RelayUrl) -> ConnectRelayUrl {
        ConnectRelayUrl::parse(&relay.to_string()).expect("connect relay")
    }

    fn test_signer_with_options(sign_events: bool, fail_crypto: bool) -> TestSigner {
        TestSigner {
            signer_identity: keys_from_secret(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            user_identity: keys_from_secret(
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
            sign_events,
            fail_crypto,
        }
    }

    fn embedded_backend() -> RadrootsNostrEmbeddedSignerBackend {
        RadrootsNostrEmbeddedSignerBackend::new(
            crate::signer::manager::RadrootsNostrSignerManager::new_in_memory(),
            test_signer().signer_identity.clone(),
        )
        .expect("embedded backend")
    }

    fn handler_with_backend(
        backend: RadrootsNostrEmbeddedSignerBackend,
    ) -> RadrootsNostrSignerNip46Handler<RadrootsNostrEmbeddedSignerBackend, TestPolicy, TestSigner>
    {
        handler_with_policy(backend, TestPolicy::default())
    }

    fn handler_with_policy(
        backend: RadrootsNostrEmbeddedSignerBackend,
        policy: TestPolicy,
    ) -> RadrootsNostrSignerNip46Handler<RadrootsNostrEmbeddedSignerBackend, TestPolicy, TestSigner>
    {
        RadrootsNostrSignerNip46Handler::new(backend, policy, vec![primary_relay()], test_signer())
    }

    fn connect_request(secret: Option<&str>) -> RequestMessage {
        connect_request_with_permissions(secret, vec![Permission::new(Method::Nip04Encrypt)])
    }

    fn connect_request_with_permissions(
        secret: Option<&str>,
        permissions: Vec<Permission>,
    ) -> RequestMessage {
        let signer_public_key = test_signer().signer_identity.public_key();
        RequestMessage::new(
            "req-connect",
            Request::Connect {
                remote_signer_public_key: connect_public_key(signer_public_key),
                secret: secret.map(ToOwned::to_owned),
                requested_permissions: permissions.into(),
                client_metadata: None,
            },
        )
    }

    fn all_runtime_permissions() -> Vec<Permission> {
        vec![
            Permission::new(Method::SignEvent),
            Permission::new(Method::Nip04Encrypt),
            Permission::new(Method::Nip04Decrypt),
            Permission::new(Method::Nip44Encrypt),
            Permission::new(Method::Nip44Decrypt),
            Permission::new(Method::SwitchRelays),
        ]
    }

    fn request_message(id: &str, request: Request) -> RequestMessage {
        RequestMessage::new(id, request)
    }

    fn unsigned_user_event(kind: u16) -> UnsignedEvent {
        serde_json::from_value(serde_json::json!({
            "pubkey": test_signer().user_identity.public_key().to_hex(),
            "created_at": Timestamp::from(1).as_secs(),
            "kind": kind,
            "tags": [],
            "content": "hello",
        }))
        .expect("unsigned event")
    }

    fn connect_unsigned_event(kind: u16) -> ConnectUnsignedEvent {
        let event = unsigned_user_event(kind);
        ConnectUnsignedEvent::from_json(&event.as_json()).expect("connect unsigned event")
    }

    fn registered_connection(
        backend: &RadrootsNostrEmbeddedSignerBackend,
        client_public_key: &RadrootsNostrPublicKey,
    ) -> RadrootsNostrSignerConnectionRecord {
        backend
            .find_connections_by_client_public_key(client_public_key)
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection")
    }

    fn connect_with_permissions(
        handler: &RadrootsNostrSignerNip46Handler<
            RadrootsNostrEmbeddedSignerBackend,
            TestPolicy,
            TestSigner,
        >,
        client_public_key: RadrootsNostrPublicKey,
        permissions: Vec<Permission>,
    ) {
        let outcome = handler
            .handle_request(
                client_public_key,
                connect_request_with_permissions(None, permissions),
            )
            .expect("connect");
        assert!(matches!(
            outcome.handled_request,
            RadrootsNostrSignerHandledRequest::Respond { .. }
        ));
    }

    fn response_from_outcome(outcome: RadrootsNostrSignerHandledRequestOutcome) -> Response {
        match outcome.handled_request {
            RadrootsNostrSignerHandledRequest::Respond { response, .. } => *response,
            other => panic!("unexpected handled request: {other:?}"),
        }
    }

    #[test]
    fn codec_and_handler_facades_cover_rpc_event_surface() {
        let codec = super::RadrootsNostrSignerNip46Codec::new(test_signer());
        let _ = codec.filter().expect("codec filter");
        let client_public_key = fixture_carol_public_key();
        let request = request_message("req-parse", Request::Ping);
        let raw = serde_json::to_string(&request).expect("serialize request");
        let event = GenericBuilder::new(RadrootsNostrKind::Custom(RPC_KIND), raw)
            .sign_with_keys(&Keys::generate())
            .expect("sign request event");

        let parsed = codec.parse_request_event(&event).expect("parse request");
        assert_eq!(parsed, request);

        let response_builder = codec
            .build_response_event(client_public_key, "req-parse", Response::Pong)
            .expect("response builder");
        let response_event = response_builder
            .sign_with_keys(&Keys::generate())
            .expect("sign response event");
        assert_eq!(response_event.kind, RadrootsNostrKind::Custom(RPC_KIND));
        assert!(response_event.tags.iter().any(|tag| {
            tag.kind() == RadrootsNostrTagKind::p()
                && tag.content() == Some(client_public_key.to_hex().as_str())
        }));

        let handler = handler_with_backend(embedded_backend());
        let _ = handler.filter().expect("handler filter");
        assert_eq!(
            handler.parse_request_event(&event).expect("handler parse"),
            request
        );
        let handler_event = handler
            .build_response_event(
                client_public_key,
                "req-handler",
                Response::ConnectAcknowledged,
            )
            .expect("handler response")
            .sign_with_keys(&Keys::generate())
            .expect("sign handler response event");
        assert_eq!(handler_event.kind, RadrootsNostrKind::Custom(RPC_KIND));
    }

    #[test]
    fn codec_crypto_and_signing_responses_cover_method_matrix() {
        let codec = super::RadrootsNostrSignerNip46Codec::new(test_signer());
        let client_public_key = fixture_carol_public_key();

        assert_eq!(
            codec
                .crypto_response(Request::Nip04Encrypt {
                    public_key: connect_public_key(client_public_key),
                    plaintext: "plain".to_owned(),
                })
                .expect("nip04 encrypt"),
            Response::Nip04Encrypt("plain".to_owned())
        );
        assert_eq!(
            codec
                .crypto_response(Request::Nip04Decrypt {
                    public_key: connect_public_key(client_public_key),
                    ciphertext: "cipher".to_owned(),
                })
                .expect("nip04 decrypt"),
            Response::Nip04Decrypt("cipher".to_owned())
        );
        assert_eq!(
            codec
                .crypto_response(Request::Nip44Encrypt {
                    public_key: connect_public_key(client_public_key),
                    plaintext: "plain44".to_owned(),
                })
                .expect("nip44 encrypt"),
            Response::Nip44Encrypt("plain44".to_owned())
        );
        assert_eq!(
            codec
                .crypto_response(Request::Nip44Decrypt {
                    public_key: connect_public_key(client_public_key),
                    ciphertext: "cipher44".to_owned(),
                })
                .expect("nip44 decrypt"),
            Response::Nip44Decrypt("cipher44".to_owned())
        );

        let non_crypto = codec
            .crypto_response(Request::Ping)
            .expect("non crypto response");
        assert!(matches!(non_crypto, Response::Error { .. }));

        let failing_codec =
            super::RadrootsNostrSignerNip46Codec::new(test_signer_with_options(false, true));
        for request in [
            Request::Nip04Encrypt {
                public_key: connect_public_key(client_public_key),
                plaintext: "plain".to_owned(),
            },
            Request::Nip04Decrypt {
                public_key: connect_public_key(client_public_key),
                ciphertext: "cipher".to_owned(),
            },
            Request::Nip44Encrypt {
                public_key: connect_public_key(client_public_key),
                plaintext: "plain44".to_owned(),
            },
            Request::Nip44Decrypt {
                public_key: connect_public_key(client_public_key),
                ciphertext: "cipher44".to_owned(),
            },
        ] {
            assert!(matches!(
                failing_codec
                    .crypto_response(request)
                    .expect("failing crypto response"),
                Response::Error { .. }
            ));
        }

        let signing = codec
            .sign_event_response(unsigned_user_event(1))
            .expect("signing response");
        match signing {
            Response::Error { error, .. } => {
                assert!(error.contains("failed to sign event"));
            }
            other => panic!("unexpected sign response: {other:?}"),
        }

        let signed =
            super::RadrootsNostrSignerNip46Codec::new(test_signer_with_options(true, false))
                .sign_event_response(unsigned_user_event(1))
                .expect("signed response");
        assert!(matches!(signed, Response::SignedEvent(_)));
    }

    #[test]
    fn handler_connect_policy_paths_cover_registration_branches() {
        let client_public_key = fixture_carol_public_key();

        let rate_limited = handler_with_policy(
            embedded_backend(),
            TestPolicy {
                rate_limit_reason: Some("slow down"),
                ..TestPolicy::default()
            },
        )
        .handle_request(client_public_key, connect_request(None))
        .expect("rate limit outcome");
        assert_eq!(
            response_from_outcome(rate_limited),
            Response::Error {
                result: None,
                error: "slow down".to_owned(),
            }
        );

        let denied_registration = handler_with_policy(
            embedded_backend(),
            TestPolicy {
                approval_requirement: None,
                ..TestPolicy::default()
            },
        )
        .handle_request(client_public_key, connect_request(None))
        .expect("registration denial");
        assert_eq!(
            response_from_outcome(denied_registration),
            Response::Error {
                result: None,
                error: "client public key denied by policy".to_owned(),
            }
        );

        let approval_backend = embedded_backend();
        let approval_handler = handler_with_policy(
            approval_backend.clone(),
            TestPolicy {
                approval_requirement: Some(RadrootsNostrSignerApprovalRequirement::ExplicitUser),
                ..TestPolicy::default()
            },
        );
        let _ = approval_handler
            .handle_request(client_public_key, connect_request(None))
            .expect("approval connect");
        let approval_connection = registered_connection(&approval_backend, &client_public_key);
        assert_eq!(
            approval_connection.approval_requirement,
            RadrootsNostrSignerApprovalRequirement::ExplicitUser
        );
    }

    #[test]
    fn handler_connect_existing_connection_paths_cover_policy_edges() {
        let client_public_key = fixture_carol_public_key();
        let secret = "connect-secret";
        let existing_backend = embedded_backend();
        let existing_handler = handler_with_backend(existing_backend.clone());

        let first = existing_handler
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("initial connect");
        assert_eq!(
            response_from_outcome(first),
            Response::ConnectSecretEcho(secret.to_owned())
        );
        let existing = existing_handler
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("existing connect by secret");
        assert_eq!(
            response_from_outcome(existing),
            Response::ConnectSecretEcho(secret.to_owned())
        );

        let denied_backend = embedded_backend();
        let denied_handler = handler_with_backend(denied_backend.clone());
        let _ = denied_handler
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("denied seed connect");
        let denying_handler = handler_with_policy(
            denied_backend,
            TestPolicy {
                connect_decision: RadrootsNostrSignerNip46ConnectDecision::Deny,
                ..TestPolicy::default()
            },
        );
        let denied = denying_handler
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("existing connect denied");
        assert_eq!(
            response_from_outcome(denied),
            Response::Error {
                result: None,
                error: "client public key denied by policy".to_owned(),
            }
        );
    }

    #[test]
    fn handler_request_paths_cover_base_sign_crypto_denied_and_challenged() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let client_public_key = fixture_carol_public_key();
        connect_with_permissions(&handler, client_public_key, all_runtime_permissions());

        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message("req-pubkey", Request::GetPublicKey),
                    )
                    .expect("pubkey")
            ),
            Response::UserPublicKey(_)
        ));
        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message("req-capability", Request::GetSessionCapability,),
                    )
                    .expect("capability")
            ),
            Response::RemoteSessionCapability(_)
        ));
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message("req-relays", Request::SwitchRelays),
                    )
                    .expect("relays")
            ),
            Response::RelayList(vec![connect_relay(primary_relay())])
        );
        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message("req-sign", Request::SignEvent(connect_unsigned_event(1)),),
                    )
                    .expect("sign")
            ),
            Response::Error { .. }
        ));
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message(
                            "req-nip04-decrypt",
                            Request::Nip04Decrypt {
                                public_key: connect_public_key(client_public_key),
                                ciphertext: "cipher".to_owned(),
                            },
                        ),
                    )
                    .expect("nip04 decrypt")
            ),
            Response::Nip04Decrypt("cipher".to_owned())
        );
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message(
                            "req-nip44-encrypt",
                            Request::Nip44Encrypt {
                                public_key: connect_public_key(client_public_key),
                                plaintext: "plain".to_owned(),
                            },
                        ),
                    )
                    .expect("nip44 encrypt")
            ),
            Response::Nip44Encrypt("plain".to_owned())
        );

        let unimplemented = handler
            .handle_request(
                client_public_key,
                request_message(
                    "req-custom",
                    Request::Custom {
                        method: Method::custom("publish_note").expect("valid custom NIP-46 method"),
                        params: vec![],
                    },
                ),
            )
            .expect("custom");
        assert!(matches!(
            response_from_outcome(unimplemented),
            Response::Error { .. }
        ));

        let limited_backend = embedded_backend();
        let limited_handler = handler_with_backend(limited_backend);
        connect_with_permissions(
            &limited_handler,
            client_public_key,
            vec![Permission::new(Method::Nip04Encrypt)],
        );
        let denied_crypto = limited_handler
            .handle_request(
                client_public_key,
                request_message(
                    "req-denied",
                    Request::Nip04Decrypt {
                        public_key: connect_public_key(client_public_key),
                        ciphertext: "cipher".to_owned(),
                    },
                ),
            )
            .expect("denied crypto");
        assert!(matches!(
            response_from_outcome(denied_crypto),
            Response::Error { .. }
        ));

        let denied_backend = embedded_backend();
        let open_handler = handler_with_backend(denied_backend.clone());
        connect_with_permissions(&open_handler, client_public_key, all_runtime_permissions());
        let denying_handler = handler_with_policy(
            denied_backend,
            TestPolicy {
                prepare_denial: Some("policy blocked"),
                ..TestPolicy::default()
            },
        );
        let denied_base = denying_handler
            .handle_request(
                client_public_key,
                request_message("req-policy-denied", Request::Ping),
            )
            .expect("policy denied");
        assert!(matches!(
            response_from_outcome(denied_base),
            Response::Error { .. }
        ));
        let denied_sign = denying_handler
            .handle_request(
                client_public_key,
                request_message(
                    "req-policy-denied-sign",
                    Request::SignEvent(connect_unsigned_event(1)),
                ),
            )
            .expect("policy denied sign");
        assert!(matches!(
            response_from_outcome(denied_sign),
            Response::Error { .. }
        ));
        let denied_crypto = denying_handler
            .handle_request(
                client_public_key,
                request_message(
                    "req-policy-denied-crypto",
                    Request::Nip44Encrypt {
                        public_key: connect_public_key(client_public_key),
                        plaintext: "plain".to_owned(),
                    },
                ),
            )
            .expect("policy denied crypto");
        assert!(matches!(
            response_from_outcome(denied_crypto),
            Response::Error { .. }
        ));

        let challenge_backend = embedded_backend();
        let challenge_handler = handler_with_backend(challenge_backend.clone());
        connect_with_permissions(
            &challenge_handler,
            client_public_key,
            all_runtime_permissions(),
        );
        let challenged = registered_connection(&challenge_backend, &client_public_key);
        challenge_backend
            .manager()
            .require_auth_challenge(&challenged.connection_id, "https://example.test/auth")
            .expect("require challenge");
        let auth_url = challenge_handler
            .handle_request(
                client_public_key,
                request_message("req-challenge", Request::Ping),
            )
            .expect("challenge");
        assert_eq!(
            response_from_outcome(auth_url),
            Response::AuthUrl("https://example.test/auth".to_owned())
        );
    }

    #[test]
    fn policy_denial_propagates_audit_persistence_failures() {
        let store = ToggleSaveStore::default();
        let manager = RadrootsNostrSignerManager::new(Arc::new(store.clone()))
            .expect("manager with toggle store");
        let backend =
            RadrootsNostrEmbeddedSignerBackend::new(manager, test_signer().signer_identity.clone())
                .expect("embedded backend");
        let client_public_key = fixture_carol_public_key();
        connect_with_permissions(
            &handler_with_backend(backend.clone()),
            client_public_key,
            Vec::new(),
        );
        store.fail_saves.store(true, Ordering::SeqCst);

        let handler = handler_with_policy(
            backend,
            TestPolicy {
                prepare_denial: Some("policy blocked"),
                ..TestPolicy::default()
            },
        );
        let error = handler
            .handle_request(
                client_public_key,
                request_message("req-audit-save", Request::Ping),
            )
            .expect_err("audit persistence failure");
        assert!(error.to_string().contains("test store save failure"));
    }

    #[test]
    fn handler_rejects_unauthorized_base_sign_and_crypto_requests() {
        let handler = handler_with_backend(embedded_backend());
        let client_public_key = fixture_carol_public_key();

        for request in [
            Request::Ping,
            Request::SignEvent(connect_unsigned_event(1)),
            Request::Nip04Decrypt {
                public_key: connect_public_key(client_public_key),
                ciphertext: "cipher".to_owned(),
            },
        ] {
            let outcome = handler
                .handle_request(
                    client_public_key,
                    request_message("req-unauthorized", request),
                )
                .expect("unauthorized request");
            assert_eq!(
                response_from_outcome(outcome),
                Response::Error {
                    result: None,
                    error: "unauthorized".to_owned(),
                }
            );
        }
    }

    #[test]
    fn handler_allowed_sign_and_crypto_requests_execute_codec_paths() {
        let backend = embedded_backend();
        let handler = RadrootsNostrSignerNip46Handler::new(
            backend,
            TestPolicy::default(),
            vec![primary_relay()],
            test_signer_with_options(true, false),
        );
        let client_public_key = fixture_carol_public_key();
        connect_with_permissions(
            &handler,
            client_public_key,
            vec![
                Permission::with_parameter(Method::SignEvent, "kind:1"),
                Permission::new(Method::Nip04Encrypt),
            ],
        );

        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message(
                            "req-allowed-sign",
                            Request::SignEvent(connect_unsigned_event(1)),
                        ),
                    )
                    .expect("allowed sign")
            ),
            Response::SignedEvent(_)
        ));
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_request(
                        client_public_key,
                        request_message(
                            "req-allowed-nip04-encrypt",
                            Request::Nip04Encrypt {
                                public_key: connect_public_key(client_public_key),
                                plaintext: "plain".to_owned(),
                            },
                        ),
                    )
                    .expect("allowed nip04 encrypt")
            ),
            Response::Nip04Encrypt("plain".to_owned())
        );
    }

    #[test]
    fn handler_authorized_evaluation_facade_covers_request_variants() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let client_public_key = fixture_carol_public_key();
        connect_with_permissions(&handler, client_public_key, all_runtime_permissions());
        let connection = registered_connection(&backend, &client_public_key);

        let base = request_message("req-eval-ping", Request::Ping);
        let base_eval = backend
            .evaluate_request(&connection.connection_id, base.clone())
            .expect("base evaluation");
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_authorized_request_evaluation(base, base_eval)
                    .expect("base authorized")
            ),
            Response::Pong
        );
        let mut denied_base_eval = backend
            .evaluate_request(
                &connection.connection_id,
                request_message("req-eval-denied-ping", Request::Ping),
            )
            .expect("denied base evaluation");
        denied_base_eval.action = RadrootsNostrSignerRequestAction::Denied {
            reason: "blocked".to_owned(),
        };
        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_authorized_request_evaluation(
                        request_message("req-eval-denied-ping", Request::Ping),
                        denied_base_eval,
                    )
                    .expect("denied base authorized")
            ),
            Response::Error { .. }
        ));

        let crypto = request_message(
            "req-eval-crypto",
            Request::Nip44Decrypt {
                public_key: connect_public_key(client_public_key),
                ciphertext: "sealed".to_owned(),
            },
        );
        let crypto_eval = backend
            .evaluate_request(&connection.connection_id, crypto.clone())
            .expect("crypto evaluation");
        assert_eq!(
            response_from_outcome(
                handler
                    .handle_authorized_request_evaluation(crypto, crypto_eval)
                    .expect("crypto authorized")
            ),
            Response::Nip44Decrypt("sealed".to_owned())
        );

        let sign = request_message(
            "req-eval-sign",
            Request::SignEvent(connect_unsigned_event(1)),
        );
        let sign_eval = backend
            .evaluate_request(&connection.connection_id, sign.clone())
            .expect("sign evaluation");
        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_authorized_request_evaluation(sign, sign_eval)
                    .expect("sign authorized")
            ),
            Response::Error { .. }
        ));

        let custom = request_message(
            "req-eval-custom",
            Request::Custom {
                method: Method::custom("do_work").expect("valid custom NIP-46 method"),
                params: vec![],
            },
        );
        let custom_eval = backend
            .evaluate_request(&connection.connection_id, custom.clone())
            .expect("custom evaluation");
        assert!(matches!(
            response_from_outcome(
                handler
                    .handle_authorized_request_evaluation(custom, custom_eval)
                    .expect("custom authorized")
            ),
            Response::Error { .. }
        ));
    }

    #[test]
    fn standalone_response_helpers_cover_publish_parts_and_hints() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let client_public_key = fixture_carol_public_key();
        connect_with_permissions(&handler, client_public_key, all_runtime_permissions());
        let connection = registered_connection(&backend, &client_public_key);

        let parts = super::connect_response_outcome(&connection, Some("secret".to_owned()))
            .into_publish_parts()
            .expect("publish parts");
        assert_eq!(parts.0, Response::ConnectSecretEcho("secret".to_owned()));
        assert_eq!(parts.1, Some(connection.connection_id.clone()));
        assert_eq!(parts.2, Some(connection.connection_id.clone()));
        assert!(
            RadrootsNostrSignerHandledRequest::Ignore
                .into_publish_parts()
                .is_none()
        );
        assert!(
            RadrootsNostrSignerHandledRequest::respond(Response::Pong)
                .into_publish_parts()
                .is_some()
        );
        assert_eq!(
            response_from_outcome(RadrootsNostrSignerHandledRequestOutcome::respond(
                Response::Pong,
            )),
            Response::Pong
        );

        assert_eq!(
            super::response_from_hint(
                &connection,
                RadrootsNostrSignerRequestResponseHint::UserPublicKey(connect_public_key(
                    client_public_key,
                )),
            ),
            Response::UserPublicKey(connect_public_key(client_public_key))
        );
        let capability = RemoteSessionCapability {
            user_public_key: connect_public_key(client_public_key),
            relays: vec![connect_relay(primary_relay())],
            permissions: all_runtime_permissions().into(),
        };
        assert_eq!(
            super::response_from_hint(
                &connection,
                RadrootsNostrSignerRequestResponseHint::RemoteSessionCapability(capability.clone(),),
            ),
            Response::RemoteSessionCapability(capability)
        );
        assert_eq!(
            super::response_from_hint(
                &connection,
                RadrootsNostrSignerRequestResponseHint::RelayList(vec![connect_relay(
                    primary_relay(),
                )]),
            ),
            Response::RelayList(vec![connect_relay(primary_relay())])
        );
        assert_eq!(
            super::response_from_hint(
                &connection,
                RadrootsNostrSignerRequestResponseHint::RelayList(Vec::new()),
            ),
            Response::RelayList(vec![connect_relay(primary_relay())])
        );
        assert!(matches!(
            super::response_from_hint(&connection, RadrootsNostrSignerRequestResponseHint::None),
            Response::Error { .. }
        ));

        let denied = super::handled_request_for_action(
            &connection,
            RadrootsNostrSignerRequestAction::Denied {
                reason: "blocked".to_owned(),
            },
            || Ok(Response::Pong),
        )
        .expect("denied action");
        assert!(matches!(
            denied,
            RadrootsNostrSignerHandledRequest::Respond { .. }
        ));

        let allowed = super::handled_request_for_action(
            &connection,
            RadrootsNostrSignerRequestAction::Allowed {
                required_permission: None,
                response_hint: RadrootsNostrSignerRequestResponseHint::Pong,
            },
            || Ok(Response::Pong),
        )
        .expect("allowed action");
        assert!(matches!(
            allowed,
            RadrootsNostrSignerHandledRequest::Respond { .. }
        ));

        let challenged = super::handled_request_for_action(
            &connection,
            RadrootsNostrSignerRequestAction::Challenged {
                auth_challenge: RadrootsNostrSignerAuthChallenge::new(
                    "https://example.test/auth",
                    1,
                )
                .expect("challenge"),
                pending_request: RadrootsNostrSignerPendingRequest::new(
                    request_message("req-pending", Request::Ping),
                    1,
                )
                .expect("pending"),
            },
            || Ok(Response::Pong),
        )
        .expect("challenged action");
        assert!(matches!(
            challenged,
            RadrootsNostrSignerHandledRequest::Respond { .. }
        ));
    }

    #[test]
    fn handler_reports_ambiguous_client_sessions() {
        let backend = embedded_backend();
        let client_public_key = fixture_carol_public_key();
        backend
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                client_public_key,
                test_signer().user_identity(),
            ))
            .expect("first connection");
        backend
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                client_public_key,
                public_identity_from_keys(&keys_from_secret(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )),
            ))
            .expect("second connection");

        let outcome = handler_with_backend(backend)
            .handle_request(
                client_public_key,
                request_message("req-ambiguous", Request::Ping),
            )
            .expect("ambiguous request");
        assert_eq!(
            response_from_outcome(outcome),
            Response::Error {
                result: None,
                error: "ambiguous client sessions".to_owned(),
            }
        );
    }

    #[test]
    fn handler_registers_connections_and_returns_audit_for_authorized_requests() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let client_public_key = fixture_carol_public_key();

        let connect = handler
            .handle_request(client_public_key, connect_request(None))
            .expect("connect outcome");
        assert!(connect.audit.is_none());
        match connect.handled_request {
            RadrootsNostrSignerHandledRequest::Respond { response, .. } => {
                assert_eq!(*response, Response::ConnectAcknowledged);
            }
            other => panic!("unexpected connect outcome: {other:?}"),
        }

        let ping = handler
            .handle_request(
                client_public_key,
                RequestMessage::new("req-ping", Request::Ping),
            )
            .expect("ping outcome");
        match ping.handled_request {
            RadrootsNostrSignerHandledRequest::Respond { response, .. } => {
                assert_eq!(*response, Response::Pong);
            }
            other => panic!("unexpected ping outcome: {other:?}"),
        }
        let audit = ping.audit.expect("audit");
        assert_eq!(audit.request_id.as_str(), "req-ping");
        assert_eq!(
            backend
                .find_connections_by_client_public_key(&client_public_key)
                .expect("connections")
                .len(),
            1
        );
    }

    #[test]
    fn handler_ignores_reused_consumed_connect_secrets() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let client_public_key = fixture_carol_public_key();
        let secret = "connect-secret";

        let first = handler
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("first connect");
        assert!(first.audit.is_none());

        let connection = backend
            .find_connections_by_client_public_key(&client_public_key)
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection");
        backend
            .mark_connect_secret_consumed(&connection.connection_id)
            .expect("consume secret");

        let reused = handler_with_backend(backend)
            .handle_request(client_public_key, connect_request(Some(secret)))
            .expect("reused outcome");
        assert_eq!(
            reused.handled_request,
            RadrootsNostrSignerHandledRequest::Ignore
        );
    }

    #[test]
    fn sign_event_response_rejects_wrong_user_pubkey() {
        let codec = super::RadrootsNostrSignerNip46Codec::new(test_signer());
        let response = codec
            .sign_event_response(
                serde_json::from_value(serde_json::json!({
                    "pubkey": fixture_alice_identity().public_key().to_hex(),
                    "created_at": 1,
                    "kind": 1,
                    "tags": [],
                    "content": "hello",
                }))
                .expect("unsigned event"),
            )
            .expect("response");

        assert_eq!(
            response,
            Response::Error {
                result: None,
                error: "sign_event pubkey does not match the managed user identity".to_owned(),
            }
        );
    }

    #[test]
    fn connect_decision_enum_covers_all_states() {
        assert_eq!(
            [
                RadrootsNostrSignerNip46ConnectDecision::Allow,
                RadrootsNostrSignerNip46ConnectDecision::RequireApproval,
                RadrootsNostrSignerNip46ConnectDecision::Deny,
            ]
            .len(),
            3
        );
    }

    #[test]
    fn connect_request_keeps_requested_permissions() {
        let request = connect_request(None);
        assert_eq!(
            request.request,
            Request::Connect {
                remote_signer_public_key: connect_public_key(
                    test_signer().signer_identity.public_key(),
                ),
                secret: None,
                requested_permissions: vec![Permission::new(Method::Nip04Encrypt,)].into(),
                client_metadata: None,
            }
        );
    }

    #[test]
    fn handler_registration_initializes_non_terminal_connection_state() {
        let backend = embedded_backend();
        let handler = handler_with_backend(backend.clone());
        let _ = handler
            .handle_request(fixture_carol_public_key(), connect_request(None))
            .expect("connect");
        let connection = backend
            .find_connections_by_client_public_key(&fixture_carol_public_key())
            .expect("connections")
            .into_iter()
            .next()
            .expect("connection");
        assert!(matches!(
            connection.auth_state,
            RadrootsNostrSignerAuthState::NotRequired
                | RadrootsNostrSignerAuthState::Pending
                | RadrootsNostrSignerAuthState::Authorized
        ));
        assert_eq!(
            connection.user_identity.id(),
            test_signer().user_identity().id()
        );
    }
}
