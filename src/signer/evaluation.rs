use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::model::{
    RadrootsNostrSignerAuthChallenge, RadrootsNostrSignerConnectionDraft,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerPendingRequest,
    RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestId,
};
use nostr::PublicKey;
use radroots_nostr_connect::uri::RelayUrl as ConnectRelayUrl;
use radroots_nostr_connect::{
    Method, Permission, Request, message::RemoteSessionCapability, permission::Permissions,
    uri::ClientMetadata,
};

#[derive(Debug, Clone)]
pub enum RadrootsNostrSignerSessionLookup {
    None,
    Connection(Box<RadrootsNostrSignerConnectionRecord>),
    Ambiguous(Vec<RadrootsNostrSignerConnectionRecord>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadrootsNostrSignerConnectProposal {
    pub client_public_key: PublicKey,
    pub connect_secret: Option<String>,
    pub client_metadata: Option<ClientMetadata>,
    pub requested_permissions: Permissions,
}

#[derive(Debug, Clone)]
pub enum RadrootsNostrSignerConnectEvaluation {
    ExistingConnection(Box<RadrootsNostrSignerConnectionRecord>),
    RegistrationRequired(RadrootsNostrSignerConnectProposal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadrootsNostrSignerRequestResponseHint {
    None,
    Pong,
    UserPublicKey(radroots_identity::PublicKey),
    RemoteSessionCapability(RemoteSessionCapability),
    RelayList(Vec<ConnectRelayUrl>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadrootsNostrSignerRequestAction {
    Allowed {
        required_permission: Option<Permission>,
        response_hint: RadrootsNostrSignerRequestResponseHint,
    },
    Denied {
        reason: String,
    },
    Challenged {
        auth_challenge: RadrootsNostrSignerAuthChallenge,
        pending_request: RadrootsNostrSignerPendingRequest,
    },
}

#[derive(Debug, Clone)]
pub struct RadrootsNostrSignerRequestEvaluation {
    pub request_id: RadrootsNostrSignerRequestId,
    pub method: Method,
    pub connection: RadrootsNostrSignerConnectionRecord,
    pub audit: RadrootsNostrSignerRequestAuditRecord,
    pub action: RadrootsNostrSignerRequestAction,
}

impl RadrootsNostrSignerConnectProposal {
    pub fn into_connection_draft(
        self,
        user_identity: PublicIdentity,
    ) -> RadrootsNostrSignerConnectionDraft {
        let mut draft =
            RadrootsNostrSignerConnectionDraft::new(self.client_public_key, user_identity)
                .with_requested_permissions(self.requested_permissions);
        if let Some(connect_secret) = self.connect_secret {
            draft = draft.with_connect_secret(connect_secret);
        }
        if let Some(client_metadata) = self.client_metadata {
            draft = draft.with_client_metadata(client_metadata);
        }
        draft
    }
}

impl RadrootsNostrSignerRequestEvaluation {
    pub fn denied_reason(&self) -> Option<&str> {
        match &self.action {
            RadrootsNostrSignerRequestAction::Denied { reason } => Some(reason.as_str()),
            _ => None,
        }
    }
}

impl RadrootsNostrSignerRequestAction {
    pub fn audit_message(&self) -> Option<String> {
        match self {
            Self::Allowed { .. } => None,
            Self::Denied { reason } => Some(reason.clone()),
            Self::Challenged { .. } => Some("auth challenge required".into()),
        }
    }
}

pub(crate) fn required_permission_for_request(request: &Request) -> Option<Permission> {
    radroots_nostr_connect::server::required_permission(request)
}

pub(crate) fn request_allowed_by_permissions(
    granted_permissions: &Permissions,
    request: &Request,
) -> bool {
    let Some(required_permission) = required_permission_for_request(request) else {
        return true;
    };

    granted_permissions
        .as_slice()
        .iter()
        .any(|permission| permission_matches(permission, &required_permission))
}

pub(crate) fn response_hint_for_request(
    connection: &RadrootsNostrSignerConnectionRecord,
    request: &Request,
) -> Result<RadrootsNostrSignerRequestResponseHint, RadrootsNostrSignerError> {
    match request {
        Request::GetPublicKey => Ok(RadrootsNostrSignerRequestResponseHint::UserPublicKey(
            identity_public_key(&connection.user_identity)?,
        )),
        Request::GetSessionCapability => Ok(
            RadrootsNostrSignerRequestResponseHint::RemoteSessionCapability(
                RemoteSessionCapability {
                    user_public_key: identity_public_key(&connection.user_identity)?,
                    relays: connection
                        .relays
                        .iter()
                        .map(|relay| ConnectRelayUrl::parse(&relay.to_string()))
                        .collect::<Result<Vec<_>, _>>()?,
                    permissions: connection.effective_permissions(),
                },
            ),
        ),
        Request::Ping => Ok(RadrootsNostrSignerRequestResponseHint::Pong),
        Request::SwitchRelays => Ok(RadrootsNostrSignerRequestResponseHint::RelayList(
            connection
                .relays
                .iter()
                .map(|relay| ConnectRelayUrl::parse(&relay.to_string()))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Ok(RadrootsNostrSignerRequestResponseHint::None),
    }
}

fn permission_matches(granted_permission: &Permission, required_permission: &Permission) -> bool {
    if granted_permission.method != required_permission.method {
        return false;
    }

    match (
        &granted_permission.method,
        granted_permission.parameter.as_deref(),
        required_permission.parameter.as_deref(),
    ) {
        (Method::SignEvent, None, _) => true,
        (Method::SignEvent, Some(parameter), Some(required)) => {
            parameter == required || parameter == sign_event_kind_suffix(required)
        }
        (_, None, _) => true,
        (_, Some(parameter), Some(required)) => parameter == required,
        (_, Some(_), None) => false,
    }
}

fn sign_event_kind_suffix(value: &str) -> &str {
    value.strip_prefix("kind:").unwrap_or(value)
}

fn identity_public_key(
    identity: &PublicIdentity,
) -> Result<radroots_identity::PublicKey, RadrootsNostrSignerError> {
    Ok(identity.public_key())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::signer::test_support::{
        api_primary_https, fixture_alice_identity, fixture_alice_public_key, fixture_bob_identity,
        fixture_carol_public_key, fixture_diego_identity, primary_relay, synthetic_public_key,
    };
    use nostr::{PublicKey, Timestamp};
    use radroots_nostr_connect::message::UnsignedEvent as ConnectUnsignedEvent;
    use serde_json::json;

    fn public_key(index: u32) -> PublicKey {
        synthetic_public_key(index)
    }

    fn connect_public_key(public_key: PublicKey) -> radroots_identity::PublicKey {
        radroots_nostr::key::public_key_from_nostr(public_key).expect("identity public key")
    }

    fn connect_relay(relay: nostr::RelayUrl) -> ConnectRelayUrl {
        ConnectRelayUrl::parse(&relay.to_string()).expect("connect relay")
    }

    fn unsigned_event(kind: u16) -> ConnectUnsignedEvent {
        ConnectUnsignedEvent::from_json(
            &json!({
                "pubkey": fixture_alice_public_key().to_hex(),
                "created_at": Timestamp::from(1).as_secs(),
                "kind": kind,
                "tags": [],
                "content": "hello"
            })
            .to_string(),
        )
        .expect("unsigned event")
    }

    fn connection() -> RadrootsNostrSignerConnectionRecord {
        RadrootsNostrSignerConnectionRecord::new(
            crate::signer::model::RadrootsNostrSignerConnectionId::new_v7(),
            fixture_bob_identity(),
            RadrootsNostrSignerConnectionDraft::new(
                fixture_carol_public_key(),
                fixture_diego_identity(),
            )
            .with_relays(vec![primary_relay()]),
            1,
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_action_audit_message_none(action: &RadrootsNostrSignerRequestAction) {
        assert_eq!(action.audit_message(), None);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_response_hint_none(hint: RadrootsNostrSignerRequestResponseHint) {
        match hint {
            RadrootsNostrSignerRequestResponseHint::None => {}
            other => panic!("unexpected response hint: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_response_hint_pong(hint: RadrootsNostrSignerRequestResponseHint) {
        match hint {
            RadrootsNostrSignerRequestResponseHint::Pong => {}
            other => panic!("unexpected response hint: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_response_hint_user_public_key(hint: RadrootsNostrSignerRequestResponseHint) {
        match hint {
            RadrootsNostrSignerRequestResponseHint::UserPublicKey(_) => {}
            other => panic!("unexpected response hint: {other:?}"),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_response_hint_remote_session_capability(
        hint: RadrootsNostrSignerRequestResponseHint,
        expected_permissions: Permissions,
    ) {
        match hint {
            RadrootsNostrSignerRequestResponseHint::RemoteSessionCapability(capability) => {
                let expected_public_key = fixture_diego_identity().public_key();
                assert_eq!(capability.user_public_key, expected_public_key);
                assert_eq!(capability.relays, vec![connect_relay(primary_relay())]);
                assert_eq!(capability.permissions, expected_permissions);
            }
            other => panic!("unexpected response hint: {other:?}"),
        }
    }

    #[test]
    fn connect_proposal_builds_connection_draft() {
        let requested_permissions: Permissions = vec![Permission::new(Method::Nip04Encrypt)].into();
        let proposal = RadrootsNostrSignerConnectProposal {
            client_public_key: public_key(5),
            connect_secret: Some("secret".into()),
            client_metadata: Some(ClientMetadata {
                requested_permissions: Permissions::default(),
                name: Some("Example Client".into()),
                url: Some("https://client.example.com/".into()),
                image: None,
            }),
            requested_permissions: requested_permissions.clone(),
        };

        let draft = proposal.into_connection_draft(fixture_alice_identity());

        assert_eq!(draft.connect_secret.as_deref(), Some("secret"));
        assert_eq!(draft.requested_permissions, requested_permissions);
        assert_eq!(
            draft
                .client_metadata
                .as_ref()
                .and_then(|metadata| metadata.name.as_deref()),
            Some("Example Client")
        );

        let no_secret = RadrootsNostrSignerConnectProposal {
            client_public_key: public_key(7),
            connect_secret: None,
            client_metadata: None,
            requested_permissions: Permissions::default(),
        }
        .into_connection_draft(fixture_bob_identity());
        assert!(no_secret.connect_secret.is_none());
    }

    #[test]
    fn request_action_audit_message_and_denied_reason_cover_variants() {
        let denied = RadrootsNostrSignerRequestAction::Denied {
            reason: "unauthorized".into(),
        };
        let challenged = RadrootsNostrSignerRequestAction::Challenged {
            auth_challenge: crate::signer::model::RadrootsNostrSignerAuthChallenge::new(
                api_primary_https(),
                1,
            )
            .expect("challenge"),
            pending_request: crate::signer::model::RadrootsNostrSignerPendingRequest::new(
                radroots_nostr_connect::message::RequestMessage::new("req-1", Request::Ping),
                1,
            )
            .expect("pending"),
        };
        let evaluation = RadrootsNostrSignerRequestEvaluation {
            request_id: RadrootsNostrSignerRequestId::new_v7(),
            method: Method::Ping,
            connection: connection(),
            audit: crate::signer::model::RadrootsNostrSignerRequestAuditRecord::new(
                RadrootsNostrSignerRequestId::new_v7(),
                crate::signer::model::RadrootsNostrSignerConnectionId::new_v7(),
                Method::Ping,
                crate::signer::model::RadrootsNostrSignerRequestDecision::Denied,
                Some("unauthorized".into()),
                1,
            ),
            action: denied.clone(),
        };

        assert_eq!(denied.audit_message().as_deref(), Some("unauthorized"));
        assert_eq!(
            challenged.audit_message().as_deref(),
            Some("auth challenge required")
        );
        assert_eq!(evaluation.denied_reason(), Some("unauthorized"));
        assert_action_audit_message_none(&RadrootsNostrSignerRequestAction::Allowed {
            required_permission: None,
            response_hint: RadrootsNostrSignerRequestResponseHint::None,
        });
    }

    #[test]
    fn request_permission_matching_covers_generic_and_sign_event_forms() {
        let kind_one = unsigned_event(1);
        let kind_two = unsigned_event(2);
        let sign_kind = Permission::with_parameter(Method::SignEvent, "kind:1");
        let sign_numeric = Permission::with_parameter(Method::SignEvent, "1");
        let sign_all = Permission::new(Method::SignEvent);
        let nip44 = Permission::new(Method::Nip44Encrypt);

        assert!(request_allowed_by_permissions(
            &vec![sign_kind.clone()].into(),
            &Request::SignEvent(kind_one.clone()),
        ));
        assert!(request_allowed_by_permissions(
            &vec![sign_numeric].into(),
            &Request::SignEvent(kind_one),
        ));
        assert!(request_allowed_by_permissions(
            &vec![sign_all].into(),
            &Request::SignEvent(kind_two),
        ));
        assert!(!request_allowed_by_permissions(
            &vec![sign_kind, nip44].into(),
            &Request::Nip04Encrypt {
                public_key: connect_public_key(public_key(7)),
                plaintext: "hello".into(),
            },
        ));
        assert!(request_allowed_by_permissions(
            &Permissions::default(),
            &Request::Ping,
        ));
        assert!(!request_allowed_by_permissions(
            &vec![Permission::with_parameter(
                Method::custom("do_thing").expect("valid custom NIP-46 method"),
                "scoped",
            )]
            .into(),
            &Request::Custom {
                method: Method::custom("do_thing").expect("valid custom NIP-46 method"),
                params: vec!["value".into()],
            },
        ));
        assert!(permission_matches(
            &Permission::new(Method::Nip04Encrypt),
            &Permission::new(Method::Nip04Encrypt),
        ));
        assert!(permission_matches(
            &Permission::with_parameter(
                Method::custom("scoped").expect("valid custom NIP-46 method"),
                "alpha",
            ),
            &Permission::with_parameter(
                Method::custom("scoped").expect("valid custom NIP-46 method"),
                "alpha",
            ),
        ));
    }

    #[test]
    fn required_permission_and_response_hint_cover_request_variants() {
        let connection = connection();
        let public_key = public_key(8);
        let connect = Request::Connect {
            remote_signer_public_key: connect_public_key(public_key),
            secret: Some("secret".into()),
            requested_permissions: Permissions::default(),
            client_metadata: None,
        };
        let ping = Request::Ping;
        let get_public_key = Request::GetPublicKey;
        let get_session_capability = Request::GetSessionCapability;
        let switch_relays = Request::SwitchRelays;
        let sign_event = Request::SignEvent(unsigned_event(7));
        let custom = Request::Custom {
            method: Method::custom("do_thing").expect("valid custom NIP-46 method"),
            params: vec!["a".into()],
        };

        assert!(required_permission_for_request(&connect).is_none());
        assert!(required_permission_for_request(&ping).is_none());
        assert!(required_permission_for_request(&get_public_key).is_none());
        assert!(required_permission_for_request(&get_session_capability).is_none());
        assert_eq!(
            required_permission_for_request(&Request::Nip04Decrypt {
                public_key: connect_public_key(public_key),
                ciphertext: "cipher".into(),
            })
            .expect("nip04 decrypt permission")
            .to_string(),
            "nip04_decrypt"
        );
        assert_eq!(
            required_permission_for_request(&Request::Nip44Encrypt {
                public_key: connect_public_key(public_key),
                plaintext: "hello".into(),
            })
            .expect("nip44 encrypt permission")
            .to_string(),
            "nip44_encrypt"
        );
        assert_eq!(
            required_permission_for_request(&Request::Nip44Decrypt {
                public_key: connect_public_key(public_key),
                ciphertext: "cipher".into(),
            })
            .expect("nip44 decrypt permission")
            .to_string(),
            "nip44_decrypt"
        );
        assert_eq!(
            required_permission_for_request(&switch_relays)
                .expect("switch relays permission")
                .to_string(),
            "switch_relays"
        );
        assert_eq!(
            required_permission_for_request(&sign_event)
                .expect("sign_event permission")
                .to_string(),
            "sign_event:kind:7"
        );
        assert_eq!(
            required_permission_for_request(&custom)
                .expect("custom permission")
                .to_string(),
            "do_thing"
        );

        assert_response_hint_none(
            response_hint_for_request(
                &connection,
                &Request::Nip04Decrypt {
                    public_key: connect_public_key(public_key),
                    ciphertext: "cipher".into(),
                },
            )
            .expect("nip04 response hint"),
        );
        assert_response_hint_pong(
            response_hint_for_request(&connection, &ping).expect("ping hint"),
        );
        assert_response_hint_user_public_key(
            response_hint_for_request(&connection, &get_public_key).expect("pubkey hint"),
        );
        assert_response_hint_remote_session_capability(
            response_hint_for_request(&connection, &get_session_capability)
                .expect("capability hint"),
            connection.effective_permissions(),
        );
        assert_eq!(
            response_hint_for_request(&connection, &switch_relays).expect("relay hint"),
            RadrootsNostrSignerRequestResponseHint::RelayList(vec![connect_relay(primary_relay())])
        );
    }
}
