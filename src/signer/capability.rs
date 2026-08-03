use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::model::{RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord};
use nostr::RelayUrl;
use radroots_identity::AccountId;
use radroots_nostr_connect::permission::Permissions;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadrootsNostrLocalSignerAvailability {
    PublicOnly,
    SecretBacked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrLocalSignerCapability {
    pub account_id: AccountId,
    pub public_identity: PublicIdentity,
    pub availability: RadrootsNostrLocalSignerAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadrootsNostrRemoteSessionSignerCapability {
    pub connection_id: RadrootsNostrSignerConnectionId,
    pub signer_identity: PublicIdentity,
    pub user_identity: PublicIdentity,
    pub relays: Vec<RelayUrl>,
    pub permissions: Permissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RadrootsNostrSignerCapability {
    LocalAccount(Box<RadrootsNostrLocalSignerCapability>),
    RemoteSession(Box<RadrootsNostrRemoteSessionSignerCapability>),
}

fn public_identity_eq(left: &PublicIdentity, right: &PublicIdentity) -> bool {
    left == right
}

impl RadrootsNostrLocalSignerCapability {
    pub fn new(
        account_id: AccountId,
        public_identity: PublicIdentity,
        availability: RadrootsNostrLocalSignerAvailability,
    ) -> Self {
        Self {
            account_id,
            public_identity,
            availability,
        }
    }

    pub fn is_secret_backed(&self) -> bool {
        self.availability == RadrootsNostrLocalSignerAvailability::SecretBacked
    }
}

impl RadrootsNostrRemoteSessionSignerCapability {
    pub fn new(
        connection_id: RadrootsNostrSignerConnectionId,
        signer_identity: PublicIdentity,
        user_identity: PublicIdentity,
    ) -> Self {
        Self {
            connection_id,
            signer_identity,
            user_identity,
            relays: Vec::new(),
            permissions: Permissions::default(),
        }
    }

    pub fn with_relays(mut self, relays: Vec<RelayUrl>) -> Self {
        self.relays = relays;
        self
    }

    pub fn with_permissions(mut self, permissions: Permissions) -> Self {
        self.permissions = permissions;
        self
    }
}

impl RadrootsNostrSignerCapability {
    pub fn public_identity(&self) -> &PublicIdentity {
        match self {
            Self::LocalAccount(capability) => &capability.public_identity,
            Self::RemoteSession(capability) => &capability.user_identity,
        }
    }

    pub fn local_account(&self) -> Option<&RadrootsNostrLocalSignerCapability> {
        match self {
            Self::LocalAccount(capability) => Some(capability.as_ref()),
            Self::RemoteSession(_) => None,
        }
    }

    pub fn remote_session(&self) -> Option<&RadrootsNostrRemoteSessionSignerCapability> {
        match self {
            Self::RemoteSession(capability) => Some(capability.as_ref()),
            Self::LocalAccount(_) => None,
        }
    }
}

impl PartialEq for RadrootsNostrLocalSignerCapability {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.availability == other.availability
            && public_identity_eq(&self.public_identity, &other.public_identity)
    }
}

impl Eq for RadrootsNostrLocalSignerCapability {}

impl PartialEq for RadrootsNostrRemoteSessionSignerCapability {
    fn eq(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
            && self.relays == other.relays
            && self.permissions == other.permissions
            && public_identity_eq(&self.signer_identity, &other.signer_identity)
            && public_identity_eq(&self.user_identity, &other.user_identity)
    }
}

impl Eq for RadrootsNostrRemoteSessionSignerCapability {}

impl PartialEq for RadrootsNostrSignerCapability {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LocalAccount(left), Self::LocalAccount(right)) => {
                left.as_ref() == right.as_ref()
            }
            (Self::RemoteSession(left), Self::RemoteSession(right)) => {
                left.as_ref() == right.as_ref()
            }
            _ => false,
        }
    }
}

impl Eq for RadrootsNostrSignerCapability {}

impl From<&RadrootsNostrSignerConnectionRecord> for RadrootsNostrRemoteSessionSignerCapability {
    fn from(value: &RadrootsNostrSignerConnectionRecord) -> Self {
        Self {
            connection_id: value.connection_id.clone(),
            signer_identity: value.signer_identity.clone(),
            user_identity: value.user_identity.clone(),
            relays: value.relays.clone(),
            permissions: value.effective_permissions(),
        }
    }
}

impl RadrootsNostrSignerConnectionRecord {
    pub fn remote_session_capability(&self) -> RadrootsNostrSignerCapability {
        RadrootsNostrSignerCapability::RemoteSession(Box::new(
            RadrootsNostrRemoteSessionSignerCapability::from(self),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
    use crate::signer::model::{
        RadrootsNostrSignerConnectionDraft, RadrootsNostrSignerConnectionRecord,
    };
    use crate::signer::test_support::{
        fixture_alice_identity, fixture_bob_identity, fixture_carol_identity,
        fixture_diego_public_key, primary_relay, secondary_relay,
    };
    use radroots_nostr_connect::{Method, Permission};

    fn assert_public_identity_matches(actual: &PublicIdentity, expected: &PublicIdentity) {
        assert_eq!(actual, expected);
    }

    #[test]
    fn local_capability_reports_secret_backing_and_public_identity() {
        let public_identity = fixture_alice_identity();
        let capability = RadrootsNostrSignerCapability::LocalAccount(Box::new(
            RadrootsNostrLocalSignerCapability::new(
                public_identity.account_id(),
                public_identity.clone(),
                RadrootsNostrLocalSignerAvailability::SecretBacked,
            ),
        ));

        assert_public_identity_matches(capability.public_identity(), &public_identity);
        assert!(
            capability
                .local_account()
                .expect("local capability")
                .is_secret_backed()
        );
        assert!(capability.remote_session().is_none());
    }

    #[test]
    fn remote_session_capability_reflects_connection_effective_permissions() {
        let signer_identity = fixture_bob_identity();
        let user_identity = fixture_carol_identity();
        let record = RadrootsNostrSignerConnectionRecord::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            signer_identity.clone(),
            RadrootsNostrSignerConnectionDraft::new(
                fixture_diego_public_key(),
                user_identity.clone(),
            )
            .with_requested_permissions(vec![Permission::new(Method::Ping)].into())
            .with_relays(vec![primary_relay()]),
            1,
        );

        let capability = record.remote_session_capability();
        assert_public_identity_matches(capability.public_identity(), &user_identity);
        assert!(capability.local_account().is_none());
        let remote = capability.remote_session().expect("remote capability");
        assert_eq!(remote.connection_id, record.connection_id);
        assert_public_identity_matches(&remote.signer_identity, &signer_identity);
        assert_public_identity_matches(&remote.user_identity, &user_identity);
        assert_eq!(remote.permissions, record.effective_permissions());
        assert_eq!(remote.relays, record.relays);
    }

    #[test]
    fn remote_session_builder_helpers_replace_default_fields() {
        let capability = RadrootsNostrRemoteSessionSignerCapability::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            fixture_alice_identity(),
            fixture_bob_identity(),
        )
        .with_permissions(vec![Permission::new(Method::SwitchRelays)].into())
        .with_relays(vec![primary_relay()]);

        assert_eq!(capability.permissions.as_slice().len(), 1);
        assert_eq!(capability.relays.len(), 1);
    }

    #[test]
    fn capability_equality_accounts_for_identity_fields_and_variant_kind() {
        let alice = fixture_alice_identity();
        let bob = fixture_bob_identity();

        let local = RadrootsNostrLocalSignerCapability::new(
            alice.account_id(),
            alice.clone(),
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        );
        let local_same = RadrootsNostrLocalSignerCapability::new(
            alice.account_id(),
            alice.clone(),
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        );
        let local_changed_account = RadrootsNostrLocalSignerCapability::new(
            bob.account_id(),
            alice.clone(),
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        );
        let local_changed_availability = RadrootsNostrLocalSignerCapability::new(
            alice.account_id(),
            alice.clone(),
            RadrootsNostrLocalSignerAvailability::PublicOnly,
        );
        let local_changed_identity = RadrootsNostrLocalSignerCapability::new(
            alice.account_id(),
            bob,
            RadrootsNostrLocalSignerAvailability::SecretBacked,
        );
        assert_eq!(local, local_same);
        assert_ne!(local, local_changed_account);
        assert_ne!(local, local_changed_availability);
        assert_ne!(local, local_changed_identity);

        let remote = RadrootsNostrRemoteSessionSignerCapability::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            fixture_bob_identity(),
            fixture_carol_identity(),
        )
        .with_relays(vec![primary_relay()]);
        let remote_same = remote.clone();
        let remote_changed_connection = RadrootsNostrRemoteSessionSignerCapability::new(
            RadrootsNostrSignerConnectionId::new_v7(),
            remote.signer_identity.clone(),
            remote.user_identity.clone(),
        )
        .with_relays(remote.relays.clone())
        .with_permissions(remote.permissions.clone());
        let remote_changed_relays = remote.clone().with_relays(vec![secondary_relay()]);
        let remote_changed_permissions = remote
            .clone()
            .with_permissions(vec![Permission::new(Method::Ping)].into());
        let mut remote_changed_signer = remote.clone();
        remote_changed_signer.signer_identity = fixture_alice_identity();
        let mut remote_changed_user = remote.clone();
        remote_changed_user.user_identity = fixture_alice_identity();
        assert_eq!(remote, remote_same);
        assert_ne!(remote, remote_changed_connection);
        assert_ne!(remote, remote_changed_relays);
        assert_ne!(remote, remote_changed_permissions);
        assert_ne!(remote, remote_changed_signer);
        assert_ne!(remote, remote_changed_user);

        assert_eq!(
            RadrootsNostrSignerCapability::LocalAccount(Box::new(local.clone())),
            RadrootsNostrSignerCapability::LocalAccount(Box::new(local_same))
        );
        assert_eq!(
            RadrootsNostrSignerCapability::RemoteSession(Box::new(remote.clone())),
            RadrootsNostrSignerCapability::RemoteSession(Box::new(remote))
        );
        assert_ne!(
            RadrootsNostrSignerCapability::LocalAccount(Box::new(local)),
            RadrootsNostrSignerCapability::RemoteSession(Box::new(remote_changed_user))
        );
    }

    #[test]
    fn public_identity_eq_compares_invariant_checked_values() {
        let alice = fixture_alice_identity();
        let bob = fixture_bob_identity();

        assert!(!public_identity_eq(&alice, &bob));
        assert!(public_identity_eq(&alice, &alice));
    }
}
