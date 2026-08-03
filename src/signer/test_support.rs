use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::test_fixtures::{
    API_PRIMARY_HTTPS, ApprovedFixtureIdentity, FIXTURE_ALICE, FIXTURE_BOB, FIXTURE_CAROL,
    FIXTURE_DIEGO, RELAY_PRIMARY_WSS, RELAY_SECONDARY_WSS, RELAY_TERTIARY_WSS,
};
use nostr::{Keys, PublicKey, RelayUrl, SecretKey};

fn approved_public_identity(identity: ApprovedFixtureIdentity) -> PublicIdentity {
    let public_key = approved_public_key(identity);
    PublicIdentity::new(public_key).expect("identity public key")
}

fn approved_public_key(identity: ApprovedFixtureIdentity) -> PublicKey {
    let secret = SecretKey::from_hex(identity.secret_key_hex).expect("secret");
    Keys::new(secret).public_key()
}

fn relay(url: &str) -> RelayUrl {
    RelayUrl::parse(url).expect("relay")
}

pub(crate) fn fixture_alice_identity() -> PublicIdentity {
    approved_public_identity(FIXTURE_ALICE)
}

pub(crate) fn fixture_alice_public_key() -> PublicKey {
    approved_public_key(FIXTURE_ALICE)
}

pub(crate) fn fixture_bob_identity() -> PublicIdentity {
    approved_public_identity(FIXTURE_BOB)
}

pub(crate) fn fixture_carol_identity() -> PublicIdentity {
    approved_public_identity(FIXTURE_CAROL)
}

pub(crate) fn fixture_carol_public_key() -> PublicKey {
    approved_public_key(FIXTURE_CAROL)
}

pub(crate) fn fixture_diego_identity() -> PublicIdentity {
    approved_public_identity(FIXTURE_DIEGO)
}

pub(crate) fn fixture_diego_public_key() -> PublicKey {
    approved_public_key(FIXTURE_DIEGO)
}

pub(crate) fn primary_relay() -> RelayUrl {
    relay(RELAY_PRIMARY_WSS)
}

pub(crate) fn secondary_relay() -> RelayUrl {
    relay(RELAY_SECONDARY_WSS)
}

pub(crate) fn tertiary_relay() -> RelayUrl {
    relay(RELAY_TERTIARY_WSS)
}

pub(crate) fn api_primary_https() -> &'static str {
    API_PRIMARY_HTTPS
}

pub(crate) fn synthetic_secret_hex(index: u32) -> String {
    format!("{index:064x}")
}

pub(crate) fn synthetic_public_identity(index: u32) -> PublicIdentity {
    let public_key = synthetic_public_key(index);
    PublicIdentity::new(public_key).expect("identity public key")
}

pub(crate) fn synthetic_public_key(index: u32) -> PublicKey {
    let secret_hex = synthetic_secret_hex(index);
    let secret = SecretKey::from_hex(secret_hex.as_str()).expect("secret");
    Keys::new(secret).public_key()
}

pub(crate) fn synthetic_keys(index: u32) -> Keys {
    let secret_hex = synthetic_secret_hex(index);
    let secret = SecretKey::from_hex(secret_hex.as_str()).expect("secret");
    Keys::new(secret)
}
