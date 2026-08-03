#![forbid(unsafe_code)]
#![allow(dead_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedFixtureIdentity {
    pub label: &'static str,
    pub username: &'static str,
    pub email: &'static str,
    pub secret_key_hex: &'static str,
    pub public_key_hex: &'static str,
    pub nsec: &'static str,
    pub npub: &'static str,
}

pub const APPROVED_FIXTURE_NAMESPACE: &str = "radroots-approved-fixture-v1";

pub const FIXTURE_ALICE_LABEL: &str = "fixture_alice";
pub const FIXTURE_ALICE_USERNAME: &str = "fixture_alice";
pub const FIXTURE_ALICE_EMAIL: &str = "fixture_alice@fixtures.test";
pub const FIXTURE_ALICE_SECRET_KEY_HEX: &str =
    "10c5304d6c9ae3a1a16f7860f1cc8f5e3a76225a2663b3a989a0d775919b7df5";
pub const FIXTURE_ALICE_PUBLIC_KEY_HEX: &str =
    "585591529da0bab31b3b1b1f986611cf5f435dca84f978c89ee8a40cca7103df";
pub const FIXTURE_ALICE_NSEC: &str =
    "nsec1zrznqntvnt36rgt00ps0rny0tca8vgj6ye3m82vf5rthtyvm0h6syu7drz";
pub const FIXTURE_ALICE_NPUB: &str =
    "npub1tp2ez55a5zatxxemrv0eses3ea05xhw2snuh3jy7azjqejn3q00s3vy5a9";
pub const FIXTURE_ALICE: ApprovedFixtureIdentity = ApprovedFixtureIdentity {
    label: FIXTURE_ALICE_LABEL,
    username: FIXTURE_ALICE_USERNAME,
    email: FIXTURE_ALICE_EMAIL,
    secret_key_hex: FIXTURE_ALICE_SECRET_KEY_HEX,
    public_key_hex: FIXTURE_ALICE_PUBLIC_KEY_HEX,
    nsec: FIXTURE_ALICE_NSEC,
    npub: FIXTURE_ALICE_NPUB,
};

pub const FIXTURE_BOB_LABEL: &str = "fixture_bob";
pub const FIXTURE_BOB_USERNAME: &str = "fixture_bob";
pub const FIXTURE_BOB_EMAIL: &str = "fixture_bob@fixtures.test";
pub const FIXTURE_BOB_SECRET_KEY_HEX: &str =
    "59392e9068f66431b12f70218fb61281cb6b433d7f27c55d61f1a63fe1a96ff8";
pub const FIXTURE_BOB_PUBLIC_KEY_HEX: &str =
    "e0266e3cfb0d2886f91c73f5f868f3b98273713e5fcd97c081663f5518a4b3af";
pub const FIXTURE_BOB_NSEC: &str =
    "nsec1tyujayrg7ejrrvf0wqscldsjs89kksea0unu2htp7xnrlcdfdluqrjya9h";
pub const FIXTURE_BOB_NPUB: &str =
    "npub1uqnxu08mp55gd7guw06ls68nhxp8xuf7tlxe0sypvcl42x9ykwhsd55k2g";
pub const FIXTURE_BOB: ApprovedFixtureIdentity = ApprovedFixtureIdentity {
    label: FIXTURE_BOB_LABEL,
    username: FIXTURE_BOB_USERNAME,
    email: FIXTURE_BOB_EMAIL,
    secret_key_hex: FIXTURE_BOB_SECRET_KEY_HEX,
    public_key_hex: FIXTURE_BOB_PUBLIC_KEY_HEX,
    nsec: FIXTURE_BOB_NSEC,
    npub: FIXTURE_BOB_NPUB,
};

pub const FIXTURE_CAROL_LABEL: &str = "fixture_carol";
pub const FIXTURE_CAROL_USERNAME: &str = "fixture_carol";
pub const FIXTURE_CAROL_EMAIL: &str = "fixture_carol@fixtures.test";
pub const FIXTURE_CAROL_SECRET_KEY_HEX: &str =
    "4d6c20fdd86857de77ff5cfa5c545751ba2efd126e0b6642dae9764d782d6509";
pub const FIXTURE_CAROL_PUBLIC_KEY_HEX: &str =
    "1952b8c6943898bceffcff1b7699c4a775a4d13b4a9ba0096ba26ef04492bb1c";
pub const FIXTURE_CAROL_NSEC: &str =
    "nsec1f4kzplwcdptaualltna9c4zh2xazalgjdc9kvsk6a9my67pdv5ys2pqkaj";
pub const FIXTURE_CAROL_NPUB: &str =
    "npub1r9ft33558zvtemluludhdxwy5a66f5fmf2d6qztt5fh0q3yjhvwqgzmkl6";
pub const FIXTURE_CAROL: ApprovedFixtureIdentity = ApprovedFixtureIdentity {
    label: FIXTURE_CAROL_LABEL,
    username: FIXTURE_CAROL_USERNAME,
    email: FIXTURE_CAROL_EMAIL,
    secret_key_hex: FIXTURE_CAROL_SECRET_KEY_HEX,
    public_key_hex: FIXTURE_CAROL_PUBLIC_KEY_HEX,
    nsec: FIXTURE_CAROL_NSEC,
    npub: FIXTURE_CAROL_NPUB,
};

pub const FIXTURE_DIEGO_LABEL: &str = "fixture_diego";
pub const FIXTURE_DIEGO_USERNAME: &str = "fixture_diego";
pub const FIXTURE_DIEGO_EMAIL: &str = "fixture_diego@fixtures.test";
pub const FIXTURE_DIEGO_SECRET_KEY_HEX: &str =
    "9de56c1fdfce9ab00af85b3d7003c1d15cffb84cdf303c3a83c1a3fb1a2d0db0";
pub const FIXTURE_DIEGO_PUBLIC_KEY_HEX: &str =
    "5d3eab6e78eb7e467a9e196a63456c9fafb93fb88b7052b83229870889923aa4";
pub const FIXTURE_DIEGO_NSEC: &str =
    "nsec1nhjkc87le6dtqzhctv7hqq7p69w0lwzvmucrcw5rcx3lkx3dpkcqkrmgp5";
pub const FIXTURE_DIEGO_NPUB: &str =
    "npub1t5l2kmncadlyv757r94xx3tvn7hmj0ac3dc99wpj9xrs3zvj82jqwwcglm";
pub const FIXTURE_DIEGO: ApprovedFixtureIdentity = ApprovedFixtureIdentity {
    label: FIXTURE_DIEGO_LABEL,
    username: FIXTURE_DIEGO_USERNAME,
    email: FIXTURE_DIEGO_EMAIL,
    secret_key_hex: FIXTURE_DIEGO_SECRET_KEY_HEX,
    public_key_hex: FIXTURE_DIEGO_PUBLIC_KEY_HEX,
    nsec: FIXTURE_DIEGO_NSEC,
    npub: FIXTURE_DIEGO_NPUB,
};

pub const RELAY_PRIMARY_WSS: &str = "wss://relay.example.com";
pub const RELAY_SECONDARY_WSS: &str = "wss://relay-2.example.com";
pub const RELAY_TERTIARY_WSS: &str = "wss://relay-3.example.com";

pub const APP_PRIMARY_HTTPS: &str = "https://app.example.com";
pub const API_PRIMARY_HTTPS: &str = "https://api.example.com";
pub const CDN_PRIMARY_HTTPS: &str = "https://cdn.example.com";
