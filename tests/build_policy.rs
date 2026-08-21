#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../Cargo.toml");
const RELEASE_ACCEPTANCE: &str = include_str!("../scripts/release-acceptance.sh");
const SOURCE_LOCK: &str = include_str!("../radroots.lib.source-lock.v1.toml");

#[test]
fn manifest_freezes_the_final_rust_policy() {
    assert!(MANIFEST.contains("[workspace]\nresolver = \"3\""));
    assert!(MANIFEST.contains("[workspace.lints.rust]\nunsafe_code = \"deny\""));
    assert!(MANIFEST.contains("[workspace.lints.rustdoc]\nbroken_intra_doc_links = \"deny\""));
    assert!(MANIFEST.contains(
        "[workspace.lints.clippy]\ndbg_macro = \"deny\"\ntodo = \"deny\"\nunimplemented = \"deny\""
    ));
    assert!(MANIFEST.contains("[lints]\nworkspace = true"));
}

#[test]
fn service_host_is_the_exact_default_feature_profile() {
    assert!(MANIFEST.contains("[features]\ndefault = [\"service-host\"]\nservice-host = []"));
    assert!(!MANIFEST.contains("getrandom = \"0.2\""));
    assert!(MANIFEST.contains(
        "tokio = { version = \"1.48\", default-features = false, features = [\"io-util\", \"macros\", \"net\", \"process\", \"rt-multi-thread\", \"sync\", \"time\"] }"
    ));
}

#[test]
fn release_acceptance_checks_both_feature_profiles() {
    assert!(
        RELEASE_ACCEPTANCE.contains("cargo check --locked --all-targets --no-default-features\n")
    );
    assert!(RELEASE_ACCEPTANCE.contains(
        "cargo check --locked --all-targets --no-default-features --features service-host\n"
    ));
    assert!(!RELEASE_ACCEPTANCE.contains("nix "));
}

#[test]
fn source_lock_binds_the_current_cargo_lock() {
    let digest = hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")));
    assert!(SOURCE_LOCK.contains(&format!("lockfile_sha256 = \"{digest}\"")));
}
