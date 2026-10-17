#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../Cargo.toml");
const RELEASE_ACCEPTANCE: &str = include_str!("../scripts/release-acceptance.sh");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source_lock.v4.toml");
const FLAKE_LOCK: &[u8] = include_bytes!("../flake.lock");

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
        "tokio = { version = \"1.48\", default-features = false, features = [\"io-util\", \"macros\", \"net\", \"rt-multi-thread\", \"signal\", \"sync\", \"time\"] }"
    ));
}

#[test]
fn shared_runtime_paths_is_exactly_pinned_to_the_source_locked_lib() {
    assert!(MANIFEST.contains(
        "radroots_runtime_paths = { git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\" }"
    ));
}

#[test]
fn shared_identity_is_exactly_pinned_to_the_source_locked_lib() {
    assert!(MANIFEST.contains(
        "radroots_identity = { git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\" }"
    ));
}

#[test]
fn shared_service_host_is_exactly_pinned_to_the_source_locked_lib() {
    assert!(MANIFEST.contains(
        "radroots_service_host = { git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\" }"
    ));
}

#[test]
fn shared_service_sqlite_is_exactly_pinned_to_the_source_locked_lib() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\" }"
    ));
}

#[test]
fn shared_storage_evidence_is_exactly_pinned_to_the_source_locked_lib() {
    assert!(MANIFEST.contains(
        "radroots_storage = { git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\", default-features = false }"
    ));
}

#[test]
fn delivery_dependencies_are_exactly_source_locked() {
    for dependency in [
        "radroots_event_codec",
        "radroots_transport",
        "radroots_transport_nostr",
    ] {
        assert!(
            MANIFEST.contains(&format!(
                "{dependency} = {{ git = \"https://github.com/radrootslabs/lib\", rev = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\", version = \"=0.1.0-alpha\""
            )),
            "{dependency} is not pinned to the exact source lock"
        );
    }
}

#[test]
fn release_acceptance_checks_both_feature_profiles() {
    assert!(
        RELEASE_ACCEPTANCE.contains("cargo check --locked --all-targets --no-default-features\n")
    );
    assert!(RELEASE_ACCEPTANCE.contains(
        "cargo check --locked --all-targets --no-default-features --features service-host\n"
    ));
    assert!(RELEASE_ACCEPTANCE.contains("cargo test --locked -p myc_xtask\n"));
    assert!(!RELEASE_ACCEPTANCE.contains("nix "));
}

#[test]
fn source_lock_binds_the_current_cargo_lock() {
    let digest = hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")));
    let flake_digest = hex::encode(Sha256::digest(FLAKE_LOCK));
    assert!(SOURCE_LOCK.starts_with(
        "schema = \"radroots.service.source_lock.v4\"\ncontract_version = 4\nservice = \"myc\"\n"
    ));
    assert!(SOURCE_LOCK.contains(&format!("cargo_lock_sha256 = \"{digest}\"")));
    assert!(SOURCE_LOCK.contains(&format!("sha256 = \"{flake_digest}\"")));
    assert!(SOURCE_LOCK.contains("revision = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\""));
    assert!(SOURCE_LOCK.contains(
        "[nix]\nmaterial = \"bound\"\nlib_revision = \"b6f927c4d484ed2f8afcf171a83f2c8f967fb4d4\"\nsupported_systems = [\"aarch64-darwin\", \"x86_64-linux\"]\n"
    ));
    assert!(SOURCE_LOCK.contains(
        "workspace_catalog_sha256 = \"1e679431ad70a024affc52e6c71151459aca41707429dd8015d014d27e5f40b6\""
    ));
    assert!(SOURCE_LOCK.contains(
        "source_archive_sha256 = \"2e301532e6baa538e94d44aaa34cc8eb8bd209ba910e687ccaf0e967d118455e\""
    ));
    assert!(SOURCE_LOCK.ends_with(
        "[contract_versions]\nconfig = 1\nstate = 12\nadmin = 1\nstatus = 1\nprovider = 1\n"
    ));
}
