use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/encrypted_identity_envelope.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const ENVELOPE_SOURCE: &str = include_str!("../src/provider_envelope.rs");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const MAINTENANCE_SOURCE: &str = include_str!("../src/state_maintenance.rs");

#[test]
fn machine_contract_freezes_the_exact_envelope_and_backup_boundary() {
    let actual: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.myc.encrypted-identity-envelope",
            "schema_version": 1,
            "contract_version": 1,
            "radroots_secrets_envelope_version": 2,
            "encoded_max_bytes": 262144,
            "identity_secret_bytes": 32,
            "wrapping_credential_bytes": 32,
            "provisioning_entropy": {
                "data_key_bytes": 32,
                "envelope_nonce_bytes": 24,
                "wrapping_nonce_bytes": 24,
                "caller_supplied": true
            },
            "authenticated_context": {
                "purpose": "radroots.myc.encrypted_identity",
                "subject_type": "provider_identity",
                "subject_value": "<role>:<expected_public_key>",
                "payload_schema": "radroots.myc.identity_secret.v1",
                "credential_reference_bound": true
            },
            "artifact": {
                "create_new": true,
                "overwrite": false,
                "symlink_follow": false,
                "regular_file": true,
                "single_link": true,
                "owner_uid": "effective_uid",
                "create_mode_octal": "0600",
                "read_modes_octal": ["0400", "0600"]
            },
            "verification": {
                "expected_identity_required": true,
                "derived_public_key_must_match": true,
                "legacy_envelope_accepted": false,
                "ordinary_run_provisions": false
            },
            "backup": {
                "state_backup_includes_envelope": false,
                "state_backup_includes_wrapping_credential": false,
                "state_backup_includes_plaintext_identity": false
            }
        })
    );
}

#[test]
fn implementation_uses_the_shared_envelope_and_keeps_secret_resolution_sealed() {
    for required in [
        "EncryptedEnvelope::seal(",
        "EncryptedEnvelope::decode(",
        ".open(&opener, expected_context)",
        "binding.role().as_str()",
        "OFlags::CREATE",
        "OFlags::EXCL",
        "OFlags::NOFOLLOW",
        "Mode::RUSR | Mode::WUSR",
        "derived_public_key_must_match",
    ] {
        assert!(
            ENVELOPE_SOURCE.contains(required) || CONTRACT.contains(required),
            "missing envelope boundary {required}"
        );
    }
    for forbidden in [
        "pub fn from_resolved_bytes",
        "pub fn from_bytes",
        "std::env::",
        "process::Command",
        "keyring::",
        "LEGACY_ENVELOPE_VERSION",
        "open_legacy_v1",
        "reseal_legacy_v1",
        ".key\"",
        "create_dir_all",
    ] {
        assert!(
            !ENVELOPE_SOURCE.contains(forbidden),
            "forbidden envelope authority {forbidden}"
        );
    }
    assert!(LIB_SOURCE.contains("mod provider_envelope;"));
    assert!(!LIB_SOURCE.contains("pub mod provider_envelope"));
}

#[test]
fn service_state_backup_remains_a_single_database_without_provider_material() {
    assert!(HOST_SOURCE.contains(".capture_online_backup(staging_directory, created_at)"));
    assert!(MAINTENANCE_SOURCE.contains("verify_backup_bundle("));
    for source in [HOST_SOURCE, MAINTENANCE_SOURCE] {
        for forbidden in [
            "provider_envelope",
            "identity.ncrypt",
            "MycWrappingCredential",
            "MycDecryptedIdentity",
        ] {
            assert!(
                !source.contains(forbidden),
                "state backup must exclude {forbidden}"
            );
        }
    }
}

#[test]
fn public_error_and_protected_types_are_dependency_and_path_free() {
    for required in [
        "pub enum MycEncryptedIdentityEnvelopeErrorKind",
        "pub struct MycEncryptedIdentityEnvelopeError",
        "pub struct MycWrappingCredential(",
        "pub struct MycCredentialResolutionProof",
        "pub struct MycEncryptedIdentityProvisioningMaterial",
        "pub struct MycDecryptedIdentity",
        "formatter.write_str(\"MycWrappingCredential([redacted])\")",
        "impl Error for MycEncryptedIdentityEnvelopeError {}",
        "pub fn from_resolution(\n        proof: MycCredentialResolutionProof,",
    ] {
        assert!(
            ENVELOPE_SOURCE.contains(required),
            "missing boundary {required}"
        );
    }
    for forbidden in [
        "pub path:",
        "pub source:",
        "pub credential:",
        "pub secret:",
        "pub data_key:",
        "pub envelope_nonce:",
        "pub wrapping_nonce:",
        "pub fn expose_secret",
        "pub fn encrypted_envelope_path",
    ] {
        assert!(!ENVELOPE_SOURCE.contains(forbidden));
    }
}
