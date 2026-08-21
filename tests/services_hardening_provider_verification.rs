#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/provider_verification.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const VERIFICATION_SOURCE: &str = include_str!("../src/provider_verification.rs");
const TRANSPORT_SOURCE: &str = include_str!("../src/provider_local_signer.rs");

#[test]
fn machine_contract_freezes_independent_provider_verification() {
    let actual: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.myc.provider-verification",
            "schema_version": 1,
            "provider_contract_version": 1,
            "local_signer_transport_contract_version": 1,
            "observation_time": {
                "source": "injected",
                "minimum_unix_ms": 1,
                "maximum_unix_ms": 9223372036854775807_i64
            },
            "verification_order": [
                "configured_binding", "absolute_deadline", "outer_correlation",
                "response_envelope_binding", "result_shape", "semantic_result"
            ],
            "response_binding": [
                "contract_version", "provider_instance", "role", "operation_id",
                "correlation_id", "absolute_deadline_unix_ms", "expected_identity",
                "capability"
            ],
            "describe": {
                "identity": "exact_expected",
                "protocol_version": 1,
                "capabilities": "closed_unique_contains_role_requirements",
                "maximum_request_bytes": "exact_configured_limit"
            },
            "public_identity": "exact_expected",
            "sign_event": [
                "canonical_unsigned_json", "exact_unsigned_fields", "exact_expected_author",
                "computed_event_id", "valid_schnorr_signature", "canonical_signed_json",
                "retain_exact_verified_bytes"
            ],
            "nip04": {
                "direction": "exact_result_tag",
                "peer": "exact_echo",
                "ciphertext": "canonical_base64_aes_cbc_shape",
                "encrypt_length": "exact_plaintext_padding_length",
                "decrypt_length": "less_than_ciphertext_block_capacity"
            },
            "nip44": {
                "direction": "exact_result_tag",
                "peer": "exact_echo",
                "version": 2,
                "plaintext_max_bytes": 65_408,
                "ciphertext": "canonical_base64_v2_shape",
                "encrypt_length": "exact_v2_plaintext_padding_length",
                "decrypt_length": "bounded_by_ciphertext_padding_capacity"
            },
            "semantic_output_max_bytes": 1_048_576,
            "verified_result_sealed": true,
            "verified_result_serializable": false,
            "safe_errors_source_free": true,
            "late_result_usable": false,
            "ambiguous_result_is_publication": false,
            "signing_is_publication": false,
            "database_transaction_allowed": false,
            "provider_execution_allowed": false
        })
    );
}

#[test]
fn implementation_rebinds_every_response_before_semantic_use() {
    for required in [
        "observed_at.get() > operation.deadline().get()",
        "parts.outer_correlation_id.as_ref() != expected_correlation_id",
        "response.operation_id != expected_operation_id",
        "response.correlation_id != expected_correlation_id",
        "response.expected_identity != operation.expected_identity().as_hex()",
        "response.capability != WireCapability::from(operation.input().capability())",
        "verify_peer(operation, &peer)?",
        "event.verify().is_err()",
        "canonical_event.as_slice() != payload.as_slice()",
        "VerifiedProviderResult::SignedEvent(payload)",
        "verify_nip04_ciphertext",
        "verify_nip44_ciphertext",
    ] {
        assert!(
            VERIFICATION_SOURCE.contains(required),
            "missing verifier {required}"
        );
    }
    assert!(TRANSPORT_SOURCE.contains("pub(crate) struct LocalSignerUntrustedParts"));
}

#[test]
fn verified_boundary_is_sealed_redacted_and_not_publication() {
    for required in [
        "pub struct MycVerifiedProviderResponse",
        "pub struct MycProviderResponseObservedAtUnixMs",
        "pub enum MycProviderVerificationErrorKind",
        "pub struct MycProviderVerificationError",
        ".field(\"result\", &\"[redacted]\")",
        "impl Error for MycProviderVerificationError {}",
    ] {
        assert!(VERIFICATION_SOURCE.contains(required));
    }
    for forbidden in [
        "pub result:",
        "pub payload:",
        "pub outer_correlation_id:",
        "pub fn into_inner",
        "pub fn raw_response",
        "impl Serialize for MycVerifiedProviderResponse",
        "pub const fn signed_event",
        "ServiceSqliteTransaction",
        "publish(",
        "nostr_sdk",
    ] {
        assert!(!VERIFICATION_SOURCE.contains(forbidden));
    }
    assert!(LIB_SOURCE.contains("mod provider_verification;"));
    assert!(!LIB_SOURCE.contains("pub mod provider_verification"));
}

#[test]
fn peer_and_nip44_version_are_mandatory_response_evidence() {
    let response = TRANSPORT_SOURCE
        .split("pub(crate) enum WireProviderResult")
        .nth(1)
        .expect("response result enum");
    for variant in [
        "Nip04Encrypt",
        "Nip04Decrypt",
        "Nip44Encrypt",
        "Nip44Decrypt",
    ] {
        assert!(
            response.contains(&format!("{variant} {{\n        peer: String,")),
            "missing peer echo on {variant}"
        );
    }
    assert!(VERIFICATION_SOURCE.contains("version != requested_version.as_u8()"));
    assert!(VERIFICATION_SOURCE.contains("decoded.first().copied() != Some(version.as_u8())"));
}
