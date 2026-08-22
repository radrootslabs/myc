#![forbid(unsafe_code)]

use serde_json::{Value, json};

const CONTRACT: &str = include_str!("../contracts/services_hardening/nip46_work.v1.json");
const SOURCE: &str = include_str!("../src/nip46_work.rs");

#[test]
fn machine_contract_freezes_decryption_method_and_work_authority() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("work contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-work.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["decryption"]["operation_id_domain"],
        "radroots.myc.nip46.decrypt.operation.v1\\0"
    );
    assert_eq!(
        contract["decryption"]["correlation_id_domain"],
        "radroots.myc.nip46.decrypt.correlation.v1\\0"
    );
    assert_eq!(
        contract["decryption"]["provider_result_binding"]["domain"],
        "radroots.myc.provider.operation_binding.v1\\0"
    );
    assert_eq!(
        contract["decryption"]["provider_result_binding"]["field_order"],
        json!([
            "role",
            "instance",
            "provider",
            "operation_id",
            "correlation_id",
            "absolute_deadline_unix_ms",
            "expected_identity",
            "capability",
            "peer_or_empty",
            "nip44_version_or_zero",
            "input_or_empty"
        ])
    );
    assert_eq!(
        contract["method_inventory"],
        json!([
            "connect",
            "get_public_key",
            "get_session_capability",
            "sign_event",
            "nip04_encrypt",
            "nip04_decrypt",
            "nip44_encrypt",
            "nip44_decrypt",
            "ping",
            "switch_relays",
            "logout"
        ])
    );
    assert_eq!(contract["custom_methods"], "unsupported_v1");
    assert_eq!(contract["work_classes"]["provider"]["role"], "user");
    assert_eq!(
        contract["work_classes"]["provider"]["sign_event_input"],
        json!([
            "canonical_unsigned_json",
            "valid_optional_event_id",
            "exact_configured_user_author"
        ])
    );
    assert_eq!(
        contract["authorization"]["required_permission_api"],
        "radroots_nostr_connect::server::required_permission"
    );
    assert_eq!(contract["sqlite"]["transaction_parameter"], "forbidden");
    assert_eq!(
        contract["nonclaims"],
        json!([
            "provider_execution",
            "response_commit",
            "outbox_creation",
            "relay_publication"
        ])
    );
}

#[test]
fn implementation_uses_the_shared_permission_truth_and_has_no_external_authority() {
    for required in [
        "server::required_permission",
        "required_permission(&request)",
        "record.matches_request(&signer_request)",
        "response.matches_operation(&self.operation)",
        "MycProviderRole::Transport",
        "MycProviderRole::User",
        "Request::Custom { .. }",
        "MycNip46WorkErrorKind::UnsupportedMethod",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing Step 145 binding `{required}`"
        );
    }

    for forbidden in [
        "sqlx::",
        "ServiceSqlite",
        "StateRepository",
        "StateHost",
        "ServiceSqliteTransaction",
        "tokio::spawn",
        "std::time::SystemTime",
        "Timestamp::now",
        "rand::",
        "getrandom",
        "RelayPool",
        ".execute(",
        ".publish(",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "Step 145 work gained forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn public_work_values_are_sealed_and_redacted() {
    for required in [
        "pub struct MycNip46DecryptWork {",
        "pub struct MycDecryptedNip46Request {",
        "pub struct MycPreparedNip46Request {",
        "pub struct MycNip46Work {",
        "MycDecryptedNip46Request([redacted])",
        ".field(\"request\", &\"[redacted]\")",
        "impl Error for MycNip46WorkError {}",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing sealed boundary `{required}`"
        );
    }
    for forbidden in [
        "pub replay:",
        "pub signer_request:",
        "pub request:",
        "pub payload:",
        "fn source(",
        "impl Serialize for MycNip46Work",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "public work leak `{forbidden}`"
        );
    }
}
