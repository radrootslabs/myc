#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/local_signer_transport.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const TRANSPORT_SOURCE: &str = include_str!("../src/provider_local_signer.rs");
const PROVIDER_SOURCE: &str = include_str!("../src/provider_contract.rs");
const CARGO_SOURCE: &str = include_str!("../Cargo.toml");

#[test]
fn machine_contract_freezes_the_complete_local_signer_transport() {
    let actual: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.myc.local-signer-transport",
            "schema_version": 1,
            "contract_version": 1,
            "transport": "http_1_1_json_over_unix_domain_socket",
            "shared_transport": "radroots_service_host::AdminClient",
            "endpoint": "/v1/provider/operation",
            "method": "POST",
            "outer_admin_contract_version": 1,
            "request_fields": [
                "contract_version", "provider_instance", "role", "operation_id",
                "correlation_id", "absolute_deadline_unix_ms", "expected_identity",
                "capability", "input"
            ],
            "response_fields": [
                "contract_version", "provider_instance", "role", "operation_id",
                "correlation_id", "absolute_deadline_unix_ms", "expected_identity",
                "capability", "result"
            ],
            "tagged_operations": [
                "describe", "public_identity", "sign_event", "nip04_encrypt",
                "nip04_decrypt", "nip44_encrypt", "nip44_decrypt"
            ],
            "operation_shapes": {
                "describe": {
                    "input_fields": [],
                    "result_fields": ["public_identity", "protocol_version", "capabilities", "maximum_request_bytes"]
                },
                "public_identity": {
                    "input_fields": [],
                    "result_fields": ["public_identity"]
                },
                "sign_event": {
                    "input_fields": ["payload_hex"],
                    "result_fields": ["payload_hex"]
                },
                "nip04_encrypt": {
                    "input_fields": ["peer", "payload_hex"],
                    "result_fields": ["peer", "payload_hex"]
                },
                "nip04_decrypt": {
                    "input_fields": ["peer", "payload_hex"],
                    "result_fields": ["peer", "payload_hex"]
                },
                "nip44_encrypt": {
                    "input_fields": ["peer", "version", "payload_hex"],
                    "result_fields": ["peer", "version", "payload_hex"]
                },
                "nip44_decrypt": {
                    "input_fields": ["peer", "version", "payload_hex"],
                    "result_fields": ["peer", "version", "payload_hex"]
                }
            },
            "protected_payload_encoding": "lowercase_hex",
            "limits_source": "validated_provider_binding",
            "concurrency_scope": "per_client",
            "semantic_success_trusted": false,
            "semantic_verification_owner": "step-135",
            "cancellation_proves_no_effect": false,
            "signing_is_publication": false,
            "tcp_allowed": false,
            "browser_origin_allowed": false,
            "child_process_allowed": false
        })
    );
}

#[test]
fn implementation_uses_only_the_hardened_fixed_unix_admin_boundary() {
    for required in [
        "radroots_service_host = { git = \"https://github.com/radrootslabs/lib\", rev = \"053d0c750bf9cd683c6ea37cefe7e79617ba629f\"",
        "const MYC_LOCAL_SIGNER_ENDPOINT: &str = \"/v1/provider/operation\"",
        "radroots_service_host::AdminClient",
        ".mutate::<_, LocalSignerResponse>(",
        "tokio::sync::Semaphore",
        "tokio::time::timeout(self.request_deadline",
        "#[serde(tag = \"type\", rename_all = \"snake_case\", deny_unknown_fields)]",
        "MycLocalSignerUntrustedResponse",
    ] {
        assert!(
            CARGO_SOURCE.contains(required)
                || TRANSPORT_SOURCE.contains(required)
                || LIB_SOURCE.contains(required),
            "missing hardened transport boundary {required}"
        );
    }
    assert!(PROVIDER_SOURCE.contains("pub(crate) fn local_signer_socket_path"));
}

#[test]
fn no_parallel_transport_provider_execution_or_success_trust_is_introduced() {
    let production = TRANSPORT_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("production source");
    for forbidden in [
        "TcpStream",
        "reqwest",
        "hyper::",
        "std::process",
        "tokio::process",
        "Command::new",
        "UnixStream::connect",
        "AdminServer",
        "signing_is_publication = true",
        "semantic_success_trusted = true",
        "ServiceSqliteTransaction",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden local-signer authority {forbidden}"
        );
    }
}

#[test]
fn public_boundary_is_sealed_redacted_and_dependency_free() {
    for required in [
        "pub struct MycLocalSignerClient",
        "pub struct MycLocalSignerUntrustedResponse",
        "pub enum MycLocalSignerTransportErrorKind",
        "pub struct MycLocalSignerTransportError",
        "impl Error for MycLocalSignerTransportError {}",
        ".field(\"result\", &\"[redacted]\")",
    ] {
        assert!(TRANSPORT_SOURCE.contains(required));
    }
    for forbidden in [
        "pub transport:",
        "pub permits:",
        "pub response:",
        "pub outer_correlation_id:",
        "pub socket_path:",
        "pub fn into_inner",
        "pub fn raw_response",
        "pub source:",
        "radroots_service_host::AdminClientError",
    ] {
        assert!(!LIB_SOURCE.contains(forbidden));
    }
    assert!(LIB_SOURCE.contains("mod provider_local_signer;"));
    assert!(!LIB_SOURCE.contains("pub mod provider_local_signer"));
}
