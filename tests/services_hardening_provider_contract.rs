use std::error::Error;
use std::path::PathBuf;

use myc::{
    MYC_PROVIDER_CONCURRENCY_MAX, MYC_PROVIDER_CONTRACT_VERSION, MYC_PROVIDER_INPUT_MAX_BYTES,
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS,
    MYC_PROVIDER_REQUEST_MAX_BYTES, MYC_PROVIDER_RESPONSE_MAX_BYTES, MycConfigProfile,
    MycProviderCapability, MycProviderContractErrorKind, MycProviderCorrelationId,
    MycProviderDeadlineUnixMs, MycProviderKind, MycProviderNip44Version, MycProviderOperation,
    MycProviderOperationId, MycProviderOperationInput, MycProviderRole, MycUntrustedProviderOutput,
    parse_myc_config_v1,
};
use serde_json::{Value, json};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/provider_contract.v1.json");

#[test]
fn machine_contract_freezes_the_complete_provider_inventory() {
    let actual: Value = serde_json::from_str(CONTRACT).expect("provider contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.myc.provider-contract",
            "schema_version": 1,
            "contract_version": MYC_PROVIDER_CONTRACT_VERSION,
            "provider_kinds": ["encrypted_file", "local_signer"],
            "capabilities": [
                "describe",
                "public_identity",
                "sign_event",
                "nip04_encrypt",
                "nip04_decrypt",
                "nip44_encrypt",
                "nip44_decrypt"
            ],
            "roles": [
                {
                    "role": "transport",
                    "provider_instance": "transport",
                    "required_capabilities": [
                        "describe",
                        "public_identity",
                        "nip04_encrypt",
                        "nip04_decrypt",
                        "nip44_encrypt",
                        "nip44_decrypt"
                    ]
                },
                {
                    "role": "user",
                    "provider_instance": "user",
                    "required_capabilities": [
                        "describe",
                        "public_identity",
                        "sign_event",
                        "nip04_encrypt",
                        "nip04_decrypt",
                        "nip44_encrypt",
                        "nip44_decrypt"
                    ]
                },
                {
                    "role": "discovery",
                    "provider_instance": "discovery",
                    "required_capabilities": ["describe", "public_identity", "sign_event"]
                }
            ],
            "operation_binding": {
                "operation_id_bytes": 32,
                "correlation_id_bytes": 32,
                "absolute_deadline_unix_ms": {
                    "minimum": 1,
                    "maximum": i64::MAX
                },
                "nip44_versions": [2],
                "semantic_input_max_bytes": MYC_PROVIDER_INPUT_MAX_BYTES,
                "untrusted_output_max_bytes": MYC_PROVIDER_OUTPUT_MAX_BYTES
            },
            "local_signer_limits": {
                "request_deadline_ms": {
                    "minimum": 1,
                    "maximum": MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS
                },
                "request_max_bytes": {
                    "minimum": 1,
                    "maximum": MYC_PROVIDER_REQUEST_MAX_BYTES
                },
                "response_max_bytes": {
                    "minimum": 1,
                    "maximum": MYC_PROVIDER_RESPONSE_MAX_BYTES
                },
                "concurrency": {
                    "minimum": 1,
                    "maximum": MYC_PROVIDER_CONCURRENCY_MAX
                }
            },
            "credential_reference": {
                "maximum_utf8_bytes": 128,
                "shared_type": "ServiceCredentialArtifactName",
                "material_in_configuration": false
            },
            "execution": {
                "database_transaction_held": false,
                "provider_result_trusted": false,
                "cancellation_proves_no_effect": false,
                "signing_is_publication": false
            }
        })
    );
}

#[test]
fn admitted_configuration_derives_exact_role_bindings_and_limits() {
    let config = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::Production)
        .expect("canonical configuration");
    let contract = config.provider_contract();
    assert_eq!(contract.bindings().len(), 3);

    let transport = contract
        .binding(MycProviderRole::Transport)
        .expect("transport binding");
    assert_eq!(transport.kind(), MycProviderKind::EncryptedFile);
    assert_eq!(transport.instance().as_str(), "transport");
    assert_eq!(
        transport
            .credential_reference()
            .expect("credential")
            .as_str(),
        "transport_wrapping_key"
    );
    assert!(transport.local_signer_limits().is_none());
    assert!(
        !transport
            .required_capabilities()
            .contains(MycProviderCapability::SignEvent)
    );

    let user = contract
        .binding(MycProviderRole::User)
        .expect("user binding");
    assert_eq!(user.kind(), MycProviderKind::LocalSigner);
    assert_eq!(user.instance().as_str(), "user");
    assert!(user.credential_reference().is_none());
    let limits = user.local_signer_limits().expect("local signer limits");
    assert_eq!(limits.request_deadline_ms(), 15_000);
    assert_eq!(limits.request_max_bytes(), 65_536);
    assert_eq!(limits.response_max_bytes(), 1_048_576);
    assert_eq!(limits.concurrency(), 32);
    assert_eq!(user.required_capabilities().len(), 7);

    let discovery = contract
        .binding(MycProviderRole::Discovery)
        .expect("discovery binding");
    assert_eq!(discovery.kind(), MycProviderKind::EncryptedFile);
    assert_eq!(discovery.required_capabilities().len(), 3);
    assert_eq!(
        discovery
            .required_capabilities()
            .iter()
            .map(MycProviderCapability::as_str)
            .collect::<Vec<_>>(),
        ["describe", "public_identity", "sign_event"]
    );
}

#[test]
fn explicitly_disabled_discovery_omits_only_that_provider_binding() {
    let mut value = CONFIG.parse::<toml::Table>().expect("configuration TOML");
    value.insert(
        "discovery".to_owned(),
        toml::Value::Table(toml::Table::from_iter([(
            "enabled".to_owned(),
            toml::Value::Boolean(false),
        )])),
    );
    value
        .get_mut("identity")
        .and_then(toml::Value::as_table_mut)
        .expect("identity")
        .insert(
            "discovery".to_owned(),
            toml::Value::Table(toml::Table::from_iter([(
                "enabled".to_owned(),
                toml::Value::Boolean(false),
            )])),
        );
    let source = toml::to_string(&value).expect("disabled discovery fixture");
    let config = parse_myc_config_v1(source.as_bytes(), MycConfigProfile::Production)
        .expect("disabled discovery config");
    assert_eq!(config.provider_contract().bindings().len(), 2);
    assert!(
        config
            .provider_contract()
            .binding(MycProviderRole::Discovery)
            .is_none()
    );
}

#[test]
fn every_operation_is_identity_deadline_and_role_bound_before_execution() {
    let config = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::Production)
        .expect("canonical configuration");
    let operation_id = MycProviderOperationId::from_bytes([7; 32]);
    let correlation_id = MycProviderCorrelationId::from_bytes([9; 32]);
    let deadline = MycProviderDeadlineUnixMs::new(1_800_000_000_000).expect("deadline");

    let user = config
        .provider_contract()
        .binding(MycProviderRole::User)
        .expect("user");
    let sign = MycProviderOperation::new(
        user,
        operation_id,
        correlation_id,
        deadline,
        MycProviderOperationInput::sign_event(br#"{"kind":1}"#).expect("event input"),
    )
    .expect("bound operation");
    assert_eq!(sign.contract_version(), MYC_PROVIDER_CONTRACT_VERSION);
    assert_eq!(sign.role(), MycProviderRole::User);
    assert_eq!(sign.instance().as_str(), "user");
    assert_eq!(sign.provider(), MycProviderKind::LocalSigner);
    assert_eq!(sign.operation_id().as_bytes(), &[7; 32]);
    assert_eq!(sign.correlation_id().as_bytes(), &[9; 32]);
    assert_eq!(sign.deadline().get(), 1_800_000_000_000);
    assert_eq!(sign.expected_identity(), user.expected_identity());
    assert_eq!(sign.input().capability(), MycProviderCapability::SignEvent);

    let transport = config
        .provider_contract()
        .binding(MycProviderRole::Transport)
        .expect("transport");
    let rejected = MycProviderOperation::new(
        transport,
        operation_id,
        correlation_id,
        deadline,
        MycProviderOperationInput::sign_event(br#"{"kind":1}"#).expect("event input"),
    )
    .expect_err("transport cannot sign events");
    assert_eq!(
        rejected.kind(),
        MycProviderContractErrorKind::UnsupportedOperation
    );
}

#[test]
fn protected_inputs_outputs_bind_nip_version_and_never_render_values() {
    let peer = myc::MycProviderPublicIdentity::new(&"2".repeat(64)).expect("peer");
    let input = MycProviderOperationInput::nip44_decrypt(
        peer,
        MycProviderNip44Version::V2,
        b"ciphertext-secret-marker",
    )
    .expect("decrypt input");
    assert_eq!(input.capability(), MycProviderCapability::Nip44Decrypt);
    assert_eq!(
        input.nip44_version().map(MycProviderNip44Version::as_u8),
        Some(2)
    );
    assert_eq!(input.bytes(), Some(b"ciphertext-secret-marker".as_slice()));
    assert!(!format!("{input:?}").contains("ciphertext-secret-marker"));

    let output =
        MycUntrustedProviderOutput::new(b"provider-output-secret-marker").expect("bounded output");
    assert_eq!(output.as_bytes(), b"provider-output-secret-marker");
    assert!(!format!("{output:?}").contains("provider-output-secret-marker"));
}

#[test]
fn all_provider_debug_and_errors_are_path_secret_and_source_free() {
    let config = parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::Production)
        .expect("canonical configuration");
    let rendered = format!("{:?}", config.provider_contract());
    for forbidden in [
        "/var/lib/radroots",
        "/run/radroots",
        "transport_wrapping_key",
        "4444444444444444",
        "2222222222222222",
    ] {
        assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        for binding in config.provider_contract().bindings() {
            assert!(!format!("{binding:?}").contains(forbidden));
        }
    }

    let error = MycProviderDeadlineUnixMs::new(0).expect_err("zero deadline");
    assert_eq!(error.kind(), MycProviderContractErrorKind::InvalidDeadline);
    assert!(error.source().is_none());
    assert!(!error.to_string().contains('/'));
}

#[test]
fn provider_contract_has_no_io_or_public_path_escape_hatch() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/provider_contract.rs"))
        .expect("provider contract source");
    for forbidden in [
        "std::fs::",
        "tokio::",
        "sqlx::",
        "reqwest::",
        "Command::new",
        "pub fn envelope_path",
        "pub fn socket_path",
        "impl serde::Serialize",
        "impl serde::Deserialize",
    ] {
        assert!(!source.contains(forbidden), "forbidden source: {forbidden}");
    }
}
