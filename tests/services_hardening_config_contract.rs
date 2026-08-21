#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use serde_json::{Map, Value, json};

const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");
const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

#[derive(Clone, Copy)]
enum Profile {
    Production,
    RepoLocal,
}

fn schema() -> Value {
    serde_json::from_str(CONFIG_SCHEMA).expect("configuration schema must be valid JSON")
}

fn example() -> Value {
    let value = toml::from_str::<toml::Value>(CONFIG_EXAMPLE)
        .expect("configuration example must be valid TOML");
    serde_json::to_value(value).expect("TOML value must convert to JSON")
}

fn schema_valid(value: &Value) -> bool {
    jsonschema::validator_for(&schema())
        .expect("configuration schema must compile")
        .is_valid(value)
}

fn string_array<'a>(value: &'a Value, pointer: &str) -> Vec<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .expect("string array")
        .iter()
        .map(|value| value.as_str().expect("string item"))
        .collect()
}

fn semantic_valid(value: &Value, profile: Profile) -> bool {
    if !schema_valid(value) {
        return false;
    }

    let relays = value["relays"].as_array().expect("relays");
    let relay_ids = relays
        .iter()
        .map(|relay| relay["id"].as_str().expect("relay id"))
        .collect::<Vec<_>>();
    let relay_urls = relays
        .iter()
        .map(|relay| relay["url"].as_str().expect("relay URL"))
        .collect::<Vec<_>>();
    let parsed_relay_urls = relay_urls
        .iter()
        .map(|raw| {
            url::Url::parse(raw)
                .ok()
                .filter(|parsed| parsed.as_str() == *raw)
        })
        .collect::<Vec<_>>();
    if relay_ids.iter().collect::<BTreeSet<_>>().len() != relay_ids.len()
        || relay_urls.iter().collect::<BTreeSet<_>>().len() != relay_urls.len()
        || parsed_relay_urls.iter().any(Option::is_none)
        || parsed_relay_urls.iter().flatten().any(|url| {
            !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        })
        || relays.iter().any(|relay| {
            let read = relay["read"].as_bool().expect("read");
            let write = relay["write"].as_bool().expect("write");
            (!read && !write) || (relay["required"].as_bool().expect("required") && !read && !write)
        })
        || !relays
            .iter()
            .any(|relay| relay["read"].as_bool() == Some(true))
        || !relays
            .iter()
            .any(|relay| relay["write"].as_bool() == Some(true))
        || !relays.iter().any(|relay| {
            relay["required"].as_bool() == Some(true) && relay["read"].as_bool() == Some(true)
        })
        || !relays.iter().any(|relay| {
            relay["required"].as_bool() == Some(true) && relay["write"].as_bool() == Some(true)
        })
    {
        return false;
    }
    if parsed_relay_urls.iter().flatten().any(|url| match profile {
        Profile::Production => url.scheme() != "wss",
        Profile::RepoLocal => match url.scheme() {
            "wss" => false,
            "ws" => !matches!(
                url.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
            ),
            _ => true,
        },
    }) {
        return false;
    }

    let trusted = string_array(value, "/policy/trusted_clients")
        .into_iter()
        .collect::<BTreeSet<_>>();
    let denied = string_array(value, "/policy/denied_clients")
        .into_iter()
        .collect::<BTreeSet<_>>();
    if !trusted.is_disjoint(&denied) {
        return false;
    }

    let mut expected_role_keys = vec![
        value["identity"]["transport"]["expected_public_key"]
            .as_str()
            .expect("transport key"),
        value["identity"]["user"]["expected_public_key"]
            .as_str()
            .expect("user key"),
    ];
    if value["identity"]["discovery"]["enabled"] == true {
        expected_role_keys.push(
            value["identity"]["discovery"]["binding"]["expected_public_key"]
                .as_str()
                .expect("discovery key"),
        );
    }
    if expected_role_keys.iter().collect::<BTreeSet<_>>().len() != expected_role_keys.len() {
        return false;
    }

    let permitted_kinds = string_array(value, "/policy/permission_ceiling")
        .into_iter()
        .filter_map(|permission| permission.strip_prefix("sign_event:kind:"))
        .filter_map(|kind| kind.parse::<u64>().ok())
        .collect::<BTreeSet<_>>();
    let allowed_kinds = value["policy"]["allowed_sign_event_kinds"]
        .as_array()
        .expect("allowed kinds")
        .iter()
        .map(|kind| kind.as_u64().expect("event kind"))
        .collect::<BTreeSet<_>>();
    if permitted_kinds != allowed_kinds {
        return false;
    }

    let challenges = &value["policy"]["challenges"];
    if challenges["enabled"] == true
        && challenges["authorized_lifetime_ms"].as_u64()
            < challenges["pending_lifetime_ms"].as_u64()
    {
        return false;
    }
    for (name, expected_scope) in [
        ("connection_admission", "global_and_relay"),
        ("challenge_creation", "connection"),
        ("challenge_authorization", "connection"),
    ] {
        let limit = &value["rate_limits"][name];
        if limit["scope"] != expected_scope
            || limit["retention_ms"].as_u64() < limit["window_ms"].as_u64()
        {
            return false;
        }
    }

    let retry = &value["transport"]["publish_retry"];
    if !retry.is_null()
        && retry["initial_backoff_ms"].as_u64() > retry["maximum_backoff_ms"].as_u64()
    {
        return false;
    }
    let required_writers = relays
        .iter()
        .filter(|relay| {
            relay["required"].as_bool() == Some(true) && relay["write"].as_bool() == Some(true)
        })
        .count() as u64;
    let delivery = &value["transport"]["delivery_policy"];
    if delivery["mode"] == "required_quorum"
        && delivery["required_acknowledgements"].as_u64() > Some(required_writers)
    {
        return false;
    }

    let discovery_enabled = value["discovery"]["enabled"].as_bool();
    if discovery_enabled != value["identity"]["discovery"]["enabled"].as_bool() {
        return false;
    }
    if discovery_enabled == Some(true) {
        let by_id = relays
            .iter()
            .map(|relay| (relay["id"].as_str().unwrap(), relay))
            .collect::<BTreeMap<_, _>>();
        if string_array(value, "/discovery/public_relay_ids")
            .iter()
            .any(|id| by_id.get(id).and_then(|relay| relay["read"].as_bool()) != Some(true))
            || string_array(value, "/discovery/publish_relay_ids")
                .iter()
                .any(|id| by_id.get(id).and_then(|relay| relay["write"].as_bool()) != Some(true))
        {
            return false;
        }
    }

    let operations = &value["operations"];
    if operations["enabled"] == true {
        let Ok(listen) = operations["listen"]
            .as_str()
            .unwrap_or_default()
            .parse::<SocketAddr>()
        else {
            return false;
        };
        if listen.port() == 0
            || (operations["bind_policy"] == "loopback_only" && !listen.ip().is_loopback())
        {
            return false;
        }
    }
    true
}

fn assert_rejected(value: &Value, profile: Profile) {
    assert!(
        !semantic_valid(value, profile),
        "negative configuration vector unexpectedly passed"
    );
}

fn insert(value: &mut Value, pointer: &str, key: &str, replacement: Value) {
    value
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .expect("object pointer")
        .insert(key.to_owned(), replacement);
}

fn defaults(value: &Value, pointer: &str, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            if let Some(default) = object.get("default") {
                assert!(
                    object.contains_key("x-radroots-default-source"),
                    "default without provenance at {pointer}"
                );
                output.insert(pointer.to_owned(), default.clone());
            }
            for (key, child) in object {
                defaults(child, &format!("{pointer}/{key}"), output);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                defaults(child, &format!("{pointer}/{index}"), output);
            }
        }
        _ => {}
    }
}

fn assert_integer_bounds(value: &Value, pointer: &str) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("integer".to_owned())) {
                assert!(
                    object.contains_key("minimum"),
                    "missing minimum at {pointer}"
                );
                assert!(
                    object.contains_key("maximum"),
                    "missing maximum at {pointer}"
                );
            }
            for (key, child) in object {
                assert_integer_bounds(child, &format!("{pointer}/{key}"));
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                assert_integer_bounds(child, &format!("{pointer}/{index}"));
            }
        }
        _ => {}
    }
}

#[test]
fn schema_identity_structure_and_machine_policy_are_exact() {
    let schema = schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        json!([
            "schema",
            "schema_version",
            "service",
            "logging",
            "operations",
            "database",
            "identity",
            "relays",
            "transport",
            "policy",
            "rate_limits",
            "resource_limits",
            "discovery"
        ])
    );
    assert_eq!(
        schema["properties"]["schema"]["const"],
        "radroots.myc.config"
    );
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["x-radroots-contract"]["bootstrap_only"],
        json!(["profile", "instance", "repo_local_root", "config_path"])
    );
    assert_eq!(
        schema["x-radroots-contract"]["document_max_utf8_bytes"],
        1_048_576
    );
    assert_eq!(
        schema["x-radroots-contract"]["duplicate_keys"],
        "reject_on_original_wire"
    );
    assert_eq!(
        schema["x-radroots-contract"]["null_values"],
        "reject_on_original_wire"
    );
    assert_eq!(
        schema["x-radroots-contract"]["environment_overlay"],
        "forbidden"
    );
    assert_eq!(
        schema["x-radroots-contract"]["protected_material"],
        "forbidden"
    );
    assert_eq!(
        schema["x-radroots-contract"]["effective_output"],
        "deterministic_redacted_with_exact_provenance"
    );
    assert_integer_bounds(&schema, "");

    let mut found_defaults = BTreeMap::new();
    defaults(&schema, "", &mut found_defaults);
    assert_eq!(found_defaults.len(), 39);
    for source in found_defaults.keys().map(|pointer| {
        schema.pointer(pointer).unwrap()["x-radroots-default-source"]
            .as_str()
            .unwrap()
    }) {
        assert!(
            schema["x-radroots-contract"]["safe_default_sources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|allowed| allowed == source)
        );
    }
}

#[test]
fn lib_derived_limits_and_defaults_are_literal_frozen() {
    let schema = schema();
    let exact = [
        ("/$defs/operations_limits/properties/header_count", 64, 32),
        (
            "/$defs/operations_limits/properties/header_bytes",
            32_768,
            16_384,
        ),
        (
            "/$defs/operations_limits/properties/response_body_utf8_bytes",
            1_048_576,
            1_048_576,
        ),
        (
            "/$defs/operations_limits/properties/concurrent_connections",
            64,
            32,
        ),
        (
            "/$defs/operations_limits/properties/request_deadline_ms",
            30_000,
            15_000,
        ),
        (
            "/$defs/operations_limits/properties/idle_timeout_ms",
            60_000,
            30_000,
        ),
        ("/$defs/database/properties/busy_timeout_ms", 60_000, 5_000),
        ("/$defs/database/properties/max_connections", 8, 8),
        ("/$defs/admin_limits/properties/header_count", 64, 32),
        (
            "/$defs/admin_limits/properties/header_bytes",
            32_768,
            16_384,
        ),
        (
            "/$defs/admin_limits/properties/request_body_utf8_bytes",
            65_536,
            65_536,
        ),
        (
            "/$defs/admin_limits/properties/response_body_utf8_bytes",
            1_048_576,
            1_048_576,
        ),
        (
            "/$defs/admin_limits/properties/concurrent_connections",
            64,
            32,
        ),
        (
            "/$defs/admin_limits/properties/request_deadline_ms",
            30_000,
            15_000,
        ),
        (
            "/$defs/admin_limits/properties/idle_timeout_ms",
            60_000,
            30_000,
        ),
        ("/$defs/admin_limits/properties/query_items", 200, 100),
        ("/$defs/metrics_limits/properties/descriptors", 64, 64),
        ("/$defs/metrics_limits/properties/samples", 512, 512),
        ("/$defs/metrics_limits/properties/labels_per_sample", 8, 8),
        (
            "/$defs/metrics_limits/properties/render_utf8_bytes",
            1_048_576,
            1_048_576,
        ),
        (
            "/$defs/event_limits/properties/wire_bytes",
            524_288,
            262_144,
        ),
        (
            "/$defs/event_limits/properties/content_bytes",
            131_072,
            131_072,
        ),
        ("/$defs/event_limits/properties/tag_count", 1_024, 1_024),
        (
            "/$defs/event_limits/properties/tag_total_elements",
            4_096,
            4_096,
        ),
        (
            "/$defs/event_limits/properties/tag_element_bytes",
            4_096,
            4_096,
        ),
        (
            "/$defs/event_limits/properties/tag_total_bytes",
            131_072,
            131_072,
        ),
        (
            "/$defs/event_limits/properties/decrypted_plaintext_bytes",
            262_144,
            262_144,
        ),
    ];
    for (pointer, maximum, default) in exact {
        assert_eq!(
            schema.pointer(pointer).unwrap()["maximum"],
            maximum,
            "{pointer}"
        );
        assert_eq!(
            schema.pointer(pointer).unwrap()["default"],
            default,
            "{pointer}"
        );
    }
}

#[test]
fn canonical_example_and_required_positive_variants_pass() {
    let value = example();
    assert!(semantic_valid(&value, Profile::Production));
    assert_eq!(value["identity"]["transport"]["provider"], "encrypted_file");
    assert_eq!(value["identity"]["user"]["provider"], "local_signer");
    assert_eq!(
        value["identity"]["discovery"]["binding"]["provider"],
        "encrypted_file"
    );

    let mut disabled_discovery = value.clone();
    disabled_discovery["identity"]["discovery"] = json!({"enabled": false});
    disabled_discovery["discovery"] = json!({"enabled": false});
    assert!(semantic_valid(&disabled_discovery, Profile::Production));

    let mut repo_local = disabled_discovery.clone();
    repo_local["relays"][0]["url"] = json!("ws://127.0.0.1:8080/");
    repo_local["relays"][1]["url"] = json!("ws://localhost:8081/");
    assert!(semantic_valid(&repo_local, Profile::RepoLocal));
    assert_rejected(&repo_local, Profile::Production);

    let mut enabled_operations = value;
    enabled_operations["operations"] = json!({
        "enabled": true,
        "listen": "127.0.0.1:9460",
        "bind_policy": "loopback_only",
        "limits": {}
    });
    assert!(semantic_valid(&enabled_operations, Profile::Production));
}

#[test]
fn structural_unknown_legacy_and_original_wire_vectors_fail() {
    let value = example();
    for (pointer, key) in [
        ("", "unknown"),
        ("/service", "shutdowm_grace_ms"),
        ("/identity/transport", "executable"),
        ("/resource_limits/admin", "body_bytes"),
        ("/policy/challenges", "redirect_from_client"),
    ] {
        let mut invalid = value.clone();
        insert(&mut invalid, pointer, key, json!(true));
        assert_rejected(&invalid, Profile::Production);
    }
    for field in schema()["x-radroots-contract"]["forbidden_prototype_fields"]
        .as_array()
        .unwrap()
    {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().insert(
            field.as_str().unwrap().to_owned(),
            Value::Object(Map::new()),
        );
        assert_rejected(&invalid, Profile::Production);
    }

    assert!(toml::from_str::<toml::Value>("schema='a'\nschema='b'\n").is_err());
    assert!(toml::from_str::<toml::Value>("schema = null\n").is_err());
}

#[test]
fn identity_relay_and_network_authority_fail_closed() {
    let value = example();
    for pointer in [
        "/identity/transport/envelope_path",
        "/identity/user/socket_path",
    ] {
        let mut invalid = value.clone();
        *invalid.pointer_mut(pointer).unwrap() = json!("relative/path");
        assert_rejected(&invalid, Profile::Production);
    }
    for provider in [
        "plaintext_file",
        "external_command",
        "host_vault",
        "keyring",
        "managed_account",
    ] {
        let mut invalid = value.clone();
        invalid["identity"]["transport"]["provider"] = json!(provider);
        assert_rejected(&invalid, Profile::Production);
    }

    let mut duplicate_id = value.clone();
    duplicate_id["relays"][1]["id"] = duplicate_id["relays"][0]["id"].clone();
    assert_rejected(&duplicate_id, Profile::Production);
    let mut duplicate_url = value.clone();
    duplicate_url["relays"][1]["url"] = duplicate_url["relays"][0]["url"].clone();
    assert_rejected(&duplicate_url, Profile::Production);
    let mut inactive = value.clone();
    inactive["relays"][0]["read"] = json!(false);
    inactive["relays"][0]["write"] = json!(false);
    assert_rejected(&inactive, Profile::Production);
    let mut insecure = value;
    insecure["relays"][0]["url"] = json!("ws://127.0.0.1:8080/");
    assert_rejected(&insecure, Profile::Production);

    let mut collapsed_roles = example();
    collapsed_roles["identity"]["user"]["expected_public_key"] =
        collapsed_roles["identity"]["transport"]["expected_public_key"].clone();
    assert_rejected(&collapsed_roles, Profile::Production);

    let mut noncanonical_url = example();
    noncanonical_url["relays"][0]["url"] = json!("WSS://relay-primary.example.test");
    assert_rejected(&noncanonical_url, Profile::Production);
    let mut credential_name = example();
    credential_name["identity"]["transport"]["credential_reference"] =
        json!("transport.identity-key");
    assert!(semantic_valid(&credential_name, Profile::Production));
    credential_name["identity"]["transport"]["credential_reference"] =
        json!(format!("a{}z", "x".repeat(126)));
    assert!(semantic_valid(&credential_name, Profile::Production));
    credential_name["identity"]["transport"]["credential_reference"] =
        json!(format!("a{}z", "x".repeat(127)));
    assert_rejected(&credential_name, Profile::Production);
}

#[test]
fn bounds_relationships_and_conditional_authority_fail_closed() {
    let value = example();
    for (pointer, exact, over) in [
        ("/database/busy_timeout_ms", 60_000_u64, 60_001_u64),
        ("/database/max_connections", 8, 9),
        ("/resource_limits/admin/header_count", 64, 65),
        ("/resource_limits/admin/query_items", 200, 201),
        ("/resource_limits/events/wire_bytes", 524_288, 524_289),
        ("/resource_limits/metrics/samples", 512, 513),
        ("/identity/user/request_deadline_ms", 30_000, 30_001),
        ("/identity/user/concurrency", 64, 65),
    ] {
        let mut minimum = value.clone();
        *minimum.pointer_mut(pointer).unwrap() = json!(1);
        assert!(
            semantic_valid(&minimum, Profile::Production),
            "minimum {pointer}"
        );
        let mut maximum = value.clone();
        *maximum.pointer_mut(pointer).unwrap() = json!(exact);
        assert!(
            semantic_valid(&maximum, Profile::Production),
            "maximum {pointer}"
        );
        let mut zero = value.clone();
        *zero.pointer_mut(pointer).unwrap() = json!(0);
        assert_rejected(&zero, Profile::Production);
        let mut excessive = value.clone();
        *excessive.pointer_mut(pointer).unwrap() = json!(over);
        assert_rejected(&excessive, Profile::Production);
    }

    let mut overlap = value.clone();
    overlap["policy"]["denied_clients"] = overlap["policy"]["trusted_clients"].clone();
    assert_rejected(&overlap, Profile::Production);
    let mut permission_mismatch = value.clone();
    permission_mismatch["policy"]["allowed_sign_event_kinds"] = json!([1, 7]);
    assert_rejected(&permission_mismatch, Profile::Production);
    let mut challenge_lifetime = value.clone();
    challenge_lifetime["policy"]["challenges"]["authorized_lifetime_ms"] = json!(1000);
    assert_rejected(&challenge_lifetime, Profile::Production);
    let mut challenge_missing = value.clone();
    challenge_missing["policy"]["challenges"]
        .as_object_mut()
        .unwrap()
        .remove("url");
    assert_rejected(&challenge_missing, Profile::Production);
    let mut challenge_disabled_leak = value.clone();
    challenge_disabled_leak["policy"]["challenges"]["enabled"] = json!(false);
    assert_rejected(&challenge_disabled_leak, Profile::Production);
    let mut rate_retention = value.clone();
    rate_retention["rate_limits"]["challenge_creation"]["retention_ms"] = json!(1);
    assert_rejected(&rate_retention, Profile::Production);
    let mut backoff = value.clone();
    backoff["transport"]["publish_retry"]["initial_backoff_ms"] = json!(30_000);
    backoff["transport"]["publish_retry"]["maximum_backoff_ms"] = json!(1);
    assert_rejected(&backoff, Profile::Production);
    let mut quorum = value.clone();
    quorum["transport"]["delivery_policy"] =
        json!({"mode": "required_quorum", "required_acknowledgements": 3});
    assert_rejected(&quorum, Profile::Production);
    let mut discovery_mismatch = value.clone();
    discovery_mismatch["identity"]["discovery"] = json!({"enabled": false});
    assert_rejected(&discovery_mismatch, Profile::Production);
    let mut missing_relay = value.clone();
    missing_relay["discovery"]["publish_relay_ids"] = json!(["missing"]);
    assert_rejected(&missing_relay, Profile::Production);
    let mut invalid_template = value;
    invalid_template["discovery"]["nostrconnect_url_template"] =
        json!("https://myc.example.test/connect");
    assert_rejected(&invalid_template, Profile::Production);
}

#[test]
fn schema_and_version_are_closed_and_defaults_are_only_safe_leaves() {
    let value = example();
    for replacement in [json!("radroots.myc.config.v2"), json!("myc")] {
        let mut invalid = value.clone();
        invalid["schema"] = replacement;
        assert_rejected(&invalid, Profile::Production);
    }
    for replacement in [json!(0), json!(2), json!("1")] {
        let mut invalid = value.clone();
        invalid["schema_version"] = replacement;
        assert_rejected(&invalid, Profile::Production);
    }

    let mut safe_defaults_omitted = value;
    safe_defaults_omitted["service"] = json!({});
    safe_defaults_omitted["logging"] = json!({});
    safe_defaults_omitted["database"]
        .as_object_mut()
        .unwrap()
        .remove("busy_timeout_ms");
    safe_defaults_omitted["database"]
        .as_object_mut()
        .unwrap()
        .remove("max_connections");
    safe_defaults_omitted["transport"]
        .as_object_mut()
        .unwrap()
        .remove("connect_deadline_ms");
    safe_defaults_omitted["transport"]
        .as_object_mut()
        .unwrap()
        .remove("publish_retry");
    safe_defaults_omitted["resource_limits"] = json!({});
    assert!(semantic_valid(&safe_defaults_omitted, Profile::Production));

    for required in [
        "minimum_free_bytes",
        "transport",
        "user",
        "relays",
        "connection_approval",
        "trusted_clients",
        "denied_clients",
        "permission_ceiling",
        "allowed_sign_event_kinds",
        "challenges",
        "rate_limits",
        "delivery_policy",
        "discovery",
    ] {
        assert!(
            CONFIG_SCHEMA.contains(required),
            "missing authority {required}"
        );
    }
}

#[test]
fn canonical_example_contains_no_protected_material_or_legacy_selector() {
    let lowercase = CONFIG_EXAMPLE.to_ascii_lowercase();
    for forbidden in [
        "private_key",
        "secret_key",
        "mnemonic",
        "nsec1",
        "wrapping_key =",
        "myc_",
        "env_file",
        "external_command",
        "plaintext_file",
        "keyring",
        "managed_account",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "canonical example contains forbidden material or selector {forbidden}"
        );
    }
}
