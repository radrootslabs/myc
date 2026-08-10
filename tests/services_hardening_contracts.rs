#![forbid(unsafe_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");
const CONSUMER_ROOT: &str = include_str!("../.radroots-consumer-root");

fn contract() -> Value {
    serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract must be valid JSON")
}

fn decision_sections_digest(value: &Value) -> String {
    let sections = serde_json::json!({
        "identity_contract": value["admin"]["identity_contract"],
        "model_wire_contract": value["admin"]["model_wire_contract"],
        "models": value["admin"]["models"],
        "mutation_contract": value["admin"]["mutation_contract"],
        "pagination": value["admin"]["pagination"],
        "path_parameters": value["admin"]["path_parameters"],
        "types": value["admin"]["types"]
    });
    hex::encode(Sha256::digest(
        serde_json::to_vec(&sections).expect("serialize decision sections"),
    ))
}

fn permission_vector_is_valid(value: &str) -> bool {
    if matches!(
        value,
        "nip04_decrypt" | "nip04_encrypt" | "nip44_decrypt" | "nip44_encrypt" | "switch_relays"
    ) {
        return true;
    }
    let Some(kind) = value.strip_prefix("sign_event:kind:") else {
        return false;
    };
    if kind.is_empty() || (kind.len() > 1 && kind.starts_with('0')) {
        return false;
    }
    kind.bytes().all(|byte| byte.is_ascii_digit()) && kind.parse::<u32>().is_ok()
}

#[test]
fn source_lock_identity_and_shared_host_reference_are_exact() {
    assert_eq!(CONSUMER_ROOT, "myc\n");
    let value = contract();
    assert_eq!(value["schema"], "radroots.myc.operator-contract.v1");
    assert_eq!(value["contract_version"], 1);
    assert_eq!(value["decision_state"], "reserved_preimplementation");
    assert_eq!(value["service"], "myc");
    assert_eq!(
        value["shared_host_contract"],
        serde_json::json!({
            "repository": "https://github.com/radrootslabs/lib",
            "path": "contracts/architecture/decisions/services_hardening_host.v1.json",
            "schema": "radroots.services-hardening.host-decisions.v1",
            "contract_version": 1
        })
    );
}

#[test]
fn admin_inventory_is_closed_unique_and_model_complete() {
    let value = contract();
    assert_eq!(
        value["admin"]["transport"],
        "http_1_1_over_unix_domain_socket"
    );
    assert_eq!(value["admin"]["base_path"], "/v1");
    assert_eq!(value["admin"]["route_inventory_closed"], true);

    let routes = value["admin"]["routes"].as_array().expect("routes");
    let exact_routes = routes
        .iter()
        .map(|route| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                route["method"].as_str().unwrap(),
                route["path"].as_str().unwrap(),
                route["operation_id"].as_str().unwrap(),
                route["request_model"].as_str().unwrap(),
                route["response_model"].as_str().unwrap(),
                route["mutation"].as_bool().unwrap()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        exact_routes,
        [
            "GET|/v1/status|radroots.myc.status.get.v1|empty|service_status_v1|false",
            "GET|/v1/config/effective|radroots.myc.config.effective.get.v1|empty|effective_config_v1|false",
            "GET|/v1/identity/status|radroots.myc.identity.status.get.v1|identity_status_query_v1|identity_status_v1|false",
            "POST|/v1/identity/rekey|radroots.myc.identity.rekey.v1|identity_rekey_request_v1|identity_mutation_receipt_v1|true",
            "POST|/v1/identity/replace|radroots.myc.identity.replace.v1|identity_replace_request_v1|identity_mutation_receipt_v1|true",
            "GET|/v1/identity/public|radroots.myc.identity.public.get.v1|identity_public_query_v1|identity_public_v1|false",
            "GET|/v1/state/status|radroots.myc.state.status.get.v1|empty|state_status_v1|false",
            "POST|/v1/state/backup|radroots.myc.state.backup.create.v1|state_backup_request_v1|state_backup_receipt_v1|true",
            "GET|/v1/metrics/snapshot|radroots.myc.metrics.snapshot.get.v1|empty|metrics_snapshot_v1|false",
            "GET|/v1/connections|radroots.myc.connections.list.v1|connections_query_v1|connections_page_v1|false",
            "POST|/v1/connections/{connection_id}/approve|radroots.myc.connection.approve.v1|connection_approve_request_v1|connection_mutation_receipt_v1|true",
            "POST|/v1/connections/{connection_id}/reject|radroots.myc.connection.reject.v1|connection_reject_request_v1|connection_mutation_receipt_v1|true",
            "POST|/v1/connections/{connection_id}/revoke|radroots.myc.connection.revoke.v1|connection_revoke_request_v1|connection_mutation_receipt_v1|true",
            "POST|/v1/authorization/challenges/require|radroots.myc.authorization.challenge.require.v1|challenge_require_request_v1|challenge_v1|true",
            "POST|/v1/authorization/challenges/{challenge_id}/authorize|radroots.myc.authorization.challenge.authorize.v1|challenge_authorize_request_v1|challenge_authorization_receipt_v1|true",
            "GET|/v1/audit/events|radroots.myc.audit.events.list.v1|audit_events_query_v1|audit_events_page_v1|false",
            "GET|/v1/audit/summary|radroots.myc.audit.summary.get.v1|audit_summary_query_v1|audit_summary_v1|false",
            "GET|/v1/discovery/desired|radroots.myc.discovery.desired.get.v1|empty|discovery_desired_v1|false",
            "POST|/v1/discovery/render|radroots.myc.discovery.render.v1|discovery_render_request_v1|discovery_render_receipt_v1|true",
            "POST|/v1/discovery/refresh|radroots.myc.discovery.refresh.v1|discovery_refresh_request_v1|discovery_refresh_receipt_v1|true",
            "POST|/v1/discovery/publish|radroots.myc.discovery.publish.v1|discovery_publish_request_v1|discovery_publish_receipt_v1|true"
        ]
    );
    let route_keys = routes
        .iter()
        .map(|route| format!("{} {}", route["method"], route["path"]))
        .collect::<BTreeSet<_>>();
    let operation_ids = routes
        .iter()
        .map(|route| route["operation_id"].as_str().expect("operation ID"))
        .collect::<BTreeSet<_>>();
    assert_eq!(route_keys.len(), routes.len());
    assert_eq!(operation_ids.len(), routes.len());
    assert!(
        operation_ids
            .iter()
            .all(|id| id.starts_with("radroots.myc.") && id.ends_with(".v1"))
    );

    let models = value["admin"]["models"].as_object().expect("models");
    let types = value["admin"]["types"].as_object().expect("types");
    for route in routes {
        for key in ["request_model", "response_model"] {
            let model = route[key].as_str().expect("model reference");
            assert!(models.contains_key(model), "missing model {model}");
        }
        assert_eq!(route["mutation"], route["method"] == "POST");
    }
    for (model_name, model) in models {
        assert_eq!(
            model
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["fields"],
            "model {model_name} must be a closed field inventory"
        );
        for (field_name, field) in model["fields"].as_object().unwrap() {
            assert_eq!(
                field
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["presence", "type"],
                "field {model_name}.{field_name} must bind only type and presence"
            );
            assert!(
                matches!(field["presence"].as_str(), Some("required" | "optional")),
                "invalid presence for {model_name}.{field_name}"
            );
            let type_name = field["type"].as_str().unwrap();
            assert!(types.contains_key(type_name), "unknown type {type_name}");
        }
    }
    for (type_name, descriptor) in types {
        let referenced = match descriptor["kind"].as_str().unwrap() {
            "array" | "canonical_delimited_set" => {
                vec![descriptor["items"].as_str().unwrap()]
            }
            "map" => vec![
                descriptor["key"].as_str().unwrap(),
                descriptor["value"].as_str().unwrap(),
            ],
            "closed_object" => descriptor["fields"]
                .as_object()
                .unwrap()
                .values()
                .map(|field| field.as_str().unwrap())
                .collect(),
            "tagged_union" => descriptor["variants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|variant| variant.as_str().unwrap())
                .collect(),
            "alias" => vec![descriptor["target"].as_str().unwrap()],
            "optional" => vec![descriptor["value"].as_str().unwrap()],
            "boolean"
            | "canonical_json_object"
            | "enum"
            | "integer"
            | "literal"
            | "string"
            | "string_union" => Vec::new(),
            kind => panic!("unknown descriptor kind {kind} for {type_name}"),
        };
        for reference in referenced {
            assert!(
                types.contains_key(reference),
                "type {type_name} references missing type {reference}"
            );
        }
    }
    assert_eq!(
        value["admin"]["identity_contract"]["roles"],
        serde_json::json!([
            { "id": "transport", "required": true, "disabled_allowed": false, "providers": ["encrypted_file", "local_signer"] },
            { "id": "user", "required": true, "disabled_allowed": false, "providers": ["encrypted_file", "local_signer"] },
            { "id": "discovery", "required": false, "disabled_allowed": true, "providers": ["encrypted_file", "local_signer"] }
        ])
    );
    assert_eq!(
        value["admin"]["types"]["service_phase"],
        serde_json::json!({
            "kind": "enum",
            "values": ["starting", "ready", "degraded", "unready", "stopping", "failed"]
        })
    );
    assert_eq!(
        value["admin"]["types"]["nip46_permission"],
        serde_json::json!({
            "kind": "string_union",
            "simple_values": ["nip04_decrypt", "nip04_encrypt", "nip44_decrypt", "nip44_encrypt", "switch_relays"],
            "sign_event_pattern": "^sign_event:kind:(0|[1-9][0-9]{0,9})$",
            "sign_event_kind_minimum": 0,
            "sign_event_kind_maximum": 4_294_967_295_u64,
            "sign_event_kind_encoding": "canonical_unsigned_decimal_no_leading_zeroes",
            "maximum_utf8_bytes": 64,
            "unpermissioned_methods": ["connect", "get_public_key", "get_session_capability", "ping", "logout"],
            "custom_methods": "unsupported_v1",
            "required_permission_api": "radroots_nostr_connect::server::required_permission",
            "permission_type": "radroots_nostr_connect::Permission",
            "fixed_vectors": {
                "valid": ["sign_event:kind:0", "sign_event:kind:1", "sign_event:kind:4294967295", "switch_relays"],
                "invalid": ["get_public_key", "ping", "sign_event", "sign_event:kind:", "sign_event:kind:00", "sign_event:kind:4294967296", "sign_event:kind:9999999999"]
            }
        })
    );
    for vector in value["admin"]["types"]["nip46_permission"]["fixed_vectors"]["valid"]
        .as_array()
        .unwrap()
    {
        assert!(permission_vector_is_valid(vector.as_str().unwrap()));
    }
    for vector in value["admin"]["types"]["nip46_permission"]["fixed_vectors"]["invalid"]
        .as_array()
        .unwrap()
    {
        assert!(!permission_vector_is_valid(vector.as_str().unwrap()));
    }
    assert_eq!(
        value["admin"]["models"]["service_status_v1"]["fields"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "build_info",
            "configuration",
            "contract_version",
            "instance",
            "myc",
            "persistence",
            "phase",
            "provider",
            "ready",
            "reason_codes",
            "service",
            "transport",
            "uptime_millis"
        ]
    );
    assert_eq!(
        value["admin"]["identity_contract"]["replace_provider_variants"],
        serde_json::json!({
            "discriminator": "provider",
            "encrypted_file": {
                "required_fields": ["provider", "envelope_path", "credential_reference", "expected_public_key"],
                "provider_value": "encrypted_file"
            },
            "local_signer": {
                "required_fields": ["provider", "socket_path", "request_deadline_ms", "request_max_bytes", "response_max_bytes", "concurrency", "expected_public_key"],
                "provider_value": "local_signer"
            }
        })
    );
    assert_eq!(
        value["admin"]["path_parameters"],
        serde_json::json!({
            "connection_id": { "type": "bounded_id", "source": "percent_decoded_single_path_segment", "slash_allowed": false },
            "challenge_id": { "type": "bounded_id", "source": "percent_decoded_single_path_segment", "slash_allowed": false }
        })
    );
    assert_eq!(
        value["admin"]["pagination"],
        serde_json::json!({
            "cursor_type": "page_cursor",
            "limit_min": 1,
            "limit_max": 200,
            "terminal_page": "next_cursor_field_absent",
            "cursor_reuse": "same_route_same_filters_only",
            "filter_or_route_mismatch": "invalid_cursor",
            "connections_order": ["created_at_utc_ascending", "connection_id_ascending"],
            "connections_snapshot": "generation_fixed_by_first_page_cursor",
            "audit_order": ["occurred_at_utc_descending", "audit_id_descending"],
            "audit_snapshot": "maximum_audit_sequence_fixed_by_first_page_cursor"
        })
    );

    let mutation_operations = routes
        .iter()
        .filter(|route| route["mutation"] == true)
        .map(|route| route["operation_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let committed_effects = value["admin"]["mutation_contract"]["committed_effects"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(mutation_operations, committed_effects);
    assert_eq!(
        decision_sections_digest(&value),
        "55890c43b1ad17e897e20afe1df72941589b3d6df554bc3c81731aefe1c55d58"
    );
}

#[test]
fn doctor_exit_and_tcp_contracts_are_exact() {
    let value = contract();
    assert_eq!(
        value["doctor"]["shared_schema"],
        "radroots.service.doctor.v1"
    );
    assert_eq!(value["doctor"]["contract_version"], 1);
    assert_eq!(
        value["doctor"]["checks"],
        serde_json::json!([
            { "id": "paths_permissions", "required": true },
            { "id": "writer_lock", "required": true },
            { "id": "sqlite_schema", "required": true },
            { "id": "sqlite_integrity", "required": true },
            { "id": "sqlite_free_space", "required": true },
            { "id": "identity_binding", "required": true },
            { "id": "signer_provider", "required": true },
            { "id": "admin_bind_policy", "required": true },
            { "id": "operations_bind_policy", "required": true },
            { "id": "network_policy", "required": true },
            { "id": "required_relays", "required": true },
            { "id": "outbox_invariants", "required": true },
            { "id": "clock_skew", "required": false }
        ])
    );
    assert_eq!(
        value["exit_codes"],
        serde_json::json!([
            { "code": 0, "name": "success", "meaning": "successful command or completed graceful first-signal shutdown" },
            { "code": 1, "name": "unexpected_internal", "meaning": "unexpected invariant, critical task, or internal failure" },
            { "code": 2, "name": "input_or_configuration", "meaning": "CLI, config, validation, or unsupported contract input" },
            { "code": 3, "name": "service_or_dependency_unavailable", "meaning": "daemon, required provider, relay, source, or local dependency unavailable" },
            { "code": 4, "name": "state_or_identity_unavailable", "meaning": "state, schema, lock, credential, or identity unavailable" },
            { "code": 5, "name": "operation_rejected_or_conflict", "meaning": "authorization rejection, idempotency conflict, stale generation, or domain conflict" },
            { "code": 6, "name": "doctor_required_check_failed", "meaning": "one or more required doctor checks failed or timed out" }
        ])
    );
    assert_eq!(
        value["tcp_operations"],
        serde_json::json!({
            "routes": [
                { "method": "GET", "path": "/livez", "source": "cached_supervisor_state" },
                { "method": "GET", "path": "/readyz", "source": "cached_readiness_state" },
                { "method": "GET", "path": "/metrics", "source": "cached_bounded_metrics_snapshot" }
            ],
            "active_probe_per_request": false,
            "additional_routes": false
        })
    );
}
