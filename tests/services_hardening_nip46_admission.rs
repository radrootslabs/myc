#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    MYC_NIP46_EVENT_ID_MAX_BYTES, MYC_NIP46_PUBLIC_KEY_MAX_BYTES, MYC_NIP46_SIGNATURE_MAX_BYTES,
    MycConfigProfile, MycNip46AdmissionErrorKind, MycNip46AdmissionLimits, admit_myc_nip46_event,
    admit_myc_nip46_request, parse_myc_config_v1,
};
use serde_json::{Value, json};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/nip46_admission.v1.json");

fn configuration(overrides: &[(&str, usize)]) -> myc::MycConfigDocumentV1 {
    let mut source = CONFIG.to_owned();
    for (field, value) in overrides {
        let prefix = format!("{field} = ");
        let original = source
            .lines()
            .find(|line| line.starts_with(&prefix))
            .expect("configured event limit")
            .to_owned();
        source = source.replacen(&original, &format!("{field} = {value}"), 1);
    }
    parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal).expect("test configuration")
}

fn limits(overrides: &[(&str, usize)]) -> MycNip46AdmissionLimits {
    MycNip46AdmissionLimits::from_config(&configuration(overrides)).expect("admission limits")
}

fn event(content: &str, tags: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "11".repeat(32),
        "pubkey": "22".repeat(32),
        "created_at": 1_725_000_000_u64,
        "kind": 24_133_u64,
        "tags": tags,
        "content": content,
        "sig": "33".repeat(64)
    }))
    .expect("event JSON")
}

fn request(id: &str, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": id, "method": method, "params": params}))
        .expect("request JSON")
}

fn event_error(bytes: &[u8], limits: MycNip46AdmissionLimits) -> MycNip46AdmissionErrorKind {
    admit_myc_nip46_event(limits, bytes)
        .expect_err("event must fail")
        .kind()
}

fn request_error(bytes: &[u8], limits: MycNip46AdmissionLimits) -> MycNip46AdmissionErrorKind {
    admit_myc_nip46_request(limits, bytes)
        .expect_err("request must fail")
        .kind()
}

#[test]
fn machine_contract_and_config_projection_are_exact() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("admission contract JSON");
    assert_eq!(contract["schema"], "radroots.myc.nip46-admission.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["event"]["original_wire_cap_before_parse"], true);
    assert_eq!(
        contract["event"]["decryption"],
        "forbidden_before_admission"
    );
    assert_eq!(contract["request"]["typed_decode"], "deferred_to_step_142");

    let limits = limits(&[]);
    assert_eq!(limits.event_wire_bytes(), 262_144);
    assert_eq!(limits.event_content_bytes(), 131_072);
    assert_eq!(limits.event_tag_count(), 1_024);
    assert_eq!(limits.event_tag_total_elements(), 4_096);
    assert_eq!(limits.event_tag_element_bytes(), 4_096);
    assert_eq!(limits.event_tag_total_bytes(), 131_072);
    assert_eq!(limits.decrypted_plaintext_bytes(), 262_144);
    assert_eq!(MYC_NIP46_EVENT_ID_MAX_BYTES, 64);
    assert_eq!(MYC_NIP46_PUBLIC_KEY_MAX_BYTES, 64);
    assert_eq!(MYC_NIP46_SIGNATURE_MAX_BYTES, 128);
}

#[test]
fn event_admission_retains_exact_bytes_and_bounded_ciphertext_without_semantic_claims() {
    let bytes = event(
        "ciphertext-secret-marker",
        json!([["p", "44".repeat(32)], ["alt", "v"]]),
    );
    let admitted = admit_myc_nip46_event(limits(&[]), &bytes).expect("bounded event");
    assert_eq!(admitted.original_bytes(), bytes);
    assert_eq!(admitted.encrypted_content(), "ciphertext-secret-marker");
    assert_eq!(admitted.tag_count(), 2);
    assert_eq!(admitted.tag_element_count(), 4);
    assert_eq!(admitted.tag_bytes(), 1 + 64 + 3 + 1);

    let rendered = format!("{admitted:?}");
    assert!(!rendered.contains("ciphertext-secret-marker"));
    assert!(!rendered.contains(&"44".repeat(32)));
}

#[test]
fn original_event_cap_precedes_utf8_json_and_allocation() {
    let cap = 128;
    let oversized = vec![0xff; cap + 1];
    assert_eq!(
        event_error(&oversized, limits(&[("wire_bytes", cap)])),
        MycNip46AdmissionErrorKind::EventTooLarge
    );
    assert_eq!(
        event_error(&[], limits(&[])),
        MycNip46AdmissionErrorKind::EmptyEvent
    );
    assert_eq!(
        event_error(&[0xff], limits(&[])),
        MycNip46AdmissionErrorKind::InvalidEventUtf8
    );
}

#[test]
fn event_object_is_closed_duplicate_free_nonnull_and_exactly_consumed() {
    let valid = String::from_utf8(event("x", json!([]))).expect("UTF-8 event");
    let duplicate = valid.replacen("\"id\":", "\"id\":\"11\",\"id\":", 1);
    let unknown = valid.replacen('{', "{\"extra\":1,", 1);
    let null = valid.replacen("\"content\":\"x\"", "\"content\":null", 1);
    for wire in [duplicate, unknown, null, format!("{valid} true")] {
        assert_eq!(
            event_error(wire.as_bytes(), limits(&[])),
            MycNip46AdmissionErrorKind::MalformedEvent
        );
    }
}

#[test]
fn event_identifier_and_content_bounds_count_decoded_utf8_bytes() {
    let base = String::from_utf8(event("x", json!([]))).expect("event");
    for (field, maximum) in [
        ("id", MYC_NIP46_EVENT_ID_MAX_BYTES),
        ("pubkey", MYC_NIP46_PUBLIC_KEY_MAX_BYTES),
        ("sig", MYC_NIP46_SIGNATURE_MAX_BYTES),
    ] {
        let current = if field == "sig" {
            "33".repeat(64)
        } else if field == "pubkey" {
            "22".repeat(32)
        } else {
            "11".repeat(32)
        };
        let oversized = base.replacen(
            &format!("\"{field}\":\"{current}\""),
            &format!("\"{field}\":\"{}\"", "a".repeat(maximum + 1)),
            1,
        );
        assert_eq!(
            event_error(oversized.as_bytes(), limits(&[])),
            MycNip46AdmissionErrorKind::EventIdentifierTooLarge
        );
    }

    let exact = event("éé", json!([]));
    assert!(admit_myc_nip46_event(limits(&[("content_bytes", 4)]), &exact).is_ok());
    let over = event("ééa", json!([]));
    assert_eq!(
        event_error(&over, limits(&[("content_bytes", 4)])),
        MycNip46AdmissionErrorKind::EventContentTooLarge
    );

    let escaped_exact = base.replacen("\"content\":\"x\"", "\"content\":\"\\u00e9\\u00e9\"", 1);
    assert!(
        admit_myc_nip46_event(limits(&[("content_bytes", 4)]), escaped_exact.as_bytes()).is_ok()
    );
}

#[test]
fn tag_count_element_and_aggregate_bounds_fail_independently() {
    let exact_count = event("x", json!([["a"], ["b"]]));
    assert!(admit_myc_nip46_event(limits(&[("tag_count", 2)]), &exact_count).is_ok());
    let over_count = event("x", json!([["a"], ["b"], ["c"]]));
    assert_eq!(
        event_error(&over_count, limits(&[("tag_count", 2)])),
        MycNip46AdmissionErrorKind::TooManyTags
    );

    let exact_elements = event("x", json!([["a", "b"], ["c"]]));
    assert!(admit_myc_nip46_event(limits(&[("tag_total_elements", 3)]), &exact_elements).is_ok());
    let over_elements = event("x", json!([["a", "b"], ["c", "d"]]));
    assert_eq!(
        event_error(&over_elements, limits(&[("tag_total_elements", 3)])),
        MycNip46AdmissionErrorKind::TooManyTagElements
    );

    let exact_element = event("x", json!([["éé"]]));
    assert!(admit_myc_nip46_event(limits(&[("tag_element_bytes", 4)]), &exact_element).is_ok());
    let over_element = event("x", json!([["ééa"]]));
    assert_eq!(
        event_error(&over_element, limits(&[("tag_element_bytes", 4)])),
        MycNip46AdmissionErrorKind::TagElementTooLarge
    );

    let exact_total = event("x", json!([["ab"], ["cd"]]));
    assert!(admit_myc_nip46_event(limits(&[("tag_total_bytes", 4)]), &exact_total).is_ok());
    let over_total = event("x", json!([["ab"], ["cde"]]));
    assert_eq!(
        event_error(&over_total, limits(&[("tag_total_bytes", 4)])),
        MycNip46AdmissionErrorKind::TagsTooLarge
    );

    for malformed in [event("x", json!(["not-a-tag"])), event("x", json!([[1]]))] {
        assert_eq!(
            event_error(&malformed, limits(&[])),
            MycNip46AdmissionErrorKind::MalformedEvent
        );
    }
}

#[test]
fn request_plaintext_cap_precedes_utf8_json_and_content_exposure() {
    let cap = 128;
    let oversized = vec![0xff; cap + 1];
    assert_eq!(
        request_error(&oversized, limits(&[("decrypted_plaintext_bytes", cap)])),
        MycNip46AdmissionErrorKind::PlaintextTooLarge
    );
    assert_eq!(
        request_error(&[], limits(&[])),
        MycNip46AdmissionErrorKind::EmptyPlaintext
    );
    assert_eq!(
        request_error(&[0xff], limits(&[])),
        MycNip46AdmissionErrorKind::InvalidPlaintextUtf8
    );

    let bytes = request("request-secret-marker", "ping", json!([]));
    let admitted = admit_myc_nip46_request(limits(&[]), &bytes).expect("bounded request");
    assert_eq!(admitted.plaintext_bytes(), bytes.len());
    assert_eq!(admitted.request_id_bytes(), 21);
    assert_eq!(admitted.method_bytes(), 4);
    assert_eq!(admitted.parameter_count(), 0);
    let rendered = format!("{admitted:?}");
    assert!(!rendered.contains("request-secret-marker"));
    assert!(!rendered.contains("ping"));
}

#[test]
fn request_object_identifiers_and_parameters_are_strict_and_bounded() {
    let valid = String::from_utf8(request("id", "ping", json!([]))).expect("request");
    let duplicate = valid.replacen("\"id\":", "\"id\":\"other\",\"id\":", 1);
    let unknown = valid.replacen('{', "{\"extra\":1,", 1);
    let null = valid.replacen("\"params\":[]", "\"params\":null", 1);
    for wire in [duplicate, unknown, null, format!("{valid} false")] {
        assert_eq!(
            request_error(wire.as_bytes(), limits(&[])),
            MycNip46AdmissionErrorKind::MalformedRequest
        );
    }

    assert_eq!(
        request_error(&request(&"i".repeat(129), "ping", json!([])), limits(&[])),
        MycNip46AdmissionErrorKind::RequestIdentifierTooLarge
    );
    assert_eq!(
        request_error(&request("id", &"m".repeat(65), json!([])), limits(&[])),
        MycNip46AdmissionErrorKind::RequestMethodTooLarge
    );

    let exact_count = request("id", "custom", json!(vec!["x"; 64]));
    assert!(admit_myc_nip46_request(limits(&[]), &exact_count).is_ok());
    let over_count = request("id", "custom", json!(vec!["x"; 65]));
    assert_eq!(
        request_error(&over_count, limits(&[])),
        MycNip46AdmissionErrorKind::TooManyRequestParameters
    );

    let exact_parameter = request("id", "custom", json!(["x".repeat(65_536)]));
    assert!(admit_myc_nip46_request(limits(&[]), &exact_parameter).is_ok());
    let over_parameter = request("id", "custom", json!(["x".repeat(65_537)]));
    assert_eq!(
        request_error(&over_parameter, limits(&[])),
        MycNip46AdmissionErrorKind::RequestParameterTooLarge
    );

    assert_eq!(
        request_error(&request("id", "custom", json!([1])), limits(&[])),
        MycNip46AdmissionErrorKind::MalformedRequest
    );
}

#[test]
fn public_errors_are_source_free_and_diagnostics_never_render_input() {
    let marker = "protected-plaintext-marker";
    let bytes = request(marker, "ping", json!([]));
    let error = admit_myc_nip46_request(limits(&[("decrypted_plaintext_bytes", 1)]), &bytes)
        .expect_err("oversized plaintext");
    assert_eq!(error.kind(), MycNip46AdmissionErrorKind::PlaintextTooLarge);
    assert!(error.source().is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(marker));
    assert!(!rendered.contains(&String::from_utf8_lossy(&bytes).into_owned()));
}
