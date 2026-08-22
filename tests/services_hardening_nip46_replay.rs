#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use myc::{
    MycConfigProfile, MycNip46AdmissionLimits, MycNip46AuthoredTimePolicy,
    MycNip46ObservedAtUnixSeconds, MycNip46ReplayDisposition, MycProviderBinding, MycProviderRole,
    admit_myc_nip46_event, admit_myc_nip46_request, bind_myc_nip46_replay, parse_myc_config_v1,
    verify_myc_nip46_event, verify_myc_nip46_request,
};
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{Value, json};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/nip46_replay.v1.json");
const OBSERVED_AT: u64 = 1_725_000_000;

fn limits() -> MycNip46AdmissionLimits {
    let config =
        parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::RepoLocal).expect("test config");
    MycNip46AdmissionLimits::from_config(&config).expect("limits")
}

fn keys(seed: u8) -> Keys {
    Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
}

fn provider_binding(target: &Keys) -> MycProviderBinding {
    let section_start = CONFIG
        .find("[identity.transport]")
        .expect("transport section");
    let original = "4444444444444444444444444444444444444444444444444444444444444444";
    let mut source = CONFIG.to_owned();
    let relative = source[section_start..]
        .find(original)
        .expect("configured identity");
    let identity_start = section_start + relative;
    source.replace_range(
        identity_start..identity_start + original.len(),
        &target.public_key().to_hex(),
    );
    parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("test config")
        .provider_contract()
        .binding(MycProviderRole::Transport)
        .expect("transport binding")
        .clone()
}

fn event(sender: &Keys, target: &Keys, created_at: u64) -> Event {
    let content = BASE64_STANDARD.encode([vec![2], vec![0; 32], vec![0; 34], vec![0; 32]].concat());
    EventBuilder::new(Kind::Custom(24_133), content)
        .tag(Tag::public_key(target.public_key()))
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(sender)
        .expect("signed event")
}

fn candidate(
    sender: &Keys,
    target: &Keys,
    created_at: u64,
    request_id: &str,
    method: &str,
    params: Value,
) -> myc::MycReplayBoundNip46Request {
    let plaintext = serde_json::to_vec(&json!({
        "id": request_id,
        "method": method,
        "params": params
    }))
    .expect("request wire");
    candidate_from_plaintext(sender, target, created_at, &plaintext)
}

fn candidate_from_plaintext(
    sender: &Keys,
    target: &Keys,
    created_at: u64,
    plaintext: &[u8],
) -> myc::MycReplayBoundNip46Request {
    let event = event(sender, target, created_at);
    let wire = serde_json::to_vec(&event).expect("event wire");
    let event = verify_myc_nip46_event(
        admit_myc_nip46_event(limits(), &wire).expect("bounded event"),
        &provider_binding(target),
        MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT).expect("observed"),
        MycNip46AuthoredTimePolicy::new(60, 60).expect("policy"),
    )
    .expect("verified event");
    let request = verify_myc_nip46_request(
        admit_myc_nip46_request(limits(), plaintext).expect("bounded request"),
    )
    .expect("verified request");
    bind_myc_nip46_replay(event, request).expect("replay binding")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn machine_contract_freezes_identity_framing_and_authority_split() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("replay contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-replay.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["prerequisite"], "nip46_verification.v1");
    assert_eq!(
        contract["connection_identity"]["domain"],
        "radroots.myc.nip46.connection_identity.v1\\0"
    );
    assert_eq!(
        contract["request_identity"]["domain"],
        "radroots.myc.nip46.request_identity.v1\\0"
    );
    assert_eq!(
        contract["request_digest"]["domain"],
        "radroots.myc.nip46.request.v1\\0"
    );
    assert_eq!(contract["connection_identity"]["digest"], "sha256");
    assert_eq!(contract["request_identity"]["digest"], "sha256");
    assert_eq!(contract["request_digest"]["digest"], "sha256");
    assert_eq!(
        contract["durable_authority"]["new_replay_store"],
        "forbidden"
    );
    assert_eq!(
        contract["nonclaims"],
        json!([
            "ciphertext_decryption",
            "plaintext_event_cryptographic_binding",
            "supported_method_admission",
            "authorization",
            "provider_execution",
            "database_mutation",
            "relay_publication"
        ])
    );
}

#[test]
fn stable_connection_request_and_content_vectors_are_exact() {
    let bound = candidate(
        &keys(1),
        &keys(2),
        OBSERVED_AT,
        "request-01",
        "ping",
        json!([]),
    );
    assert_eq!(
        hex(bound.connection_identity().as_bytes()),
        "93f2c20f3c8043fdae2ec14f08e398ef5012fd813868285d3ed5c2c98ac8e1c1"
    );
    assert_eq!(
        hex(bound.request_identity().as_bytes()),
        "68efc9cd254207260f097997205ee3e34228b290315c53c92cba054dce0452d9"
    );
    assert_eq!(
        hex(bound.request_digest().as_bytes()),
        "378d4f7906aed41e5af96c7000dfc57d9c4c4c9ad3d94b84e985621c25e727f2"
    );
}

#[test]
fn duplicate_replay_conflict_and_distinct_relations_are_total() {
    let sender = keys(3);
    let target = keys(4);
    let retained = candidate(
        &sender,
        &target,
        OBSERVED_AT,
        "request-01",
        "ping",
        json!([]),
    );
    let retained_key = retained.replay_key();
    assert_eq!(format!("{retained_key:?}"), "MycNip46ReplayKey([redacted])");
    drop(retained);
    let duplicate = candidate(
        &sender,
        &target,
        OBSERVED_AT,
        "request-01",
        "ping",
        json!([]),
    );
    assert_eq!(
        duplicate.classify_against(retained_key),
        MycNip46ReplayDisposition::DuplicateEvent
    );

    let replay = candidate(
        &sender,
        &target,
        OBSERVED_AT + 1,
        "request-01",
        "ping",
        json!([]),
    );
    assert_eq!(
        replay.classify_against(retained_key),
        MycNip46ReplayDisposition::ExactRequestReplay
    );

    let normalized_replay = candidate_from_plaintext(
        &sender,
        &target,
        OBSERVED_AT + 1,
        br#"{ "params" : [ ], "method" : "ping", "id" : "request-01" }"#,
    );
    assert_eq!(
        normalized_replay.classify_against(retained_key),
        MycNip46ReplayDisposition::ExactRequestReplay
    );

    let request_conflict = candidate(
        &sender,
        &target,
        OBSERVED_AT + 2,
        "request-01",
        "vendor_method",
        json!(["changed"]),
    );
    assert_eq!(
        request_conflict.classify_against(retained_key),
        MycNip46ReplayDisposition::ConflictingRequestReuse
    );

    let event_conflict = candidate(
        &sender,
        &target,
        OBSERVED_AT,
        "request-02",
        "ping",
        json!([]),
    );
    assert_eq!(
        event_conflict.classify_against(retained_key),
        MycNip46ReplayDisposition::ConflictingEventReuse
    );

    let distinct = candidate(
        &keys(5),
        &target,
        OBSERVED_AT + 3,
        "request-01",
        "ping",
        json!([]),
    );
    assert_eq!(
        distinct.classify_against(retained_key),
        MycNip46ReplayDisposition::DistinctRequest
    );

    let other_receiver = candidate(
        &sender,
        &keys(8),
        OBSERVED_AT + 4,
        "request-01",
        "ping",
        json!([]),
    );
    assert_eq!(
        other_receiver.classify_against(retained_key),
        MycNip46ReplayDisposition::DistinctRequest
    );
}

#[test]
fn binding_is_sealed_redacted_and_not_execution_authority() {
    let sender = keys(6);
    let target = keys(7);
    let bound = candidate(
        &sender,
        &target,
        OBSERVED_AT,
        "protected-request-marker",
        "vendor_secret_method",
        json!(["protected-parameter-marker"]),
    );
    let rendered = format!("{bound:?}");
    for secret in [
        "protected-request-marker",
        "vendor_secret_method",
        "protected-parameter-marker",
        &sender.public_key().to_hex(),
    ] {
        assert!(!rendered.contains(secret));
    }
    assert_eq!(
        rendered,
        "MycReplayBoundNip46Request { identity: \"[redacted]\" }"
    );
}
