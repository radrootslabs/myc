#![forbid(unsafe_code)]

use std::error::Error;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use myc::{
    MycConfigProfile, MycNip46AdmissionLimits, MycNip46AuthoredTimePolicy,
    MycNip46EncryptionContext, MycNip46ObservedAtUnixSeconds, MycNip46VerificationErrorKind,
    MycProviderBinding, MycProviderRole, admit_myc_nip46_event, admit_myc_nip46_request,
    parse_myc_config_v1, verify_myc_nip46_event, verify_myc_nip46_request,
};
use nostr::{
    Event, EventBuilder, EventId, Keys, Kind, Tag, Timestamp,
    nips::{nip04, nip44},
};
use serde_json::{Value, json};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/nip46_verification.v1.json");
const OBSERVED_AT: u64 = 1_725_000_000;

fn limits() -> MycNip46AdmissionLimits {
    let config =
        parse_myc_config_v1(CONFIG.as_bytes(), MycConfigProfile::RepoLocal).expect("test config");
    MycNip46AdmissionLimits::from_config(&config).expect("limits")
}

fn keys(seed: u8) -> Keys {
    Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
}

fn provider_binding(role: MycProviderRole, keys: &Keys) -> MycProviderBinding {
    let (section, original) = match role {
        MycProviderRole::Transport => (
            "[identity.transport]",
            "4444444444444444444444444444444444444444444444444444444444444444",
        ),
        MycProviderRole::User => (
            "[identity.user]",
            "2222222222222222222222222222222222222222222222222222222222222222",
        ),
        MycProviderRole::Discovery => (
            "[identity.discovery.binding]",
            "3333333333333333333333333333333333333333333333333333333333333333",
        ),
    };
    let section_start = CONFIG.find(section).expect("identity section");
    let mut source = CONFIG.to_owned();
    let relative = source[section_start..]
        .find(original)
        .expect("configured identity");
    let identity_start = section_start + relative;
    source.replace_range(
        identity_start..identity_start + original.len(),
        &keys.public_key().to_hex(),
    );
    parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
        .expect("test config")
        .provider_contract()
        .binding(role)
        .expect("provider binding")
        .clone()
}

fn signed_event(sender: &Keys, receiver: &Keys, content: String, created_at: u64) -> Event {
    EventBuilder::new(Kind::Custom(24_133), content)
        .tag(Tag::public_key(receiver.public_key()))
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(sender)
        .expect("signed event")
}

fn verify_event(
    event: &Event,
    receiver_keys: &Keys,
    policy: MycNip46AuthoredTimePolicy,
) -> Result<myc::MycVerifiedNip46Event, myc::MycNip46VerificationError> {
    let wire = serde_json::to_vec(event).expect("event JSON");
    let bounded = admit_myc_nip46_event(limits(), &wire).expect("bounded event");
    verify_myc_nip46_event(
        bounded,
        &provider_binding(MycProviderRole::Transport, receiver_keys),
        MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT).expect("observation"),
        policy,
    )
}

fn request(id: &str, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": id, "method": method, "params": params}))
        .expect("request JSON")
}

#[test]
fn machine_contract_freezes_exact_step_boundary() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("verification contract");
    assert_eq!(contract["schema"], "radroots.myc.nip46-verification.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["event"]["kind"], 24_133);
    assert_eq!(contract["authored_time"]["default"], "none");
    assert_eq!(
        contract["encryption"]["contexts"],
        json!(["nip04", "nip44_v2"])
    );
    assert_eq!(contract["encryption"]["decryption"], "deferred_to_step_145");
    assert_eq!(
        contract["request"]["replay_and_conflicting_reuse"],
        "deferred_to_step_143"
    );
}

#[test]
fn signed_nip44_and_nip04_events_verify_without_decrypting() {
    let sender = keys(1);
    let target = keys(2);
    let policy = MycNip46AuthoredTimePolicy::new(60, 10).expect("policy");
    let plaintext = br#"{"id":"request-secret-marker","method":"ping","params":[]}"#;

    let nip44_content = nip44::encrypt(
        sender.secret_key(),
        &target.public_key(),
        plaintext,
        nip44::Version::V2,
    )
    .expect("NIP-44 encrypt");
    let event = signed_event(&sender, &target, nip44_content.clone(), OBSERVED_AT);
    let wire = serde_json::to_vec(&event).expect("event wire");
    let verified = verify_event(&event, &target, policy).expect("verified NIP-44 event");
    assert_eq!(verified.original_bytes(), wire);
    assert_eq!(verified.event_id().as_bytes(), &event.id.to_bytes());
    assert_eq!(
        verified.client_public_key().as_hex(),
        sender.public_key().to_hex()
    );
    assert_eq!(verified.authored_at_unix_seconds(), OBSERVED_AT);
    assert_eq!(
        verified.encryption_context(),
        MycNip46EncryptionContext::Nip44V2
    );
    assert_eq!(verified.encrypted_content(), nip44_content);

    let nip04_content = nip04::encrypt(sender.secret_key(), &target.public_key(), plaintext)
        .expect("NIP-04 encrypt");
    let event = signed_event(&sender, &target, nip04_content, OBSERVED_AT);
    assert_eq!(
        verify_event(&event, &target, policy)
            .expect("verified NIP-04 event")
            .encryption_context(),
        MycNip46EncryptionContext::Nip04
    );
}

#[test]
fn canonical_kind_sender_and_exact_receiver_shape_fail_closed() {
    let sender = keys(3);
    let target = keys(4);
    let policy = MycNip46AuthoredTimePolicy::new(60, 10).expect("policy");
    let content = BASE64_STANDARD.encode([vec![2], vec![0; 32], vec![0; 34], vec![0; 32]].concat());

    let wrong_kind = EventBuilder::new(Kind::Custom(24_132), content.clone())
        .tag(Tag::public_key(target.public_key()))
        .custom_created_at(Timestamp::from_secs(OBSERVED_AT))
        .sign_with_keys(&sender)
        .expect("wrong-kind event");
    assert_eq!(
        verify_event(&wrong_kind, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidKind
    );

    let self_sent = signed_event(&target, &target, content.clone(), OBSERVED_AT);
    assert_eq!(
        verify_event(&self_sent, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidSender
    );

    let wrong_target = keys(5);
    let wrong_recipient = signed_event(&sender, &wrong_target, content.clone(), OBSERVED_AT);
    assert_eq!(
        verify_event(&wrong_recipient, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidReceiver
    );

    let extra_tag = EventBuilder::new(Kind::Custom(24_133), content)
        .tags([
            Tag::public_key(target.public_key()),
            Tag::parse(["client", "untrusted-metadata"]).expect("extra tag"),
        ])
        .custom_created_at(Timestamp::from_secs(OBSERVED_AT))
        .sign_with_keys(&sender)
        .expect("extra-tag event");
    assert_eq!(
        verify_event(&extra_tag, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidReceiver
    );
}

#[test]
fn identifiers_event_id_and_signature_are_independently_verified() {
    let sender = keys(6);
    let target = keys(7);
    let policy = MycNip46AuthoredTimePolicy::new(60, 10).expect("policy");
    let payload = BASE64_STANDARD.encode([vec![2], vec![0; 32], vec![0; 34], vec![0; 32]].concat());
    let event = signed_event(&sender, &target, payload.clone(), OBSERVED_AT);

    let wire = String::from_utf8(serde_json::to_vec(&event).expect("wire")).expect("UTF-8");
    let uppercase = wire.replacen(&event.id.to_hex(), &event.id.to_hex().to_uppercase(), 1);
    let bounded = admit_myc_nip46_event(limits(), uppercase.as_bytes()).expect("bounded uppercase");
    assert_eq!(
        verify_myc_nip46_event(
            bounded,
            &provider_binding(MycProviderRole::Transport, &target),
            MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT).expect("observed"),
            policy,
        )
        .unwrap_err()
        .kind(),
        MycNip46VerificationErrorKind::NonCanonicalEvent
    );

    let mut wrong_id = event.clone();
    wrong_id.id = EventId::all_zeros();
    assert_eq!(
        verify_event(&wrong_id, &target, policy).unwrap_err().kind(),
        MycNip46VerificationErrorKind::InvalidEventId
    );

    let other = signed_event(&keys(8), &target, payload, OBSERVED_AT);
    let mut wrong_signature = event;
    wrong_signature.sig = other.sig;
    assert_eq!(
        verify_event(&wrong_signature, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidSignature
    );
}

#[test]
fn authored_time_policy_is_explicit_inclusive_and_overflow_safe() {
    assert!(MycNip46ObservedAtUnixSeconds::new(0).is_err());
    assert!(MycNip46ObservedAtUnixSeconds::new(i64::MAX as u64).is_ok());
    assert!(MycNip46ObservedAtUnixSeconds::new(i64::MAX as u64 + 1).is_err());
    assert!(MycNip46AuthoredTimePolicy::new(i64::MAX as u64, 0).is_ok());
    assert!(MycNip46AuthoredTimePolicy::new(i64::MAX as u64 + 1, 0).is_err());

    let sender = keys(9);
    let target = keys(10);
    let payload = BASE64_STANDARD.encode([vec![2], vec![0; 32], vec![0; 34], vec![0; 32]].concat());
    let policy = MycNip46AuthoredTimePolicy::new(10, 2).expect("policy");
    for accepted in [OBSERVED_AT - 10, OBSERVED_AT + 2] {
        verify_event(
            &signed_event(&sender, &target, payload.clone(), accepted),
            &target,
            policy,
        )
        .expect("inclusive boundary");
    }
    for rejected in [OBSERVED_AT - 11, OBSERVED_AT + 3] {
        assert_eq!(
            verify_event(
                &signed_event(&sender, &target, payload.clone(), rejected),
                &target,
                policy,
            )
            .unwrap_err()
            .kind(),
            MycNip46VerificationErrorKind::AuthoredTimeRejected
        );
    }
}

#[test]
fn only_the_configured_transport_role_can_supply_receiver_authority() {
    let sender = keys(15);
    let target = keys(16);
    let payload = BASE64_STANDARD.encode([vec![2], vec![0; 32], vec![0; 34], vec![0; 32]].concat());
    let event = signed_event(&sender, &target, payload, OBSERVED_AT);
    let wire = serde_json::to_vec(&event).expect("event wire");
    let bounded = admit_myc_nip46_event(limits(), &wire).expect("bounded event");
    let error = verify_myc_nip46_event(
        bounded,
        &provider_binding(MycProviderRole::User, &target),
        MycNip46ObservedAtUnixSeconds::new(OBSERVED_AT).expect("observation"),
        MycNip46AuthoredTimePolicy::new(0, 0).expect("policy"),
    )
    .expect_err("user identity cannot become transport receiver authority");
    assert_eq!(
        error.kind(),
        MycNip46VerificationErrorKind::InvalidTransportBinding
    );
}

#[test]
fn nip04_and_nip44_envelope_shapes_are_canonical_and_versioned() {
    let sender = keys(11);
    let target = keys(12);
    let policy = MycNip46AuthoredTimePolicy::new(1, 1).expect("policy");

    let invalid_nip04 = signed_event(&sender, &target, "AAAA?iv=AAAA".to_owned(), OBSERVED_AT);
    assert_eq!(
        verify_event(&invalid_nip04, &target, policy)
            .unwrap_err()
            .kind(),
        MycNip46VerificationErrorKind::InvalidNip04Envelope
    );

    let mut wrong_version = vec![0; 99];
    wrong_version[0] = 3;
    let event = signed_event(
        &sender,
        &target,
        BASE64_STANDARD.encode(wrong_version),
        OBSERVED_AT,
    );
    assert_eq!(
        verify_event(&event, &target, policy).unwrap_err().kind(),
        MycNip46VerificationErrorKind::InvalidNip44Envelope
    );

    let mut invalid_padding = vec![0; 100];
    invalid_padding[0] = 2;
    let event = signed_event(
        &sender,
        &target,
        BASE64_STANDARD.encode(invalid_padding),
        OBSERVED_AT,
    );
    assert_eq!(
        verify_event(&event, &target, policy).unwrap_err().kind(),
        MycNip46VerificationErrorKind::InvalidNip44Envelope
    );
}

#[test]
fn exact_typed_request_decoding_accepts_governed_and_custom_methods_only_when_semantic() {
    let ping = request("request-01", "ping", json!([]));
    let bounded = admit_myc_nip46_request(limits(), &ping).expect("bounded ping");
    let verified = verify_myc_nip46_request(bounded).expect("typed ping");
    assert_eq!(verified.request_id().as_str(), "request-01");
    assert_eq!(verified.method(), "ping");
    assert_eq!(verified.parameter_count(), 0);
    assert_eq!(verified.parameter_bytes(), 0);

    let custom = request("custom-01", "vendor_method", json!(["a", "bc"]));
    let bounded = admit_myc_nip46_request(limits(), &custom).expect("bounded custom");
    let verified = verify_myc_nip46_request(bounded).expect("typed custom");
    assert_eq!(verified.method(), "vendor_method");
    assert_eq!(verified.parameter_count(), 2);
    assert_eq!(verified.parameter_bytes(), 3);

    for invalid in [
        request("", "ping", json!([])),
        request(" request ", "ping", json!([])),
        request("request-02", "ping", json!(["unexpected"])),
        request("request-03", "nip44_encrypt", json!(["not-a-key", "x"])),
    ] {
        let bounded = admit_myc_nip46_request(limits(), &invalid).expect("structurally bounded");
        assert_eq!(
            verify_myc_nip46_request(bounded).unwrap_err().kind(),
            MycNip46VerificationErrorKind::InvalidTypedRequest
        );
    }
}

#[test]
fn verified_capabilities_and_errors_redact_protected_content() {
    let sender = keys(13);
    let target = keys(14);
    let marker = br#"{"id":"protected-request-marker","method":"ping","params":[]}"#;
    let ciphertext = nip44::encrypt(
        sender.secret_key(),
        &target.public_key(),
        marker,
        nip44::Version::V2,
    )
    .expect("ciphertext");
    let event = signed_event(&sender, &target, ciphertext.clone(), OBSERVED_AT);
    let verified_event = verify_event(
        &event,
        &target,
        MycNip46AuthoredTimePolicy::new(0, 0).expect("policy"),
    )
    .expect("verified event");
    let rendered = format!("{verified_event:?}");
    assert!(!rendered.contains(&ciphertext));
    assert!(!rendered.contains(&sender.public_key().to_hex()));

    let bounded = admit_myc_nip46_request(limits(), marker).expect("bounded request");
    let verified_request = verify_myc_nip46_request(bounded).expect("verified request");
    let rendered = format!("{verified_request:?}");
    assert!(!rendered.contains("protected-request-marker"));
    assert!(!rendered.contains("ping"));

    for kind in [
        MycNip46VerificationErrorKind::InvalidObservationTime,
        MycNip46VerificationErrorKind::InvalidTimePolicy,
        MycNip46VerificationErrorKind::InvalidTransportBinding,
        MycNip46VerificationErrorKind::MalformedEvent,
        MycNip46VerificationErrorKind::NonCanonicalEvent,
        MycNip46VerificationErrorKind::InvalidKind,
        MycNip46VerificationErrorKind::InvalidSender,
        MycNip46VerificationErrorKind::InvalidReceiver,
        MycNip46VerificationErrorKind::InvalidEventId,
        MycNip46VerificationErrorKind::InvalidSignature,
        MycNip46VerificationErrorKind::AuthoredTimeRejected,
        MycNip46VerificationErrorKind::InvalidNip04Envelope,
        MycNip46VerificationErrorKind::InvalidNip44Envelope,
        MycNip46VerificationErrorKind::InvalidTypedRequest,
    ] {
        let error = if kind == MycNip46VerificationErrorKind::InvalidObservationTime {
            MycNip46ObservedAtUnixSeconds::new(0).unwrap_err()
        } else if kind == MycNip46VerificationErrorKind::InvalidTimePolicy {
            MycNip46AuthoredTimePolicy::new(u64::MAX, 0).unwrap_err()
        } else {
            continue;
        };
        assert_eq!(error.kind(), kind);
        assert!(!error.to_string().is_empty());
        assert!(error.source().is_none());
    }
}
