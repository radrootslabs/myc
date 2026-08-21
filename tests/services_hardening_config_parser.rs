#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    MYC_CONFIG_SCHEMA, MYC_CONFIG_SCHEMA_VERSION, MycConfigProfile, MycConfigV1ErrorKind,
    parse_myc_config_v1,
};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

#[test]
fn root_api_admits_the_canonical_document_and_exposes_only_redacted_effective_output() {
    let document = parse_myc_config_v1(EXAMPLE.as_bytes(), MycConfigProfile::Production)
        .expect("canonical configuration");
    assert_eq!(document.schema(), MYC_CONFIG_SCHEMA);
    assert_eq!(document.schema_version(), MYC_CONFIG_SCHEMA_VERSION);
    assert_eq!(document.relay_count(), 2);

    let effective = document.effective().canonical_json();
    assert!(effective.contains("\"source\":\"document\""));
    assert!(effective.contains("[redacted-public-key]"));
    for forbidden in [
        "/var/lib/radroots",
        "/run/radroots",
        "relay-primary.example.test",
        "1111111111111111",
        "transport_wrapping_key",
    ] {
        assert!(!effective.contains(forbidden));
        assert!(!format!("{document:?}").contains(forbidden));
    }
}

#[test]
fn root_api_failure_is_stable_and_source_free() {
    let secret = "never-render-this-value";
    let invalid = EXAMPLE.replacen(
        "shutdown_grace_ms = 30000",
        &format!("unknown = \"{secret}\""),
        1,
    );
    let failure = parse_myc_config_v1(invalid.as_bytes(), MycConfigProfile::Production)
        .expect_err("unknown field must fail");
    assert_eq!(failure.kind(), MycConfigV1ErrorKind::InvalidDocument);
    assert!(Error::source(&failure).is_none());
    assert!(!format!("{failure} {failure:?}").contains(secret));
}
