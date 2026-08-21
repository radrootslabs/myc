//! Strict, bounded Myc configuration document v1 admission.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;

use nostr::PublicKey;
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use crate::provider_contract::MycProviderContract;

const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");

/// Exact schema identity for the production Myc configuration document.
pub const MYC_CONFIG_SCHEMA: &str = "radroots.myc.config";

/// Exact supported Myc configuration schema version.
pub const MYC_CONFIG_SCHEMA_VERSION: u32 = 1;

/// Hard cap applied to original bytes before UTF-8 or TOML parsing.
pub const MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES: usize = 1_048_576;

/// Bootstrap-selected network posture used during relay admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConfigProfile {
    /// Production and ordinary service-host configurations require WSS relays.
    Production,
    /// Explicit repository-local development may also use loopback WS relays.
    RepoLocal,
}

/// Stable source classification for an effective configuration value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycConfigValueSource {
    Document,
    RadrootsServiceHost,
    RadrootsServiceSqlite,
    RadrootsEvent,
    RadrootsNostrConnect,
    AcceptedServiceAuthority,
    EngineeringSafety,
}

/// Stable source-free classification for configuration admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConfigV1ErrorKind {
    TooLarge,
    InvalidUtf8,
    MalformedToml,
    MissingSchema,
    InvalidSchema,
    SchemaMismatch,
    MissingSchemaVersion,
    InvalidSchemaVersion,
    UnsupportedSchemaVersion,
    InvalidDocument,
    InvalidRelationship,
    Encoding,
}

impl MycConfigV1ErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "configuration document exceeds its size limit",
            Self::InvalidUtf8 => "configuration document is not valid UTF-8",
            Self::MalformedToml => "configuration document is not valid TOML",
            Self::MissingSchema => "configuration document schema is missing",
            Self::InvalidSchema => "configuration document schema is invalid",
            Self::SchemaMismatch => "configuration document schema is unsupported",
            Self::MissingSchemaVersion => "configuration document schema version is missing",
            Self::InvalidSchemaVersion => "configuration document schema version is invalid",
            Self::UnsupportedSchemaVersion => {
                "configuration document schema version is unsupported"
            }
            Self::InvalidDocument => "configuration document fields are invalid",
            Self::InvalidRelationship => "configuration document relationships are invalid",
            Self::Encoding => "effective configuration could not be encoded",
        }
    }
}

/// One source-free configuration admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycConfigV1Error {
    kind: MycConfigV1ErrorKind,
}

impl MycConfigV1Error {
    const fn new(kind: MycConfigV1ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycConfigV1ErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycConfigV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConfigV1Error")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycConfigV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycConfigV1Error {}

/// Deterministic redacted effective configuration with exact leaf provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct MycEffectiveConfigV1 {
    canonical_json: Box<str>,
    field_count: usize,
}

impl MycEffectiveConfigV1 {
    /// Returns compact JSON in deterministic path order.
    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    /// Returns the number of projected effective leaf values.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.field_count
    }
}

impl fmt::Debug for MycEffectiveConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycEffectiveConfigV1")
            .field("canonical_json", &"[redacted]")
            .field("field_count", &self.field_count)
            .finish()
    }
}

/// A validated immutable Myc configuration document v1.
pub struct MycConfigDocumentV1 {
    profile: MycConfigProfile,
    normalized: Value,
    effective: MycEffectiveConfigV1,
    provider_contract: MycProviderContract,
}

impl MycConfigDocumentV1 {
    /// Returns the exact admitted schema identity.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        MYC_CONFIG_SCHEMA
    }

    /// Returns the exact admitted schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        MYC_CONFIG_SCHEMA_VERSION
    }

    /// Returns the bootstrap-selected network posture used during admission.
    #[must_use]
    pub const fn profile(&self) -> MycConfigProfile {
        self.profile
    }

    /// Returns the deterministic redacted effective configuration projection.
    #[must_use]
    pub const fn effective(&self) -> &MycEffectiveConfigV1 {
        &self.effective
    }

    /// Returns the exact number of configured relay bindings.
    #[must_use]
    pub fn relay_count(&self) -> usize {
        self.normalized
            .pointer("/relays")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    /// Returns the immutable provider assignments derived from this document.
    #[must_use]
    pub const fn provider_contract(&self) -> &MycProviderContract {
        &self.provider_contract
    }

    pub(crate) const fn normalized(&self) -> &Value {
        &self.normalized
    }
}

impl fmt::Debug for MycConfigDocumentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConfigDocumentV1")
            .field("schema", &MYC_CONFIG_SCHEMA)
            .field("schema_version", &MYC_CONFIG_SCHEMA_VERSION)
            .field("profile", &self.profile)
            .field("effective", &self.effective)
            .field("provider_contract", &self.provider_contract)
            .finish()
    }
}

/// Parses and semantically validates one complete Myc configuration document.
pub fn parse_myc_config_v1(
    bytes: &[u8],
    profile: MycConfigProfile,
) -> Result<MycConfigDocumentV1, MycConfigV1Error> {
    if bytes.len() > MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES {
        return Err(error(MycConfigV1ErrorKind::TooLarge));
    }
    let source =
        std::str::from_utf8(bytes).map_err(|_| error(MycConfigV1ErrorKind::InvalidUtf8))?;
    let original = source
        .parse::<toml::Table>()
        .map_err(|_| error(MycConfigV1ErrorKind::MalformedToml))?;
    validate_header(&original)?;
    let mut normalized = serde_json::to_value(toml::Value::Table(original.clone()))
        .map_err(|_| error(MycConfigV1ErrorKind::InvalidDocument))?;
    let schema: Value =
        serde_json::from_str(CONFIG_SCHEMA).map_err(|_| error(MycConfigV1ErrorKind::Encoding))?;
    let validator =
        jsonschema::validator_for(&schema).map_err(|_| error(MycConfigV1ErrorKind::Encoding))?;
    if !validator.is_valid(&normalized) {
        return Err(error(MycConfigV1ErrorKind::InvalidDocument));
    }
    apply_defaults(&mut normalized)?;
    if !validator.is_valid(&normalized) {
        return Err(error(MycConfigV1ErrorKind::InvalidDocument));
    }
    validate_relationships(&normalized, profile)?;
    let effective = build_effective(&normalized, &original)?;
    let provider_contract = MycProviderContract::from_normalized(&normalized)
        .map_err(|_| error(MycConfigV1ErrorKind::InvalidRelationship))?;
    Ok(MycConfigDocumentV1 {
        profile,
        normalized,
        effective,
        provider_contract,
    })
}

fn validate_header(header: &toml::Table) -> Result<(), MycConfigV1Error> {
    let schema = header
        .get("schema")
        .ok_or_else(|| error(MycConfigV1ErrorKind::MissingSchema))?
        .as_str()
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidSchema))?;
    if !valid_schema_id(schema) {
        return Err(error(MycConfigV1ErrorKind::InvalidSchema));
    }
    if schema != MYC_CONFIG_SCHEMA {
        return Err(error(MycConfigV1ErrorKind::SchemaMismatch));
    }
    let version = header
        .get("schema_version")
        .ok_or_else(|| error(MycConfigV1ErrorKind::MissingSchemaVersion))?
        .as_integer()
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidSchemaVersion))?;
    let version =
        u32::try_from(version).map_err(|_| error(MycConfigV1ErrorKind::InvalidSchemaVersion))?;
    if version == 0 {
        return Err(error(MycConfigV1ErrorKind::InvalidSchemaVersion));
    }
    if version != MYC_CONFIG_SCHEMA_VERSION {
        return Err(error(MycConfigV1ErrorKind::UnsupportedSchemaVersion));
    }
    Ok(())
}

fn valid_schema_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[derive(Clone, Copy)]
struct DefaultEntry {
    path: &'static str,
    value: DefaultValue,
    source: MycConfigValueSource,
    enabled_pointer: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum DefaultValue {
    Integer(u64),
    String(&'static str),
}

const DEFAULTS: &[DefaultEntry] = &[
    default(
        "/service/shutdown_grace_ms",
        30_000,
        MycConfigValueSource::EngineeringSafety,
    ),
    default_string(
        "/logging/level",
        "info",
        MycConfigValueSource::EngineeringSafety,
    ),
    default_string(
        "/logging/format",
        "json",
        MycConfigValueSource::AcceptedServiceAuthority,
    ),
    conditional_default(
        "/operations/limits/header_count",
        32,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/header_bytes",
        16_384,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/response_body_utf8_bytes",
        1_048_576,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/concurrent_connections",
        32,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/request_deadline_ms",
        15_000,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/idle_timeout_ms",
        30_000,
        MycConfigValueSource::RadrootsServiceHost,
        "/operations/enabled",
    ),
    default(
        "/database/busy_timeout_ms",
        5_000,
        MycConfigValueSource::RadrootsServiceSqlite,
    ),
    default(
        "/database/max_connections",
        8,
        MycConfigValueSource::RadrootsServiceSqlite,
    ),
    default(
        "/transport/connect_deadline_ms",
        10_000,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/transport/publish_retry/max_attempts",
        5,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/transport/publish_retry/initial_backoff_ms",
        250,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/transport/publish_retry/maximum_backoff_ms",
        30_000,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/transport/publish_retry/attempt_deadline_ms",
        15_000,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/header_count",
        32,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/header_bytes",
        16_384,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/request_body_utf8_bytes",
        65_536,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/response_body_utf8_bytes",
        1_048_576,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/concurrent_connections",
        32,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/request_deadline_ms",
        15_000,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/idle_timeout_ms",
        30_000,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/query_items",
        100,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/events/wire_bytes",
        262_144,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/content_bytes",
        131_072,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_count",
        1_024,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_total_elements",
        4_096,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_element_bytes",
        4_096,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_total_bytes",
        131_072,
        MycConfigValueSource::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/decrypted_plaintext_bytes",
        262_144,
        MycConfigValueSource::RadrootsNostrConnect,
    ),
    default(
        "/resource_limits/queues/ingress",
        1_024,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/provider",
        64,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/outbox",
        4_096,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/discovery",
        64,
        MycConfigValueSource::EngineeringSafety,
    ),
    default(
        "/resource_limits/metrics/descriptors",
        64,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/samples",
        512,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/labels_per_sample",
        8,
        MycConfigValueSource::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/render_utf8_bytes",
        1_048_576,
        MycConfigValueSource::RadrootsServiceHost,
    ),
];

const fn default(path: &'static str, value: u64, source: MycConfigValueSource) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::Integer(value),
        source,
        enabled_pointer: None,
    }
}

const fn conditional_default(
    path: &'static str,
    value: u64,
    source: MycConfigValueSource,
    enabled_pointer: &'static str,
) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::Integer(value),
        source,
        enabled_pointer: Some(enabled_pointer),
    }
}

const fn default_string(
    path: &'static str,
    value: &'static str,
    source: MycConfigValueSource,
) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::String(value),
        source,
        enabled_pointer: None,
    }
}

fn apply_defaults(document: &mut Value) -> Result<(), MycConfigV1Error> {
    for entry in DEFAULTS {
        if entry
            .enabled_pointer
            .is_some_and(|pointer| document.pointer(pointer) != Some(&Value::Bool(true)))
            || document.pointer(entry.path).is_some()
        {
            continue;
        }
        insert_json_pointer(document, entry.path, entry.value)?;
    }
    Ok(())
}

fn insert_json_pointer(
    root: &mut Value,
    pointer: &str,
    value: DefaultValue,
) -> Result<(), MycConfigV1Error> {
    let mut parts = pointer
        .split('/')
        .filter(|part| !part.is_empty())
        .peekable();
    let mut current = root;
    while let Some(part) = parts.next() {
        let object = current
            .as_object_mut()
            .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))?;
        if parts.peek().is_none() {
            object.insert(
                part.to_owned(),
                match value {
                    DefaultValue::Integer(value) => Value::Number(value.into()),
                    DefaultValue::String(value) => Value::String(value.to_owned()),
                },
            );
            return Ok(());
        }
        current = object
            .entry(part.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Err(error(MycConfigV1ErrorKind::InvalidDocument))
}

fn validate_relationships(
    document: &Value,
    profile: MycConfigProfile,
) -> Result<(), MycConfigV1Error> {
    validate_utf8_byte_limits(document)?;
    let relays = array(document, "/relays")?;
    let mut ids = BTreeSet::new();
    let mut urls = BTreeSet::new();
    let mut has_read = false;
    let mut has_write = false;
    let mut has_required_read = false;
    let mut has_required_write = false;
    for relay in relays {
        let id = string_at(relay, "/id")?;
        let raw_url = string_at(relay, "/url")?;
        canonical_relay_url(raw_url, profile)?;
        let read = bool_at(relay, "/read")?;
        let write = bool_at(relay, "/write")?;
        let required = bool_at(relay, "/required")?;
        if !ids.insert(id) || !urls.insert(raw_url) || (!read && !write) {
            return relationship_error();
        }
        has_read |= read;
        has_write |= write;
        has_required_read |= required && read;
        has_required_write |= required && write;
    }
    if !(has_read && has_write && has_required_read && has_required_write) {
        return relationship_error();
    }
    validate_unique_role_keys(document)?;
    validate_client_policy(document)?;
    validate_challenges(document)?;
    validate_rate_limits(document)?;
    validate_transport(document, relays)?;
    validate_discovery(document, relays)?;
    validate_operations(document)
}

fn validate_utf8_byte_limits(document: &Value) -> Result<(), MycConfigV1Error> {
    validate_provider_bytes(document, "/identity/transport")?;
    validate_provider_bytes(document, "/identity/user")?;
    if bool_value(document, "/identity/discovery/enabled")? {
        validate_provider_bytes(document, "/identity/discovery/binding")?;
    }
    for relay in array(document, "/relays")? {
        validate_string_bytes(string_at(relay, "/id")?, 1, 64)?;
        validate_string_bytes(string_at(relay, "/url")?, 1, 2_048)?;
    }
    if bool_value(document, "/operations/enabled")? {
        validate_string_bytes(string(document, "/operations/listen")?, 1, 128)?;
    }
    if bool_value(document, "/policy/challenges/enabled")? {
        validate_string_bytes(string(document, "/policy/challenges/url")?, 1, 2_048)?;
    }
    if bool_value(document, "/discovery/enabled")? {
        for (pointer, minimum, maximum) in [
            ("/discovery/domain", 1, 253),
            ("/discovery/handler_identifier", 1, 128),
            ("/discovery/nostrconnect_url_template", 1, 2_048),
            ("/discovery/metadata/name", 1, 128),
            ("/discovery/metadata/display_name", 1, 128),
            ("/discovery/metadata/about", 0, 1_024),
            ("/discovery/metadata/website", 1, 2_048),
            ("/discovery/metadata/picture", 1, 2_048),
        ] {
            validate_string_bytes(string(document, pointer)?, minimum, maximum)?;
        }
    }
    Ok(())
}

fn validate_provider_bytes(document: &Value, prefix: &str) -> Result<(), MycConfigV1Error> {
    match string(document, &format!("{prefix}/provider"))? {
        "encrypted_file" => {
            validate_string_bytes(
                string(document, &format!("{prefix}/envelope_path"))?,
                1,
                4_096,
            )?;
            validate_string_bytes(
                string(document, &format!("{prefix}/credential_reference"))?,
                1,
                128,
            )
        }
        "local_signer" => validate_string_bytes(
            string(document, &format!("{prefix}/socket_path"))?,
            1,
            4_096,
        ),
        _ => document_error(),
    }
}

fn validate_string_bytes(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), MycConfigV1Error> {
    if (minimum..=maximum).contains(&value.len()) {
        Ok(())
    } else {
        document_error()
    }
}

fn validate_unique_role_keys(document: &Value) -> Result<(), MycConfigV1Error> {
    let mut keys = vec![
        string(document, "/identity/transport/expected_public_key")?,
        string(document, "/identity/user/expected_public_key")?,
    ];
    if bool_value(document, "/identity/discovery/enabled")? {
        keys.push(string(
            document,
            "/identity/discovery/binding/expected_public_key",
        )?);
    }
    if keys.iter().any(|key| !valid_nostr_public_key(key))
        || keys.iter().copied().collect::<BTreeSet<_>>().len() != keys.len()
    {
        return relationship_error();
    }
    Ok(())
}

fn validate_client_policy(document: &Value) -> Result<(), MycConfigV1Error> {
    let trusted = string_set(document, "/policy/trusted_clients")?;
    let denied = string_set(document, "/policy/denied_clients")?;
    if trusted
        .iter()
        .chain(denied.iter())
        .any(|key| !valid_nostr_public_key(key))
        || !trusted.is_disjoint(&denied)
    {
        return relationship_error();
    }
    let permission_kinds = string_set(document, "/policy/permission_ceiling")?
        .into_iter()
        .filter_map(|permission| permission.strip_prefix("sign_event:kind:"))
        .map(|kind| {
            kind.parse::<u32>()
                .map_err(|_| error(MycConfigV1ErrorKind::InvalidDocument))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let allowed_kinds = array(document, "/policy/allowed_sign_event_kinds")?
        .iter()
        .map(|kind| kind.as_u64().and_then(|value| u32::try_from(value).ok()))
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))?;
    if permission_kinds != allowed_kinds {
        return relationship_error();
    }
    Ok(())
}

fn valid_nostr_public_key(value: &str) -> bool {
    PublicKey::from_hex(value).is_ok_and(|public_key| public_key.xonly().is_ok())
}

fn validate_challenges(document: &Value) -> Result<(), MycConfigV1Error> {
    if bool_value(document, "/policy/challenges/enabled")?
        && integer(document, "/policy/challenges/authorized_lifetime_ms")?
            < integer(document, "/policy/challenges/pending_lifetime_ms")?
    {
        return relationship_error();
    }
    Ok(())
}

fn validate_rate_limits(document: &Value) -> Result<(), MycConfigV1Error> {
    for (name, expected_scope) in [
        ("connection_admission", "global_and_relay"),
        ("challenge_creation", "connection"),
        ("challenge_authorization", "connection"),
    ] {
        let prefix = format!("/rate_limits/{name}");
        if string(document, &format!("{prefix}/scope"))? != expected_scope
            || integer(document, &format!("{prefix}/retention_ms"))?
                < integer(document, &format!("{prefix}/window_ms"))?
        {
            return relationship_error();
        }
    }
    Ok(())
}

fn validate_transport(document: &Value, relays: &[Value]) -> Result<(), MycConfigV1Error> {
    if integer(document, "/transport/publish_retry/initial_backoff_ms")?
        > integer(document, "/transport/publish_retry/maximum_backoff_ms")?
    {
        return relationship_error();
    }
    if string(document, "/transport/delivery_policy/mode")? == "required_quorum" {
        let required = integer(
            document,
            "/transport/delivery_policy/required_acknowledgements",
        )?;
        let required_writers = relays
            .iter()
            .filter(|relay| {
                bool_at(relay, "/required") == Ok(true) && bool_at(relay, "/write") == Ok(true)
            })
            .count() as u64;
        if required > required_writers {
            return relationship_error();
        }
    }
    Ok(())
}

fn validate_discovery(document: &Value, relays: &[Value]) -> Result<(), MycConfigV1Error> {
    let enabled = bool_value(document, "/discovery/enabled")?;
    if enabled != bool_value(document, "/identity/discovery/enabled")? {
        return relationship_error();
    }
    if !enabled {
        return Ok(());
    }
    for (pointer, capability) in [
        ("/discovery/public_relay_ids", "read"),
        ("/discovery/publish_relay_ids", "write"),
    ] {
        for relay_id in string_set(document, pointer)? {
            if !relays.iter().any(|relay| {
                string_at(relay, "/id") == Ok(relay_id)
                    && bool_at(relay, &format!("/{capability}")) == Ok(true)
            }) {
                return relationship_error();
            }
        }
    }
    Ok(())
}

fn validate_operations(document: &Value) -> Result<(), MycConfigV1Error> {
    if !bool_value(document, "/operations/enabled")? {
        return Ok(());
    }
    let address = string(document, "/operations/listen")?
        .parse::<SocketAddr>()
        .map_err(|_| error(MycConfigV1ErrorKind::InvalidDocument))?;
    if address.port() == 0
        || (string(document, "/operations/bind_policy")? == "loopback_only"
            && !address.ip().is_loopback())
    {
        return relationship_error();
    }
    Ok(())
}

fn canonical_relay_url(value: &str, profile: MycConfigProfile) -> Result<Url, MycConfigV1Error> {
    let parsed = Url::parse(value).map_err(|_| error(MycConfigV1ErrorKind::InvalidDocument))?;
    if parsed.as_str() != value
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return document_error();
    }
    let allowed = match profile {
        MycConfigProfile::Production => parsed.scheme() == "wss",
        MycConfigProfile::RepoLocal => match parsed.scheme() {
            "wss" => true,
            "ws" => parsed
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")),
            _ => false,
        },
    };
    if !allowed {
        return relationship_error();
    }
    Ok(parsed)
}

fn array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value], MycConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, MycConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, MycConfigV1Error> {
    string(value, pointer)
}

fn string_set<'a>(value: &'a Value, pointer: &str) -> Result<BTreeSet<&'a str>, MycConfigV1Error> {
    array(value, pointer)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))
        })
        .collect()
}

fn bool_value(value: &Value, pointer: &str) -> Result<bool, MycConfigV1Error> {
    bool_at(value, pointer)
}

fn bool_at(value: &Value, pointer: &str) -> Result<bool, MycConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))
}

fn integer(value: &Value, pointer: &str) -> Result<u64, MycConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| error(MycConfigV1ErrorKind::InvalidDocument))
}

fn document_error<T>() -> Result<T, MycConfigV1Error> {
    Err(error(MycConfigV1ErrorKind::InvalidDocument))
}

fn relationship_error<T>() -> Result<T, MycConfigV1Error> {
    Err(error(MycConfigV1ErrorKind::InvalidRelationship))
}

const fn error(kind: MycConfigV1ErrorKind) -> MycConfigV1Error {
    MycConfigV1Error::new(kind)
}

#[derive(Serialize)]
struct EffectiveProjection {
    schema: &'static str,
    schema_version: u32,
    fields: Vec<EffectiveField>,
}

#[derive(Serialize)]
struct EffectiveField {
    path: String,
    source: MycConfigValueSource,
    value: Value,
}

fn build_effective(
    normalized: &Value,
    original: &toml::Table,
) -> Result<MycEffectiveConfigV1, MycConfigV1Error> {
    let mut flattened = BTreeMap::new();
    flatten_value("", normalized, &mut flattened);
    let original = toml::Value::Table(original.clone());
    let fields = flattened
        .into_iter()
        .map(|(path, value)| EffectiveField {
            source: default_entry(&path).map_or(MycConfigValueSource::Document, |entry| {
                if toml_path(&original, &path).is_some() {
                    MycConfigValueSource::Document
                } else {
                    entry.source
                }
            }),
            value: redacted_value(&path, value),
            path,
        })
        .collect::<Vec<_>>();
    let field_count = fields.len();
    let canonical_json = serde_json::to_string(&EffectiveProjection {
        schema: "radroots.myc.effective-config",
        schema_version: 1,
        fields,
    })
    .map_err(|_| error(MycConfigV1ErrorKind::Encoding))?
    .into_boxed_str();
    Ok(MycEffectiveConfigV1 {
        canonical_json,
        field_count,
    })
}

fn flatten_value(path: &str, value: &Value, fields: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                flatten_value(&format!("{path}/{key}"), child, fields);
            }
        }
        Value::Array(array) if array.iter().all(Value::is_object) => {
            for (index, child) in array.iter().enumerate() {
                flatten_value(&format!("{path}/{index}"), child, fields);
            }
        }
        _ => {
            fields.insert(path.to_owned(), value.clone());
        }
    }
}

fn redacted_value(path: &str, value: Value) -> Value {
    let scalar_redaction = if path.ends_with("/envelope_path") || path.ends_with("/socket_path") {
        Some("[redacted-path]")
    } else if path.ends_with("/credential_reference") {
        Some("[redacted-credential-reference]")
    } else if path.ends_with("/expected_public_key") {
        Some("[redacted-public-key]")
    } else if path == "/operations/listen" {
        Some("[redacted-address]")
    } else if path.starts_with("/relays/") && path.ends_with("/id") {
        Some("[redacted-relay-id]")
    } else if (path.starts_with("/relays/") && path.ends_with("/url"))
        || path == "/policy/challenges/url"
    {
        Some("[redacted-url]")
    } else if matches!(
        path,
        "/discovery/domain"
            | "/discovery/handler_identifier"
            | "/discovery/nostrconnect_url_template"
            | "/discovery/metadata/name"
            | "/discovery/metadata/display_name"
            | "/discovery/metadata/about"
            | "/discovery/metadata/website"
            | "/discovery/metadata/picture"
    ) {
        Some("[redacted]")
    } else {
        None
    };
    if let Some(redaction) = scalar_redaction {
        return Value::String(redaction.to_owned());
    }
    if matches!(
        path,
        "/policy/trusted_clients"
            | "/policy/denied_clients"
            | "/discovery/public_relay_ids"
            | "/discovery/publish_relay_ids"
    ) {
        return json!({
            "count": value.as_array().map_or(0, Vec::len),
            "values": "[redacted]"
        });
    }
    value
}

fn default_entry(path: &str) -> Option<&'static DefaultEntry> {
    DEFAULTS.iter().find(|entry| entry.path == path)
}

fn toml_path<'a>(root: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    path.split('/')
        .filter(|part| !part.is_empty())
        .try_fold(root, |value, part| {
            if let Ok(index) = part.parse::<usize>() {
                value.as_array()?.get(index)
            } else {
                value.as_table()?.get(part)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn parse(source: &str) -> Result<MycConfigDocumentV1, MycConfigV1Error> {
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::Production)
    }

    fn replace(source: &str, old: &str, new: &str) -> String {
        assert!(source.contains(old), "missing fixture fragment: {old}");
        source.replacen(old, new, 1)
    }

    #[test]
    fn canonical_example_is_deterministic_and_redacted() {
        let first = parse(EXAMPLE).expect("canonical example");
        let second = parse(EXAMPLE).expect("canonical example again");
        assert_eq!(first.schema(), MYC_CONFIG_SCHEMA);
        assert_eq!(first.schema_version(), MYC_CONFIG_SCHEMA_VERSION);
        assert_eq!(first.profile(), MycConfigProfile::Production);
        assert_eq!(first.relay_count(), 2);
        assert_eq!(first.effective(), second.effective());
        assert!(first.effective().field_count() > 80);
        let output = first.effective().canonical_json();
        assert!(output.starts_with(
            "{\"schema\":\"radroots.myc.effective-config\",\"schema_version\":1,\"fields\":["
        ));
        for forbidden in [
            "/var/lib/radroots",
            "/run/radroots",
            "4444444444444444",
            "7777777777777777",
            "relay-primary.example.test",
            "myc.example.test",
            "transport_wrapping_key",
            "Radroots Myc",
        ] {
            assert!(!output.contains(forbidden), "leaked {forbidden}");
            assert!(!format!("{first:?}").contains(forbidden));
        }
    }

    #[test]
    fn exact_document_bound_precedes_parsing() {
        let mut exact = EXAMPLE.as_bytes().to_vec();
        exact.extend_from_slice(b"\n#");
        exact.resize(MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, b'a');
        assert!(parse_myc_config_v1(&exact, MycConfigProfile::Production).is_ok());
        exact.push(b'a');
        assert_eq!(
            parse_myc_config_v1(&exact, MycConfigProfile::Production)
                .unwrap_err()
                .kind(),
            MycConfigV1ErrorKind::TooLarge
        );
    }

    #[test]
    fn invalid_utf8_duplicate_null_unknown_and_malformed_wire_fail() {
        assert_eq!(
            parse_myc_config_v1(&[0xff], MycConfigProfile::Production)
                .unwrap_err()
                .kind(),
            MycConfigV1ErrorKind::InvalidUtf8
        );
        for source in [
            format!("schema = \"radroots.myc.config\"\n{EXAMPLE}"),
            replace(
                EXAMPLE,
                "shutdown_grace_ms = 30000",
                "shutdown_grace_ms = null",
            ),
            replace(
                EXAMPLE,
                "shutdown_grace_ms = 30000",
                "shutdown_grace_ms = [null]",
            ),
        ] {
            assert_eq!(
                parse(&source).unwrap_err().kind(),
                MycConfigV1ErrorKind::MalformedToml
            );
        }
        let unknown = replace(
            EXAMPLE,
            "shutdown_grace_ms = 30000",
            "shutdown_grace_ms = 30000\nsecret = \"do-not-render\"",
        );
        assert_eq!(
            parse(&unknown).unwrap_err().kind(),
            MycConfigV1ErrorKind::InvalidDocument
        );
        let nested_duplicate = replace(
            EXAMPLE,
            "busy_timeout_ms = 5000",
            "busy_timeout_ms = 5000\nbusy_timeout_ms = 5000",
        );
        assert_eq!(
            parse(&nested_duplicate).unwrap_err().kind(),
            MycConfigV1ErrorKind::MalformedToml
        );
        let mut table = EXAMPLE.parse::<toml::Table>().expect("example table");
        table.remove("resource_limits");
        assert_eq!(
            parse(&toml::to_string(&table).expect("missing-table TOML"))
                .unwrap_err()
                .kind(),
            MycConfigV1ErrorKind::InvalidDocument
        );
    }

    #[test]
    fn header_failures_are_classified_before_document_admission() {
        for (source, expected) in [
            (
                EXAMPLE.replace("schema = \"radroots.myc.config\"\n", ""),
                MycConfigV1ErrorKind::MissingSchema,
            ),
            (
                replace(EXAMPLE, "schema = \"radroots.myc.config\"", "schema = 1"),
                MycConfigV1ErrorKind::InvalidSchema,
            ),
            (
                replace(EXAMPLE, "radroots.myc.config", "radroots.rhi.config"),
                MycConfigV1ErrorKind::SchemaMismatch,
            ),
            (
                EXAMPLE.replace("schema_version = 1\n", ""),
                MycConfigV1ErrorKind::MissingSchemaVersion,
            ),
            (
                replace(EXAMPLE, "schema_version = 1", "schema_version = \"1\""),
                MycConfigV1ErrorKind::InvalidSchemaVersion,
            ),
            (
                replace(EXAMPLE, "schema_version = 1", "schema_version = 2"),
                MycConfigV1ErrorKind::UnsupportedSchemaVersion,
            ),
        ] {
            assert_eq!(parse(&source).unwrap_err().kind(), expected);
        }
    }

    #[test]
    fn production_and_repo_local_relay_postures_are_distinct() {
        let local = replace(
            EXAMPLE,
            "wss://relay-primary.example.test/",
            "ws://127.0.0.1:7777/",
        );
        assert_eq!(
            parse(&local).unwrap_err().kind(),
            MycConfigV1ErrorKind::InvalidRelationship
        );
        assert!(parse_myc_config_v1(local.as_bytes(), MycConfigProfile::RepoLocal).is_ok());
        let remote = replace(&local, "ws://127.0.0.1:7777/", "ws://relay.example.test/");
        assert_eq!(
            parse_myc_config_v1(remote.as_bytes(), MycConfigProfile::RepoLocal)
                .unwrap_err()
                .kind(),
            MycConfigV1ErrorKind::InvalidDocument
        );
    }

    #[test]
    fn semantic_relationship_failures_are_rejected() {
        let cases = [
            replace(EXAMPLE, "id = \"secondary\"", "id = \"primary\""),
            replace(
                EXAMPLE,
                "url = \"wss://relay-secondary.example.test/\"",
                "url = \"wss://relay-primary.example.test/\"",
            ),
            replace(
                EXAMPLE,
                "trusted_clients = [\"7777777777777777777777777777777777777777777777777777777777777777\"]",
                "trusted_clients = [\"8888888888888888888888888888888888888888888888888888888888888888\"]",
            ),
            replace(
                EXAMPLE,
                "expected_public_key = \"3333333333333333333333333333333333333333333333333333333333333333\"",
                "expected_public_key = \"2222222222222222222222222222222222222222222222222222222222222222\"",
            ),
            replace(
                EXAMPLE,
                "allowed_sign_event_kinds = [1]",
                "allowed_sign_event_kinds = [2]",
            ),
            replace(
                EXAMPLE,
                "authorized_lifetime_ms = 3600000",
                "authorized_lifetime_ms = 1000",
            ),
            replace(EXAMPLE, "retention_ms = 3600000", "retention_ms = 1"),
            replace(
                EXAMPLE,
                "initial_backoff_ms = 250",
                "initial_backoff_ms = 30001",
            ),
            replace(
                EXAMPLE,
                "public_relay_ids = [\"primary\", \"secondary\"]",
                "public_relay_ids = [\"missing\"]",
            ),
            replace(
                EXAMPLE,
                "[discovery]\nenabled = true",
                "[discovery]\nenabled = false",
            ),
        ];
        for source in cases {
            assert!(matches!(
                parse(&source).unwrap_err().kind(),
                MycConfigV1ErrorKind::InvalidDocument | MycConfigV1ErrorKind::InvalidRelationship
            ));
        }
    }

    #[test]
    fn defaults_have_exact_sources_and_explicit_values_override_them() {
        assert_eq!(DEFAULTS.len(), 39);
        let mut table = EXAMPLE.parse::<toml::Table>().expect("example TOML");
        for entry in DEFAULTS {
            remove_toml_path(&mut table, entry.path);
        }
        let minimal = toml::to_string(&table).expect("minimal TOML");
        let parsed = parse(&minimal).expect("defaults admitted");
        let output = parsed.effective().canonical_json();
        for source in [
            "engineering_safety",
            "accepted_service_authority",
            "radroots_service_sqlite",
            "radroots_service_host",
            "radroots_event",
            "radroots_nostr_connect",
        ] {
            assert!(output.contains(&format!("\"source\":\"{source}\"")));
        }
        let explicit = parse(EXAMPLE).expect("explicit example");
        assert!(
            explicit
                .effective()
                .canonical_json()
                .matches("\"source\":\"document\"")
                .count()
                > output.matches("\"source\":\"document\"").count()
        );
    }

    #[test]
    fn errors_and_debug_are_source_free() {
        let secret = "credential-secret-value";
        let source = replace(
            EXAMPLE,
            "shutdown_grace_ms = 30000",
            &format!("unknown = \"{secret}\""),
        );
        let failure = parse(&source).unwrap_err();
        let rendered = format!("{failure} {failure:?}");
        assert!(!rendered.contains(secret));
        assert!(Error::source(&failure).is_none());
    }

    #[test]
    fn annotated_utf8_limits_are_measured_in_bytes() {
        let exact_name = "é".repeat(64);
        let exact = replace(
            EXAMPLE,
            "name = \"myc\"",
            &format!("name = \"{exact_name}\""),
        );
        assert!(parse(&exact).is_ok());
        let over_name = "é".repeat(65);
        let over = replace(
            EXAMPLE,
            "name = \"myc\"",
            &format!("name = \"{over_name}\""),
        );
        assert_eq!(
            parse(&over).unwrap_err().kind(),
            MycConfigV1ErrorKind::InvalidDocument
        );
    }

    fn remove_toml_path(table: &mut toml::Table, pointer: &str) {
        let mut parts = pointer
            .split('/')
            .filter(|part| !part.is_empty())
            .peekable();
        let mut current = table;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                current.remove(part);
                return;
            }
            let Some(next) = current.get_mut(part).and_then(toml::Value::as_table_mut) else {
                return;
            };
            current = next;
        }
    }
}
