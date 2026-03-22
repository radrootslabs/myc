use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::DEFAULT_IDENTITY_PATH;
use radroots_nostr::prelude::RadrootsNostrRelayUrl;
use radroots_nostr_signer::prelude::RadrootsNostrSignerApprovalRequirement;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::error::MycError;

pub const DEFAULT_ENV_PATH: &str = ".env";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycConfig {
    pub service: MycServiceConfig,
    pub logging: MycLoggingConfig,
    pub paths: MycPathsConfig,
    pub audit: MycAuditConfig,
    pub discovery: MycDiscoveryConfig,
    pub policy: MycPolicyConfig,
    pub transport: MycTransportConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycServiceConfig {
    pub instance_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycLoggingConfig {
    pub filter: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycPathsConfig {
    pub state_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycAuditConfig {
    pub default_read_limit: usize,
    pub max_active_file_bytes: u64,
    pub max_archived_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycDiscoveryConfig {
    pub enabled: bool,
    pub domain: Option<String>,
    pub handler_identifier: String,
    pub app_identity_path: Option<PathBuf>,
    pub public_relays: Vec<String>,
    pub publish_relays: Vec<String>,
    pub nostrconnect_url_template: Option<String>,
    pub nip05_output_path: Option<PathBuf>,
    pub metadata: MycDiscoveryMetadataConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycDiscoveryMetadataConfig {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub website: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycTransportConfig {
    pub enabled: bool,
    pub connect_timeout_secs: u64,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycConnectionApproval {
    NotRequired,
    ExplicitUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycPolicyConfig {
    pub connection_approval: MycConnectionApproval,
}

impl Default for MycConfig {
    fn default() -> Self {
        Self {
            service: MycServiceConfig::default(),
            logging: MycLoggingConfig::default(),
            paths: MycPathsConfig::default(),
            audit: MycAuditConfig::default(),
            discovery: MycDiscoveryConfig::default(),
            policy: MycPolicyConfig::default(),
            transport: MycTransportConfig::default(),
        }
    }
}

impl Default for MycServiceConfig {
    fn default() -> Self {
        Self {
            instance_name: "myc".to_owned(),
        }
    }
}

impl Default for MycLoggingConfig {
    fn default() -> Self {
        Self {
            filter: "info,myc=info".to_owned(),
        }
    }
}

impl Default for MycPathsConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("var"),
            signer_identity_path: PathBuf::from(DEFAULT_IDENTITY_PATH),
            user_identity_path: PathBuf::from(DEFAULT_IDENTITY_PATH),
        }
    }
}

impl Default for MycTransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            connect_timeout_secs: 10,
            relays: Vec::new(),
        }
    }
}

impl Default for MycAuditConfig {
    fn default() -> Self {
        Self {
            default_read_limit: 200,
            max_active_file_bytes: 262_144,
            max_archived_files: 8,
        }
    }
}

impl Default for MycDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: None,
            handler_identifier: "myc".to_owned(),
            app_identity_path: None,
            public_relays: Vec::new(),
            publish_relays: Vec::new(),
            nostrconnect_url_template: None,
            nip05_output_path: None,
            metadata: MycDiscoveryMetadataConfig::default(),
        }
    }
}

impl Default for MycDiscoveryMetadataConfig {
    fn default() -> Self {
        Self {
            name: None,
            display_name: None,
            about: None,
            website: None,
            picture: None,
        }
    }
}

impl Default for MycPolicyConfig {
    fn default() -> Self {
        Self {
            connection_approval: MycConnectionApproval::ExplicitUser,
        }
    }
}

impl MycConnectionApproval {
    pub fn into_signer_approval_requirement(self) -> RadrootsNostrSignerApprovalRequirement {
        match self {
            Self::NotRequired => RadrootsNostrSignerApprovalRequirement::NotRequired,
            Self::ExplicitUser => RadrootsNostrSignerApprovalRequirement::ExplicitUser,
        }
    }
}

impl MycConfig {
    pub fn load_from_default_env_path() -> Result<Self, MycError> {
        Self::load_from_env_path(DEFAULT_ENV_PATH)
    }

    pub fn load_from_env_path(path: impl AsRef<Path>) -> Result<Self, MycError> {
        let path = path.as_ref();
        let value = fs::read_to_string(path).map_err(|source| MycError::ConfigIo {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_env_str_with_source(&value, path)
    }

    pub fn from_env_str(value: &str) -> Result<Self, MycError> {
        Self::from_env_str_with_source(value, Path::new("<inline>"))
    }

    pub fn validate(&self) -> Result<(), MycError> {
        if self.service.instance_name.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "service.instance_name must not be empty".to_owned(),
            ));
        }

        if self.logging.filter.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "logging.filter must not be empty".to_owned(),
            ));
        }

        EnvFilter::try_new(self.logging.filter.clone()).map_err(|source| {
            MycError::InvalidLogFilter {
                filter: self.logging.filter.clone(),
                source,
            }
        })?;

        if self.paths.state_dir.as_os_str().is_empty() {
            return Err(MycError::InvalidConfig(
                "paths.state_dir must not be empty".to_owned(),
            ));
        }

        if self.paths.signer_identity_path.as_os_str().is_empty() {
            return Err(MycError::InvalidConfig(
                "paths.signer_identity_path must not be empty".to_owned(),
            ));
        }

        if self.paths.user_identity_path.as_os_str().is_empty() {
            return Err(MycError::InvalidConfig(
                "paths.user_identity_path must not be empty".to_owned(),
            ));
        }

        if self.audit.default_read_limit == 0 {
            return Err(MycError::InvalidConfig(
                "audit.default_read_limit must be greater than zero".to_owned(),
            ));
        }

        if self.audit.max_active_file_bytes == 0 {
            return Err(MycError::InvalidConfig(
                "audit.max_active_file_bytes must be greater than zero".to_owned(),
            ));
        }

        self.discovery.validate(&self.transport)?;

        if self.transport.connect_timeout_secs == 0 {
            return Err(MycError::InvalidConfig(
                "transport.connect_timeout_secs must be greater than zero".to_owned(),
            ));
        }

        let parsed_relays = self.transport.parse_relays()?;
        if self.transport.enabled && parsed_relays.is_empty() {
            return Err(MycError::InvalidConfig(
                "transport.relays must not be empty when transport.enabled is true".to_owned(),
            ));
        }

        Ok(())
    }

    fn from_env_str_with_source(value: &str, path: &Path) -> Result<Self, MycError> {
        let entries = parse_env_entries(value, path)?;
        let mut config = Self::default();
        for (key, value, line_number) in entries {
            apply_env_entry(&mut config, key.as_str(), value.as_str(), path, line_number)?;
        }
        config.validate()?;
        Ok(config)
    }
}

fn parse_env_entries(value: &str, path: &Path) -> Result<Vec<(String, String, usize)>, MycError> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();

    for (index, raw_line) in value.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key_raw, value_raw)) = raw_line.split_once('=') else {
            return Err(config_parse_error(
                path,
                line_number,
                "expected KEY=VALUE assignment",
            ));
        };
        let key = key_raw.trim();
        if key.is_empty() {
            return Err(config_parse_error(
                path,
                line_number,
                "environment variable name must not be empty",
            ));
        }
        if !key.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        }) {
            return Err(config_parse_error(
                path,
                line_number,
                format!("invalid environment variable name `{key}`"),
            ));
        }
        if !seen.insert(key.to_owned()) {
            return Err(config_parse_error(
                path,
                line_number,
                format!("duplicate environment variable `{key}`"),
            ));
        }
        entries.push((
            key.to_owned(),
            parse_env_value(value_raw.trim(), path, line_number)?,
            line_number,
        ));
    }

    Ok(entries)
}

fn parse_env_value(value: &str, path: &Path, line_number: usize) -> Result<String, MycError> {
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = value.chars().next().expect("quoted env value prefix");
        if !value.ends_with(quote) || value.len() < 2 {
            return Err(config_parse_error(
                path,
                line_number,
                "unterminated quoted environment value",
            ));
        }
        return Ok(value[1..value.len() - 1].to_owned());
    }
    Ok(value.to_owned())
}

fn apply_env_entry(
    config: &mut MycConfig,
    key: &str,
    value: &str,
    path: &Path,
    line_number: usize,
) -> Result<(), MycError> {
    match key {
        "MYC_SERVICE_INSTANCE_NAME" => config.service.instance_name = value.to_owned(),
        "MYC_LOGGING_FILTER" => config.logging.filter = value.to_owned(),
        "MYC_PATHS_STATE_DIR" => config.paths.state_dir = PathBuf::from(value),
        "MYC_PATHS_SIGNER_IDENTITY_PATH" => {
            config.paths.signer_identity_path = PathBuf::from(value);
        }
        "MYC_PATHS_USER_IDENTITY_PATH" => {
            config.paths.user_identity_path = PathBuf::from(value);
        }
        "MYC_AUDIT_DEFAULT_READ_LIMIT" => {
            config.audit.default_read_limit = parse_usize_env(key, value, path, line_number)?;
        }
        "MYC_AUDIT_MAX_ACTIVE_FILE_BYTES" => {
            config.audit.max_active_file_bytes = parse_u64_env(key, value, path, line_number)?;
        }
        "MYC_AUDIT_MAX_ARCHIVED_FILES" => {
            config.audit.max_archived_files = parse_usize_env(key, value, path, line_number)?;
        }
        "MYC_DISCOVERY_ENABLED" => {
            config.discovery.enabled = parse_bool_env(key, value, path, line_number)?;
        }
        "MYC_DISCOVERY_DOMAIN" => {
            config.discovery.domain = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_HANDLER_IDENTIFIER" => {
            config.discovery.handler_identifier = value.to_owned();
        }
        "MYC_DISCOVERY_APP_IDENTITY_PATH" => {
            config.discovery.app_identity_path = parse_optional_path_env(value);
        }
        "MYC_DISCOVERY_PUBLIC_RELAYS" => {
            config.discovery.public_relays = parse_string_list_env(value);
        }
        "MYC_DISCOVERY_PUBLISH_RELAYS" => {
            config.discovery.publish_relays = parse_string_list_env(value);
        }
        "MYC_DISCOVERY_NOSTRCONNECT_URL_TEMPLATE" => {
            config.discovery.nostrconnect_url_template = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_NIP05_OUTPUT_PATH" => {
            config.discovery.nip05_output_path = parse_optional_path_env(value);
        }
        "MYC_DISCOVERY_METADATA_NAME" => {
            config.discovery.metadata.name = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_METADATA_DISPLAY_NAME" => {
            config.discovery.metadata.display_name = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_METADATA_ABOUT" => {
            config.discovery.metadata.about = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_METADATA_WEBSITE" => {
            config.discovery.metadata.website = parse_optional_string_env(value);
        }
        "MYC_DISCOVERY_METADATA_PICTURE" => {
            config.discovery.metadata.picture = parse_optional_string_env(value);
        }
        "MYC_POLICY_CONNECTION_APPROVAL" => {
            config.policy.connection_approval =
                parse_connection_approval_env(key, value, path, line_number)?;
        }
        "MYC_TRANSPORT_ENABLED" => {
            config.transport.enabled = parse_bool_env(key, value, path, line_number)?;
        }
        "MYC_TRANSPORT_CONNECT_TIMEOUT_SECS" => {
            config.transport.connect_timeout_secs = parse_u64_env(key, value, path, line_number)?;
        }
        "MYC_TRANSPORT_RELAYS" => {
            config.transport.relays = parse_string_list_env(value);
        }
        _ => {
            return Err(config_parse_error(
                path,
                line_number,
                format!("unknown environment variable `{key}`"),
            ));
        }
    }

    Ok(())
}

fn parse_bool_env(
    key: &str,
    value: &str,
    path: &Path,
    line_number: usize,
) -> Result<bool, MycError> {
    value.parse::<bool>().map_err(|_| {
        config_parse_error(
            path,
            line_number,
            format!("{key} must be `true` or `false`"),
        )
    })
}

fn parse_usize_env(
    key: &str,
    value: &str,
    path: &Path,
    line_number: usize,
) -> Result<usize, MycError> {
    value.parse::<usize>().map_err(|_| {
        config_parse_error(
            path,
            line_number,
            format!("{key} must be an unsigned integer"),
        )
    })
}

fn parse_u64_env(key: &str, value: &str, path: &Path, line_number: usize) -> Result<u64, MycError> {
    value.parse::<u64>().map_err(|_| {
        config_parse_error(
            path,
            line_number,
            format!("{key} must be an unsigned integer"),
        )
    })
}

fn parse_connection_approval_env(
    key: &str,
    value: &str,
    path: &Path,
    line_number: usize,
) -> Result<MycConnectionApproval, MycError> {
    match value {
        "not_required" => Ok(MycConnectionApproval::NotRequired),
        "explicit_user" => Ok(MycConnectionApproval::ExplicitUser),
        _ => Err(config_parse_error(
            path,
            line_number,
            format!("{key} must be `not_required` or `explicit_user`"),
        )),
    }
}

fn parse_optional_string_env(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn parse_optional_path_env(value: &str) -> Option<PathBuf> {
    parse_optional_string_env(value).map(PathBuf::from)
}

fn parse_string_list_env(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn config_parse_error(path: &Path, line_number: usize, message: impl Into<String>) -> MycError {
    MycError::ConfigParse {
        path: path.to_path_buf(),
        line_number,
        message: message.into(),
    }
}

impl MycTransportConfig {
    pub fn parse_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        self.relays
            .iter()
            .map(|value| {
                RadrootsNostrRelayUrl::parse(value).map_err(|source| {
                    MycError::InvalidConfig(format!(
                        "transport.relays contains invalid relay url `{value}`: {source}"
                    ))
                })
            })
            .collect()
    }
}

impl MycDiscoveryConfig {
    pub fn parse_public_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        parse_discovery_relays(&self.public_relays, "discovery.public_relays")
    }

    pub fn parse_publish_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        parse_discovery_relays(&self.publish_relays, "discovery.publish_relays")
    }

    pub fn resolved_public_relays(
        &self,
        transport: &MycTransportConfig,
    ) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        let relays = if self.public_relays.is_empty() {
            transport.parse_relays()?
        } else {
            self.parse_public_relays()?
        };
        Ok(normalize_discovery_relays(relays))
    }

    pub fn resolved_publish_relays(
        &self,
        transport: &MycTransportConfig,
    ) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        let relays = if self.publish_relays.is_empty() {
            self.resolved_public_relays(transport)?
        } else {
            self.parse_publish_relays()?
        };
        Ok(normalize_discovery_relays(relays))
    }

    fn validate(&self, transport: &MycTransportConfig) -> Result<(), MycError> {
        if !self.enabled {
            return Ok(());
        }

        let domain = self.domain.as_deref().ok_or_else(|| {
            MycError::InvalidConfig(
                "discovery.domain must be set when discovery.enabled is true".to_owned(),
            )
        })?;
        validate_discovery_domain(domain)?;

        if self.handler_identifier.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "discovery.handler_identifier must not be empty when discovery.enabled is true"
                    .to_owned(),
            ));
        }

        if let Some(path) = self.app_identity_path.as_ref() {
            if path.as_os_str().is_empty() {
                return Err(MycError::InvalidConfig(
                    "discovery.app_identity_path must not be empty".to_owned(),
                ));
            }
        }

        if let Some(template) = self.nostrconnect_url_template.as_deref() {
            validate_nostrconnect_url_template(template)?;
        }

        if let Some(path) = self.nip05_output_path.as_ref() {
            if path.as_os_str().is_empty() {
                return Err(MycError::InvalidConfig(
                    "discovery.nip05_output_path must not be empty".to_owned(),
                ));
            }
        }

        if self.resolved_public_relays(transport)?.is_empty() {
            return Err(MycError::InvalidConfig(
                "discovery requires at least one public relay hint via discovery.public_relays or transport.relays".to_owned(),
            ));
        }

        let _ = self.resolved_publish_relays(transport)?;
        Ok(())
    }
}

fn parse_discovery_relays(
    values: &[String],
    field_name: &str,
) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
    values
        .iter()
        .map(|value| {
            RadrootsNostrRelayUrl::parse(value).map_err(|source| {
                MycError::InvalidConfig(format!(
                    "{field_name} contains invalid relay url `{value}`: {source}"
                ))
            })
        })
        .collect()
}

fn normalize_discovery_relays(
    mut relays: Vec<RadrootsNostrRelayUrl>,
) -> Vec<RadrootsNostrRelayUrl> {
    relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relays.dedup_by(|left, right| left.as_str() == right.as_str());
    relays
}

fn validate_discovery_domain(domain: &str) -> Result<(), MycError> {
    let trimmed = domain.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err(MycError::InvalidConfig(format!(
            "discovery.domain must be a bare host name without scheme or path: `{domain}`"
        )));
    }
    Ok(())
}

fn validate_nostrconnect_url_template(template: &str) -> Result<(), MycError> {
    let trimmed = template.trim();
    if trimmed.is_empty() {
        return Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must not be empty when set".to_owned(),
        ));
    }
    if !trimmed.contains("<nostrconnect>") {
        return Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must contain the `<nostrconnect>` placeholder"
                .to_owned(),
        ));
    }
    let candidate = trimmed.replace("<nostrconnect>", "nostrconnect%3A%2F%2Fclient");
    let url = nostr::Url::parse(&candidate).map_err(|source| {
        MycError::InvalidConfig(format!(
            "discovery.nostrconnect_url_template is invalid: {source}"
        ))
    })?;

    match url.scheme() {
        "https" => Ok(()),
        "http" if discovery_host_is_local(url.host_str()) => Ok(()),
        _ => Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must use `https://`, except loopback hosts may use `http://`".to_owned(),
        )),
    }
}

fn discovery_host_is_local(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn default_config_is_stable() {
        let config = MycConfig::default();
        assert_eq!(config.service.instance_name, "myc");
        assert_eq!(config.logging.filter, "info,myc=info");
        assert_eq!(config.paths.state_dir, PathBuf::from("var"));
        assert_eq!(
            config.paths.signer_identity_path,
            PathBuf::from(DEFAULT_IDENTITY_PATH)
        );
        assert_eq!(
            config.paths.user_identity_path,
            PathBuf::from(DEFAULT_IDENTITY_PATH)
        );
        assert_eq!(
            config.policy.connection_approval,
            MycConnectionApproval::ExplicitUser
        );
        assert_eq!(config.audit.default_read_limit, 200);
        assert_eq!(config.audit.max_active_file_bytes, 262_144);
        assert_eq!(config.audit.max_archived_files, 8);
        assert!(!config.discovery.enabled);
        assert_eq!(config.discovery.handler_identifier, "myc");
        assert!(config.discovery.domain.is_none());
        assert!(config.discovery.public_relays.is_empty());
        assert!(config.discovery.publish_relays.is_empty());
        assert!(config.discovery.nostrconnect_url_template.is_none());
        assert!(config.discovery.nip05_output_path.is_none());
        assert!(!config.transport.enabled);
        assert_eq!(config.transport.connect_timeout_secs, 10);
        assert!(config.transport.relays.is_empty());
    }

    #[test]
    fn parse_config_from_env_overrides_defaults() {
        let config = MycConfig::from_env_str(
            r#"
MYC_SERVICE_INSTANCE_NAME=myc-dev
MYC_LOGGING_FILTER=debug,myc=trace
MYC_PATHS_STATE_DIR=/tmp/myc
MYC_PATHS_SIGNER_IDENTITY_PATH=/tmp/myc-identity.json
MYC_PATHS_USER_IDENTITY_PATH=/tmp/myc-user.json
MYC_AUDIT_DEFAULT_READ_LIMIT=50
MYC_AUDIT_MAX_ACTIVE_FILE_BYTES=4096
MYC_AUDIT_MAX_ARCHIVED_FILES=3
MYC_DISCOVERY_ENABLED=true
MYC_DISCOVERY_DOMAIN=myc.example.com
MYC_DISCOVERY_HANDLER_IDENTIFIER=myc-main
MYC_DISCOVERY_APP_IDENTITY_PATH=/tmp/myc-app.json
MYC_DISCOVERY_PUBLIC_RELAYS=wss://relay.discovery.example.com
MYC_DISCOVERY_PUBLISH_RELAYS=wss://relay.publish.example.com
MYC_DISCOVERY_NOSTRCONNECT_URL_TEMPLATE=https://myc.example.com/connect/<nostrconnect>
MYC_DISCOVERY_NIP05_OUTPUT_PATH=/tmp/nostr.json
MYC_DISCOVERY_METADATA_NAME=myc
MYC_DISCOVERY_METADATA_DISPLAY_NAME=Mycorrhiza
MYC_DISCOVERY_METADATA_ABOUT=NIP-46 signer
MYC_DISCOVERY_METADATA_WEBSITE=https://myc.example.com
MYC_DISCOVERY_METADATA_PICTURE=https://myc.example.com/logo.png
MYC_POLICY_CONNECTION_APPROVAL=not_required
MYC_TRANSPORT_ENABLED=true
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=15
MYC_TRANSPORT_RELAYS=wss://relay.example.com,wss://relay2.example.com
            "#,
        )
        .expect("config");

        assert_eq!(config.service.instance_name, "myc-dev");
        assert_eq!(config.logging.filter, "debug,myc=trace");
        assert_eq!(config.paths.state_dir, PathBuf::from("/tmp/myc"));
        assert_eq!(
            config.paths.signer_identity_path,
            PathBuf::from("/tmp/myc-identity.json")
        );
        assert_eq!(
            config.paths.user_identity_path,
            PathBuf::from("/tmp/myc-user.json")
        );
        assert_eq!(config.audit.default_read_limit, 50);
        assert_eq!(config.audit.max_active_file_bytes, 4096);
        assert_eq!(config.audit.max_archived_files, 3);
        assert!(config.discovery.enabled);
        assert_eq!(config.discovery.domain.as_deref(), Some("myc.example.com"));
        assert_eq!(config.discovery.handler_identifier, "myc-main");
        assert_eq!(
            config.discovery.app_identity_path,
            Some(PathBuf::from("/tmp/myc-app.json"))
        );
        assert_eq!(
            config.discovery.public_relays,
            vec!["wss://relay.discovery.example.com".to_owned()]
        );
        assert_eq!(
            config.discovery.publish_relays,
            vec!["wss://relay.publish.example.com".to_owned()]
        );
        assert_eq!(
            config.discovery.nostrconnect_url_template.as_deref(),
            Some("https://myc.example.com/connect/<nostrconnect>")
        );
        assert_eq!(
            config.discovery.nip05_output_path,
            Some(PathBuf::from("/tmp/nostr.json"))
        );
        assert_eq!(config.discovery.metadata.name.as_deref(), Some("myc"));
        assert_eq!(
            config.discovery.metadata.display_name.as_deref(),
            Some("Mycorrhiza")
        );
        assert_eq!(
            config.policy.connection_approval,
            MycConnectionApproval::NotRequired
        );
        assert!(config.transport.enabled);
        assert_eq!(config.transport.connect_timeout_secs, 15);
        assert_eq!(
            config.transport.relays,
            vec![
                "wss://relay.example.com".to_owned(),
                "wss://relay2.example.com".to_owned()
            ]
        );
    }

    #[test]
    fn load_from_missing_env_path_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let err = MycConfig::load_from_env_path(temp.path().join("missing.env"))
            .expect_err("missing env");

        assert!(err.to_string().contains("config io error"));
    }

    #[test]
    fn parse_rejects_unknown_env_keys() {
        let err = MycConfig::from_env_str(
            r#"
MYC_SERVICE_INSTANCE_NAME=myc-dev
MYC_UNKNOWN=nope
            "#,
        )
        .expect_err("unknown key");

        assert!(err.to_string().contains("config parse error"));
    }

    #[test]
    fn validate_rejects_enabled_transport_without_relays() {
        let mut config = MycConfig::default();
        config.transport.enabled = true;

        let err = config.validate().expect_err("missing relays");
        assert!(err.to_string().contains("transport.relays"));
    }

    #[test]
    fn validate_rejects_zero_audit_read_limit() {
        let mut config = MycConfig::default();
        config.audit.default_read_limit = 0;

        let err = config.validate().expect_err("invalid audit read limit");
        assert!(err.to_string().contains("audit.default_read_limit"));
    }

    #[test]
    fn discovery_validation_requires_domain_and_relays_when_enabled() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.transport.enabled = true;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];

        let err = config.validate().expect_err("missing discovery domain");
        assert!(err.to_string().contains("discovery.domain"));

        config.discovery.domain = Some("myc.example.com".to_owned());
        config.transport.relays.clear();
        let err = config.validate().expect_err("missing relay hints");
        assert!(err.to_string().contains("at least one public relay hint"));
    }

    #[test]
    fn discovery_validation_allows_localhost_http_nostrconnect_template() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.discovery.domain = Some("localhost".to_owned());
        config.discovery.public_relays = vec!["ws://localhost:8080".to_owned()];
        config.discovery.nostrconnect_url_template =
            Some("http://localhost/connect?uri=<nostrconnect>".to_owned());

        config.validate().expect("localhost http template");
    }

    #[test]
    fn discovery_validation_rejects_invalid_nostrconnect_template() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.discovery.domain = Some("myc.example.com".to_owned());
        config.discovery.public_relays = vec!["wss://relay.example.com".to_owned()];
        config.discovery.nostrconnect_url_template = Some("http://bad.example.com".to_owned());

        let err = config.validate().expect_err("invalid discovery template");
        assert!(
            err.to_string()
                .contains("discovery.nostrconnect_url_template")
        );
    }

    #[test]
    fn example_env_parses_and_validates() {
        let example =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env.example"))
                .expect("read example config");

        let config = MycConfig::from_env_str(&example).expect("example config");

        assert_eq!(config.service.instance_name, "myc");
        assert!(config.discovery.enabled);
        assert_eq!(
            config.discovery.domain.as_deref(),
            Some("localhost")
        );
        assert_eq!(config.discovery.handler_identifier, "myc");
        assert_eq!(
            config.discovery.nip05_output_path,
            Some(PathBuf::from("var/public/.well-known/nostr.json"))
        );
    }
}
