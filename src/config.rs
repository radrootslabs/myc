use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::DEFAULT_IDENTITY_PATH;
use radroots_nostr::prelude::RadrootsNostrRelayUrl;
use radroots_nostr_signer::prelude::RadrootsNostrSignerApprovalRequirement;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::error::MycError;

pub const DEFAULT_CONFIG_PATH: &str = "config.toml";

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
    pub fn load_from_default_path_if_exists() -> Result<Self, MycError> {
        Self::load_from_path_if_exists(DEFAULT_CONFIG_PATH)
    }

    pub fn load_from_path_if_exists(path: impl AsRef<Path>) -> Result<Self, MycError> {
        let path = path.as_ref();
        if !path.exists() {
            let config = Self::default();
            config.validate()?;
            return Ok(config);
        }

        Self::load_from_path(path)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, MycError> {
        let path = path.as_ref();
        let value = fs::read_to_string(path).map_err(|source| MycError::ConfigIo {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str_with_source(&value, path)
    }

    pub fn from_toml_str(value: &str) -> Result<Self, MycError> {
        Self::from_toml_str_with_source(value, Path::new("<inline>"))
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

    fn from_toml_str_with_source(value: &str, path: &Path) -> Result<Self, MycError> {
        let config: Self = toml::from_str(value).map_err(|source| MycError::ConfigParse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
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
    if !trimmed.starts_with("https://") {
        return Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must start with `https://`".to_owned(),
        ));
    }
    let candidate = trimmed.replace("<nostrconnect>", "nostrconnect%3A%2F%2Fclient");
    nostr::Url::parse(&candidate).map_err(|source| {
        MycError::InvalidConfig(format!(
            "discovery.nostrconnect_url_template is invalid: {source}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
    fn parse_config_from_toml_overrides_defaults() {
        let config = MycConfig::from_toml_str(
            r#"
                [service]
                instance_name = "myc-dev"

                [logging]
                filter = "debug,myc=trace"

                [paths]
                state_dir = "/tmp/myc"
                signer_identity_path = "/tmp/myc-identity.json"
                user_identity_path = "/tmp/myc-user.json"

                [audit]
                default_read_limit = 50
                max_active_file_bytes = 4096
                max_archived_files = 3

                [discovery]
                enabled = true
                domain = "myc.example.com"
                handler_identifier = "myc-main"
                app_identity_path = "/tmp/myc-app.json"
                public_relays = ["wss://relay.discovery.example.com"]
                publish_relays = ["wss://relay.publish.example.com"]
                nostrconnect_url_template = "https://myc.example.com/connect/<nostrconnect>"
                nip05_output_path = "/tmp/nostr.json"

                [discovery.metadata]
                name = "myc"
                display_name = "Mycorrhiza"
                about = "NIP-46 signer"
                website = "https://myc.example.com"
                picture = "https://myc.example.com/logo.png"

                [policy]
                connection_approval = "not_required"

                [transport]
                enabled = true
                connect_timeout_secs = 15
                relays = ["wss://relay.example.com", "wss://relay2.example.com"]
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
    fn load_from_missing_path_returns_default_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = MycConfig::load_from_path_if_exists(temp.path().join("missing.toml"))
            .expect("missing path fallback");

        assert_eq!(config, MycConfig::default());
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let err = MycConfig::from_toml_str(
            r#"
                [service]
                instance_name = "myc-dev"
                extra = "nope"
            "#,
        )
        .expect_err("unknown field");

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
}
