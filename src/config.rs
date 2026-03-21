use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::DEFAULT_IDENTITY_PATH;
use radroots_nostr::prelude::RadrootsNostrRelayUrl;
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
pub struct MycTransportConfig {
    pub enabled: bool,
    pub connect_timeout_secs: u64,
    pub relays: Vec<String>,
}

impl Default for MycConfig {
    fn default() -> Self {
        Self {
            service: MycServiceConfig::default(),
            logging: MycLoggingConfig::default(),
            paths: MycPathsConfig::default(),
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
}
