use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::DEFAULT_IDENTITY_PATH;
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
}

impl Default for MycConfig {
    fn default() -> Self {
        Self {
            service: MycServiceConfig::default(),
            logging: MycLoggingConfig::default(),
            paths: MycPathsConfig::default(),
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
}
