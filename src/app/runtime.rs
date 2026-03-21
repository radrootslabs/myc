use std::fs;
use std::path::PathBuf;

use crate::config::MycConfig;
use crate::error::MycError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycRuntimePaths {
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycStartupSnapshot {
    pub instance_name: String,
    pub log_filter: String,
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_state_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct MycRuntime {
    config: MycConfig,
    paths: MycRuntimePaths,
}

impl MycRuntime {
    pub fn bootstrap(config: MycConfig) -> Result<Self, MycError> {
        config.validate()?;

        let runtime = Self {
            paths: MycRuntimePaths::from_config(&config),
            config,
        };
        runtime.prepare_filesystem()?;
        Ok(runtime)
    }

    pub fn paths(&self) -> &MycRuntimePaths {
        &self.paths
    }

    pub fn config(&self) -> &MycConfig {
        &self.config
    }

    pub fn snapshot(&self) -> MycStartupSnapshot {
        MycStartupSnapshot {
            instance_name: self.config.service.instance_name.clone(),
            log_filter: self.config.logging.filter.clone(),
            state_dir: self.paths.state_dir.clone(),
            audit_dir: self.paths.audit_dir.clone(),
            signer_state_path: self.paths.signer_state_path.clone(),
        }
    }

    pub fn run(self) -> Result<(), MycError> {
        let snapshot = self.snapshot();
        tracing::info!(
            instance_name = %snapshot.instance_name,
            state_dir = %snapshot.state_dir.display(),
            audit_dir = %snapshot.audit_dir.display(),
            signer_state_path = %snapshot.signer_state_path.display(),
            "myc runtime bootstrapped"
        );
        Ok(())
    }

    fn prepare_filesystem(&self) -> Result<(), MycError> {
        fs::create_dir_all(&self.paths.state_dir).map_err(|source| MycError::CreateDir {
            path: self.paths.state_dir.clone(),
            source,
        })?;
        fs::create_dir_all(&self.paths.audit_dir).map_err(|source| MycError::CreateDir {
            path: self.paths.audit_dir.clone(),
            source,
        })?;
        Ok(())
    }
}

impl MycRuntimePaths {
    fn from_config(config: &MycConfig) -> Self {
        let state_dir = config.paths.state_dir.clone();
        Self {
            signer_state_path: state_dir.join("signer-state.json"),
            audit_dir: state_dir.join("audit"),
            state_dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::MycConfig;

    use super::MycRuntime;

    #[test]
    fn bootstrap_creates_runtime_directories() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(temp.path()).join("state");

        let runtime = MycRuntime::bootstrap(config).expect("runtime");
        assert!(runtime.paths().state_dir.is_dir());
        assert!(runtime.paths().audit_dir.is_dir());
        assert!(
            runtime
                .paths()
                .signer_state_path
                .ends_with("signer-state.json")
        );
    }

    #[test]
    fn bootstrap_rejects_invalid_config() {
        let mut config = MycConfig::default();
        config.service.instance_name.clear();

        let err = MycRuntime::bootstrap(config).expect_err("invalid config");
        assert!(err.to_string().contains("service.instance_name"));
    }
}
