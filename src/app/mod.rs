pub mod backend;
pub mod runtime;

use crate::config::MycConfig;
use crate::error::MycError;

pub use backend::MycSignerBackend;
pub use runtime::{MycRuntime, MycRuntimePaths, MycSignerContext, MycStartupSnapshot};

#[derive(Clone)]
pub struct MycApp {
    runtime: MycRuntime,
}

impl MycApp {
    pub fn bootstrap(config: MycConfig) -> Result<Self, MycError> {
        Ok(Self {
            runtime: MycRuntime::bootstrap(config)?,
        })
    }

    pub fn runtime(&self) -> &MycRuntime {
        &self.runtime
    }

    pub fn snapshot(&self) -> MycStartupSnapshot {
        self.runtime.snapshot()
    }

    pub async fn run(self) -> Result<(), MycError> {
        self.runtime.run().await
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<(), MycError>
    where
        F: std::future::Future<Output = ()>,
    {
        self.runtime.run_until(shutdown).await
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use radroots_identity::RadrootsIdentity;

    use crate::config::{MycConfig, MycSignerStateBackend};

    use super::MycApp;

    fn write_test_identity(path: &std::path::Path, secret_key: &str) {
        let identity =
            RadrootsIdentity::from_secret_key_str(secret_key).expect("identity from secret");
        crate::identity_files::store_encrypted_identity(path, &identity).expect("write identity");
    }

    #[test]
    fn app_bootstrap_preserves_runtime_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(temp.path()).join("state");
        config.paths.signer_identity_path = temp.path().join("identity.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let app = MycApp::bootstrap(config).expect("bootstrap");
        let snapshot = app.snapshot();

        assert!(snapshot.state_dir.ends_with("state"));
        assert!(snapshot.audit_dir.ends_with("audit"));
        assert!(
            snapshot
                .signer_identity_path
                .as_ref()
                .expect("encrypted signer path")
                .ends_with("identity.json")
        );
        assert!(
            snapshot
                .user_identity_path
                .as_ref()
                .expect("encrypted user path")
                .ends_with("user.json")
        );
        assert_eq!(
            snapshot.signer_identity_source.backend.as_str(),
            "encrypted_file"
        );
        assert_eq!(
            snapshot.user_identity_source.backend.as_str(),
            "encrypted_file"
        );
        assert_eq!(snapshot.signer_state_backend.as_str(), "json_file");
        assert!(snapshot.signer_state_path.ends_with("signer-state.json"));
        assert_eq!(snapshot.runtime_audit_backend.as_str(), "jsonl_file");
        assert!(snapshot.runtime_audit_path.ends_with("operations.jsonl"));
        assert!(!snapshot.signer_identity_id.is_empty());
        assert!(!snapshot.signer_public_key_hex.is_empty());
        assert!(!snapshot.user_identity_id.is_empty());
        assert!(!snapshot.user_public_key_hex.is_empty());
        assert!(!snapshot.transport.enabled);
    }

    #[test]
    fn app_bootstrap_uses_backend_aware_signer_state_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(temp.path()).join("state");
        config.paths.signer_identity_path = temp.path().join("identity.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
        config.persistence.runtime_audit_backend = crate::config::MycRuntimeAuditBackend::Sqlite;
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let app = MycApp::bootstrap(config).expect("bootstrap");
        let snapshot = app.snapshot();

        assert_eq!(snapshot.signer_state_backend.as_str(), "sqlite");
        assert!(snapshot.signer_state_path.ends_with("signer-state.sqlite"));
        assert_eq!(snapshot.runtime_audit_backend.as_str(), "sqlite");
        assert!(snapshot.runtime_audit_path.ends_with("operations.sqlite"));
    }
}
