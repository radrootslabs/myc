use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use crate::config::MycConfig;
use crate::error::MycError;
use crate::transport::{MycNip46Service, MycNostrTransport, MycTransportSnapshot};
use radroots_identity::{RadrootsIdentity, RadrootsIdentityPublic};
use radroots_nostr_signer::prelude::{
    RadrootsNostrFileSignerStore, RadrootsNostrSignerApprovalRequirement,
    RadrootsNostrSignerManager,
};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycRuntimePaths {
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
    pub signer_state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycStartupSnapshot {
    pub instance_name: String,
    pub log_filter: String,
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
    pub signer_state_path: PathBuf,
    pub signer_identity_id: String,
    pub signer_public_key_hex: String,
    pub user_identity_id: String,
    pub user_public_key_hex: String,
    pub transport: MycTransportSnapshot,
}

#[derive(Clone)]
pub struct MycSignerContext {
    signer_identity: RadrootsIdentity,
    user_identity: RadrootsIdentity,
    signer_state_path: PathBuf,
    connection_approval_requirement: RadrootsNostrSignerApprovalRequirement,
}

#[derive(Clone)]
pub struct MycRuntime {
    config: MycConfig,
    paths: MycRuntimePaths,
    signer: MycSignerContext,
    transport: Option<MycNostrTransport>,
}

impl MycRuntime {
    pub fn bootstrap(config: MycConfig) -> Result<Self, MycError> {
        config.validate()?;

        let paths = MycRuntimePaths::from_config(&config);
        Self::prepare_filesystem_for(&paths)?;
        let signer = MycSignerContext::bootstrap(
            &paths,
            config
                .policy
                .connection_approval
                .into_signer_approval_requirement(),
        )?;
        let transport = MycNostrTransport::bootstrap(&config.transport, &signer.signer_identity)?;
        let runtime = Self {
            paths,
            config,
            signer,
            transport,
        };
        Ok(runtime)
    }

    pub fn paths(&self) -> &MycRuntimePaths {
        &self.paths
    }

    pub fn config(&self) -> &MycConfig {
        &self.config
    }

    pub fn signer_identity(&self) -> &RadrootsIdentity {
        self.signer.signer_identity()
    }

    pub fn signer_public_identity(&self) -> RadrootsIdentityPublic {
        self.signer.signer_public_identity()
    }

    pub fn user_identity(&self) -> &RadrootsIdentity {
        self.signer.user_identity()
    }

    pub fn user_public_identity(&self) -> RadrootsIdentityPublic {
        self.signer.user_public_identity()
    }

    pub fn signer_manager(&self) -> Result<RadrootsNostrSignerManager, MycError> {
        self.signer.load_signer_manager()
    }

    pub fn transport(&self) -> Option<&MycNostrTransport> {
        self.transport.as_ref()
    }

    pub(crate) fn signer_context(&self) -> MycSignerContext {
        self.signer.clone()
    }

    pub fn snapshot(&self) -> MycStartupSnapshot {
        let signer_public = self.signer.signer_identity.to_public();
        let user_public = self.signer.user_identity.to_public();
        MycStartupSnapshot {
            instance_name: self.config.service.instance_name.clone(),
            log_filter: self.config.logging.filter.clone(),
            state_dir: self.paths.state_dir.clone(),
            audit_dir: self.paths.audit_dir.clone(),
            signer_identity_path: self.paths.signer_identity_path.clone(),
            user_identity_path: self.paths.user_identity_path.clone(),
            signer_state_path: self.paths.signer_state_path.clone(),
            signer_identity_id: signer_public.id.into_string(),
            signer_public_key_hex: signer_public.public_key_hex,
            user_identity_id: user_public.id.into_string(),
            user_public_key_hex: user_public.public_key_hex,
            transport: self
                .transport
                .as_ref()
                .map(MycNostrTransport::snapshot)
                .unwrap_or_else(MycTransportSnapshot::disabled),
        }
    }

    pub async fn run(self) -> Result<(), MycError> {
        self.run_until(std::future::pending()).await
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<(), MycError>
    where
        F: Future<Output = ()>,
    {
        let snapshot = self.snapshot();
        tracing::info!(
            instance_name = %snapshot.instance_name,
            state_dir = %snapshot.state_dir.display(),
            audit_dir = %snapshot.audit_dir.display(),
            signer_identity_path = %snapshot.signer_identity_path.display(),
            user_identity_path = %snapshot.user_identity_path.display(),
            signer_state_path = %snapshot.signer_state_path.display(),
            signer_identity_id = %snapshot.signer_identity_id,
            signer_public_key_hex = %snapshot.signer_public_key_hex,
            user_identity_id = %snapshot.user_identity_id,
            user_public_key_hex = %snapshot.user_public_key_hex,
            transport_enabled = snapshot.transport.enabled,
            transport_relay_count = snapshot.transport.relay_count,
            transport_connect_timeout_secs = snapshot.transport.connect_timeout_secs,
            "myc runtime bootstrapped"
        );
        if let Some(transport) = self.transport.clone() {
            let service = MycNip46Service::new(self.signer_context(), transport);
            return service.run_until(shutdown).await;
        }
        tokio::pin!(shutdown);
        shutdown.await;
        Ok(())
    }

    fn prepare_filesystem_for(paths: &MycRuntimePaths) -> Result<(), MycError> {
        fs::create_dir_all(&paths.state_dir).map_err(|source| MycError::CreateDir {
            path: paths.state_dir.clone(),
            source,
        })?;
        fs::create_dir_all(&paths.audit_dir).map_err(|source| MycError::CreateDir {
            path: paths.audit_dir.clone(),
            source,
        })?;
        Ok(())
    }
}

impl MycRuntimePaths {
    fn from_config(config: &MycConfig) -> Self {
        let state_dir = config.paths.state_dir.clone();
        Self {
            signer_identity_path: config.paths.signer_identity_path.clone(),
            user_identity_path: config.paths.user_identity_path.clone(),
            signer_state_path: state_dir.join("signer-state.json"),
            audit_dir: state_dir.join("audit"),
            state_dir,
        }
    }
}

impl MycSignerContext {
    pub fn signer_identity(&self) -> &RadrootsIdentity {
        &self.signer_identity
    }

    pub fn signer_public_identity(&self) -> RadrootsIdentityPublic {
        self.signer_identity.to_public()
    }

    pub fn user_identity(&self) -> &RadrootsIdentity {
        &self.user_identity
    }

    pub fn user_public_identity(&self) -> RadrootsIdentityPublic {
        self.user_identity.to_public()
    }

    pub fn load_signer_manager(&self) -> Result<RadrootsNostrSignerManager, MycError> {
        Self::load_signer_manager_from_path(&self.signer_state_path)
    }

    pub fn connection_approval_requirement(&self) -> RadrootsNostrSignerApprovalRequirement {
        self.connection_approval_requirement
    }

    fn bootstrap(
        paths: &MycRuntimePaths,
        connection_approval_requirement: RadrootsNostrSignerApprovalRequirement,
    ) -> Result<Self, MycError> {
        let signer_identity = RadrootsIdentity::load_from_path_auto(&paths.signer_identity_path)?;
        let user_identity = RadrootsIdentity::load_from_path_auto(&paths.user_identity_path)?;
        let manager = Self::load_signer_manager_from_path(&paths.signer_state_path)?;
        let configured_public = signer_identity.to_public();

        match manager.signer_identity()? {
            Some(existing) if existing.id != configured_public.id => {
                return Err(MycError::SignerIdentityMismatch {
                    identity_path: paths.signer_identity_path.clone(),
                    state_path: paths.signer_state_path.clone(),
                    configured_identity_id: configured_public.id.to_string(),
                    persisted_identity_id: existing.id.to_string(),
                });
            }
            Some(_) => manager.set_signer_identity(configured_public.clone())?,
            None => manager.set_signer_identity(configured_public.clone())?,
        }

        Ok(Self {
            signer_identity,
            user_identity,
            signer_state_path: paths.signer_state_path.clone(),
            connection_approval_requirement,
        })
    }

    fn load_signer_manager_from_path(path: &Path) -> Result<RadrootsNostrSignerManager, MycError> {
        Ok(RadrootsNostrSignerManager::new(Arc::new(
            RadrootsNostrFileSignerStore::new(path),
        ))?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_signer::prelude::{
        RadrootsNostrFileSignerStore, RadrootsNostrSignerManager,
    };

    use crate::config::MycConfig;
    use crate::error::MycError;

    use super::MycRuntime;

    fn write_test_identity(path: &std::path::Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity from secret")
            .save_json(path)
            .expect("write identity");
    }

    #[test]
    fn bootstrap_creates_runtime_directories() {
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

        let runtime = MycRuntime::bootstrap(config).expect("runtime");
        assert!(runtime.paths().state_dir.is_dir());
        assert!(runtime.paths().audit_dir.is_dir());
        assert_eq!(
            runtime.paths().signer_identity_path,
            temp.path().join("identity.json")
        );
        assert_eq!(
            runtime.paths().user_identity_path,
            temp.path().join("user.json")
        );
        assert!(
            runtime
                .paths()
                .signer_state_path
                .ends_with("signer-state.json")
        );
        assert!(runtime.paths().signer_state_path.is_file());
        assert_eq!(
            runtime
                .signer_manager()
                .expect("manager")
                .signer_identity()
                .expect("signer identity")
                .expect("configured signer")
                .id
                .to_string(),
            runtime.snapshot().signer_identity_id
        );
        assert_eq!(
            runtime.user_identity().public_key_hex(),
            runtime.snapshot().user_public_key_hex
        );
        assert!(!runtime.snapshot().transport.enabled);
    }

    #[test]
    fn bootstrap_rejects_invalid_config() {
        let mut config = MycConfig::default();
        config.service.instance_name.clear();

        let err = match MycRuntime::bootstrap(config) {
            Ok(_) => panic!("expected invalid config error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("service.instance_name"));
    }

    #[test]
    fn bootstrap_rejects_mismatched_persisted_signer_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let identity_path = temp.path().join("identity.json");
        let user_path = temp.path().join("user.json");
        write_test_identity(
            &identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &user_path,
            "3333333333333333333333333333333333333333333333333333333333333333",
        );

        let store_identity = RadrootsIdentity::from_secret_key_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("second identity");
        let store = Arc::new(RadrootsNostrFileSignerStore::new(
            temp.path().join("state").join("signer-state.json"),
        ));
        let manager = RadrootsNostrSignerManager::new(store).expect("manager");
        manager
            .set_signer_identity(store_identity.to_public())
            .expect("persist signer");

        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = identity_path;
        config.paths.user_identity_path = user_path;

        let err = match MycRuntime::bootstrap(config) {
            Ok(_) => panic!("expected identity mismatch"),
            Err(err) => err,
        };
        assert!(matches!(err, MycError::SignerIdentityMismatch { .. }));
    }

    #[test]
    fn bootstrap_keeps_signer_and_user_identities_distinct() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let runtime = MycRuntime::bootstrap(config).expect("runtime");

        assert_ne!(
            runtime.signer_public_identity().public_key_hex,
            runtime.user_public_identity().public_key_hex
        );
        assert_ne!(
            runtime.snapshot().signer_identity_id,
            runtime.snapshot().user_identity_id
        );
    }

    #[test]
    fn bootstrap_prepares_transport_when_enabled() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 15;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let runtime = MycRuntime::bootstrap(config).expect("runtime");

        assert!(runtime.transport().is_some());
        assert!(runtime.snapshot().transport.enabled);
        assert_eq!(runtime.snapshot().transport.relay_count, 1);
        assert_eq!(runtime.snapshot().transport.connect_timeout_secs, 15);
    }
}
