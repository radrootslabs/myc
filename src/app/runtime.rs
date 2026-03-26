use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::audit::{MycJsonlOperationAuditStore, MycOperationAuditRecord, MycOperationAuditStore};
use crate::audit_sqlite::MycSqliteOperationAuditStore;
use crate::config::{
    MycAuditConfig, MycConfig, MycIdentitySourceSpec, MycPersistenceConfig, MycRuntimeAuditBackend,
    MycSignerStateBackend,
};
use crate::custody::MycIdentityProvider;
use crate::error::MycError;
use crate::operability::server::run_observability_server;
use crate::policy::MycPolicyContext;
use crate::transport::{MycNip46Service, MycNostrTransport, MycTransportSnapshot};
use radroots_identity::{RadrootsIdentity, RadrootsIdentityPublic};
use radroots_nostr_signer::prelude::{
    RadrootsNostrFileSignerStore, RadrootsNostrSignerApprovalRequirement,
    RadrootsNostrSignerManager, RadrootsNostrSignerStore,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycRuntimePaths {
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
    pub signer_state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycStartupSnapshot {
    pub instance_name: String,
    pub log_filter: String,
    pub observability_enabled: bool,
    pub observability_bind_addr: SocketAddr,
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
    pub signer_identity_source: MycIdentitySourceSpec,
    pub user_identity_source: MycIdentitySourceSpec,
    pub signer_state_path: PathBuf,
    pub signer_identity_id: String,
    pub signer_public_key_hex: String,
    pub user_identity_id: String,
    pub user_public_key_hex: String,
    pub transport: MycTransportSnapshot,
}

#[derive(Clone)]
pub struct MycSignerContext {
    signer_identity_provider: MycIdentityProvider,
    user_identity_provider: MycIdentityProvider,
    signer_identity: RadrootsIdentity,
    user_identity: RadrootsIdentity,
    signer_store: Arc<dyn RadrootsNostrSignerStore>,
    operation_audit_store: Arc<dyn MycOperationAuditStore>,
    policy: MycPolicyContext,
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
            &config.persistence,
            config.audit.clone(),
            MycPolicyContext::from_config(&config.policy)?,
            config.paths.signer_identity_source(),
            config.paths.user_identity_source(),
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

    pub fn operation_audit_store(&self) -> Arc<dyn MycOperationAuditStore> {
        self.signer.operation_audit_store()
    }

    pub fn record_operation_audit(&self, record: &MycOperationAuditRecord) {
        self.signer.record_operation_audit(record);
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
            observability_enabled: self.config.observability.enabled,
            observability_bind_addr: self.config.observability.bind_addr,
            state_dir: self.paths.state_dir.clone(),
            audit_dir: self.paths.audit_dir.clone(),
            signer_identity_path: self.paths.signer_identity_path.clone(),
            user_identity_path: self.paths.user_identity_path.clone(),
            signer_identity_source: self.signer.signer_identity_source().clone(),
            user_identity_source: self.signer.user_identity_source().clone(),
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
            signer_identity_backend = %snapshot.signer_identity_source.backend.as_str(),
            user_identity_backend = %snapshot.user_identity_source.backend.as_str(),
            signer_keyring_account_id = snapshot.signer_identity_source.keyring_account_id.as_deref().unwrap_or(""),
            user_keyring_account_id = snapshot.user_identity_source.keyring_account_id.as_deref().unwrap_or(""),
            signer_state_path = %snapshot.signer_state_path.display(),
            signer_identity_id = %snapshot.signer_identity_id,
            signer_public_key_hex = %snapshot.signer_public_key_hex,
            user_identity_id = %snapshot.user_identity_id,
            user_public_key_hex = %snapshot.user_public_key_hex,
            observability_enabled = snapshot.observability_enabled,
            observability_bind_addr = %snapshot.observability_bind_addr,
            transport_enabled = snapshot.transport.enabled,
            transport_relay_count = snapshot.transport.relay_count,
            transport_connect_timeout_secs = snapshot.transport.connect_timeout_secs,
            "myc runtime bootstrapped"
        );
        let mut tasks = tokio::task::JoinSet::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        if let Some(transport) = self.transport.clone() {
            let service = MycNip46Service::new(self.signer_context(), transport);
            let shutdown = observe_shutdown_signal(shutdown_rx.clone());
            tasks.spawn(async move { service.run_until(shutdown).await });
        }
        if self.config.observability.enabled {
            let runtime = self.clone();
            let shutdown = observe_shutdown_signal(shutdown_rx);
            tasks.spawn(async move { run_observability_server(runtime, shutdown).await });
        }

        tokio::pin!(shutdown);
        if tasks.is_empty() {
            shutdown.await;
            return Ok(());
        }

        tokio::select! {
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(true);
                drain_runtime_tasks(tasks).await
            }
            joined = tasks.join_next() => {
                let _ = shutdown_tx.send(true);
                let first_result = match joined {
                    Some(result) => result.map_err(|error| {
                        MycError::InvalidOperation(format!("myc runtime task failed: {error}"))
                    })?,
                    None => Ok(()),
                };
                let remaining = drain_runtime_tasks(tasks).await;
                first_result.and(remaining)
            }
        }
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

async fn drain_runtime_tasks(
    mut tasks: tokio::task::JoinSet<Result<(), MycError>>,
) -> Result<(), MycError> {
    let mut first_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(MycError::InvalidOperation(format!(
                        "myc runtime task failed: {error}"
                    )));
                }
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn observe_shutdown_signal(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        if shutdown_rx.changed().await.is_err() {
            break;
        }
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

    pub fn signer_identity_source(&self) -> &MycIdentitySourceSpec {
        self.signer_identity_provider.source()
    }

    pub fn signer_identity_provider(&self) -> &MycIdentityProvider {
        &self.signer_identity_provider
    }

    pub fn signer_public_identity(&self) -> RadrootsIdentityPublic {
        self.signer_identity.to_public()
    }

    pub fn user_identity(&self) -> &RadrootsIdentity {
        &self.user_identity
    }

    pub fn user_identity_source(&self) -> &MycIdentitySourceSpec {
        self.user_identity_provider.source()
    }

    pub fn user_identity_provider(&self) -> &MycIdentityProvider {
        &self.user_identity_provider
    }

    pub fn user_public_identity(&self) -> RadrootsIdentityPublic {
        self.user_identity.to_public()
    }

    pub fn load_signer_manager(&self) -> Result<RadrootsNostrSignerManager, MycError> {
        Self::load_signer_manager_from_store(self.signer_store.clone())
    }

    pub fn operation_audit_store(&self) -> Arc<dyn MycOperationAuditStore> {
        self.operation_audit_store.clone()
    }

    pub fn record_operation_audit(&self, record: &MycOperationAuditRecord) {
        emit_operation_audit_trace(record);
        if let Err(error) = self.operation_audit_store.append(record) {
            tracing::error!(
                operation = ?record.operation,
                outcome = ?record.outcome,
                relay_url = record.relay_url.as_deref().unwrap_or(""),
                connection_id = record.connection_id.as_deref().unwrap_or(""),
                request_id = record.request_id.as_deref().unwrap_or(""),
                attempt_id = record.attempt_id.as_deref().unwrap_or(""),
                delivery_policy = ?record.delivery_policy,
                required_acknowledged_relay_count = record.required_acknowledged_relay_count.unwrap_or_default(),
                publish_attempt_count = record.publish_attempt_count.unwrap_or_default(),
                relay_count = record.relay_count,
                acknowledged_relay_count = record.acknowledged_relay_count,
                relay_outcome_summary = %record.relay_outcome_summary,
                error = %error,
                "failed to persist myc operation audit record"
            );
        }
    }

    pub fn connection_approval_requirement(&self) -> RadrootsNostrSignerApprovalRequirement {
        self.connection_approval_requirement
    }

    pub fn policy(&self) -> &MycPolicyContext {
        &self.policy
    }

    fn bootstrap(
        paths: &MycRuntimePaths,
        persistence: &MycPersistenceConfig,
        audit_config: MycAuditConfig,
        policy: MycPolicyContext,
        signer_identity_source: MycIdentitySourceSpec,
        user_identity_source: MycIdentitySourceSpec,
    ) -> Result<Self, MycError> {
        let signer_identity_provider =
            MycIdentityProvider::from_source("signer", signer_identity_source)?;
        let user_identity_provider =
            MycIdentityProvider::from_source("user", user_identity_source)?;
        let signer_identity = signer_identity_provider.load_identity()?;
        let user_identity = user_identity_provider.load_identity()?;
        let signer_store = Self::build_signer_store(persistence, &paths.signer_state_path);
        let operation_audit_store =
            Self::build_operation_audit_store(persistence, &paths.audit_dir, audit_config)?;
        let manager = Self::load_signer_manager_from_store(signer_store.clone())?;
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
            signer_identity_provider,
            user_identity_provider,
            signer_identity,
            user_identity,
            signer_store,
            operation_audit_store,
            connection_approval_requirement: policy.default_approval_requirement(),
            policy,
        })
    }

    fn build_signer_store(
        persistence: &MycPersistenceConfig,
        path: &Path,
    ) -> Arc<dyn RadrootsNostrSignerStore> {
        match persistence.signer_state_backend {
            MycSignerStateBackend::JsonFile => Arc::new(RadrootsNostrFileSignerStore::new(path)),
        }
    }

    fn build_operation_audit_store(
        persistence: &MycPersistenceConfig,
        audit_dir: &Path,
        audit_config: MycAuditConfig,
    ) -> Result<Arc<dyn MycOperationAuditStore>, MycError> {
        match persistence.runtime_audit_backend {
            MycRuntimeAuditBackend::JsonlFile => Ok(Arc::new(MycJsonlOperationAuditStore::new(
                audit_dir,
                audit_config,
            ))),
            MycRuntimeAuditBackend::Sqlite => Ok(Arc::new(MycSqliteOperationAuditStore::open(
                audit_dir,
                audit_config,
            )?)),
        }
    }

    fn load_signer_manager_from_store(
        store: Arc<dyn RadrootsNostrSignerStore>,
    ) -> Result<RadrootsNostrSignerManager, MycError> {
        Ok(RadrootsNostrSignerManager::new(store)?)
    }
}

fn emit_operation_audit_trace(record: &MycOperationAuditRecord) {
    match record.outcome {
        crate::audit::MycOperationAuditOutcome::Succeeded
        | crate::audit::MycOperationAuditOutcome::Missing
        | crate::audit::MycOperationAuditOutcome::Matched
        | crate::audit::MycOperationAuditOutcome::Skipped => tracing::info!(
            operation = ?record.operation,
            outcome = ?record.outcome,
            relay_url = record.relay_url.as_deref().unwrap_or(""),
            connection_id = record.connection_id.as_deref().unwrap_or(""),
            request_id = record.request_id.as_deref().unwrap_or(""),
            attempt_id = record.attempt_id.as_deref().unwrap_or(""),
            delivery_policy = ?record.delivery_policy,
            required_acknowledged_relay_count = record.required_acknowledged_relay_count.unwrap_or_default(),
            publish_attempt_count = record.publish_attempt_count.unwrap_or_default(),
            relay_count = record.relay_count,
            acknowledged_relay_count = record.acknowledged_relay_count,
            relay_outcome_summary = %record.relay_outcome_summary,
            "recorded myc operation audit"
        ),
        crate::audit::MycOperationAuditOutcome::Rejected
        | crate::audit::MycOperationAuditOutcome::Restored
        | crate::audit::MycOperationAuditOutcome::Unavailable
        | crate::audit::MycOperationAuditOutcome::Drifted
        | crate::audit::MycOperationAuditOutcome::Conflicted => tracing::warn!(
            operation = ?record.operation,
            outcome = ?record.outcome,
            relay_url = record.relay_url.as_deref().unwrap_or(""),
            connection_id = record.connection_id.as_deref().unwrap_or(""),
            request_id = record.request_id.as_deref().unwrap_or(""),
            attempt_id = record.attempt_id.as_deref().unwrap_or(""),
            delivery_policy = ?record.delivery_policy,
            required_acknowledged_relay_count = record.required_acknowledged_relay_count.unwrap_or_default(),
            publish_attempt_count = record.publish_attempt_count.unwrap_or_default(),
            relay_count = record.relay_count,
            acknowledged_relay_count = record.acknowledged_relay_count,
            relay_outcome_summary = %record.relay_outcome_summary,
            "recorded myc operation audit"
        ),
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

    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::config::{MycConfig, MycRuntimeAuditBackend};
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

    #[test]
    fn bootstrap_supports_sqlite_operation_audit_backend() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let runtime = MycRuntime::bootstrap(config).expect("runtime");
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Succeeded,
            None,
            Some("request-1"),
            1,
            1,
            "relay acknowledged publish",
        ));

        let records = runtime
            .operation_audit_store()
            .list()
            .expect("list runtime audit");
        assert_eq!(records.len(), 1);
        assert!(
            runtime
                .paths()
                .audit_dir
                .join("operations.sqlite")
                .is_file()
        );
    }
}
