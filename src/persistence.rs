use std::fs;
use std::path::PathBuf;

use radroots_nostr_signer::prelude::{
    RadrootsNostrFileSignerStore, RadrootsNostrSignerStore, RadrootsNostrSqliteSignerStore,
};
use serde::Serialize;

use crate::app::MycRuntimePaths;
use crate::audit::MycJsonlOperationAuditStore;
use crate::audit_sqlite::MycSqliteOperationAuditStore;
use crate::config::{MycConfig, MycRuntimeAuditBackend, MycSignerStateBackend};
use crate::custody::MycIdentityProvider;
use crate::error::MycError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MycPersistenceImportSelection {
    import_signer_state: bool,
    import_runtime_audit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycPersistenceImportJsonToSqliteOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_state: Option<MycSignerStateImportOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_audit: Option<MycRuntimeAuditImportOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycSignerStateImportOutput {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity_id: Option<String>,
    pub connection_count: usize,
    pub request_audit_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRuntimeAuditImportOutput {
    pub source_dir: PathBuf,
    pub destination_path: PathBuf,
    pub record_count: usize,
}

impl MycPersistenceImportSelection {
    pub fn new(import_signer_state: bool, import_runtime_audit: bool) -> Self {
        Self {
            import_signer_state,
            import_runtime_audit,
        }
    }

    fn resolve(self, config: &MycConfig) -> Result<Self, MycError> {
        let import_signer_state = if self.import_signer_state || self.import_runtime_audit {
            self.import_signer_state
        } else {
            config.persistence.signer_state_backend == MycSignerStateBackend::Sqlite
        };
        let import_runtime_audit = if self.import_signer_state || self.import_runtime_audit {
            self.import_runtime_audit
        } else {
            config.persistence.runtime_audit_backend == MycRuntimeAuditBackend::Sqlite
        };

        if import_signer_state
            && config.persistence.signer_state_backend != MycSignerStateBackend::Sqlite
        {
            return Err(MycError::InvalidOperation(
                "json-to-sqlite signer-state import requires MYC_PERSISTENCE_SIGNER_STATE_BACKEND=sqlite"
                    .to_owned(),
            ));
        }
        if import_runtime_audit
            && config.persistence.runtime_audit_backend != MycRuntimeAuditBackend::Sqlite
        {
            return Err(MycError::InvalidOperation(
                "json-to-sqlite runtime-audit import requires MYC_PERSISTENCE_RUNTIME_AUDIT_BACKEND=sqlite"
                    .to_owned(),
            ));
        }
        if !import_signer_state && !import_runtime_audit {
            return Err(MycError::InvalidOperation(
                "json-to-sqlite import requires at least one sqlite-backed destination".to_owned(),
            ));
        }

        Ok(Self {
            import_signer_state,
            import_runtime_audit,
        })
    }
}

pub fn import_json_to_sqlite(
    config: &MycConfig,
    selection: MycPersistenceImportSelection,
) -> Result<MycPersistenceImportJsonToSqliteOutput, MycError> {
    config.validate()?;
    let selection = selection.resolve(config)?;
    let state_dir = &config.paths.state_dir;
    let audit_dir = MycRuntimePaths::audit_dir_for_state_dir(state_dir);
    fs::create_dir_all(state_dir).map_err(|source| MycError::CreateDir {
        path: state_dir.clone(),
        source,
    })?;
    fs::create_dir_all(&audit_dir).map_err(|source| MycError::CreateDir {
        path: audit_dir.clone(),
        source,
    })?;
    let mut output = MycPersistenceImportJsonToSqliteOutput {
        signer_state: None,
        runtime_audit: None,
    };

    if selection.import_signer_state {
        output.signer_state = Some(import_signer_state_json_to_sqlite(config)?);
    }
    if selection.import_runtime_audit {
        output.runtime_audit = Some(import_runtime_audit_jsonl_to_sqlite(config, &audit_dir)?);
    }

    Ok(output)
}

fn import_signer_state_json_to_sqlite(
    config: &MycConfig,
) -> Result<MycSignerStateImportOutput, MycError> {
    let source_path = MycRuntimePaths::signer_state_path_for_backend(
        &config.paths.state_dir,
        MycSignerStateBackend::JsonFile,
    );
    let destination_path = MycRuntimePaths::signer_state_path_for_backend(
        &config.paths.state_dir,
        MycSignerStateBackend::Sqlite,
    );
    let source_store = RadrootsNostrFileSignerStore::new(&source_path);
    let source_state = source_store.load()?;
    let signer_identity_provider =
        MycIdentityProvider::from_source("signer", config.paths.signer_identity_source())?;
    let configured_signer_identity = signer_identity_provider.load_identity()?.to_public();
    if let Some(imported_signer_identity) = source_state.signer_identity.as_ref() {
        if imported_signer_identity.id != configured_signer_identity.id {
            return Err(MycError::SignerIdentityImportMismatch {
                state_path: source_path.clone(),
                configured_identity_id: configured_signer_identity.id.to_string(),
                imported_identity_id: imported_signer_identity.id.to_string(),
            });
        }
    }

    let destination_store = RadrootsNostrSqliteSignerStore::open(&destination_path)?;
    let existing_destination_state = destination_store.load()?;
    if !signer_store_state_is_empty(&existing_destination_state) {
        return Err(MycError::InvalidOperation(format!(
            "sqlite signer-state destination {} is not empty; refusing import",
            destination_path.display()
        )));
    }

    destination_store.save(&source_state)?;

    Ok(MycSignerStateImportOutput {
        source_path,
        destination_path,
        signer_identity_id: source_state
            .signer_identity
            .as_ref()
            .map(|identity| identity.id.to_string()),
        connection_count: source_state.connections.len(),
        request_audit_count: source_state.audit_records.len(),
    })
}

fn import_runtime_audit_jsonl_to_sqlite(
    config: &MycConfig,
    audit_dir: &std::path::Path,
) -> Result<MycRuntimeAuditImportOutput, MycError> {
    let source_store = MycJsonlOperationAuditStore::new(audit_dir, config.audit.clone());
    let source_records = source_store.list_all()?;
    let destination_store = MycSqliteOperationAuditStore::open(audit_dir, config.audit.clone())?;
    let existing_destination_records = destination_store.list_all()?;
    if !existing_destination_records.is_empty() {
        return Err(MycError::InvalidOperation(format!(
            "sqlite runtime-audit destination {} is not empty; refusing import",
            destination_store.path().display()
        )));
    }
    for record in &source_records {
        destination_store.append(record)?;
    }

    Ok(MycRuntimeAuditImportOutput {
        source_dir: audit_dir.to_path_buf(),
        destination_path: destination_store.path().to_path_buf(),
        record_count: source_records.len(),
    })
}

fn signer_store_state_is_empty(
    state: &radroots_nostr_signer::prelude::RadrootsNostrSignerStoreState,
) -> bool {
    state.signer_identity.is_none()
        && state.connections.is_empty()
        && state.audit_records.is_empty()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use nostr::PublicKey;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_signer::prelude::{
        RadrootsNostrFileSignerStore, RadrootsNostrSignerConnectionDraft, RadrootsNostrSignerStore,
        RadrootsNostrSqliteSignerStore,
    };

    use super::{MycPersistenceImportSelection, import_json_to_sqlite};
    use crate::app::MycRuntime;
    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::audit_sqlite::MycSqliteOperationAuditStore;
    use crate::config::{MycConfig, MycRuntimeAuditBackend, MycSignerStateBackend};
    use crate::error::MycError;

    fn write_identity(path: &Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn base_config(temp: &Path) -> MycConfig {
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.join("state");
        config.paths.signer_identity_path = temp.join("signer.json");
        config.paths.user_identity_path = temp.join("user.json");
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        config
    }

    fn bootstrap_json_runtime(temp: &Path) -> MycRuntime {
        let config = base_config(temp);
        MycRuntime::bootstrap(config).expect("runtime")
    }

    #[test]
    fn import_json_to_sqlite_moves_signer_state_and_runtime_audit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                PublicKey::from_hex(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .expect("pubkey"),
                runtime.user_public_identity(),
            ))
            .expect("register connection");
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Succeeded,
            Some(&connection.connection_id),
            Some("request-1"),
            1,
            1,
            "publish succeeded",
        ));

        let mut sqlite_config = base_config(temp.path());
        sqlite_config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
        sqlite_config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;

        let output = import_json_to_sqlite(
            &sqlite_config,
            MycPersistenceImportSelection::new(false, false),
        )
        .expect("import");

        assert_eq!(
            output
                .signer_state
                .as_ref()
                .expect("signer-state output")
                .connection_count,
            1
        );
        assert_eq!(
            output
                .runtime_audit
                .as_ref()
                .expect("runtime-audit output")
                .record_count,
            1
        );

        let imported_runtime = MycRuntime::bootstrap(sqlite_config).expect("sqlite runtime");
        assert_eq!(
            imported_runtime
                .signer_manager()
                .expect("manager")
                .list_connections()
                .expect("connections")
                .len(),
            1
        );
        assert_eq!(
            imported_runtime
                .operation_audit_store()
                .list_all()
                .expect("audit records")
                .len(),
            1
        );
    }

    #[test]
    fn import_signer_state_rejects_non_empty_sqlite_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                PublicKey::from_hex(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .expect("pubkey"),
                runtime.user_public_identity(),
            ))
            .expect("register connection");

        let mut sqlite_config = base_config(temp.path());
        sqlite_config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;

        let sqlite_store = RadrootsNostrSqliteSignerStore::open(
            temp.path().join("state").join("signer-state.sqlite"),
        )
        .expect("sqlite store");
        let existing_state =
            RadrootsNostrFileSignerStore::new(temp.path().join("state").join("signer-state.json"))
                .load()
                .expect("load source state");
        sqlite_store
            .save(&existing_state)
            .expect("save sqlite state");

        let err = import_json_to_sqlite(
            &sqlite_config,
            MycPersistenceImportSelection::new(true, false),
        )
        .expect_err("non-empty sqlite signer destination should fail");

        assert!(err.to_string().contains("sqlite signer-state destination"));
    }

    #[test]
    fn import_runtime_audit_rejects_non_empty_sqlite_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Succeeded,
            None,
            Some("request-1"),
            1,
            1,
            "publish succeeded",
        ));

        let mut sqlite_config = base_config(temp.path());
        sqlite_config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;

        let sqlite_audit_store = MycSqliteOperationAuditStore::open(
            temp.path().join("state").join("audit"),
            sqlite_config.audit.clone(),
        )
        .expect("sqlite audit store");
        sqlite_audit_store
            .append(&MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayRestore,
                MycOperationAuditOutcome::Restored,
                None,
                Some("request-2"),
                1,
                0,
                "restored pending auth challenge",
            ))
            .expect("append");

        let err = import_json_to_sqlite(
            &sqlite_config,
            MycPersistenceImportSelection::new(false, true),
        )
        .expect_err("non-empty sqlite audit destination should fail");

        assert!(err.to_string().contains("sqlite runtime-audit destination"));
    }

    #[test]
    fn import_signer_state_rejects_mismatched_configured_signer_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                PublicKey::from_hex(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .expect("pubkey"),
                runtime.user_public_identity(),
            ))
            .expect("register connection");

        let mut sqlite_config = base_config(temp.path());
        let other_signer_path = PathBuf::from(temp.path()).join("other-signer.json");
        write_identity(
            &other_signer_path,
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        sqlite_config.paths.signer_identity_path = other_signer_path;
        sqlite_config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;

        let err = import_json_to_sqlite(
            &sqlite_config,
            MycPersistenceImportSelection::new(true, false),
        )
        .expect_err("mismatched signer identity should fail");

        assert!(matches!(err, MycError::SignerIdentityImportMismatch { .. }));
    }
}
