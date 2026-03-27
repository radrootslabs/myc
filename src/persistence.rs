use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use nostr::PublicKey;
use radroots_nostr_signer::prelude::{
    RadrootsNostrFileSignerStore, RadrootsNostrSignerAuthState,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerPublishWorkflowKind,
    RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerPublishWorkflowState,
    RadrootsNostrSignerStore, RadrootsNostrSignerStoreState, RadrootsNostrSqliteSignerStore,
};
use serde::Serialize;

use crate::app::MycRuntimePaths;
use crate::audit::MycJsonlOperationAuditStore;
use crate::audit_sqlite::MycSqliteOperationAuditStore;
use crate::config::{MycConfig, MycRuntimeAuditBackend, MycSignerStateBackend};
use crate::custody::MycIdentityProvider;
use crate::error::MycError;
use crate::outbox::{
    MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycDeliveryOutboxStatus, MycDeliveryOutboxStore,
};
use crate::outbox_sqlite::MycSqliteDeliveryOutboxStore;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycPersistenceVerifyRestoreOutput {
    pub signer_identity_id: String,
    pub user_identity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_app_identity_id: Option<String>,
    pub signer_state: MycSignerStateVerifyRestoreOutput,
    pub runtime_audit: MycRuntimeAuditVerifyRestoreOutput,
    pub delivery_outbox: MycDeliveryOutboxVerifyRestoreOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycSignerStateVerifyRestoreOutput {
    pub backend: MycSignerStateBackend,
    pub path: PathBuf,
    pub connection_count: usize,
    pub request_audit_count: usize,
    pub publish_workflow_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRuntimeAuditVerifyRestoreOutput {
    pub backend: MycRuntimeAuditBackend,
    pub path: PathBuf,
    pub record_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycDeliveryOutboxVerifyRestoreOutput {
    pub path: PathBuf,
    pub total_job_count: usize,
    pub queued_job_count: usize,
    pub published_pending_finalize_job_count: usize,
    pub finalized_job_count: usize,
    pub failed_job_count: usize,
    pub unfinished_job_count: usize,
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

pub fn verify_restored_state(
    config: &MycConfig,
) -> Result<MycPersistenceVerifyRestoreOutput, MycError> {
    config.validate()?;

    let state_dir = &config.paths.state_dir;
    let audit_dir = MycRuntimePaths::audit_dir_for_state_dir(state_dir);
    let signer_state_path = MycRuntimePaths::signer_state_path_for_backend(
        state_dir,
        config.persistence.signer_state_backend,
    );
    let runtime_audit_path = MycRuntimePaths::runtime_audit_path_for_backend(
        &audit_dir,
        config.persistence.runtime_audit_backend,
    );
    let delivery_outbox_path = MycRuntimePaths::delivery_outbox_path_for_state_dir(state_dir);

    require_existing_restore_file(
        &signer_state_path,
        format!(
            "{} signer-state backend",
            config.persistence.signer_state_backend.as_str()
        ),
    )?;
    require_existing_restore_file(
        &runtime_audit_path,
        format!(
            "{} runtime-audit backend",
            config.persistence.runtime_audit_backend.as_str()
        ),
    )?;
    require_existing_restore_file(&delivery_outbox_path, "delivery outbox".to_owned())?;

    let signer_identity_provider =
        MycIdentityProvider::from_source("signer", config.paths.signer_identity_source())?;
    let signer_identity = signer_identity_provider.load_active_identity()?;
    let user_identity_provider =
        MycIdentityProvider::from_source("user", config.paths.user_identity_source())?;
    let user_identity = user_identity_provider.load_active_identity()?;
    let discovery_app_identity = match config.discovery.app_identity_source() {
        Some(source) => Some(MycIdentityProvider::from_source("discovery app", source)?),
        None => None,
    }
    .map(|provider| provider.load_active_identity())
    .transpose()?;

    let signer_state = load_existing_signer_state(config, &signer_state_path)?;
    let configured_signer_identity = signer_identity.to_public();
    if let Some(existing_signer_identity) = signer_state.signer_identity.as_ref() {
        if existing_signer_identity.id != configured_signer_identity.id {
            return Err(MycError::SignerIdentityMismatch {
                identity_path: config.paths.signer_identity_path.clone(),
                state_path: signer_state_path.clone(),
                configured_identity_id: configured_signer_identity.id.to_string(),
                persisted_identity_id: existing_signer_identity.id.to_string(),
            });
        }
    }

    let runtime_audit_record_count = load_existing_runtime_audit_record_count(config, &audit_dir)?;
    let outbox_store = MycSqliteDeliveryOutboxStore::open(state_dir)?;
    let outbox_records = outbox_store.list_all()?;
    verify_restored_delivery_state(
        &signer_state,
        &outbox_records,
        signer_identity.public_key(),
        discovery_app_identity
            .as_ref()
            .map(|identity| identity.public_key()),
    )?;

    let mut queued_job_count = 0usize;
    let mut published_pending_finalize_job_count = 0usize;
    let mut finalized_job_count = 0usize;
    let mut failed_job_count = 0usize;
    for record in &outbox_records {
        match record.status {
            MycDeliveryOutboxStatus::Queued => queued_job_count += 1,
            MycDeliveryOutboxStatus::PublishedPendingFinalize => {
                published_pending_finalize_job_count += 1
            }
            MycDeliveryOutboxStatus::Finalized => finalized_job_count += 1,
            MycDeliveryOutboxStatus::Failed => failed_job_count += 1,
        }
    }

    Ok(MycPersistenceVerifyRestoreOutput {
        signer_identity_id: signer_identity.id().to_string(),
        user_identity_id: user_identity.id().to_string(),
        discovery_app_identity_id: discovery_app_identity
            .as_ref()
            .map(|identity| identity.id().to_string()),
        signer_state: MycSignerStateVerifyRestoreOutput {
            backend: config.persistence.signer_state_backend,
            path: signer_state_path,
            connection_count: signer_state.connections.len(),
            request_audit_count: signer_state.audit_records.len(),
            publish_workflow_count: signer_state.publish_workflows.len(),
        },
        runtime_audit: MycRuntimeAuditVerifyRestoreOutput {
            backend: config.persistence.runtime_audit_backend,
            path: runtime_audit_path,
            record_count: runtime_audit_record_count,
        },
        delivery_outbox: MycDeliveryOutboxVerifyRestoreOutput {
            path: delivery_outbox_path,
            total_job_count: outbox_records.len(),
            queued_job_count,
            published_pending_finalize_job_count,
            finalized_job_count,
            failed_job_count,
            unfinished_job_count: queued_job_count + published_pending_finalize_job_count,
        },
    })
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
        && state.publish_workflows.is_empty()
}

fn require_existing_restore_file(path: &std::path::Path, label: String) -> Result<(), MycError> {
    if path.is_file() {
        return Ok(());
    }
    Err(MycError::InvalidOperation(format!(
        "persistence verify-restore requires an existing {label} file at {}",
        path.display()
    )))
}

fn load_existing_signer_state(
    config: &MycConfig,
    signer_state_path: &std::path::Path,
) -> Result<RadrootsNostrSignerStoreState, MycError> {
    match config.persistence.signer_state_backend {
        MycSignerStateBackend::JsonFile => RadrootsNostrFileSignerStore::new(signer_state_path)
            .load()
            .map_err(MycError::from),
        MycSignerStateBackend::Sqlite => RadrootsNostrSqliteSignerStore::open(signer_state_path)?
            .load()
            .map_err(MycError::from),
    }
}

fn load_existing_runtime_audit_record_count(
    config: &MycConfig,
    audit_dir: &std::path::Path,
) -> Result<usize, MycError> {
    match config.persistence.runtime_audit_backend {
        MycRuntimeAuditBackend::JsonlFile => Ok(MycJsonlOperationAuditStore::new(
            audit_dir,
            config.audit.clone(),
        )
        .list_all()?
        .len()),
        MycRuntimeAuditBackend::Sqlite => Ok(MycSqliteOperationAuditStore::open(
            audit_dir,
            config.audit.clone(),
        )?
        .list_all()?
        .len()),
    }
}

fn verify_restored_delivery_state(
    signer_state: &RadrootsNostrSignerStoreState,
    outbox_records: &[MycDeliveryOutboxRecord],
    signer_public_key: PublicKey,
    discovery_app_public_key: Option<PublicKey>,
) -> Result<(), MycError> {
    let connections_by_id = signer_state
        .connections
        .iter()
        .map(|connection| (connection.connection_id.as_str().to_owned(), connection))
        .collect::<BTreeMap<_, _>>();
    let workflows_by_id = signer_state
        .publish_workflows
        .iter()
        .map(|workflow| (workflow.workflow_id.as_str().to_owned(), workflow))
        .collect::<BTreeMap<_, _>>();
    let mut referenced_unfinished_workflow_ids = BTreeSet::new();

    for record in outbox_records {
        verify_discovery_restore_author(record, signer_public_key, discovery_app_public_key)?;

        if !matches!(
            record.status,
            MycDeliveryOutboxStatus::Queued | MycDeliveryOutboxStatus::PublishedPendingFinalize
        ) {
            continue;
        }

        let workflow = match record.signer_publish_workflow_id.as_ref() {
            Some(workflow_id) => {
                referenced_unfinished_workflow_ids.insert(workflow_id.as_str().to_owned());
                workflows_by_id.get(workflow_id.as_str()).copied()
            }
            None => None,
        };

        verify_restore_outbox_record(record, workflow, &connections_by_id)?;
    }

    let orphaned_workflows = signer_state
        .publish_workflows
        .iter()
        .filter(|workflow| {
            !referenced_unfinished_workflow_ids.contains(workflow.workflow_id.as_str())
        })
        .map(|workflow| {
            format!(
                "{}:{}:{:?}",
                workflow.workflow_id, workflow.connection_id, workflow.kind
            )
        })
        .collect::<Vec<_>>();
    if !orphaned_workflows.is_empty() {
        return Err(MycError::InvalidOperation(format!(
            "persistence verify-restore found orphaned signer publish workflows with no unfinished delivery outbox job: {}",
            orphaned_workflows.join(", ")
        )));
    }

    Ok(())
}

fn verify_discovery_restore_author(
    record: &MycDeliveryOutboxRecord,
    signer_public_key: PublicKey,
    discovery_app_public_key: Option<PublicKey>,
) -> Result<(), MycError> {
    if record.kind != MycDeliveryOutboxKind::DiscoveryHandlerPublish {
        return Ok(());
    }
    if record.event.pubkey == signer_public_key
        || discovery_app_public_key == Some(record.event.pubkey)
    {
        return Ok(());
    }

    Err(MycError::InvalidOperation(format!(
        "persistence verify-restore found discovery delivery outbox job `{}` authored by `{}` but the configured signer/discovery identities do not match",
        record.job_id, record.event.pubkey
    )))
}

fn verify_restore_outbox_record<'a>(
    record: &MycDeliveryOutboxRecord,
    workflow: Option<&'a RadrootsNostrSignerPublishWorkflowRecord>,
    connections_by_id: &BTreeMap<String, &'a RadrootsNostrSignerConnectionRecord>,
) -> Result<(), MycError> {
    match record.kind {
        MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
            if record.signer_publish_workflow_id.is_some() {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found discovery delivery outbox job `{}` that incorrectly references a signer publish workflow",
                    record.job_id
                )));
            }
        }
        MycDeliveryOutboxKind::ConnectAcceptPublish | MycDeliveryOutboxKind::AuthReplayPublish => {
            if record.signer_publish_workflow_id.is_none() {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found control delivery outbox job `{}` without a signer publish workflow",
                    record.job_id
                )));
            }
        }
        MycDeliveryOutboxKind::ListenerResponsePublish => {}
    }

    match workflow {
        Some(workflow) => {
            let expected_kind = match record.kind {
                MycDeliveryOutboxKind::ListenerResponsePublish
                | MycDeliveryOutboxKind::ConnectAcceptPublish => {
                    RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization
                }
                MycDeliveryOutboxKind::AuthReplayPublish => {
                    RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization
                }
                MycDeliveryOutboxKind::DiscoveryHandlerPublish => unreachable!(),
            };
            if workflow.kind != expected_kind {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` expecting signer workflow kind `{:?}` but found `{:?}`",
                    record.job_id, expected_kind, workflow.kind
                )));
            }

            let connection_id = record.connection_id.as_ref().ok_or_else(|| {
                MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` missing a connection id required for signer workflow verification",
                    record.job_id
                ))
            })?;
            if workflow.connection_id.as_str() != connection_id.as_str() {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` bound to connection `{connection_id}` but signer workflow `{}` is bound to `{}`",
                    record.job_id, workflow.workflow_id, workflow.connection_id
                )));
            }
            if record.status == MycDeliveryOutboxStatus::PublishedPendingFinalize
                && workflow.state
                    != RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize
            {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` waiting for finalize but signer workflow `{}` is in `{:?}`",
                    record.job_id, workflow.workflow_id, workflow.state
                )));
            }
        }
        None => {
            if record.signer_publish_workflow_id.is_some() {
                if record.status == MycDeliveryOutboxStatus::PublishedPendingFinalize {
                    verify_already_finalized_without_workflow(record, connections_by_id)?;
                } else {
                    return Err(MycError::InvalidOperation(format!(
                        "persistence verify-restore found delivery outbox job `{}` referencing a missing signer publish workflow before finalize",
                        record.job_id
                    )));
                }
            }
        }
    }

    Ok(())
}

fn verify_already_finalized_without_workflow(
    record: &MycDeliveryOutboxRecord,
    connections_by_id: &BTreeMap<String, &RadrootsNostrSignerConnectionRecord>,
) -> Result<(), MycError> {
    let workflow_id = record.signer_publish_workflow_id.as_ref().ok_or_else(|| {
        MycError::InvalidOperation(format!(
            "persistence verify-restore found delivery outbox job `{}` missing a signer workflow id for finalization verification",
            record.job_id
        ))
    })?;
    let connection_id = record.connection_id.as_ref().ok_or_else(|| {
        MycError::InvalidOperation(format!(
            "persistence verify-restore found delivery outbox job `{}` missing a connection id for finalization verification",
            record.job_id
        ))
    })?;
    let connection = connections_by_id
        .get(connection_id.as_str())
        .copied()
        .ok_or_else(|| {
            MycError::InvalidOperation(format!(
                "persistence verify-restore found delivery outbox job `{}` referencing missing connection `{connection_id}`",
                record.job_id
            ))
        })?;

    match record.kind {
        MycDeliveryOutboxKind::ListenerResponsePublish
        | MycDeliveryOutboxKind::ConnectAcceptPublish => {
            if !connection.connect_secret_is_consumed() {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` referencing connect workflow `{workflow_id}` but the connection secret is still reusable",
                    record.job_id
                )));
            }
        }
        MycDeliveryOutboxKind::AuthReplayPublish => {
            if connection.auth_state != RadrootsNostrSignerAuthState::Authorized
                || connection.pending_request.is_some()
            {
                return Err(MycError::InvalidOperation(format!(
                    "persistence verify-restore found delivery outbox job `{}` referencing auth replay workflow `{workflow_id}` but the connection auth state is not finalized",
                    record.job_id
                )));
            }
        }
        MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
            return Err(MycError::InvalidOperation(format!(
                "persistence verify-restore found discovery delivery outbox job `{}` unexpectedly referencing signer workflow `{workflow_id}`",
                record.job_id
            )));
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use nostr::PublicKey;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr::prelude::{
        RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKind,
    };
    use radroots_nostr_signer::prelude::{
        RADROOTS_NOSTR_SIGNER_STORE_VERSION, RadrootsNostrFileSignerStore,
        RadrootsNostrSignerConnectionDraft, RadrootsNostrSignerConnectionId,
        RadrootsNostrSignerStore, RadrootsNostrSignerStoreState, RadrootsNostrSignerWorkflowId,
        RadrootsNostrSqliteSignerStore,
    };

    use super::{
        MycPersistenceImportSelection, import_json_to_sqlite, signer_store_state_is_empty,
        verify_restored_delivery_state,
    };
    use crate::app::MycRuntime;
    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::audit_sqlite::MycSqliteOperationAuditStore;
    use crate::config::{MycConfig, MycRuntimeAuditBackend, MycSignerStateBackend};
    use crate::error::MycError;
    use crate::outbox::{MycDeliveryOutboxKind, MycDeliveryOutboxRecord};

    const SIGNER_SECRET_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const USER_SECRET_KEY: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const OTHER_SECRET_KEY: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";

    fn write_identity(path: &Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn identity(secret_key: &str) -> RadrootsIdentity {
        RadrootsIdentity::from_secret_key_str(secret_key).expect("identity")
    }

    fn signer_identity() -> RadrootsIdentity {
        identity(SIGNER_SECRET_KEY)
    }

    fn user_identity() -> RadrootsIdentity {
        identity(USER_SECRET_KEY)
    }

    fn signed_event(secret_key: &str) -> RadrootsNostrEvent {
        RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "hello")
            .sign_with_keys(identity(secret_key).keys())
            .expect("sign event")
    }

    fn outbox_record(kind: MycDeliveryOutboxKind, secret_key: &str) -> MycDeliveryOutboxRecord {
        MycDeliveryOutboxRecord::new(
            kind,
            signed_event(secret_key),
            vec!["wss://relay.example.com".parse().expect("relay")],
        )
        .expect("record")
    }

    fn client_public_key(value: &str) -> PublicKey {
        PublicKey::from_hex(value).expect("pubkey")
    }

    fn load_json_signer_state(temp: &Path) -> RadrootsNostrSignerStoreState {
        RadrootsNostrFileSignerStore::new(temp.join("state").join("signer-state.json"))
            .load()
            .expect("load signer state")
    }

    fn empty_signer_state() -> RadrootsNostrSignerStoreState {
        RadrootsNostrSignerStoreState {
            version: RADROOTS_NOSTR_SIGNER_STORE_VERSION,
            signer_identity: None,
            connections: Vec::new(),
            audit_records: Vec::new(),
            publish_workflows: Vec::new(),
        }
    }

    fn base_config(temp: &Path) -> MycConfig {
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.join("state");
        config.paths.signer_identity_path = temp.join("signer.json");
        config.paths.user_identity_path = temp.join("user.json");
        write_identity(&config.paths.signer_identity_path, SIGNER_SECRET_KEY);
        write_identity(&config.paths.user_identity_path, USER_SECRET_KEY);
        config
    }

    fn bootstrap_json_runtime(temp: &Path) -> MycRuntime {
        let config = base_config(temp);
        MycRuntime::bootstrap(config).expect("runtime")
    }

    #[test]
    fn signer_store_state_is_not_empty_when_only_publish_workflows_are_present() {
        let workflow = radroots_nostr_signer::prelude::RadrootsNostrSignerPublishWorkflowRecord::new_connect_secret_finalization(
            RadrootsNostrSignerConnectionId::parse("workflow-only-connection")
                .expect("workflow connection id"),
            17,
        );
        let state = RadrootsNostrSignerStoreState {
            version: RADROOTS_NOSTR_SIGNER_STORE_VERSION,
            signer_identity: None,
            connections: Vec::new(),
            audit_records: Vec::new(),
            publish_workflows: vec![workflow],
        };

        assert!(
            !signer_store_state_is_empty(&state),
            "publish workflows must make the signer-state destination non-empty"
        );
    }

    #[test]
    fn verify_restore_rejects_orphaned_signer_publish_workflows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("orphan-secret"),
            )
            .expect("register connection");
        manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");

        let signer_state = load_json_signer_state(temp.path());
        let err = verify_restored_delivery_state(
            &signer_state,
            &[],
            signer_identity().public_key(),
            None,
        )
        .expect_err("orphaned workflow should fail restore verification");

        assert!(
            err.to_string()
                .contains("orphaned signer publish workflows")
        );
    }

    #[test]
    fn verify_restore_rejects_discovery_author_mismatch() {
        let signer_state = empty_signer_state();
        let record = outbox_record(
            MycDeliveryOutboxKind::DiscoveryHandlerPublish,
            OTHER_SECRET_KEY,
        );

        let err = verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            Some(user_identity().public_key()),
        )
        .expect_err("unexpected discovery author should fail restore verification");

        assert!(
            err.to_string()
                .contains("configured signer/discovery identities do not match")
        );
    }

    #[test]
    fn verify_restore_rejects_missing_workflow_before_finalize() {
        let signer_state = empty_signer_state();
        let workflow_id =
            RadrootsNostrSignerWorkflowId::parse("missing-workflow").expect("workflow id");
        let record = outbox_record(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            SIGNER_SECRET_KEY,
        )
        .with_signer_publish_workflow_id(&workflow_id);

        let err = verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            None,
        )
        .expect_err("missing unfinished workflow should fail restore verification");

        assert!(
            err.to_string()
                .contains("referencing a missing signer publish workflow before finalize")
        );
    }

    #[test]
    fn verify_restore_accepts_published_pending_finalize_job_after_connect_finalization() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "c6047f9441ed7d6d3045406e95c07cd85a65f77e53bde42a6d0f46b4f0f92b4f",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("accepted-secret"),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");
        manager
            .mark_publish_workflow_published(&workflow.workflow_id)
            .expect("mark published");
        manager
            .finalize_publish_workflow(&workflow.workflow_id)
            .expect("finalize workflow");

        let signer_state = load_json_signer_state(temp.path());
        let mut record = outbox_record(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            SIGNER_SECRET_KEY,
        )
        .with_connection_id(&connection.connection_id)
        .with_signer_publish_workflow_id(&workflow.workflow_id);
        record
            .mark_published_pending_finalize(1, record.created_at_unix + 1)
            .expect("mark published");

        verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            None,
        )
        .expect("already-finalized connect workflow should be accepted");
    }

    #[test]
    fn verify_restore_rejects_wrong_workflow_kind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "f9308a019258c3106f85b9d5b3e8c8f923dc4bde7b5b6d8f8f9ad7881e5341e5",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("kind-secret"),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");

        let signer_state = load_json_signer_state(temp.path());
        let record = outbox_record(MycDeliveryOutboxKind::AuthReplayPublish, SIGNER_SECRET_KEY)
            .with_connection_id(&connection.connection_id)
            .with_signer_publish_workflow_id(&workflow.workflow_id);

        let err = verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            None,
        )
        .expect_err("workflow kind mismatch should fail restore verification");

        assert!(err.to_string().contains("expecting signer workflow kind"));
    }

    #[test]
    fn verify_restore_rejects_wrong_connection_binding() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let first = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("first-secret"),
            )
            .expect("register first");
        let second = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "c6047f9441ed7d6d3045406e95c07cd85a65f77e53bde42a6d0f46b4f0f92b4f",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("second-secret"),
            )
            .expect("register second");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&first.connection_id)
            .expect("begin workflow");

        let signer_state = load_json_signer_state(temp.path());
        let record = outbox_record(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            SIGNER_SECRET_KEY,
        )
        .with_connection_id(&second.connection_id)
        .with_signer_publish_workflow_id(&workflow.workflow_id);

        let err = verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            None,
        )
        .expect_err("workflow connection mismatch should fail restore verification");

        assert!(err.to_string().contains("is bound to"));
    }

    #[test]
    fn verify_restore_rejects_missing_connection_id_for_workflow_job() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = bootstrap_json_runtime(temp.path());
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key(
                        "f9308a019258c3106f85b9d5b3e8c8f923dc4bde7b5b6d8f8f9ad7881e5341e5",
                    ),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("missing-connection-id-secret"),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");

        let signer_state = load_json_signer_state(temp.path());
        let record = outbox_record(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            SIGNER_SECRET_KEY,
        )
        .with_signer_publish_workflow_id(&workflow.workflow_id);

        let err = verify_restored_delivery_state(
            &signer_state,
            &[record],
            signer_identity().public_key(),
            None,
        )
        .expect_err("missing connection id should fail restore verification");

        assert!(
            err.to_string()
                .contains("missing a connection id required for signer workflow verification")
        );
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
