use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::audit::{
    MycJsonlOperationAuditStore, MycOperationAuditKind, MycOperationAuditOutcome,
    MycOperationAuditRecord, MycOperationAuditStore,
};
use crate::audit_sqlite::MycSqliteOperationAuditStore;
use crate::config::{
    MycAuditConfig, MycConfig, MycIdentitySourceSpec, MycPersistenceConfig, MycRuntimeAuditBackend,
    MycSignerStateBackend, MycTransportDeliveryPolicy,
};
use crate::custody::{MycActiveIdentity, MycIdentityProvider};
use crate::discovery::MycDiscoveryContext;
use crate::error::MycError;
use crate::operability::{
    MycDeliveryOutboxStatusOutput, MycLiveMetricsHandle, MycLiveMetricsState, MycMetricsSnapshot,
    server::run_observability_server,
};
use crate::outbox::{
    MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycDeliveryOutboxStatus, MycDeliveryOutboxStore,
};
use crate::outbox_sqlite::MycSqliteDeliveryOutboxStore;
use crate::policy::MycPolicyContext;
use crate::transport::{
    MycNip46Service, MycNostrTransport, MycPublishOutcome, MycTransportSnapshot,
};
use radroots_identity::RadrootsIdentityPublic;
use radroots_nostr_signer::prelude::{
    RadrootsNostrFileSignerStore, RadrootsNostrSignerApprovalRequirement,
    RadrootsNostrSignerAuthState, RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerManager,
    RadrootsNostrSignerPublishWorkflowKind, RadrootsNostrSignerPublishWorkflowRecord,
    RadrootsNostrSignerPublishWorkflowState, RadrootsNostrSignerRequestAuditRecord,
    RadrootsNostrSignerStore, RadrootsNostrSqliteSignerStore,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycRuntimePaths {
    pub state_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub signer_identity_path: PathBuf,
    pub user_identity_path: PathBuf,
    pub signer_state_path: PathBuf,
    pub runtime_audit_path: PathBuf,
    pub delivery_outbox_path: PathBuf,
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
    pub signer_state_backend: MycSignerStateBackend,
    pub signer_state_path: PathBuf,
    pub runtime_audit_backend: MycRuntimeAuditBackend,
    pub runtime_audit_path: PathBuf,
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
    signer_identity: MycActiveIdentity,
    user_identity: MycActiveIdentity,
    signer_store: Arc<dyn RadrootsNostrSignerStore>,
    operation_audit_store: Arc<dyn MycOperationAuditStore>,
    live_metrics: MycLiveMetricsHandle,
    policy: MycPolicyContext,
    connection_approval_requirement: RadrootsNostrSignerApprovalRequirement,
}

#[derive(Clone)]
pub struct MycRuntime {
    config: MycConfig,
    paths: MycRuntimePaths,
    signer: MycSignerContext,
    transport: Option<MycNostrTransport>,
    delivery_outbox_store: Arc<dyn MycDeliveryOutboxStore>,
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
        let delivery_outbox_store = Arc::new(MycSqliteDeliveryOutboxStore::open(&paths.state_dir)?);
        let runtime = Self {
            paths,
            config,
            signer,
            transport,
            delivery_outbox_store,
        };
        Ok(runtime)
    }

    pub fn paths(&self) -> &MycRuntimePaths {
        &self.paths
    }

    pub fn config(&self) -> &MycConfig {
        &self.config
    }

    pub fn signer_identity(&self) -> &MycActiveIdentity {
        self.signer.signer_identity()
    }

    pub fn signer_public_identity(&self) -> RadrootsIdentityPublic {
        self.signer.signer_public_identity()
    }

    pub fn user_identity(&self) -> &MycActiveIdentity {
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

    pub(crate) fn metrics_snapshot(
        &self,
        outbox_status: &MycDeliveryOutboxStatusOutput,
    ) -> MycMetricsSnapshot {
        self.signer.metrics_snapshot(outbox_status)
    }

    pub fn delivery_outbox_store(&self) -> Arc<dyn MycDeliveryOutboxStore> {
        self.delivery_outbox_store.clone()
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
            signer_state_backend: self.config.persistence.signer_state_backend,
            signer_state_path: self.paths.signer_state_path.clone(),
            runtime_audit_backend: self.config.persistence.runtime_audit_backend,
            runtime_audit_path: self.paths.runtime_audit_path.clone(),
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
            signer_state_backend = snapshot.signer_state_backend.as_str(),
            signer_state_path = %snapshot.signer_state_path.display(),
            runtime_audit_backend = snapshot.runtime_audit_backend.as_str(),
            runtime_audit_path = %snapshot.runtime_audit_path.display(),
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
        self.recover_pending_delivery_jobs().await?;
        let mut tasks = tokio::task::JoinSet::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        if let Some(transport) = self.transport.clone() {
            let service = MycNip46Service::new(
                self.signer_context(),
                transport,
                self.delivery_outbox_store(),
            );
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

    async fn recover_pending_delivery_jobs(&self) -> Result<(), MycError> {
        let mut queued_records = self
            .delivery_outbox_store
            .list_by_status(MycDeliveryOutboxStatus::Queued)?;
        let published_records = self
            .delivery_outbox_store
            .list_by_status(MycDeliveryOutboxStatus::PublishedPendingFinalize)?;
        if queued_records.is_empty() && published_records.is_empty() {
            if let Err(error) = self.ensure_no_orphaned_publish_workflows() {
                self.record_delivery_recovery_summary(
                    MycOperationAuditOutcome::Rejected,
                    0,
                    0,
                    0,
                    error.to_string(),
                );
                return Err(error);
            }
            return Ok(());
        }

        queued_records.extend(published_records);
        queued_records.sort_by(|left, right| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left.job_id.as_str().cmp(right.job_id.as_str()))
        });

        tracing::info!(
            unfinished_delivery_job_count = queued_records.len(),
            "starting myc delivery recovery"
        );

        let unfinished_delivery_job_count = queued_records.len();
        let mut finalized_job_count = 0usize;
        let mut republished_job_count = 0usize;
        let manager = self.signer_manager()?;
        for record in queued_records {
            match self.recover_delivery_outbox_record(&manager, record).await {
                Ok(republished) => {
                    finalized_job_count += 1;
                    if republished {
                        republished_job_count += 1;
                    }
                }
                Err(error) => {
                    self.record_delivery_recovery_summary(
                        MycOperationAuditOutcome::Rejected,
                        unfinished_delivery_job_count,
                        finalized_job_count,
                        republished_job_count,
                        error.to_string(),
                    );
                    return Err(error);
                }
            }
        }
        if let Err(error) = self.ensure_no_orphaned_publish_workflows() {
            self.record_delivery_recovery_summary(
                MycOperationAuditOutcome::Rejected,
                unfinished_delivery_job_count,
                finalized_job_count,
                republished_job_count,
                error.to_string(),
            );
            return Err(error);
        }
        self.record_delivery_recovery_summary(
            MycOperationAuditOutcome::Succeeded,
            unfinished_delivery_job_count,
            finalized_job_count,
            republished_job_count,
            format!(
                "recovered {finalized_job_count}/{unfinished_delivery_job_count} delivery outbox job(s); republished {republished_job_count}"
            ),
        );

        tracing::info!("completed myc delivery recovery");
        Ok(())
    }

    fn ensure_no_orphaned_publish_workflows(&self) -> Result<(), MycError> {
        let workflows = self.signer_manager()?.list_publish_workflows()?;
        if workflows.is_empty() {
            return Ok(());
        }

        let remaining = workflows
            .into_iter()
            .map(|workflow| {
                format!(
                    "{}:{}:{:?}",
                    workflow.workflow_id, workflow.connection_id, workflow.kind
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        Err(MycError::InvalidOperation(format!(
            "startup recovery found orphaned signer publish workflows with no recoverable outbox job: {remaining}"
        )))
    }

    async fn recover_delivery_outbox_record(
        &self,
        manager: &RadrootsNostrSignerManager,
        record: MycDeliveryOutboxRecord,
    ) -> Result<bool, MycError> {
        self.validate_outbox_workflow_expectations(&record)?;
        let workflow = self.lookup_publish_workflow_for_record(manager, &record)?;
        tracing::info!(
            job_id = %record.job_id,
            kind = ?record.kind,
            status = ?record.status,
            request_id = record.request_id.as_deref().unwrap_or(""),
            attempt_id = record.attempt_id.as_deref().unwrap_or(""),
            signer_publish_workflow_id = record
                .signer_publish_workflow_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            "recovering myc delivery outbox job"
        );

        match record.status {
            MycDeliveryOutboxStatus::Queued => {
                if record.signer_publish_workflow_id.is_some() && workflow.is_none() {
                    return Err(self.wrap_recovery_error(
                        &record,
                        MycError::InvalidOperation(
                            "delivery outbox job references a missing signer publish workflow before startup recovery publish"
                                .to_owned(),
                        ),
                    ));
                }
                if matches!(
                    workflow.as_ref().map(|workflow| workflow.state),
                    Some(RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize)
                ) {
                    let publish_attempt_count = record.publish_attempt_count.max(1);
                    let published = self
                        .delivery_outbox_store
                        .mark_published_pending_finalize(&record.job_id, publish_attempt_count)?;
                    self.finalize_recovered_delivery_job(
                        manager,
                        published,
                        workflow.as_ref(),
                        None,
                    )?;
                    return Ok(false);
                }

                let publish_outcome = self
                    .republish_recovered_outbox_event(&record)
                    .await
                    .map_err(|error| self.wrap_recovery_error(&record, error))?;
                if let Some(workflow) = workflow.as_ref() {
                    manager
                        .mark_publish_workflow_published(&workflow.workflow_id)
                        .map_err(|error| {
                            self.wrap_recovery_error(
                                &record,
                                MycError::InvalidOperation(format!(
                                    "failed to mark signer publish workflow as published during startup recovery: {error}"
                                )),
                            )
                        })?;
                }
                let published_workflow = match record.signer_publish_workflow_id.as_ref() {
                    Some(workflow_id) => Some(
                        manager
                            .get_publish_workflow(workflow_id)
                            .map_err(MycError::from)
                            .and_then(|workflow| {
                                workflow.ok_or_else(|| {
                                    MycError::InvalidOperation(format!(
                                        "signer publish workflow `{workflow_id}` disappeared after startup recovery publish confirmation"
                                    ))
                                })
                            })
                            .map_err(|error| self.wrap_recovery_error(&record, error))?,
                    ),
                    None => None,
                };
                let published = self
                    .delivery_outbox_store
                    .mark_published_pending_finalize(&record.job_id, publish_outcome.attempt_count)
                    .map_err(|error| self.wrap_recovery_error(&record, error))?;
                self.finalize_recovered_delivery_job(
                    manager,
                    published,
                    published_workflow.as_ref(),
                    Some(&publish_outcome),
                )?;
                Ok(true)
            }
            MycDeliveryOutboxStatus::PublishedPendingFinalize => {
                self.finalize_recovered_delivery_job(manager, record, workflow.as_ref(), None)?;
                Ok(false)
            }
            MycDeliveryOutboxStatus::Finalized | MycDeliveryOutboxStatus::Failed => Ok(false),
        }
    }

    fn finalize_recovered_delivery_job(
        &self,
        manager: &RadrootsNostrSignerManager,
        record: MycDeliveryOutboxRecord,
        workflow: Option<&RadrootsNostrSignerPublishWorkflowRecord>,
        publish_outcome: Option<&MycPublishOutcome>,
    ) -> Result<(), MycError> {
        if let Some(workflow) = workflow {
            if workflow.state != RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize {
                return Err(self.wrap_recovery_error(
                        &record,
                        MycError::InvalidOperation(format!(
                            "signer publish workflow `{}` is in `{}` instead of `published_pending_finalize` during startup recovery",
                            workflow.workflow_id,
                            format!("{:?}", workflow.state)
                        )),
                    ));
            }
            manager
                .finalize_publish_workflow(&workflow.workflow_id)
                .map_err(|error| {
                    self.wrap_recovery_error(
                        &record,
                        MycError::InvalidOperation(format!(
                            "failed to finalize signer publish workflow during startup recovery: {error}"
                        )),
                    )
                })?;
        } else {
            self.ensure_record_is_already_finalized_without_workflow(manager, &record)?;
        }

        let finalized_record = self
            .delivery_outbox_store
            .mark_finalized(&record.job_id)
            .map_err(|error| self.wrap_recovery_error(&record, error))?;
        self.record_recovery_success(&finalized_record, publish_outcome);
        Ok(())
    }

    fn ensure_record_is_already_finalized_without_workflow(
        &self,
        manager: &RadrootsNostrSignerManager,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<(), MycError> {
        let Some(workflow_id) = record.signer_publish_workflow_id.as_ref() else {
            return Ok(());
        };

        match record.kind {
            MycDeliveryOutboxKind::ListenerResponsePublish
            | MycDeliveryOutboxKind::ConnectAcceptPublish => {
                let connection = self.recovery_connection_record(manager, record)?;
                if !connection.connect_secret_is_consumed() {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(format!(
                            "delivery outbox job `{}` references consumed-secret workflow `{workflow_id}` but the connection secret is still reusable",
                            record.job_id
                        )),
                    ));
                }
            }
            MycDeliveryOutboxKind::AuthReplayPublish => {
                let connection = self.recovery_connection_record(manager, record)?;
                if connection.auth_state != RadrootsNostrSignerAuthState::Authorized
                    || connection.pending_request.is_some()
                {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(format!(
                            "delivery outbox job `{}` references auth replay workflow `{workflow_id}` but the connection auth state is not finalized",
                            record.job_id
                        )),
                    ));
                }
            }
            MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
                return Err(self.wrap_recovery_error(
                    record,
                    MycError::InvalidOperation(format!(
                        "discovery delivery outbox job `{}` unexpectedly references signer workflow `{workflow_id}`",
                        record.job_id
                    )),
                ));
            }
        }

        Ok(())
    }

    fn recovery_connection_record(
        &self,
        manager: &RadrootsNostrSignerManager,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<RadrootsNostrSignerConnectionRecord, MycError> {
        let connection_id = record.connection_id.as_ref().ok_or_else(|| {
            self.wrap_recovery_error(
                record,
                MycError::InvalidOperation(
                    "delivery outbox job is missing a connection id required for recovery"
                        .to_owned(),
                ),
            )
        })?;
        manager.get_connection(connection_id)?.ok_or_else(|| {
            self.wrap_recovery_error(
                record,
                MycError::InvalidOperation(format!(
                    "delivery outbox job references missing connection `{connection_id}`"
                )),
            )
        })
    }

    fn validate_outbox_workflow_expectations(
        &self,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<(), MycError> {
        match record.kind {
            MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
                if record.signer_publish_workflow_id.is_some() {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(
                            "discovery delivery outbox jobs must not reference signer publish workflows"
                                .to_owned(),
                        ),
                    ));
                }
            }
            MycDeliveryOutboxKind::ConnectAcceptPublish
            | MycDeliveryOutboxKind::AuthReplayPublish => {
                if record.signer_publish_workflow_id.is_none() {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(
                            "control delivery outbox jobs must reference signer publish workflows"
                                .to_owned(),
                        ),
                    ));
                }
            }
            MycDeliveryOutboxKind::ListenerResponsePublish => {}
        }
        Ok(())
    }

    fn lookup_publish_workflow_for_record(
        &self,
        manager: &RadrootsNostrSignerManager,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<Option<RadrootsNostrSignerPublishWorkflowRecord>, MycError> {
        let Some(workflow_id) = record.signer_publish_workflow_id.as_ref() else {
            return Ok(None);
        };
        let workflow = manager.get_publish_workflow(workflow_id)?.map(|workflow| {
            let kind_label = match record.kind {
                MycDeliveryOutboxKind::ListenerResponsePublish
                | MycDeliveryOutboxKind::ConnectAcceptPublish => {
                    RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization
                }
                MycDeliveryOutboxKind::AuthReplayPublish => {
                    RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization
                }
                MycDeliveryOutboxKind::DiscoveryHandlerPublish => unreachable!(),
            };
            if workflow.kind != kind_label {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(format!(
                            "delivery outbox job `{}` expects signer workflow kind `{}` but found `{}`",
                            record.job_id,
                            format!("{kind_label:?}"),
                            format!("{:?}", workflow.kind),
                        )),
                    ));
                }
            if let Some(connection_id) = record.connection_id.as_ref() {
                if &workflow.connection_id != connection_id {
                    return Err(self.wrap_recovery_error(
                        record,
                        MycError::InvalidOperation(format!(
                            "delivery outbox job `{}` connection `{connection_id}` does not match signer workflow connection `{}`",
                            record.job_id, workflow.connection_id
                        )),
                    ));
                }
            }
            Ok(workflow)
        });
        workflow.transpose()
    }

    async fn republish_recovered_outbox_event(
        &self,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<MycPublishOutcome, MycError> {
        let signer_identity = self.recovery_publisher_identity(record)?;
        MycNostrTransport::publish_event_once(
            &signer_identity,
            &record.relay_urls,
            &self.config.transport,
            recovery_operation_label(record.kind),
            &record.event,
        )
        .await
    }

    fn recovery_publisher_identity(
        &self,
        record: &MycDeliveryOutboxRecord,
    ) -> Result<MycActiveIdentity, MycError> {
        if record.kind != MycDeliveryOutboxKind::DiscoveryHandlerPublish {
            return Ok(self.signer_identity().clone());
        }
        if record.event.pubkey == self.signer_identity().public_key() {
            return Ok(self.signer_identity().clone());
        }

        let context = MycDiscoveryContext::from_runtime(self)?;
        if record.event.pubkey != context.app_identity().public_key() {
            return Err(self.wrap_recovery_error(
                record,
                MycError::InvalidOperation(format!(
                    "discovery delivery outbox job author `{}` does not match the configured signer or discovery app identity",
                    record.event.pubkey
                )),
            ));
        }
        Ok(context.app_identity().clone())
    }

    fn record_recovery_success(
        &self,
        outbox_record: &MycDeliveryOutboxRecord,
        publish_outcome: Option<&MycPublishOutcome>,
    ) {
        let (relay_count, acknowledged_relay_count, summary, mut audit_record) =
            match publish_outcome {
                Some(publish_outcome) => (
                    publish_outcome.relay_count,
                    publish_outcome.acknowledged_relay_count,
                    publish_outcome.relay_outcome_summary.clone(),
                    MycOperationAuditRecord::new(
                        recovery_operation_audit_kind(outbox_record.kind),
                        MycOperationAuditOutcome::Succeeded,
                        outbox_record.connection_id.as_ref(),
                        outbox_record.request_id.as_deref(),
                        publish_outcome.relay_count,
                        publish_outcome.acknowledged_relay_count,
                        publish_outcome.relay_outcome_summary.clone(),
                    )
                    .with_delivery_details(
                        publish_outcome.delivery_policy,
                        publish_outcome.required_acknowledged_relay_count,
                        publish_outcome.attempt_count,
                    ),
                ),
                None => {
                    let relay_count = outbox_record.relay_urls.len();
                    let required_acknowledged_relay_count = self
                        .required_acknowledged_relay_count(relay_count)
                        .unwrap_or_default();
                    let summary = "startup recovery finalized previously published delivery job";
                    (
                        relay_count,
                        required_acknowledged_relay_count,
                        summary.to_owned(),
                        MycOperationAuditRecord::new(
                            recovery_operation_audit_kind(outbox_record.kind),
                            MycOperationAuditOutcome::Succeeded,
                            outbox_record.connection_id.as_ref(),
                            outbox_record.request_id.as_deref(),
                            relay_count,
                            required_acknowledged_relay_count,
                            summary.to_owned(),
                        )
                        .with_delivery_details(
                            self.config.transport.delivery_policy,
                            required_acknowledged_relay_count,
                            outbox_record.publish_attempt_count.max(1),
                        ),
                    )
                }
            };
        if let Some(attempt_id) = outbox_record.attempt_id.as_deref() {
            audit_record = audit_record.with_attempt_id(attempt_id);
        }
        tracing::info!(
            job_id = %outbox_record.job_id,
            kind = ?outbox_record.kind,
            relay_count,
            acknowledged_relay_count,
            summary = %summary,
            "recovered myc delivery outbox job"
        );
        self.record_operation_audit(&audit_record);
    }

    fn record_delivery_recovery_summary(
        &self,
        outcome: MycOperationAuditOutcome,
        unfinished_job_count: usize,
        finalized_job_count: usize,
        republished_job_count: usize,
        summary: impl Into<String>,
    ) {
        let summary = summary.into();
        let record = MycOperationAuditRecord::new(
            MycOperationAuditKind::DeliveryRecovery,
            outcome,
            None,
            None,
            unfinished_job_count,
            finalized_job_count,
            summary.clone(),
        );
        tracing::info!(
            outcome = ?outcome,
            unfinished_job_count,
            finalized_job_count,
            republished_job_count,
            summary = %summary,
            "recorded myc delivery recovery summary"
        );
        self.record_operation_audit(&record);
    }

    fn required_acknowledged_relay_count(&self, relay_count: usize) -> Result<usize, MycError> {
        match self.config.transport.delivery_policy {
            MycTransportDeliveryPolicy::Any => Ok(1),
            MycTransportDeliveryPolicy::All => Ok(relay_count),
            MycTransportDeliveryPolicy::Quorum => {
                let delivery_quorum = self.config.transport.delivery_quorum.ok_or_else(|| {
                    MycError::InvalidOperation(
                        "transport.delivery_quorum must be set when transport.delivery_policy is `quorum`"
                            .to_owned(),
                    )
                })?;
                if delivery_quorum > relay_count {
                    return Err(MycError::InvalidOperation(format!(
                        "transport.delivery_quorum `{delivery_quorum}` cannot be satisfied by `{relay_count}` target relays"
                    )));
                }
                Ok(delivery_quorum)
            }
        }
    }

    fn wrap_recovery_error(&self, record: &MycDeliveryOutboxRecord, error: MycError) -> MycError {
        let wrapped = MycError::InvalidOperation(format!(
            "startup recovery failed for delivery outbox job `{}` ({:?}): {error}",
            record.job_id, record.kind
        ));
        tracing::error!(
            job_id = %record.job_id,
            kind = ?record.kind,
            status = ?record.status,
            request_id = record.request_id.as_deref().unwrap_or(""),
            attempt_id = record.attempt_id.as_deref().unwrap_or(""),
            error = %wrapped,
            "myc startup delivery recovery failed"
        );
        wrapped
    }
}

fn recovery_operation_label(kind: MycDeliveryOutboxKind) -> &'static str {
    match kind {
        MycDeliveryOutboxKind::ListenerResponsePublish => "listener response recovery publish",
        MycDeliveryOutboxKind::ConnectAcceptPublish => "connect accept recovery publish",
        MycDeliveryOutboxKind::AuthReplayPublish => "auth replay recovery publish",
        MycDeliveryOutboxKind::DiscoveryHandlerPublish => "discovery handler recovery publish",
    }
}

fn recovery_operation_audit_kind(kind: MycDeliveryOutboxKind) -> MycOperationAuditKind {
    match kind {
        MycDeliveryOutboxKind::ListenerResponsePublish => {
            MycOperationAuditKind::ListenerResponsePublish
        }
        MycDeliveryOutboxKind::ConnectAcceptPublish => MycOperationAuditKind::ConnectAcceptPublish,
        MycDeliveryOutboxKind::AuthReplayPublish => MycOperationAuditKind::AuthReplayPublish,
        MycDeliveryOutboxKind::DiscoveryHandlerPublish => {
            MycOperationAuditKind::DiscoveryHandlerPublish
        }
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
    pub(crate) fn audit_dir_for_state_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("audit")
    }

    pub(crate) fn signer_state_path_for_backend(
        state_dir: &Path,
        backend: MycSignerStateBackend,
    ) -> PathBuf {
        state_dir.join(match backend {
            MycSignerStateBackend::JsonFile => "signer-state.json",
            MycSignerStateBackend::Sqlite => "signer-state.sqlite",
        })
    }

    pub(crate) fn runtime_audit_path_for_backend(
        audit_dir: &Path,
        backend: MycRuntimeAuditBackend,
    ) -> PathBuf {
        audit_dir.join(match backend {
            MycRuntimeAuditBackend::JsonlFile => "operations.jsonl",
            MycRuntimeAuditBackend::Sqlite => "operations.sqlite",
        })
    }

    pub(crate) fn delivery_outbox_path_for_state_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("delivery-outbox.sqlite")
    }

    fn from_config(config: &MycConfig) -> Self {
        let state_dir = config.paths.state_dir.clone();
        let audit_dir = Self::audit_dir_for_state_dir(&state_dir);
        Self {
            signer_identity_path: config.paths.signer_identity_path.clone(),
            user_identity_path: config.paths.user_identity_path.clone(),
            signer_state_path: Self::signer_state_path_for_backend(
                &state_dir,
                config.persistence.signer_state_backend,
            ),
            runtime_audit_path: Self::runtime_audit_path_for_backend(
                &audit_dir,
                config.persistence.runtime_audit_backend,
            ),
            delivery_outbox_path: Self::delivery_outbox_path_for_state_dir(&state_dir),
            audit_dir,
            state_dir,
        }
    }
}

impl MycSignerContext {
    pub fn signer_identity(&self) -> &MycActiveIdentity {
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

    pub fn user_identity(&self) -> &MycActiveIdentity {
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

    pub fn record_signer_request_audit(&self, record: &RadrootsNostrSignerRequestAuditRecord) {
        let mut metrics = self
            .live_metrics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        metrics.record_signer_request_audit(record);
    }

    pub fn record_operation_audit(&self, record: &MycOperationAuditRecord) {
        emit_operation_audit_trace(record);
        match self.operation_audit_store.append(record) {
            Ok(()) => {
                let mut metrics = self
                    .live_metrics
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                metrics.record_runtime_operation(record);
            }
            Err(error) => {
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
    }

    pub fn metrics_snapshot(
        &self,
        outbox_status: &MycDeliveryOutboxStatusOutput,
    ) -> MycMetricsSnapshot {
        let metrics = self
            .live_metrics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        metrics.snapshot(outbox_status)
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
        let signer_identity = signer_identity_provider.load_active_identity()?;
        let user_identity = user_identity_provider.load_active_identity()?;
        let signer_store = Self::build_signer_store(persistence, &paths.signer_state_path)?;
        let operation_audit_store =
            Self::build_operation_audit_store(persistence, &paths.audit_dir, audit_config)?;
        let manager = Self::load_signer_manager_from_store(signer_store.clone())?;
        let live_metrics = Arc::new(std::sync::Mutex::new(MycLiveMetricsState::from_records(
            &manager.list_audit_records()?,
            &operation_audit_store.list_all()?,
        )));
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
        let stale_session_cleanup_count = policy.cleanup_stale_sessions(&manager)?;
        if stale_session_cleanup_count > 0 {
            tracing::info!(
                stale_session_cleanup_count,
                "cleaned stale trusted auth sessions during myc bootstrap"
            );
        }

        Ok(Self {
            signer_identity_provider,
            user_identity_provider,
            signer_identity,
            user_identity,
            signer_store,
            operation_audit_store,
            live_metrics,
            connection_approval_requirement: policy.default_approval_requirement(),
            policy,
        })
    }

    fn build_signer_store(
        persistence: &MycPersistenceConfig,
        path: &Path,
    ) -> Result<Arc<dyn RadrootsNostrSignerStore>, MycError> {
        match persistence.signer_state_backend {
            MycSignerStateBackend::JsonFile => {
                Ok(Arc::new(RadrootsNostrFileSignerStore::new(path)))
            }
            MycSignerStateBackend::Sqlite => {
                Ok(Arc::new(RadrootsNostrSqliteSignerStore::open(path)?))
            }
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

    use nostr::PublicKey;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr::prelude::{RadrootsNostrEventBuilder, RadrootsNostrKind};
    use radroots_nostr_signer::prelude::{
        RadrootsNostrFileSignerStore, RadrootsNostrSignerApprovalRequirement,
        RadrootsNostrSignerAuthState, RadrootsNostrSignerConnectionDraft,
        RadrootsNostrSignerManager, RadrootsNostrSqliteSignerStore,
    };

    use super::MycRuntime;
    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::config::{MycConfig, MycRuntimeAuditBackend, MycSignerStateBackend};
    use crate::error::MycError;
    use crate::outbox::{MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycDeliveryOutboxStatus};

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
        assert!(
            runtime
                .paths()
                .delivery_outbox_path
                .ends_with("delivery-outbox.sqlite")
        );
        assert!(runtime.paths().delivery_outbox_path.is_file());
        assert!(
            runtime
                .delivery_outbox_store()
                .list_all()
                .expect("list outbox jobs")
                .is_empty()
        );
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
    fn bootstrap_cleans_stale_trusted_authorized_sessions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.policy.auth_url = Some("https://auth.example/challenge".to_owned());
        config.policy.auth_authorized_ttl_secs = Some(1);
        let client_public_key =
            PublicKey::parse("4545454545454545454545454545454545454545454545454545454545454545")
                .expect("client public key");
        config.policy.trusted_client_pubkeys = vec![client_public_key.to_hex()];
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let runtime = MycRuntime::bootstrap(config.clone()).expect("runtime");
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key,
                    runtime.user_public_identity(),
                )
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
            )
            .expect("register connection");
        manager
            .require_auth_challenge(
                &connection.connection_id,
                config.policy.auth_url.as_deref().expect("auth url"),
            )
            .expect("require auth");
        manager
            .authorize_auth_challenge(&connection.connection_id)
            .expect("authorize auth");

        std::thread::sleep(std::time::Duration::from_secs(2));
        drop(runtime);

        let runtime = MycRuntime::bootstrap(config).expect("runtime restart");
        let reloaded = runtime
            .signer_manager()
            .expect("manager")
            .get_connection(&connection.connection_id)
            .expect("load connection")
            .expect("connection");

        assert_eq!(reloaded.auth_state, RadrootsNostrSignerAuthState::Pending);
        assert!(reloaded.auth_challenge.is_some());
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
    fn bootstrap_supports_sqlite_signer_state_backend() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
        write_test_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_test_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        let runtime = MycRuntime::bootstrap(config).expect("runtime");

        assert!(
            runtime
                .paths()
                .signer_state_path
                .ends_with("signer-state.sqlite")
        );
        assert!(runtime.paths().signer_state_path.is_file());
        assert!(runtime.paths().delivery_outbox_path.is_file());
    }

    #[test]
    fn bootstrap_rejects_mismatched_persisted_sqlite_signer_identity() {
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
        let store = Arc::new(
            RadrootsNostrSqliteSignerStore::open(
                temp.path().join("state").join("signer-state.sqlite"),
            )
            .expect("open sqlite store"),
        );
        let manager = RadrootsNostrSignerManager::new(store).expect("manager");
        manager
            .set_signer_identity(store_identity.to_public())
            .expect("persist signer");

        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = identity_path;
        config.paths.user_identity_path = user_path;
        config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;

        let err = match MycRuntime::bootstrap(config) {
            Ok(_) => panic!("expected identity mismatch"),
            Err(err) => err,
        };
        assert!(matches!(err, MycError::SignerIdentityMismatch { .. }));
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
        assert!(runtime.paths().delivery_outbox_path.is_file());
    }

    #[tokio::test]
    async fn startup_recovery_rejects_orphaned_signer_publish_workflow() {
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
        let client_identity = RadrootsIdentity::from_secret_key_str(
            "7777777777777777777777777777777777777777777777777777777777777777",
        )
        .expect("client identity");
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_identity.public_key(),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("orphan-secret")
                .with_relays(vec!["wss://relay.example.com".parse().expect("relay url")])
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");

        let error = runtime
            .recover_pending_delivery_jobs()
            .await
            .expect_err("orphaned workflow should fail recovery");
        let message = error.to_string();
        assert!(message.contains("orphaned signer publish workflows"));
        assert!(message.contains(workflow.workflow_id.as_str()));
    }

    #[tokio::test]
    async fn startup_recovery_finalizes_published_connect_secret_workflow() {
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
        let client_identity = RadrootsIdentity::from_secret_key_str(
            "7777777777777777777777777777777777777777777777777777777777777777",
        )
        .expect("client identity");
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_identity.public_key(),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("recovery-secret")
                .with_relays(vec!["wss://relay.example.com".parse().expect("relay url")])
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");
        manager
            .mark_publish_workflow_published(&workflow.workflow_id)
            .expect("mark workflow published");

        let event = runtime
            .signer_identity()
            .sign_event_builder(
                RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "recovery"),
                "recovery test",
            )
            .expect("sign event");
        let outbox_record = MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            event,
            vec!["wss://relay.example.com".parse().expect("relay url")],
        )
        .expect("outbox record")
        .with_connection_id(&connection.connection_id)
        .with_request_id("recovery-request")
        .with_signer_publish_workflow_id(&workflow.workflow_id);
        runtime
            .delivery_outbox_store()
            .enqueue(&outbox_record)
            .expect("enqueue outbox");
        runtime
            .delivery_outbox_store()
            .mark_published_pending_finalize(&outbox_record.job_id, 1)
            .expect("mark outbox published");

        runtime
            .recover_pending_delivery_jobs()
            .await
            .expect("recovery should succeed");

        let connection = runtime
            .signer_manager()
            .expect("manager")
            .get_connection(&connection.connection_id)
            .expect("get connection")
            .expect("stored connection");
        assert!(connection.connect_secret_is_consumed());
        assert!(
            runtime
                .signer_manager()
                .expect("manager")
                .list_publish_workflows()
                .expect("list workflows")
                .is_empty()
        );
        let outbox_records = runtime
            .delivery_outbox_store()
            .list_all()
            .expect("list outbox");
        assert_eq!(outbox_records.len(), 1);
        assert_eq!(outbox_records[0].status, MycDeliveryOutboxStatus::Finalized);
        assert!(outbox_records[0].finalized_at_unix.is_some());
        let audit_records = runtime.operation_audit_store().list().expect("list audit");
        assert_eq!(audit_records.len(), 2);
        assert_eq!(
            audit_records[0].operation,
            MycOperationAuditKind::ListenerResponsePublish
        );
        assert_eq!(
            audit_records[0].outcome,
            MycOperationAuditOutcome::Succeeded
        );
        assert_eq!(
            audit_records[0].request_id.as_deref(),
            Some("recovery-request")
        );
        assert_eq!(
            audit_records[1].operation,
            MycOperationAuditKind::DeliveryRecovery
        );
        assert_eq!(
            audit_records[1].outcome,
            MycOperationAuditOutcome::Succeeded
        );
    }

    #[tokio::test]
    async fn startup_recovery_rejects_queued_job_with_missing_signer_workflow() {
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
        let client_identity = RadrootsIdentity::from_secret_key_str(
            "7777777777777777777777777777777777777777777777777777777777777777",
        )
        .expect("client identity");
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_identity.public_key(),
                    runtime.user_public_identity(),
                )
                .with_connect_secret("missing-workflow-secret")
                .with_relays(vec!["wss://relay.example.com".parse().expect("relay url")])
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
            )
            .expect("register connection");
        let workflow = manager
            .begin_connect_secret_publish_finalization(&connection.connection_id)
            .expect("begin workflow");
        let event = runtime
            .signer_identity()
            .sign_event_builder(
                RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "queued-recovery"),
                "queued recovery test",
            )
            .expect("sign event");
        let outbox_record = MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            event,
            vec!["wss://relay.example.com".parse().expect("relay url")],
        )
        .expect("outbox record")
        .with_connection_id(&connection.connection_id)
        .with_request_id("queued-missing-workflow")
        .with_signer_publish_workflow_id(&workflow.workflow_id);
        runtime
            .delivery_outbox_store()
            .enqueue(&outbox_record)
            .expect("enqueue outbox");
        manager
            .cancel_publish_workflow(&workflow.workflow_id)
            .expect("cancel workflow");

        let error = runtime
            .recover_pending_delivery_jobs()
            .await
            .expect_err("queued job with missing workflow should fail recovery");
        assert!(
            error
                .to_string()
                .contains("missing signer publish workflow before startup recovery publish")
        );
    }
}
