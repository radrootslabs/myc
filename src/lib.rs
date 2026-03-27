#![forbid(unsafe_code)]

pub mod app;
pub mod audit;
mod audit_sqlite;
pub mod cli;
pub mod config;
pub mod control;
pub mod custody;
pub mod discovery;
pub mod error;
pub mod logging;
pub mod operability;
pub mod outbox;
mod outbox_sqlite;
pub mod persistence;
pub mod policy;
pub mod transport;

pub use app::{MycApp, MycRuntime, MycRuntimePaths, MycSignerContext, MycStartupSnapshot};
pub use audit::{
    MycJsonlOperationAuditStore, MycOperationAuditKind, MycOperationAuditOutcome,
    MycOperationAuditRecord, MycOperationAuditStore,
};
pub use audit_sqlite::MycSqliteOperationAuditStore;
pub use config::{
    DEFAULT_ENV_PATH, MycAuditConfig, MycConfig, MycConnectionApproval, MycDiscoveryConfig,
    MycDiscoveryMetadataConfig, MycIdentityBackend, MycIdentitySourceSpec, MycLoggingConfig,
    MycObservabilityConfig, MycPathsConfig, MycPersistenceConfig, MycPolicyConfig,
    MycRuntimeAuditBackend, MycServiceConfig, MycSignerStateBackend, MycTransportConfig,
    MycTransportDeliveryPolicy,
};
pub use control::{MycAcceptedConnectionOutput, MycAuthorizedReplayOutput};
pub use custody::{
    MycActiveIdentity, MycIdentityProvider, MycIdentityStatusOutput,
    MycManagedAccountMutationOutput, MycManagedAccountSelectionState, MycManagedAccountsOutput,
};
pub use discovery::{
    MycDiscoveryBundleManifest, MycDiscoveryBundleOutput, MycDiscoveryContext,
    MycDiscoveryDiffOutput, MycDiscoveryLiveStatus, MycDiscoveryRelayFetchStatus,
    MycDiscoveryRelayRepairResult, MycDiscoveryRelayState, MycDiscoveryRelaySummary,
    MycDiscoveryRepairOutcome, MycDiscoveryRepairSummary, MycFetchedLiveNip89Output,
    MycLiveNip89Event, MycLiveNip89Group, MycLiveNip89RelayState, MycNip05Document,
    MycNip05DocumentSection, MycNip89HandlerDocument, MycNormalizedNip89Handler,
    MycPublishedNip89Output, MycRefreshedNip89Output, MycRenderedNip05Output,
    MycRenderedNip89Output, diff_live_nip89, fetch_live_nip89, publish_nip89_event, refresh_nip89,
    render_nip05_output, verify_bundle,
};
pub use error::MycError;
pub use operability::{
    MycAuditDecisionCounts, MycCustodyStatusOutput, MycDeliveryOutboxStatusOutput,
    MycDeliveryRecoveryStatusOutput, MycDiscoveryStatusOutput, MycMetricsSnapshot,
    MycOperationOutcomeCounts, MycPersistenceStatusOutput, MycRelayProbe,
    MycRelayProbeAvailability, MycRuntimeAuditPersistenceStatusOutput, MycRuntimeStatus,
    MycSignerStatePersistenceStatusOutput, MycSqliteSchemaStatusOutput, MycStatusFullOutput,
    MycStatusSummaryOutput, MycTransportStatusOutput, collect_metrics, collect_status_full,
    collect_status_summary, render_metrics_text,
};
pub use outbox::{
    MycDeliveryOutboxJobId, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
    MycDeliveryOutboxStatus, MycDeliveryOutboxStore,
};
pub use outbox_sqlite::MycSqliteDeliveryOutboxStore;
pub use persistence::{
    MycDeliveryOutboxVerifyRestoreOutput, MycPersistenceImportJsonToSqliteOutput,
    MycPersistenceImportSelection, MycPersistenceVerifyRestoreOutput, MycRuntimeAuditImportOutput,
    MycRuntimeAuditVerifyRestoreOutput, MycSignerStateImportOutput,
    MycSignerStateVerifyRestoreOutput, import_json_to_sqlite, verify_restored_state,
};
pub use policy::{MycConnectDecision, MycPolicyContext};
pub use transport::{MycNostrTransport, MycRelayPublishResult, MycTransportSnapshot};

pub async fn run() -> Result<(), MycError> {
    let config = MycConfig::load_from_default_env_path()?;
    logging::init_logging(&config.logging)?;
    MycApp::bootstrap(config)?.run().await
}

pub async fn run_cli() -> Result<(), MycError> {
    cli::run_from_env().await
}
