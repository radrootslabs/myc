#![forbid(unsafe_code)]

pub mod accounts;
pub mod app;
pub mod audit;
mod audit_sqlite;
mod cli_v1;
pub mod config;
mod config_v1;
pub mod control;
pub mod custody;
pub mod discovery;
pub mod error;
pub mod host_identity;
pub mod identity_files;
pub mod logging;
pub mod nostr_contract;
pub mod operability;
pub mod outbox;
mod outbox_sqlite;
mod paths;
pub mod persistence;
pub mod policy;
mod runtime_context;
pub mod signer;
mod signing_adapter;
pub mod sql;
mod state_catalog;
mod state_host;
pub mod transport;

pub use app::{
    MycApp, MycRuntime, MycRuntimePaths, MycSignerBackend, MycSignerContext, MycStartupSnapshot,
};
pub use audit::{
    MycJsonlOperationAuditStore, MycOperationAuditKind, MycOperationAuditOutcome,
    MycOperationAuditRecord, MycOperationAuditStore,
};
pub use audit_sqlite::MycSqliteOperationAuditStore;
pub use cli_v1::{
    MycBootstrapProfileV1, MycCliInvocationV1, MycCliV1Error, MycCliV1ErrorKind, MycCommandV1,
    MycConfigCommandV1, MycIdentityCommandV1, MycStateCommandV1, parse_myc_cli_v1_from,
};
pub use config::{
    MycAuditConfig, MycConfig, MycConnectionApproval, MycCustodyConfig, MycDiscoveryConfig,
    MycDiscoveryMetadataConfig, MycIdentityBackend, MycIdentitySourceSpec, MycLoggingConfig,
    MycObservabilityConfig, MycPathsConfig, MycPersistenceConfig, MycPolicyConfig,
    MycRuntimeAuditBackend, MycRuntimeContractOutput, MycSignerStateBackend, MycTransportConfig,
    MycTransportDeliveryPolicy,
};
pub use config_v1::{
    MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, MYC_CONFIG_SCHEMA, MYC_CONFIG_SCHEMA_VERSION,
    MycConfigDocumentV1, MycConfigProfile, MycConfigV1Error, MycConfigV1ErrorKind,
    MycConfigValueSource, MycEffectiveConfigV1, parse_myc_config_v1,
};
pub use control::{MycAcceptedConnectionOutput, MycAuthorizedReplayOutput};
pub use custody::{
    MycActiveIdentity, MycCustodyExportOutput, MycCustodyImportOutput, MycCustodyRotateOutput,
    MycIdentityProvider, MycIdentityStatusOutput, MycManagedAccountMutationOutput,
    MycManagedAccountSelectionState, MycManagedAccountsOutput,
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
    MYC_SIGNER_STATUS_CONTRACT_VERSION, MycAuditDecisionCounts, MycCustodyStatusOutput,
    MycDeliveryOutboxStatusOutput, MycDeliveryRecoveryStatusOutput, MycDiscoveryStatusOutput,
    MycMetricsSnapshot, MycOperationOutcomeCounts, MycPersistenceStatusOutput, MycRelayProbe,
    MycRelayProbeAvailability, MycRuntimeAuditPersistenceStatusOutput, MycRuntimeStatus,
    MycSignerBackendStatusOutput, MycSignerStatePersistenceStatusOutput,
    MycSqliteSchemaStatusOutput, MycStatusFullOutput, MycStatusSignerOutput,
    MycStatusSummaryOutput, MycTransportStatusOutput, collect_metrics, collect_status_full,
    collect_status_signer, collect_status_summary, render_metrics_text,
};
pub use outbox::{
    MycDeliveryOutboxJobId, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
    MycDeliveryOutboxStatus, MycDeliveryOutboxStore,
};
pub use outbox_sqlite::MycSqliteDeliveryOutboxStore;
pub use persistence::{
    MycDeliveryOutboxVerifyRestoreOutput, MycPersistenceBackupOutput,
    MycPersistenceBackupStateOutput, MycPersistenceIdentityReferenceBackupOutput,
    MycPersistenceIdentityReferenceRestoreOutput, MycPersistenceImportJsonToSqliteOutput,
    MycPersistenceImportSelection, MycPersistenceRestoreOutput, MycPersistenceRestoreStateOutput,
    MycPersistenceVerifyRestoreOutput, MycRuntimeAuditImportOutput,
    MycRuntimeAuditVerifyRestoreOutput, MycSignerStateImportOutput,
    MycSignerStateVerifyRestoreOutput, backup_persistence, import_json_to_sqlite, restore_backup,
    verify_restored_state,
};
pub use policy::{MycConnectDecision, MycPolicyContext};
pub use radroots_runtime_paths::{
    INSTANCE_ID_MAX_BYTES, InstanceId, RadrootsHostEnvironment, RadrootsPathProfile,
    RadrootsPathResolver, RadrootsPlatform, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextSource, ServiceId,
};
pub use runtime_context::{
    MycRuntimeContext, MycRuntimeContextError, MycRuntimeContextErrorKind,
    resolve_myc_runtime_context,
};
pub use state_catalog::{
    MYC_MIGRATION_CATALOG_SHA256, MYC_STATE_SCHEMA_CATALOG_SHA256, MYC_STATE_SCHEMA_VERSION,
    MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_1_SHA256,
    MycStateCatalogError, MycStateCatalogErrorKind, myc_migration_catalog, myc_schema_catalog,
    validate_myc_state_catalogs,
};
pub use state_host::{
    MycStateHost, MycStateHostError, MycStateHostErrorKind, MycStateHostMode, initialize_myc_state,
    open_myc_state_inspection, open_myc_state_read_write,
};
pub use transport::{MycNostrTransport, MycRelayPublishResult, MycTransportSnapshot};
