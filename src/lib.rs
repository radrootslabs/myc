#![forbid(unsafe_code)]

pub mod app;
pub mod audit;
pub mod cli;
pub mod config;
pub mod control;
pub mod discovery;
pub mod error;
pub mod logging;
pub mod transport;

pub use app::{MycApp, MycRuntime, MycRuntimePaths, MycSignerContext, MycStartupSnapshot};
pub use audit::{
    MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
    MycOperationAuditStore,
};
pub use config::{
    DEFAULT_CONFIG_PATH, MycAuditConfig, MycConfig, MycConnectionApproval, MycDiscoveryConfig,
    MycDiscoveryMetadataConfig, MycLoggingConfig, MycPathsConfig, MycPolicyConfig,
    MycServiceConfig, MycTransportConfig,
};
pub use control::{MycAcceptedConnectionOutput, MycAuthorizedReplayOutput};
pub use discovery::{
    MycDiscoveryBundleManifest, MycDiscoveryBundleOutput, MycDiscoveryContext,
    MycDiscoveryDiffOutput, MycDiscoveryLiveStatus, MycDiscoveryRelayState,
    MycDiscoveryRelaySummary, MycFetchedLiveNip89Output, MycLiveNip89Event, MycLiveNip89Group,
    MycLiveNip89RelayState, MycNip05Document, MycNip05DocumentSection, MycNip89HandlerDocument,
    MycNormalizedNip89Handler, MycPublishedNip89Output, MycRefreshedNip89Output,
    MycRenderedNip05Output, MycRenderedNip89Output, diff_live_nip89, fetch_live_nip89,
    publish_nip89_event, refresh_nip89, render_nip05_output, verify_bundle,
};
pub use error::MycError;
pub use transport::{MycNostrTransport, MycTransportSnapshot};

pub async fn run() -> Result<(), MycError> {
    let config = MycConfig::load_from_default_path_if_exists()?;
    logging::init_logging(&config.logging)?;
    MycApp::bootstrap(config)?.run().await
}

pub async fn run_cli() -> Result<(), MycError> {
    cli::run_from_env().await
}
