#![forbid(unsafe_code)]

pub mod app;
pub mod audit;
pub mod cli;
pub mod config;
pub mod control;
pub mod error;
pub mod logging;
pub mod transport;

pub use app::{MycApp, MycRuntime, MycRuntimePaths, MycSignerContext, MycStartupSnapshot};
pub use audit::{
    MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
    MycOperationAuditStore,
};
pub use config::{
    DEFAULT_CONFIG_PATH, MycConfig, MycConnectionApproval, MycLoggingConfig, MycPathsConfig,
    MycPolicyConfig, MycServiceConfig, MycTransportConfig,
};
pub use control::{MycAcceptedConnectionOutput, MycAuthorizedReplayOutput};
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
