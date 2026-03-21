#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod error;
pub mod logging;

pub use app::{MycApp, MycRuntime, MycRuntimePaths, MycStartupSnapshot};
pub use config::{
    DEFAULT_CONFIG_PATH, MycConfig, MycLoggingConfig, MycPathsConfig, MycServiceConfig,
};
pub use error::MycError;

pub fn run() -> Result<(), MycError> {
    let config = MycConfig::load_from_default_path_if_exists()?;
    logging::init_logging(&config.logging)?;
    MycApp::bootstrap(config)?.run()
}
