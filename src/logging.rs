use tracing_subscriber::EnvFilter;

use crate::config::MycLoggingConfig;
use crate::error::MycError;

pub fn build_env_filter(filter: &str) -> Result<EnvFilter, MycError> {
    EnvFilter::try_new(filter).map_err(|source| MycError::InvalidLogFilter {
        filter: filter.to_owned(),
        source,
    })
}

pub fn init_logging(config: &MycLoggingConfig) -> Result<(), MycError> {
    let filter = build_env_filter(&config.filter)?;
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| MycError::LoggingAlreadyInitialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_env_filter_accepts_valid_filter() {
        assert!(build_env_filter("info,myc=debug").is_ok());
    }

    #[test]
    fn build_env_filter_rejects_invalid_filter() {
        let err = build_env_filter("info,myc=[").expect_err("invalid filter");
        assert!(err.to_string().contains("invalid log filter"));
    }
}
