use radroots_log::{LogFileLayout, LoggingOptions};
use crate::config::MycLoggingConfig;
use crate::error::MycError;

pub fn init_logging(config: &MycLoggingConfig) -> Result<(), MycError> {
    radroots_log::init_logging(LoggingOptions {
        dir: config.output_dir.clone(),
        file_name: "log".to_owned(),
        stdout: config.stdout,
        default_level: Some(config.filter.clone()),
        file_layout: LogFileLayout::DatedFileName,
    })
    .map_err(|source| MycError::InvalidOperation(format!("failed to initialize logging: {source}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::MycConfig;

    #[test]
    fn config_parses_logging_output_dir_and_stdout() {
        let config = MycConfig::from_env_str(
            r#"
MYC_LOGGING_FILTER=info,myc=debug
MYC_LOGGING_OUTPUT_DIR=/tmp/myc-logs
MYC_LOGGING_STDOUT=false
MYC_PATHS_STATE_DIR=/tmp/myc
MYC_PATHS_SIGNER_IDENTITY_PATH=/tmp/signer.json
MYC_PATHS_USER_IDENTITY_PATH=/tmp/user.json
MYC_DISCOVERY_ENABLED=false
MYC_TRANSPORT_ENABLED=false
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=10
            "#,
        )
        .expect("config");

        assert_eq!(config.logging.output_dir, Some(PathBuf::from("/tmp/myc-logs")));
        assert!(!config.logging.stdout);
    }
}
