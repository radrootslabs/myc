use crate::config::MycLoggingConfig;
use crate::error::MycError;
use radroots_log::{LogFileLayout, LoggingOptions};

pub fn init_logging(config: &MycLoggingConfig) -> Result<(), MycError> {
    radroots_log::init_logging(LoggingOptions {
        dir: config.output_dir.clone(),
        file_name: "myc.log".to_owned(),
        stdout: config.stdout,
        default_level: Some(config.filter.clone()),
        file_layout: LogFileLayout::StableFileName,
        ..LoggingOptions::default()
    })
    .map_err(|source| MycError::InvalidOperation(format!("failed to initialize logging: {source}")))
}

#[cfg(test)]
mod tests {
    use radroots_log::{LogFileLayout, LoggingOptions};
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
MYC_IDENTITY_SIGNER_PATH=/tmp/signer.json
MYC_IDENTITY_USER_PATH=/tmp/user.json
MYC_DISCOVERY_ENABLED=false
MYC_TRANSPORT_ENABLED=false
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=10
            "#,
        )
        .expect("config");

        assert_eq!(
            config.logging.output_dir,
            Some(PathBuf::from("/tmp/myc-logs"))
        );
        assert!(!config.logging.stdout);
    }

    #[test]
    fn logging_options_resolve_bounded_stable_file_path() {
        let config = MycConfig::from_env_str(
            r#"
MYC_LOGGING_FILTER=info,myc=debug
MYC_LOGGING_OUTPUT_DIR=/tmp/myc-logs
MYC_LOGGING_STDOUT=false
MYC_PATHS_STATE_DIR=/tmp/myc
MYC_IDENTITY_SIGNER_PATH=/tmp/signer.json
MYC_IDENTITY_USER_PATH=/tmp/user.json
MYC_DISCOVERY_ENABLED=false
MYC_TRANSPORT_ENABLED=false
MYC_TRANSPORT_CONNECT_TIMEOUT_SECS=10
            "#,
        )
        .expect("config");

        let path = LoggingOptions {
            dir: config.logging.output_dir.clone(),
            file_name: "myc.log".to_owned(),
            stdout: config.logging.stdout,
            default_level: Some(config.logging.filter.clone()),
            file_layout: LogFileLayout::StableFileName,
            ..LoggingOptions::default()
        }
        .resolved_current_log_file_path()
        .expect("resolved log path");

        assert_eq!(
            path.parent(),
            Some(PathBuf::from("/tmp/myc-logs").as_path())
        );
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("myc.log")
        );
    }
}
