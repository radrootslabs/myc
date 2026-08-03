use crate::config::MycLoggingConfig;
use crate::error::MycError;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    std::sync::OnceLock::new();

pub fn init_logging(config: &MycLoggingConfig) -> Result<(), MycError> {
    let filter =
        EnvFilter::try_new(config.filter.clone()).map_err(|source| MycError::InvalidLogFilter {
            filter: config.filter.clone(),
            source,
        })?;
    let registry = tracing_subscriber::registry().with(filter);

    match config.output_dir.as_deref() {
        Some(directory) => {
            std::fs::create_dir_all(directory).map_err(|source| MycError::CreateDir {
                path: directory.to_path_buf(),
                source,
            })?;
            let appender = tracing_appender::rolling::never(directory, "myc.log");
            let (file_writer, guard) = tracing_appender::non_blocking(appender);
            if config.stdout {
                registry
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(std::io::stdout.and(file_writer)),
                    )
                    .try_init()
                    .map_err(|_| MycError::LoggingAlreadyInitialized)?;
            } else {
                registry
                    .with(tracing_subscriber::fmt::layer().with_writer(file_writer))
                    .try_init()
                    .map_err(|_| MycError::LoggingAlreadyInitialized)?;
            }
            LOG_GUARD
                .set(guard)
                .map_err(|_| MycError::LoggingAlreadyInitialized)?;
        }
        None if config.stdout => {
            registry
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                .try_init()
                .map_err(|_| MycError::LoggingAlreadyInitialized)?;
        }
        None => {
            return Err(MycError::InvalidOperation(
                "logging requires stdout or an output directory".to_owned(),
            ));
        }
    }

    tracing::info!("logging initialized");
    Ok(())
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
    fn stable_log_path_is_host_owned() {
        let directory = PathBuf::from("/tmp/myc-logs");
        assert_eq!(
            directory.join("myc.log"),
            PathBuf::from("/tmp/myc-logs/myc.log")
        );
    }
}
