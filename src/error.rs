use std::path::PathBuf;

use radroots_identity::IdentityError;
use radroots_nostr_signer::prelude::RadrootsNostrSignerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MycError {
    #[error("config io error at {path}: {source}")]
    ConfigIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config parse error at {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid log filter `{filter}`: {source}")]
    InvalidLogFilter {
        filter: String,
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },
    #[error("logging already initialized")]
    LoggingAlreadyInitialized,
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    SignerState(#[from] RadrootsNostrSignerError),
    #[error(
        "configured signer identity `{configured_identity_id}` at {identity_path} does not match persisted signer identity `{persisted_identity_id}` in {state_path}"
    )]
    SignerIdentityMismatch {
        identity_path: PathBuf,
        state_path: PathBuf,
        configured_identity_id: String,
        persisted_identity_id: String,
    },
}
