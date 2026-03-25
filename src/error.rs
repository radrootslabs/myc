use std::path::PathBuf;

use radroots_identity::IdentityError;
use radroots_nostr::prelude::RadrootsNostrError;
use radroots_nostr_connect::prelude::RadrootsNostrConnectError;
use radroots_nostr_signer::prelude::RadrootsNostrSignerError;
use thiserror::Error;

use crate::config::MycTransportDeliveryPolicy;

#[derive(Debug, Error)]
pub enum MycError {
    #[error("config io error at {path}: {source}")]
    ConfigIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config parse error at {path}:{line_number}: {message}")]
    ConfigParse {
        path: PathBuf,
        line_number: usize,
        message: String,
    },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
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
    #[error("audit io error at {path}: {source}")]
    AuditIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit parse error at {path}:{line_number}: {source}")]
    AuditParse {
        path: PathBuf,
        line_number: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize audit record at {path}: {source}")]
    AuditSerialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("discovery io error at {path}: {source}")]
    DiscoveryIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("discovery parse error at {path}: {source}")]
    DiscoveryParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid discovery bundle: {0}")]
    InvalidDiscoveryBundle(String),
    #[error("invalid discovery event: {0}")]
    InvalidDiscoveryEvent(String),
    #[error(
        "failed to fetch discovery state from all configured relays ({relay_count}): {details}"
    )]
    DiscoveryFetchUnavailable { relay_count: usize, details: String },
    #[error("discovery refresh attempt {attempt_id} failed: {source}")]
    DiscoveryRefreshFailed {
        attempt_id: String,
        #[source]
        source: Box<MycError>,
    },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Nostr(#[from] RadrootsNostrError),
    #[error(transparent)]
    NostrConnect(#[from] RadrootsNostrConnectError),
    #[error(transparent)]
    SignerState(#[from] RadrootsNostrSignerError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("NIP-46 decrypt failed: {0}")]
    Nip46Decrypt(String),
    #[error("NIP-46 encrypt failed: {0}")]
    Nip46Encrypt(String),
    #[error("NIP-46 listener notifications closed")]
    Nip46ListenerClosed,
    #[error(
        "Nostr publish failed for {operation} after {attempt_count} attempt(s) with delivery policy {} requiring {required_acknowledged_relay_count} acknowledgements: {details}",
        delivery_policy.as_str()
    )]
    PublishRejected {
        operation: String,
        relay_count: usize,
        acknowledged_relay_count: usize,
        required_acknowledged_relay_count: usize,
        delivery_policy: MycTransportDeliveryPolicy,
        attempt_count: usize,
        details: String,
        rejected_relays: Vec<String>,
    },
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

impl MycError {
    pub fn with_discovery_refresh_attempt_id(self, attempt_id: impl Into<String>) -> Self {
        match self {
            Self::DiscoveryRefreshFailed { .. } => self,
            source => Self::DiscoveryRefreshFailed {
                attempt_id: attempt_id.into(),
                source: Box::new(source),
            },
        }
    }

    pub fn discovery_refresh_attempt_id(&self) -> Option<&str> {
        match self {
            Self::DiscoveryRefreshFailed { attempt_id, .. } => Some(attempt_id.as_str()),
            _ => None,
        }
    }

    pub fn publish_rejection_details(&self) -> Option<&str> {
        match self {
            Self::PublishRejected { details, .. } => Some(details.as_str()),
            Self::DiscoveryRefreshFailed { source, .. } => source.publish_rejection_details(),
            _ => None,
        }
    }

    pub fn publish_rejection_counts(&self) -> Option<(usize, usize)> {
        match self {
            Self::PublishRejected {
                relay_count,
                acknowledged_relay_count,
                ..
            } => Some((*relay_count, *acknowledged_relay_count)),
            Self::DiscoveryRefreshFailed { source, .. } => source.publish_rejection_counts(),
            _ => None,
        }
    }

    pub fn publish_rejected_relays(&self) -> Option<&[String]> {
        match self {
            Self::PublishRejected {
                rejected_relays, ..
            } => Some(rejected_relays.as_slice()),
            Self::DiscoveryRefreshFailed { source, .. } => source.publish_rejected_relays(),
            _ => None,
        }
    }

    pub fn publish_delivery_policy(&self) -> Option<MycTransportDeliveryPolicy> {
        match self {
            Self::PublishRejected {
                delivery_policy, ..
            } => Some(*delivery_policy),
            Self::DiscoveryRefreshFailed { source, .. } => source.publish_delivery_policy(),
            _ => None,
        }
    }

    pub fn publish_attempt_count(&self) -> Option<usize> {
        match self {
            Self::PublishRejected { attempt_count, .. } => Some(*attempt_count),
            Self::DiscoveryRefreshFailed { source, .. } => source.publish_attempt_count(),
            _ => None,
        }
    }

    pub fn publish_required_acknowledged_relay_count(&self) -> Option<usize> {
        match self {
            Self::PublishRejected {
                required_acknowledged_relay_count,
                ..
            } => Some(*required_acknowledged_relay_count),
            Self::DiscoveryRefreshFailed { source, .. } => {
                source.publish_required_acknowledged_relay_count()
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::MycTransportDeliveryPolicy;

    use super::MycError;

    #[test]
    fn discovery_refresh_wrapper_preserves_attempt_id_and_publish_details() {
        let wrapped = MycError::PublishRejected {
            operation: "discovery refresh".to_owned(),
            relay_count: 2,
            acknowledged_relay_count: 0,
            required_acknowledged_relay_count: 1,
            delivery_policy: MycTransportDeliveryPolicy::Any,
            attempt_count: 2,
            details: "relay-a: blocked".to_owned(),
            rejected_relays: vec!["wss://relay-a.example.com".to_owned()],
        }
        .with_discovery_refresh_attempt_id("attempt-1");

        assert_eq!(wrapped.discovery_refresh_attempt_id(), Some("attempt-1"));
        assert_eq!(
            wrapped.publish_rejection_details(),
            Some("relay-a: blocked")
        );
        assert_eq!(wrapped.publish_rejection_counts(), Some((2, 0)));
        assert_eq!(
            wrapped.publish_rejected_relays(),
            Some(["wss://relay-a.example.com".to_owned()].as_slice())
        );
        assert_eq!(
            wrapped.publish_delivery_policy(),
            Some(MycTransportDeliveryPolicy::Any)
        );
        assert_eq!(wrapped.publish_required_acknowledged_relay_count(), Some(1));
        assert_eq!(wrapped.publish_attempt_count(), Some(2));
    }
}
