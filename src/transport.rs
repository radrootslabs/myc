pub mod nip46;

use std::time::Duration;

use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEventBuilder, RadrootsNostrOutput, RadrootsNostrRelayUrl,
};

use crate::config::MycTransportConfig;
use crate::error::MycError;

pub use nip46::{MycNip46Handler, MycNip46Service};

#[derive(Clone)]
pub struct MycNostrTransport {
    client: RadrootsNostrClient,
    relays: Vec<RadrootsNostrRelayUrl>,
    connect_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycTransportSnapshot {
    pub enabled: bool,
    pub relay_count: usize,
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycPublishOutcome {
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub relay_outcome_summary: String,
}

impl MycNostrTransport {
    pub fn bootstrap(
        config: &MycTransportConfig,
        signer_identity: &RadrootsIdentity,
    ) -> Result<Option<Self>, MycError> {
        if !config.enabled {
            return Ok(None);
        }

        Ok(Some(Self {
            client: RadrootsNostrClient::from_identity(signer_identity),
            relays: config.parse_relays()?,
            connect_timeout_secs: config.connect_timeout_secs,
        }))
    }

    pub fn client(&self) -> &RadrootsNostrClient {
        &self.client
    }

    pub fn relays(&self) -> &[RadrootsNostrRelayUrl] {
        self.relays.as_slice()
    }

    pub fn connect_timeout_secs(&self) -> u64 {
        self.connect_timeout_secs
    }

    pub async fn connect(&self) -> Result<(), MycError> {
        for relay in &self.relays {
            let _ = self.client.add_relay(relay.as_str()).await?;
        }
        self.client.connect().await;
        self.client
            .wait_for_connection(Duration::from_secs(self.connect_timeout_secs))
            .await;
        Ok(())
    }

    pub async fn publish_once(
        signer_identity: &RadrootsIdentity,
        relays: &[RadrootsNostrRelayUrl],
        connect_timeout_secs: u64,
        event: RadrootsNostrEventBuilder,
    ) -> Result<MycPublishOutcome, MycError> {
        if relays.is_empty() {
            return Err(MycError::InvalidOperation(
                "cannot publish without at least one relay".to_owned(),
            ));
        }

        let client = RadrootsNostrClient::from_identity(signer_identity);
        for relay in relays {
            let _ = client.add_relay(relay.as_str()).await?;
        }
        client.connect().await;
        client
            .wait_for_connection(Duration::from_secs(connect_timeout_secs))
            .await;
        let output = client.send_event_builder(event).await?;
        ensure_publish_confirmed(output, "one-shot Nostr publish")
    }

    pub fn snapshot(&self) -> MycTransportSnapshot {
        MycTransportSnapshot {
            enabled: true,
            relay_count: self.relays.len(),
            connect_timeout_secs: self.connect_timeout_secs,
        }
    }
}

pub(crate) fn ensure_publish_confirmed<T>(
    output: RadrootsNostrOutput<T>,
    operation: &str,
) -> Result<MycPublishOutcome, MycError>
where
    T: std::fmt::Debug,
{
    let relay_count = output.success.len() + output.failed.len();
    let acknowledged_relay_count = output.success.len();
    let relay_outcome_summary = summarize_publish_output(&output);

    if !output.success.is_empty() {
        return Ok(MycPublishOutcome {
            relay_count,
            acknowledged_relay_count,
            relay_outcome_summary,
        });
    }

    Err(MycError::PublishRejected {
        operation: operation.to_owned(),
        relay_count,
        acknowledged_relay_count,
        details: relay_outcome_summary,
    })
}

fn summarize_publish_output<T>(output: &RadrootsNostrOutput<T>) -> String
where
    T: std::fmt::Debug,
{
    let relay_count = output.success.len() + output.failed.len();
    let acknowledged_relay_count = output.success.len();
    if relay_count == 0 {
        return "no relay acknowledged the publish".to_owned();
    }

    let mut summary =
        format!("{acknowledged_relay_count}/{relay_count} relays acknowledged publish");
    if !output.failed.is_empty() {
        let failures = output
            .failed
            .iter()
            .map(|(relay, error)| format!("{relay}: {error}"))
            .collect::<Vec<_>>()
            .join("; ");
        summary.push_str("; failures: ");
        summary.push_str(&failures);
    }
    summary
}

impl MycTransportSnapshot {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            relay_count: 0,
            connect_timeout_secs: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use radroots_identity::RadrootsIdentity;

    use crate::config::MycTransportConfig;

    use super::{MycNostrTransport, MycTransportSnapshot};

    fn signer_identity() -> RadrootsIdentity {
        RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity")
    }

    #[test]
    fn bootstrap_returns_none_when_transport_disabled() {
        let config = MycTransportConfig::default();

        let transport =
            MycNostrTransport::bootstrap(&config, &signer_identity()).expect("disabled transport");

        assert!(transport.is_none());
    }

    #[test]
    fn bootstrap_builds_transport_snapshot_when_enabled() {
        let mut config = MycTransportConfig::default();
        config.enabled = true;
        config.connect_timeout_secs = 15;
        config.relays = vec![
            "wss://relay.example.com".to_owned(),
            "wss://relay2.example.com".to_owned(),
        ];

        let transport = MycNostrTransport::bootstrap(&config, &signer_identity())
            .expect("transport")
            .expect("enabled transport");

        assert_eq!(transport.relays().len(), 2);
        assert_eq!(transport.connect_timeout_secs(), 15);
        assert_eq!(
            transport.snapshot(),
            MycTransportSnapshot {
                enabled: true,
                relay_count: 2,
                connect_timeout_secs: 15,
            }
        );
    }
}
