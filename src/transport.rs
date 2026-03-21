use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{RadrootsNostrClient, RadrootsNostrRelayUrl};

use crate::config::MycTransportConfig;
use crate::error::MycError;

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

    pub fn snapshot(&self) -> MycTransportSnapshot {
        MycTransportSnapshot {
            enabled: true,
            relay_count: self.relays.len(),
            connect_timeout_secs: self.connect_timeout_secs,
        }
    }
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
