//! Myc-owned relay client and explicit aliases at the final Nostr boundary.

use std::time::Duration;

pub use nostr::{PublicKey as RadrootsNostrPublicKey, RelayUrl as RadrootsNostrRelayUrl};
pub use nostr_sdk::prelude::Output as RadrootsNostrOutput;
pub use nostr_sdk::{
    RelayPoolNotification as RadrootsNostrRelayPoolNotification,
    RelayStatus as RadrootsNostrRelayStatus,
};
pub use radroots_nostr::Error as RadrootsNostrError;
pub use radroots_nostr::event::{
    ApplicationHandlerSpec as RadrootsNostrApplicationHandlerSpec, Event as RadrootsNostrEvent,
    EventId as RadrootsNostrEventId, ExternalSigningRequest as RadrootsNostrExternalSigningRequest,
    GenericBuilder as RadrootsNostrGenericEventBuilder, Kind as RadrootsNostrKind,
    Metadata as RadrootsNostrMetadata, Timestamp as RadrootsNostrTimestamp,
    build_application_handler as radroots_nostr_build_application_handler_event,
    metadata_has_fields as radroots_nostr_metadata_has_fields,
};
pub use radroots_nostr::filter::Filter as RadrootsNostrFilter;
pub use radroots_nostr::tag::{Tag as RadrootsNostrTag, TagKind as RadrootsNostrTagKind};

pub fn radroots_nostr_filter_tag(
    filter: RadrootsNostrFilter,
    tag: &str,
    values: Vec<String>,
) -> Result<RadrootsNostrFilter, RadrootsNostrError> {
    radroots_nostr::filter::with_tag(filter, tag, values)
}

pub fn radroots_nostr_tag_first_value(tag: &RadrootsNostrTag, key: &str) -> Option<String> {
    radroots_nostr::tag::first_value(tag, key)
}

pub fn radroots_nostr_kind(kind: u16) -> RadrootsNostrKind {
    radroots_nostr::filter::kind(kind)
}

#[derive(Clone)]
pub struct RadrootsNostrClient {
    inner: nostr_sdk::Client,
}

impl RadrootsNostrClient {
    pub fn with_keys(keys: nostr::Keys) -> Self {
        let inner = nostr_sdk::Client::new(keys);
        inner.automatic_authentication(false);
        Self { inner }
    }

    pub fn from_identity(identity: &crate::host_identity::RadrootsIdentity) -> Self {
        Self::with_keys(identity.keys().clone())
    }

    pub fn from_identity_owned(identity: crate::host_identity::RadrootsIdentity) -> Self {
        Self::with_keys(identity.keys().clone())
    }

    pub fn new_signerless() -> Self {
        let inner = nostr_sdk::Client::default();
        inner.automatic_authentication(false);
        Self { inner }
    }

    pub fn into_inner(self) -> nostr_sdk::Client {
        self.inner
    }

    pub async fn connect(&self) {
        self.inner.connect().await;
    }

    pub async fn wait_for_connection(&self, timeout: Duration) {
        self.inner.wait_for_connection(timeout).await;
    }

    pub async fn add_relay(&self, url: &str) -> Result<bool, nostr_sdk::client::Error> {
        self.inner.add_relay(url).await
    }

    pub async fn relays(&self) -> std::collections::HashMap<nostr::RelayUrl, nostr_sdk::Relay> {
        self.inner.relays().await
    }

    pub async fn has_signer(&self) -> bool {
        self.inner.has_signer().await
    }

    pub async fn fetch_events(
        &self,
        filter: RadrootsNostrFilter,
        timeout: Duration,
    ) -> Result<Vec<RadrootsNostrEvent>, nostr_sdk::client::Error> {
        self.inner
            .fetch_events(filter, timeout)
            .await
            .map(|events| events.to_vec())
    }

    pub async fn subscribe(
        &self,
        filter: RadrootsNostrFilter,
        options: Option<nostr_sdk::SubscribeAutoCloseOptions>,
    ) -> Result<RadrootsNostrOutput<nostr::SubscriptionId>, nostr_sdk::client::Error> {
        self.inner.subscribe(filter, options).await
    }

    pub async fn send_event(
        &self,
        event: &RadrootsNostrEvent,
    ) -> Result<RadrootsNostrOutput<RadrootsNostrEventId>, nostr_sdk::client::Error> {
        self.inner.send_event(event).await
    }
}
