pub mod nip46;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrOutput,
    RadrootsNostrRelayUrl,
};
use serde::Serialize;
use tokio::time::sleep;

use crate::config::{MycTransportConfig, MycTransportDeliveryPolicy};
use crate::error::MycError;

pub use nip46::{MycNip46Handler, MycNip46Service};

#[derive(Clone)]
pub struct MycNostrTransport {
    client: RadrootsNostrClient,
    relays: Vec<RadrootsNostrRelayUrl>,
    connect_timeout_secs: u64,
    delivery_policy: MycTransportDeliveryPolicy,
    delivery_quorum: Option<usize>,
    publish_max_attempts: usize,
    publish_initial_backoff_millis: u64,
    publish_max_backoff_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycTransportSnapshot {
    pub enabled: bool,
    pub relay_count: usize,
    pub connect_timeout_secs: u64,
    pub delivery_policy: MycTransportDeliveryPolicy,
    pub delivery_quorum: Option<usize>,
    pub publish_max_attempts: usize,
    pub publish_initial_backoff_millis: u64,
    pub publish_max_backoff_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MycPublishOutcome {
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub required_acknowledged_relay_count: usize,
    pub delivery_policy: MycTransportDeliveryPolicy,
    pub attempt_count: usize,
    pub relay_outcome_summary: String,
    pub relay_results: Vec<MycRelayPublishResult>,
    pub attempt_summaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRelayPublishResult {
    pub relay_url: String,
    pub acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycPublishSettings {
    delivery_policy: MycTransportDeliveryPolicy,
    delivery_quorum: Option<usize>,
    publish_max_attempts: usize,
    publish_initial_backoff_millis: u64,
    publish_max_backoff_millis: u64,
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
            delivery_policy: config.delivery_policy,
            delivery_quorum: config.delivery_quorum,
            publish_max_attempts: config.publish_max_attempts,
            publish_initial_backoff_millis: config.publish_initial_backoff_millis,
            publish_max_backoff_millis: config.publish_max_backoff_millis,
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

    pub fn delivery_policy(&self) -> MycTransportDeliveryPolicy {
        self.delivery_policy
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
        config: &MycTransportConfig,
        operation: &str,
        event: RadrootsNostrEventBuilder,
    ) -> Result<MycPublishOutcome, MycError> {
        if relays.is_empty() {
            return Err(MycError::InvalidOperation(
                "cannot publish without at least one relay".to_owned(),
            ));
        }

        let event = event
            .sign_with_keys(signer_identity.keys())
            .map_err(|error| {
                MycError::InvalidOperation(format!("failed to sign publish event: {error}"))
            })?;
        Self::publish_event_once(signer_identity, relays, config, operation, &event).await
    }

    pub async fn publish_event_once(
        signer_identity: &RadrootsIdentity,
        relays: &[RadrootsNostrRelayUrl],
        config: &MycTransportConfig,
        operation: &str,
        event: &RadrootsNostrEvent,
    ) -> Result<MycPublishOutcome, MycError> {
        if relays.is_empty() {
            return Err(MycError::InvalidOperation(
                "cannot publish without at least one relay".to_owned(),
            ));
        }

        let settings = MycPublishSettings::from_config(config);
        publish_with_policy(relays, &settings, operation, || async {
            let client = RadrootsNostrClient::from_identity(signer_identity);
            for relay in relays {
                client
                    .add_relay(relay.as_str())
                    .await
                    .map_err(|error| error.to_string())?;
            }
            client.connect().await;
            client
                .wait_for_connection(Duration::from_secs(config.connect_timeout_secs))
                .await;
            client
                .send_event(event)
                .await
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn publish_event(
        &self,
        operation: &str,
        event: &RadrootsNostrEvent,
    ) -> Result<MycPublishOutcome, MycError> {
        publish_with_policy(
            self.relays(),
            &self.publish_settings(),
            operation,
            || async {
                self.client
                    .send_event(event)
                    .await
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub fn snapshot(&self) -> MycTransportSnapshot {
        MycTransportSnapshot {
            enabled: true,
            relay_count: self.relays.len(),
            connect_timeout_secs: self.connect_timeout_secs,
            delivery_policy: self.delivery_policy,
            delivery_quorum: self.delivery_quorum,
            publish_max_attempts: self.publish_max_attempts,
            publish_initial_backoff_millis: self.publish_initial_backoff_millis,
            publish_max_backoff_millis: self.publish_max_backoff_millis,
        }
    }

    fn publish_settings(&self) -> MycPublishSettings {
        MycPublishSettings {
            delivery_policy: self.delivery_policy,
            delivery_quorum: self.delivery_quorum,
            publish_max_attempts: self.publish_max_attempts,
            publish_initial_backoff_millis: self.publish_initial_backoff_millis,
            publish_max_backoff_millis: self.publish_max_backoff_millis,
        }
    }
}

async fn publish_with_policy<T, F, Fut>(
    relays: &[RadrootsNostrRelayUrl],
    settings: &MycPublishSettings,
    operation: &str,
    mut send_attempt: F,
) -> Result<MycPublishOutcome, MycError>
where
    T: std::fmt::Debug,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<RadrootsNostrOutput<T>, String>>,
{
    let relay_count = relays.len();
    let required_acknowledged_relay_count =
        settings.required_acknowledged_relay_count(relay_count)?;
    let mut attempt_results = Vec::new();

    for attempt_number in 1..=settings.publish_max_attempts {
        let attempt = match send_attempt().await {
            Ok(output) => build_publish_attempt_result(relays, attempt_number, &output),
            Err(error) => build_failed_publish_attempt_result(relays, attempt_number, error),
        };
        let threshold_reached =
            attempt.acknowledged_relay_count >= required_acknowledged_relay_count;
        attempt_results.push(attempt);

        if threshold_reached {
            let final_attempt = attempt_results
                .last()
                .expect("publish attempt results contain the successful attempt");
            return Ok(MycPublishOutcome {
                relay_count,
                acknowledged_relay_count: final_attempt.acknowledged_relay_count,
                required_acknowledged_relay_count,
                delivery_policy: settings.delivery_policy,
                attempt_count: attempt_results.len(),
                relay_outcome_summary: summarize_delivery_policy_result(
                    settings.delivery_policy,
                    required_acknowledged_relay_count,
                    &attempt_results,
                ),
                relay_results: final_attempt.relay_results.clone(),
                attempt_summaries: attempt_results
                    .iter()
                    .map(|attempt| attempt.relay_outcome_summary.clone())
                    .collect(),
            });
        }

        if attempt_number < settings.publish_max_attempts {
            sleep(Duration::from_millis(
                settings.backoff_for_attempt(attempt_number),
            ))
            .await;
        }
    }

    let final_attempt = attempt_results
        .last()
        .expect("publish attempt results contain at least one attempt");
    Err(MycError::PublishRejected {
        operation: operation.to_owned(),
        relay_count,
        acknowledged_relay_count: final_attempt.acknowledged_relay_count,
        required_acknowledged_relay_count,
        delivery_policy: settings.delivery_policy,
        attempt_count: attempt_results.len(),
        details: summarize_delivery_policy_result(
            settings.delivery_policy,
            required_acknowledged_relay_count,
            &attempt_results,
        ),
        rejected_relays: final_attempt
            .relay_results
            .iter()
            .filter(|result| !result.acknowledged)
            .map(|result| result.relay_url.clone())
            .collect(),
    })
}

fn build_publish_relay_results<T>(
    relays: &[RadrootsNostrRelayUrl],
    output: &RadrootsNostrOutput<T>,
) -> Vec<MycRelayPublishResult>
where
    T: std::fmt::Debug,
{
    let acknowledged_relays = output
        .success
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let failed_relays = output
        .failed
        .iter()
        .map(|(relay, error)| (relay.to_string(), error.to_string()))
        .collect::<BTreeMap<_, _>>();

    relays
        .iter()
        .map(|relay| {
            let relay_url = relay.to_string();
            if acknowledged_relays.contains(&relay_url) {
                MycRelayPublishResult {
                    relay_url,
                    acknowledged: true,
                    detail: None,
                }
            } else {
                MycRelayPublishResult {
                    relay_url: relay_url.clone(),
                    acknowledged: false,
                    detail: Some(
                        failed_relays
                            .get(&relay_url)
                            .cloned()
                            .unwrap_or_else(|| "no relay acknowledgement reported".to_owned()),
                    ),
                }
            }
        })
        .collect()
}

fn build_publish_attempt_result<T>(
    relays: &[RadrootsNostrRelayUrl],
    attempt_number: usize,
    output: &RadrootsNostrOutput<T>,
) -> MycPublishAttemptResult
where
    T: std::fmt::Debug,
{
    let relay_results = build_publish_relay_results(relays, output);
    let acknowledged_relay_count = relay_results
        .iter()
        .filter(|result| result.acknowledged)
        .count();
    MycPublishAttemptResult {
        attempt_number,
        acknowledged_relay_count,
        relay_outcome_summary: summarize_publish_results(&relay_results),
        relay_results,
    }
}

fn build_failed_publish_attempt_result(
    relays: &[RadrootsNostrRelayUrl],
    attempt_number: usize,
    error: String,
) -> MycPublishAttemptResult {
    let relay_results = relays
        .iter()
        .map(|relay| MycRelayPublishResult {
            relay_url: relay.to_string(),
            acknowledged: false,
            detail: Some(error.clone()),
        })
        .collect::<Vec<_>>();
    MycPublishAttemptResult {
        attempt_number,
        acknowledged_relay_count: 0,
        relay_outcome_summary: summarize_publish_results(&relay_results),
        relay_results,
    }
}

fn summarize_publish_results(relay_results: &[MycRelayPublishResult]) -> String {
    let relay_count = relay_results.len();
    let acknowledged_relay_count = relay_results
        .iter()
        .filter(|result| result.acknowledged)
        .count();
    if relay_count == 0 {
        return "no relay acknowledged the publish".to_owned();
    }

    let mut summary =
        format!("{acknowledged_relay_count}/{relay_count} relays acknowledged publish");
    let acknowledged = relay_results
        .iter()
        .filter(|result| result.acknowledged)
        .map(|result| result.relay_url.clone())
        .collect::<Vec<_>>();
    if !acknowledged.is_empty() {
        summary.push_str("; acknowledged: ");
        summary.push_str(&acknowledged.join(", "));
    }
    let failures = relay_results
        .iter()
        .filter(|result| !result.acknowledged)
        .map(|result| match result.detail.as_deref() {
            Some(detail) => format!("{}: {detail}", result.relay_url),
            None => result.relay_url.clone(),
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        summary.push_str("; failures: ");
        summary.push_str(&failures.join("; "));
    }
    summary
}

fn summarize_delivery_policy_result(
    delivery_policy: MycTransportDeliveryPolicy,
    required_acknowledged_relay_count: usize,
    attempt_results: &[MycPublishAttemptResult],
) -> String {
    let attempt_count = attempt_results.len();
    let final_attempt = attempt_results
        .last()
        .expect("delivery policy summary requires at least one attempt");
    let mut summary = format!(
        "delivery policy {} required {required_acknowledged_relay_count} acknowledgements across {attempt_count} attempt(s); final attempt {}: {}",
        delivery_policy.as_str(),
        final_attempt.attempt_number,
        final_attempt.relay_outcome_summary,
    );
    if attempt_results.len() > 1 {
        let attempt_summaries = attempt_results
            .iter()
            .map(|attempt| {
                format!(
                    "attempt {}: {}",
                    attempt.attempt_number, attempt.relay_outcome_summary
                )
            })
            .collect::<Vec<_>>();
        summary.push_str("; ");
        summary.push_str(&attempt_summaries.join(" | "));
    }
    summary
}

impl MycTransportSnapshot {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            relay_count: 0,
            connect_timeout_secs: 0,
            delivery_policy: MycTransportDeliveryPolicy::Any,
            delivery_quorum: None,
            publish_max_attempts: 1,
            publish_initial_backoff_millis: 250,
            publish_max_backoff_millis: 2_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycPublishAttemptResult {
    attempt_number: usize,
    acknowledged_relay_count: usize,
    relay_outcome_summary: String,
    relay_results: Vec<MycRelayPublishResult>,
}

impl MycPublishSettings {
    fn from_config(config: &MycTransportConfig) -> Self {
        Self {
            delivery_policy: config.delivery_policy,
            delivery_quorum: config.delivery_quorum,
            publish_max_attempts: config.publish_max_attempts,
            publish_initial_backoff_millis: config.publish_initial_backoff_millis,
            publish_max_backoff_millis: config.publish_max_backoff_millis,
        }
    }

    fn required_acknowledged_relay_count(&self, relay_count: usize) -> Result<usize, MycError> {
        match self.delivery_policy {
            MycTransportDeliveryPolicy::Any => Ok(1),
            MycTransportDeliveryPolicy::All => Ok(relay_count),
            MycTransportDeliveryPolicy::Quorum => {
                let delivery_quorum = self.delivery_quorum.ok_or_else(|| {
                    MycError::InvalidConfig(
                        "transport.delivery_quorum must be set when transport.delivery_policy is `quorum`"
                            .to_owned(),
                    )
                })?;
                if delivery_quorum > relay_count {
                    return Err(MycError::InvalidOperation(format!(
                        "transport.delivery_quorum `{delivery_quorum}` cannot be satisfied by `{relay_count}` target relays"
                    )));
                }
                Ok(delivery_quorum)
            }
        }
    }

    fn backoff_for_attempt(&self, completed_attempt_number: usize) -> u64 {
        let exponent = completed_attempt_number.saturating_sub(1) as u32;
        let scaled = self
            .publish_initial_backoff_millis
            .saturating_mul(2_u64.saturating_pow(exponent));
        scaled.min(self.publish_max_backoff_millis)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr::prelude::{
        RadrootsNostrEventId, RadrootsNostrOutput, RadrootsNostrRelayUrl,
    };
    use tokio::time::Instant;

    use crate::config::{MycTransportConfig, MycTransportDeliveryPolicy};

    use super::{MycNostrTransport, MycPublishSettings, MycTransportSnapshot, publish_with_policy};

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
        config.delivery_policy = MycTransportDeliveryPolicy::Quorum;
        config.delivery_quorum = Some(2);
        config.publish_max_attempts = 3;
        config.publish_initial_backoff_millis = 125;
        config.publish_max_backoff_millis = 500;

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
                delivery_policy: MycTransportDeliveryPolicy::Quorum,
                delivery_quorum: Some(2),
                publish_max_attempts: 3,
                publish_initial_backoff_millis: 125,
                publish_max_backoff_millis: 500,
            }
        );
    }

    #[tokio::test]
    async fn publish_with_policy_retries_until_threshold_is_met() {
        let relays = vec![
            RadrootsNostrRelayUrl::parse("wss://relay-a.example.com").expect("relay-a"),
            RadrootsNostrRelayUrl::parse("wss://relay-b.example.com").expect("relay-b"),
        ];
        let settings = MycPublishSettings {
            delivery_policy: MycTransportDeliveryPolicy::All,
            delivery_quorum: None,
            publish_max_attempts: 2,
            publish_initial_backoff_millis: 10,
            publish_max_backoff_millis: 10,
        };
        let attempts = Arc::new(Mutex::new(vec![
            publish_output(
                "1111111111111111111111111111111111111111111111111111111111111111",
                &["wss://relay-a.example.com"],
                &[("wss://relay-b.example.com", "blocked")],
            ),
            publish_output(
                "2222222222222222222222222222222222222222222222222222222222222222",
                &["wss://relay-a.example.com", "wss://relay-b.example.com"],
                &[],
            ),
        ]));

        let start = Instant::now();
        let outcome = publish_with_policy(&relays, &settings, "test publish", || {
            let attempts = Arc::clone(&attempts);
            async move {
                let output = attempts.lock().expect("attempts lock").remove(0);
                Ok(output)
            }
        })
        .await
        .expect("publish succeeds on retry");

        assert_eq!(outcome.delivery_policy, MycTransportDeliveryPolicy::All);
        assert_eq!(outcome.required_acknowledged_relay_count, 2);
        assert_eq!(outcome.attempt_count, 2);
        assert_eq!(outcome.acknowledged_relay_count, 2);
        assert_eq!(outcome.relay_results.len(), 2);
        assert_eq!(outcome.attempt_summaries.len(), 2);
        assert!(
            outcome
                .relay_outcome_summary
                .contains("delivery policy all")
        );
        assert!(outcome.relay_outcome_summary.contains("attempt 1"));
        assert!(start.elapsed() >= std::time::Duration::from_millis(10));
    }

    #[tokio::test]
    async fn publish_with_policy_reports_threshold_failure() {
        let relays = vec![
            RadrootsNostrRelayUrl::parse("wss://relay-a.example.com").expect("relay-a"),
            RadrootsNostrRelayUrl::parse("wss://relay-b.example.com").expect("relay-b"),
        ];
        let settings = MycPublishSettings {
            delivery_policy: MycTransportDeliveryPolicy::Quorum,
            delivery_quorum: Some(2),
            publish_max_attempts: 2,
            publish_initial_backoff_millis: 1,
            publish_max_backoff_millis: 1,
        };

        let error = publish_with_policy::<RadrootsNostrEventId, _, _>(
            &relays,
            &settings,
            "test publish",
            || async {
                Ok(publish_output(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    &["wss://relay-a.example.com"],
                    &[("wss://relay-b.example.com", "blocked")],
                ))
            },
        )
        .await
        .expect_err("quorum should fail without both acknowledgements");

        assert_eq!(
            error.publish_delivery_policy(),
            Some(MycTransportDeliveryPolicy::Quorum)
        );
        assert_eq!(error.publish_required_acknowledged_relay_count(), Some(2));
        assert_eq!(error.publish_attempt_count(), Some(2));
        assert!(error.to_string().contains("delivery policy quorum"));
    }

    #[test]
    fn publish_settings_reject_impossible_quorum_for_target_relays() {
        let settings = MycPublishSettings {
            delivery_policy: MycTransportDeliveryPolicy::Quorum,
            delivery_quorum: Some(3),
            publish_max_attempts: 1,
            publish_initial_backoff_millis: 10,
            publish_max_backoff_millis: 100,
        };

        let error = settings
            .required_acknowledged_relay_count(2)
            .expect_err("impossible quorum");
        assert!(
            error
                .to_string()
                .contains("cannot be satisfied by `2` target relays")
        );
    }

    fn publish_output(
        event_id_hex: &str,
        succeeded_relays: &[&str],
        failed_relays: &[(&str, &str)],
    ) -> RadrootsNostrOutput<RadrootsNostrEventId> {
        let success = succeeded_relays
            .iter()
            .map(|relay| RadrootsNostrRelayUrl::parse(*relay).expect("success relay"))
            .collect::<HashSet<_>>();
        let failed = failed_relays
            .iter()
            .map(|(relay, error)| {
                (
                    RadrootsNostrRelayUrl::parse(*relay).expect("failed relay"),
                    (*error).to_owned(),
                )
            })
            .collect::<HashMap<_, _>>();

        RadrootsNostrOutput {
            val: RadrootsNostrEventId::parse(event_id_hex).expect("event id"),
            success,
            failed,
        }
    }
}
