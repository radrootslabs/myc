use std::collections::{HashMap, VecDeque};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use myc::control;
use myc::{
    MycConfig, MycConnectionApproval, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
    MycDeliveryOutboxStatus, MycDiscoveryContext, MycDiscoveryLiveStatus,
    MycDiscoveryRelayFetchStatus, MycDiscoveryRepairOutcome, MycOperationAuditKind,
    MycOperationAuditOutcome, MycOperationAuditRecord, MycRuntime, MycRuntimeAuditBackend,
    MycSignerStateBackend, MycTransportDeliveryPolicy, diff_live_nip89, fetch_live_nip89,
    publish_nip89_event, refresh_nip89,
};
use nostr::filter::MatchEventOptions;
use nostr::nips::nip44;
use nostr::nips::nip44::Version;
use nostr::nips::nip46::{
    NostrConnectMessage as ExternalNostrConnectMessage,
    NostrConnectMethod as ExternalNostrConnectMethod,
    NostrConnectRequest as ExternalNostrConnectRequest,
    NostrConnectResponse as ExternalNostrConnectResponse, ResponseResult as ExternalResponseResult,
};
use nostr::{
    ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, PublicKey, RelayMessage,
    SecretKey, SubscriptionId, Tag, Timestamp, UnsignedEvent,
};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrClient, RadrootsNostrMetadata,
    radroots_nostr_build_application_handler_event,
};
use radroots_nostr_connect::prelude::{
    RADROOTS_NOSTR_CONNECT_RPC_KIND, RadrootsNostrConnectClientMetadata,
    RadrootsNostrConnectClientUri, RadrootsNostrConnectRequest, RadrootsNostrConnectRequestMessage,
    RadrootsNostrConnectResponseEnvelope, RadrootsNostrConnectUri,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthState,
    RadrootsNostrSignerConnectionDraft,
};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
struct RelaySubscription {
    connection_id: usize,
    subscription_id: SubscriptionId,
    filters: Vec<Filter>,
}

#[derive(Default)]
struct RelayState {
    next_connection_id: usize,
    senders: HashMap<usize, mpsc::UnboundedSender<Message>>,
    subscriptions: Vec<RelaySubscription>,
    published_events: Vec<Event>,
    publish_outcomes_by_pubkey: HashMap<String, VecDeque<bool>>,
}

struct TestRelay {
    url: String,
    state: Arc<Mutex<RelayState>>,
    notify: Arc<Notify>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestRelay {
    async fn spawn() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let url = format!("ws://{addr}");
        let state = Arc::new(Mutex::new(RelayState::default()));
        let notify = Arc::new(Notify::new());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let relay_state = Arc::clone(&state);
        let relay_notify = Arc::clone(&notify);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        let state = Arc::clone(&relay_state);
                        let notify = Arc::clone(&relay_notify);
                        tokio::spawn(async move {
                            let _ = handle_relay_connection(stream, state, notify).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            url,
            state,
            notify,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> &str {
        self.url.as_str()
    }

    async fn queue_publish_outcomes(&self, public_key: PublicKey, outcomes: &[bool]) {
        let mut state = self.state.lock().await;
        state
            .publish_outcomes_by_pubkey
            .insert(public_key.to_hex(), outcomes.iter().copied().collect());
    }

    async fn wait_for_subscription_count(&self, expected: usize) -> TestResult<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                if self.state.lock().await.subscriptions.len() >= expected {
                    return;
                }
                self.notify.notified().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn wait_for_published_events_by_author(
        &self,
        public_key: PublicKey,
        expected: usize,
    ) -> TestResult<Vec<Event>> {
        timeout(Duration::from_secs(5), async {
            loop {
                let events = self.published_events_by_author(public_key).await;
                if events.len() >= expected {
                    return events;
                }
                self.notify.notified().await;
            }
        })
        .await
        .map_err(Into::into)
    }

    async fn published_events_by_author(&self, public_key: PublicKey) -> Vec<Event> {
        self.state
            .lock()
            .await
            .published_events
            .iter()
            .filter(|event| event.pubkey == public_key)
            .cloned()
            .collect()
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

struct HangingRelay {
    url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl HangingRelay {
    async fn spawn(hold_open_for: Duration) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let url = format!("ws://{addr}");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        tokio::spawn(async move {
                            sleep(hold_open_for).await;
                            drop(stream);
                        });
                    }
                }
            }
        });

        Ok(Self {
            url,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> &str {
        self.url.as_str()
    }
}

impl Drop for HangingRelay {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

async fn handle_relay_connection(
    stream: TcpStream,
    state: Arc<Mutex<RelayState>>,
    notify: Arc<Notify>,
) -> TestResult<()> {
    let websocket = tokio_tungstenite::accept_async(stream).await?;
    let (mut writer, mut reader) = websocket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let connection_id = {
        let mut state = state.lock().await;
        let connection_id = state.next_connection_id;
        state.next_connection_id += 1;
        state.senders.insert(connection_id, tx);
        notify.notify_waiters();
        connection_id
    };

    let writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if writer.send(message).await.is_err() {
                break;
            }
        }
    });

    while let Some(message) = reader.next().await {
        let message = message?;
        let Message::Text(text) = message else {
            continue;
        };
        let client_message = ClientMessage::from_json(text.as_str())?;
        handle_client_message(connection_id, client_message, &state, &notify).await?;
    }

    writer_task.abort();
    let mut state = state.lock().await;
    state.senders.remove(&connection_id);
    state
        .subscriptions
        .retain(|subscription| subscription.connection_id != connection_id);
    notify.notify_waiters();
    Ok(())
}

async fn handle_client_message(
    connection_id: usize,
    client_message: ClientMessage<'_>,
    state: &Arc<Mutex<RelayState>>,
    notify: &Arc<Notify>,
) -> TestResult<()> {
    match client_message {
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            let (sender, matching_events) = {
                let mut state = state.lock().await;
                let matching_events = state
                    .published_events
                    .iter()
                    .filter(|event| {
                        filters
                            .iter()
                            .any(|filter| filter.match_event(event, MatchEventOptions::new()))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                state.subscriptions.push(RelaySubscription {
                    connection_id,
                    subscription_id: subscription_id.as_ref().clone(),
                    filters: filters
                        .into_iter()
                        .map(|filter| filter.into_owned())
                        .collect(),
                });
                notify.notify_waiters();
                (state.senders.get(&connection_id).cloned(), matching_events)
            };
            if let Some(sender) = sender {
                for event in matching_events {
                    let message =
                        RelayMessage::event(subscription_id.as_ref().clone(), event).as_json();
                    let _ = sender.send(Message::Text(message.into()));
                }
                let eose = RelayMessage::eose(subscription_id.as_ref().clone()).as_json();
                let _ = sender.send(Message::Text(eose.into()));
            }
        }
        ClientMessage::Close(subscription_id) => {
            let mut state = state.lock().await;
            state.subscriptions.retain(|subscription| {
                subscription.connection_id != connection_id
                    || subscription.subscription_id != *subscription_id
            });
            notify.notify_waiters();
        }
        ClientMessage::Event(event) => {
            let event = event.into_owned();
            let (ok_message, subscriber_messages) =
                accept_published_event(connection_id, event, state, notify).await?;
            if let Some((sender, message)) = ok_message {
                let _ = sender.send(message);
            }
            for (sender, message) in subscriber_messages {
                let _ = sender.send(message);
            }
        }
        _ => {}
    }

    Ok(())
}

async fn accept_published_event(
    connection_id: usize,
    event: Event,
    state: &Arc<Mutex<RelayState>>,
    notify: &Arc<Notify>,
) -> TestResult<(
    Option<(mpsc::UnboundedSender<Message>, Message)>,
    Vec<(mpsc::UnboundedSender<Message>, Message)>,
)> {
    let event_id = event.id;
    let event_pubkey_hex = event.pubkey.to_hex();
    let mut subscriber_messages = Vec::new();
    let mut ok_message = None;

    {
        let mut state = state.lock().await;
        let publish_status = state
            .publish_outcomes_by_pubkey
            .get_mut(&event_pubkey_hex)
            .and_then(|outcomes| outcomes.pop_front())
            .unwrap_or(true);

        if let Some(sender) = state.senders.get(&connection_id).cloned() {
            let message = if publish_status {
                RelayMessage::ok(event_id, true, "").as_json()
            } else {
                RelayMessage::ok(event_id, false, "blocked by test relay").as_json()
            };
            ok_message = Some((sender, Message::Text(message.into())));
        }

        if publish_status {
            state.published_events.push(event.clone());
            for subscription in &state.subscriptions {
                if subscription
                    .filters
                    .iter()
                    .any(|filter| filter.match_event(&event, MatchEventOptions::new()))
                {
                    if let Some(sender) = state.senders.get(&subscription.connection_id).cloned() {
                        let message = RelayMessage::event(
                            subscription.subscription_id.clone(),
                            event.clone(),
                        )
                        .as_json();
                        subscriber_messages.push((sender, Message::Text(message.into())));
                    }
                }
            }
            notify.notify_waiters();
        }
    }

    Ok((ok_message, subscriber_messages))
}

struct MycTestRuntime {
    _temp: TempDir,
    runtime: MycRuntime,
}

impl MycTestRuntime {
    fn new(relay_url: &str, approval: MycConnectionApproval) -> Self {
        Self::new_with_transport_relays(&[relay_url], approval)
    }

    fn new_with_transport_relays(relay_urls: &[&str], approval: MycConnectionApproval) -> Self {
        Self::new_with_transport_config(relay_urls, approval, |_| {})
    }

    fn new_with_transport_config<F>(
        relay_urls: &[&str],
        approval: MycConnectionApproval,
        configure: F,
    ) -> Self
    where
        F: FnOnce(&mut MycConfig),
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.policy.connection_approval = approval;
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 1;
        config.transport.relays = relay_urls.iter().map(|relay| (*relay).to_owned()).collect();
        configure(&mut config);
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        Self {
            runtime: MycRuntime::bootstrap(config).expect("runtime"),
            _temp: temp,
        }
    }

    fn new_with_discovery(relay_url: &str, approval: MycConnectionApproval) -> Self {
        Self::new_with_discovery_relays(&[relay_url], approval)
    }

    fn new_with_discovery_relays(relay_urls: &[&str], approval: MycConnectionApproval) -> Self {
        Self::new_with_discovery_relays_and_timeout(relay_urls, approval, 1)
    }

    fn new_with_discovery_relays_and_timeout(
        relay_urls: &[&str],
        approval: MycConnectionApproval,
        connect_timeout_secs: u64,
    ) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.policy.connection_approval = approval;
        config.transport.connect_timeout_secs = connect_timeout_secs;
        config.discovery.enabled = true;
        config.discovery.domain = Some("signer.example.com".to_owned());
        config.discovery.public_relays =
            relay_urls.iter().map(|relay| (*relay).to_owned()).collect();
        config.discovery.publish_relays =
            relay_urls.iter().map(|relay| (*relay).to_owned()).collect();
        config.discovery.nostrconnect_url_template =
            Some("https://signer.example.com/connect?uri=<nostrconnect>".to_owned());
        config.discovery.app_identity_path = Some(temp.path().join("app.json"));
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        write_identity(
            config
                .discovery
                .app_identity_path
                .as_ref()
                .expect("app identity path"),
            "6666666666666666666666666666666666666666666666666666666666666666",
        );

        Self {
            runtime: MycRuntime::bootstrap(config).expect("runtime"),
            _temp: temp,
        }
    }
}

fn write_identity(path: &std::path::Path, secret_key: &str) {
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity")
        .save_json(path)
        .expect("save identity");
}

fn identity(secret_key: &str) -> RadrootsIdentity {
    RadrootsIdentity::from_secret_key_str(secret_key).expect("identity")
}

fn unavailable_relay_url() -> TestResult<String> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(format!("ws://{addr}"))
}

async fn publish_handler_event(
    relay_url: &str,
    identity: &RadrootsIdentity,
    spec: &RadrootsNostrApplicationHandlerSpec,
) -> TestResult<Event> {
    let event = radroots_nostr_build_application_handler_event(spec)?
        .sign_with_keys(identity.keys())
        .map_err(|error| format!("failed to sign handler event: {error}"))?;
    let client = RadrootsNostrClient::from_identity(identity);
    let _ = client.add_relay(relay_url).await?;
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(1)).await;
    let output = client.send_event(&event).await?;
    assert!(
        !output.success.is_empty(),
        "handler event publish did not succeed: {:?}",
        output.failed
    );
    Ok(event)
}

async fn publish_signed_event(
    relay_url: &str,
    identity: &RadrootsIdentity,
    event: &Event,
) -> TestResult<()> {
    let client = RadrootsNostrClient::from_identity(identity);
    let _ = client.add_relay(relay_url).await?;
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(1)).await;
    let output = client.send_event(event).await?;
    assert!(
        !output.success.is_empty(),
        "signed event publish did not succeed: {:?}",
        output.failed
    );
    Ok(())
}

fn connect_request_message(
    request_id: &str,
    signer_public_key: PublicKey,
    secret: &str,
) -> RadrootsNostrConnectRequestMessage {
    RadrootsNostrConnectRequestMessage::new(
        request_id,
        RadrootsNostrConnectRequest::Connect {
            remote_signer_public_key: signer_public_key,
            secret: Some(secret.to_owned()),
            requested_permissions: Default::default(),
        },
    )
}

fn ping_request_message(request_id: &str) -> RadrootsNostrConnectRequestMessage {
    RadrootsNostrConnectRequestMessage::new(request_id, RadrootsNostrConnectRequest::Ping)
}

fn build_request_event(
    client_identity: &RadrootsIdentity,
    signer_public_key: PublicKey,
    request_message: RadrootsNostrConnectRequestMessage,
    created_at_unix: u64,
) -> Event {
    let payload = serde_json::to_string(&request_message).expect("request payload");
    let ciphertext = nip44::encrypt(
        client_identity.keys().secret_key(),
        &signer_public_key,
        payload,
        Version::V2,
    )
    .expect("encrypt request");
    EventBuilder::new(Kind::Custom(RADROOTS_NOSTR_CONNECT_RPC_KIND), ciphertext)
        .tags([Tag::public_key(signer_public_key)])
        .custom_created_at(Timestamp::from(created_at_unix))
        .sign_with_keys(client_identity.keys())
        .expect("sign request event")
}

fn build_external_request_message(
    request_id: &str,
    request: &ExternalNostrConnectRequest,
) -> ExternalNostrConnectMessage {
    ExternalNostrConnectMessage::Request {
        id: request_id.to_owned(),
        method: request.method(),
        params: request.params(),
    }
}

fn build_external_request_event(
    client_identity: &RadrootsIdentity,
    signer_public_key: PublicKey,
    request_message: &ExternalNostrConnectMessage,
    created_at_unix: u64,
) -> Event {
    let payload = request_message.as_json();
    let ciphertext = nip44::encrypt(
        client_identity.keys().secret_key(),
        &signer_public_key,
        payload,
        Version::V2,
    )
    .expect("encrypt external request");
    EventBuilder::new(Kind::Custom(RADROOTS_NOSTR_CONNECT_RPC_KIND), ciphertext)
        .tags([Tag::public_key(signer_public_key)])
        .custom_created_at(Timestamp::from(created_at_unix))
        .sign_with_keys(client_identity.keys())
        .expect("sign external request event")
}

fn build_signer_noise_event(signer_identity: &RadrootsIdentity, created_at_unix: u64) -> Event {
    EventBuilder::new(
        Kind::Custom(RADROOTS_NOSTR_CONNECT_RPC_KIND),
        "non-nip44-signer-noise",
    )
    .custom_created_at(Timestamp::from(created_at_unix))
    .sign_with_keys(signer_identity.keys())
    .expect("sign noise event")
}

fn decrypt_response(
    client_identity: &RadrootsIdentity,
    signer_public_key: PublicKey,
    response_event: &Event,
) -> RadrootsNostrConnectResponseEnvelope {
    let plaintext = nip44::decrypt(
        client_identity.keys().secret_key(),
        &signer_public_key,
        &response_event.content,
    )
    .expect("decrypt response");
    serde_json::from_str(&plaintext).expect("response envelope")
}

async fn wait_for_external_response(
    relay: &TestRelay,
    client_identity: &RadrootsIdentity,
    signer_public_key: PublicKey,
    request_id: &str,
    method: ExternalNostrConnectMethod,
) -> TestResult<(Event, ExternalNostrConnectResponse)> {
    timeout(Duration::from_secs(10), async {
        loop {
            let events = relay.published_events_by_author(signer_public_key).await;
            for event in events {
                let Ok(plaintext) = nip44::decrypt(
                    client_identity.keys().secret_key(),
                    &signer_public_key,
                    &event.content,
                ) else {
                    continue;
                };
                let Ok(message) = ExternalNostrConnectMessage::from_json(&plaintext) else {
                    continue;
                };
                if message.id() != request_id {
                    continue;
                }
                let response = message.to_response(method)?;
                return Ok((event, response));
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
}

async fn publish_external_request_and_wait_for_response(
    relay: &TestRelay,
    client_identity: &RadrootsIdentity,
    signer_public_key: PublicKey,
    request_id: &str,
    request: ExternalNostrConnectRequest,
    created_at_unix: u64,
) -> TestResult<(Event, ExternalNostrConnectResponse)> {
    let method = request.method();
    let request_message = build_external_request_message(request_id, &request);
    let event = build_external_request_event(
        client_identity,
        signer_public_key,
        &request_message,
        created_at_unix,
    );
    publish_event(relay.url(), &event).await?;
    wait_for_external_response(
        relay,
        client_identity,
        signer_public_key,
        request_id,
        method,
    )
    .await
}

fn register_external_client_session(
    runtime: &MycRuntime,
    client_public_key: PublicKey,
    relay_url: &str,
    permissions: &str,
) -> TestResult<()> {
    let manager = runtime.signer_manager()?;
    let requested_permissions: radroots_nostr_connect::prelude::RadrootsNostrConnectPermissions =
        if permissions.trim().is_empty() {
            Default::default()
        } else {
            permissions.parse()?
        };
    let connection = manager.register_connection(
        RadrootsNostrSignerConnectionDraft::new(client_public_key, runtime.user_public_identity())
            .with_requested_permissions(requested_permissions.clone())
            .with_relays(vec![relay_url.parse()?])
            .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
    )?;
    let _ = manager.set_granted_permissions(&connection.connection_id, requested_permissions)?;
    Ok(())
}

async fn publish_event(relay_url: &str, event: &Event) -> TestResult<()> {
    let (mut websocket, _) = tokio_tungstenite::connect_async(relay_url).await?;
    websocket
        .send(Message::Text(
            ClientMessage::event(event.clone()).as_json().into(),
        ))
        .await?;

    while let Some(message) = websocket.next().await {
        let message = message?;
        let Message::Text(text) = message else {
            continue;
        };
        let relay_message = RelayMessage::from_json(text.as_str())?;
        if let RelayMessage::Ok {
            event_id,
            status,
            message,
        } = relay_message
        {
            assert_eq!(event_id, event.id);
            assert!(status, "client publish rejected: {message}");
            return Ok(());
        }
    }

    Err("relay connection closed before OK".into())
}

async fn wait_for_connection_count(runtime: &MycRuntime, expected: usize) -> TestResult<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .signer_manager()
                .expect("manager")
                .list_connections()
                .expect("connections")
                .len()
                >= expected
            {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    Ok(())
}

async fn wait_for_connect_secret_consumed(runtime: &MycRuntime) -> TestResult<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            let consumed = runtime
                .signer_manager()
                .expect("manager")
                .list_connections()
                .expect("connections")
                .into_iter()
                .any(|connection| connection.connect_secret_is_consumed());
            if consumed {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    Ok(())
}

async fn wait_for_operation_audit_count(
    runtime: &MycRuntime,
    expected: usize,
) -> TestResult<Vec<MycOperationAuditRecord>> {
    timeout(Duration::from_secs(5), async {
        loop {
            let records = runtime
                .operation_audit_store()
                .list()
                .expect("operation audit");
            if records.len() >= expected {
                return records;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(Into::into)
}

async fn wait_for_delivery_outbox_records<F>(
    runtime: &MycRuntime,
    predicate: F,
) -> TestResult<Vec<MycDeliveryOutboxRecord>>
where
    F: Fn(&[MycDeliveryOutboxRecord]) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let records = runtime
                .delivery_outbox_store()
                .list_all()
                .expect("delivery outbox");
            if predicate(&records) {
                return records;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(Into::into)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_listener_rejects_denied_clients_without_registering_connection() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let client_identity =
        identity("7777777777777777777777777777777777777777777777777777777777777777");
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay.url()],
        MycConnectionApproval::ExplicitUser,
        |config| {
            config.policy.denied_client_pubkeys = vec![client_identity.public_key().to_hex()];
        },
    );
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let request_event = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("denied-connect", signer_public_key, "denied-secret"),
        Timestamp::now().as_secs(),
    );
    publish_event(relay.url(), &request_event).await?;

    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, "denied-connect");
    let parsed = radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::from_envelope(
        &RadrootsNostrConnectRequest::Connect {
            remote_signer_public_key: signer_public_key,
            secret: Some("denied-secret".to_owned()),
            requested_permissions: Default::default(),
        }
        .method(),
        response,
    )?;
    assert_eq!(
        parsed,
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::Error {
            result: None,
            error: "client public key denied by policy".to_owned(),
        }
    );
    assert!(runtime.signer_manager()?.list_connections()?.is_empty());

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_nostr_client_compatibility_covers_connect_and_base_methods() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let user_public_key = runtime.user_identity().public_key();
    let client_identity =
        identity("3333333333333333333333333333333333333333333333333333333333333333");
    let base_created_at = Timestamp::now().as_secs();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let (_, connect_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-connect",
        ExternalNostrConnectRequest::Connect {
            remote_signer_public_key: signer_public_key,
            secret: None,
        },
        base_created_at,
    )
    .await?;
    assert_eq!(connect_response.result, Some(ExternalResponseResult::Ack));
    assert_eq!(connect_response.error, None);

    wait_for_connection_count(&runtime, 1).await?;

    let (_, get_public_key_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-get-public-key",
        ExternalNostrConnectRequest::GetPublicKey,
        base_created_at + 1,
    )
    .await?;
    assert_eq!(
        get_public_key_response.result,
        Some(ExternalResponseResult::GetPublicKey(user_public_key))
    );
    assert_eq!(get_public_key_response.error, None);

    let (_, ping_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-ping",
        ExternalNostrConnectRequest::Ping,
        base_created_at + 2,
    )
    .await?;
    assert_eq!(ping_response.result, Some(ExternalResponseResult::Pong));
    assert_eq!(ping_response.error, None);

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_nostr_client_compatibility_covers_signed_and_crypto_methods() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let user_public_key = runtime.user_identity().public_key();
    let client_identity =
        identity("3333333333333333333333333333333333333333333333333333333333333333");
    let peer_identity =
        identity("4444444444444444444444444444444444444444444444444444444444444444");
    let base_created_at = Timestamp::now().as_secs();

    register_external_client_session(
        &runtime,
        client_identity.public_key(),
        relay.url(),
        "sign_event:1,nip04_encrypt,nip04_decrypt,nip44_encrypt,nip44_decrypt",
    )?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let unsigned_event: UnsignedEvent = serde_json::from_value(serde_json::json!({
        "pubkey": user_public_key.to_hex(),
        "created_at": base_created_at,
        "kind": 1,
        "tags": [],
        "content": "hello from an external nostr client"
    }))?;
    let (_, sign_event_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-sign-event",
        ExternalNostrConnectRequest::SignEvent(unsigned_event.clone()),
        base_created_at,
    )
    .await?;
    let signed_event = sign_event_response
        .result
        .expect("sign_event result")
        .to_sign_event()?;
    assert_eq!(signed_event.pubkey, user_public_key);
    assert_eq!(signed_event.kind, unsigned_event.kind);
    assert_eq!(signed_event.content, unsigned_event.content);
    signed_event.verify()?;

    let (_, nip04_encrypt_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-nip04-encrypt",
        ExternalNostrConnectRequest::Nip04Encrypt {
            public_key: peer_identity.public_key(),
            text: "hello via nip04".to_owned(),
        },
        base_created_at + 1,
    )
    .await?;
    let nip04_ciphertext = nip04_encrypt_response
        .result
        .expect("nip04 encrypt result")
        .to_nip04_encrypt()?;
    let nip04_plaintext = nostr::nips::nip04::decrypt(
        peer_identity.keys().secret_key(),
        &user_public_key,
        nip04_ciphertext.clone(),
    )?;
    assert_eq!(nip04_plaintext, "hello via nip04");

    let nip04_reply_ciphertext = nostr::nips::nip04::encrypt(
        peer_identity.keys().secret_key(),
        &user_public_key,
        "reply via nip04".to_owned(),
    )?;
    let (_, nip04_decrypt_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-nip04-decrypt",
        ExternalNostrConnectRequest::Nip04Decrypt {
            public_key: peer_identity.public_key(),
            ciphertext: nip04_reply_ciphertext,
        },
        base_created_at + 2,
    )
    .await?;
    assert_eq!(
        nip04_decrypt_response
            .result
            .expect("nip04 decrypt result")
            .to_nip04_decrypt()?,
        "reply via nip04"
    );

    let (_, nip44_encrypt_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-nip44-encrypt",
        ExternalNostrConnectRequest::Nip44Encrypt {
            public_key: peer_identity.public_key(),
            text: "hello via nip44".to_owned(),
        },
        base_created_at + 3,
    )
    .await?;
    let nip44_ciphertext = nip44_encrypt_response
        .result
        .expect("nip44 encrypt result")
        .to_nip44_encrypt()?;
    let nip44_plaintext = nip44::decrypt(
        peer_identity.keys().secret_key(),
        &user_public_key,
        &nip44_ciphertext,
    )?;
    assert_eq!(nip44_plaintext, "hello via nip44");

    let nip44_reply_ciphertext = nip44::encrypt(
        peer_identity.keys().secret_key(),
        &user_public_key,
        "reply via nip44".to_owned(),
        Version::V2,
    )?;
    let (_, nip44_decrypt_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-nip44-decrypt",
        ExternalNostrConnectRequest::Nip44Decrypt {
            public_key: peer_identity.public_key(),
            ciphertext: nip44_reply_ciphertext,
        },
        base_created_at + 4,
    )
    .await?;
    assert_eq!(
        nip44_decrypt_response
            .result
            .expect("nip44 decrypt result")
            .to_nip44_decrypt()?,
        "reply via nip44"
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_nostr_client_surfaces_pending_approval_state() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("8888888888888888888888888888888888888888888888888888888888888888");
    let base_created_at = Timestamp::now().as_secs();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let (_, connect_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-explicit-connect",
        ExternalNostrConnectRequest::Connect {
            remote_signer_public_key: signer_public_key,
            secret: None,
        },
        base_created_at,
    )
    .await?;
    assert_eq!(connect_response.result, Some(ExternalResponseResult::Ack));

    wait_for_connection_count(&runtime, 1).await?;

    let (_, pending_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-pending-get-public-key",
        ExternalNostrConnectRequest::GetPublicKey,
        base_created_at + 1,
    )
    .await?;
    assert_eq!(pending_response.result, None);
    assert_eq!(
        pending_response.error.as_deref(),
        Some("connection is pending")
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_nostr_client_surfaces_auth_challenge_state() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let client_identity =
        identity("8989898989898989898989898989898989898989898989898989898989898989");
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let base_created_at = Timestamp::now().as_secs();

    register_external_client_session(&runtime, client_identity.public_key(), relay.url(), "")?;
    let connection_id = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .find(|connection| connection.client_public_key == client_identity.public_key())
        .expect("active connection")
        .connection_id;
    let _ = runtime
        .signer_manager()?
        .require_auth_challenge(&connection_id, "https://auth.example/challenge")?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let (_, connect_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-auth-ping",
        ExternalNostrConnectRequest::Ping,
        base_created_at,
    )
    .await?;
    assert_eq!(
        connect_response.result,
        Some(ExternalResponseResult::AuthUrl)
    );
    assert_eq!(
        connect_response.error.as_deref(),
        Some("https://auth.example/challenge")
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_nostr_client_ignores_unrelated_signer_events_before_response() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime.clone();
    let signer_identity = runtime.signer_identity();
    let signer_public_key = signer_identity.public_key();
    let client_identity =
        identity("5656565656565656565656565656565656565656565656565656565656565656");
    let base_created_at = Timestamp::now().as_secs();

    register_external_client_session(&runtime, client_identity.public_key(), relay.url(), "")?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let noise_event = build_signer_noise_event(&signer_identity, base_created_at);
    publish_event(relay.url(), &noise_event).await?;

    let (_, ping_response) = publish_external_request_and_wait_for_response(
        &relay,
        &client_identity,
        signer_public_key,
        "external-noise-ping",
        ExternalNostrConnectRequest::Ping,
        base_created_at + 1,
    )
    .await?;
    assert_eq!(ping_response.result, Some(ExternalResponseResult::Pong));
    assert_eq!(ping_response.error, None);

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_listener_consumes_connect_secret_only_after_successful_publish() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("3333333333333333333333333333333333333333333333333333333333333333");
    let base_created_at = Timestamp::now().as_secs();

    relay
        .queue_publish_outcomes(signer_public_key, &[false, true])
        .await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let request_one = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("connect-1", signer_public_key, "shared-secret"),
        base_created_at,
    );
    publish_event(relay.url(), &request_one).await?;
    wait_for_connection_count(&runtime, 1).await?;
    sleep(Duration::from_millis(100)).await;

    assert!(
        relay
            .published_events_by_author(signer_public_key)
            .await
            .is_empty()
    );
    let initial_connection = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(!initial_connection.connect_secret_is_consumed());
    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(operation_audit.len(), 1);
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::ListenerResponsePublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Rejected
    );
    assert_eq!(
        operation_audit[0].connection_id.as_deref(),
        Some(initial_connection.connection_id.as_str())
    );
    assert_eq!(operation_audit[0].request_id.as_deref(), Some("connect-1"));
    assert_eq!(operation_audit[0].relay_count, 1);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 0);
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("blocked by test relay")
    );
    let outbox_records = wait_for_delivery_outbox_records(&runtime, |records| {
        records.len() >= 1 && records[0].status == MycDeliveryOutboxStatus::Failed
    })
    .await?;
    assert_eq!(
        outbox_records[0].kind,
        MycDeliveryOutboxKind::ListenerResponsePublish
    );
    assert_eq!(outbox_records[0].status, MycDeliveryOutboxStatus::Failed);
    assert_eq!(
        outbox_records[0]
            .connection_id
            .as_ref()
            .map(|value| value.as_str()),
        Some(initial_connection.connection_id.as_str())
    );
    assert_eq!(outbox_records[0].request_id.as_deref(), Some("connect-1"));
    assert!(outbox_records[0].signer_publish_workflow_id.is_some());
    assert!(
        runtime
            .signer_manager()?
            .list_publish_workflows()?
            .is_empty()
    );

    let request_two = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("connect-2", signer_public_key, "shared-secret"),
        base_created_at + 1,
    );
    publish_event(relay.url(), &request_two).await?;

    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, "connect-2");
    assert_eq!(
        response.result,
        Some(serde_json::Value::String("shared-secret".to_owned()))
    );

    wait_for_connect_secret_consumed(&runtime).await?;
    let consumed_connection = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(consumed_connection.connect_secret_is_consumed());
    let outbox_records = wait_for_delivery_outbox_records(&runtime, |records| {
        records.len() >= 2 && records[1].status == MycDeliveryOutboxStatus::Finalized
    })
    .await?;
    assert_eq!(
        outbox_records[1].kind,
        MycDeliveryOutboxKind::ListenerResponsePublish
    );
    assert_eq!(outbox_records[1].status, MycDeliveryOutboxStatus::Finalized);
    assert_eq!(outbox_records[1].request_id.as_deref(), Some("connect-2"));
    assert!(outbox_records[1].published_at_unix.is_some());
    assert!(outbox_records[1].finalized_at_unix.is_some());
    assert!(outbox_records[1].signer_publish_workflow_id.is_some());
    assert!(
        runtime
            .signer_manager()?
            .list_publish_workflows()?
            .is_empty()
    );

    let request_three = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("connect-3", signer_public_key, "shared-secret"),
        base_created_at + 2,
    );
    publish_event(relay.url(), &request_three).await?;
    sleep(Duration::from_millis(300)).await;

    assert_eq!(
        relay
            .published_events_by_author(signer_public_key)
            .await
            .len(),
        1
    );
    let operation_audit = runtime.operation_audit_store().list()?;
    assert_eq!(operation_audit.len(), 2);
    assert_eq!(
        operation_audit[1].operation,
        MycOperationAuditKind::ListenerResponsePublish
    );
    assert_eq!(
        operation_audit[1].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert_eq!(operation_audit[1].request_id.as_deref(), Some("connect-2"));

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_listener_works_with_sqlite_signer_state_and_runtime_audit() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay.url()],
        MycConnectionApproval::NotRequired,
        |config| {
            config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
            config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;
        },
    );
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("5353535353535353535353535353535353535353535353535353535353535353");
    let base_created_at = Timestamp::now().as_secs();

    assert_eq!(
        runtime
            .paths()
            .signer_state_path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("signer-state.sqlite")
    );
    assert_eq!(
        runtime
            .paths()
            .runtime_audit_path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("operations.sqlite")
    );

    relay
        .queue_publish_outcomes(signer_public_key, &[false, true])
        .await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let request_one = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("sqlite-connect-1", signer_public_key, "sqlite-secret"),
        base_created_at,
    );
    publish_event(relay.url(), &request_one).await?;
    wait_for_connection_count(&runtime, 1).await?;
    sleep(Duration::from_millis(100)).await;

    assert!(
        relay
            .published_events_by_author(signer_public_key)
            .await
            .is_empty()
    );
    let initial_connection = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(!initial_connection.connect_secret_is_consumed());

    let request_two = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("sqlite-connect-2", signer_public_key, "sqlite-secret"),
        base_created_at + 1,
    );
    publish_event(relay.url(), &request_two).await?;

    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, "sqlite-connect-2");
    assert_eq!(
        response.result,
        Some(serde_json::Value::String("sqlite-secret".to_owned()))
    );

    wait_for_connect_secret_consumed(&runtime).await?;
    let consumed_connection = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(consumed_connection.connect_secret_is_consumed());
    let operation_audit = runtime.operation_audit_store().list_all()?;
    assert_eq!(operation_audit.len(), 2);
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Rejected
    );
    assert_eq!(
        operation_audit[1].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    let outbox_records = wait_for_delivery_outbox_records(&runtime, |records| {
        records.len() >= 2 && records[1].status == MycDeliveryOutboxStatus::Finalized
    })
    .await?;
    assert_eq!(outbox_records[0].status, MycDeliveryOutboxStatus::Failed);
    assert_eq!(outbox_records[1].status, MycDeliveryOutboxStatus::Finalized);

    let restarted_runtime = MycRuntime::bootstrap(runtime.config().clone())?;
    assert_eq!(
        restarted_runtime
            .signer_manager()?
            .list_connections()?
            .len(),
        1
    );
    assert_eq!(
        restarted_runtime.operation_audit_store().list_all()?.len(),
        2
    );
    let restarted_outbox = restarted_runtime.delivery_outbox_store().list_all()?;
    assert_eq!(restarted_outbox.len(), 2);
    assert_eq!(restarted_outbox[0].status, MycDeliveryOutboxStatus::Failed);
    assert_eq!(
        restarted_outbox[1].status,
        MycDeliveryOutboxStatus::Finalized
    );
    assert_eq!(
        restarted_outbox[0].request_id.as_deref(),
        Some("sqlite-connect-1")
    );
    assert_eq!(
        restarted_outbox[1].request_id.as_deref(),
        Some("sqlite-connect-2")
    );
    assert!(restarted_outbox[0].signer_publish_workflow_id.is_some());
    assert!(restarted_outbox[1].signer_publish_workflow_id.is_some());
    assert!(
        restarted_runtime
            .signer_manager()?
            .list_publish_workflows()?
            .is_empty()
    );
    assert!(
        restarted_runtime
            .signer_manager()?
            .list_connections()?
            .into_iter()
            .next()
            .expect("persisted connection")
            .connect_secret_is_consumed()
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_client_reauths_after_authorized_ttl() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let client_identity =
        identity("7878787878787878787878787878787878787878787878787878787878787878");
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay.url()],
        MycConnectionApproval::ExplicitUser,
        |config| {
            config.policy.trusted_client_pubkeys = vec![client_identity.public_key().to_hex()];
            config.policy.permission_ceiling = "sign_event:1".parse().expect("permission ceiling");
            config.policy.allowed_sign_event_kinds = vec![1];
            config.policy.auth_url = Some("https://auth.example/challenge".to_owned());
            config.policy.auth_authorized_ttl_secs = Some(1);
        },
    );
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay.wait_for_subscription_count(1).await?;

    let connect_request = build_request_event(
        &client_identity,
        signer_public_key,
        RadrootsNostrConnectRequestMessage::new(
            "trusted-connect",
            RadrootsNostrConnectRequest::Connect {
                remote_signer_public_key: signer_public_key,
                secret: None,
                requested_permissions: "sign_event:1".parse().expect("requested permissions"),
            },
        ),
        Timestamp::now().as_secs(),
    );
    publish_event(relay.url(), &connect_request).await?;
    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let connect_response =
        decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    let connect_parsed =
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::from_envelope(
            &RadrootsNostrConnectRequest::Connect {
                remote_signer_public_key: signer_public_key,
                secret: None,
                requested_permissions: "sign_event:1".parse().expect("requested permissions"),
            }
            .method(),
            connect_response,
        )?;
    assert_eq!(
        connect_parsed,
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::ConnectAcknowledged
    );

    let sign_request = |request_id: &str, created_at_unix| {
        build_request_event(
            &client_identity,
            signer_public_key,
            RadrootsNostrConnectRequestMessage::new(
                request_id,
                RadrootsNostrConnectRequest::SignEvent(
                    serde_json::from_value(serde_json::json!({
                        "pubkey": runtime.user_identity().public_key().to_hex(),
                        "created_at": created_at_unix,
                        "kind": 1,
                        "tags": [],
                        "content": request_id
                    }))
                    .expect("unsigned event"),
                ),
            ),
            created_at_unix,
        )
    };

    publish_event(
        relay.url(),
        &sign_request("trusted-sign-1", Timestamp::now().as_secs()),
    )
    .await?;
    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 2)
        .await?;
    let first_auth = decrypt_response(&client_identity, signer_public_key, &response_events[1]);
    let first_auth = radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::from_envelope(
        &RadrootsNostrConnectRequest::SignEvent(
            serde_json::from_value(serde_json::json!({
                "pubkey": runtime.user_identity().public_key().to_hex(),
                "created_at": Timestamp::from(1).as_secs(),
                "kind": 1,
                "tags": [],
                "content": "trusted-sign-1"
            }))
            .expect("unsigned event"),
        )
        .method(),
        first_auth,
    )?;
    assert_eq!(
        first_auth,
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::AuthUrl(
            "https://auth.example/challenge".to_owned()
        )
    );

    let connection = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("connection");
    let replayed = control::authorize_auth_challenge(&runtime, &connection.connection_id).await?;
    assert_eq!(
        replayed.replayed_request_id.as_deref(),
        Some("trusted-sign-1")
    );

    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 3)
        .await?;
    let replay_response =
        decrypt_response(&client_identity, signer_public_key, &response_events[2]);
    let replay_parsed =
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::from_envelope(
            &RadrootsNostrConnectRequest::SignEvent(
                serde_json::from_value(serde_json::json!({
                    "pubkey": runtime.user_identity().public_key().to_hex(),
                    "created_at": Timestamp::from(1).as_secs(),
                    "kind": 1,
                    "tags": [],
                    "content": "trusted-sign-1"
                }))
                .expect("unsigned event"),
            )
            .method(),
            replay_response,
        )?;
    assert!(matches!(
        replay_parsed,
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::SignedEvent(_)
    ));

    sleep(Duration::from_secs(2)).await;

    publish_event(
        relay.url(),
        &sign_request("trusted-sign-2", Timestamp::now().as_secs()),
    )
    .await?;
    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 4)
        .await?;
    let second_auth = decrypt_response(&client_identity, signer_public_key, &response_events[3]);
    let second_auth = radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::from_envelope(
        &RadrootsNostrConnectRequest::SignEvent(
            serde_json::from_value(serde_json::json!({
                "pubkey": runtime.user_identity().public_key().to_hex(),
                "created_at": Timestamp::from(1).as_secs(),
                "kind": 1,
                "tags": [],
                "content": "trusted-sign-2"
            }))
            .expect("unsigned event"),
        )
        .method(),
        second_auth,
    )?;
    assert_eq!(
        second_auth,
        radroots_nostr_connect::prelude::RadrootsNostrConnectResponse::AuthUrl(
            "https://auth.example/challenge".to_owned()
        )
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_accept_retries_without_consuming_secret_until_publish_succeeds() -> TestResult<()>
{
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime;
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("4444444444444444444444444444444444444444444444444444444444444444");

    relay
        .queue_publish_outcomes(signer_public_key, &[false, true])
        .await;

    let client_uri = RadrootsNostrConnectUri::Client(RadrootsNostrConnectClientUri {
        client_public_key: client_identity.public_key(),
        relays: vec![nostr::RelayUrl::parse(relay.url())?],
        secret: "client-secret".to_owned(),
        metadata: RadrootsNostrConnectClientMetadata::default(),
    })
    .to_string();

    let failed = control::accept_client_uri(&runtime, &client_uri)
        .await
        .expect_err("first publish should fail");
    assert!(failed.to_string().contains("Nostr publish failed"));

    let stored_after_failure = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(!stored_after_failure.connect_secret_is_consumed());
    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::ConnectAcceptPublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Rejected
    );
    assert_eq!(
        operation_audit[0].connection_id.as_deref(),
        Some(stored_after_failure.connection_id.as_str())
    );
    assert!(operation_audit[0].request_id.is_some());
    assert_eq!(operation_audit[0].relay_count, 1);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 0);
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("blocked by test relay")
    );

    let accepted = control::accept_client_uri(&runtime, &client_uri).await?;
    assert_eq!(accepted.response_request_id.len(), 36);

    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, accepted.response_request_id);
    assert_eq!(
        response.result,
        Some(serde_json::Value::String("client-secret".to_owned()))
    );

    let stored_after_success = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(stored_after_success.connect_secret_is_consumed());
    let operation_audit = wait_for_operation_audit_count(&runtime, 2).await?;
    assert_eq!(
        operation_audit[1].operation,
        MycOperationAuditKind::ConnectAcceptPublish
    );
    assert_eq!(
        operation_audit[1].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert_eq!(
        operation_audit[1].connection_id.as_deref(),
        Some(stored_after_success.connection_id.as_str())
    );
    assert_eq!(
        operation_audit[1].request_id.as_deref(),
        Some(accepted.response_request_id.as_str())
    );
    assert_eq!(operation_audit[1].relay_count, 1);
    assert_eq!(operation_audit[1].acknowledged_relay_count, 1);
    assert!(
        operation_audit[1]
            .relay_outcome_summary
            .contains("1/1 relays acknowledged publish")
    );

    let consumed = control::accept_client_uri(&runtime, &client_uri)
        .await
        .expect_err("consumed secret should be rejected");
    assert!(
        consumed
            .to_string()
            .contains("connect secret has already been consumed")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_accept_succeeds_with_any_delivery_policy_when_one_relay_acknowledges()
-> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::NotRequired,
        |config| {
            config.transport.delivery_policy = MycTransportDeliveryPolicy::Any;
            config.transport.publish_max_attempts = 1;
        },
    );
    let runtime = test_runtime.runtime;
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("5555555555555555555555555555555555555555555555555555555555555555");

    relay_a
        .queue_publish_outcomes(signer_public_key, &[false])
        .await;
    relay_b
        .queue_publish_outcomes(signer_public_key, &[true])
        .await;

    let client_uri = RadrootsNostrConnectUri::Client(RadrootsNostrConnectClientUri {
        client_public_key: client_identity.public_key(),
        relays: vec![
            nostr::RelayUrl::parse(relay_a.url())?,
            nostr::RelayUrl::parse(relay_b.url())?,
        ],
        secret: "delivery-any-secret".to_owned(),
        metadata: RadrootsNostrConnectClientMetadata::default(),
    })
    .to_string();

    let accepted = control::accept_client_uri(&runtime, &client_uri).await?;
    assert_eq!(accepted.response_relays.len(), 2);
    let stored = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .find(|connection| connection.connection_id == accepted.connection.connection_id)
        .expect("stored connection");
    assert!(stored.connect_secret_is_consumed());

    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::ConnectAcceptPublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert_eq!(operation_audit[0].relay_count, 2);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 1);
    assert_eq!(
        operation_audit[0].delivery_policy,
        Some(MycTransportDeliveryPolicy::Any)
    );
    assert_eq!(
        operation_audit[0].required_acknowledged_relay_count,
        Some(1)
    );
    assert_eq!(operation_audit[0].publish_attempt_count, Some(1));
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("delivery policy any")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_accept_rejects_when_quorum_delivery_policy_is_not_met() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::NotRequired,
        |config| {
            config.transport.delivery_policy = MycTransportDeliveryPolicy::Quorum;
            config.transport.delivery_quorum = Some(2);
            config.transport.publish_max_attempts = 1;
        },
    );
    let runtime = test_runtime.runtime;
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("6666666666666666666666666666666666666666666666666666666666666665");

    relay_a
        .queue_publish_outcomes(signer_public_key, &[true])
        .await;
    relay_b
        .queue_publish_outcomes(signer_public_key, &[false])
        .await;

    let client_uri = RadrootsNostrConnectUri::Client(RadrootsNostrConnectClientUri {
        client_public_key: client_identity.public_key(),
        relays: vec![
            nostr::RelayUrl::parse(relay_a.url())?,
            nostr::RelayUrl::parse(relay_b.url())?,
        ],
        secret: "delivery-quorum-secret".to_owned(),
        metadata: RadrootsNostrConnectClientMetadata::default(),
    })
    .to_string();

    let error = control::accept_client_uri(&runtime, &client_uri)
        .await
        .expect_err("quorum publish should fail");
    assert!(
        error
            .to_string()
            .contains("delivery policy quorum requiring 2 acknowledgements")
    );
    assert_eq!(
        error.publish_delivery_policy(),
        Some(MycTransportDeliveryPolicy::Quorum)
    );
    assert_eq!(error.publish_required_acknowledged_relay_count(), Some(2));
    assert_eq!(error.publish_attempt_count(), Some(1));

    let stored = runtime
        .signer_manager()?
        .list_connections()?
        .into_iter()
        .next()
        .expect("stored connection");
    assert!(!stored.connect_secret_is_consumed());

    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::ConnectAcceptPublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Rejected
    );
    assert_eq!(operation_audit[0].relay_count, 2);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 1);
    assert_eq!(
        operation_audit[0].delivery_policy,
        Some(MycTransportDeliveryPolicy::Quorum)
    );
    assert_eq!(
        operation_audit[0].required_acknowledged_relay_count,
        Some(2)
    );
    assert_eq!(operation_audit[0].publish_attempt_count, Some(1));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_listener_retries_until_all_delivery_policy_is_met() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_transport_config(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::NotRequired,
        |config| {
            config.transport.delivery_policy = MycTransportDeliveryPolicy::All;
            config.transport.publish_max_attempts = 2;
            config.transport.publish_initial_backoff_millis = 10;
            config.transport.publish_max_backoff_millis = 10;
        },
    );
    let runtime = test_runtime.runtime.clone();
    let signer_public_key = runtime.signer_identity().public_key();
    let client_identity =
        identity("7777777777777777777777777777777777777777777777777777777777777777");
    let base_created_at = Timestamp::now().as_secs();

    relay_a
        .queue_publish_outcomes(signer_public_key, &[true, true])
        .await;
    relay_b
        .queue_publish_outcomes(signer_public_key, &[false, true])
        .await;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let service_runtime = runtime.clone();
    let listener_task = tokio::spawn(async move {
        service_runtime
            .run_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    relay_a.wait_for_subscription_count(1).await?;
    relay_b.wait_for_subscription_count(1).await?;

    let request = build_request_event(
        &client_identity,
        signer_public_key,
        connect_request_message("connect-all-1", signer_public_key, "shared-secret-all"),
        base_created_at,
    );
    publish_event(relay_a.url(), &request).await?;

    let response_events = relay_b
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, "connect-all-1");
    assert_eq!(
        response.result,
        Some(serde_json::Value::String("shared-secret-all".to_owned()))
    );

    wait_for_connect_secret_consumed(&runtime).await?;
    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::ListenerResponsePublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert_eq!(operation_audit[0].relay_count, 2);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 2);
    assert_eq!(
        operation_audit[0].delivery_policy,
        Some(MycTransportDeliveryPolicy::All)
    );
    assert_eq!(
        operation_audit[0].required_acknowledged_relay_count,
        Some(2)
    );
    assert_eq!(operation_audit[0].publish_attempt_count, Some(2));
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("attempt 1: 1/2 relays acknowledged publish")
    );

    let _ = shutdown_tx.send(());
    listener_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_replay_restores_pending_request_until_publish_succeeds() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new(relay.url(), MycConnectionApproval::NotRequired);
    let runtime = test_runtime.runtime;
    let signer_public_key = runtime.signer_identity().public_key();
    let client_public_key = Keys::new(SecretKey::from_hex(
        "5555555555555555555555555555555555555555555555555555555555555555",
    )?)
    .public_key();

    relay
        .queue_publish_outcomes(signer_public_key, &[false, true])
        .await;

    let manager = runtime.signer_manager()?;
    let connection = manager.register_connection(
        RadrootsNostrSignerConnectionDraft::new(client_public_key, runtime.user_public_identity())
            .with_relays(vec![nostr::RelayUrl::parse(relay.url())?])
            .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
    )?;
    manager.require_auth_challenge(&connection.connection_id, "https://auth.example/flow")?;
    manager.set_pending_request(&connection.connection_id, ping_request_message("auth-ping"))?;

    let first_attempt = control::authorize_auth_challenge(&runtime, &connection.connection_id)
        .await
        .expect_err("first replay publish should fail");
    assert!(first_attempt.to_string().contains("Nostr publish failed"));

    let restored = runtime
        .signer_manager()?
        .get_connection(&connection.connection_id)?
        .expect("restored connection");
    assert_eq!(restored.auth_state, RadrootsNostrSignerAuthState::Pending);
    assert_eq!(
        restored
            .pending_request
            .as_ref()
            .expect("pending request")
            .request_id()
            .as_str(),
        "auth-ping"
    );
    assert_eq!(
        restored
            .auth_challenge
            .as_ref()
            .expect("auth challenge")
            .authorized_at_unix,
        None
    );
    let operation_audit = wait_for_operation_audit_count(&runtime, 2).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::AuthReplayPublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Rejected
    );
    assert_eq!(
        operation_audit[0].connection_id.as_deref(),
        Some(connection.connection_id.as_str())
    );
    assert_eq!(operation_audit[0].request_id.as_deref(), Some("auth-ping"));
    assert_eq!(operation_audit[0].relay_count, 1);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 0);
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("blocked by test relay")
    );
    assert_eq!(
        operation_audit[1].operation,
        MycOperationAuditKind::AuthReplayRestore
    );
    assert_eq!(
        operation_audit[1].outcome,
        MycOperationAuditOutcome::Restored
    );
    assert_eq!(
        operation_audit[1].connection_id.as_deref(),
        Some(connection.connection_id.as_str())
    );
    assert_eq!(operation_audit[1].request_id.as_deref(), Some("auth-ping"));
    assert_eq!(operation_audit[1].relay_count, 1);
    assert_eq!(operation_audit[1].acknowledged_relay_count, 0);
    assert!(
        operation_audit[1]
            .relay_outcome_summary
            .contains("restored pending auth challenge")
    );

    let replayed = control::authorize_auth_challenge(&runtime, &connection.connection_id).await?;
    assert_eq!(replayed.replayed_request_id.as_deref(), Some("auth-ping"));

    let client_identity =
        identity("5555555555555555555555555555555555555555555555555555555555555555");
    let response_events = relay
        .wait_for_published_events_by_author(signer_public_key, 1)
        .await?;
    let response = decrypt_response(&client_identity, signer_public_key, &response_events[0]);
    assert_eq!(response.id, "auth-ping");
    assert_eq!(
        response.result,
        Some(serde_json::Value::String("pong".to_owned()))
    );

    let authorized = runtime
        .signer_manager()?
        .get_connection(&connection.connection_id)?
        .expect("authorized connection");
    assert_eq!(
        authorized.auth_state,
        RadrootsNostrSignerAuthState::Authorized
    );
    assert!(authorized.pending_request.is_none());
    assert!(authorized.last_authenticated_at_unix.is_some());
    let operation_audit = wait_for_operation_audit_count(&runtime, 3).await?;
    assert_eq!(
        operation_audit[2].operation,
        MycOperationAuditKind::AuthReplayPublish
    );
    assert_eq!(
        operation_audit[2].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert_eq!(
        operation_audit[2].connection_id.as_deref(),
        Some(connection.connection_id.as_str())
    );
    assert_eq!(operation_audit[2].request_id.as_deref(), Some("auth-ping"));
    assert_eq!(operation_audit[2].relay_count, 1);
    assert_eq!(operation_audit[2].acknowledged_relay_count, 1);
    assert!(
        operation_audit[2]
            .relay_outcome_summary
            .contains("1/1 relays acknowledged publish")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_nip89_publish_uses_app_identity_and_records_audit() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;

    let published = publish_nip89_event(&runtime).await?;
    let published_event_id = published.event.id.to_hex();
    let published_events = relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    let event = &published_events[0];
    let event_json = event.as_json();

    assert_eq!(
        published.author_public_key_hex,
        app_identity.public_key_hex()
    );
    assert_eq!(
        published.signer_public_key_hex,
        runtime.signer_identity().public_key_hex()
    );
    assert_eq!(event.kind.as_u16(), 31_990);
    assert!(event_json.contains("\"24133\""));
    assert!(event_json.contains("\"relay\""));
    assert!(event_json.contains("\"nostrconnect_url\""));
    assert_eq!(published.relay_count, 1);
    assert_eq!(published.acknowledged_relay_count, 1);

    let operation_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        operation_audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(
        operation_audit[0].outcome,
        MycOperationAuditOutcome::Succeeded
    );
    assert!(operation_audit[0].connection_id.is_none());
    assert_eq!(
        operation_audit[0].request_id.as_deref(),
        Some(published_event_id.as_str())
    );
    assert_eq!(operation_audit[0].relay_count, 1);
    assert_eq!(operation_audit[0].acknowledged_relay_count, 1);
    assert!(
        operation_audit[0]
            .relay_outcome_summary
            .contains("1/1 relays acknowledged publish")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_nip89_publish_retries_cleanly_after_rejection() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[false, true])
        .await;

    let failed = publish_nip89_event(&runtime)
        .await
        .expect_err("first publish should fail");
    assert!(failed.to_string().contains("Nostr publish failed"));
    assert!(
        relay
            .published_events_by_author(app_identity.public_key())
            .await
            .is_empty()
    );

    let first_audit = wait_for_operation_audit_count(&runtime, 1).await?;
    assert_eq!(
        first_audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(first_audit[0].outcome, MycOperationAuditOutcome::Rejected);
    assert!(first_audit[0].connection_id.is_none());
    assert!(first_audit[0].request_id.is_some());
    assert_eq!(first_audit[0].relay_count, 1);
    assert_eq!(first_audit[0].acknowledged_relay_count, 0);
    assert!(
        first_audit[0]
            .relay_outcome_summary
            .contains("blocked by test relay")
    );

    let published = publish_nip89_event(&runtime).await?;
    let published_events = relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    assert_eq!(published_events.len(), 1);
    assert_eq!(published.relay_count, 1);
    assert_eq!(published.acknowledged_relay_count, 1);

    let second_audit = wait_for_operation_audit_count(&runtime, 2).await?;
    assert_eq!(
        second_audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(second_audit[1].outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(
        second_audit[1].request_id.as_deref(),
        Some(published.event.id.to_hex().as_str())
    );
    assert_eq!(second_audit[1].relay_count, 1);
    assert_eq!(second_audit[1].acknowledged_relay_count, 1);
    assert!(
        second_audit[1]
            .relay_outcome_summary
            .contains("1/1 relays acknowledged publish")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_live_nip89_reports_missing_when_handler_is_unpublished() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);

    let output = fetch_live_nip89(&test_runtime.runtime).await?;

    assert_eq!(output.handler_identifier, "myc");
    assert_eq!(output.publish_relays, vec![relay.url().to_owned()]);
    assert!(output.live_groups.is_empty());
    assert_eq!(output.relay_states.len(), 1);
    assert_eq!(
        output.relay_states[0].fetch_status,
        MycDiscoveryRelayFetchStatus::Available
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_live_nip89_fails_when_all_discovery_relays_are_unavailable() -> TestResult<()> {
    let unavailable_a = unavailable_relay_url()?;
    let unavailable_b = unavailable_relay_url()?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[unavailable_a.as_str(), unavailable_b.as_str()],
        MycConnectionApproval::ExplicitUser,
    );

    let error = fetch_live_nip89(&test_runtime.runtime)
        .await
        .expect_err("all-unavailable discovery fetch should fail");
    assert!(
        error
            .to_string()
            .contains("failed to fetch discovery state from all configured relays")
    );

    let audit = wait_for_operation_audit_count(&test_runtime.runtime, 1).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerFetch
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Unavailable);
    assert_eq!(audit[0].relay_count, 2);
    assert_eq!(audit[0].acknowledged_relay_count, 0);
    assert!(audit[0].relay_outcome_summary.contains(&unavailable_a));
    assert!(audit[0].relay_outcome_summary.contains(&unavailable_b));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_live_nip89_parallelizes_relay_fetch_and_preserves_configured_order() -> TestResult<()>
{
    let live_relay = TestRelay::spawn().await?;
    let slow_a = HangingRelay::spawn(Duration::from_secs(3)).await?;
    let slow_b = HangingRelay::spawn(Duration::from_secs(3)).await?;
    let slow_c = HangingRelay::spawn(Duration::from_secs(3)).await?;
    let slow_d = HangingRelay::spawn(Duration::from_secs(3)).await?;
    let relay_urls = [
        slow_a.url(),
        live_relay.url(),
        slow_b.url(),
        slow_c.url(),
        slow_d.url(),
    ];
    let mut expected_relay_states = vec![
        (
            slow_a.url().to_owned(),
            MycDiscoveryRelayFetchStatus::Unavailable,
        ),
        (
            live_relay.url().to_owned(),
            MycDiscoveryRelayFetchStatus::Available,
        ),
        (
            slow_b.url().to_owned(),
            MycDiscoveryRelayFetchStatus::Unavailable,
        ),
        (
            slow_c.url().to_owned(),
            MycDiscoveryRelayFetchStatus::Unavailable,
        ),
        (
            slow_d.url().to_owned(),
            MycDiscoveryRelayFetchStatus::Unavailable,
        ),
    ];
    expected_relay_states.sort_by(|left, right| left.0.cmp(&right.0));
    let expected_relay_urls = expected_relay_states
        .iter()
        .map(|(relay_url, _)| relay_url.clone())
        .collect::<Vec<_>>();
    let test_runtime = MycTestRuntime::new_with_discovery_relays_and_timeout(
        &relay_urls,
        MycConnectionApproval::ExplicitUser,
        1,
    );

    let started_at = Instant::now();
    let output = fetch_live_nip89(&test_runtime.runtime).await?;
    let elapsed = started_at.elapsed();

    assert!(
        elapsed < Duration::from_millis(2500),
        "expected concurrent relay fetch to finish under 2.5s, got {:?}",
        elapsed
    );
    assert_eq!(
        output
            .relay_states
            .iter()
            .map(|relay_state| relay_state.relay_url.clone())
            .collect::<Vec<_>>(),
        expected_relay_urls
    );
    assert_eq!(
        output
            .relay_states
            .iter()
            .map(|relay_state| relay_state.fetch_status)
            .collect::<Vec<_>>(),
        expected_relay_states
            .iter()
            .map(|(_, fetch_status)| *fetch_status)
            .collect::<Vec<_>>()
    );
    for relay_state in &output.relay_states {
        if relay_state.fetch_status == MycDiscoveryRelayFetchStatus::Available {
            assert!(relay_state.fetch_error.is_none());
            assert!(relay_state.live_groups.is_empty());
        } else {
            assert!(relay_state.fetch_error.is_some());
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diff_live_nip89_reports_matched_after_publish() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let published = publish_nip89_event(&runtime).await?;
    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    let diff = diff_live_nip89(&runtime).await?;

    assert_eq!(diff.status, MycDiscoveryLiveStatus::Matched);
    assert!(diff.differing_fields.is_empty());
    assert_eq!(diff.live_groups.len(), 1);
    let live_event = diff.live_groups[0]
        .events
        .last()
        .cloned()
        .expect("live event");
    assert_eq!(live_event.event_id_hex, published.event.id.to_hex());
    assert_eq!(
        live_event.handler.author_public_key_hex,
        app_identity.public_key_hex()
    );
    assert_eq!(live_event.handler.kinds, vec![24_133]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_publishes_when_live_handler_is_missing() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;

    let refreshed = refresh_nip89(&runtime, false).await?;

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Missing);
    assert_eq!(refreshed.differing_fields, vec!["live_groups".to_owned()]);
    assert!(refreshed.live_groups.is_empty());
    assert!(refreshed.published.is_some());
    assert_eq!(refreshed.repair_summary.repaired, 1);
    assert_eq!(refreshed.repair_summary.failed, 0);
    assert_eq!(refreshed.repair_summary.unchanged, 0);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.remaining_repair_relays, Vec::<String>::new());
    assert_eq!(refreshed.repair_results.len(), 1);
    assert_eq!(
        refreshed.repair_results[0].outcome,
        MycDiscoveryRepairOutcome::Repaired
    );

    let audit = wait_for_operation_audit_count(&runtime, 3).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Missing);
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerRepair
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Succeeded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_repairs_missing_relays_without_republishing_matched_relays() -> TestResult<()>
{
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::ExplicitUser,
    );
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let matched_event = MycDiscoveryContext::from_runtime(&runtime)?
        .build_signed_handler_event()
        .expect("matched event");
    publish_signed_event(relay_a.url(), &app_identity, &matched_event).await?;
    relay_a
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    relay_b
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let refreshed = refresh_nip89(&runtime, false).await?;
    let published = refreshed.published.expect("published output");

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Matched);
    assert_eq!(published.publish_relays, vec![relay_b.url().to_owned()]);
    assert_eq!(published.relay_count, 1);
    assert_eq!(published.acknowledged_relay_count, 1);
    assert_eq!(refreshed.repair_summary.repaired, 1);
    assert_eq!(refreshed.repair_summary.failed, 0);
    assert_eq!(refreshed.repair_summary.unchanged, 1);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.remaining_repair_relays, Vec::<String>::new());
    assert_eq!(refreshed.repair_results.len(), 2);
    assert_eq!(
        refreshed
            .repair_results
            .iter()
            .find(|result| result.relay_url == relay_a.url())
            .expect("matched relay repair result")
            .outcome,
        MycDiscoveryRepairOutcome::Unchanged
    );
    assert_eq!(
        refreshed
            .repair_results
            .iter()
            .find(|result| result.relay_url == relay_b.url())
            .expect("repaired relay result")
            .outcome,
        MycDiscoveryRepairOutcome::Repaired
    );

    relay_b
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    assert_eq!(
        relay_a
            .published_events_by_author(app_identity.public_key())
            .await
            .len(),
        1
    );
    assert_eq!(
        relay_b
            .published_events_by_author(app_identity.public_key())
            .await
            .len(),
        1
    );

    let diff = diff_live_nip89(&runtime).await?;
    assert_eq!(diff.status, MycDiscoveryLiveStatus::Matched);
    assert_eq!(diff.relay_summary.matched_relays.len(), 2);
    assert!(diff.relay_summary.missing_relays.is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_skips_when_live_handler_matches() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    publish_nip89_event(&runtime).await?;
    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    let refreshed = refresh_nip89(&runtime, false).await?;

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Matched);
    assert!(refreshed.differing_fields.is_empty());
    assert_eq!(refreshed.live_groups.len(), 1);
    assert!(refreshed.published.is_none());
    assert_eq!(refreshed.repair_summary.repaired, 0);
    assert_eq!(refreshed.repair_summary.failed, 0);
    assert_eq!(refreshed.repair_summary.unchanged, 1);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.remaining_repair_relays, Vec::<String>::new());
    assert_eq!(refreshed.repair_results.len(), 1);
    assert_eq!(
        refreshed.repair_results[0].outcome,
        MycDiscoveryRepairOutcome::Unchanged
    );

    let audit = wait_for_operation_audit_count(&runtime, 4).await?;
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Matched);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerRepair
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Matched);
    assert_eq!(
        audit[3].operation,
        MycOperationAuditKind::DiscoveryHandlerRefresh
    );
    assert_eq!(audit[3].outcome, MycOperationAuditOutcome::Skipped);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_republishes_when_live_handler_drifted() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let mut drifted_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    drifted_spec.identifier = Some("myc".to_owned());
    drifted_spec.relays = vec!["wss://wrong.example.com".to_owned()];
    drifted_spec.nostrconnect_url =
        Some("https://wrong.example.com/connect?uri=nostrconnect%3A%2F%2Fstale".to_owned());
    let mut metadata = RadrootsNostrMetadata::default();
    metadata.name = Some("stale".to_owned());
    drifted_spec.metadata = Some(metadata);
    publish_handler_event(relay.url(), &app_identity, &drifted_spec).await?;
    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let refreshed = refresh_nip89(&runtime, false).await?;

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Drifted);
    assert_eq!(refreshed.live_groups.len(), 1);
    assert!(refreshed.published.is_some());
    assert_eq!(refreshed.repair_summary.repaired, 1);
    assert_eq!(refreshed.repair_summary.failed, 0);
    assert_eq!(refreshed.repair_summary.unchanged, 0);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.remaining_repair_relays, Vec::<String>::new());
    assert_eq!(refreshed.repair_results.len(), 1);
    assert_eq!(
        refreshed.repair_results[0].outcome,
        MycDiscoveryRepairOutcome::Repaired
    );
    assert!(
        refreshed
            .differing_fields
            .iter()
            .any(|field| field == "relays" || field == "nostrconnect_url" || field == "metadata")
    );

    let audit = wait_for_operation_audit_count(&runtime, 3).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Drifted);
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerRepair
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Succeeded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_repairs_drifted_relays_without_force_when_other_relays_match()
-> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::ExplicitUser,
    );
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let matched_event = MycDiscoveryContext::from_runtime(&runtime)?
        .build_signed_handler_event()
        .expect("matched event");
    publish_signed_event(relay_a.url(), &app_identity, &matched_event).await?;

    let mut drifted_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    drifted_spec.identifier = Some("myc".to_owned());
    drifted_spec.relays = vec!["wss://stale.example.com".to_owned()];
    publish_handler_event(relay_b.url(), &app_identity, &drifted_spec).await?;

    relay_a
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    relay_b
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    relay_b
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let refreshed = refresh_nip89(&runtime, false).await?;
    let published = refreshed.published.expect("published output");

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Conflicted);
    assert_eq!(published.publish_relays, vec![relay_b.url().to_owned()]);
    assert_eq!(published.relay_count, 1);
    assert_eq!(published.acknowledged_relay_count, 1);
    assert_eq!(refreshed.repair_summary.repaired, 1);
    assert_eq!(refreshed.repair_summary.failed, 0);
    assert_eq!(refreshed.repair_summary.unchanged, 1);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.remaining_repair_relays, Vec::<String>::new());
    assert_eq!(refreshed.repair_results.len(), 2);
    assert_eq!(
        refreshed
            .repair_results
            .iter()
            .find(|result| result.relay_url == relay_a.url())
            .expect("matched relay result")
            .outcome,
        MycDiscoveryRepairOutcome::Unchanged
    );
    assert_eq!(
        refreshed
            .repair_results
            .iter()
            .find(|result| result.relay_url == relay_b.url())
            .expect("repaired relay result")
            .outcome,
        MycDiscoveryRepairOutcome::Repaired
    );

    relay_b
        .wait_for_published_events_by_author(app_identity.public_key(), 2)
        .await?;
    assert_eq!(
        relay_a
            .published_events_by_author(app_identity.public_key())
            .await
            .len(),
        1
    );
    assert_eq!(
        relay_b
            .published_events_by_author(app_identity.public_key())
            .await
            .len(),
        2
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_reports_remaining_relays_after_mixed_targeted_repair() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::ExplicitUser,
    );
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    relay_a
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    relay_b
        .queue_publish_outcomes(app_identity.public_key(), &[false])
        .await;

    let refreshed = refresh_nip89(&runtime, false).await?;
    let published = refreshed.published.expect("published output");

    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Missing);
    assert_eq!(
        published.publish_relays,
        vec![relay_a.url().to_owned(), relay_b.url().to_owned()]
    );
    assert_eq!(published.relay_count, 2);
    assert_eq!(published.acknowledged_relay_count, 1);
    assert_eq!(published.relay_results.len(), 2);
    assert_eq!(refreshed.repair_summary.repaired, 1);
    assert_eq!(refreshed.repair_summary.failed, 1);
    assert_eq!(refreshed.repair_summary.unchanged, 0);
    assert_eq!(refreshed.repair_summary.skipped, 0);
    assert_eq!(refreshed.repair_results.len(), 2);
    assert_eq!(
        refreshed.remaining_repair_relays,
        vec![relay_b.url().to_owned()]
    );

    let repaired = refreshed
        .repair_results
        .iter()
        .find(|result| result.relay_url == relay_a.url())
        .expect("repaired relay result");
    assert_eq!(repaired.outcome, MycDiscoveryRepairOutcome::Repaired);

    let failed = refreshed
        .repair_results
        .iter()
        .find(|result| result.relay_url == relay_b.url())
        .expect("failed relay result");
    assert_eq!(failed.outcome, MycDiscoveryRepairOutcome::Failed);
    assert!(
        failed
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("blocked by test relay")
    );

    relay_a
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    assert_eq!(
        relay_b
            .published_events_by_author(app_identity.public_key())
            .await
            .len(),
        0
    );

    let diff = diff_live_nip89(&runtime).await?;
    assert_eq!(diff.status, MycDiscoveryLiveStatus::Matched);
    assert_eq!(
        diff.relay_summary.matched_relays,
        vec![relay_a.url().to_owned()]
    );
    assert_eq!(
        diff.relay_summary.missing_relays,
        vec![relay_b.url().to_owned()]
    );

    let audit = wait_for_operation_audit_count(&runtime, 4).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Missing);
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerPublish
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerRepair
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(audit[2].relay_url.as_deref(), Some(relay_a.url()));
    assert_eq!(
        audit[3].operation,
        MycOperationAuditKind::DiscoveryHandlerRepair
    );
    assert_eq!(audit[3].outcome, MycOperationAuditOutcome::Rejected);
    assert_eq!(audit[3].relay_url.as_deref(), Some(relay_b.url()));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diff_live_nip89_reports_conflicted_when_live_groups_disagree() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let mut first_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    first_spec.identifier = Some("myc".to_owned());
    first_spec.relays = vec!["wss://relay-a.example.com".to_owned()];
    publish_handler_event(relay.url(), &app_identity, &first_spec).await?;

    let mut second_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    second_spec.identifier = Some("myc".to_owned());
    second_spec.relays = vec!["wss://relay-b.example.com".to_owned()];
    publish_handler_event(relay.url(), &app_identity, &second_spec).await?;

    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 2)
        .await?;

    let diff = diff_live_nip89(&runtime).await?;

    assert_eq!(diff.status, MycDiscoveryLiveStatus::Conflicted);
    assert_eq!(diff.differing_fields, vec!["live_groups".to_owned()]);
    assert_eq!(diff.live_groups.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn diff_live_nip89_surfaces_relay_divergence_with_provenance() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[relay_a.url(), relay_b.url()],
        MycConnectionApproval::ExplicitUser,
    );
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let matched_event = MycDiscoveryContext::from_runtime(&runtime)?
        .build_signed_handler_event()
        .expect("matched event");
    publish_signed_event(relay_a.url(), &app_identity, &matched_event).await?;

    let mut drifted_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    drifted_spec.identifier = Some("myc".to_owned());
    drifted_spec.relays = vec!["wss://stale.example.com".to_owned()];
    let mut drifted_metadata = RadrootsNostrMetadata::default();
    drifted_metadata.name = Some("stale".to_owned());
    drifted_spec.metadata = Some(drifted_metadata);
    publish_handler_event(relay_b.url(), &app_identity, &drifted_spec).await?;

    relay_a
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;
    relay_b
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    let diff = diff_live_nip89(&runtime).await?;

    assert_eq!(diff.status, MycDiscoveryLiveStatus::Conflicted);
    assert_eq!(diff.live_groups.len(), 2);
    assert_eq!(diff.relay_states.len(), 2);
    assert_eq!(diff.relay_summary.total_relays, 2);
    assert_eq!(
        diff.relay_summary.matched_relays,
        vec![relay_a.url().to_owned()]
    );
    assert_eq!(
        diff.relay_summary.drifted_relays,
        vec![relay_b.url().to_owned()]
    );
    assert!(diff.relay_summary.unavailable_relays.is_empty());
    assert!(diff.relay_summary.missing_relays.is_empty());
    assert!(diff.relay_summary.conflicted_relays.is_empty());

    let matched_relay = diff
        .relay_states
        .iter()
        .find(|relay_state| relay_state.relay_url == relay_a.url())
        .expect("matched relay");
    assert_eq!(
        matched_relay.fetch_status,
        MycDiscoveryRelayFetchStatus::Available
    );
    assert_eq!(
        matched_relay.live_status,
        Some(MycDiscoveryLiveStatus::Matched)
    );
    assert_eq!(matched_relay.live_groups.len(), 1);
    assert_eq!(
        matched_relay.live_groups[0].source_relays,
        vec![relay_a.url().to_owned()]
    );

    let drifted_relay = diff
        .relay_states
        .iter()
        .find(|relay_state| relay_state.relay_url == relay_b.url())
        .expect("drifted relay");
    assert_eq!(
        drifted_relay.fetch_status,
        MycDiscoveryRelayFetchStatus::Available
    );
    assert_eq!(
        drifted_relay.live_status,
        Some(MycDiscoveryLiveStatus::Drifted)
    );
    assert_eq!(drifted_relay.live_groups.len(), 1);
    assert_eq!(
        drifted_relay.live_groups[0].source_relays,
        vec![relay_b.url().to_owned()]
    );

    let live_group_relays = diff
        .live_groups
        .iter()
        .map(|group| group.source_relays.clone())
        .collect::<Vec<_>>();
    assert!(live_group_relays.contains(&vec![relay_a.url().to_owned()]));
    assert!(live_group_relays.contains(&vec![relay_b.url().to_owned()]));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_requires_force_when_any_discovery_relay_is_unavailable() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let unavailable_relay = unavailable_relay_url()?;
    let test_runtime = MycTestRuntime::new_with_discovery_relays(
        &[relay.url(), unavailable_relay.as_str()],
        MycConnectionApproval::ExplicitUser,
    );
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let diff = diff_live_nip89(&runtime).await?;
    assert_eq!(diff.status, MycDiscoveryLiveStatus::Missing);
    assert_eq!(
        diff.relay_summary.unavailable_relays,
        vec![unavailable_relay.clone()]
    );
    assert_eq!(
        diff.relay_summary.missing_relays,
        vec![relay.url().to_owned()]
    );

    let unavailable_state = diff
        .relay_states
        .iter()
        .find(|relay_state| relay_state.relay_url == unavailable_relay)
        .expect("unavailable relay");
    assert_eq!(
        unavailable_state.fetch_status,
        MycDiscoveryRelayFetchStatus::Unavailable
    );
    assert_eq!(unavailable_state.live_status, None);
    assert!(unavailable_state.fetch_error.is_some());

    let error = refresh_nip89(&runtime, false)
        .await
        .expect_err("refresh without force should fail when a relay is unavailable");
    assert!(error.to_string().contains("unavailable"));

    let audit = wait_for_operation_audit_count(&runtime, 4).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerFetch
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Unavailable);
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerFetch
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Unavailable);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Missing);
    assert_eq!(
        audit[3].operation,
        MycOperationAuditKind::DiscoveryHandlerRefresh
    );
    assert_eq!(audit[3].outcome, MycOperationAuditOutcome::Unavailable);

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let refreshed = refresh_nip89(&runtime, true).await?;
    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Missing);
    assert_eq!(
        refreshed.relay_summary.unavailable_relays,
        vec![unavailable_relay.clone()]
    );
    assert!(refreshed.published.is_some());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_nip89_requires_force_when_live_handler_is_conflicted() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let test_runtime =
        MycTestRuntime::new_with_discovery(relay.url(), MycConnectionApproval::ExplicitUser);
    let runtime = test_runtime.runtime;
    let app_identity = RadrootsIdentity::load_from_path_auto(
        runtime
            .config()
            .discovery
            .app_identity_path
            .as_ref()
            .expect("app identity path"),
    )?;

    let mut first_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    first_spec.identifier = Some("myc".to_owned());
    first_spec.relays = vec!["wss://relay-a.example.com".to_owned()];
    publish_handler_event(relay.url(), &app_identity, &first_spec).await?;

    let mut second_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    second_spec.identifier = Some("myc".to_owned());
    second_spec.relays = vec!["wss://relay-b.example.com".to_owned()];
    publish_handler_event(relay.url(), &app_identity, &second_spec).await?;

    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 2)
        .await?;

    let error = refresh_nip89(&runtime, false)
        .await
        .expect_err("conflicted refresh without force should fail");
    assert!(
        error
            .to_string()
            .contains("live discovery handler state is conflicted")
    );

    let audit = wait_for_operation_audit_count(&runtime, 2).await?;
    assert_eq!(
        audit[0].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[0].outcome, MycOperationAuditOutcome::Conflicted);
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerRefresh
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Conflicted);

    relay
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    let refreshed = refresh_nip89(&runtime, true).await?;
    assert_eq!(refreshed.status, MycDiscoveryLiveStatus::Conflicted);
    assert_eq!(refreshed.live_groups.len(), 2);
    assert!(refreshed.published.is_some());

    Ok(())
}
