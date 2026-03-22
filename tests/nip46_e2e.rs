use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use myc::control;
use myc::{
    MycConfig, MycConnectionApproval, MycDiscoveryLiveStatus, MycOperationAuditKind,
    MycOperationAuditOutcome, MycOperationAuditRecord, MycRuntime, diff_live_nip89,
    fetch_live_nip89, publish_nip89_event, refresh_nip89,
};
use nostr::filter::MatchEventOptions;
use nostr::nips::nip44;
use nostr::nips::nip44::Version;
use nostr::{
    ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, PublicKey, RelayMessage,
    SecretKey, SubscriptionId, Tag, Timestamp,
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
use tokio::time::{sleep, timeout};
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
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.policy.connection_approval = approval;
        config.transport.enabled = true;
        config.transport.connect_timeout_secs = 1;
        config.transport.relays = vec![relay_url.to_owned()];
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
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = temp.path().join("state");
        config.paths.signer_identity_path = temp.path().join("signer.json");
        config.paths.user_identity_path = temp.path().join("user.json");
        config.policy.connection_approval = approval;
        config.transport.connect_timeout_secs = 1;
        config.discovery.enabled = true;
        config.discovery.domain = Some("signer.example.com".to_owned());
        config.discovery.public_relays = vec![relay_url.to_owned()];
        config.discovery.publish_relays = vec![relay_url.to_owned()];
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
    assert_eq!(runtime.operation_audit_store().list()?.len(), 1);

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
    assert!(output.live_event.is_none());

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
    let live_event = diff.live_event.expect("live event");
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
    assert_eq!(refreshed.differing_fields, vec!["live_event".to_owned()]);
    assert!(refreshed.live_event.is_none());
    assert!(refreshed.published.is_some());

    let audit = wait_for_operation_audit_count(&runtime, 2).await?;
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
    assert!(refreshed.published.is_none());

    let audit = wait_for_operation_audit_count(&runtime, 3).await?;
    assert_eq!(
        audit[1].operation,
        MycOperationAuditKind::DiscoveryHandlerCompare
    );
    assert_eq!(audit[1].outcome, MycOperationAuditOutcome::Matched);
    assert_eq!(
        audit[2].operation,
        MycOperationAuditKind::DiscoveryHandlerRefresh
    );
    assert_eq!(audit[2].outcome, MycOperationAuditOutcome::Skipped);

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
    assert!(refreshed.published.is_some());
    assert!(
        refreshed
            .differing_fields
            .iter()
            .any(|field| field == "relays" || field == "nostrconnect_url" || field == "metadata")
    );

    let audit = wait_for_operation_audit_count(&runtime, 2).await?;
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

    Ok(())
}
