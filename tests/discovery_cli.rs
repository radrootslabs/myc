use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::{ClientMessage, Event, Filter, JsonUtil, PublicKey, RelayMessage, SubscriptionId};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrClient, RadrootsNostrMetadata,
    radroots_nostr_build_application_handler_event,
};
use radroots_nostr_connect::prelude::{RadrootsNostrConnectBunkerUri, RadrootsNostrConnectUri};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::time::timeout;
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
        }
        notify.notify_waiters();
    }

    Ok((ok_message, subscriber_messages))
}

fn write_identity(path: &Path, secret_key: &str) {
    RadrootsIdentity::from_secret_key_str(secret_key)
        .expect("identity")
        .save_json(path)
        .expect("save identity");
}

fn write_config(
    path: &Path,
    state_dir: &Path,
    signer_identity_path: &Path,
    user_identity_path: &Path,
    app_identity_path: &Path,
    relay_urls: &[&str],
) {
    let relay_list = relay_urls
        .iter()
        .map(|relay| format!("\"{relay}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(
        r#"[service]
instance_name = "myc"

[logging]
filter = "info,myc=info"

[paths]
state_dir = "{state_dir}"
signer_identity_path = "{signer_identity_path}"
user_identity_path = "{user_identity_path}"

[audit]
default_read_limit = 200
max_active_file_bytes = 262144
max_archived_files = 8

[discovery]
enabled = true
domain = "signer.example.com"
handler_identifier = "myc"
app_identity_path = "{app_identity_path}"
public_relays = [{relay_list}]
publish_relays = [{relay_list}]
nostrconnect_url_template = "https://signer.example.com/connect?uri=<nostrconnect>"
nip05_output_path = "{nip05_output_path}"

[discovery.metadata]
name = "myc"
display_name = "Mycorrhiza"
about = "NIP-46 signer"
website = "https://signer.example.com"
picture = "https://signer.example.com/logo.png"

[policy]
connection_approval = "explicit_user"

[transport]
enabled = false
connect_timeout_secs = 10
relays = []
"#,
        state_dir = state_dir.display(),
        signer_identity_path = signer_identity_path.display(),
        user_identity_path = user_identity_path.display(),
        app_identity_path = app_identity_path.display(),
        relay_list = relay_list,
        nip05_output_path = state_dir.join("public/.well-known/nostr.json").display(),
    );
    fs::write(path, config).expect("write config");
}

fn run_myc(config_path: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_myc"))
        .arg("--config")
        .arg(config_path)
        .args(args)
        .output()?)
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

#[test]
fn export_bundle_and_verify_bundle_work_through_the_cli() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let bundle_dir = temp.path().join("bundle");

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    write_identity(
        &app_identity_path,
        "3333333333333333333333333333333333333333333333333333333333333333",
    );
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &["wss://relay.example.com"],
    );

    let export = run_myc(
        &config_path,
        &[
            "discovery",
            "export-bundle",
            "--out",
            bundle_dir.to_str().unwrap(),
        ],
    )?;

    assert!(
        export.status.success(),
        "export-bundle failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let export_output: Value = serde_json::from_slice(&export.stdout)?;
    assert_eq!(export_output["manifest"]["domain"], "signer.example.com");
    assert!(bundle_dir.join("bundle.json").exists());
    assert!(bundle_dir.join(".well-known/nostr.json").exists());
    assert!(bundle_dir.join("nip89-handler.json").exists());

    let verify = run_myc(
        &config_path,
        &[
            "discovery",
            "verify-bundle",
            "--dir",
            bundle_dir.to_str().unwrap(),
        ],
    )?;

    assert!(
        verify.status.success(),
        "verify-bundle failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_output: Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verify_output["manifest"]["domain"], "signer.example.com");
    assert_eq!(
        verify_output["manifest"]["nip05_relative_path"],
        ".well-known/nostr.json"
    );
    assert_eq!(
        verify_output["manifest"]["nip89_relative_path"],
        "nip89-handler.json"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_sync_commands_work_through_the_cli() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay.url()],
    );

    let inspect_missing = run_myc(&config_path, &["discovery", "inspect-live-nip89"])?;
    assert!(
        inspect_missing.status.success(),
        "inspect-live-nip89 failed: {}",
        String::from_utf8_lossy(&inspect_missing.stderr)
    );
    let inspect_missing_output: Value = serde_json::from_slice(&inspect_missing.stdout)?;
    assert_eq!(
        inspect_missing_output["live_groups"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        inspect_missing_output["relay_states"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        refresh.status.success(),
        "refresh-nip89 failed: {}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    let refresh_output: Value = serde_json::from_slice(&refresh.stdout)?;
    assert_eq!(refresh_output["status"], "missing");
    assert!(refresh_output["published"].is_object());

    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    let inspect_live = run_myc(&config_path, &["discovery", "inspect-live-nip89"])?;
    assert!(
        inspect_live.status.success(),
        "inspect-live-nip89 after refresh failed: {}",
        String::from_utf8_lossy(&inspect_live.stderr)
    );
    let inspect_live_output: Value = serde_json::from_slice(&inspect_live.stdout)?;
    assert_eq!(
        inspect_live_output["live_groups"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        inspect_live_output["live_groups"][0]["source_relays"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let diff = run_myc(&config_path, &["discovery", "diff-live-nip89"])?;
    assert!(
        diff.status.success(),
        "diff-live-nip89 failed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let diff_output: Value = serde_json::from_slice(&diff.stdout)?;
    assert_eq!(diff_output["status"], "matched");
    assert_eq!(diff_output["live_groups"].as_array().unwrap().len(), 1);
    assert_eq!(
        diff_output["relay_summary"]["matched_relays"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        diff_output["relay_states"][0]["fetch_status"],
        Value::String("available".to_owned())
    );
    assert_eq!(
        diff_output["relay_states"][0]["live_status"],
        Value::String("matched".to_owned())
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicted_refresh_requires_force_through_the_cli() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay.url()],
    );

    let mut first_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    first_spec.identifier = Some("myc".to_owned());
    first_spec.relays = vec!["wss://relay-a.example.com".to_owned()];
    publish_handler_event(relay.url(), &app_identity, &first_spec).await?;

    let mut second_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    second_spec.identifier = Some("myc".to_owned());
    second_spec.relays = vec!["wss://relay-b.example.com".to_owned()];
    let mut metadata = RadrootsNostrMetadata::default();
    metadata.name = Some("conflict".to_owned());
    second_spec.metadata = Some(metadata);
    publish_handler_event(relay.url(), &app_identity, &second_spec).await?;

    relay
        .wait_for_published_events_by_author(app_identity.public_key(), 2)
        .await?;

    let diff = run_myc(&config_path, &["discovery", "diff-live-nip89"])?;
    assert!(
        diff.status.success(),
        "diff-live-nip89 failed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let diff_output: Value = serde_json::from_slice(&diff.stdout)?;
    assert_eq!(diff_output["status"], "conflicted");
    assert_eq!(diff_output["live_groups"].as_array().unwrap().len(), 2);
    assert_eq!(
        diff_output["relay_summary"]["conflicted_relays"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        diff_output["relay_summary"]["unavailable_relays"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        !refresh.status.success(),
        "refresh-nip89 unexpectedly succeeded: {}",
        String::from_utf8_lossy(&refresh.stdout)
    );
    assert!(
        String::from_utf8_lossy(&refresh.stderr).contains("conflicted"),
        "unexpected refresh stderr: {}",
        String::from_utf8_lossy(&refresh.stderr)
    );

    let forced_refresh = run_myc(&config_path, &["discovery", "refresh-nip89", "--force"])?;
    assert!(
        forced_refresh.status.success(),
        "refresh-nip89 --force failed: {}",
        String::from_utf8_lossy(&forced_refresh.stderr)
    );
    let forced_refresh_output: Value = serde_json::from_slice(&forced_refresh.stdout)?;
    assert_eq!(forced_refresh_output["status"], "conflicted");
    assert!(forced_refresh_output["published"].is_object());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_reports_partial_repair_and_audit_summary_through_the_cli() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay_a.url(), relay_b.url()],
    );

    relay_a
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    relay_b
        .queue_publish_outcomes(app_identity.public_key(), &[false])
        .await;

    let refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        refresh.status.success(),
        "refresh-nip89 failed: {}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    let refresh_output: Value = serde_json::from_slice(&refresh.stdout)?;
    assert_eq!(refresh_output["status"], "missing");
    assert_eq!(refresh_output["repair_summary"]["repaired"], 1);
    assert_eq!(refresh_output["repair_summary"]["failed"], 1);
    assert_eq!(refresh_output["repair_summary"]["unchanged"], 0);
    assert_eq!(refresh_output["repair_summary"]["skipped"], 0);
    assert_eq!(
        refresh_output["remaining_repair_relays"],
        Value::Array(vec![Value::String(relay_b.url().to_owned())])
    );
    assert_eq!(
        refresh_output["published"]["acknowledged_relay_count"],
        Value::from(1_u64)
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

    let audit_summary = run_myc(&config_path, &["audit", "summary", "--scope", "operation"])?;
    assert!(
        audit_summary.status.success(),
        "audit summary failed: {}",
        String::from_utf8_lossy(&audit_summary.stderr)
    );
    let audit_summary_output: Value = serde_json::from_slice(&audit_summary.stdout)?;
    assert_eq!(
        audit_summary_output["runtime_aggregate_publish_rejection_count"],
        Value::from(0_u64)
    );
    assert_eq!(
        audit_summary_output["runtime_repair_success_count"],
        Value::from(1_u64)
    );
    assert_eq!(
        audit_summary_output["runtime_repair_rejection_count"],
        Value::from(1_u64)
    );
    assert_eq!(
        audit_summary_output["runtime_operation_by_kind"]["discovery_handler_publish"]["succeeded"],
        Value::from(1_u64)
    );
    assert_eq!(
        audit_summary_output["runtime_operation_by_kind"]["discovery_handler_repair"]["rejected"],
        Value::from(1_u64)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_repair_attempt_commands_correlate_multiple_refresh_runs() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay_a.url(), relay_b.url()],
    );

    relay_a
        .queue_publish_outcomes(app_identity.public_key(), &[true])
        .await;
    relay_b
        .queue_publish_outcomes(app_identity.public_key(), &[false, true])
        .await;

    let first_refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        first_refresh.status.success(),
        "first refresh-nip89 failed: {}",
        String::from_utf8_lossy(&first_refresh.stderr)
    );
    let first_refresh_output: Value = serde_json::from_slice(&first_refresh.stdout)?;
    let first_attempt_id = first_refresh_output["attempt_id"]
        .as_str()
        .expect("first attempt id")
        .to_owned();
    assert_eq!(first_refresh_output["repair_summary"]["repaired"], 1);
    assert_eq!(first_refresh_output["repair_summary"]["failed"], 1);
    assert_eq!(
        first_refresh_output["remaining_repair_relays"],
        Value::Array(vec![Value::String(relay_b.url().to_owned())])
    );

    relay_a
        .wait_for_published_events_by_author(app_identity.public_key(), 1)
        .await?;

    let second_refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        second_refresh.status.success(),
        "second refresh-nip89 failed: {}",
        String::from_utf8_lossy(&second_refresh.stderr)
    );
    let second_refresh_output: Value = serde_json::from_slice(&second_refresh.stdout)?;
    let second_attempt_id = second_refresh_output["attempt_id"]
        .as_str()
        .expect("second attempt id")
        .to_owned();
    assert_ne!(first_attempt_id, second_attempt_id);
    assert_eq!(second_refresh_output["repair_summary"]["repaired"], 1);
    assert_eq!(second_refresh_output["repair_summary"]["failed"], 0);
    assert_eq!(second_refresh_output["repair_summary"]["unchanged"], 1);
    assert_eq!(
        second_refresh_output["remaining_repair_relays"],
        Value::Array(vec![])
    );

    let latest_attempt = run_myc(&config_path, &["audit", "latest-discovery-repair"])?;
    assert!(
        latest_attempt.status.success(),
        "latest-discovery-repair failed: {}",
        String::from_utf8_lossy(&latest_attempt.stderr)
    );
    let latest_attempt_output: Value = serde_json::from_slice(&latest_attempt.stdout)?;
    assert_eq!(
        latest_attempt_output["attempt_id"],
        Value::String(second_attempt_id.clone())
    );
    assert_eq!(
        latest_attempt_output["compare_outcome"],
        Value::String("matched".to_owned())
    );
    assert_eq!(
        latest_attempt_output["refresh_outcome"],
        Value::String("succeeded".to_owned())
    );
    assert_eq!(latest_attempt_output["repair_summary"]["repaired"], 1);
    assert_eq!(latest_attempt_output["repair_summary"]["failed"], 0);
    assert_eq!(latest_attempt_output["repair_summary"]["unchanged"], 1);
    assert_eq!(
        latest_attempt_output["remaining_repair_relays"],
        Value::Array(vec![])
    );

    let first_attempt_summary = run_myc(
        &config_path,
        &[
            "audit",
            "discovery-repair-attempt",
            "--attempt-id",
            first_attempt_id.as_str(),
        ],
    )?;
    assert!(
        first_attempt_summary.status.success(),
        "discovery-repair-attempt summary failed: {}",
        String::from_utf8_lossy(&first_attempt_summary.stderr)
    );
    let first_attempt_summary_output: Value =
        serde_json::from_slice(&first_attempt_summary.stdout)?;
    assert_eq!(
        first_attempt_summary_output["attempt_id"],
        Value::String(first_attempt_id.clone())
    );
    assert_eq!(
        first_attempt_summary_output["refresh_outcome"],
        Value::String("succeeded".to_owned())
    );
    assert_eq!(
        first_attempt_summary_output["repair_summary"]["repaired"],
        1
    );
    assert_eq!(first_attempt_summary_output["repair_summary"]["failed"], 1);
    assert_eq!(
        first_attempt_summary_output["failed_relays"],
        Value::Array(vec![Value::String(relay_b.url().to_owned())])
    );
    assert_eq!(
        first_attempt_summary_output["remaining_repair_relays"],
        Value::Array(vec![Value::String(relay_b.url().to_owned())])
    );

    let first_attempt_records = run_myc(
        &config_path,
        &[
            "audit",
            "discovery-repair-attempt",
            "--attempt-id",
            first_attempt_id.as_str(),
            "--view",
            "records",
        ],
    )?;
    assert!(
        first_attempt_records.status.success(),
        "discovery-repair-attempt records failed: {}",
        String::from_utf8_lossy(&first_attempt_records.stderr)
    );
    let first_attempt_records_output: Value =
        serde_json::from_slice(&first_attempt_records.stdout)?;
    let record_attempt_ids = first_attempt_records_output["runtime_operation_audit"]
        .as_array()
        .expect("attempt records")
        .iter()
        .map(|record| record["attempt_id"].as_str().expect("record attempt id"))
        .collect::<Vec<_>>();
    assert!(!record_attempt_ids.is_empty());
    assert!(
        record_attempt_ids
            .iter()
            .all(|attempt_id| *attempt_id == first_attempt_id)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_diff_surfaces_relay_provenance_through_the_cli() -> TestResult<()> {
    let relay_a = TestRelay::spawn().await?;
    let relay_b = TestRelay::spawn().await?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let signer_identity = RadrootsIdentity::from_secret_key_str(
        "1111111111111111111111111111111111111111111111111111111111111111",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay_a.url(), relay_b.url()],
    );

    let mut matched_spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133]);
    matched_spec.identifier = Some("myc".to_owned());
    matched_spec.relays = vec![relay_a.url().to_owned(), relay_b.url().to_owned()];
    let bunker_uri = RadrootsNostrConnectUri::Bunker(RadrootsNostrConnectBunkerUri {
        remote_signer_public_key: signer_identity.public_key(),
        relays: vec![
            relay_a.url().parse().expect("relay a url"),
            relay_b.url().parse().expect("relay b url"),
        ],
        secret: None,
    })
    .to_string();
    let encoded_bunker_uri: String =
        url::form_urlencoded::byte_serialize(bunker_uri.as_bytes()).collect();
    matched_spec.nostrconnect_url = Some(format!(
        "https://signer.example.com/connect?uri={encoded_bunker_uri}"
    ));
    let mut matched_metadata = RadrootsNostrMetadata::default();
    matched_metadata.name = Some("myc".to_owned());
    matched_metadata.display_name = Some("Mycorrhiza".to_owned());
    matched_metadata.about = Some("NIP-46 signer".to_owned());
    matched_metadata.website = Some("https://signer.example.com".to_owned());
    matched_metadata.picture = Some("https://signer.example.com/logo.png".to_owned());
    matched_spec.metadata = Some(matched_metadata);
    publish_handler_event(relay_a.url(), &app_identity, &matched_spec).await?;

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

    let inspect = run_myc(&config_path, &["discovery", "inspect-live-nip89"])?;
    assert!(
        inspect.status.success(),
        "inspect-live-nip89 failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_output: Value = serde_json::from_slice(&inspect.stdout)?;
    assert_eq!(inspect_output["live_groups"].as_array().unwrap().len(), 2);
    assert_eq!(inspect_output["relay_states"].as_array().unwrap().len(), 2);
    let group_relays = inspect_output["live_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| {
            group["source_relays"]
                .as_array()
                .unwrap()
                .iter()
                .map(|relay| relay.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(
        group_relays
            .iter()
            .any(|relays| relays == &vec![relay_a.url().to_owned()])
    );
    assert!(
        group_relays
            .iter()
            .any(|relays| relays == &vec![relay_b.url().to_owned()])
    );

    let diff = run_myc(&config_path, &["discovery", "diff-live-nip89"])?;
    assert!(
        diff.status.success(),
        "diff-live-nip89 failed: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let diff_output: Value = serde_json::from_slice(&diff.stdout)?;
    assert_eq!(diff_output["status"], "conflicted");
    assert_eq!(
        diff_output["relay_summary"]["matched_relays"],
        Value::Array(vec![Value::String(relay_a.url().to_owned())])
    );
    assert_eq!(
        diff_output["relay_summary"]["drifted_relays"],
        Value::Array(vec![Value::String(relay_b.url().to_owned())])
    );
    assert_eq!(
        diff_output["relay_summary"]["conflicted_relays"],
        Value::Array(vec![])
    );
    assert_eq!(diff_output["relay_states"].as_array().unwrap().len(), 2);
    for relay_state in diff_output["relay_states"].as_array().unwrap() {
        assert_eq!(
            relay_state["fetch_status"],
            Value::String("available".to_owned())
        );
        assert!(relay_state["live_status"].is_string());
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_requires_force_when_a_discovery_relay_is_unavailable_through_the_cli()
-> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let unavailable_relay = unavailable_relay_url()?;
    let temp = tempfile::tempdir()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let signer_identity_path = temp.path().join("signer.json");
    let user_identity_path = temp.path().join("user.json");
    let app_identity_path = temp.path().join("app.json");
    let app_identity = RadrootsIdentity::from_secret_key_str(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;

    write_identity(
        &signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_identity(
        &user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    app_identity.save_json(&app_identity_path)?;
    write_config(
        &config_path,
        &state_dir,
        &signer_identity_path,
        &user_identity_path,
        &app_identity_path,
        &[relay.url(), unavailable_relay.as_str()],
    );

    let inspect = run_myc(&config_path, &["discovery", "inspect-live-nip89"])?;
    assert!(
        inspect.status.success(),
        "inspect-live-nip89 failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_output: Value = serde_json::from_slice(&inspect.stdout)?;
    assert_eq!(inspect_output["live_groups"].as_array().unwrap().len(), 0);
    assert_eq!(inspect_output["relay_states"].as_array().unwrap().len(), 2);
    assert!(
        inspect_output["relay_states"]
            .as_array()
            .unwrap()
            .iter()
            .any(|relay_state| {
                relay_state["relay_url"] == Value::String(unavailable_relay.clone())
                    && relay_state["fetch_status"] == Value::String("unavailable".to_owned())
                    && relay_state["live_status"].is_null()
                    && relay_state["fetch_error"].is_string()
            })
    );

    let refresh = run_myc(&config_path, &["discovery", "refresh-nip89"])?;
    assert!(
        !refresh.status.success(),
        "refresh-nip89 unexpectedly succeeded: {}",
        String::from_utf8_lossy(&refresh.stdout)
    );
    assert!(
        String::from_utf8_lossy(&refresh.stderr).contains("unavailable"),
        "unexpected refresh stderr: {}",
        String::from_utf8_lossy(&refresh.stderr)
    );

    let forced_refresh = run_myc(&config_path, &["discovery", "refresh-nip89", "--force"])?;
    assert!(
        forced_refresh.status.success(),
        "refresh-nip89 --force failed: {}",
        String::from_utf8_lossy(&forced_refresh.stderr)
    );
    let forced_refresh_output: Value = serde_json::from_slice(&forced_refresh.stdout)?;
    assert_eq!(forced_refresh_output["status"], "missing");
    assert_eq!(
        forced_refresh_output["relay_summary"]["unavailable_relays"],
        Value::Array(vec![Value::String(unavailable_relay.clone())])
    );
    assert!(forced_refresh_output["published"].is_object());

    Ok(())
}
