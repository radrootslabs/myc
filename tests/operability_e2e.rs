use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use myc::{
    MycActiveIdentity, MycConfig, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
    MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord, MycRuntime,
    MycRuntimeAuditBackend, MycRuntimeStatus, MycSignerStateBackend, MycTransportDeliveryPolicy,
    collect_status_full,
};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrEventBuilder, RadrootsNostrKind, RadrootsNostrRelayUrl,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerConnectionDraft,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::sleep;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct TestRelay {
    url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestRelay {
    async fn spawn() -> TestResult<Self> {
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
                            let _ = tokio_tungstenite::accept_async(stream).await;
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

fn write_test_identity(path: &Path, secret_key: &str) {
    let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity from secret");
    myc::identity_files::store_encrypted_identity(path, &identity).expect("write identity");
}

fn signed_delivery_event(identity: &MycActiveIdentity, content: &str) -> nostr::Event {
    identity
        .sign_event_builder(
            RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), content),
            "operability delivery test event",
        )
        .expect("sign event")
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn build_runtime<F>(configure: F) -> MycRuntime
where
    F: FnOnce(&mut MycConfig),
{
    let temp = tempfile::tempdir().expect("tempdir").keep();
    let mut config = MycConfig::default();
    config.paths.state_dir = PathBuf::from(&temp).join("state");
    config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
    config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
    config.transport.connect_timeout_secs = 1;
    write_test_identity(
        &config.paths.signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_test_identity(
        &config.paths.user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    configure(&mut config);
    MycRuntime::bootstrap(config).expect("runtime")
}

#[tokio::test]
async fn status_is_unready_when_transport_is_disabled() -> TestResult<()> {
    let runtime = build_runtime(|_| {});

    let status = collect_status_full(&runtime).await?;

    assert_eq!(status.status, MycRuntimeStatus::Unready);
    assert!(!status.ready);
    assert_eq!(status.transport.status, MycRuntimeStatus::Unready);
    assert!(
        status
            .reasons
            .iter()
            .any(|reason| reason == "transport is disabled")
    );
    Ok(())
}

#[tokio::test]
async fn status_is_degraded_but_ready_when_any_policy_has_one_live_relay() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let hanging = HangingRelay::spawn(Duration::from_secs(5)).await?;
    let runtime = build_runtime(|config| {
        config.transport.enabled = true;
        config.transport.relays = vec![relay.url().to_owned(), hanging.url().to_owned()];
        config.transport.delivery_policy = MycTransportDeliveryPolicy::Any;
    });

    let status = collect_status_full(&runtime).await?;

    assert_eq!(status.status, MycRuntimeStatus::Degraded);
    assert!(status.ready);
    assert_eq!(status.transport.status, MycRuntimeStatus::Degraded);
    assert_eq!(status.transport.available_relay_count, 1);
    assert_eq!(status.transport.unavailable_relay_count, 1);
    Ok(())
}

#[tokio::test]
async fn status_is_unready_when_all_policy_cannot_be_satisfied() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let hanging = HangingRelay::spawn(Duration::from_secs(5)).await?;
    let runtime = build_runtime(|config| {
        config.transport.enabled = true;
        config.transport.relays = vec![relay.url().to_owned(), hanging.url().to_owned()];
        config.transport.delivery_policy = MycTransportDeliveryPolicy::All;
    });

    let status = collect_status_full(&runtime).await?;

    assert_eq!(status.status, MycRuntimeStatus::Unready);
    assert!(!status.ready);
    assert_eq!(status.transport.status, MycRuntimeStatus::Unready);
    assert_eq!(status.transport.available_relay_count, 1);
    assert_eq!(status.transport.required_available_relays, 2);
    Ok(())
}

#[tokio::test]
async fn status_is_unready_when_critical_delivery_job_is_blocked() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let relay_url: RadrootsNostrRelayUrl = relay.url().parse()?;
    let runtime = build_runtime(|config| {
        config.transport.enabled = true;
        config.transport.relays = vec![relay.url().to_owned()];
    });
    let client_identity = RadrootsIdentity::from_secret_key_str(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?;
    let manager = runtime.signer_manager()?;
    let connection = manager.register_connection(
        RadrootsNostrSignerConnectionDraft::new(
            client_identity.public_key(),
            runtime.user_public_identity(),
        )
        .with_connect_secret("blocked-secret")
        .with_relays(vec![relay_url.clone()])
        .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
    )?;
    let workflow = manager.begin_connect_secret_publish_finalization(&connection.connection_id)?;
    let outbox_record = MycDeliveryOutboxRecord::new(
        MycDeliveryOutboxKind::ListenerResponsePublish,
        signed_delivery_event(runtime.signer_identity(), "blocked-listener"),
        vec![relay_url],
    )?
    .with_connection_id(&connection.connection_id)
    .with_request_id("blocked-request")
    .with_signer_publish_workflow_id(&workflow.workflow_id);
    runtime.delivery_outbox_store().enqueue(&outbox_record)?;
    manager.cancel_publish_workflow(&workflow.workflow_id)?;

    let status = collect_status_full(&runtime).await?;

    assert_eq!(status.transport.status, MycRuntimeStatus::Healthy);
    assert_eq!(status.status, MycRuntimeStatus::Unready);
    assert!(!status.ready);
    assert_eq!(status.delivery_outbox.status, MycRuntimeStatus::Unready);
    assert!(!status.delivery_outbox.ready);
    assert_eq!(status.delivery_outbox.unfinished_job_count, 1);
    assert_eq!(status.delivery_outbox.critical_unfinished_job_count, 1);
    assert_eq!(status.delivery_outbox.blocked_job_count, 1);
    assert_eq!(status.delivery_outbox.critical_blocked_job_count, 1);
    assert!(
        status
            .reasons
            .iter()
            .any(|reason| reason == "1 critical delivery outbox job(s) are blocked")
    );
    Ok(())
}

#[tokio::test]
async fn status_is_degraded_but_ready_when_only_discovery_job_is_stuck() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let relay_url: RadrootsNostrRelayUrl = relay.url().parse()?;
    let runtime = build_runtime(|config| {
        config.transport.enabled = true;
        config.transport.relays = vec![relay.url().to_owned()];
        config.transport.connect_timeout_secs = 1;
    });
    let mut outbox_record = MycDeliveryOutboxRecord::new(
        MycDeliveryOutboxKind::DiscoveryHandlerPublish,
        signed_delivery_event(runtime.signer_identity(), "stuck-discovery"),
        vec![relay_url],
    )?
    .with_attempt_id("discovery-attempt-1");
    let old_timestamp = now_unix_secs().saturating_sub(30);
    outbox_record.created_at_unix = old_timestamp;
    outbox_record.updated_at_unix = old_timestamp;
    runtime.delivery_outbox_store().enqueue(&outbox_record)?;

    let status = collect_status_full(&runtime).await?;

    assert_eq!(status.transport.status, MycRuntimeStatus::Healthy);
    assert_eq!(status.status, MycRuntimeStatus::Degraded);
    assert!(status.ready);
    assert_eq!(status.delivery_outbox.status, MycRuntimeStatus::Degraded);
    assert!(status.delivery_outbox.ready);
    assert_eq!(status.delivery_outbox.unfinished_job_count, 1);
    assert_eq!(status.delivery_outbox.critical_unfinished_job_count, 0);
    assert_eq!(status.delivery_outbox.blocked_job_count, 1);
    assert_eq!(status.delivery_outbox.critical_blocked_job_count, 0);
    assert_eq!(status.delivery_outbox.oldest_blocked_age_secs, Some(30));
    assert!(
        status
            .reasons
            .iter()
            .any(|reason| reason == "1 non-critical delivery outbox job(s) are blocked")
    );
    Ok(())
}

#[tokio::test]
async fn status_surfaces_last_delivery_recovery_result() -> TestResult<()> {
    let runtime = build_runtime(|_| {});
    runtime.record_operation_audit(&MycOperationAuditRecord::new(
        MycOperationAuditKind::DeliveryRecovery,
        MycOperationAuditOutcome::Succeeded,
        None,
        None,
        2,
        2,
        "recovered 2/2 delivery outbox job(s); republished 1",
    ));

    let status = collect_status_full(&runtime).await?;
    let last_recovery = status
        .delivery_outbox
        .last_recovery
        .expect("last delivery recovery");

    assert_eq!(last_recovery.outcome, MycOperationAuditOutcome::Succeeded);
    assert_eq!(
        last_recovery.summary,
        "recovered 2/2 delivery outbox job(s); republished 1"
    );
    Ok(())
}

#[tokio::test]
async fn status_reports_sqlite_persistence_schema_state() -> TestResult<()> {
    let runtime = build_runtime(|config| {
        config.persistence.signer_state_backend = MycSignerStateBackend::Sqlite;
        config.persistence.runtime_audit_backend = MycRuntimeAuditBackend::Sqlite;
    });

    let status = collect_status_full(&runtime).await?;

    assert_eq!(
        status.persistence.signer_state.backend,
        MycSignerStateBackend::Sqlite
    );
    assert!(status.persistence.signer_state.exists);
    assert_eq!(
        status
            .persistence
            .signer_state
            .sqlite_schema
            .as_ref()
            .expect("signer sqlite schema")
            .applied_migration_count,
        Some(2)
    );
    assert_eq!(
        status
            .persistence
            .signer_state
            .sqlite_schema
            .as_ref()
            .expect("signer sqlite schema")
            .journal_mode
            .as_deref(),
        Some("wal")
    );
    assert_eq!(
        status
            .persistence
            .signer_state
            .sqlite_schema
            .as_ref()
            .expect("signer sqlite schema")
            .store_version,
        Some(1)
    );
    assert_eq!(
        status.persistence.runtime_audit.backend,
        MycRuntimeAuditBackend::Sqlite
    );
    assert!(status.persistence.runtime_audit.exists);
    assert_eq!(
        status
            .persistence
            .runtime_audit
            .sqlite_schema
            .as_ref()
            .expect("audit sqlite schema")
            .applied_migration_count,
        Some(1)
    );
    assert_eq!(
        status
            .persistence
            .runtime_audit
            .sqlite_schema
            .as_ref()
            .expect("audit sqlite schema")
            .latest_migration
            .as_deref(),
        Some("0000_runtime_audit_init")
    );
    assert_eq!(
        status
            .persistence
            .runtime_audit
            .sqlite_schema
            .as_ref()
            .expect("audit sqlite schema")
            .journal_mode
            .as_deref(),
        Some("wal")
    );
    Ok(())
}
