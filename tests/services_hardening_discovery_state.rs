#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use myc::host_identity::RadrootsIdentity;
use myc::nostr_contract::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrMetadata, RadrootsNostrTimestamp,
    radroots_nostr_build_application_handler_event,
};
use myc::{
    MYC_DISCOVERY_DOCUMENT_MAX_BYTES, MYC_STATE_SCHEMA_VERSION, MycConfigProfile,
    MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome, MycDeliveryClaim, MycDeliveryJobStatus,
    MycDeliveryRelayId, MycDeliverySourceKind, MycDeliveryTimeUnixMs, MycDiscoveryCommitAdmission,
    MycDiscoveryCommitRequest, MycDiscoveryStateErrorKind, MycStateMetadata,
    MycStateRepositoryErrorKind, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    initialize_myc_state, open_myc_state_read_write, parse_myc_cli_v1_from, parse_myc_config_v1,
    resolve_myc_runtime_context,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use sqlx::{ConnectOptions, Connection, sqlite::SqliteConnectOptions};

const CONFIG_EXAMPLE: &[u8] =
    include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const DISCOVERY_SOURCE: &str = include_str!("../src/state_discovery.rs");
const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const DISCOVERY_SECRET: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn runtime(root: &Path) -> myc::MycRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root,
        "run",
    ])
    .expect("valid invocation");
    resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn prepare_state_directory(runtime: &myc::MycRuntimeContext) {
    let directory = runtime.context().paths().state();
    fs::create_dir_all(directory).expect("state directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("state mode");
}

fn discovery_identity() -> RadrootsIdentity {
    RadrootsIdentity::from_secret_key_str(DISCOVERY_SECRET).expect("discovery identity")
}

fn config_source(enabled: bool) -> Vec<u8> {
    let identity = discovery_identity();
    let source = String::from_utf8(CONFIG_EXAMPLE.to_vec())
        .expect("UTF-8 configuration")
        .replace(
            "3333333333333333333333333333333333333333333333333333333333333333",
            &identity.public_key_hex(),
        );
    if enabled {
        return source.into_bytes();
    }
    let before_binding = source
        .split_once("[identity.discovery.binding]")
        .expect("discovery binding")
        .0;
    let after_binding = source.split_once("[[relays]]").expect("relay inventory").1;
    let without_binding = format!(
        "{}[[relays]]{}",
        before_binding.replace(
            "[identity.discovery]\nenabled = true",
            "[identity.discovery]\nenabled = false"
        ),
        after_binding,
    );
    let before_discovery = without_binding
        .split_once("[discovery]")
        .expect("discovery section")
        .0;
    format!("{before_discovery}[discovery]\nenabled = false\n").into_bytes()
}

fn state_metadata(runtime: &myc::MycRuntimeContext, source: &[u8]) -> MycStateMetadata {
    let configuration =
        parse_myc_config_v1(source, MycConfigProfile::RepoLocal).expect("configuration");
    MycStateMetadata::new(
        runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "b44119fbac5985be8127ad1bf56d2950e6399427",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        MYC_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

fn time(value: u64) -> MycDeliveryTimeUnixMs {
    MycDeliveryTimeUnixMs::new(value).expect("delivery time")
}

fn nostrconnect_url() -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("relay", "wss://relay-primary.example.test/");
    query.append_pair("relay", "wss://relay-secondary.example.test/");
    let bunker = format!(
        "bunker://{}?{}",
        "2222222222222222222222222222222222222222222222222222222222222222",
        query.finish()
    );
    let encoded: String = url::form_urlencoded::byte_serialize(bunker.as_bytes()).collect();
    format!("https://myc.example.test/connect?uri={encoded}")
}

fn signed_handler_event(created_at: u64) -> Vec<u8> {
    let metadata = RadrootsNostrMetadata {
        name: Some("myc".to_owned()),
        display_name: Some("Radroots Myc".to_owned()),
        about: Some("NIP-46 signer".to_owned()),
        website: Some("https://myc.example.test/".to_owned()),
        picture: Some("https://myc.example.test/myc.png".to_owned()),
        ..RadrootsNostrMetadata::default()
    };
    let spec = RadrootsNostrApplicationHandlerSpec::new(vec![24_133])
        .with_identifier("myc")
        .with_relays(vec![
            "wss://relay-primary.example.test/".to_owned(),
            "wss://relay-secondary.example.test/".to_owned(),
        ])
        .with_nostr_connect_url(nostrconnect_url())
        .with_metadata(metadata);
    let event = radroots_nostr_build_application_handler_event(&spec)
        .expect("typed handler event")
        .custom_created_at(RadrootsNostrTimestamp::from_secs(created_at))
        .sign_with_keys(discovery_identity().keys())
        .expect("signed event");
    serde_json::to_vec(&event).expect("canonical event bytes")
}

async fn deliver_all_required(
    repository: &myc::MycStateRepository<'_>,
    job_id: myc::MycDeliveryJobId,
    start: u64,
) {
    for (offset, relay_name) in ["primary", "secondary"].into_iter().enumerate() {
        let relay = MycDeliveryRelayId::new(relay_name).expect("relay");
        let claimed = match repository
            .claim_delivery_target(
                job_id,
                &relay,
                MycDeliveryAttemptNonce::from_injected_entropy([0x70 + offset as u8; 32]),
                time(start + offset as u64 * 10),
            )
            .await
            .expect("claim")
        {
            MycDeliveryClaim::Claimed(attempt) => attempt,
            other => panic!("unexpected claim: {other:?}"),
        };
        repository
            .mark_delivery_attempt_submitted(
                job_id,
                &relay,
                claimed.id(),
                time(start + offset as u64 * 10 + 1),
            )
            .await
            .expect("submitted");
        repository
            .record_delivery_attempt_outcome(
                job_id,
                &relay,
                claimed.id(),
                MycDeliveryAttemptOutcome::Delivered,
                time(start + offset as u64 * 10 + 2),
            )
            .await
            .expect("delivered");
    }
}

#[test]
fn discovery_input_is_signature_verified_bounded_and_redacted() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    let metadata = state_metadata(&runtime, &config_source(true));
    let event = signed_handler_event(1_725_000_000);
    let request = MycDiscoveryCommitRequest::new(&metadata, &event, time(100)).expect("request");
    assert!(
        !request
            .generation_id()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );

    let mut altered = event.clone();
    let position = altered
        .iter()
        .position(|byte| *byte == b'm')
        .expect("mutable event byte");
    altered[position] = b'n';
    assert_eq!(
        MycDiscoveryCommitRequest::new(&metadata, &altered, time(100))
            .expect_err("signature/canonical drift")
            .kind(),
        MycDiscoveryStateErrorKind::InvalidEvent
    );
    let mut whitespace = event.clone();
    whitespace.push(b'\n');
    assert_eq!(
        MycDiscoveryCommitRequest::new(&metadata, &whitespace, time(100))
            .expect_err("noncanonical event")
            .kind(),
        MycDiscoveryStateErrorKind::InvalidEvent
    );
    assert_eq!(
        MycDiscoveryCommitRequest::new(
            &metadata,
            &vec![b'x'; MYC_DISCOVERY_DOCUMENT_MAX_BYTES + 1],
            time(100),
        )
        .expect_err("oversize")
        .kind(),
        MycDiscoveryStateErrorKind::TooLarge
    );
    let disabled = state_metadata(&runtime, &config_source(false));
    let error = MycDiscoveryCommitRequest::new(&disabled, &event, time(100))
        .expect_err("disabled discovery");
    assert_eq!(error.kind(), MycDiscoveryStateErrorKind::Disabled);
    assert!(Error::source(&error).is_none());
    let rendered = format!("{request:?} {error} {error:?}");
    assert!(!rendered.contains(DISCOVERY_SECRET));
    assert!(!rendered.contains("myc.example.test"));
    assert!(!rendered.contains(&String::from_utf8(event).expect("event text")));
}

#[tokio::test]
async fn discovery_desired_current_and_exact_documents_are_atomic_restart_safe_and_delivery_bound()
{
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = state_metadata(&runtime, &config_source(true));
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let event = signed_handler_event(1_725_000_000);
    let request = MycDiscoveryCommitRequest::new(&metadata, &event, time(100)).expect("request");
    let committed = host
        .repository()
        .commit_discovery_desired_state(&request)
        .await
        .expect("commit");
    assert!(matches!(committed, MycDiscoveryCommitAdmission::Created(_)));
    let record = committed.record();
    assert_eq!(
        record.job().source_kind(),
        MycDeliverySourceKind::DiscoveryHandler
    );
    assert_eq!(record.job().operation_id(), None);
    assert_eq!(record.job().status(), MycDeliveryJobStatus::Pending);
    assert!(
        !request
            .desired_digest()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(record.document().event_id().len(), 32);
    assert!(
        !record
            .document()
            .nip05_projection_digest()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(record.document().event_bytes(), event);
    let projection: serde_json::Value =
        serde_json::from_slice(record.document().nip05_projection_bytes()).expect("projection");
    assert_eq!(
        projection["schema"],
        "radroots.myc.nip05-projection-input.v1"
    );
    assert_eq!(projection["domain"], "myc.example.test");
    assert_eq!(projection["name"], "_");
    assert_eq!(projection["relays"].as_array().expect("relays").len(), 2);
    assert_eq!(record.state().current_generation_id(), None);
    assert_eq!(record.state().current_job_id(), None);
    let job_id = record.job().id();

    let replay = host
        .repository()
        .commit_discovery_desired_state(&request)
        .await
        .expect("exact replay");
    assert!(matches!(
        replay,
        MycDiscoveryCommitAdmission::ExactReplay(_)
    ));
    assert_eq!(replay.record().job().id(), job_id);
    let same_time_event = signed_handler_event(1_725_000_002);
    let same_time_request = MycDiscoveryCommitRequest::new(&metadata, &same_time_event, time(100))
        .expect("same-time request");
    assert_eq!(
        host.repository()
            .commit_discovery_desired_state(&same_time_request)
            .await
            .expect_err("different desired state at the same time")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    assert_eq!(
        host.repository()
            .promote_delivered_discovery_state(job_id, time(101))
            .await
            .expect_err("pending job cannot become current")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    deliver_all_required(&host.repository(), job_id, 110).await;
    let promoted = host
        .repository()
        .promote_delivered_discovery_state(job_id, time(140))
        .await
        .expect("promoted current");
    assert_eq!(
        promoted.current_generation_id(),
        Some(request.generation_id())
    );
    assert_eq!(promoted.current_job_id(), Some(job_id));
    assert_eq!(
        host.repository()
            .read_discovery_document_for_job(job_id)
            .await
            .expect("document read")
            .expect("document")
            .event_bytes(),
        event
    );
    let next_event = signed_handler_event(1_725_000_001);
    let next_request =
        MycDiscoveryCommitRequest::new(&metadata, &next_event, time(150)).expect("next request");
    let next = host
        .repository()
        .commit_discovery_desired_state(&next_request)
        .await
        .expect("next desired state");
    assert!(matches!(next, MycDiscoveryCommitAdmission::Created(_)));
    assert_eq!(
        next.record().state().desired_generation_id(),
        next_request.generation_id()
    );
    assert_eq!(
        next.record().state().current_generation_id(),
        Some(request.generation_id())
    );
    assert_eq!(next.record().state().current_job_id(), Some(job_id));
    let next_job_id = next.record().job().id();
    assert_eq!(
        host.repository()
            .promote_delivered_discovery_state(next_job_id, time(151))
            .await
            .expect_err("new desired state is not yet current")
            .kind(),
        MycStateRepositoryErrorKind::Binding
    );
    deliver_all_required(&host.repository(), next_job_id, 160).await;
    let next_promoted = host
        .repository()
        .promote_delivered_discovery_state(next_job_id, time(190))
        .await
        .expect("next current state");
    assert_eq!(
        next_promoted.current_generation_id(),
        Some(next_request.generation_id())
    );
    assert_eq!(next_promoted.current_job_id(), Some(next_job_id));
    host.close().await.expect("close");

    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen");
    let state = host
        .repository()
        .read_discovery_publication_state()
        .await
        .expect("state")
        .expect("committed state");
    assert_eq!(state.current_job_id(), Some(next_job_id));
    host.close().await.expect("final close");
}

#[tokio::test]
async fn discovery_schema_guards_reject_mutation_and_corrupt_source_kinds() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path());
    prepare_state_directory(&runtime);
    let metadata = state_metadata(&runtime, &config_source(true));
    let (applied_at, build) = migration_evidence();
    initialize_myc_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialization");
    let host = open_myc_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let request =
        MycDiscoveryCommitRequest::new(&metadata, &signed_handler_event(1_725_000_000), time(100))
            .expect("request");
    host.repository()
        .commit_discovery_desired_state(&request)
        .await
        .expect("commit");
    host.close().await.expect("close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .expect("inspection connection");
    for statement in [
        "DELETE FROM discovery_desired_state",
        "UPDATE discovery_documents SET event_bytes = X'01'",
        "DELETE FROM discovery_publication_state",
        "UPDATE discovery_publication_state SET desired_job_id = zeroblob(32)",
        "UPDATE delivery_jobs SET source_kind = 'invalid'",
    ] {
        assert!(
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .is_err(),
            "guard accepted {statement}"
        );
    }
    for (index, source_kind) in ["signer_response", "discovery_handler"]
        .into_iter()
        .enumerate()
    {
        let job_id = [0xa0 + u8::try_from(index).expect("bounded index"); 32];
        let source_id = [0xf0 + u8::try_from(index).expect("bounded index"); 32];
        let artifact = [0xb0 + u8::try_from(index).expect("bounded index"); 32];
        let result = sqlx::query(
            "INSERT INTO delivery_jobs (job_id, source_kind, source_id, artifact_sha256, \
             policy_mode, required_acknowledgements, max_attempts, initial_backoff_ms, \
             maximum_backoff_ms, attempt_deadline_ms, status, created_at_unix_ms, \
             updated_at_unix_ms, finalized_at_unix_ms) \
             VALUES (?, ?, ?, ?, 'all_required', 1, 1, 1, 1, 1, 'pending', 1, 1, NULL)",
        )
        .bind(job_id.as_slice())
        .bind(source_kind)
        .bind(source_id.as_slice())
        .bind(artifact.as_slice())
        .execute(&mut connection)
        .await;
        assert!(result.is_err(), "accepted orphaned {source_kind} source");
    }
    connection.close().await.expect("connection close");
}

#[test]
fn discovery_boundary_is_typed_sqlx_only_and_commits_before_any_publication() {
    assert!(LIB_SOURCE.contains("mod state_discovery;"));
    assert!(!LIB_SOURCE.contains("pub mod state_discovery;"));
    assert!(DISCOVERY_SOURCE.contains("event.verify()"));
    assert!(DISCOVERY_SOURCE.contains("ServiceSqliteTransaction<'_>"));
    assert!(DISCOVERY_SOURCE.contains("source_kind = 'discovery_handler'"));
    assert!(CATALOG_SOURCE.contains("discovery_desired_state_no_update"));
    assert!(CATALOG_SOURCE.contains("discovery_documents_no_delete"));
    assert!(CATALOG_SOURCE.contains("delivery_jobs_guard_insert"));
    for forbidden in [
        "SqlitePool",
        "SqliteConnection",
        "BEGIN ",
        "COMMIT",
        "ROLLBACK",
        "reqwest",
        "send_event",
        "publish_nip89_event",
        "tokio::spawn",
        "std::env",
        "std::time",
        "rusqlite",
    ] {
        assert!(
            !DISCOVERY_SOURCE.contains(forbidden),
            "found forbidden discovery authority `{forbidden}`"
        );
    }
}
