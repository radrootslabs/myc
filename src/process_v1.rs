//! Binary-owned execution for one already-admitted command invocation.

use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use radroots_service_host::{
    AdminClient, AdminClientErrorKind, AdminClientTarget, ContractVersions, EntropySource,
    SystemEntropy, SystemWallClock, WallClock,
};
use radroots_service_sqlite::{
    BACKUP_MANIFEST_CANONICAL_MAX_BYTES, BackupCreatedAtUnixMs, IntegrityCheckOutcome,
    IntegrityCheckedAtUnixMs, MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode,
    ServiceBackupManifest, WriterAuthority,
};
use radroots_storage::event::SourceGeneration;
use serde_json::{Value, json};

use crate::admin_v1::{admin_transport_limits, admit_admin_response_value};
use crate::cli_bootstrap::read_identity_provisioning_document;
use crate::config_v1::config_schema_document;
use crate::{
    MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, MYC_CONFIG_SCHEMA, MYC_CONFIG_SCHEMA_VERSION,
    MYC_OPERATOR_CONTRACT_VERSION, MYC_PROVIDER_CONTRACT_VERSION,
    MYC_SIGNER_STATUS_CONTRACT_VERSION, MYC_STATE_SCHEMA_VERSION, MycBootstrapProfileV1,
    MycCliInvocationV1, MycCliOutputModeV1, MycCliPrimaryAuthorityV1, MycCommandV1,
    MycConfigCommandV1, MycConfigDocumentV1, MycConnectionCountsV1, MycIdentityCommandArgsV1,
    MycIdentityCommandV1, MycLocalSignerClient, MycOutboxStatusV1, MycProcessResult,
    MycProviderKind, MycProviderRole, MycRuntimeContext, MycStateBackupArgsV1, MycStateCommandV1,
    MycStateMetadata, MycStateRestoreArgsV1, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, finalize_myc_state_restore, initialize_myc_config_document,
    initialize_myc_state, load_myc_config_candidate, load_myc_config_document,
    open_myc_encrypted_identity, open_myc_state_inspection_from_config,
    open_myc_state_read_write_from_config, plan_myc_cli_v1, provision_myc_encrypted_identity,
    resolve_myc_runtime_context, resolve_myc_wrapping_credential, stage_myc_state_restore,
    verify_myc_state_backup,
};

#[derive(Clone, Copy)]
struct ProcessFailure(MycProcessResult);

type ProcessResult<T> = Result<T, ProcessFailure>;

struct OfflineStateSnapshot {
    value: Value,
    connection_counts: MycConnectionCountsV1,
    outbox: MycOutboxStatusV1,
}

/// Executes one admitted Myc invocation without reparsing process arguments.
///
/// Result bytes are written to stdout only after the governed operation
/// succeeds. The binary retains responsibility for emitting the final safe
/// structured diagnostic and choosing the process exit code.
#[must_use]
pub fn execute_myc_cli_v1(invocation: MycCliInvocationV1) -> MycProcessResult {
    execute(invocation).unwrap_or_else(|failure| failure.0)
}

/// Executes one admitted invocation with a binary-owned process-signal source.
///
/// The signal source factory is consulted only for `run` and only after the
/// governed Tokio runtime has entered. Non-daemon commands retain the exact
/// one-pass execution path used by [`execute_myc_cli_v1`].
#[must_use]
pub fn execute_myc_cli_v1_with_signal_source<F, S>(
    invocation: MycCliInvocationV1,
    make_signal_source: F,
) -> MycProcessResult
where
    F: FnOnce() -> Option<S>,
    S: crate::MycProcessSignalSource + 'static,
{
    if !matches!(invocation.command(), MycCommandV1::Run) {
        return execute_myc_cli_v1(invocation);
    }
    execute_run(invocation, make_signal_source).unwrap_or_else(|failure| failure.0)
}

fn execute_run<F, S>(
    invocation: MycCliInvocationV1,
    make_signal_source: F,
) -> ProcessResult<MycProcessResult>
where
    F: FnOnce() -> Option<S>,
    S: crate::MycProcessSignalSource + 'static,
{
    let resolver = RadrootsPathResolver::new(RadrootsPlatform::current(), host_environment());
    let runtime =
        resolve_myc_runtime_context(&resolver, &invocation).map_err(|_| input_failure())?;
    let configuration = load_myc_config_document(&runtime).map_err(|_| input_failure())?;
    let applied_at = migration_time()?;
    let build = migration_build_identity()?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    tokio.block_on(async move {
        let signals = make_signal_source().ok_or(ProcessFailure(
            MycProcessResult::ServiceOrDependencyUnavailable,
        ))?;
        Ok(crate::runtime_graph::run_myc_daemon(
            runtime,
            configuration,
            applied_at,
            &build,
            signals,
        )
        .await)
    })
}

fn execute(invocation: MycCliInvocationV1) -> ProcessResult<MycProcessResult> {
    let plan = plan_myc_cli_v1(&invocation);
    if matches!(
        (plan.primary_authority(), invocation.command()),
        (MycCliPrimaryAuthorityV1::Daemon, MycCommandV1::Run)
    ) {
        return Err(ProcessFailure(
            MycProcessResult::ServiceOrDependencyUnavailable,
        ));
    }

    let resolver = RadrootsPathResolver::new(RadrootsPlatform::current(), host_environment());
    let runtime =
        resolve_myc_runtime_context(&resolver, &invocation).map_err(|_| input_failure())?;
    let output = invocation.output_mode();

    match (plan.primary_authority(), invocation.command()) {
        (MycCliPrimaryAuthorityV1::Offline, MycCommandV1::Config(command)) => {
            execute_config(output, &runtime, command)
        }
        (
            MycCliPrimaryAuthorityV1::Offline | MycCliPrimaryAuthorityV1::LiveUnixAdmin,
            MycCommandV1::State(command),
        ) => execute_state(output, &runtime, command),
        (
            MycCliPrimaryAuthorityV1::Offline | MycCliPrimaryAuthorityV1::LiveUnixAdmin,
            MycCommandV1::Identity(command),
        ) => execute_identity(output, &runtime, command),
        (MycCliPrimaryAuthorityV1::LiveUnixAdmin, MycCommandV1::Status) => {
            execute_live_or_offline_status(output, &runtime)
        }
        (MycCliPrimaryAuthorityV1::Offline, MycCommandV1::Doctor) => {
            execute_doctor(output, &runtime)
        }
        _ => Err(ProcessFailure(MycProcessResult::UnexpectedInternal)),
    }
}

fn execute_doctor(
    _output: MycCliOutputModeV1,
    runtime: &MycRuntimeContext,
) -> ProcessResult<MycProcessResult> {
    let configuration = load_myc_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    let report = tokio
        .block_on(crate::run_myc_doctor(
            runtime,
            &crate::system_doctor::MycSystemDoctorProbe::new(runtime, &configuration),
        ))
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    emit_bytes(report.canonical_json())?;
    if report.exit_code() == 0 {
        Ok(MycProcessResult::Success)
    } else {
        Err(ProcessFailure(MycProcessResult::DoctorRequiredCheckFailed))
    }
}

fn execute_config(
    output: MycCliOutputModeV1,
    runtime: &MycRuntimeContext,
    command: &MycConfigCommandV1,
) -> ProcessResult<MycProcessResult> {
    match command {
        MycConfigCommandV1::Init => {
            let bytes = read_bounded_stdin(MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)?;
            initialize_myc_config_document(runtime, &bytes).map_err(|_| input_failure())?;
            emit_simple_success(output, "config_initialized")
        }
        MycConfigCommandV1::Validate => {
            load_myc_config_document(runtime).map_err(|_| input_failure())?;
            emit_simple_success(output, "config_valid")
        }
        MycConfigCommandV1::Show => {
            let configuration = load_myc_config_document(runtime).map_err(|_| input_failure())?;
            emit_bytes(configuration.effective().canonical_json().as_bytes())
        }
        MycConfigCommandV1::Schema => emit_bytes(config_schema_document().as_bytes()),
        MycConfigCommandV1::Apply(arguments) => {
            let current = load_myc_config_document(runtime).map_err(|_| input_failure())?;
            let candidate = load_myc_config_candidate(runtime, arguments.candidate_config())
                .map_err(|_| input_failure())?;
            let build = migration_build_identity()?;
            let applied_at = migration_time()?;
            let tokio = build_tokio_runtime(current.runtime_thread_limits())?;
            let outcome = tokio.block_on(async {
                validate_candidate_providers(runtime, &candidate).await?;
                let state =
                    open_myc_state_read_write_from_config(runtime, &current, applied_at, &build)
                        .await
                        .map_err(|_| state_failure())?;
                let applied = state
                    .repository()
                    .apply_configuration(&current, &candidate, applied_at, &build)
                    .await
                    .map_err(|error| match error.kind() {
                        crate::MycConfigApplyErrorKind::PolicyConflict
                        | crate::MycConfigApplyErrorKind::ResourceExhausted => conflict_failure(),
                        _ => state_failure(),
                    });
                let closed = state.close().await.map_err(|_| state_failure());
                closed.and(applied)
            })?;
            emit_value(
                output,
                "config_applied",
                json!({
                    "generation": outcome.generation(),
                    "revoked_challenges": outcome.revoked_challenge_count(),
                    "revoked_connections": outcome.revoked_connection_count(),
                }),
            )
        }
    }
}

fn execute_state(
    output: MycCliOutputModeV1,
    runtime: &MycRuntimeContext,
    command: &MycStateCommandV1,
) -> ProcessResult<MycProcessResult> {
    let configuration = load_myc_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    match command {
        MycStateCommandV1::Init => {
            let generation = source_generation()?;
            let created_at = wall_time_millis()?;
            let metadata = MycStateMetadata::new(runtime, &configuration, generation, created_at)
                .map_err(|_| state_failure())?;
            let applied_at = migration_time()?;
            let build = migration_build_identity()?;
            tokio
                .block_on(initialize_myc_state(runtime, &metadata, applied_at, &build))
                .map_err(|_| state_failure())?;
            emit_simple_success(output, "state_initialized")
        }
        MycStateCommandV1::Status => {
            if let Some(bytes) = tokio.block_on(live_get(
                runtime,
                &configuration,
                crate::MycAdminRoute::StateStatus,
                None,
            ))? {
                return emit_bytes(&bytes);
            }
            let value = tokio.block_on(offline_state_status(runtime, &configuration))?;
            emit_admin_value(output, crate::MycAdminRoute::StateStatus, value)
        }
        MycStateCommandV1::Backup(arguments) => {
            if let Some(bytes) = tokio.block_on(live_backup(runtime, &configuration, arguments))? {
                return emit_bytes(&bytes);
            }
            let manifest = tokio.block_on(offline_backup(runtime, &configuration, arguments))?;
            emit_exact_bytes(manifest.canonical_bytes())
        }
        MycStateCommandV1::Restore(arguments) => {
            tokio.block_on(offline_restore(runtime, &configuration, arguments))?;
            emit_simple_success(output, "state_restore_finalized")
        }
        MycStateCommandV1::Verify => {
            tokio.block_on(offline_verify(runtime, &configuration))?;
            emit_simple_success(output, "state_verified")
        }
        MycStateCommandV1::Migrate => {
            let build = migration_build_identity()?;
            let applied_at = migration_time()?;
            tokio.block_on(async {
                let state = open_myc_state_read_write_from_config(
                    runtime,
                    &configuration,
                    applied_at,
                    &build,
                )
                .await
                .map_err(|_| state_failure())?;
                state.close().await.map_err(|_| state_failure())
            })?;
            emit_simple_success(output, "state_migrated")
        }
    }
}

fn execute_identity(
    output: MycCliOutputModeV1,
    runtime: &MycRuntimeContext,
    command: &MycIdentityCommandV1,
) -> ProcessResult<MycProcessResult> {
    let configuration = load_myc_config_document(runtime).map_err(|_| input_failure())?;
    match command {
        MycIdentityCommandV1::Init(arguments) => {
            let binding = identity_binding(&configuration, *arguments)?;
            if binding.kind() != MycProviderKind::EncryptedFile {
                return Err(conflict_failure());
            }
            let material = read_identity_provisioning_document(std::io::stdin().lock())
                .map_err(|_| input_failure())?;
            let credential =
                resolve_myc_wrapping_credential(runtime, binding).map_err(|_| state_failure())?;
            let paths = crate::state_host::state_paths(runtime).map_err(|_| state_failure())?;
            let mut authority = WriterAuthority::acquire(&paths, OpenMode::Initialize)
                .map_err(|_| state_failure())?
                .ok_or_else(state_failure)?;
            let identity = provision_myc_encrypted_identity(binding, &credential, material)
                .map_err(|_| state_failure());
            let released = authority.release().map_err(|_| state_failure());
            let identity = released.and(identity)?;
            emit_identity(
                output,
                arguments.role(),
                identity.public_identity().as_hex(),
                0,
            )
        }
        MycIdentityCommandV1::Status(arguments) | MycIdentityCommandV1::ExportPublic(arguments) => {
            let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
            let route = match command {
                MycIdentityCommandV1::Status(_) => crate::MycAdminRoute::IdentityStatus,
                MycIdentityCommandV1::ExportPublic(_) => crate::MycAdminRoute::IdentityPublic,
                MycIdentityCommandV1::Init(_) => {
                    return Err(ProcessFailure(MycProcessResult::UnexpectedInternal));
                }
            };
            if let Some(bytes) = tokio.block_on(live_get(
                runtime,
                &configuration,
                route,
                Some(arguments.role()),
            ))? {
                return emit_bytes(&bytes);
            }
            let (public_key, generation, provider, available) =
                tokio.block_on(offline_identity(runtime, &configuration, arguments.role()))?;
            if matches!(command, MycIdentityCommandV1::ExportPublic(_)) {
                let public_key = public_key.ok_or_else(state_failure)?;
                emit_identity(output, arguments.role(), &public_key, generation)
            } else {
                emit_admin_value(
                    output,
                    crate::MycAdminRoute::IdentityStatus,
                    json!({
                        "available": available,
                        "configured": true,
                        "generation": generation,
                        "provider": provider.as_str(),
                        "public_key": public_key,
                        "reason_codes": if available { json!([]) } else { json!(["provider_unavailable"]) },
                        "role": arguments.role().as_str(),
                    }),
                )
            }
        }
    }
}

fn execute_live_or_offline_status(
    output: MycCliOutputModeV1,
    runtime: &MycRuntimeContext,
) -> ProcessResult<MycProcessResult> {
    let configuration = load_myc_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    if let Some(bytes) = tokio.block_on(live_get(
        runtime,
        &configuration,
        crate::MycAdminRoute::Status,
        None,
    ))? {
        return emit_bytes(&bytes);
    }
    let state = tokio.block_on(offline_service_status(runtime, &configuration))?;
    emit_admin_value(output, crate::MycAdminRoute::Status, state)
}

async fn live_get(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    route: crate::MycAdminRoute,
    role: Option<MycProviderRole>,
) -> ProcessResult<Option<Box<[u8]>>> {
    let client = AdminClient::new(
        runtime.artifacts().admin_socket(),
        admin_transport_limits(configuration).map_err(|_| input_failure())?,
    )
    .map_err(|_| input_failure())?;
    let target = if let Some(role) = role {
        AdminClientTarget::new(format!("{}?role={}", route.path(), role.as_str()))
    } else {
        AdminClientTarget::new(route.path())
    }
    .map_err(|_| input_failure())?;
    match client.get::<Value>(&target).await {
        Ok(response) => admit_admin_response_value(route, response.result())
            .map(Some)
            .map_err(|_| ProcessFailure(MycProcessResult::ServiceOrDependencyUnavailable)),
        Err(error) if error.kind() == AdminClientErrorKind::Connect => Ok(None),
        Err(error) if error.kind() == AdminClientErrorKind::ServerFailure => {
            Err(conflict_failure())
        }
        Err(_) => Err(ProcessFailure(
            MycProcessResult::ServiceOrDependencyUnavailable,
        )),
    }
}

async fn live_backup(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    arguments: &MycStateBackupArgsV1,
) -> ProcessResult<Option<Box<[u8]>>> {
    let client = AdminClient::new(
        runtime.artifacts().admin_socket(),
        admin_transport_limits(configuration).map_err(|_| input_failure())?,
    )
    .map_err(|_| input_failure())?;
    let target = AdminClientTarget::new(crate::MycAdminRoute::StateBackup.path())
        .map_err(|_| input_failure())?;
    let target_path = arguments.target().to_str().ok_or_else(input_failure)?;
    let request = json!({
        "confirmation": "confirm",
        "expected_generation": arguments.expected_generation(),
        "target_path": target_path,
    });
    let operation_id = radroots_service_host::AdminOperationId::new(arguments.operation_id())
        .map_err(|_| input_failure())?;
    match client
        .mutate::<_, Value>(&target, operation_id, None, request)
        .await
    {
        Ok(response) => {
            admit_admin_response_value(crate::MycAdminRoute::StateBackup, response.result())
                .map(Some)
                .map_err(|_| ProcessFailure(MycProcessResult::ServiceOrDependencyUnavailable))
        }
        Err(error) if error.kind() == AdminClientErrorKind::Connect => Ok(None),
        Err(error) if error.kind() == AdminClientErrorKind::ServerFailure => {
            Err(conflict_failure())
        }
        Err(_) => Err(ProcessFailure(
            MycProcessResult::ServiceOrDependencyUnavailable,
        )),
    }
}

async fn offline_state_status(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> ProcessResult<Value> {
    inspect_offline_state(runtime, configuration)
        .await
        .map(|snapshot| snapshot.value)
}

async fn inspect_offline_state(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> ProcessResult<OfflineStateSnapshot> {
    let state = open_myc_state_inspection_from_config(runtime, configuration)
        .await
        .map_err(|_| state_failure())?;
    let inspected = async {
        let generation = state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| state_failure())?;
        let connection_counts = state
            .repository()
            .read_runtime_connection_counts()
            .await
            .map_err(|_| state_failure())?;
        let outbox = state
            .repository()
            .read_runtime_outbox_status()
            .await
            .map_err(|_| state_failure())?;
        let checked_at = integrity_time()?;
        let report = state
            .inspect_integrity(checked_at)
            .await
            .map_err(|_| state_failure())?;
        let schema = state
            .metadata()
            .database_identity()
            .supported_state_schema_version()
            .get();
        let verified = report.sqlite() == IntegrityCheckOutcome::Verified
            && report.foreign_keys() == IntegrityCheckOutcome::Verified;
        Ok(OfflineStateSnapshot {
            value: json!({
                "backup_eligible": verified,
                "generation": generation,
                "integrity": if verified { "verified" } else { "failed" },
                "reason_codes": if verified { json!([]) } else { json!(["database_integrity_failed"]) },
                "schema_version": schema,
                "writer_lock": "free",
            }),
            connection_counts,
            outbox,
        })
    }
    .await;
    let closed = state.close().await.map_err(|_| state_failure());
    closed.and(inspected)
}

async fn offline_service_status(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> ProcessResult<Value> {
    let snapshot = inspect_offline_state(runtime, configuration).await?;
    let state = &snapshot.value;
    let generation = state
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or(ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    let schema_version = state
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    let integrity = state
        .get("integrity")
        .and_then(Value::as_str)
        .ok_or(ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    let build = build_info()?;
    let versions = build.contract_versions();
    let digest = crate::state_metadata::normalized_config_digest(
        configuration.profile(),
        configuration.normalized(),
    )
    .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    let discovery_configured = configuration
        .provider_contract()
        .binding(MycProviderRole::Discovery)
        .is_some();
    let unavailable = |configured: bool| {
        json!({
            "available": false,
            "configured": configured,
            "reason_codes": ["signer_provider_unavailable"],
        })
    };
    Ok(json!({
        "build_info": {
            "contract_versions": {
                "admin": versions.admin(),
                "config": versions.config(),
                "provider": versions.provider(),
                "state": versions.state(),
                "status": versions.status(),
            },
            "revision": build.service_commit(),
            "toolchain": build.rust_version(),
            "version": build.service_version(),
        },
        "configuration": {
            "digest": hex::encode(digest.as_bytes()),
            "schema": MYC_CONFIG_SCHEMA,
            "schema_version": MYC_CONFIG_SCHEMA_VERSION,
            "source": if runtime.profile() == MycBootstrapProfileV1::RepoLocal {
                "derived_repo_local"
            } else {
                "explicit_config"
            },
        },
        "contract_version": MYC_SIGNER_STATUS_CONTRACT_VERSION,
        "instance": runtime.context().instance().as_str(),
        "myc": {
            "connection_counts": snapshot.connection_counts,
            "discovery": unavailable(discovery_configured),
            "outbox": snapshot.outbox,
            "transport": unavailable(true),
            "user": unavailable(true),
        },
        "persistence": {
            "generation": generation,
            "health": "read_only",
            "integrity": integrity,
            "reason_codes": [],
            "schema_version": schema_version,
        },
        "phase": "unready",
        "provider": {
            "discovery": unavailable(discovery_configured),
            "health": "unavailable",
            "reason_codes": ["signer_provider_unavailable"],
            "transport": unavailable(true),
            "user": unavailable(true),
        },
        "ready": false,
        "reason_codes": [
            "required_relay_unavailable",
            "signer_provider_unavailable",
            "subscriber_not_active"
        ],
        "service": "myc",
        "transport": {
            "connected_relay_count": 0,
            "health": "unavailable",
            "reason_codes": ["required_relay_unavailable", "subscriber_not_active"],
            "required_relays_ready": false,
        },
        "uptime_millis": 0,
    }))
}

async fn offline_backup(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    arguments: &MycStateBackupArgsV1,
) -> ProcessResult<radroots_service_sqlite::ServiceBackupManifest> {
    let build = migration_build_identity()?;
    let applied_at = migration_time()?;
    let state = open_myc_state_read_write_from_config(runtime, configuration, applied_at, &build)
        .await
        .map_err(|_| state_failure())?;
    let captured = async {
        let generation = state
            .repository()
            .current_configuration_generation()
            .await
            .map_err(|_| state_failure())?;
        if u64::from(generation) != arguments.expected_generation() {
            return Err(conflict_failure());
        }
        let created_at = backup_time()?;
        state
            .capture_online_backup(arguments.target(), created_at)
            .await
            .map_err(|_| state_failure())
    }
    .await;
    let closed = state.close().await.map_err(|_| state_failure());
    closed.and(captured)
}

async fn offline_restore(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    arguments: &MycStateRestoreArgsV1,
) -> ProcessResult<()> {
    let manifest = read_bounded_file(arguments.manifest(), BACKUP_MANIFEST_CANONICAL_MAX_BYTES)?;
    let parsed =
        ServiceBackupManifest::from_canonical_bytes(&manifest).map_err(|_| state_failure())?;
    if parsed.digest() != arguments.manifest_sha256() {
        return Err(state_failure());
    }
    let expected = MycStateMetadata::new(
        runtime,
        configuration,
        parsed.source_generation(),
        parsed.created_at_unix_ms().get(),
    )
    .map_err(|_| state_failure())?;
    let verified = verify_myc_state_backup(
        &manifest,
        arguments.manifest_sha256(),
        arguments.bundle(),
        &expected,
        arguments.maximum_state_bytes(),
    )
    .map_err(|_| state_failure())?;
    let staged = stage_myc_state_restore(runtime, &expected, verified)
        .await
        .map_err(|_| state_failure())?;
    finalize_myc_state_restore(staged)
        .await
        .map_err(|_| state_failure())
}

async fn offline_verify(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> ProcessResult<()> {
    let build = migration_build_identity()?;
    let applied_at = migration_time()?;
    let state = open_myc_state_read_write_from_config(runtime, configuration, applied_at, &build)
        .await
        .map_err(|_| state_failure())?;
    let report = state
        .inspect_integrity(integrity_time()?)
        .await
        .map_err(|_| state_failure());
    let closed = state.close().await.map_err(|_| state_failure());
    match closed.and(report) {
        Ok(report)
            if report.sqlite() == IntegrityCheckOutcome::Verified
                && report.foreign_keys() == IntegrityCheckOutcome::Verified =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        _ => Err(state_failure()),
    }
}

async fn offline_identity(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    role: MycProviderRole,
) -> ProcessResult<(Option<String>, u16, MycProviderKind, bool)> {
    let state = open_myc_state_inspection_from_config(runtime, configuration)
        .await
        .map_err(|_| state_failure())?;
    let generation = state
        .repository()
        .current_configuration_generation()
        .await
        .map_err(|_| state_failure());
    let closed = state.close().await.map_err(|_| state_failure());
    let generation = closed.and(generation)?;
    let binding = configuration
        .provider_contract()
        .binding(role)
        .ok_or_else(input_failure)?;
    match binding.kind() {
        MycProviderKind::EncryptedFile => {
            let credential =
                resolve_myc_wrapping_credential(runtime, binding).map_err(|_| state_failure())?;
            let identity =
                open_myc_encrypted_identity(binding, &credential).map_err(|_| state_failure())?;
            Ok((
                Some(identity.public_identity().as_hex().to_owned()),
                generation,
                binding.kind(),
                true,
            ))
        }
        MycProviderKind::LocalSigner => {
            let _client = MycLocalSignerClient::new(binding).map_err(|_| state_failure())?;
            Ok((None, generation, binding.kind(), false))
        }
    }
}

fn identity_binding(
    configuration: &MycConfigDocumentV1,
    arguments: MycIdentityCommandArgsV1,
) -> ProcessResult<&crate::MycProviderBinding> {
    configuration
        .provider_contract()
        .binding(arguments.role())
        .ok_or_else(input_failure)
}

async fn validate_candidate_providers(
    runtime: &MycRuntimeContext,
    candidate: &MycConfigDocumentV1,
) -> ProcessResult<()> {
    let cancellation = crate::MycTaskCancellation::uncancelled();
    let executor =
        crate::provider_executor::MycProviderExecutor::open(runtime, candidate, &cancellation)
            .await
            .map_err(|_| state_failure())?;
    executor
        .probe_all(wall_time_millis()?, provider_probe_seed()?, &cancellation)
        .await
        .map_err(|_| state_failure())
}

fn provider_probe_seed() -> ProcessResult<[u8; 32]> {
    let mut seed = [0_u8; 32];
    SystemEntropy
        .fill_bytes(&mut seed)
        .map_err(|_| state_failure())?;
    Ok(seed)
}

fn migration_build_identity() -> ProcessResult<MigrationBuildIdentity> {
    let build = build_info()?;
    let versions = build.contract_versions();
    MigrationBuildIdentity::new(
        build.service_version(),
        build.service_commit(),
        build.lib_revision(),
        build.rust_version(),
        build.target(),
        build.feature_profile(),
        versions.config(),
        versions.state(),
        versions.admin(),
        versions.status(),
        versions.provider(),
    )
    .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn build_info() -> ProcessResult<radroots_service_host::BuildInfo> {
    let versions = ContractVersions::new(
        MYC_CONFIG_SCHEMA_VERSION,
        MYC_STATE_SCHEMA_VERSION,
        MYC_OPERATOR_CONTRACT_VERSION,
        MYC_SIGNER_STATUS_CONTRACT_VERSION,
        MYC_PROVIDER_CONTRACT_VERSION,
    )
    .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    radroots_service_host::compile_time_build_info!(
        feature_profile: "service-host",
        contract_versions: versions,
    )
    .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn source_generation() -> ProcessResult<SourceGeneration> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        SystemEntropy
            .fill_bytes(&mut bytes)
            .map_err(|_| state_failure())?;
        if let Ok(generation) = SourceGeneration::new(bytes) {
            return Ok(generation);
        }
    }
    Err(state_failure())
}

fn wall_time_seconds() -> ProcessResult<u64> {
    SystemWallClock
        .now_utc()
        .map(|time| time.get())
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn wall_time_millis() -> ProcessResult<u64> {
    wall_time_seconds()?
        .checked_mul(1_000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn migration_time() -> ProcessResult<MigrationAppliedAtUnixSeconds> {
    MigrationAppliedAtUnixSeconds::new(wall_time_seconds()?)
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn backup_time() -> ProcessResult<BackupCreatedAtUnixMs> {
    BackupCreatedAtUnixMs::new(wall_time_millis()?)
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn integrity_time() -> ProcessResult<IntegrityCheckedAtUnixMs> {
    IntegrityCheckedAtUnixMs::new(wall_time_millis()?)
        .ok_or(ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn build_tokio_runtime(
    limits: crate::MycRuntimeThreadLimitsV1,
) -> ProcessResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(limits.worker_threads())
        .max_blocking_threads(limits.blocking_threads())
        .enable_all()
        .build()
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))
}

fn host_environment() -> RadrootsHostEnvironment {
    let path = |name| {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    RadrootsHostEnvironment {
        home_dir: path("HOME"),
        xdg_config_home: path("XDG_CONFIG_HOME"),
        xdg_data_home: path("XDG_DATA_HOME"),
        xdg_state_home: path("XDG_STATE_HOME"),
        xdg_cache_home: path("XDG_CACHE_HOME"),
        xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
        appdata_dir: path("APPDATA"),
        localappdata_dir: path("LOCALAPPDATA"),
    }
}

fn read_bounded_stdin(maximum: usize) -> ProcessResult<Vec<u8>> {
    let mut reader = std::io::stdin().lock();
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1_024).saturating_add(1));
    Read::by_ref(&mut reader)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| input_failure())?;
    if bytes.len() > maximum {
        return Err(input_failure());
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_bounded_file(path: &Path, maximum: usize) -> ProcessResult<Vec<u8>> {
    crate::config_loader::read_secure_bounded_file(path, maximum).map_err(|_| state_failure())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_bounded_file(_path: &Path, _maximum: usize) -> ProcessResult<Vec<u8>> {
    Err(state_failure())
}

fn emit_identity(
    output: MycCliOutputModeV1,
    role: MycProviderRole,
    public_key: &str,
    generation: u16,
) -> ProcessResult<MycProcessResult> {
    emit_admin_value(
        output,
        crate::MycAdminRoute::IdentityPublic,
        json!({
            "generation": generation,
            "public_key": public_key,
            "role": role.as_str(),
        }),
    )
}

fn emit_simple_success(
    output: MycCliOutputModeV1,
    code: &'static str,
) -> ProcessResult<MycProcessResult> {
    emit_value(output, code, json!({"ok": true}))
}

fn emit_admin_value(
    _output: MycCliOutputModeV1,
    route: crate::MycAdminRoute,
    value: Value,
) -> ProcessResult<MycProcessResult> {
    let bytes = admit_admin_response_value(route, &value)
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    emit_bytes(&bytes)
}

fn emit_value(
    output: MycCliOutputModeV1,
    code: &'static str,
    value: Value,
) -> ProcessResult<MycProcessResult> {
    let bytes = match output {
        MycCliOutputModeV1::Json => serde_json::to_vec(&value)
            .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?,
        MycCliOutputModeV1::Human => {
            if value.is_object() && value.as_object().is_some_and(|object| object.len() > 1) {
                serde_json::to_vec(&value)
                    .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?
            } else {
                code.as_bytes().to_vec()
            }
        }
    };
    emit_bytes(&bytes)
}

fn emit_bytes(bytes: &[u8]) -> ProcessResult<MycProcessResult> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| {
            if bytes.ends_with(b"\n") {
                Ok(())
            } else {
                stdout.write_all(b"\n")
            }
        })
        .and_then(|()| stdout.flush())
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    Ok(MycProcessResult::Success)
}

fn emit_exact_bytes(bytes: &[u8]) -> ProcessResult<MycProcessResult> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|_| ProcessFailure(MycProcessResult::UnexpectedInternal))?;
    Ok(MycProcessResult::Success)
}

const fn input_failure() -> ProcessFailure {
    ProcessFailure(MycProcessResult::InputOrConfiguration)
}

const fn state_failure() -> ProcessFailure {
    ProcessFailure(MycProcessResult::StateOrIdentityUnavailable)
}

const fn conflict_failure() -> ProcessFailure {
    ProcessFailure(MycProcessResult::OperationRejectedOrConflict)
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_limits_are_used_without_cpu_derived_defaults() {
        let source = include_str!("process_v1.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert_eq!(source.matches("Builder::new_multi_thread()").count(), 1);
        assert!(!source.contains("available_parallelism"));
        assert!(source.contains("worker_threads(limits.worker_threads())"));
        assert!(source.contains("max_blocking_threads(limits.blocking_threads())"));
    }

    #[test]
    fn host_environment_uses_only_standard_path_inputs() {
        let source = include_str!("process_v1.rs");
        assert!(!source.contains("path(\"MYC_"));
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "APPDATA",
            "LOCALAPPDATA",
        ] {
            assert!(source.contains(&format!("path(\"{name}\")")));
        }
    }
}
