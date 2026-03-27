use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use radroots_nostr_connect::prelude::RadrootsNostrConnectPermissions;
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerBackend, RadrootsNostrSignerConnectionId,
    RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerRequestAuditRecord,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::config::{DEFAULT_ENV_PATH, MycConfig, MycTransportDeliveryPolicy};
use crate::control::{accept_client_uri, authorize_auth_challenge, parse_permission_values};
use crate::discovery::{
    MycDiscoveryContext, MycDiscoveryRepairSummary, diff_live_nip89, fetch_live_nip89,
    publish_nip89_event, refresh_nip89, verify_bundle,
};
use crate::error::MycError;
use crate::logging;
use crate::operability::{
    MycAuditDecisionCounts, MycOperationOutcomeCounts, MycStatusFullOutput, MycStatusSummaryOutput,
    collect_metrics, collect_status_full, collect_status_summary, increment_outcome_counts,
    is_aggregate_publish_operation, operation_kind_label, render_metrics_text,
};
use crate::persistence::{
    MycPersistenceImportSelection, backup_persistence, import_json_to_sqlite, restore_backup,
    verify_restored_state,
};

#[derive(Debug, Parser)]
#[command(name = "myc")]
#[command(about = "Mycorrhiza NIP-46 signer service")]
pub struct MycCli {
    #[arg(long = "env-file", global = true)]
    env_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<MycCommand>,
}

#[derive(Debug, Subcommand)]
pub enum MycCommand {
    Run,
    Status {
        #[arg(long, value_enum, default_value_t = MycStatusView::Summary)]
        view: MycStatusView,
    },
    Metrics {
        #[arg(long, value_enum, default_value_t = MycMetricsFormat::Prometheus)]
        format: MycMetricsFormat,
    },
    Persistence {
        #[command(subcommand)]
        command: MycPersistenceCommand,
    },
    Custody {
        #[command(subcommand)]
        command: MycCustodyCommand,
    },
    Connections {
        #[command(subcommand)]
        command: MycConnectionsCommand,
    },
    Audit {
        #[command(subcommand)]
        command: MycAuditCommand,
    },
    Auth {
        #[command(subcommand)]
        command: MycAuthCommand,
    },
    Connect {
        #[command(subcommand)]
        command: MycConnectCommand,
    },
    Discovery {
        #[command(subcommand)]
        command: MycDiscoveryCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum MycConnectionsCommand {
    List,
    Approve(MycConnectionApprovalArgs),
    Reject(MycConnectionReasonArgs),
    Revoke(MycConnectionReasonArgs),
}

#[derive(Debug, Subcommand)]
pub enum MycPersistenceCommand {
    Backup {
        #[arg(long)]
        out: PathBuf,
    },
    Restore {
        #[arg(long)]
        from: PathBuf,
    },
    ImportJsonToSqlite {
        #[arg(long)]
        signer_state: bool,
        #[arg(long)]
        runtime_audit: bool,
    },
    VerifyRestore,
}

#[derive(Debug, Subcommand)]
pub enum MycCustodyCommand {
    List {
        #[arg(long, value_enum)]
        role: MycCustodyRole,
    },
    Generate {
        #[arg(long, value_enum)]
        role: MycCustodyRole,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        select: bool,
    },
    ImportFile {
        #[arg(long, value_enum)]
        role: MycCustodyRole,
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        select: bool,
    },
    Select {
        #[arg(long, value_enum)]
        role: MycCustodyRole,
        #[arg(long)]
        account_id: String,
    },
    Remove {
        #[arg(long, value_enum)]
        role: MycCustodyRole,
        #[arg(long)]
        account_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum MycAuditCommand {
    List {
        #[arg(long)]
        connection_id: Option<String>,
        #[arg(long)]
        attempt_id: Option<String>,
        #[arg(long, value_enum, default_value_t = MycAuditScope::All)]
        scope: MycAuditScope,
        #[arg(long)]
        limit: Option<usize>,
    },
    Summary {
        #[arg(long)]
        connection_id: Option<String>,
        #[arg(long)]
        attempt_id: Option<String>,
        #[arg(long, value_enum, default_value_t = MycAuditScope::All)]
        scope: MycAuditScope,
        #[arg(long)]
        limit: Option<usize>,
    },
    LatestDiscoveryRepair {
        #[arg(long, value_enum, default_value_t = MycDiscoveryRepairAttemptView::Summary)]
        view: MycDiscoveryRepairAttemptView,
    },
    DiscoveryRepairAttempt {
        #[arg(long)]
        attempt_id: String,
        #[arg(long, value_enum, default_value_t = MycDiscoveryRepairAttemptView::Summary)]
        view: MycDiscoveryRepairAttemptView,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycAuditScope {
    All,
    Request,
    Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycDiscoveryRepairAttemptView {
    Summary,
    Records,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycStatusView {
    Summary,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycMetricsFormat {
    Json,
    Prometheus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycCustodyRole {
    Signer,
    User,
    DiscoveryApp,
}

#[derive(Debug, Subcommand)]
pub enum MycAuthCommand {
    Require {
        #[arg(long)]
        connection_id: String,
        #[arg(long)]
        url: String,
    },
    Authorize {
        #[arg(long)]
        connection_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum MycConnectCommand {
    Accept {
        #[arg(long)]
        uri: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum MycDiscoveryCommand {
    RenderNip05 {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        stdout: bool,
    },
    RenderNip89,
    PublishNip89,
    ExportBundle {
        #[arg(long)]
        out: PathBuf,
    },
    VerifyBundle {
        #[arg(long)]
        dir: PathBuf,
    },
    InspectLiveNip89,
    DiffLiveNip89,
    RefreshNip89 {
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
pub struct MycConnectionApprovalArgs {
    #[arg(long)]
    connection_id: String,
    #[arg(long = "grant")]
    grants: Vec<String>,
}

#[derive(Debug, Args)]
pub struct MycConnectionReasonArgs {
    #[arg(long)]
    connection_id: String,
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MycAuditListOutput {
    pub signer_request_audit: Vec<RadrootsNostrSignerRequestAuditRecord>,
    pub runtime_operation_audit: Vec<MycOperationAuditRecord>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MycAuditSummaryOutput {
    pub record_limit: usize,
    pub signer_request_total: usize,
    pub signer_request_decisions: MycAuditDecisionCounts,
    pub runtime_operation_total: usize,
    pub runtime_operation_outcomes: MycOperationOutcomeCounts,
    pub runtime_operation_by_kind: BTreeMap<String, MycOperationOutcomeCounts>,
    pub runtime_aggregate_publish_rejection_count: usize,
    pub runtime_repair_success_count: usize,
    pub runtime_repair_rejection_count: usize,
    pub runtime_unavailable_count: usize,
    pub runtime_replay_restore_count: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MycDiscoveryRepairAttemptRecordsOutput {
    pub attempt_id: String,
    pub runtime_operation_audit: Vec<MycOperationAuditRecord>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MycDiscoveryRepairAttemptSummaryOutput {
    pub attempt_id: String,
    pub record_count: usize,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compare_outcome: Option<MycOperationAuditOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_outcome: Option<MycOperationAuditOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_outcome: Option<MycOperationAuditOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_relay_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_acknowledged_relay_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_relay_outcome_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_delivery_policy: Option<MycTransportDeliveryPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_required_acknowledged_relay_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_publish_attempt_count: Option<usize>,
    pub repair_summary: MycDiscoveryRepairSummary,
    pub planned_repair_relays: Vec<String>,
    pub blocked_relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    pub failed_relays: Vec<String>,
    pub remaining_repair_relays: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MycDiscoveryRepairAttemptOutput {
    Summary(MycDiscoveryRepairAttemptSummaryOutput),
    Records(MycDiscoveryRepairAttemptRecordsOutput),
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MycStatusOutput {
    Summary(MycStatusSummaryOutput),
    Full(MycStatusFullOutput),
}

pub async fn run_from_env() -> Result<(), MycError> {
    let cli = MycCli::parse();
    let config = load_config(cli.env_file.as_deref())?;

    match cli.command.unwrap_or(MycCommand::Run) {
        MycCommand::Run => {
            logging::init_logging(&config.logging)?;
            MycRuntime::bootstrap(config)?.run().await
        }
        MycCommand::Status { view } => {
            let runtime = MycRuntime::bootstrap(config)?;
            let output = match view {
                MycStatusView::Summary => {
                    MycStatusOutput::Summary(collect_status_summary(&runtime).await?)
                }
                MycStatusView::Full => MycStatusOutput::Full(collect_status_full(&runtime).await?),
            };
            print_json(&output)
        }
        MycCommand::Metrics { format } => {
            let runtime = MycRuntime::bootstrap(config)?;
            let output = collect_metrics(&runtime)?;
            match format {
                MycMetricsFormat::Json => print_json(&output),
                MycMetricsFormat::Prometheus => {
                    print_text(&render_metrics_text(&output));
                    Ok(())
                }
            }
        }
        MycCommand::Persistence { command } => match command {
            MycPersistenceCommand::Backup { out } => {
                let output = backup_persistence(&config, out)?;
                print_json(&output)
            }
            MycPersistenceCommand::Restore { from } => {
                let output = restore_backup(&config, from)?;
                print_json(&output)
            }
            MycPersistenceCommand::ImportJsonToSqlite {
                signer_state,
                runtime_audit,
            } => {
                let output = import_json_to_sqlite(
                    &config,
                    MycPersistenceImportSelection::new(signer_state, runtime_audit),
                )?;
                print_json(&output)
            }
            MycPersistenceCommand::VerifyRestore => {
                let output = verify_restored_state(&config)?;
                print_json(&output)
            }
        },
        MycCommand::Custody { command } => {
            let provider = custody_provider_for_command(&config, &command)?;
            match command {
                MycCustodyCommand::List { .. } => print_json(&provider.list_managed_accounts()?),
                MycCustodyCommand::Generate { label, select, .. } => {
                    let output = provider.generate_managed_account(label, select)?;
                    print_json(&output)
                }
                MycCustodyCommand::ImportFile {
                    path,
                    label,
                    select,
                    ..
                } => {
                    let output = provider.import_managed_account_file(path, label, select)?;
                    print_json(&output)
                }
                MycCustodyCommand::Select { account_id, .. } => {
                    let output = provider.select_managed_account(account_id.as_str())?;
                    print_json(&output)
                }
                MycCustodyCommand::Remove { account_id, .. } => {
                    let output = provider.remove_managed_account(account_id.as_str())?;
                    print_json(&output)
                }
            }
        }
        MycCommand::Connections { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            let backend = runtime.signer_backend();
            match command {
                MycConnectionsCommand::List => print_json(&backend.list_connections()?),
                MycConnectionsCommand::Approve(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let granted_permissions = granted_permissions_for_approval(
                        runtime.signer_context().policy(),
                        &backend.list_connections()?,
                        &connection_id,
                        &args.grants,
                    )?;
                    let connection =
                        backend.approve_connection(&connection_id, granted_permissions)?;
                    print_json(&connection)
                }
                MycConnectionsCommand::Reject(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let connection = backend.reject_connection(&connection_id, args.reason)?;
                    print_json(&connection)
                }
                MycConnectionsCommand::Revoke(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let connection = backend.revoke_connection(&connection_id, args.reason)?;
                    print_json(&connection)
                }
            }
        }
        MycCommand::Audit { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            let manager = runtime.signer_manager()?;
            match command {
                MycAuditCommand::List {
                    connection_id,
                    attempt_id,
                    scope,
                    limit,
                } => {
                    let output = load_audit_output(
                        &runtime,
                        &manager,
                        connection_id.as_deref(),
                        attempt_id.as_deref(),
                        scope,
                        limit,
                    )?;
                    print_json(&output)
                }
                MycAuditCommand::Summary {
                    connection_id,
                    attempt_id,
                    scope,
                    limit,
                } => {
                    let output = summarize_audit_output(
                        &runtime,
                        &manager,
                        connection_id.as_deref(),
                        attempt_id.as_deref(),
                        scope,
                        limit,
                    )?;
                    print_json(&output)
                }
                MycAuditCommand::LatestDiscoveryRepair { view } => {
                    let output = load_latest_discovery_repair_attempt_output(&runtime, view)?;
                    print_json(&output)
                }
                MycAuditCommand::DiscoveryRepairAttempt { attempt_id, view } => {
                    let output =
                        load_discovery_repair_attempt_output(&runtime, attempt_id.as_str(), view)?;
                    print_json(&output)
                }
            }
        }
        MycCommand::Auth { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            let backend = runtime.signer_backend();
            match command {
                MycAuthCommand::Require { connection_id, url } => {
                    let connection_id = parse_connection_id(&connection_id)?;
                    let connection = backend.require_auth_challenge(&connection_id, &url)?;
                    print_json(&connection)
                }
                MycAuthCommand::Authorize { connection_id } => {
                    let connection_id = parse_connection_id(&connection_id)?;
                    let replayed = authorize_auth_challenge(&runtime, &connection_id).await?;
                    print_json(&replayed)
                }
            }
        }
        MycCommand::Connect { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            match command {
                MycConnectCommand::Accept { uri } => {
                    let accepted = accept_client_uri(&runtime, &uri).await?;
                    print_json(&accepted)
                }
            }
        }
        MycCommand::Discovery { command } => match command {
            MycDiscoveryCommand::VerifyBundle { dir } => {
                let output = verify_bundle(dir)?;
                print_json(&output)
            }
            MycDiscoveryCommand::InspectLiveNip89 => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                let output = fetch_live_nip89(&runtime).await?;
                print_json(&output)
            }
            MycDiscoveryCommand::DiffLiveNip89 => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                let output = diff_live_nip89(&runtime).await?;
                print_json(&output)
            }
            MycDiscoveryCommand::RefreshNip89 { force } => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                let output = refresh_nip89(&runtime, force).await?;
                print_json(&output)
            }
            MycDiscoveryCommand::RenderNip05 { out, stdout } => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                if stdout && out.is_some() {
                    return Err(MycError::InvalidOperation(
                        "discovery render-nip05 cannot use --stdout and --out together".to_owned(),
                    ));
                }
                let context = MycDiscoveryContext::from_runtime(&runtime)?;
                if stdout || (out.is_none() && context.nip05_output_path().is_none()) {
                    println!("{}", context.render_nip05_json_pretty()?);
                    Ok(())
                } else {
                    let output = context.write_nip05_document(
                            out.as_deref().or(context.nip05_output_path()).ok_or_else(|| {
                                MycError::InvalidOperation(
                                    "discovery render-nip05 requires --out or discovery.nip05_output_path"
                                        .to_owned(),
                                )
                            })?,
                        )?;
                    print_json(&output)
                }
            }
            MycDiscoveryCommand::RenderNip89 => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                let output = MycDiscoveryContext::from_runtime(&runtime)?.render_nip89_output()?;
                print_json(&output)
            }
            MycDiscoveryCommand::PublishNip89 => {
                let runtime = MycRuntime::bootstrap(config.clone())?;
                let output = publish_nip89_event(&runtime).await?;
                print_json(&output)
            }
            MycDiscoveryCommand::ExportBundle { out } => {
                let runtime = MycRuntime::bootstrap(config)?;
                let output = MycDiscoveryContext::from_runtime(&runtime)?.write_bundle(out)?;
                print_json(&output)
            }
        },
    }
}

fn load_config(path: Option<&Path>) -> Result<MycConfig, MycError> {
    match path {
        Some(path) => MycConfig::load_from_env_path(path),
        None => MycConfig::load_from_env_path(DEFAULT_ENV_PATH),
    }
}

fn custody_provider_for_command(
    config: &MycConfig,
    command: &MycCustodyCommand,
) -> Result<crate::custody::MycIdentityProvider, MycError> {
    let role = match command {
        MycCustodyCommand::List { role }
        | MycCustodyCommand::Generate { role, .. }
        | MycCustodyCommand::ImportFile { role, .. }
        | MycCustodyCommand::Select { role, .. }
        | MycCustodyCommand::Remove { role, .. } => *role,
    };

    custody_provider_for_role(config, role)
}

fn custody_provider_for_role(
    config: &MycConfig,
    role: MycCustodyRole,
) -> Result<crate::custody::MycIdentityProvider, MycError> {
    match role {
        MycCustodyRole::Signer => crate::custody::MycIdentityProvider::from_source(
            "signer",
            config.paths.signer_identity_source(),
        ),
        MycCustodyRole::User => crate::custody::MycIdentityProvider::from_source(
            "user",
            config.paths.user_identity_source(),
        ),
        MycCustodyRole::DiscoveryApp => {
            let Some(source) = config.discovery.app_identity_source() else {
                return Err(MycError::InvalidOperation(
                    "discovery app identity is not separately configured; it currently reuses the signer identity".to_owned(),
                ));
            };
            crate::custody::MycIdentityProvider::from_source("discovery app", source)
        }
    }
}

fn parse_connection_id(value: &str) -> Result<RadrootsNostrSignerConnectionId, MycError> {
    Ok(RadrootsNostrSignerConnectionId::parse(value)?)
}

fn granted_permissions_for_approval(
    policy: &crate::policy::MycPolicyContext,
    connections: &[RadrootsNostrSignerConnectionRecord],
    connection_id: &RadrootsNostrSignerConnectionId,
    grants: &[String],
) -> Result<RadrootsNostrConnectPermissions, MycError> {
    if !grants.is_empty() {
        return policy.validate_operator_grants(parse_permission_values(grants)?);
    }

    let connection = connections
        .iter()
        .find(|connection| &connection.connection_id == connection_id)
        .ok_or_else(|| {
            MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
        })?;
    policy.validate_operator_grants(connection.requested_permissions.clone())
}

fn load_audit_output(
    runtime: &MycRuntime,
    manager: &radroots_nostr_signer::prelude::RadrootsNostrSignerManager,
    connection_id: Option<&str>,
    attempt_id: Option<&str>,
    scope: MycAuditScope,
    limit: Option<usize>,
) -> Result<MycAuditListOutput, MycError> {
    if connection_id.is_some() && attempt_id.is_some() {
        return Err(MycError::InvalidOperation(
            "audit commands cannot filter by both connection_id and attempt_id".to_owned(),
        ));
    }
    if attempt_id.is_some() && scope == MycAuditScope::Request {
        return Err(MycError::InvalidOperation(
            "audit attempt lookup only supports operation or all scope".to_owned(),
        ));
    }

    let limit = audit_read_limit(runtime, limit);
    let connection_id = connection_id.map(parse_connection_id).transpose()?;
    let signer_request_audit = match (scope, connection_id.as_ref()) {
        (MycAuditScope::Operation, _) => Vec::new(),
        (_, Some(connection_id)) => manager
            .audit_records_for_connection(connection_id)?
            .into_iter()
            .rev()
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
        (_, None) => manager
            .list_audit_records()?
            .into_iter()
            .rev()
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
    };
    let runtime_operation_audit = match (scope, connection_id.as_ref(), attempt_id) {
        (MycAuditScope::Request, _, _) => Vec::new(),
        (_, Some(connection_id), _) => runtime
            .operation_audit_store()
            .list_for_connection_with_limit(connection_id, limit)?,
        (_, None, Some(attempt_id)) => runtime
            .operation_audit_store()
            .list_for_attempt_id_with_limit(attempt_id, limit)?,
        (_, None, None) => runtime.operation_audit_store().list_with_limit(limit)?,
    };

    Ok(MycAuditListOutput {
        signer_request_audit,
        runtime_operation_audit,
    })
}

fn summarize_audit_output(
    runtime: &MycRuntime,
    manager: &radroots_nostr_signer::prelude::RadrootsNostrSignerManager,
    connection_id: Option<&str>,
    attempt_id: Option<&str>,
    scope: MycAuditScope,
    limit: Option<usize>,
) -> Result<MycAuditSummaryOutput, MycError> {
    let record_limit = audit_read_limit(runtime, limit);
    let audit = load_audit_output(
        runtime,
        manager,
        connection_id,
        attempt_id,
        scope,
        Some(record_limit),
    )?;
    let mut signer_request_decisions = MycAuditDecisionCounts::default();
    for record in &audit.signer_request_audit {
        match record.decision {
            radroots_nostr_signer::prelude::RadrootsNostrSignerRequestDecision::Allowed => {
                signer_request_decisions.allowed += 1;
            }
            radroots_nostr_signer::prelude::RadrootsNostrSignerRequestDecision::Denied => {
                signer_request_decisions.denied += 1;
            }
            radroots_nostr_signer::prelude::RadrootsNostrSignerRequestDecision::Challenged => {
                signer_request_decisions.challenged += 1;
            }
        }
    }

    let mut runtime_operation_outcomes = MycOperationOutcomeCounts::default();
    let mut runtime_operation_by_kind = BTreeMap::new();
    let mut runtime_aggregate_publish_rejection_count = 0;
    let mut runtime_repair_success_count = 0;
    let mut runtime_repair_rejection_count = 0;
    let mut runtime_unavailable_count = 0;
    let mut runtime_replay_restore_count = 0;
    for record in &audit.runtime_operation_audit {
        increment_outcome_counts(&mut runtime_operation_outcomes, record.outcome);
        let key = operation_kind_label(record.operation);
        increment_outcome_counts(
            runtime_operation_by_kind.entry(key).or_default(),
            record.outcome,
        );
        if is_aggregate_publish_operation(record.operation)
            && record.outcome == MycOperationAuditOutcome::Rejected
        {
            runtime_aggregate_publish_rejection_count += 1;
        }
        if record.operation == MycOperationAuditKind::DiscoveryHandlerRepair {
            match record.outcome {
                MycOperationAuditOutcome::Succeeded => runtime_repair_success_count += 1,
                MycOperationAuditOutcome::Rejected => runtime_repair_rejection_count += 1,
                _ => {}
            }
        }
        if record.outcome == MycOperationAuditOutcome::Unavailable {
            runtime_unavailable_count += 1;
        }
        if record.operation == MycOperationAuditKind::AuthReplayRestore
            && record.outcome == MycOperationAuditOutcome::Restored
        {
            runtime_replay_restore_count += 1;
        }
    }

    Ok(MycAuditSummaryOutput {
        record_limit,
        signer_request_total: audit.signer_request_audit.len(),
        signer_request_decisions,
        runtime_operation_total: audit.runtime_operation_audit.len(),
        runtime_operation_outcomes,
        runtime_operation_by_kind,
        runtime_aggregate_publish_rejection_count,
        runtime_repair_success_count,
        runtime_repair_rejection_count,
        runtime_unavailable_count,
        runtime_replay_restore_count,
    })
}

fn load_latest_discovery_repair_attempt_output(
    runtime: &MycRuntime,
    view: MycDiscoveryRepairAttemptView,
) -> Result<MycDiscoveryRepairAttemptOutput, MycError> {
    let attempt_id = runtime
        .operation_audit_store()
        .latest_attempt_id_for_operation(MycOperationAuditKind::DiscoveryHandlerRefresh)?
        .ok_or_else(|| {
            MycError::InvalidOperation("no discovery repair attempts have been recorded".to_owned())
        })?;
    load_discovery_repair_attempt_output(runtime, attempt_id.as_str(), view)
}

fn load_discovery_repair_attempt_output(
    runtime: &MycRuntime,
    attempt_id: &str,
    view: MycDiscoveryRepairAttemptView,
) -> Result<MycDiscoveryRepairAttemptOutput, MycError> {
    let records = runtime
        .operation_audit_store()
        .list_for_attempt_id(attempt_id)?;
    if records.is_empty() {
        return Err(MycError::InvalidOperation(format!(
            "discovery repair attempt `{attempt_id}` was not found"
        )));
    }

    match view {
        MycDiscoveryRepairAttemptView::Summary => Ok(MycDiscoveryRepairAttemptOutput::Summary(
            MycDiscoveryRepairAttemptSummaryOutput::from_records(attempt_id, &records)?,
        )),
        MycDiscoveryRepairAttemptView::Records => Ok(MycDiscoveryRepairAttemptOutput::Records(
            MycDiscoveryRepairAttemptRecordsOutput {
                attempt_id: attempt_id.to_owned(),
                runtime_operation_audit: records,
            },
        )),
    }
}

fn audit_read_limit(runtime: &MycRuntime, limit: Option<usize>) -> usize {
    limit.unwrap_or(runtime.operation_audit_store().config().default_read_limit)
}

impl MycDiscoveryRepairAttemptSummaryOutput {
    fn from_records(
        attempt_id: &str,
        records: &[MycOperationAuditRecord],
    ) -> Result<Self, MycError> {
        let Some(first_record) = records.first() else {
            return Err(MycError::InvalidOperation(format!(
                "discovery repair attempt `{attempt_id}` had no records"
            )));
        };
        let finished_at_unix = records
            .last()
            .map(|record| record.recorded_at_unix)
            .unwrap_or(first_record.recorded_at_unix);
        let compare_outcome = records.iter().find_map(|record| {
            (record.operation == MycOperationAuditKind::DiscoveryHandlerCompare)
                .then_some(record.outcome)
        });
        let refresh_outcome = records.iter().rev().find_map(|record| {
            (record.operation == MycOperationAuditKind::DiscoveryHandlerRefresh)
                .then_some(record.outcome)
        });
        let refresh_record = records
            .iter()
            .rev()
            .find(|record| record.operation == MycOperationAuditKind::DiscoveryHandlerRefresh);
        let publish_record = records
            .iter()
            .rev()
            .find(|record| record.operation == MycOperationAuditKind::DiscoveryHandlerPublish);

        let mut repair_summary = MycDiscoveryRepairSummary::default();
        let mut failed_relays = Vec::new();
        for record in records
            .iter()
            .filter(|record| record.operation == MycOperationAuditKind::DiscoveryHandlerRepair)
        {
            match record.outcome {
                MycOperationAuditOutcome::Succeeded => repair_summary.repaired += 1,
                MycOperationAuditOutcome::Rejected => {
                    repair_summary.failed += 1;
                    if let Some(relay_url) = record.relay_url.clone() {
                        failed_relays.push(relay_url);
                    }
                }
                MycOperationAuditOutcome::Matched => repair_summary.unchanged += 1,
                MycOperationAuditOutcome::Skipped => repair_summary.skipped += 1,
                _ => {}
            }
        }
        failed_relays.sort();
        failed_relays.dedup();
        let planned_repair_relays = refresh_record
            .map(|record| record.planned_repair_relays.clone())
            .unwrap_or_default();
        let blocked_relays = refresh_record
            .map(|record| record.blocked_relays.clone())
            .unwrap_or_default();
        let blocked_reason = refresh_record.and_then(|record| record.blocked_reason.clone());
        let remaining_repair_relays = if !failed_relays.is_empty() {
            failed_relays.clone()
        } else if matches!(
            refresh_outcome,
            Some(
                MycOperationAuditOutcome::Unavailable
                    | MycOperationAuditOutcome::Conflicted
                    | MycOperationAuditOutcome::Rejected
            )
        ) {
            planned_repair_relays.clone()
        } else {
            Vec::new()
        };

        Ok(Self {
            attempt_id: attempt_id.to_owned(),
            record_count: records.len(),
            started_at_unix: first_record.recorded_at_unix,
            finished_at_unix,
            compare_outcome,
            refresh_outcome,
            aggregate_publish_outcome: publish_record.map(|record| record.outcome),
            aggregate_publish_relay_count: publish_record.map(|record| record.relay_count),
            aggregate_publish_acknowledged_relay_count: publish_record
                .map(|record| record.acknowledged_relay_count),
            aggregate_publish_relay_outcome_summary: publish_record
                .map(|record| record.relay_outcome_summary.clone()),
            aggregate_publish_delivery_policy: publish_record
                .and_then(|record| record.delivery_policy),
            aggregate_publish_required_acknowledged_relay_count: publish_record
                .and_then(|record| record.required_acknowledged_relay_count),
            aggregate_publish_attempt_count: publish_record
                .and_then(|record| record.publish_attempt_count),
            repair_summary,
            planned_repair_relays,
            blocked_relays,
            blocked_reason,
            failed_relays: failed_relays.clone(),
            remaining_repair_relays,
        })
    }
}

fn print_json<T>(value: &T) -> Result<(), MycError>
where
    T: Serialize,
{
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_text(value: &str) {
    println!("{value}");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use nostr::Timestamp;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_connect::prelude::RadrootsNostrConnectRequest;
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionDraft;
    use serde_json::json;

    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::config::MycConfig;

    use super::{
        MycAuditScope, MycCli, MycCommand, MycCustodyCommand, MycCustodyRole,
        granted_permissions_for_approval, load_audit_output, summarize_audit_output,
    };
    use crate::app::MycRuntime;

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime() -> MycRuntime {
        runtime_with_config(|_| {})
    }

    fn runtime_with_config<F>(configure: F) -> MycRuntime
    where
        F: FnOnce(&mut MycConfig),
    {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.audit.default_read_limit = 2;
        config.paths.state_dir = PathBuf::from(&temp).join("state");
        config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
        config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
        configure(&mut config);
        write_identity(
            &config.paths.signer_identity_path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        write_identity(
            &config.paths.user_identity_path,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        MycRuntime::bootstrap(config).expect("runtime")
    }

    #[test]
    fn granted_permissions_for_approval_respects_policy_ceiling() {
        let runtime = runtime_with_config(|config| {
            config.policy.permission_ceiling = "nip04_encrypt".parse().expect("permission ceiling");
        });
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    nostr::Keys::generate().public_key(),
                    runtime.user_public_identity(),
                )
                .with_requested_permissions(
                    "nip44_encrypt".parse().expect("requested permissions"),
                ),
            )
            .expect("register connection");

        let error = granted_permissions_for_approval(
            runtime.signer_context().policy(),
            &manager.list_connections().expect("connections"),
            &connection.connection_id,
            &[],
        )
        .expect_err("requested permissions outside policy should be rejected");

        assert!(
            error
                .to_string()
                .contains("granted permissions exceed the configured policy ceiling")
        );
    }

    #[test]
    fn audit_output_surfaces_both_request_and_operation_records() {
        let runtime = runtime();
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                nostr::Keys::generate().public_key(),
                runtime.user_public_identity(),
            ))
            .expect("register connection");
        let request_evaluation = manager
            .evaluate_request(
                &connection.connection_id,
                radroots_nostr_connect::prelude::RadrootsNostrConnectRequestMessage::new(
                    "request-1",
                    RadrootsNostrConnectRequest::Ping,
                ),
            )
            .expect("record audit");
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::AuthReplayRestore,
            MycOperationAuditOutcome::Restored,
            Some(&connection.connection_id),
            Some(request_evaluation.audit.request_id.as_str()),
            1,
            0,
            "restored pending auth challenge after replay failure",
        ));

        let output = load_audit_output(
            &runtime,
            &manager,
            Some(connection.connection_id.as_str()),
            None,
            MycAuditScope::All,
            None,
        )
        .expect("load audit output");

        assert_eq!(output.signer_request_audit, vec![request_evaluation.audit]);
        assert_eq!(output.runtime_operation_audit.len(), 1);
        assert_eq!(
            output.runtime_operation_audit[0].operation,
            MycOperationAuditKind::AuthReplayRestore
        );
    }

    #[test]
    fn audit_summary_counts_recent_failures_and_restores() {
        let runtime = runtime();
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                nostr::Keys::generate().public_key(),
                runtime.user_public_identity(),
            ))
            .expect("register connection");

        let denied = manager
            .evaluate_request(
                &connection.connection_id,
                radroots_nostr_connect::prelude::RadrootsNostrConnectRequestMessage::new(
                    "request-1",
                    RadrootsNostrConnectRequest::SignEvent(
                        serde_json::from_value(json!({
                            "pubkey": runtime.user_identity().public_key().to_hex(),
                            "created_at": Timestamp::from(1).as_secs(),
                            "kind": 1,
                            "tags": [],
                            "content": "hello"
                        }))
                        .expect("unsigned event"),
                    ),
                ),
            )
            .expect("denied request");
        let challenged = manager
            .require_auth_challenge(&connection.connection_id, "https://auth.example")
            .expect("require auth challenge");
        let challenged_eval = manager
            .evaluate_request(
                &challenged.connection_id,
                radroots_nostr_connect::prelude::RadrootsNostrConnectRequestMessage::new(
                    "request-2",
                    RadrootsNostrConnectRequest::Ping,
                ),
            )
            .expect("challenged request");

        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Rejected,
            Some(&connection.connection_id),
            Some("request-1"),
            1,
            0,
            "listener publish rejected",
        ));
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::AuthReplayRestore,
            MycOperationAuditOutcome::Restored,
            Some(&connection.connection_id),
            Some("request-2"),
            1,
            0,
            "restored pending auth challenge after replay failure",
        ));
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ConnectAcceptPublish,
            MycOperationAuditOutcome::Succeeded,
            Some(&connection.connection_id),
            Some("request-3"),
            1,
            1,
            "publish succeeded",
        ));

        let summary = summarize_audit_output(
            &runtime,
            &manager,
            Some(connection.connection_id.as_str()),
            None,
            MycAuditScope::All,
            None,
        )
        .expect("summary");

        assert_eq!(summary.record_limit, 2);
        assert_eq!(summary.signer_request_total, 2);
        assert_eq!(summary.signer_request_decisions.denied, 1);
        assert_eq!(summary.signer_request_decisions.challenged, 1);
        assert_eq!(summary.runtime_operation_total, 2);
        assert_eq!(summary.runtime_operation_outcomes.succeeded, 1);
        assert_eq!(summary.runtime_operation_outcomes.restored, 1);
        assert_eq!(summary.runtime_aggregate_publish_rejection_count, 0);
        assert_eq!(summary.runtime_repair_success_count, 0);
        assert_eq!(summary.runtime_repair_rejection_count, 0);
        assert_eq!(summary.runtime_unavailable_count, 0);
        assert_eq!(summary.runtime_replay_restore_count, 1);
        assert_eq!(
            summary
                .runtime_operation_by_kind
                .get("auth_replay_restore")
                .expect("restore kind")
                .restored,
            1
        );
        assert_eq!(
            summary
                .runtime_operation_by_kind
                .get("connect_accept_publish")
                .expect("connect kind")
                .succeeded,
            1
        );
        assert_eq!(denied.audit.request_id.as_str(), "request-1");
        assert_eq!(challenged_eval.audit.request_id.as_str(), "request-2");
    }

    #[test]
    fn audit_summary_separates_repair_rejections_from_aggregate_publish_rejections() {
        let runtime = runtime();
        let manager = runtime.signer_manager().expect("manager");
        let connection = manager
            .register_connection(RadrootsNostrSignerConnectionDraft::new(
                nostr::Keys::generate().public_key(),
                runtime.user_public_identity(),
            ))
            .expect("register connection");

        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::DiscoveryHandlerPublish,
            MycOperationAuditOutcome::Succeeded,
            Some(&connection.connection_id),
            Some("request-1"),
            2,
            1,
            "1/2 relays acknowledged publish; failures: relay-b: blocked",
        ));
        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRepair,
                MycOperationAuditOutcome::Succeeded,
                Some(&connection.connection_id),
                Some("request-1"),
                1,
                1,
                "relay repaired",
            )
            .with_relay_url("wss://relay-a.example.com"),
        );
        runtime.record_operation_audit(
            &MycOperationAuditRecord::new(
                MycOperationAuditKind::DiscoveryHandlerRepair,
                MycOperationAuditOutcome::Rejected,
                Some(&connection.connection_id),
                Some("request-1"),
                1,
                0,
                "blocked by relay",
            )
            .with_relay_url("wss://relay-b.example.com"),
        );
        runtime.record_operation_audit(&MycOperationAuditRecord::new(
            MycOperationAuditKind::ListenerResponsePublish,
            MycOperationAuditOutcome::Rejected,
            Some(&connection.connection_id),
            Some("request-2"),
            1,
            0,
            "listener publish rejected",
        ));

        let summary = summarize_audit_output(
            &runtime,
            &manager,
            Some(connection.connection_id.as_str()),
            None,
            MycAuditScope::Operation,
            Some(10),
        )
        .expect("summary");

        assert_eq!(summary.runtime_operation_total, 4);
        assert_eq!(summary.runtime_aggregate_publish_rejection_count, 1);
        assert_eq!(summary.runtime_repair_success_count, 1);
        assert_eq!(summary.runtime_repair_rejection_count, 1);
        assert_eq!(summary.runtime_replay_restore_count, 0);
        assert_eq!(
            summary
                .runtime_operation_by_kind
                .get("discovery_handler_publish")
                .expect("publish kind")
                .succeeded,
            1
        );
        assert_eq!(
            summary
                .runtime_operation_by_kind
                .get("discovery_handler_repair")
                .expect("repair kind")
                .succeeded,
            1
        );
        assert_eq!(
            summary
                .runtime_operation_by_kind
                .get("discovery_handler_repair")
                .expect("repair kind")
                .rejected,
            1
        );
    }

    #[test]
    fn parses_custody_list_command() {
        let cli = MycCli::try_parse_from(["myc", "custody", "list", "--role", "signer"])
            .expect("parse custody list");

        assert!(matches!(
            cli.command,
            Some(MycCommand::Custody {
                command: MycCustodyCommand::List {
                    role: MycCustodyRole::Signer
                }
            })
        ));
    }

    #[test]
    fn parses_custody_generate_and_import_commands() {
        let generate = MycCli::try_parse_from([
            "myc", "custody", "generate", "--role", "user", "--label", "primary", "--select",
        ])
        .expect("parse custody generate");
        assert!(matches!(
            generate.command,
            Some(MycCommand::Custody {
                command: MycCustodyCommand::Generate {
                    role: MycCustodyRole::User,
                    select: true,
                    ..
                }
            })
        ));

        let import = MycCli::try_parse_from([
            "myc",
            "custody",
            "import-file",
            "--role",
            "discovery-app",
            "--path",
            "/tmp/discovery.json",
        ])
        .expect("parse custody import");
        assert!(matches!(
            import.command,
            Some(MycCommand::Custody {
                command: MycCustodyCommand::ImportFile {
                    role: MycCustodyRole::DiscoveryApp,
                    select: false,
                    ..
                }
            })
        ));
    }
}
