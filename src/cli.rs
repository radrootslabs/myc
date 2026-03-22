use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use radroots_nostr_connect::prelude::RadrootsNostrConnectPermissions;
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerRequestAuditRecord,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
use crate::config::{DEFAULT_CONFIG_PATH, MycConfig};
use crate::control::{accept_client_uri, authorize_auth_challenge, parse_permission_values};
use crate::discovery::{
    MycDiscoveryContext, diff_live_nip89, fetch_live_nip89, publish_nip89_event, refresh_nip89,
    verify_bundle,
};
use crate::error::MycError;
use crate::logging;

#[derive(Debug, Parser)]
#[command(name = "myc")]
#[command(about = "Mycorrhiza NIP-46 signer service")]
pub struct MycCli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<MycCommand>,
}

#[derive(Debug, Subcommand)]
pub enum MycCommand {
    Run,
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
pub enum MycAuditCommand {
    List {
        #[arg(long)]
        connection_id: Option<String>,
        #[arg(long, value_enum, default_value_t = MycAuditScope::All)]
        scope: MycAuditScope,
        #[arg(long)]
        limit: Option<usize>,
    },
    Summary {
        #[arg(long)]
        connection_id: Option<String>,
        #[arg(long, value_enum, default_value_t = MycAuditScope::All)]
        scope: MycAuditScope,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MycAuditScope {
    All,
    Request,
    Operation,
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

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct MycAuditDecisionCounts {
    pub allowed: usize,
    pub denied: usize,
    pub challenged: usize,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct MycOperationOutcomeCounts {
    pub succeeded: usize,
    pub rejected: usize,
    pub restored: usize,
    pub missing: usize,
    pub matched: usize,
    pub drifted: usize,
    pub conflicted: usize,
    pub skipped: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MycAuditSummaryOutput {
    pub record_limit: usize,
    pub signer_request_total: usize,
    pub signer_request_decisions: MycAuditDecisionCounts,
    pub runtime_operation_total: usize,
    pub runtime_operation_outcomes: MycOperationOutcomeCounts,
    pub runtime_operation_by_kind: BTreeMap<String, MycOperationOutcomeCounts>,
    pub runtime_publish_rejection_count: usize,
    pub runtime_replay_restore_count: usize,
}

pub async fn run_from_env() -> Result<(), MycError> {
    let cli = MycCli::parse();
    let config = load_config(cli.config.as_deref())?;

    match cli.command.unwrap_or(MycCommand::Run) {
        MycCommand::Run => {
            logging::init_logging(&config.logging)?;
            MycRuntime::bootstrap(config)?.run().await
        }
        MycCommand::Connections { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            match command {
                MycConnectionsCommand::List => {
                    let manager = runtime.signer_manager()?;
                    print_json(&manager.list_connections()?)
                }
                MycConnectionsCommand::Approve(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let manager = runtime.signer_manager()?;
                    let granted_permissions = granted_permissions_for_approval(
                        &manager.list_connections()?,
                        &connection_id,
                        &args.grants,
                    )?;
                    let connection =
                        manager.approve_connection(&connection_id, granted_permissions)?;
                    print_json(&connection)
                }
                MycConnectionsCommand::Reject(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let manager = runtime.signer_manager()?;
                    let connection = manager.reject_connection(&connection_id, args.reason)?;
                    print_json(&connection)
                }
                MycConnectionsCommand::Revoke(args) => {
                    let connection_id = parse_connection_id(&args.connection_id)?;
                    let manager = runtime.signer_manager()?;
                    let connection = manager.revoke_connection(&connection_id, args.reason)?;
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
                    scope,
                    limit,
                } => {
                    let output = load_audit_output(
                        &runtime,
                        &manager,
                        connection_id.as_deref(),
                        scope,
                        limit,
                    )?;
                    print_json(&output)
                }
                MycAuditCommand::Summary {
                    connection_id,
                    scope,
                    limit,
                } => {
                    let output = summarize_audit_output(
                        &runtime,
                        &manager,
                        connection_id.as_deref(),
                        scope,
                        limit,
                    )?;
                    print_json(&output)
                }
            }
        }
        MycCommand::Auth { command } => {
            let runtime = MycRuntime::bootstrap(config)?;
            match command {
                MycAuthCommand::Require { connection_id, url } => {
                    let connection_id = parse_connection_id(&connection_id)?;
                    let manager = runtime.signer_manager()?;
                    let connection = manager.require_auth_challenge(&connection_id, url)?;
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
        Some(path) => MycConfig::load_from_path_if_exists(path),
        None => MycConfig::load_from_path_if_exists(DEFAULT_CONFIG_PATH),
    }
}

fn parse_connection_id(value: &str) -> Result<RadrootsNostrSignerConnectionId, MycError> {
    Ok(RadrootsNostrSignerConnectionId::parse(value)?)
}

fn granted_permissions_for_approval(
    connections: &[RadrootsNostrSignerConnectionRecord],
    connection_id: &RadrootsNostrSignerConnectionId,
    grants: &[String],
) -> Result<RadrootsNostrConnectPermissions, MycError> {
    if !grants.is_empty() {
        return parse_permission_values(grants);
    }

    let connection = connections
        .iter()
        .find(|connection| &connection.connection_id == connection_id)
        .ok_or_else(|| {
            MycError::InvalidOperation(format!("connection `{connection_id}` was not found"))
        })?;
    Ok(connection.requested_permissions.clone())
}

fn load_audit_output(
    runtime: &MycRuntime,
    manager: &radroots_nostr_signer::prelude::RadrootsNostrSignerManager,
    connection_id: Option<&str>,
    scope: MycAuditScope,
    limit: Option<usize>,
) -> Result<MycAuditListOutput, MycError> {
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
    let runtime_operation_audit = match (scope, connection_id.as_ref()) {
        (MycAuditScope::Request, _) => Vec::new(),
        (_, Some(connection_id)) => runtime
            .operation_audit_store()
            .list_for_connection_with_limit(connection_id, limit)?,
        (_, None) => runtime.operation_audit_store().list_with_limit(limit)?,
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
    scope: MycAuditScope,
    limit: Option<usize>,
) -> Result<MycAuditSummaryOutput, MycError> {
    let record_limit = audit_read_limit(runtime, limit);
    let audit = load_audit_output(runtime, manager, connection_id, scope, Some(record_limit))?;
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
    let mut runtime_publish_rejection_count = 0;
    let mut runtime_replay_restore_count = 0;
    for record in &audit.runtime_operation_audit {
        increment_outcome_counts(&mut runtime_operation_outcomes, record.outcome);
        let key = operation_kind_label(record.operation);
        increment_outcome_counts(
            runtime_operation_by_kind.entry(key).or_default(),
            record.outcome,
        );
        if record.outcome == MycOperationAuditOutcome::Rejected {
            runtime_publish_rejection_count += 1;
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
        runtime_publish_rejection_count,
        runtime_replay_restore_count,
    })
}

fn audit_read_limit(runtime: &MycRuntime, limit: Option<usize>) -> usize {
    limit.unwrap_or(runtime.operation_audit_store().config().default_read_limit)
}

fn increment_outcome_counts(
    counts: &mut MycOperationOutcomeCounts,
    outcome: MycOperationAuditOutcome,
) {
    match outcome {
        MycOperationAuditOutcome::Succeeded => counts.succeeded += 1,
        MycOperationAuditOutcome::Rejected => counts.rejected += 1,
        MycOperationAuditOutcome::Restored => counts.restored += 1,
        MycOperationAuditOutcome::Missing => counts.missing += 1,
        MycOperationAuditOutcome::Matched => counts.matched += 1,
        MycOperationAuditOutcome::Drifted => counts.drifted += 1,
        MycOperationAuditOutcome::Conflicted => counts.conflicted += 1,
        MycOperationAuditOutcome::Skipped => counts.skipped += 1,
    }
}

fn operation_kind_label(kind: MycOperationAuditKind) -> String {
    match kind {
        MycOperationAuditKind::ListenerResponsePublish => "listener_response_publish".to_owned(),
        MycOperationAuditKind::ConnectAcceptPublish => "connect_accept_publish".to_owned(),
        MycOperationAuditKind::AuthReplayPublish => "auth_replay_publish".to_owned(),
        MycOperationAuditKind::AuthReplayRestore => "auth_replay_restore".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerPublish => "discovery_handler_publish".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerCompare => "discovery_handler_compare".to_owned(),
        MycOperationAuditKind::DiscoveryHandlerRefresh => "discovery_handler_refresh".to_owned(),
    }
}

fn print_json<T>(value: &T) -> Result<(), MycError>
where
    T: Serialize,
{
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nostr::Timestamp;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_connect::prelude::RadrootsNostrConnectRequest;
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionDraft;
    use serde_json::json;

    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::config::MycConfig;

    use super::{MycAuditScope, load_audit_output, summarize_audit_output};
    use crate::app::MycRuntime;

    fn write_identity(path: &std::path::Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn runtime() -> MycRuntime {
        let temp = tempfile::tempdir().expect("tempdir").keep();
        let mut config = MycConfig::default();
        config.audit.default_read_limit = 2;
        config.paths.state_dir = PathBuf::from(&temp).join("state");
        config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
        config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
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
        assert_eq!(summary.runtime_publish_rejection_count, 0);
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
}
