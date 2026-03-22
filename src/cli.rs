use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use radroots_nostr_connect::prelude::RadrootsNostrConnectPermissions;
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerRequestAuditRecord,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::audit::MycOperationAuditRecord;
use crate::config::{DEFAULT_CONFIG_PATH, MycConfig};
use crate::control::{accept_client_uri, authorize_auth_challenge, parse_permission_values};
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
                } => {
                    let output =
                        load_audit_output(&runtime, &manager, connection_id.as_deref(), scope)?;
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
) -> Result<MycAuditListOutput, MycError> {
    let connection_id = connection_id.map(parse_connection_id).transpose()?;
    let signer_request_audit = match (scope, connection_id.as_ref()) {
        (MycAuditScope::Operation, _) => Vec::new(),
        (_, Some(connection_id)) => manager.audit_records_for_connection(connection_id)?,
        (_, None) => manager.list_audit_records()?,
    };
    let runtime_operation_audit = match (scope, connection_id.as_ref()) {
        (MycAuditScope::Request, _) => Vec::new(),
        (_, Some(connection_id)) => runtime
            .operation_audit_store()
            .list_for_connection(connection_id)?,
        (_, None) => runtime.operation_audit_store().list()?,
    };

    Ok(MycAuditListOutput {
        signer_request_audit,
        runtime_operation_audit,
    })
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

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_connect::prelude::RadrootsNostrConnectRequest;
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionDraft;

    use crate::audit::{MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord};
    use crate::config::MycConfig;

    use super::{MycAuditScope, load_audit_output};
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
        )
        .expect("load audit output");

        assert_eq!(output.signer_request_audit, vec![request_evaluation.audit]);
        assert_eq!(output.runtime_operation_audit.len(), 1);
        assert_eq!(
            output.runtime_operation_audit[0].operation,
            MycOperationAuditKind::AuthReplayRestore
        );
    }
}
