use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use radroots_nostr_connect::prelude::RadrootsNostrConnectPermissions;
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
};
use serde::Serialize;

use crate::app::MycRuntime;
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
    },
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
                MycAuditCommand::List { connection_id } => {
                    if let Some(connection_id) = connection_id {
                        let connection_id = parse_connection_id(&connection_id)?;
                        print_json(&manager.audit_records_for_connection(&connection_id)?)
                    } else {
                        print_json(&manager.list_audit_records()?)
                    }
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

fn print_json<T>(value: &T) -> Result<(), MycError>
where
    T: Serialize,
{
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
