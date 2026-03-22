use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{Args, Parser, Subcommand};
use radroots_nostr_connect::prelude::{
    RadrootsNostrConnectPermission, RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
    RadrootsNostrConnectResponse, RadrootsNostrConnectUri,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthorizationOutcome,
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerRequestId,
};
use serde::Serialize;

use crate::app::MycRuntime;
use crate::config::{DEFAULT_CONFIG_PATH, MycConfig};
use crate::error::MycError;
use crate::logging;
use crate::transport::{MycNip46Handler, MycNostrTransport};

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

#[derive(Debug, Serialize)]
struct MycAuthorizedReplayOutput {
    connection: RadrootsNostrSignerConnectionRecord,
    replayed_request_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct MycAcceptedConnectionOutput {
    connection: RadrootsNostrSignerConnectionRecord,
    response_request_id: String,
    response_relays: Vec<String>,
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
                    let outcome = runtime
                        .signer_manager()?
                        .authorize_auth_challenge(&connection_id)?;
                    let replayed_request_id = replay_authorized_request(&runtime, &outcome).await?;
                    print_json(&MycAuthorizedReplayOutput {
                        connection: outcome.connection,
                        replayed_request_id,
                    })
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

fn parse_permission_values(values: &[String]) -> Result<RadrootsNostrConnectPermissions, MycError> {
    let mut permissions = Vec::new();
    for value in values {
        for fragment in value.split(',') {
            let trimmed = fragment.trim();
            if trimmed.is_empty() {
                continue;
            }
            permissions.push(RadrootsNostrConnectPermission::from_str(trimmed)?);
        }
    }
    permissions.sort();
    permissions.dedup();
    Ok(permissions.into())
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

async fn replay_authorized_request(
    runtime: &MycRuntime,
    outcome: &RadrootsNostrSignerAuthorizationOutcome,
) -> Result<Option<String>, MycError> {
    let Some(pending_request) = &outcome.pending_request else {
        return Ok(None);
    };
    let transport = runtime.transport().ok_or_else(|| {
        MycError::InvalidOperation(
            "transport.enabled must be true to replay authorized requests".to_owned(),
        )
    })?;
    let handler = MycNip46Handler::new(runtime.signer_context(), transport.relays().to_vec());
    let response = handler.handle_request(
        outcome.connection.client_public_key,
        pending_request.request_message.clone(),
    )?;
    let event = handler.build_response_event(
        outcome.connection.client_public_key,
        pending_request.request_message.id.clone(),
        response,
    )?;
    let publish_relays = if outcome.connection.relays.is_empty() {
        transport.relays().to_vec()
    } else {
        outcome.connection.relays.clone()
    };
    MycNostrTransport::publish_once(
        runtime.signer_identity(),
        &publish_relays,
        transport.connect_timeout_secs(),
        event,
    )
    .await?;
    Ok(Some(pending_request.request_message.id.clone()))
}

async fn accept_client_uri(
    runtime: &MycRuntime,
    uri: &str,
) -> Result<MycAcceptedConnectionOutput, MycError> {
    let Some(transport) = runtime.transport() else {
        return Err(MycError::InvalidOperation(
            "transport.enabled must be true to accept client nostrconnect URIs".to_owned(),
        ));
    };
    let preferred_relays = transport.relays().to_vec();
    if preferred_relays.is_empty() {
        return Err(MycError::InvalidOperation(
            "transport.relays must not be empty to accept client nostrconnect URIs".to_owned(),
        ));
    }

    let client_uri = match RadrootsNostrConnectUri::parse(uri)? {
        RadrootsNostrConnectUri::Client(client_uri) => client_uri,
        RadrootsNostrConnectUri::Bunker(_) => {
            return Err(MycError::InvalidOperation(
                "connect accept requires a nostrconnect:// client URI".to_owned(),
            ));
        }
    };

    let request = RadrootsNostrConnectRequest::Connect {
        remote_signer_public_key: runtime.signer_identity().public_key(),
        secret: Some(client_uri.secret.clone()),
        requested_permissions: client_uri.metadata.requested_permissions.clone(),
    };
    let manager = runtime.signer_manager()?;
    let proposal = match manager.evaluate_connect_request(client_uri.client_public_key, request)? {
        radroots_nostr_signer::prelude::RadrootsNostrSignerConnectEvaluation::ExistingConnection(_) => {
            return Err(MycError::InvalidOperation(
                "connect secret is already bound to an existing connection".to_owned(),
            ));
        }
        radroots_nostr_signer::prelude::RadrootsNostrSignerConnectEvaluation::RegistrationRequired(
            proposal,
        ) => proposal,
    };

    let draft = proposal
        .into_connection_draft(runtime.user_public_identity())
        .with_relays(preferred_relays.clone())
        .with_approval_requirement(runtime.signer_context().connection_approval_requirement());
    let connection = manager.register_connection(draft)?;
    if runtime.signer_context().connection_approval_requirement()
        == RadrootsNostrSignerApprovalRequirement::NotRequired
    {
        let _ = manager.set_granted_permissions(
            &connection.connection_id,
            connection.requested_permissions.clone(),
        )?;
    }

    let handler = MycNip46Handler::new(runtime.signer_context(), preferred_relays.clone());
    let response_request_id = RadrootsNostrSignerRequestId::new_v7().into_string();
    let event = handler.build_response_event(
        client_uri.client_public_key,
        response_request_id.clone(),
        RadrootsNostrConnectResponse::ConnectSecretEcho(client_uri.secret),
    )?;
    let response_relays = merge_relays(&client_uri.relays, &preferred_relays);
    MycNostrTransport::publish_once(
        runtime.signer_identity(),
        &response_relays,
        transport.connect_timeout_secs(),
        event,
    )
    .await?;

    Ok(MycAcceptedConnectionOutput {
        connection: runtime
            .signer_manager()?
            .list_connections()?
            .into_iter()
            .find(|record| record.connection_id == connection.connection_id)
            .ok_or_else(|| {
                MycError::InvalidOperation("accepted connection was not persisted".to_owned())
            })?,
        response_request_id,
        response_relays: response_relays.iter().map(ToString::to_string).collect(),
    })
}

fn merge_relays(
    primary: &[nostr::RelayUrl],
    secondary: &[nostr::RelayUrl],
) -> Vec<nostr::RelayUrl> {
    let mut relays = primary.to_vec();
    relays.extend_from_slice(secondary);
    relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relays.dedup_by(|left, right| left.as_str() == right.as_str());
    relays
}

fn print_json<T>(value: &T) -> Result<(), MycError>
where
    T: Serialize,
{
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
