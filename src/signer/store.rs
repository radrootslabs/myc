use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::model::RadrootsNostrSignerStoreState;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::host_identity::RadrootsIdentityPublic as PublicIdentity;
use crate::signer::model::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerApprovalState,
    RadrootsNostrSignerAuthChallenge, RadrootsNostrSignerAuthState,
    RadrootsNostrSignerConnectSecretHash, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerConnectionStatus, RadrootsNostrSignerPendingRequest,
    RadrootsNostrSignerPermissionGrant, RadrootsNostrSignerPublishWorkflowKind,
    RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerPublishWorkflowState,
    RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestDecision,
};
use crate::signer::sqlite::RadrootsNostrSignerSqliteDb;
use crate::sql::SqlExecutor;
use nostr::RelayUrl;
use radroots_nostr_connect::{Method, Permission, message::RequestMessage, uri::ClientMetadata};
use std::collections::BTreeMap;

pub trait RadrootsNostrSignerStore: Send + Sync {
    fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError>;
    fn save(&self, state: &RadrootsNostrSignerStoreState) -> Result<(), RadrootsNostrSignerError>;
}

#[derive(Debug, Clone)]
pub struct RadrootsNostrFileSignerStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct RadrootsNostrMemorySignerStore {
    state: Arc<RwLock<RadrootsNostrSignerStoreState>>,
}

#[derive(Clone)]
pub struct RadrootsNostrSqliteSignerStore {
    db: Arc<RadrootsNostrSignerSqliteDb>,
}

impl RadrootsNostrFileSignerStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl RadrootsNostrMemorySignerStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RadrootsNostrSqliteSignerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RadrootsNostrSignerError> {
        Ok(Self {
            db: Arc::new(RadrootsNostrSignerSqliteDb::open(path)?),
        })
    }

    pub fn open_memory() -> Result<Self, RadrootsNostrSignerError> {
        Ok(Self {
            db: Arc::new(RadrootsNostrSignerSqliteDb::open_memory()?),
        })
    }
}

impl RadrootsNostrSignerStore for RadrootsNostrFileSignerStore {
    fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
        if !self.path.exists() {
            return Ok(RadrootsNostrSignerStoreState::default());
        }
        let encoded = fs::read(self.path.as_path())
            .map_err(|_| RadrootsNostrSignerError::Store("read signer state".into()))?;
        serde_json::from_slice(encoded.as_slice()).map_err(Into::into)
    }

    fn save(&self, state: &RadrootsNostrSignerStoreState) -> Result<(), RadrootsNostrSignerError> {
        if self.path.exists() {
            let _ = self.load()?;
        }
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|_| RadrootsNostrSignerError::Store("create signer state directory".into()))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| {
            RadrootsNostrSignerError::Store("create signer state temporary file".into())
        })?;
        serde_json::to_writer_pretty(&mut temporary, state)?;
        temporary
            .write_all(b"\n")
            .map_err(|_| RadrootsNostrSignerError::Store("write signer state".into()))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| RadrootsNostrSignerError::Store("sync signer state".into()))?;
        set_private_file_permissions(temporary.as_file())?;
        temporary
            .persist(self.path.as_path())
            .map_err(|_| RadrootsNostrSignerError::Store("persist signer state".into()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| RadrootsNostrSignerError::Store("sync signer state directory".into()))?;
        Ok(())
    }
}

fn set_private_file_permissions(file: &fs::File) -> Result<(), RadrootsNostrSignerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RadrootsNostrSignerError::Store("set signer state permissions".into()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

impl RadrootsNostrSignerStore for RadrootsNostrMemorySignerStore {
    fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
        let guard = self
            .state
            .read()
            .map_err(|_| RadrootsNostrSignerError::Store("memory store lock poisoned".into()))?;
        Ok(guard.clone())
    }

    fn save(&self, state: &RadrootsNostrSignerStoreState) -> Result<(), RadrootsNostrSignerError> {
        let mut guard = self
            .state
            .write()
            .map_err(|_| RadrootsNostrSignerError::Store("memory store lock poisoned".into()))?;
        *guard = state.clone();
        Ok(())
    }
}

impl RadrootsNostrSignerStore for RadrootsNostrSqliteSignerStore {
    fn load(&self) -> Result<RadrootsNostrSignerStoreState, RadrootsNostrSignerError> {
        let metadata_rows: Vec<SignerStoreMetadataRow> = query_rows(
            self.db.as_ref(),
            "SELECT store_version, signer_identity_json FROM signer_store_metadata WHERE singleton_id = 1",
        )?;
        let metadata = match metadata_rows.as_slice() {
            [row] => row,
            [] => {
                return Err(RadrootsNostrSignerError::Store(
                    "sqlite signer metadata row missing".into(),
                ));
            }
            _ => {
                return Err(RadrootsNostrSignerError::Store(
                    "sqlite signer metadata row is not singular".into(),
                ));
            }
        };

        let mut state = RadrootsNostrSignerStoreState {
            version: u32::try_from(metadata.store_version).map_err(|_| {
                RadrootsNostrSignerError::Store(format!(
                    "sqlite signer store version {} is out of range",
                    metadata.store_version
                ))
            })?,
            signer_identity: metadata
                .signer_identity_json
                .as_deref()
                .map(parse_json_field::<PublicIdentity>)
                .transpose()?,
            connections: Vec::new(),
            audit_records: Vec::new(),
            publish_workflows: Vec::new(),
        };

        let connection_rows: Vec<SignerConnectionRow> = query_rows(
            self.db.as_ref(),
            "SELECT connection_id, client_public_key_hex, signer_identity_json, user_identity_json, connect_secret_hash_algorithm, connect_secret_hash_digest_hex, connect_secret_consumed_at_unix, requested_permissions_json, client_metadata_json, approval_requirement, approval_state, auth_state, status, status_reason, created_at_unix, updated_at_unix, last_authenticated_at_unix, last_request_at_unix FROM signer_connection ORDER BY created_at_unix, connection_id",
        )?;
        let mut connection_indexes = BTreeMap::new();
        for row in connection_rows {
            let connection = row.into_record()?;
            connection_indexes.insert(
                connection.connection_id.as_str().to_owned(),
                state.connections.len(),
            );
            state.connections.push(connection);
        }

        let permission_rows: Vec<SignerConnectionPermissionGrantRow> = query_rows(
            self.db.as_ref(),
            "SELECT connection_id, permission, granted_at_unix FROM signer_connection_permission_grant ORDER BY connection_id, granted_at_unix, permission",
        )?;
        for row in permission_rows {
            let index = *connection_indexes
                .get(row.connection_id.as_str())
                .ok_or_else(|| {
                    RadrootsNostrSignerError::Store(format!(
                        "permission grant row references missing connection `{}`",
                        row.connection_id
                    ))
                })?;
            state.connections[index]
                .granted_permissions
                .push(row.into_grant()?);
        }

        let relay_rows: Vec<SignerConnectionRelayRow> = query_rows(
            self.db.as_ref(),
            "SELECT connection_id, relay_url FROM signer_connection_relay ORDER BY connection_id, ordinal",
        )?;
        for row in relay_rows {
            let index = *connection_indexes
                .get(row.connection_id.as_str())
                .ok_or_else(|| {
                    RadrootsNostrSignerError::Store(format!(
                        "relay row references missing connection `{}`",
                        row.connection_id
                    ))
                })?;
            state.connections[index].relays.push(
                RelayUrl::parse(row.relay_url.as_str())
                    .map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))?,
            );
        }

        let auth_rows: Vec<SignerConnectionAuthChallengeRow> = query_rows(
            self.db.as_ref(),
            "SELECT connection_id, auth_url, required_at_unix, authorized_at_unix FROM signer_connection_auth_challenge",
        )?;
        for row in auth_rows {
            let index = *connection_indexes
                .get(row.connection_id.as_str())
                .ok_or_else(|| {
                    RadrootsNostrSignerError::Store(format!(
                        "auth challenge row references missing connection `{}`",
                        row.connection_id
                    ))
                })?;
            state.connections[index].auth_challenge = Some(
                RadrootsNostrSignerAuthChallenge::new(row.auth_url.as_str(), row.required_at_unix)
                    .map(|mut challenge| {
                        challenge.authorized_at_unix = row.authorized_at_unix;
                        challenge
                    })?,
            );
        }

        let pending_rows: Vec<SignerConnectionPendingRequestRow> = query_rows(
            self.db.as_ref(),
            "SELECT connection_id, request_message_json, created_at_unix FROM signer_connection_pending_request",
        )?;
        for row in pending_rows {
            let index = *connection_indexes
                .get(row.connection_id.as_str())
                .ok_or_else(|| {
                    RadrootsNostrSignerError::Store(format!(
                        "pending request row references missing connection `{}`",
                        row.connection_id
                    ))
                })?;
            let request_message =
                parse_json_field::<RequestMessage>(row.request_message_json.as_str())?;
            state.connections[index].pending_request = Some(
                RadrootsNostrSignerPendingRequest::new(request_message, row.created_at_unix)?,
            );
        }

        let audit_rows: Vec<SignerRequestAuditRow> = query_rows(
            self.db.as_ref(),
            "SELECT request_id, connection_id, method, decision, message, created_at_unix FROM signer_request_audit ORDER BY created_at_unix, request_id",
        )?;
        state.audit_records = audit_rows
            .into_iter()
            .map(SignerRequestAuditRow::into_record)
            .collect::<Result<Vec<_>, _>>()?;

        let workflow_rows: Vec<SignerPublishWorkflowRow> = query_rows(
            self.db.as_ref(),
            "SELECT workflow_id, connection_id, kind, state, pending_request_json, authorized_at_unix, created_at_unix, updated_at_unix FROM signer_publish_workflow ORDER BY created_at_unix, workflow_id",
        )?;
        state.publish_workflows = workflow_rows
            .into_iter()
            .map(SignerPublishWorkflowRow::into_record)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(state)
    }

    fn save(&self, state: &RadrootsNostrSignerStoreState) -> Result<(), RadrootsNostrSignerError> {
        let executor = self.db.executor();
        executor.begin()?;
        let result = (|| -> Result<(), RadrootsNostrSignerError> {
            exec_json(executor, "DELETE FROM signer_publish_workflow", json!([]))?;
            exec_json(executor, "DELETE FROM signer_request_audit", json!([]))?;
            exec_json(executor, "DELETE FROM signer_connection", json!([]))?;

            exec_json(
                executor,
                "INSERT INTO signer_store_metadata(singleton_id, store_version, signer_identity_id, signer_identity_public_key_hex, signer_identity_json, updated_at) VALUES(1, ?, ?, ?, ?, datetime('now')) ON CONFLICT(singleton_id) DO UPDATE SET store_version = excluded.store_version, signer_identity_id = excluded.signer_identity_id, signer_identity_public_key_hex = excluded.signer_identity_public_key_hex, signer_identity_json = excluded.signer_identity_json, updated_at = excluded.updated_at",
                json!([
                    i64::from(state.version),
                    state
                        .signer_identity
                        .as_ref()
                        .map(|identity| identity.id().to_string()),
                    state
                        .signer_identity
                        .as_ref()
                        .map(|identity| identity.public_key().to_hex()),
                    state
                        .signer_identity
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                ]),
            )?;

            for connection in &state.connections {
                exec_json(
                    executor,
                    "INSERT INTO signer_connection(connection_id, client_public_key_hex, signer_identity_id, signer_identity_public_key_hex, signer_identity_json, user_identity_id, user_identity_public_key_hex, user_identity_json, connect_secret_hash_algorithm, connect_secret_hash_digest_hex, connect_secret_consumed_at_unix, requested_permissions_json, client_metadata_json, approval_requirement, approval_state, auth_state, status, status_reason, created_at_unix, updated_at_unix, last_authenticated_at_unix, last_request_at_unix) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    json!([
                        connection.connection_id.as_str(),
                        connection.client_public_key.to_hex(),
                        connection.signer_identity.id().to_string(),
                        connection.signer_identity.public_key().to_hex(),
                        serde_json::to_string(&connection.signer_identity)?,
                        connection.user_identity.id().to_string(),
                        connection.user_identity.public_key().to_hex(),
                        serde_json::to_string(&connection.user_identity)?,
                        connection
                            .connect_secret_hash
                            .as_ref()
                            .map(|hash| secret_digest_algorithm_label(hash)),
                        connection
                            .connect_secret_hash
                            .as_ref()
                            .map(|hash| hash.digest_hex.clone()),
                        connection.connect_secret_consumed_at_unix,
                        serde_json::to_string(&connection.requested_permissions)?,
                        connection
                            .client_metadata
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                        approval_requirement_label(connection.approval_requirement),
                        approval_state_label(connection.approval_state),
                        auth_state_label(connection.auth_state),
                        connection_status_label(connection.status),
                        connection.status_reason.clone(),
                        connection.created_at_unix,
                        connection.updated_at_unix,
                        connection.last_authenticated_at_unix,
                        connection.last_request_at_unix,
                    ]),
                )?;

                for grant in &connection.granted_permissions {
                    exec_json(
                        executor,
                        "INSERT INTO signer_connection_permission_grant(connection_id, permission, granted_at_unix) VALUES(?, ?, ?)",
                        json!([
                            connection.connection_id.as_str(),
                            grant.permission.to_string(),
                            grant.granted_at_unix,
                        ]),
                    )?;
                }

                for (ordinal, relay) in connection.relays.iter().enumerate() {
                    exec_json(
                        executor,
                        "INSERT INTO signer_connection_relay(connection_id, ordinal, relay_url) VALUES(?, ?, ?)",
                        json!([
                            connection.connection_id.as_str(),
                            i64::try_from(ordinal).map_err(|_| {
                                RadrootsNostrSignerError::Store(format!(
                                    "relay ordinal for connection `{}` is out of range",
                                    connection.connection_id
                                ))
                            })?,
                            relay.as_str(),
                        ]),
                    )?;
                }

                if let Some(challenge) = connection.auth_challenge.as_ref() {
                    exec_json(
                        executor,
                        "INSERT INTO signer_connection_auth_challenge(connection_id, auth_url, required_at_unix, authorized_at_unix) VALUES(?, ?, ?, ?)",
                        json!([
                            connection.connection_id.as_str(),
                            challenge.auth_url,
                            challenge.required_at_unix,
                            challenge.authorized_at_unix,
                        ]),
                    )?;
                }

                if let Some(pending_request) = connection.pending_request.as_ref() {
                    exec_json(
                        executor,
                        "INSERT INTO signer_connection_pending_request(connection_id, request_message_json, created_at_unix) VALUES(?, ?, ?)",
                        json!([
                            connection.connection_id.as_str(),
                            serde_json::to_string(&pending_request.request_message)?,
                            pending_request.created_at_unix,
                        ]),
                    )?;
                }
            }

            for audit in &state.audit_records {
                exec_json(
                    executor,
                    "INSERT INTO signer_request_audit(request_id, connection_id, method, decision, message, created_at_unix) VALUES(?, ?, ?, ?, ?, ?)",
                    json!([
                        audit.request_id.as_str(),
                        audit.connection_id.as_str(),
                        audit.method.to_string(),
                        request_decision_label(audit.decision),
                        audit.message.clone(),
                        audit.created_at_unix,
                    ]),
                )?;
            }

            for workflow in &state.publish_workflows {
                exec_json(
                    executor,
                    "INSERT INTO signer_publish_workflow(workflow_id, connection_id, kind, state, pending_request_json, authorized_at_unix, created_at_unix, updated_at_unix) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    json!([
                        workflow.workflow_id.as_str(),
                        workflow.connection_id.as_str(),
                        publish_workflow_kind_label(workflow.kind),
                        publish_workflow_state_label(workflow.state),
                        workflow
                            .pending_request
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()?,
                        workflow.authorized_at_unix,
                        workflow.created_at_unix,
                        workflow.updated_at_unix,
                    ]),
                )?;
            }

            Ok(())
        })();

        match result {
            Ok(()) => {
                executor.commit()?;
                Ok(())
            }
            Err(error) => {
                let _ = executor.rollback();
                Err(error)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct SignerStoreMetadataRow {
    store_version: i64,
    signer_identity_json: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignerConnectionRow {
    connection_id: String,
    client_public_key_hex: String,
    signer_identity_json: String,
    user_identity_json: String,
    connect_secret_hash_algorithm: Option<String>,
    connect_secret_hash_digest_hex: Option<String>,
    connect_secret_consumed_at_unix: Option<u64>,
    requested_permissions_json: String,
    client_metadata_json: Option<String>,
    approval_requirement: String,
    approval_state: String,
    auth_state: String,
    status: String,
    status_reason: Option<String>,
    created_at_unix: u64,
    updated_at_unix: u64,
    last_authenticated_at_unix: Option<u64>,
    last_request_at_unix: Option<u64>,
}

impl SignerConnectionRow {
    fn into_record(self) -> Result<RadrootsNostrSignerConnectionRecord, RadrootsNostrSignerError> {
        Ok(RadrootsNostrSignerConnectionRecord {
            connection_id: self.connection_id.parse()?,
            client_public_key: parse_public_key_hex(self.client_public_key_hex.as_str())?,
            signer_identity: parse_json_field(self.signer_identity_json.as_str())?,
            user_identity: parse_json_field(self.user_identity_json.as_str())?,
            connect_secret_hash: match (
                self.connect_secret_hash_algorithm.as_deref(),
                self.connect_secret_hash_digest_hex,
            ) {
                (None, None) => None,
                (Some(algorithm), Some(digest_hex)) => Some(RadrootsNostrSignerConnectSecretHash {
                    algorithm: parse_secret_digest_algorithm(algorithm)?,
                    digest_hex,
                }),
                _ => {
                    return Err(RadrootsNostrSignerError::Store(
                        "sqlite connection secret hash columns are inconsistent".into(),
                    ));
                }
            },
            connect_secret_consumed_at_unix: self.connect_secret_consumed_at_unix,
            requested_permissions: parse_json_field(self.requested_permissions_json.as_str())?,
            client_metadata: self
                .client_metadata_json
                .as_deref()
                .map(parse_json_field::<ClientMetadata>)
                .transpose()?,
            granted_permissions: Vec::new(),
            relays: Vec::new(),
            approval_requirement: parse_approval_requirement(self.approval_requirement.as_str())?,
            approval_state: parse_approval_state(self.approval_state.as_str())?,
            auth_state: parse_auth_state(self.auth_state.as_str())?,
            auth_challenge: None,
            pending_request: None,
            status: parse_connection_status(self.status.as_str())?,
            status_reason: self.status_reason,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
            last_authenticated_at_unix: self.last_authenticated_at_unix,
            last_request_at_unix: self.last_request_at_unix,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SignerConnectionPermissionGrantRow {
    connection_id: String,
    permission: String,
    granted_at_unix: u64,
}

impl SignerConnectionPermissionGrantRow {
    fn into_grant(self) -> Result<RadrootsNostrSignerPermissionGrant, RadrootsNostrSignerError> {
        Ok(RadrootsNostrSignerPermissionGrant {
            permission: self
                .permission
                .parse::<Permission>()
                .map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))?,
            granted_at_unix: self.granted_at_unix,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SignerConnectionRelayRow {
    connection_id: String,
    relay_url: String,
}

#[derive(Debug, Deserialize)]
struct SignerConnectionAuthChallengeRow {
    connection_id: String,
    auth_url: String,
    required_at_unix: u64,
    authorized_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SignerConnectionPendingRequestRow {
    connection_id: String,
    request_message_json: String,
    created_at_unix: u64,
}

#[derive(Debug, Deserialize)]
struct SignerRequestAuditRow {
    request_id: String,
    connection_id: String,
    method: String,
    decision: String,
    message: Option<String>,
    created_at_unix: u64,
}

impl SignerRequestAuditRow {
    fn into_record(
        self,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerError> {
        Ok(RadrootsNostrSignerRequestAuditRecord {
            request_id: self.request_id.parse()?,
            connection_id: self.connection_id.parse()?,
            method: self
                .method
                .parse::<Method>()
                .map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))?,
            decision: parse_request_decision(self.decision.as_str())?,
            message: self.message,
            created_at_unix: self.created_at_unix,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SignerPublishWorkflowRow {
    workflow_id: String,
    connection_id: String,
    kind: String,
    state: String,
    pending_request_json: Option<String>,
    authorized_at_unix: Option<u64>,
    created_at_unix: u64,
    updated_at_unix: u64,
}

impl SignerPublishWorkflowRow {
    fn into_record(
        self,
    ) -> Result<RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerError> {
        Ok(RadrootsNostrSignerPublishWorkflowRecord {
            workflow_id: self.workflow_id.parse()?,
            connection_id: self.connection_id.parse()?,
            kind: parse_publish_workflow_kind(self.kind.as_str())?,
            state: parse_publish_workflow_state(self.state.as_str())?,
            pending_request: self
                .pending_request_json
                .as_deref()
                .map(parse_json_field::<RadrootsNostrSignerPendingRequest>)
                .transpose()?,
            authorized_at_unix: self.authorized_at_unix,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

fn query_rows<T: DeserializeOwned>(
    db: &RadrootsNostrSignerSqliteDb,
    sql: &str,
) -> Result<Vec<T>, RadrootsNostrSignerError> {
    let raw = db.executor().query_raw(sql, "[]")?;
    serde_json::from_str(&raw).map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))
}

fn exec_json(
    executor: &impl crate::sql::SqlExecutor,
    sql: &str,
    params: Value,
) -> Result<(), RadrootsNostrSignerError> {
    let _ = executor.exec(sql, params.to_string().as_str())?;
    Ok(())
}

fn parse_json_field<T: DeserializeOwned>(value: &str) -> Result<T, RadrootsNostrSignerError> {
    serde_json::from_str(value).map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))
}

fn parse_public_key_hex(value: &str) -> Result<nostr::PublicKey, RadrootsNostrSignerError> {
    nostr::PublicKey::parse(value)
        .or_else(|_| nostr::PublicKey::from_hex(value))
        .map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))
}

fn approval_requirement_label(value: RadrootsNostrSignerApprovalRequirement) -> &'static str {
    match value {
        RadrootsNostrSignerApprovalRequirement::NotRequired => "not_required",
        RadrootsNostrSignerApprovalRequirement::ExplicitUser => "explicit_user",
    }
}

fn parse_approval_requirement(
    value: &str,
) -> Result<RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerError> {
    match value {
        "not_required" => Ok(RadrootsNostrSignerApprovalRequirement::NotRequired),
        "explicit_user" => Ok(RadrootsNostrSignerApprovalRequirement::ExplicitUser),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite approval requirement `{other}`"
        ))),
    }
}

fn approval_state_label(value: RadrootsNostrSignerApprovalState) -> &'static str {
    match value {
        RadrootsNostrSignerApprovalState::NotRequired => "not_required",
        RadrootsNostrSignerApprovalState::Pending => "pending",
        RadrootsNostrSignerApprovalState::Approved => "approved",
        RadrootsNostrSignerApprovalState::Rejected => "rejected",
    }
}

fn parse_approval_state(
    value: &str,
) -> Result<RadrootsNostrSignerApprovalState, RadrootsNostrSignerError> {
    match value {
        "not_required" => Ok(RadrootsNostrSignerApprovalState::NotRequired),
        "pending" => Ok(RadrootsNostrSignerApprovalState::Pending),
        "approved" => Ok(RadrootsNostrSignerApprovalState::Approved),
        "rejected" => Ok(RadrootsNostrSignerApprovalState::Rejected),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite approval state `{other}`"
        ))),
    }
}

fn auth_state_label(value: RadrootsNostrSignerAuthState) -> &'static str {
    match value {
        RadrootsNostrSignerAuthState::NotRequired => "not_required",
        RadrootsNostrSignerAuthState::Pending => "pending",
        RadrootsNostrSignerAuthState::Authorized => "authorized",
    }
}

fn parse_auth_state(value: &str) -> Result<RadrootsNostrSignerAuthState, RadrootsNostrSignerError> {
    match value {
        "not_required" => Ok(RadrootsNostrSignerAuthState::NotRequired),
        "pending" => Ok(RadrootsNostrSignerAuthState::Pending),
        "authorized" => Ok(RadrootsNostrSignerAuthState::Authorized),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite auth state `{other}`"
        ))),
    }
}

fn connection_status_label(value: RadrootsNostrSignerConnectionStatus) -> &'static str {
    match value {
        RadrootsNostrSignerConnectionStatus::Pending => "pending",
        RadrootsNostrSignerConnectionStatus::Active => "active",
        RadrootsNostrSignerConnectionStatus::Rejected => "rejected",
        RadrootsNostrSignerConnectionStatus::Revoked => "revoked",
    }
}

fn parse_connection_status(
    value: &str,
) -> Result<RadrootsNostrSignerConnectionStatus, RadrootsNostrSignerError> {
    match value {
        "pending" => Ok(RadrootsNostrSignerConnectionStatus::Pending),
        "active" => Ok(RadrootsNostrSignerConnectionStatus::Active),
        "rejected" => Ok(RadrootsNostrSignerConnectionStatus::Rejected),
        "revoked" => Ok(RadrootsNostrSignerConnectionStatus::Revoked),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite connection status `{other}`"
        ))),
    }
}

fn request_decision_label(value: RadrootsNostrSignerRequestDecision) -> &'static str {
    match value {
        RadrootsNostrSignerRequestDecision::Allowed => "allowed",
        RadrootsNostrSignerRequestDecision::Denied => "denied",
        RadrootsNostrSignerRequestDecision::Challenged => "challenged",
    }
}

fn parse_request_decision(
    value: &str,
) -> Result<RadrootsNostrSignerRequestDecision, RadrootsNostrSignerError> {
    match value {
        "allowed" => Ok(RadrootsNostrSignerRequestDecision::Allowed),
        "denied" => Ok(RadrootsNostrSignerRequestDecision::Denied),
        "challenged" => Ok(RadrootsNostrSignerRequestDecision::Challenged),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite request decision `{other}`"
        ))),
    }
}

fn publish_workflow_kind_label(value: RadrootsNostrSignerPublishWorkflowKind) -> &'static str {
    match value {
        RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization => {
            "connect_secret_finalization"
        }
        RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization => {
            "auth_replay_finalization"
        }
    }
}

fn parse_publish_workflow_kind(
    value: &str,
) -> Result<RadrootsNostrSignerPublishWorkflowKind, RadrootsNostrSignerError> {
    match value {
        "connect_secret_finalization" => {
            Ok(RadrootsNostrSignerPublishWorkflowKind::ConnectSecretFinalization)
        }
        "auth_replay_finalization" => {
            Ok(RadrootsNostrSignerPublishWorkflowKind::AuthReplayFinalization)
        }
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite publish workflow kind `{other}`"
        ))),
    }
}

fn publish_workflow_state_label(value: RadrootsNostrSignerPublishWorkflowState) -> &'static str {
    match value {
        RadrootsNostrSignerPublishWorkflowState::PendingPublish => "pending_publish",
        RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize => {
            "published_pending_finalize"
        }
    }
}

fn parse_publish_workflow_state(
    value: &str,
) -> Result<RadrootsNostrSignerPublishWorkflowState, RadrootsNostrSignerError> {
    match value {
        "pending_publish" => Ok(RadrootsNostrSignerPublishWorkflowState::PendingPublish),
        "published_pending_finalize" => {
            Ok(RadrootsNostrSignerPublishWorkflowState::PublishedPendingFinalize)
        }
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite publish workflow state `{other}`"
        ))),
    }
}

fn secret_digest_algorithm_label(hash: &RadrootsNostrSignerConnectSecretHash) -> &'static str {
    match hash.algorithm {
        crate::signer::model::RadrootsNostrSignerSecretDigestAlgorithm::Sha256 => "sha256",
    }
}

fn parse_secret_digest_algorithm(
    value: &str,
) -> Result<crate::signer::model::RadrootsNostrSignerSecretDigestAlgorithm, RadrootsNostrSignerError>
{
    match value {
        "sha256" => Ok(crate::signer::model::RadrootsNostrSignerSecretDigestAlgorithm::Sha256),
        other => Err(RadrootsNostrSignerError::Store(format!(
            "unknown sqlite secret digest algorithm `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::model::{
        RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthChallenge,
        RadrootsNostrSignerAuthState, RadrootsNostrSignerConnectionDraft,
        RadrootsNostrSignerConnectionId, RadrootsNostrSignerPendingRequest,
        RadrootsNostrSignerPermissionGrant, RadrootsNostrSignerPublishWorkflowRecord,
        RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestDecision,
        RadrootsNostrSignerRequestId,
    };
    use crate::signer::test_support::{
        api_primary_https, fixture_alice_identity, fixture_bob_identity, fixture_carol_public_key,
        primary_relay, secondary_relay,
    };
    use radroots_nostr_connect::{
        Method, Permission, Request, message::RequestMessage, permission::Permissions,
        uri::ClientMetadata,
    };
    use std::thread;

    #[test]
    fn production_source_has_no_dead_code_allowance() {
        let forbidden = ["#[allow(", "dead_code", ")]"].concat();
        assert!(!include_str!("store.rs").contains(forbidden.as_str()));
    }

    #[test]
    fn file_store_round_trip_and_path_accessor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.json");
        let store = RadrootsNostrFileSignerStore::new(path.as_path());

        assert_eq!(store.path(), path.as_path());
        store
            .save(&RadrootsNostrSignerStoreState::default())
            .expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(
            loaded.version,
            RadrootsNostrSignerStoreState::default().version
        );
        assert!(loaded.connections.is_empty());
    }

    #[test]
    fn file_store_load_missing_and_reports_parse_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = RadrootsNostrFileSignerStore::new(temp.path().join("missing.json"));
        let loaded = missing.load().expect("missing load");
        assert!(loaded.connections.is_empty());

        let path = temp.path().join("invalid.json");
        std::fs::write(&path, "{").expect("write invalid json");
        let store = RadrootsNostrFileSignerStore::new(path.as_path());
        let err = store.load().expect_err("invalid json");
        assert!(err.to_string().starts_with("store error:"));
    }

    #[test]
    fn file_store_save_reports_parse_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("invalid-save.json");
        std::fs::write(&path, "{").expect("write invalid json");
        let store = RadrootsNostrFileSignerStore::new(path.as_path());
        let err = store
            .save(&RadrootsNostrSignerStoreState::default())
            .expect_err("invalid save");
        assert!(err.to_string().starts_with("store error:"));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_save_reports_write_error() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.json");
        let json =
            serde_json::to_string(&RadrootsNostrSignerStoreState::default()).expect("serialize");
        std::fs::write(&path, json).expect("write json");
        let store = RadrootsNostrFileSignerStore::new(path.as_path());

        let mut perms = std::fs::metadata(temp.path())
            .expect("dir metadata")
            .permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(temp.path(), perms).expect("set perms");

        let err = store
            .save(&RadrootsNostrSignerStoreState::default())
            .expect_err("read-only save");
        assert!(err.to_string().starts_with("store error:"));

        let mut perms = std::fs::metadata(temp.path())
            .expect("dir metadata")
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(temp.path(), perms).expect("restore perms");
    }

    #[test]
    fn memory_store_round_trip_and_poison_errors() {
        let store = RadrootsNostrMemorySignerStore::new();
        let state = RadrootsNostrSignerStoreState::default();
        store.save(&state).expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.version, state.version);

        let shared = store.state.clone();
        let _ = thread::spawn(move || {
            let _guard = shared.write().expect("write");
            panic!("poison memory store");
        })
        .join();

        let load = store.load().expect_err("poisoned load");
        let save = store.save(&state).expect_err("poisoned save");
        assert!(load.to_string().contains("memory store lock poisoned"));
        assert!(save.to_string().contains("memory store lock poisoned"));
    }

    fn sample_request_message(id: &str) -> RequestMessage {
        RequestMessage::new(id, Request::Ping)
    }

    fn sample_sqlite_state() -> RadrootsNostrSignerStoreState {
        let signer_identity = fixture_alice_identity();
        let user_identity = fixture_bob_identity();
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-sqlite").expect("id");
        let mut connection = RadrootsNostrSignerConnectionRecord::new(
            connection_id.clone(),
            signer_identity.clone(),
            RadrootsNostrSignerConnectionDraft::new(fixture_carol_public_key(), user_identity)
                .with_connect_secret("sqlite-secret")
                .with_client_metadata(ClientMetadata {
                    requested_permissions: Permissions::default(),
                    name: Some("Example Client".to_owned()),
                    url: Some("https://client.example.com/".to_owned()),
                    image: Some("https://client.example.com/icon.png".to_owned()),
                })
                .with_relays(vec![primary_relay(), secondary_relay()])
                .with_requested_permissions(
                    vec![
                        Permission::new(Method::Ping),
                        Permission::with_parameter(Method::SignEvent, "kind:1"),
                    ]
                    .into(),
                )
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::ExplicitUser),
            100,
        );
        connection.approval_state =
            crate::signer::model::RadrootsNostrSignerApprovalState::Approved;
        connection.auth_state = RadrootsNostrSignerAuthState::Pending;
        connection.status = crate::signer::model::RadrootsNostrSignerConnectionStatus::Active;
        connection.status_reason = Some("approved by operator".to_owned());
        connection.updated_at_unix = 140;
        connection.last_authenticated_at_unix = Some(130);
        connection.last_request_at_unix = Some(135);
        connection.mark_connect_secret_consumed(125);
        connection.granted_permissions = vec![
            RadrootsNostrSignerPermissionGrant::new(Permission::new(Method::Ping), 110),
            RadrootsNostrSignerPermissionGrant::new(
                Permission::with_parameter(Method::SignEvent, "kind:1"),
                111,
            ),
        ];
        connection.auth_challenge = Some(
            RadrootsNostrSignerAuthChallenge::new(
                format!("{}/challenge", api_primary_https()).as_str(),
                120,
            )
            .expect("challenge"),
        );
        connection.pending_request = Some(
            RadrootsNostrSignerPendingRequest::new(sample_request_message("req-sqlite"), 121)
                .expect("pending request"),
        );

        RadrootsNostrSignerStoreState {
            version: 1,
            signer_identity: Some(signer_identity),
            connections: vec![connection.clone()],
            audit_records: vec![RadrootsNostrSignerRequestAuditRecord::new(
                RadrootsNostrSignerRequestId::parse("audit-1").expect("request id"),
                connection_id,
                Method::Ping,
                RadrootsNostrSignerRequestDecision::Allowed,
                Some("permitted".to_owned()),
                150,
            )],
            publish_workflows: vec![
                RadrootsNostrSignerPublishWorkflowRecord::new_connect_secret_finalization(
                    connection.connection_id.clone(),
                    151,
                ),
                RadrootsNostrSignerPublishWorkflowRecord::new_auth_replay_finalization(
                    connection.connection_id.clone(),
                    RadrootsNostrSignerPendingRequest::new(
                        sample_request_message("req-replay"),
                        152,
                    )
                    .expect("auth replay pending request"),
                    153,
                ),
            ],
        }
    }

    #[test]
    fn sqlite_store_round_trip_on_memory_backend() {
        let store = RadrootsNostrSqliteSignerStore::open_memory().expect("open memory store");
        let state = sample_sqlite_state();

        store.save(&state).expect("save sqlite state");
        let loaded = store.load().expect("load sqlite state");

        assert_eq!(
            serde_json::to_value(&loaded).expect("serialize loaded"),
            serde_json::to_value(&state).expect("serialize state")
        );
    }

    #[test]
    fn sqlite_store_persists_to_disk_and_recovers_after_reopen() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.sqlite");
        let state = sample_sqlite_state();

        let store = RadrootsNostrSqliteSignerStore::open(&path).expect("open sqlite store");
        store.save(&state).expect("save sqlite state");

        let reopened = RadrootsNostrSqliteSignerStore::open(&path).expect("reopen sqlite store");
        let loaded = reopened.load().expect("load reopened sqlite state");

        assert_eq!(
            serde_json::to_value(&loaded).expect("serialize loaded"),
            serde_json::to_value(&state).expect("serialize state")
        );
    }
}
