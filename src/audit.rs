use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;
use serde::{Deserialize, Serialize};

use crate::config::MycAuditConfig;
use crate::config::MycTransportDeliveryPolicy;
use crate::error::MycError;

const MYC_OPERATION_AUDIT_FILE_NAME: &str = "operations.jsonl";
const MYC_OPERATION_AUDIT_ARCHIVE_PREFIX: &str = "operations.";
const MYC_OPERATION_AUDIT_ARCHIVE_SUFFIX: &str = ".jsonl";
const MYC_OPERATION_AUDIT_INDEX_DIR_NAME: &str = "index";
const MYC_OPERATION_AUDIT_INDEX_TMP_DIR_NAME: &str = "index.tmp";
const MYC_OPERATION_AUDIT_ATTEMPTS_DIR_NAME: &str = "attempts";
const MYC_OPERATION_AUDIT_LATEST_DIR_NAME: &str = "latest";
const MYC_OPERATION_AUDIT_LATEST_SUFFIX: &str = ".attempt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditKind {
    ListenerResponsePublish,
    ConnectAcceptPublish,
    AuthReplayPublish,
    AuthReplayRestore,
    DiscoveryHandlerFetch,
    DiscoveryHandlerPublish,
    DiscoveryHandlerCompare,
    DiscoveryHandlerRefresh,
    DiscoveryHandlerRepair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditOutcome {
    Succeeded,
    Rejected,
    Restored,
    Unavailable,
    Missing,
    Matched,
    Drifted,
    Conflicted,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycOperationAuditRecord {
    pub recorded_at_unix: u64,
    pub operation: MycOperationAuditKind,
    pub outcome: MycOperationAuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub planned_repair_relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_policy: Option<MycTransportDeliveryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_acknowledged_relay_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_attempt_count: Option<usize>,
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub relay_outcome_summary: String,
}

#[derive(Debug, Clone)]
pub struct MycOperationAuditStore {
    audit_dir: PathBuf,
    config: MycAuditConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MycAuditRotationResult {
    pruned_retained_records: bool,
}

impl MycOperationAuditRecord {
    pub fn new(
        operation: MycOperationAuditKind,
        outcome: MycOperationAuditOutcome,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: Option<&str>,
        relay_count: usize,
        acknowledged_relay_count: usize,
        relay_outcome_summary: impl Into<String>,
    ) -> Self {
        Self {
            recorded_at_unix: now_unix_secs(),
            operation,
            outcome,
            relay_url: None,
            connection_id: connection_id.map(ToString::to_string),
            request_id: request_id.map(ToOwned::to_owned),
            attempt_id: None,
            planned_repair_relays: Vec::new(),
            blocked_relays: Vec::new(),
            blocked_reason: None,
            delivery_policy: None,
            required_acknowledged_relay_count: None,
            publish_attempt_count: None,
            relay_count,
            acknowledged_relay_count,
            relay_outcome_summary: relay_outcome_summary.into(),
        }
    }

    pub fn with_relay_url(mut self, relay_url: impl Into<String>) -> Self {
        self.relay_url = Some(relay_url.into());
        self
    }

    pub fn with_attempt_id(mut self, attempt_id: impl Into<String>) -> Self {
        self.attempt_id = Some(attempt_id.into());
        self
    }

    pub fn with_planned_repair_relays(mut self, planned_repair_relays: Vec<String>) -> Self {
        self.planned_repair_relays = planned_repair_relays;
        self
    }

    pub fn with_blocked_relays(
        mut self,
        blocked_reason: impl Into<String>,
        blocked_relays: Vec<String>,
    ) -> Self {
        self.blocked_reason = Some(blocked_reason.into());
        self.blocked_relays = blocked_relays;
        self
    }

    pub fn with_delivery_details(
        mut self,
        delivery_policy: MycTransportDeliveryPolicy,
        required_acknowledged_relay_count: usize,
        publish_attempt_count: usize,
    ) -> Self {
        self.delivery_policy = Some(delivery_policy);
        self.required_acknowledged_relay_count = Some(required_acknowledged_relay_count);
        self.publish_attempt_count = Some(publish_attempt_count);
        self
    }
}

impl MycOperationAuditStore {
    pub fn new(audit_dir: impl AsRef<Path>, config: MycAuditConfig) -> Self {
        Self {
            audit_dir: audit_dir.as_ref().to_path_buf(),
            config,
        }
    }

    pub fn path(&self) -> PathBuf {
        self.active_path()
    }

    pub fn config(&self) -> &MycAuditConfig {
        &self.config
    }

    pub fn append(&self, record: &MycOperationAuditRecord) -> Result<(), MycError> {
        let active_path = self.active_path();
        let encoded = serde_json::to_vec(record).map_err(|source| MycError::AuditSerialize {
            path: active_path.clone(),
            source,
        })?;
        let rotation = self.rotate_if_needed(encoded.len() as u64 + 1)?;
        self.append_encoded_record_line(&active_path, &encoded)?;

        if rotation.pruned_retained_records {
            self.rebuild_query_indexes_from_retained_logs()?;
        } else {
            self.append_record_to_indexes(record)?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_with_limit(self.config.default_read_limit)
    }

    pub fn list_with_limit(&self, limit: usize) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_matching(limit, |_| true)
    }

    pub fn list_for_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_for_connection_with_limit(connection_id, self.config.default_read_limit)
    }

    pub fn list_for_connection_with_limit(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_matching(limit, |record| {
            record.connection_id.as_deref() == Some(connection_id.as_str())
        })
    }

    pub fn list_for_attempt_id(
        &self,
        attempt_id: &str,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_for_attempt_id_with_limit(attempt_id, usize::MAX)
    }

    pub fn list_for_attempt_id_with_limit(
        &self,
        attempt_id: &str,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let attempt_path = self.attempt_index_path(attempt_id);
        if !attempt_path.exists() {
            self.rebuild_query_indexes_from_retained_logs()?;
        }
        self.read_recent_records_from_path_with_limit(&attempt_path, limit)
    }

    pub fn latest_attempt_id_for_operation(
        &self,
        operation: MycOperationAuditKind,
    ) -> Result<Option<String>, MycError> {
        let latest_path = self.latest_attempt_path(operation);
        if !latest_path.exists() {
            self.rebuild_query_indexes_from_retained_logs()?;
        }
        self.read_latest_attempt_id_from_path(&latest_path)
    }

    fn list_matching<F>(
        &self,
        limit: usize,
        predicate: F,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError>
    where
        F: Fn(&MycOperationAuditRecord) -> bool,
    {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut newest_records = Vec::new();
        for path in self.read_paths_newest_first()? {
            let remaining = limit.saturating_sub(newest_records.len());
            if remaining == 0 {
                break;
            }

            let mut file_records =
                self.read_recent_records_from_path_matching(&path, remaining, &predicate)?;
            file_records.reverse();
            newest_records.extend(file_records);
        }

        newest_records.reverse();
        Ok(newest_records)
    }

    fn read_records_from_path(
        &self,
        path: &Path,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(path).map_err(|source| MycError::AuditIo {
            path: path.to_path_buf(),
            source,
        })?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (line_number, line) in reader.lines().enumerate() {
            let line = line.map_err(|source| MycError::AuditIo {
                path: path.to_path_buf(),
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }

            let record =
                serde_json::from_str::<MycOperationAuditRecord>(&line).map_err(|source| {
                    MycError::AuditParse {
                        path: path.to_path_buf(),
                        line_number: line_number + 1,
                        source,
                    }
                })?;
            records.push(record);
        }

        Ok(records)
    }

    fn rotate_if_needed(&self, additional_bytes: u64) -> Result<MycAuditRotationResult, MycError> {
        let active_path = self.active_path();
        let current_len = match fs::metadata(&active_path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(source) => {
                return Err(MycError::AuditIo {
                    path: active_path,
                    source,
                });
            }
        };

        if current_len == 0
            || current_len.saturating_add(additional_bytes) <= self.config.max_active_file_bytes
        {
            return Ok(MycAuditRotationResult {
                pruned_retained_records: false,
            });
        }

        self.rotate_active_file()
    }

    fn rotate_active_file(&self) -> Result<MycAuditRotationResult, MycError> {
        let mut pruned_retained_records = false;
        for index in (1..=self.config.max_archived_files).rev() {
            let archived_path = self.archive_path(index);
            if !archived_path.exists() {
                continue;
            }

            if index == self.config.max_archived_files {
                fs::remove_file(&archived_path).map_err(|source| MycError::AuditIo {
                    path: archived_path,
                    source,
                })?;
                pruned_retained_records = true;
            } else {
                let next_path = self.archive_path(index + 1);
                fs::rename(&archived_path, &next_path).map_err(|source| MycError::AuditIo {
                    path: archived_path,
                    source,
                })?;
            }
        }

        let active_path = self.active_path();
        if !active_path.exists() {
            return Ok(MycAuditRotationResult {
                pruned_retained_records,
            });
        }

        if self.config.max_archived_files == 0 {
            fs::remove_file(&active_path).map_err(|source| MycError::AuditIo {
                path: active_path,
                source,
            })?;
            return Ok(MycAuditRotationResult {
                pruned_retained_records: true,
            });
        }

        let first_archive = self.archive_path(1);
        fs::rename(&active_path, &first_archive).map_err(|source| MycError::AuditIo {
            path: active_path,
            source,
        })?;
        Ok(MycAuditRotationResult {
            pruned_retained_records,
        })
    }

    fn read_paths_newest_first(&self) -> Result<Vec<PathBuf>, MycError> {
        let mut paths = Vec::new();
        let active_path = self.active_path();
        if active_path.exists() {
            paths.push(active_path);
        }

        let mut archived = self.archived_paths()?;
        archived.sort_by_key(|(_, index)| *index);
        for (path, _) in archived {
            paths.push(path);
        }

        Ok(paths)
    }

    fn archived_paths(&self) -> Result<Vec<(PathBuf, usize)>, MycError> {
        let mut archived = Vec::new();
        if !self.audit_dir.exists() {
            return Ok(archived);
        }

        for entry in fs::read_dir(&self.audit_dir).map_err(|source| MycError::AuditIo {
            path: self.audit_dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| MycError::AuditIo {
                path: self.audit_dir.clone(),
                source,
            })?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(index) = parse_archive_index(file_name) else {
                continue;
            };
            archived.push((entry.path(), index));
        }

        Ok(archived)
    }

    fn active_path(&self) -> PathBuf {
        self.audit_dir.join(MYC_OPERATION_AUDIT_FILE_NAME)
    }

    fn archive_path(&self, index: usize) -> PathBuf {
        self.audit_dir.join(format!(
            "{MYC_OPERATION_AUDIT_ARCHIVE_PREFIX}{index}{MYC_OPERATION_AUDIT_ARCHIVE_SUFFIX}"
        ))
    }

    fn index_dir(&self) -> PathBuf {
        self.audit_dir.join(MYC_OPERATION_AUDIT_INDEX_DIR_NAME)
    }

    fn attempt_index_dir(&self) -> PathBuf {
        self.index_dir().join(MYC_OPERATION_AUDIT_ATTEMPTS_DIR_NAME)
    }

    fn latest_attempt_dir(&self) -> PathBuf {
        self.index_dir().join(MYC_OPERATION_AUDIT_LATEST_DIR_NAME)
    }

    fn attempt_index_path(&self, attempt_id: &str) -> PathBuf {
        self.attempt_index_dir()
            .join(format!("{}.jsonl", encode_index_component(attempt_id)))
    }

    fn latest_attempt_path(&self, operation: MycOperationAuditKind) -> PathBuf {
        self.latest_attempt_dir().join(format!(
            "{}{MYC_OPERATION_AUDIT_LATEST_SUFFIX}",
            operation_index_label(operation)
        ))
    }

    fn append_encoded_record_line(&self, path: &Path, encoded: &[u8]) -> Result<(), MycError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| MycError::AuditIo {
                path: path.to_path_buf(),
                source,
            })?;
        file.write_all(encoded)
            .map_err(|source| MycError::AuditIo {
                path: path.to_path_buf(),
                source,
            })?;
        file.write_all(b"\n").map_err(|source| MycError::AuditIo {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    fn append_record_to_indexes(&self, record: &MycOperationAuditRecord) -> Result<(), MycError> {
        let Some(attempt_id) = record.attempt_id.as_deref() else {
            return Ok(());
        };

        self.ensure_index_dirs()?;
        self.append_record_to_index_root(&self.index_dir(), record)?;
        self.write_latest_attempt_pointer(record.operation, attempt_id)
    }

    fn ensure_index_dirs(&self) -> Result<(), MycError> {
        fs::create_dir_all(self.attempt_index_dir()).map_err(|source| MycError::AuditIo {
            path: self.attempt_index_dir(),
            source,
        })?;
        fs::create_dir_all(self.latest_attempt_dir()).map_err(|source| MycError::AuditIo {
            path: self.latest_attempt_dir(),
            source,
        })?;
        Ok(())
    }

    fn append_record_to_index_root(
        &self,
        index_root: &Path,
        record: &MycOperationAuditRecord,
    ) -> Result<(), MycError> {
        let Some(attempt_id) = record.attempt_id.as_deref() else {
            return Ok(());
        };

        let attempts_dir = index_root.join(MYC_OPERATION_AUDIT_ATTEMPTS_DIR_NAME);
        fs::create_dir_all(&attempts_dir).map_err(|source| MycError::AuditIo {
            path: attempts_dir.clone(),
            source,
        })?;
        let latest_dir = index_root.join(MYC_OPERATION_AUDIT_LATEST_DIR_NAME);
        fs::create_dir_all(&latest_dir).map_err(|source| MycError::AuditIo {
            path: latest_dir.clone(),
            source,
        })?;

        let encoded = serde_json::to_vec(record).map_err(|source| MycError::AuditSerialize {
            path: attempts_dir.join(format!("{}.jsonl", encode_index_component(attempt_id))),
            source,
        })?;
        self.append_encoded_record_line(
            &attempts_dir.join(format!("{}.jsonl", encode_index_component(attempt_id))),
            &encoded,
        )?;
        self.write_latest_attempt_pointer_to_root(index_root, record.operation, attempt_id)
    }

    fn write_latest_attempt_pointer(
        &self,
        operation: MycOperationAuditKind,
        attempt_id: &str,
    ) -> Result<(), MycError> {
        self.write_latest_attempt_pointer_to_root(&self.index_dir(), operation, attempt_id)
    }

    fn write_latest_attempt_pointer_to_root(
        &self,
        index_root: &Path,
        operation: MycOperationAuditKind,
        attempt_id: &str,
    ) -> Result<(), MycError> {
        let latest_dir = index_root.join(MYC_OPERATION_AUDIT_LATEST_DIR_NAME);
        fs::create_dir_all(&latest_dir).map_err(|source| MycError::AuditIo {
            path: latest_dir.clone(),
            source,
        })?;
        let path = latest_dir.join(format!(
            "{}{MYC_OPERATION_AUDIT_LATEST_SUFFIX}",
            operation_index_label(operation)
        ));
        write_atomic_text(&path, attempt_id)
    }

    fn rebuild_query_indexes_from_retained_logs(&self) -> Result<(), MycError> {
        let staging_root = self.audit_dir.join(MYC_OPERATION_AUDIT_INDEX_TMP_DIR_NAME);
        if staging_root.exists() {
            fs::remove_dir_all(&staging_root).map_err(|source| MycError::AuditIo {
                path: staging_root.clone(),
                source,
            })?;
        }
        fs::create_dir_all(&staging_root).map_err(|source| MycError::AuditIo {
            path: staging_root.clone(),
            source,
        })?;

        let mut retained_paths = self.read_paths_newest_first()?;
        retained_paths.reverse();
        for path in retained_paths {
            for record in self.read_records_from_path(&path)? {
                self.append_record_to_index_root(&staging_root, &record)?;
            }
        }

        let final_root = self.index_dir();
        if final_root.exists() {
            fs::remove_dir_all(&final_root).map_err(|source| MycError::AuditIo {
                path: final_root.clone(),
                source,
            })?;
        }
        fs::rename(&staging_root, &final_root).map_err(|source| MycError::AuditIo {
            path: staging_root,
            source,
        })?;
        Ok(())
    }

    fn read_latest_attempt_id_from_path(&self, path: &Path) -> Result<Option<String>, MycError> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let attempt_id = contents.trim();
                if attempt_id.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(attempt_id.to_owned()))
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(MycError::AuditIo {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn read_recent_records_from_path_with_limit(
        &self,
        path: &Path,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.read_recent_records_from_path_matching(path, limit, &|_| true)
    }

    fn read_recent_records_from_path_matching<F>(
        &self,
        path: &Path,
        limit: usize,
        predicate: &F,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError>
    where
        F: Fn(&MycOperationAuditRecord) -> bool,
    {
        if limit == 0 || !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(path).map_err(|source| MycError::AuditIo {
            path: path.to_path_buf(),
            source,
        })?;
        let reader = BufReader::new(file);
        let mut recent_records = VecDeque::new();

        for (line_number, line) in reader.lines().enumerate() {
            let line = line.map_err(|source| MycError::AuditIo {
                path: path.to_path_buf(),
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }

            let record =
                serde_json::from_str::<MycOperationAuditRecord>(&line).map_err(|source| {
                    MycError::AuditParse {
                        path: path.to_path_buf(),
                        line_number: line_number + 1,
                        source,
                    }
                })?;
            if !predicate(&record) {
                continue;
            }

            if recent_records.len() == limit {
                recent_records.pop_front();
            }
            recent_records.push_back(record);
        }

        Ok(recent_records.into_iter().collect())
    }
}

fn parse_archive_index(file_name: &str) -> Option<usize> {
    file_name
        .strip_prefix(MYC_OPERATION_AUDIT_ARCHIVE_PREFIX)?
        .strip_suffix(MYC_OPERATION_AUDIT_ARCHIVE_SUFFIX)?
        .parse()
        .ok()
}

fn operation_index_label(kind: MycOperationAuditKind) -> &'static str {
    match kind {
        MycOperationAuditKind::ListenerResponsePublish => "listener_response_publish",
        MycOperationAuditKind::ConnectAcceptPublish => "connect_accept_publish",
        MycOperationAuditKind::AuthReplayPublish => "auth_replay_publish",
        MycOperationAuditKind::AuthReplayRestore => "auth_replay_restore",
        MycOperationAuditKind::DiscoveryHandlerFetch => "discovery_handler_fetch",
        MycOperationAuditKind::DiscoveryHandlerPublish => "discovery_handler_publish",
        MycOperationAuditKind::DiscoveryHandlerCompare => "discovery_handler_compare",
        MycOperationAuditKind::DiscoveryHandlerRefresh => "discovery_handler_refresh",
        MycOperationAuditKind::DiscoveryHandlerRepair => "discovery_handler_repair",
    }
}

fn encode_index_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn write_atomic_text(path: &Path, contents: &str) -> Result<(), MycError> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents).map_err(|source| MycError::AuditIo {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, path).map_err(|source| MycError::AuditIo {
        path: tmp_path,
        source,
    })?;
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;

    use crate::config::MycAuditConfig;

    use super::{
        MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
        MycOperationAuditStore,
    };

    fn config() -> MycAuditConfig {
        MycAuditConfig {
            default_read_limit: 10,
            max_active_file_bytes: 512,
            max_archived_files: 2,
        }
    }

    #[test]
    fn append_and_list_operation_audit_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path(), config());
        let connection_id =
            RadrootsNostrSignerConnectionId::parse("connection-1").expect("connection id");

        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::ConnectAcceptPublish,
                    MycOperationAuditOutcome::Rejected,
                    Some(&connection_id),
                    Some("request-1"),
                    2,
                    0,
                    "0/2 relays acknowledged publish; failures: relay-a: rejected",
                )
                .with_attempt_id("attempt-1"),
            )
            .expect("append rejected record");
        store
            .append(&MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayRestore,
                MycOperationAuditOutcome::Restored,
                Some(&connection_id),
                Some("request-1"),
                0,
                0,
                "restored pending auth challenge after replay publish rejection",
            ))
            .expect("append restored record");

        let records = store.list().expect("list records");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].operation,
            MycOperationAuditKind::ConnectAcceptPublish
        );
        assert_eq!(records[0].outcome, MycOperationAuditOutcome::Rejected);
        assert_eq!(records[0].connection_id.as_deref(), Some("connection-1"));
        assert_eq!(records[0].request_id.as_deref(), Some("request-1"));
        assert_eq!(records[0].attempt_id.as_deref(), Some("attempt-1"));
        assert_eq!(records[0].relay_count, 2);
        assert_eq!(records[0].acknowledged_relay_count, 0);

        let connection_records = store
            .list_for_connection(&connection_id)
            .expect("list connection records");
        assert_eq!(connection_records, records);
    }

    #[test]
    fn list_returns_empty_when_audit_file_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path(), config());

        assert!(store.list().expect("list missing records").is_empty());
    }

    #[test]
    fn rotation_and_bounded_reads_keep_recent_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(
            temp.path(),
            MycAuditConfig {
                default_read_limit: 3,
                max_active_file_bytes: 180,
                max_archived_files: 2,
            },
        );

        for index in 0..6 {
            store
                .append(
                    &MycOperationAuditRecord::new(
                        MycOperationAuditKind::ListenerResponsePublish,
                        MycOperationAuditOutcome::Rejected,
                        None,
                        Some(&format!("request-{index}")),
                        1,
                        0,
                        format!("failure-{index}"),
                    )
                    .with_attempt_id(format!("attempt-{index}")),
                )
                .expect("append record");
        }

        let records = store.list().expect("list bounded records");
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].request_id.as_deref(), Some("request-3"));
        assert_eq!(records[2].request_id.as_deref(), Some("request-5"));
        assert!(temp.path().join("operations.1.jsonl").exists());
        assert!(temp.path().join("operations.2.jsonl").exists());
        assert!(!temp.path().join("operations.3.jsonl").exists());
    }

    #[test]
    fn list_for_attempt_and_latest_attempt_id_work() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path(), config());

        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    None,
                    2,
                    0,
                    "first attempt rejected",
                )
                .with_attempt_id("attempt-1")
                .with_planned_repair_relays(vec!["wss://relay-a.example.com".to_owned()])
                .with_blocked_relays(
                    "unavailable_relays",
                    vec!["wss://relay-b.example.com".to_owned()],
                ),
            )
            .expect("append first attempt");
        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRepair,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    None,
                    1,
                    0,
                    "relay-a rejected",
                )
                .with_attempt_id("attempt-1")
                .with_relay_url("wss://relay-a.example.com"),
            )
            .expect("append first repair");
        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Succeeded,
                    None,
                    None,
                    1,
                    1,
                    "second attempt succeeded",
                )
                .with_attempt_id("attempt-2"),
            )
            .expect("append second attempt");

        let attempt_records = store
            .list_for_attempt_id("attempt-1")
            .expect("list attempt records");
        assert_eq!(attempt_records.len(), 2);
        assert!(
            attempt_records
                .iter()
                .all(|record| record.attempt_id.as_deref() == Some("attempt-1"))
        );
        assert_eq!(
            attempt_records[0].planned_repair_relays,
            vec!["wss://relay-a.example.com".to_owned()]
        );
        assert_eq!(
            attempt_records[0].blocked_relays,
            vec!["wss://relay-b.example.com".to_owned()]
        );
        assert_eq!(
            attempt_records[0].blocked_reason.as_deref(),
            Some("unavailable_relays")
        );
        assert_eq!(
            store
                .latest_attempt_id_for_operation(MycOperationAuditKind::DiscoveryHandlerRefresh)
                .expect("latest attempt"),
            Some("attempt-2".to_owned())
        );
    }

    #[test]
    fn attempt_lookup_rebuilds_indexes_from_retained_logs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path(), config());

        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    None,
                    2,
                    0,
                    "first attempt rejected",
                )
                .with_attempt_id("attempt-1"),
            )
            .expect("append first attempt");
        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Succeeded,
                    None,
                    None,
                    1,
                    1,
                    "second attempt succeeded",
                )
                .with_attempt_id("attempt-2"),
            )
            .expect("append second attempt");

        fs::remove_dir_all(store.index_dir()).expect("remove index dir");

        let rebuilt_attempt_records = store
            .list_for_attempt_id("attempt-1")
            .expect("rebuild attempt records");
        assert_eq!(rebuilt_attempt_records.len(), 1);
        assert_eq!(
            rebuilt_attempt_records[0].attempt_id.as_deref(),
            Some("attempt-1")
        );
        assert_eq!(
            store
                .latest_attempt_id_for_operation(MycOperationAuditKind::DiscoveryHandlerRefresh)
                .expect("latest attempt after rebuild"),
            Some("attempt-2".to_owned())
        );
        assert!(store.attempt_index_path("attempt-1").exists());
        assert!(
            store
                .latest_attempt_path(MycOperationAuditKind::DiscoveryHandlerRefresh)
                .exists()
        );
    }
}
