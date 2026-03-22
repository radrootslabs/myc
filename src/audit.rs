use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;
use serde::{Deserialize, Serialize};

use crate::config::MycAuditConfig;
use crate::error::MycError;

const MYC_OPERATION_AUDIT_FILE_NAME: &str = "operations.jsonl";
const MYC_OPERATION_AUDIT_ARCHIVE_PREFIX: &str = "operations.";
const MYC_OPERATION_AUDIT_ARCHIVE_SUFFIX: &str = ".jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditKind {
    ListenerResponsePublish,
    ConnectAcceptPublish,
    AuthReplayPublish,
    AuthReplayRestore,
    DiscoveryHandlerPublish,
    DiscoveryHandlerCompare,
    DiscoveryHandlerRefresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditOutcome {
    Succeeded,
    Rejected,
    Restored,
    Missing,
    Matched,
    Drifted,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycOperationAuditRecord {
    pub recorded_at_unix: u64,
    pub operation: MycOperationAuditKind,
    pub outcome: MycOperationAuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub relay_outcome_summary: String,
}

#[derive(Debug, Clone)]
pub struct MycOperationAuditStore {
    audit_dir: PathBuf,
    config: MycAuditConfig,
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
            connection_id: connection_id.map(ToString::to_string),
            request_id: request_id.map(ToOwned::to_owned),
            relay_count,
            acknowledged_relay_count,
            relay_outcome_summary: relay_outcome_summary.into(),
        }
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
        self.rotate_if_needed(encoded.len() as u64 + 1)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)
            .map_err(|source| MycError::AuditIo {
                path: active_path.clone(),
                source,
            })?;
        file.write_all(&encoded)
            .map_err(|source| MycError::AuditIo {
                path: active_path.clone(),
                source,
            })?;
        file.write_all(b"\n").map_err(|source| MycError::AuditIo {
            path: active_path,
            source,
        })?;
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
            let mut file_records = self.read_records_from_path(&path)?;
            file_records.reverse();

            for record in file_records {
                if predicate(&record) {
                    newest_records.push(record);
                    if newest_records.len() == limit {
                        newest_records.reverse();
                        return Ok(newest_records);
                    }
                }
            }
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

    fn rotate_if_needed(&self, additional_bytes: u64) -> Result<(), MycError> {
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
            return Ok(());
        }

        self.rotate_active_file()
    }

    fn rotate_active_file(&self) -> Result<(), MycError> {
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
            return Ok(());
        }

        if self.config.max_archived_files == 0 {
            fs::remove_file(&active_path).map_err(|source| MycError::AuditIo {
                path: active_path,
                source,
            })?;
            return Ok(());
        }

        let first_archive = self.archive_path(1);
        fs::rename(&active_path, &first_archive).map_err(|source| MycError::AuditIo {
            path: active_path,
            source,
        })?;
        Ok(())
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
}

fn parse_archive_index(file_name: &str) -> Option<usize> {
    file_name
        .strip_prefix(MYC_OPERATION_AUDIT_ARCHIVE_PREFIX)?
        .strip_suffix(MYC_OPERATION_AUDIT_ARCHIVE_SUFFIX)?
        .parse()
        .ok()
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
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
            .append(&MycOperationAuditRecord::new(
                MycOperationAuditKind::ConnectAcceptPublish,
                MycOperationAuditOutcome::Rejected,
                Some(&connection_id),
                Some("request-1"),
                2,
                0,
                "0/2 relays acknowledged publish; failures: relay-a: rejected",
            ))
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
                .append(&MycOperationAuditRecord::new(
                    MycOperationAuditKind::ListenerResponsePublish,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    Some(&format!("request-{index}")),
                    1,
                    0,
                    format!("failure-{index}"),
                ))
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
}
