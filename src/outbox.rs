use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use radroots_nostr::prelude::{RadrootsNostrEvent, RadrootsNostrRelayUrl};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerConnectionId, RadrootsNostrSignerWorkflowId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::MycError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MycDeliveryOutboxJobId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycDeliveryOutboxKind {
    ListenerResponsePublish,
    ConnectAcceptPublish,
    AuthReplayPublish,
    DiscoveryHandlerPublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycDeliveryOutboxStatus {
    Queued,
    PublishedPendingFinalize,
    Finalized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycDeliveryOutboxRecord {
    pub job_id: MycDeliveryOutboxJobId,
    pub kind: MycDeliveryOutboxKind,
    pub status: MycDeliveryOutboxStatus,
    pub event: RadrootsNostrEvent,
    pub relay_urls: Vec<RadrootsNostrRelayUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<RadrootsNostrSignerConnectionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_publish_workflow_id: Option<RadrootsNostrSignerWorkflowId>,
    pub publish_attempt_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_at_unix: Option<u64>,
}

pub trait MycDeliveryOutboxStore: Send + Sync {
    fn enqueue(&self, record: &MycDeliveryOutboxRecord) -> Result<(), MycError>;
    fn get(
        &self,
        job_id: &MycDeliveryOutboxJobId,
    ) -> Result<Option<MycDeliveryOutboxRecord>, MycError>;
    fn list_all(&self) -> Result<Vec<MycDeliveryOutboxRecord>, MycError>;
    fn list_by_status(
        &self,
        status: MycDeliveryOutboxStatus,
    ) -> Result<Vec<MycDeliveryOutboxRecord>, MycError>;
    fn mark_published_pending_finalize(
        &self,
        job_id: &MycDeliveryOutboxJobId,
        publish_attempt_count: usize,
    ) -> Result<MycDeliveryOutboxRecord, MycError>;
    fn mark_failed(
        &self,
        job_id: &MycDeliveryOutboxJobId,
        publish_attempt_count: usize,
        error: &str,
    ) -> Result<MycDeliveryOutboxRecord, MycError>;
    fn mark_finalized(
        &self,
        job_id: &MycDeliveryOutboxJobId,
    ) -> Result<MycDeliveryOutboxRecord, MycError>;
}

impl MycDeliveryOutboxJobId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, MycError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(MycError::InvalidDeliveryOutboxJobId(value.to_owned()));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for MycDeliveryOutboxJobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for MycDeliveryOutboxJobId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for MycDeliveryOutboxJobId {
    type Err = MycError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl MycDeliveryOutboxRecord {
    pub fn new(
        kind: MycDeliveryOutboxKind,
        event: RadrootsNostrEvent,
        relay_urls: Vec<RadrootsNostrRelayUrl>,
    ) -> Result<Self, MycError> {
        if relay_urls.is_empty() {
            return Err(MycError::InvalidOperation(
                "delivery outbox job requires at least one relay".to_owned(),
            ));
        }
        let created_at_unix = now_unix_secs();
        Ok(Self {
            job_id: MycDeliveryOutboxJobId::new_v7(),
            kind,
            status: MycDeliveryOutboxStatus::Queued,
            event,
            relay_urls,
            connection_id: None,
            request_id: None,
            attempt_id: None,
            signer_publish_workflow_id: None,
            publish_attempt_count: 0,
            last_error: None,
            created_at_unix,
            updated_at_unix: created_at_unix,
            published_at_unix: None,
            finalized_at_unix: None,
        })
    }

    pub fn with_connection_id(mut self, connection_id: &RadrootsNostrSignerConnectionId) -> Self {
        self.connection_id = Some(connection_id.clone());
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_attempt_id(mut self, attempt_id: impl Into<String>) -> Self {
        self.attempt_id = Some(attempt_id.into());
        self
    }

    pub fn with_signer_publish_workflow_id(
        mut self,
        workflow_id: &RadrootsNostrSignerWorkflowId,
    ) -> Self {
        self.signer_publish_workflow_id = Some(workflow_id.clone());
        self
    }

    pub fn mark_published_pending_finalize(
        &mut self,
        publish_attempt_count: usize,
        updated_at_unix: u64,
    ) -> Result<(), MycError> {
        match self.status {
            MycDeliveryOutboxStatus::Queued | MycDeliveryOutboxStatus::Failed => {
                self.status = MycDeliveryOutboxStatus::PublishedPendingFinalize;
                self.publish_attempt_count = publish_attempt_count;
                self.last_error = None;
                self.published_at_unix = Some(updated_at_unix);
                self.updated_at_unix = updated_at_unix;
                Ok(())
            }
            MycDeliveryOutboxStatus::PublishedPendingFinalize => Ok(()),
            MycDeliveryOutboxStatus::Finalized => Err(MycError::InvalidOperation(
                "cannot mark a finalized delivery outbox job as published".to_owned(),
            )),
        }
    }

    pub fn mark_failed(
        &mut self,
        publish_attempt_count: usize,
        error: impl AsRef<str>,
        updated_at_unix: u64,
    ) -> Result<(), MycError> {
        if self.status == MycDeliveryOutboxStatus::Finalized {
            return Err(MycError::InvalidOperation(
                "cannot fail a finalized delivery outbox job".to_owned(),
            ));
        }
        let error = error.as_ref().trim();
        if error.is_empty() {
            return Err(MycError::InvalidOperation(
                "delivery outbox failure reason must not be empty".to_owned(),
            ));
        }

        self.status = MycDeliveryOutboxStatus::Failed;
        self.publish_attempt_count = publish_attempt_count;
        self.last_error = Some(error.to_owned());
        self.updated_at_unix = updated_at_unix;
        Ok(())
    }

    pub fn mark_finalized(&mut self, updated_at_unix: u64) -> Result<(), MycError> {
        if self.status != MycDeliveryOutboxStatus::PublishedPendingFinalize {
            return Err(MycError::InvalidOperation(
                "cannot finalize a delivery outbox job before publish confirmation".to_owned(),
            ));
        }

        self.status = MycDeliveryOutboxStatus::Finalized;
        self.finalized_at_unix = Some(updated_at_unix);
        self.updated_at_unix = updated_at_unix;
        Ok(())
    }
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr::prelude::{RadrootsNostrEventBuilder, RadrootsNostrKind};
    use radroots_nostr_signer::prelude::{
        RadrootsNostrSignerConnectionId, RadrootsNostrSignerWorkflowId,
    };

    use super::{
        MycDeliveryOutboxJobId, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
        MycDeliveryOutboxStatus,
    };

    fn signed_event() -> nostr::Event {
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");
        RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "hello")
            .sign_with_keys(identity.keys())
            .expect("sign event")
    }

    #[test]
    fn delivery_outbox_job_ids_parse_and_display() {
        let job_id = MycDeliveryOutboxJobId::parse("job-1").expect("job id");
        assert_eq!(job_id.as_str(), "job-1");
        assert_eq!(job_id.to_string(), "job-1");
        assert_eq!(job_id.as_ref(), "job-1");
        assert!(MycDeliveryOutboxJobId::parse("   ").is_err());
        assert!(!MycDeliveryOutboxJobId::new_v7().as_str().is_empty());
    }

    #[test]
    fn delivery_outbox_record_covers_state_transitions() {
        let connection_id = RadrootsNostrSignerConnectionId::parse("conn-outbox").expect("id");
        let workflow_id = RadrootsNostrSignerWorkflowId::parse("wf-outbox").expect("id");
        let mut record = MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::AuthReplayPublish,
            signed_event(),
            vec!["wss://relay.example.com".parse().expect("relay")],
        )
        .expect("record")
        .with_connection_id(&connection_id)
        .with_request_id("req-1")
        .with_attempt_id("attempt-1")
        .with_signer_publish_workflow_id(&workflow_id);

        assert_eq!(record.status, MycDeliveryOutboxStatus::Queued);
        assert_eq!(record.connection_id.as_ref(), Some(&connection_id));
        assert_eq!(record.request_id.as_deref(), Some("req-1"));
        assert_eq!(record.attempt_id.as_deref(), Some("attempt-1"));
        assert_eq!(
            record.signer_publish_workflow_id.as_ref(),
            Some(&workflow_id)
        );

        record
            .mark_published_pending_finalize(1, 100)
            .expect("mark published");
        assert_eq!(
            record.status,
            MycDeliveryOutboxStatus::PublishedPendingFinalize
        );
        assert_eq!(record.publish_attempt_count, 1);
        assert_eq!(record.published_at_unix, Some(100));

        record
            .mark_failed(2, "relay rejected", 101)
            .expect("mark failed");
        assert_eq!(record.status, MycDeliveryOutboxStatus::Failed);
        assert_eq!(record.last_error.as_deref(), Some("relay rejected"));

        record
            .mark_published_pending_finalize(3, 102)
            .expect("republish");
        record.mark_finalized(103).expect("finalize");
        assert_eq!(record.status, MycDeliveryOutboxStatus::Finalized);
        assert_eq!(record.finalized_at_unix, Some(103));
        assert!(record.mark_failed(4, "late failure", 104).is_err());
    }

    #[test]
    fn delivery_outbox_record_requires_relays() {
        let err = MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::ListenerResponsePublish,
            signed_event(),
            Vec::new(),
        )
        .expect_err("missing relays");
        assert!(
            err.to_string()
                .contains("delivery outbox job requires at least one relay")
        );
    }
}
