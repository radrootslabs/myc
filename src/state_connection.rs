//! Durable typed Myc connection, approval, and authorization-challenge state.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use url::{Host, Url};

use crate::state_governance::{
    AuditEvidence, GovernanceOperationError, MycAuditCorrelationId, MycAuditKind, MycAuditOutcome,
    MycAuditReasonCode, MycRateLimitClass, MycRateLimitPolicy, MycRateRelayId, connection_subject,
    global_subject, govern_rate_attempt, record_audit, relay_subject,
};
use crate::state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind, PersistedMetadata,
    RepositoryOperationError, require_expected_metadata,
};
use crate::{MycNip46ClientPublicKey, MycSignerOperationId, MycSignerRequestMethod};

/// Maximum number of independently granted permissions on one connection.
pub const MYC_CONNECTION_PERMISSION_MAX_COUNT: usize = 64;
/// Maximum canonical byte length of an operator-owned challenge URL.
pub const MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES: usize = 2_048;

const CONNECTION_ID_DOMAIN: &[u8] = b"radroots.myc.connection.v1\0";
const CHALLENGE_ID_DOMAIN: &[u8] = b"radroots.myc.authorization_challenge.v1\0";
const PERMISSION_SET_DOMAIN: &[u8] = b"radroots.myc.connection_permissions.v1\0";

const READ_REQUEST_BINDING_SQL: &str = r#"SELECT
    CASE WHEN typeof(correlation_id) = 'blob' AND length(correlation_id) = 32
        THEN correlation_id ELSE NULL END AS correlation_id,
    CASE WHEN typeof(client_public_key) = 'text'
        AND length(CAST(client_public_key AS BLOB)) = 64
        THEN client_public_key ELSE NULL END AS client_public_key,
    CASE WHEN typeof(method) = 'text'
        AND length(CAST(method AS BLOB)) BETWEEN 1 AND 32
        THEN method ELSE NULL END AS method,
    received_at_unix_ms
FROM nip46_requests
WHERE operation_id = ?
LIMIT 2"#;

const READ_DECISION_SQL: &str = r#"SELECT
    CASE WHEN typeof(connection_id) = 'blob' AND length(connection_id) = 32
        THEN connection_id ELSE NULL END AS connection_id,
    typeof(connection_id) AS connection_id_type,
    CASE WHEN typeof(decision) = 'text' AND length(CAST(decision AS BLOB)) <= 32
        THEN decision ELSE NULL END AS decision,
    CASE WHEN typeof(reason_code) = 'text' AND length(CAST(reason_code AS BLOB)) <= 40
        THEN reason_code ELSE NULL END AS reason_code,
    policy_generation,
    CASE WHEN typeof(requested_permissions_sha256) = 'blob'
        AND length(requested_permissions_sha256) = 32
        THEN requested_permissions_sha256 ELSE NULL END AS requested_permissions_sha256,
    CASE WHEN typeof(challenge_id) = 'blob' AND length(challenge_id) = 32
        THEN challenge_id ELSE NULL END AS challenge_id,
    typeof(challenge_id) AS challenge_id_type,
    decided_at_unix_ms
FROM nip46_request_decisions
WHERE operation_id = ?
LIMIT 2"#;

const INSERT_DECISION_SQL: &str = r#"INSERT INTO nip46_request_decisions (
    operation_id, connection_id, decision, reason_code, policy_generation,
    requested_permissions_sha256, challenge_id, decided_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#;

const INSERT_CONNECTION_SQL: &str = r#"INSERT INTO connections (
    connection_id, connection_nonce, client_public_key, requested_permissions_sha256,
    policy_generation, status, created_at_unix_ms, updated_at_unix_ms,
    authorized_until_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

const INSERT_PERMISSION_SQL: &str = r#"INSERT INTO connection_permissions (
    connection_id, permission_scope, permission_code
) VALUES (?, ?, ?)"#;

const READ_CONNECTION_SQL: &str = r#"SELECT
    CASE WHEN typeof(connection_id) = 'blob' AND length(connection_id) = 32
        THEN connection_id ELSE NULL END AS connection_id,
    CASE WHEN typeof(connection_nonce) = 'blob' AND length(connection_nonce) = 32
        THEN connection_nonce ELSE NULL END AS connection_nonce,
    CASE WHEN typeof(client_public_key) = 'text'
        AND length(CAST(client_public_key AS BLOB)) = 64
        THEN client_public_key ELSE NULL END AS client_public_key,
    CASE WHEN typeof(requested_permissions_sha256) = 'blob'
        AND length(requested_permissions_sha256) = 32
        THEN requested_permissions_sha256 ELSE NULL END AS requested_permissions_sha256,
    policy_generation,
    CASE WHEN typeof(status) = 'text' AND length(CAST(status AS BLOB)) <= 16
        THEN status ELSE NULL END AS status,
    created_at_unix_ms,
    updated_at_unix_ms,
    authorized_until_unix_ms,
    typeof(authorized_until_unix_ms) AS authorized_until_type
FROM connections
WHERE connection_id = ?
LIMIT 2"#;

const READ_PERMISSIONS_SQL: &str = r#"SELECT
    CASE WHEN typeof(permission_code) = 'text'
        AND length(CAST(permission_code AS BLOB)) BETWEEN 1 AND 64
        THEN permission_code ELSE NULL END AS permission_code
FROM connection_permissions
WHERE connection_id = ? AND permission_scope = ?
LIMIT 65"#;

const APPROVE_CONNECTION_SQL: &str = r#"UPDATE connections
SET status = 'active', updated_at_unix_ms = ?, authorized_until_unix_ms = ?
WHERE connection_id = ? AND status = 'pending' AND policy_generation = ?"#;

const DENY_CONNECTION_SQL: &str = r#"UPDATE connections
SET status = 'denied', updated_at_unix_ms = ?, authorized_until_unix_ms = NULL
WHERE connection_id = ? AND status = 'pending' AND policy_generation = ?"#;

const EXPIRE_CONNECTION_SQL: &str = r#"UPDATE connections
SET status = 'expired', updated_at_unix_ms = ?, authorized_until_unix_ms = NULL
WHERE connection_id = ? AND status = 'active' AND policy_generation = ?
    AND authorized_until_unix_ms IS NOT NULL AND authorized_until_unix_ms < ?"#;

const UPDATE_APPROVAL_DECISION_SQL: &str = r#"UPDATE nip46_request_decisions
SET decision = ?, reason_code = ?, decided_at_unix_ms = ?
WHERE operation_id = ? AND connection_id = ? AND decision = 'pending_approval'
    AND policy_generation = ?"#;

const INSERT_CHALLENGE_SQL: &str = r#"INSERT INTO connection_auth_challenges (
    challenge_id, challenge_nonce, connection_id, operation_id, policy_generation,
    challenge_url, state, issued_at_unix_ms, expires_at_unix_ms, resolved_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL)"#;

const READ_CHALLENGE_SQL: &str = r#"SELECT
    CASE WHEN typeof(challenge_id) = 'blob' AND length(challenge_id) = 32
        THEN challenge_id ELSE NULL END AS challenge_id,
    CASE WHEN typeof(challenge_nonce) = 'blob' AND length(challenge_nonce) = 32
        THEN challenge_nonce ELSE NULL END AS challenge_nonce,
    CASE WHEN typeof(connection_id) = 'blob' AND length(connection_id) = 32
        THEN connection_id ELSE NULL END AS connection_id,
    CASE WHEN typeof(operation_id) = 'blob' AND length(operation_id) = 32
        THEN operation_id ELSE NULL END AS operation_id,
    policy_generation,
    CASE WHEN typeof(challenge_url) = 'text'
        AND length(CAST(challenge_url AS BLOB)) BETWEEN 1 AND 2048
        THEN challenge_url ELSE NULL END AS challenge_url,
    CASE WHEN typeof(state) = 'text' AND length(CAST(state AS BLOB)) <= 16
        THEN state ELSE NULL END AS state,
    issued_at_unix_ms, expires_at_unix_ms, resolved_at_unix_ms,
    typeof(resolved_at_unix_ms) AS resolved_at_type
FROM connection_auth_challenges
WHERE operation_id = ?
LIMIT 2"#;

const RESOLVE_CHALLENGE_SQL: &str = r#"UPDATE connection_auth_challenges
SET state = ?, resolved_at_unix_ms = ?
WHERE challenge_id = ? AND connection_id = ? AND operation_id = ?
    AND policy_generation = ? AND state = 'pending'"#;

const UPDATE_CHALLENGE_DECISION_SQL: &str = r#"UPDATE nip46_request_decisions
SET decision = ?, reason_code = ?, decided_at_unix_ms = ?
WHERE operation_id = ? AND connection_id = ? AND challenge_id = ?
    AND policy_generation = ? AND decision = 'challenged'"#;

/// Stable construction and validation failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConnectionStateErrorKind {
    InvalidPermissionSet,
    InvalidPolicyGeneration,
    InvalidTime,
    InvalidChallengeUrl,
    InvalidChallengeLifetime,
}

impl MycConnectionStateErrorKind {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPermissionSet => "connection_permission_set_invalid",
            Self::InvalidPolicyGeneration => "connection_policy_generation_invalid",
            Self::InvalidTime => "connection_time_invalid",
            Self::InvalidChallengeUrl => "authorization_challenge_url_invalid",
            Self::InvalidChallengeLifetime => "authorization_challenge_lifetime_invalid",
        }
    }
}

/// Source-free connection-state validation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycConnectionStateError {
    kind: MycConnectionStateErrorKind,
}

impl MycConnectionStateError {
    const fn new(kind: MycConnectionStateErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycConnectionStateErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycConnectionStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycConnectionStateErrorKind::InvalidPermissionSet => {
                "connection permission set is invalid"
            }
            MycConnectionStateErrorKind::InvalidPolicyGeneration => {
                "connection policy generation is invalid"
            }
            MycConnectionStateErrorKind::InvalidTime => "connection time is invalid",
            MycConnectionStateErrorKind::InvalidChallengeUrl => {
                "authorization challenge URL is invalid"
            }
            MycConnectionStateErrorKind::InvalidChallengeLifetime => {
                "authorization challenge lifetime is invalid"
            }
        })
    }
}

impl fmt::Debug for MycConnectionStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConnectionStateError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycConnectionStateError {}

/// One closed Myc connection permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MycConnectionPermission {
    GetPublicKey,
    GetSessionCapability,
    SignEvent(u32),
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
    Ping,
    SwitchRelays,
    Logout,
}

impl MycConnectionPermission {
    fn code(self) -> String {
        match self {
            Self::GetPublicKey => "get_public_key".into(),
            Self::GetSessionCapability => "get_session_capability".into(),
            Self::SignEvent(kind) => format!("sign_event:kind:{kind}"),
            Self::Nip04Encrypt => "nip04_encrypt".into(),
            Self::Nip04Decrypt => "nip04_decrypt".into(),
            Self::Nip44Encrypt => "nip44_encrypt".into(),
            Self::Nip44Decrypt => "nip44_decrypt".into(),
            Self::Ping => "ping".into(),
            Self::SwitchRelays => "switch_relays".into(),
            Self::Logout => "logout".into(),
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "get_public_key" => Some(Self::GetPublicKey),
            "get_session_capability" => Some(Self::GetSessionCapability),
            "nip04_encrypt" => Some(Self::Nip04Encrypt),
            "nip04_decrypt" => Some(Self::Nip04Decrypt),
            "nip44_encrypt" => Some(Self::Nip44Encrypt),
            "nip44_decrypt" => Some(Self::Nip44Decrypt),
            "ping" => Some(Self::Ping),
            "switch_relays" => Some(Self::SwitchRelays),
            "logout" => Some(Self::Logout),
            _ => value
                .strip_prefix("sign_event:kind:")
                .and_then(|kind| kind.parse::<u32>().ok().map(|parsed| (kind, parsed)))
                .filter(|(kind, parsed)| *kind == parsed.to_string())
                .map(|(_, parsed)| Self::SignEvent(parsed)),
        }
    }
}

/// Immutable canonical set of connection permissions.
#[derive(Clone, PartialEq, Eq)]
pub struct MycConnectionPermissionSet {
    permissions: Box<[MycConnectionPermission]>,
    digest: [u8; 32],
}

impl MycConnectionPermissionSet {
    /// Validates, orders, and seals one bounded permission set.
    pub fn new(permissions: &[MycConnectionPermission]) -> Result<Self, MycConnectionStateError> {
        if permissions.len() > MYC_CONNECTION_PERMISSION_MAX_COUNT {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidPermissionSet,
            ));
        }
        let mut normalized = permissions.to_vec();
        normalized.sort_unstable();
        if normalized.windows(2).any(|window| window[0] == window[1]) {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidPermissionSet,
            ));
        }
        let digest = permission_digest(&normalized);
        Ok(Self {
            permissions: normalized.into_boxed_slice(),
            digest,
        })
    }

    /// Returns the canonical ordered permissions.
    #[must_use]
    pub fn permissions(&self) -> &[MycConnectionPermission] {
        &self.permissions
    }

    fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn is_subset_of(&self, other: &Self) -> bool {
        self.permissions
            .iter()
            .all(|permission| other.permissions.binary_search(permission).is_ok())
    }

    pub(crate) fn contains(&self, permission: MycConnectionPermission) -> bool {
        self.permissions.binary_search(&permission).is_ok()
    }
}

impl fmt::Debug for MycConnectionPermissionSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConnectionPermissionSet")
            .field("permission_count", &self.permissions.len())
            .finish()
    }
}

/// Injected entropy used once to derive a durable connection identity.
pub struct MycConnectionNonce([u8; 32]);

impl MycConnectionNonce {
    /// Wraps caller-injected entropy without reading ambient state.
    #[must_use]
    pub const fn from_injected_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycConnectionNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycConnectionNonce([redacted])")
    }
}

/// Injected entropy used once to derive a durable challenge identity.
pub struct MycAuthorizationChallengeNonce([u8; 32]);

impl MycAuthorizationChallengeNonce {
    /// Wraps caller-injected entropy without reading ambient state.
    #[must_use]
    pub const fn from_injected_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MycAuthorizationChallengeNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycAuthorizationChallengeNonce([redacted])")
    }
}

macro_rules! digest_id {
    ($name:ident, $debug:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the exact stable identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($debug)
            }
        }
    };
}

digest_id!(MycConnectionId, "MycConnectionId([redacted])");
digest_id!(
    MycAuthorizationChallengeId,
    "MycAuthorizationChallengeId([redacted])"
);

/// Nonzero immutable connection-policy generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MycConnectionPolicyGeneration(u64);

impl MycConnectionPolicyGeneration {
    /// Constructs a policy generation representable by SQLite.
    pub fn new(value: u64) -> Result<Self, MycConnectionStateError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidPolicyGeneration,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated generation fits SQLite")
    }
}

/// Nonzero immutable millisecond UTC evidence supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MycConnectionTimeUnixMs(u64);

impl MycConnectionTimeUnixMs {
    /// Constructs a timestamp representable by SQLite.
    pub fn new(value: u64) -> Result<Self, MycConnectionStateError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidTime,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the injected timestamp.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated time fits SQLite")
    }
}

/// Closed admission authority for a connect request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConnectionAdmissionPolicy {
    Trusted,
    ExplicitApproval,
    Denied,
}

impl MycConnectionAdmissionPolicy {
    const fn decision(self) -> MycConnectionDecision {
        match self {
            Self::Trusted => MycConnectionDecision::Allowed,
            Self::ExplicitApproval => MycConnectionDecision::PendingApproval,
            Self::Denied => MycConnectionDecision::Denied,
        }
    }
}

/// Stable durable request decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConnectionDecision {
    PendingApproval,
    Challenged,
    Allowed,
    Denied,
}

impl MycConnectionDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PendingApproval => "pending_approval",
            Self::Challenged => "challenged",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        }
    }

    const fn reason(self, policy: MycConnectionAdmissionPolicy) -> &'static str {
        match (self, policy) {
            (Self::PendingApproval, _) => "explicit_approval_required",
            (Self::Allowed, _) => "trusted_client",
            (Self::Denied, _) => "policy_denied",
            (Self::Challenged, _) => "authorization_challenge_required",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_approval" => Some(Self::PendingApproval),
            "challenged" => Some(Self::Challenged),
            "allowed" => Some(Self::Allowed),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Immutable connect-admission input.
pub struct MycConnectionAdmissionRequest {
    operation_id: MycSignerOperationId,
    client_public_key: MycNip46ClientPublicKey,
    requested_permissions: MycConnectionPermissionSet,
    policy_generation: MycConnectionPolicyGeneration,
    nonce: MycConnectionNonce,
    observed_at: MycConnectionTimeUnixMs,
    authorized_until: Option<MycConnectionTimeUnixMs>,
    policy: MycConnectionAdmissionPolicy,
    relay_id: MycRateRelayId,
}

impl MycConnectionAdmissionRequest {
    /// Constructs a request from validated protocol, policy, entropy, and time evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: MycSignerOperationId,
        client_public_key: MycNip46ClientPublicKey,
        requested_permissions: MycConnectionPermissionSet,
        policy_generation: MycConnectionPolicyGeneration,
        nonce: MycConnectionNonce,
        observed_at: MycConnectionTimeUnixMs,
        authorized_until: Option<MycConnectionTimeUnixMs>,
        policy: MycConnectionAdmissionPolicy,
        relay_id: MycRateRelayId,
    ) -> Result<Self, MycConnectionStateError> {
        if (matches!(policy, MycConnectionAdmissionPolicy::Trusted)
            && authorized_until.is_some_and(|until| until <= observed_at))
            || (!matches!(policy, MycConnectionAdmissionPolicy::Trusted)
                && authorized_until.is_some())
        {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidTime,
            ));
        }
        Ok(Self {
            operation_id,
            client_public_key,
            requested_permissions,
            policy_generation,
            nonce,
            observed_at,
            authorized_until,
            policy,
            relay_id,
        })
    }

    fn owned(&self) -> Self {
        Self {
            operation_id: self.operation_id,
            client_public_key: self.client_public_key.clone(),
            requested_permissions: self.requested_permissions.clone(),
            policy_generation: self.policy_generation,
            nonce: MycConnectionNonce(self.nonce.0),
            observed_at: self.observed_at,
            authorized_until: self.authorized_until,
            policy: self.policy,
            relay_id: self.relay_id.clone(),
        }
    }

    pub(crate) const fn client_public_key(&self) -> &MycNip46ClientPublicKey {
        &self.client_public_key
    }

    pub(crate) const fn requested_permissions(&self) -> &MycConnectionPermissionSet {
        &self.requested_permissions
    }

    pub(crate) const fn observed_at(&self) -> MycConnectionTimeUnixMs {
        self.observed_at
    }

    pub(crate) const fn authorized_until(&self) -> Option<MycConnectionTimeUnixMs> {
        self.authorized_until
    }

    pub(crate) const fn policy(&self) -> MycConnectionAdmissionPolicy {
        self.policy
    }
}

impl fmt::Debug for MycConnectionAdmissionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycConnectionAdmissionRequest([redacted])")
    }
}

/// Durable connection status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConnectionStatus {
    Pending,
    Active,
    Denied,
    Expired,
}

impl MycConnectionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Validated durable connection record.
#[derive(Clone, PartialEq, Eq)]
pub struct MycConnectionRecord {
    id: MycConnectionId,
    client_public_key: MycNip46ClientPublicKey,
    requested_permissions: MycConnectionPermissionSet,
    granted_permissions: MycConnectionPermissionSet,
    policy_generation: MycConnectionPolicyGeneration,
    status: MycConnectionStatus,
    created_at: MycConnectionTimeUnixMs,
    updated_at: MycConnectionTimeUnixMs,
    authorized_until: Option<MycConnectionTimeUnixMs>,
}

impl MycConnectionRecord {
    #[must_use]
    pub const fn id(&self) -> MycConnectionId {
        self.id
    }
    #[must_use]
    pub const fn client_public_key(&self) -> &MycNip46ClientPublicKey {
        &self.client_public_key
    }
    #[must_use]
    pub const fn requested_permissions(&self) -> &MycConnectionPermissionSet {
        &self.requested_permissions
    }
    #[must_use]
    pub const fn granted_permissions(&self) -> &MycConnectionPermissionSet {
        &self.granted_permissions
    }
    #[must_use]
    pub const fn policy_generation(&self) -> MycConnectionPolicyGeneration {
        self.policy_generation
    }
    #[must_use]
    pub const fn status(&self) -> MycConnectionStatus {
        self.status
    }
    #[must_use]
    pub const fn created_at(&self) -> MycConnectionTimeUnixMs {
        self.created_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> MycConnectionTimeUnixMs {
        self.updated_at
    }
    #[must_use]
    pub const fn authorized_until(&self) -> Option<MycConnectionTimeUnixMs> {
        self.authorized_until
    }

    #[cfg(test)]
    pub(crate) fn active_for_test(
        client_public_key: MycNip46ClientPublicKey,
        granted_permissions: MycConnectionPermissionSet,
        authorized_until: Option<MycConnectionTimeUnixMs>,
    ) -> Self {
        Self {
            id: MycConnectionId([0x45; 32]),
            client_public_key,
            requested_permissions: granted_permissions.clone(),
            granted_permissions,
            policy_generation: MycConnectionPolicyGeneration(1),
            status: MycConnectionStatus::Active,
            created_at: MycConnectionTimeUnixMs(1),
            updated_at: MycConnectionTimeUnixMs(1),
            authorized_until,
        }
    }
}

impl fmt::Debug for MycConnectionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConnectionRecord")
            .field("status", &self.status)
            .field(
                "permission_count",
                &self.granted_permissions.permissions.len(),
            )
            .finish()
    }
}

/// Durable result for initial connection admission.
#[derive(Clone, PartialEq, Eq)]
pub struct MycConnectionDecisionRecord {
    operation_id: MycSignerOperationId,
    connection: Option<MycConnectionRecord>,
    decision: MycConnectionDecision,
    policy_generation: MycConnectionPolicyGeneration,
    decided_at: MycConnectionTimeUnixMs,
}

impl MycConnectionDecisionRecord {
    #[must_use]
    pub const fn operation_id(&self) -> MycSignerOperationId {
        self.operation_id
    }
    #[must_use]
    pub const fn connection(&self) -> Option<&MycConnectionRecord> {
        self.connection.as_ref()
    }
    #[must_use]
    pub const fn decision(&self) -> MycConnectionDecision {
        self.decision
    }
    #[must_use]
    pub const fn policy_generation(&self) -> MycConnectionPolicyGeneration {
        self.policy_generation
    }
    #[must_use]
    pub const fn decided_at(&self) -> MycConnectionTimeUnixMs {
        self.decided_at
    }
}

impl fmt::Debug for MycConnectionDecisionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConnectionDecisionRecord")
            .field("decision", &self.decision)
            .finish()
    }
}

/// New or replayed connection-admission result.
#[derive(Clone, PartialEq, Eq)]
pub enum MycConnectionAdmission {
    Admitted(MycConnectionDecisionRecord),
    ExactReplay(MycConnectionDecisionRecord),
    RateLimited,
}

impl MycConnectionAdmission {
    #[must_use]
    pub const fn record(&self) -> Option<&MycConnectionDecisionRecord> {
        match self {
            Self::Admitted(record) | Self::ExactReplay(record) => Some(record),
            Self::RateLimited => None,
        }
    }
}

impl fmt::Debug for MycConnectionAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admitted(_) => "MycConnectionAdmission::Admitted([redacted])",
            Self::ExactReplay(_) => "MycConnectionAdmission::ExactReplay([redacted])",
            Self::RateLimited => "MycConnectionAdmission::RateLimited",
        })
    }
}

/// Operator decision for a pending explicit-approval connection.
pub enum MycConnectionOperatorDecision {
    Approve {
        granted_permissions: MycConnectionPermissionSet,
        authorized_until: Option<MycConnectionTimeUnixMs>,
    },
    Deny,
}

impl fmt::Debug for MycConnectionOperatorDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Approve { .. } => "MycConnectionOperatorDecision::Approve([redacted])",
            Self::Deny => "MycConnectionOperatorDecision::Deny",
        })
    }
}

/// Validated operator-owned challenge URL.
#[derive(Clone, PartialEq, Eq)]
pub struct MycAuthorizationChallengeUrl(Box<str>);

impl MycAuthorizationChallengeUrl {
    /// Admits canonical HTTPS URLs and loopback-only HTTP URLs.
    pub fn new(value: &str) -> Result<Self, MycConnectionStateError> {
        if value.is_empty() || value.len() > MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidChallengeUrl,
            ));
        }
        let parsed = Url::parse(value).map_err(|_| {
            MycConnectionStateError::new(MycConnectionStateErrorKind::InvalidChallengeUrl)
        })?;
        let loopback_http = parsed.scheme() == "http"
            && match parsed.host() {
                Some(Host::Domain("localhost")) => true,
                Some(Host::Ipv4(address)) => address.is_loopback(),
                Some(Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            };
        if (parsed.scheme() != "https" && !loopback_http)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != value
        {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidChallengeUrl,
            ));
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MycAuthorizationChallengeUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycAuthorizationChallengeUrl([redacted])")
    }
}

/// Immutable authorization-challenge creation input.
pub struct MycAuthorizationChallengeRequest {
    operation_id: MycSignerOperationId,
    connection_id: MycConnectionId,
    policy_generation: MycConnectionPolicyGeneration,
    url: MycAuthorizationChallengeUrl,
    nonce: MycAuthorizationChallengeNonce,
    issued_at: MycConnectionTimeUnixMs,
    expires_at: MycConnectionTimeUnixMs,
}

impl MycAuthorizationChallengeRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: MycSignerOperationId,
        connection_id: MycConnectionId,
        policy_generation: MycConnectionPolicyGeneration,
        url: MycAuthorizationChallengeUrl,
        nonce: MycAuthorizationChallengeNonce,
        issued_at: MycConnectionTimeUnixMs,
        expires_at: MycConnectionTimeUnixMs,
    ) -> Result<Self, MycConnectionStateError> {
        if expires_at <= issued_at {
            return Err(MycConnectionStateError::new(
                MycConnectionStateErrorKind::InvalidChallengeLifetime,
            ));
        }
        Ok(Self {
            operation_id,
            connection_id,
            policy_generation,
            url,
            nonce,
            issued_at,
            expires_at,
        })
    }

    fn owned(&self) -> Self {
        Self {
            operation_id: self.operation_id,
            connection_id: self.connection_id,
            policy_generation: self.policy_generation,
            url: self.url.clone(),
            nonce: MycAuthorizationChallengeNonce(self.nonce.0),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub(crate) const fn url(&self) -> &MycAuthorizationChallengeUrl {
        &self.url
    }

    pub(crate) const fn issued_at(&self) -> MycConnectionTimeUnixMs {
        self.issued_at
    }

    pub(crate) const fn expires_at(&self) -> MycConnectionTimeUnixMs {
        self.expires_at
    }
}

impl fmt::Debug for MycAuthorizationChallengeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycAuthorizationChallengeRequest([redacted])")
    }
}

/// Durable authorization-challenge state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAuthorizationChallengeState {
    Pending,
    Authorized,
    Expired,
}

impl MycAuthorizationChallengeState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "authorized" => Some(Self::Authorized),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Validated durable challenge record.
#[derive(Clone, PartialEq, Eq)]
pub struct MycAuthorizationChallengeRecord {
    id: MycAuthorizationChallengeId,
    operation_id: MycSignerOperationId,
    connection_id: MycConnectionId,
    policy_generation: MycConnectionPolicyGeneration,
    url: MycAuthorizationChallengeUrl,
    state: MycAuthorizationChallengeState,
    issued_at: MycConnectionTimeUnixMs,
    expires_at: MycConnectionTimeUnixMs,
    resolved_at: Option<MycConnectionTimeUnixMs>,
}

impl MycAuthorizationChallengeRecord {
    #[must_use]
    pub const fn id(&self) -> MycAuthorizationChallengeId {
        self.id
    }
    #[must_use]
    pub const fn operation_id(&self) -> MycSignerOperationId {
        self.operation_id
    }
    #[must_use]
    pub const fn connection_id(&self) -> MycConnectionId {
        self.connection_id
    }
    #[must_use]
    pub const fn policy_generation(&self) -> MycConnectionPolicyGeneration {
        self.policy_generation
    }
    #[must_use]
    pub const fn url(&self) -> &MycAuthorizationChallengeUrl {
        &self.url
    }
    #[must_use]
    pub const fn state(&self) -> MycAuthorizationChallengeState {
        self.state
    }
    #[must_use]
    pub const fn issued_at(&self) -> MycConnectionTimeUnixMs {
        self.issued_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> MycConnectionTimeUnixMs {
        self.expires_at
    }
    #[must_use]
    pub const fn resolved_at(&self) -> Option<MycConnectionTimeUnixMs> {
        self.resolved_at
    }
}

impl fmt::Debug for MycAuthorizationChallengeRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAuthorizationChallengeRecord")
            .field("state", &self.state)
            .finish()
    }
}

/// New or replayed challenge creation result.
#[derive(Clone, PartialEq, Eq)]
pub enum MycAuthorizationChallengeAdmission {
    Created(MycAuthorizationChallengeRecord),
    ExactReplay(MycAuthorizationChallengeRecord),
    RateLimited,
}

impl MycAuthorizationChallengeAdmission {
    #[must_use]
    pub const fn record(&self) -> Option<&MycAuthorizationChallengeRecord> {
        match self {
            Self::Created(record) | Self::ExactReplay(record) => Some(record),
            Self::RateLimited => None,
        }
    }
}

impl fmt::Debug for MycAuthorizationChallengeAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Created(_) => "MycAuthorizationChallengeAdmission::Created([redacted])",
            Self::ExactReplay(_) => "MycAuthorizationChallengeAdmission::ExactReplay([redacted])",
            Self::RateLimited => "MycAuthorizationChallengeAdmission::RateLimited",
        })
    }
}

/// New, replayed, or rate-limited authorization result.
#[derive(Clone, PartialEq, Eq)]
pub enum MycAuthorizationChallengeAuthorization {
    Resolved(MycAuthorizationChallengeRecord),
    ExactReplay(MycAuthorizationChallengeRecord),
    RateLimited,
}

impl MycAuthorizationChallengeAuthorization {
    #[must_use]
    pub const fn record(&self) -> Option<&MycAuthorizationChallengeRecord> {
        match self {
            Self::Resolved(record) | Self::ExactReplay(record) => Some(record),
            Self::RateLimited => None,
        }
    }
}

impl fmt::Debug for MycAuthorizationChallengeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Resolved(_) => "MycAuthorizationChallengeAuthorization::Resolved([redacted])",
            Self::ExactReplay(_) => {
                "MycAuthorizationChallengeAuthorization::ExactReplay([redacted])"
            }
            Self::RateLimited => "MycAuthorizationChallengeAuthorization::RateLimited",
        })
    }
}

impl MycStateRepository<'_> {
    /// Atomically records trusted, explicit-approval, or direct-denial admission.
    pub async fn admit_connection(
        &self,
        request: &MycConnectionAdmissionRequest,
    ) -> Result<MycConnectionAdmission, MycStateRepositoryError> {
        if !self.expected().admits_rate_relay(&request.relay_id)
            || !self.expected().admits_connection_request(request)
        {
            return Err(MycStateRepositoryError::new(
                MycStateRepositoryErrorKind::Binding,
            ));
        }
        let request = request.owned();
        let rate_policy = (request.policy != MycConnectionAdmissionPolicy::Denied).then(|| {
            self.expected()
                .governance_rate_policy(MycRateLimitClass::ConnectionAdmission)
        });
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    admit_connection(transaction, &request, rate_policy).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Atomically approves or denies one pending connection.
    pub async fn decide_pending_connection(
        &self,
        operation_id: MycSignerOperationId,
        connection_id: MycConnectionId,
        policy_generation: MycConnectionPolicyGeneration,
        observed_at: MycConnectionTimeUnixMs,
        audit_correlation: MycAuditCorrelationId,
        decision: MycConnectionOperatorDecision,
    ) -> Result<MycConnectionRecord, MycStateRepositoryError> {
        if !self
            .expected()
            .admits_connection_operator_decision(observed_at, &decision)
        {
            return Err(MycStateRepositoryError::new(
                MycStateRepositoryErrorKind::Binding,
            ));
        }
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    decide_connection(
                        transaction,
                        operation_id,
                        connection_id,
                        policy_generation,
                        observed_at,
                        audit_correlation,
                        decision,
                    )
                    .await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Idempotently marks an expired authorized connection.
    pub async fn expire_connection(
        &self,
        connection_id: MycConnectionId,
        policy_generation: MycConnectionPolicyGeneration,
        observed_at: MycConnectionTimeUnixMs,
        audit_correlation: MycAuditCorrelationId,
    ) -> Result<MycConnectionRecord, MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    let before = read_connection(transaction, connection_id).await?;
                    if before.policy_generation != policy_generation {
                        return Err(ConnectionOperationError::Binding);
                    }
                    if before.status == MycConnectionStatus::Expired {
                        record_connection_expiry_audit(
                            transaction,
                            audit_correlation,
                            before.updated_at,
                        )
                        .await?;
                        return Ok(before);
                    }
                    if before.status != MycConnectionStatus::Active
                        || before
                            .authorized_until
                            .is_none_or(|until| until >= observed_at)
                    {
                        return Err(ConnectionOperationError::Binding);
                    }
                    let result = sqlx::query(EXPIRE_CONNECTION_SQL)
                        .bind(observed_at.sqlite_value())
                        .bind(connection_id.as_bytes().as_slice())
                        .bind(policy_generation.sqlite_value())
                        .bind(observed_at.sqlite_value())
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| ConnectionOperationError::Storage)?;
                    require_one(result.rows_affected())?;
                    let record = read_connection(transaction, connection_id).await?;
                    record_connection_expiry_audit(transaction, audit_correlation, observed_at)
                        .await?;
                    Ok(record)
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Creates or replays one request-bound authorization challenge.
    pub async fn issue_authorization_challenge(
        &self,
        request: &MycAuthorizationChallengeRequest,
    ) -> Result<MycAuthorizationChallengeAdmission, MycStateRepositoryError> {
        if !self
            .expected()
            .admits_authorization_challenge_request(request)
        {
            return Err(MycStateRepositoryError::new(
                MycStateRepositoryErrorKind::Binding,
            ));
        }
        let request = request.owned();
        let rate_policy = self
            .expected()
            .governance_rate_policy(MycRateLimitClass::ChallengeCreation);
        let expected = PersistedMetadata::from(self.expected());
        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    issue_challenge(transaction, &request, rate_policy).await
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Authorizes or expires an exact bound challenge, replaying terminal state safely.
    pub async fn authorize_challenge(
        &self,
        challenge_id: MycAuthorizationChallengeId,
        connection_id: MycConnectionId,
        operation_id: MycSignerOperationId,
        policy_generation: MycConnectionPolicyGeneration,
        observed_at: MycConnectionTimeUnixMs,
    ) -> Result<MycAuthorizationChallengeAuthorization, MycStateRepositoryError> {
        let rate_policy = self
            .expected()
            .governance_rate_policy(MycRateLimitClass::ChallengeAuthorization);
        let expected = PersistedMetadata::from(self.expected());
        let result = self
            .host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    verify_metadata(transaction, &expected).await?;
                    authorize_challenge(
                        transaction,
                        challenge_id,
                        connection_id,
                        operation_id,
                        policy_generation,
                        observed_at,
                        rate_policy,
                    )
                    .await
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if result.record().is_some_and(|record| {
            record.state() == MycAuthorizationChallengeState::Authorized
                && !self
                    .expected()
                    .authorization_challenge_is_current(record, observed_at)
        }) {
            return Err(MycStateRepositoryError::new(
                MycStateRepositoryErrorKind::Binding,
            ));
        }
        Ok(result)
    }
}

async fn record_connection_expiry_audit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    correlation: MycAuditCorrelationId,
    occurred_at: MycConnectionTimeUnixMs,
) -> Result<(), ConnectionOperationError> {
    record_audit(
        transaction,
        AuditEvidence {
            correlation,
            occurred_at,
            operation_id: None,
        },
        MycAuditKind::ConnectionExpiry,
        MycAuditOutcome::Succeeded,
        MycAuditReasonCode::ConnectionExpired,
    )
    .await
    .map_err(map_governance_error)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionOperationError {
    Binding,
    Storage,
}

const fn map_governance_error(error: GovernanceOperationError) -> ConnectionOperationError {
    match error {
        GovernanceOperationError::Binding => ConnectionOperationError::Binding,
        GovernanceOperationError::Storage => ConnectionOperationError::Storage,
    }
}

async fn verify_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), ConnectionOperationError> {
    require_expected_metadata(transaction, expected)
        .await
        .map_err(|error| match error {
            RepositoryOperationError::Binding => ConnectionOperationError::Binding,
            RepositoryOperationError::Storage => ConnectionOperationError::Storage,
        })
}

async fn admit_connection(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycConnectionAdmissionRequest,
    rate_policy: Option<MycRateLimitPolicy>,
) -> Result<MycConnectionAdmission, ConnectionOperationError> {
    let binding = read_request_binding(transaction, request.operation_id).await?;
    if binding.client_public_key != request.client_public_key
        || binding.method != MycSignerRequestMethod::Connect
        || request.observed_at < binding.received_at
    {
        return Err(ConnectionOperationError::Binding);
    }
    if let Some(existing) = read_decision(transaction, request.operation_id).await? {
        if existing.policy_generation != request.policy_generation
            || existing.admission_policy != Some(request.policy)
            || existing.requested_permissions_sha256 != *request.requested_permissions.digest()
        {
            return Err(ConnectionOperationError::Binding);
        }
        let record = decision_record(transaction, request.operation_id, existing).await?;
        if record
            .connection()
            .is_some_and(|connection| connection.client_public_key != request.client_public_key)
        {
            return Err(ConnectionOperationError::Binding);
        }
        return Ok(MycConnectionAdmission::ExactReplay(record));
    }

    let evidence = AuditEvidence {
        correlation: binding.correlation,
        occurred_at: request.observed_at,
        operation_id: Some(request.operation_id),
    };
    if let Some(rate_policy) = rate_policy
        && !govern_rate_attempt(
            transaction,
            rate_policy,
            MycRateLimitClass::ConnectionAdmission,
            &[global_subject(), relay_subject(&request.relay_id)],
            evidence,
            MycAuditKind::ConnectionAdmission,
        )
        .await
        .map_err(map_governance_error)?
    {
        return Ok(MycConnectionAdmission::RateLimited);
    }

    let decision = request.policy.decision();
    let connection_id = if request.policy == MycConnectionAdmissionPolicy::Denied {
        None
    } else {
        let id = derive_connection_id(&request.client_public_key, &request.nonce);
        insert_connection(transaction, request, id).await?;
        Some(id)
    };
    insert_decision(
        transaction,
        request.operation_id,
        connection_id,
        decision,
        decision.reason(request.policy),
        request.policy_generation,
        request.requested_permissions.digest(),
        None,
        request.observed_at,
    )
    .await?;
    let persisted = read_decision(transaction, request.operation_id)
        .await?
        .ok_or(ConnectionOperationError::Binding)?;
    let record = decision_record(transaction, request.operation_id, persisted).await?;
    let (outcome, reason) = match request.policy {
        MycConnectionAdmissionPolicy::Trusted => {
            (MycAuditOutcome::Succeeded, MycAuditReasonCode::Trusted)
        }
        MycConnectionAdmissionPolicy::ExplicitApproval => (
            MycAuditOutcome::Succeeded,
            MycAuditReasonCode::ApprovalRequired,
        ),
        MycConnectionAdmissionPolicy::Denied => {
            (MycAuditOutcome::Rejected, MycAuditReasonCode::PolicyDenied)
        }
    };
    record_audit(
        transaction,
        evidence,
        MycAuditKind::ConnectionAdmission,
        outcome,
        reason,
    )
    .await
    .map_err(map_governance_error)?;
    Ok(MycConnectionAdmission::Admitted(record))
}

async fn insert_connection(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycConnectionAdmissionRequest,
    id: MycConnectionId,
) -> Result<(), ConnectionOperationError> {
    let status = match request.policy {
        MycConnectionAdmissionPolicy::Trusted => MycConnectionStatus::Active,
        MycConnectionAdmissionPolicy::ExplicitApproval => MycConnectionStatus::Pending,
        MycConnectionAdmissionPolicy::Denied => return Err(ConnectionOperationError::Binding),
    };
    let result = sqlx::query(INSERT_CONNECTION_SQL)
        .bind(id.as_bytes().as_slice())
        .bind(request.nonce.0.as_slice())
        .bind(request.client_public_key.as_hex())
        .bind(request.requested_permissions.digest().as_slice())
        .bind(request.policy_generation.sqlite_value())
        .bind(status.as_str())
        .bind(request.observed_at.sqlite_value())
        .bind(request.observed_at.sqlite_value())
        .bind(
            request
                .authorized_until
                .map(MycConnectionTimeUnixMs::sqlite_value),
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())?;
    insert_permissions(transaction, id, "requested", &request.requested_permissions).await?;
    if status == MycConnectionStatus::Active {
        insert_permissions(transaction, id, "granted", &request.requested_permissions).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_decision(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
    connection_id: Option<MycConnectionId>,
    decision: MycConnectionDecision,
    reason: &'static str,
    policy_generation: MycConnectionPolicyGeneration,
    permissions_digest: &[u8; 32],
    challenge_id: Option<MycAuthorizationChallengeId>,
    decided_at: MycConnectionTimeUnixMs,
) -> Result<(), ConnectionOperationError> {
    let result = sqlx::query(INSERT_DECISION_SQL)
        .bind(operation_id.as_bytes().as_slice())
        .bind(connection_id.map(|value| value.0.to_vec()))
        .bind(decision.as_str())
        .bind(reason)
        .bind(policy_generation.sqlite_value())
        .bind(permissions_digest.as_slice())
        .bind(challenge_id.map(|value| value.0.to_vec()))
        .bind(decided_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())
}

async fn decide_connection(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
    connection_id: MycConnectionId,
    policy_generation: MycConnectionPolicyGeneration,
    observed_at: MycConnectionTimeUnixMs,
    audit_correlation: MycAuditCorrelationId,
    decision: MycConnectionOperatorDecision,
) -> Result<MycConnectionRecord, ConnectionOperationError> {
    let existing_decision = read_decision(transaction, operation_id)
        .await?
        .ok_or(ConnectionOperationError::Binding)?;
    if existing_decision.connection_id != Some(connection_id)
        || existing_decision.policy_generation != policy_generation
    {
        return Err(ConnectionOperationError::Binding);
    }
    let connection = read_connection(transaction, connection_id).await?;
    if connection.policy_generation != policy_generation {
        return Err(ConnectionOperationError::Binding);
    }

    let (audit_outcome, audit_reason) = match decision {
        MycConnectionOperatorDecision::Approve {
            granted_permissions,
            authorized_until,
        } => {
            if !granted_permissions.is_subset_of(&connection.requested_permissions)
                || authorized_until.is_some_and(|until| until <= observed_at)
            {
                return Err(ConnectionOperationError::Binding);
            }
            if connection.status == MycConnectionStatus::Active
                && existing_decision.decision == MycConnectionDecision::Allowed
            {
                let replay = (connection.granted_permissions == granted_permissions
                    && connection.authorized_until == authorized_until)
                    .then_some(connection)
                    .ok_or(ConnectionOperationError::Binding)?;
                record_operator_audit(
                    transaction,
                    audit_correlation,
                    replay.updated_at,
                    MycAuditOutcome::Succeeded,
                    MycAuditReasonCode::OperatorApproved,
                )
                .await?;
                return Ok(replay);
            }
            if connection.status != MycConnectionStatus::Pending
                || existing_decision.decision != MycConnectionDecision::PendingApproval
                || observed_at < connection.updated_at
            {
                return Err(ConnectionOperationError::Binding);
            }
            insert_permissions(transaction, connection_id, "granted", &granted_permissions).await?;
            let result = sqlx::query(APPROVE_CONNECTION_SQL)
                .bind(observed_at.sqlite_value())
                .bind(authorized_until.map(MycConnectionTimeUnixMs::sqlite_value))
                .bind(connection_id.as_bytes().as_slice())
                .bind(policy_generation.sqlite_value())
                .execute(&mut *transaction)
                .await
                .map_err(|_| ConnectionOperationError::Storage)?;
            require_one(result.rows_affected())?;
            update_approval_decision(
                transaction,
                operation_id,
                connection_id,
                policy_generation,
                observed_at,
                MycConnectionDecision::Allowed,
                "operator_approved",
            )
            .await?;
            (
                MycAuditOutcome::Succeeded,
                MycAuditReasonCode::OperatorApproved,
            )
        }
        MycConnectionOperatorDecision::Deny => {
            if connection.status == MycConnectionStatus::Denied
                && existing_decision.decision == MycConnectionDecision::Denied
            {
                record_operator_audit(
                    transaction,
                    audit_correlation,
                    connection.updated_at,
                    MycAuditOutcome::Rejected,
                    MycAuditReasonCode::OperatorDenied,
                )
                .await?;
                return Ok(connection);
            }
            if connection.status != MycConnectionStatus::Pending
                || existing_decision.decision != MycConnectionDecision::PendingApproval
                || observed_at < connection.updated_at
            {
                return Err(ConnectionOperationError::Binding);
            }
            let result = sqlx::query(DENY_CONNECTION_SQL)
                .bind(observed_at.sqlite_value())
                .bind(connection_id.as_bytes().as_slice())
                .bind(policy_generation.sqlite_value())
                .execute(&mut *transaction)
                .await
                .map_err(|_| ConnectionOperationError::Storage)?;
            require_one(result.rows_affected())?;
            update_approval_decision(
                transaction,
                operation_id,
                connection_id,
                policy_generation,
                observed_at,
                MycConnectionDecision::Denied,
                "operator_denied",
            )
            .await?;
            (
                MycAuditOutcome::Rejected,
                MycAuditReasonCode::OperatorDenied,
            )
        }
    };
    let record = read_connection(transaction, connection_id).await?;
    record_operator_audit(
        transaction,
        audit_correlation,
        observed_at,
        audit_outcome,
        audit_reason,
    )
    .await?;
    Ok(record)
}

async fn record_operator_audit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    correlation: MycAuditCorrelationId,
    occurred_at: MycConnectionTimeUnixMs,
    outcome: MycAuditOutcome,
    reason: MycAuditReasonCode,
) -> Result<(), ConnectionOperationError> {
    record_audit(
        transaction,
        AuditEvidence {
            correlation,
            occurred_at,
            operation_id: None,
        },
        MycAuditKind::ConnectionOperatorDecision,
        outcome,
        reason,
    )
    .await
    .map_err(map_governance_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn update_approval_decision(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
    connection_id: MycConnectionId,
    policy_generation: MycConnectionPolicyGeneration,
    observed_at: MycConnectionTimeUnixMs,
    decision: MycConnectionDecision,
    reason: &'static str,
) -> Result<(), ConnectionOperationError> {
    let result = sqlx::query(UPDATE_APPROVAL_DECISION_SQL)
        .bind(decision.as_str())
        .bind(reason)
        .bind(observed_at.sqlite_value())
        .bind(operation_id.as_bytes().as_slice())
        .bind(connection_id.as_bytes().as_slice())
        .bind(policy_generation.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())
}

async fn issue_challenge(
    transaction: &mut ServiceSqliteTransaction<'_>,
    request: &MycAuthorizationChallengeRequest,
    rate_policy: MycRateLimitPolicy,
) -> Result<MycAuthorizationChallengeAdmission, ConnectionOperationError> {
    let binding = read_request_binding(transaction, request.operation_id).await?;
    if binding.method == MycSignerRequestMethod::Connect {
        return Err(ConnectionOperationError::Binding);
    }
    let connection = read_connection(transaction, request.connection_id).await?;
    if connection.client_public_key != binding.client_public_key
        || connection.policy_generation != request.policy_generation
    {
        return Err(ConnectionOperationError::Binding);
    }
    if let Some(existing) = read_challenge(transaction, request.operation_id).await? {
        if existing.connection_id != request.connection_id
            || existing.policy_generation != request.policy_generation
            || existing.url != request.url
            || existing.issued_at != request.issued_at
            || existing.expires_at != request.expires_at
        {
            return Err(ConnectionOperationError::Binding);
        }
        return Ok(MycAuthorizationChallengeAdmission::ExactReplay(existing));
    }
    if request.issued_at < binding.received_at
        || request.issued_at < connection.updated_at
        || connection.status != MycConnectionStatus::Active
        || connection
            .authorized_until
            .is_some_and(|until| until < request.issued_at)
    {
        return Err(ConnectionOperationError::Binding);
    }
    if read_decision(transaction, request.operation_id)
        .await?
        .is_some()
    {
        return Err(ConnectionOperationError::Binding);
    }
    let evidence = AuditEvidence {
        correlation: binding.correlation,
        occurred_at: request.issued_at,
        operation_id: Some(request.operation_id),
    };
    if !govern_rate_attempt(
        transaction,
        rate_policy,
        MycRateLimitClass::ChallengeCreation,
        &[connection_subject(request.connection_id)],
        evidence,
        MycAuditKind::ChallengeCreation,
    )
    .await
    .map_err(map_governance_error)?
    {
        return Ok(MycAuthorizationChallengeAdmission::RateLimited);
    }
    let challenge_id =
        derive_challenge_id(request.operation_id, request.connection_id, &request.nonce);
    let result = sqlx::query(INSERT_CHALLENGE_SQL)
        .bind(challenge_id.as_bytes().as_slice())
        .bind(request.nonce.0.as_slice())
        .bind(request.connection_id.as_bytes().as_slice())
        .bind(request.operation_id.as_bytes().as_slice())
        .bind(request.policy_generation.sqlite_value())
        .bind(request.url.as_str())
        .bind(request.issued_at.sqlite_value())
        .bind(request.expires_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())?;
    insert_decision(
        transaction,
        request.operation_id,
        Some(request.connection_id),
        MycConnectionDecision::Challenged,
        "authorization_challenge_required",
        request.policy_generation,
        connection.requested_permissions.digest(),
        Some(challenge_id),
        request.issued_at,
    )
    .await?;
    let record = read_challenge(transaction, request.operation_id)
        .await?
        .ok_or(ConnectionOperationError::Binding)?;
    record_audit(
        transaction,
        evidence,
        MycAuditKind::ChallengeCreation,
        MycAuditOutcome::Succeeded,
        MycAuditReasonCode::ChallengeRequired,
    )
    .await
    .map_err(map_governance_error)?;
    Ok(MycAuthorizationChallengeAdmission::Created(record))
}

#[allow(clippy::too_many_arguments)]
async fn authorize_challenge(
    transaction: &mut ServiceSqliteTransaction<'_>,
    challenge_id: MycAuthorizationChallengeId,
    connection_id: MycConnectionId,
    operation_id: MycSignerOperationId,
    policy_generation: MycConnectionPolicyGeneration,
    observed_at: MycConnectionTimeUnixMs,
    rate_policy: MycRateLimitPolicy,
) -> Result<MycAuthorizationChallengeAuthorization, ConnectionOperationError> {
    let before = read_challenge(transaction, operation_id)
        .await?
        .ok_or(ConnectionOperationError::Binding)?;
    if before.id != challenge_id
        || before.connection_id != connection_id
        || before.operation_id != operation_id
        || before.policy_generation != policy_generation
    {
        return Err(ConnectionOperationError::Binding);
    }
    let request_binding = read_request_binding(transaction, operation_id).await?;
    let connection = read_connection(transaction, connection_id).await?;
    if request_binding.method == MycSignerRequestMethod::Connect
        || request_binding.client_public_key != connection.client_public_key
        || connection.policy_generation != policy_generation
        || observed_at < before.issued_at
    {
        return Err(ConnectionOperationError::Binding);
    }
    if before.state != MycAuthorizationChallengeState::Pending {
        return Ok(MycAuthorizationChallengeAuthorization::ExactReplay(before));
    }
    let evidence = AuditEvidence {
        correlation: request_binding.correlation,
        occurred_at: observed_at,
        operation_id: Some(operation_id),
    };
    if !govern_rate_attempt(
        transaction,
        rate_policy,
        MycRateLimitClass::ChallengeAuthorization,
        &[connection_subject(connection_id)],
        evidence,
        MycAuditKind::ChallengeAuthorization,
    )
    .await
    .map_err(map_governance_error)?
    {
        return Ok(MycAuthorizationChallengeAuthorization::RateLimited);
    }
    let connection_expired = connection.status != MycConnectionStatus::Active
        || connection
            .authorized_until
            .is_some_and(|until| until < observed_at);
    let expired = observed_at > before.expires_at || connection_expired;
    let (state, decision, reason) = if expired {
        (
            MycAuthorizationChallengeState::Expired,
            MycConnectionDecision::Denied,
            "authorization_challenge_expired",
        )
    } else {
        (
            MycAuthorizationChallengeState::Authorized,
            MycConnectionDecision::Allowed,
            "authorization_challenge_authorized",
        )
    };
    let result = sqlx::query(RESOLVE_CHALLENGE_SQL)
        .bind(state.as_str())
        .bind(observed_at.sqlite_value())
        .bind(challenge_id.as_bytes().as_slice())
        .bind(connection_id.as_bytes().as_slice())
        .bind(operation_id.as_bytes().as_slice())
        .bind(policy_generation.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let result = sqlx::query(UPDATE_CHALLENGE_DECISION_SQL)
        .bind(decision.as_str())
        .bind(reason)
        .bind(observed_at.sqlite_value())
        .bind(operation_id.as_bytes().as_slice())
        .bind(connection_id.as_bytes().as_slice())
        .bind(challenge_id.as_bytes().as_slice())
        .bind(policy_generation.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    require_one(result.rows_affected())?;
    let record = read_challenge(transaction, operation_id)
        .await?
        .ok_or(ConnectionOperationError::Binding)?;
    let (outcome, audit_reason) = match state {
        MycAuthorizationChallengeState::Authorized => (
            MycAuditOutcome::Succeeded,
            MycAuditReasonCode::ChallengeAuthorized,
        ),
        MycAuthorizationChallengeState::Expired => (
            MycAuditOutcome::Rejected,
            MycAuditReasonCode::ChallengeExpired,
        ),
        MycAuthorizationChallengeState::Pending => {
            return Err(ConnectionOperationError::Binding);
        }
    };
    record_audit(
        transaction,
        evidence,
        MycAuditKind::ChallengeAuthorization,
        outcome,
        audit_reason,
    )
    .await
    .map_err(map_governance_error)?;
    Ok(MycAuthorizationChallengeAuthorization::Resolved(record))
}

struct RequestBinding {
    correlation: MycAuditCorrelationId,
    client_public_key: MycNip46ClientPublicKey,
    method: MycSignerRequestMethod,
    received_at: MycConnectionTimeUnixMs,
}

async fn read_request_binding(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
) -> Result<RequestBinding, ConnectionOperationError> {
    let rows = sqlx::query(READ_REQUEST_BINDING_SQL)
        .bind(operation_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(ConnectionOperationError::Binding);
    }
    let row = &rows[0];
    let correlation = MycAuditCorrelationId::new(exact_digest(row, "correlation_id")?);
    let client = row
        .try_get::<Option<&str>, _>("client_public_key")
        .map_err(|_| ConnectionOperationError::Binding)?
        .ok_or(ConnectionOperationError::Binding)
        .and_then(|value| {
            MycNip46ClientPublicKey::new(value).map_err(|_| ConnectionOperationError::Binding)
        })?;
    let method = row
        .try_get::<Option<&str>, _>("method")
        .map_err(|_| ConnectionOperationError::Binding)?
        .and_then(MycSignerRequestMethod::parse)
        .ok_or(ConnectionOperationError::Binding)?;
    Ok(RequestBinding {
        correlation,
        client_public_key: client,
        method,
        received_at: time(row, "received_at_unix_ms")?,
    })
}

#[derive(Clone, Copy)]
struct PersistedDecision {
    connection_id: Option<MycConnectionId>,
    decision: MycConnectionDecision,
    policy_generation: MycConnectionPolicyGeneration,
    requested_permissions_sha256: [u8; 32],
    challenge_id: Option<MycAuthorizationChallengeId>,
    decided_at: MycConnectionTimeUnixMs,
    admission_policy: Option<MycConnectionAdmissionPolicy>,
}

async fn read_decision(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
) -> Result<Option<PersistedDecision>, ConnectionOperationError> {
    let rows = sqlx::query(READ_DECISION_SQL)
        .bind(operation_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(ConnectionOperationError::Binding);
    }
    rows.first().map(parse_decision).transpose()
}

fn parse_decision(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<PersistedDecision, ConnectionOperationError> {
    let connection_id =
        optional_digest(row, "connection_id", "connection_id_type")?.map(MycConnectionId);
    let challenge_id =
        optional_digest(row, "challenge_id", "challenge_id_type")?.map(MycAuthorizationChallengeId);
    let decision = bounded_text(row, "decision").and_then(|value| {
        MycConnectionDecision::parse(value).ok_or(ConnectionOperationError::Binding)
    })?;
    let reason = bounded_text(row, "reason_code")?;
    if !matches!(
        (decision, reason, connection_id, challenge_id),
        (MycConnectionDecision::Denied, "policy_denied", None, None)
            | (
                MycConnectionDecision::PendingApproval,
                "explicit_approval_required",
                Some(_),
                None
            )
            | (
                MycConnectionDecision::Allowed,
                "trusted_client",
                Some(_),
                None
            )
            | (
                MycConnectionDecision::Allowed,
                "operator_approved",
                Some(_),
                None
            )
            | (
                MycConnectionDecision::Denied,
                "operator_denied",
                Some(_),
                None
            )
            | (
                MycConnectionDecision::Challenged,
                "authorization_challenge_required",
                Some(_),
                Some(_)
            )
            | (
                MycConnectionDecision::Allowed,
                "authorization_challenge_authorized",
                Some(_),
                Some(_)
            )
            | (
                MycConnectionDecision::Denied,
                "authorization_challenge_expired",
                Some(_),
                Some(_)
            )
    ) {
        return Err(ConnectionOperationError::Binding);
    }
    let admission_policy = match reason {
        "trusted_client" => Some(MycConnectionAdmissionPolicy::Trusted),
        "explicit_approval_required" | "operator_approved" | "operator_denied" => {
            Some(MycConnectionAdmissionPolicy::ExplicitApproval)
        }
        "policy_denied" => Some(MycConnectionAdmissionPolicy::Denied),
        "authorization_challenge_required"
        | "authorization_challenge_authorized"
        | "authorization_challenge_expired" => None,
        _ => return Err(ConnectionOperationError::Binding),
    };
    Ok(PersistedDecision {
        connection_id,
        decision,
        policy_generation: generation(row, "policy_generation")?,
        requested_permissions_sha256: exact_digest(row, "requested_permissions_sha256")?,
        challenge_id,
        decided_at: time(row, "decided_at_unix_ms")?,
        admission_policy,
    })
}

async fn decision_record(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
    decision: PersistedDecision,
) -> Result<MycConnectionDecisionRecord, ConnectionOperationError> {
    let connection = match decision.connection_id {
        Some(id) => Some(read_connection(transaction, id).await?),
        None => None,
    };
    if connection.as_ref().is_some_and(|value| {
        value.requested_permissions.digest() != &decision.requested_permissions_sha256
    }) || decision.challenge_id.is_some()
    {
        return Err(ConnectionOperationError::Binding);
    }
    let state_matches = match (decision.admission_policy, decision.decision, &connection) {
        (Some(MycConnectionAdmissionPolicy::Denied), MycConnectionDecision::Denied, None) => true,
        (
            Some(MycConnectionAdmissionPolicy::Trusted),
            MycConnectionDecision::Allowed,
            Some(connection),
        ) => matches!(
            connection.status,
            MycConnectionStatus::Active | MycConnectionStatus::Expired
        ),
        (
            Some(MycConnectionAdmissionPolicy::ExplicitApproval),
            MycConnectionDecision::PendingApproval,
            Some(connection),
        ) => connection.status == MycConnectionStatus::Pending,
        (
            Some(MycConnectionAdmissionPolicy::ExplicitApproval),
            MycConnectionDecision::Allowed,
            Some(connection),
        ) => matches!(
            connection.status,
            MycConnectionStatus::Active | MycConnectionStatus::Expired
        ),
        (
            Some(MycConnectionAdmissionPolicy::ExplicitApproval),
            MycConnectionDecision::Denied,
            Some(connection),
        ) => connection.status == MycConnectionStatus::Denied,
        _ => false,
    };
    if !state_matches {
        return Err(ConnectionOperationError::Binding);
    }
    Ok(MycConnectionDecisionRecord {
        operation_id,
        connection,
        decision: decision.decision,
        policy_generation: decision.policy_generation,
        decided_at: decision.decided_at,
    })
}

async fn read_connection(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: MycConnectionId,
) -> Result<MycConnectionRecord, ConnectionOperationError> {
    let rows = sqlx::query(READ_CONNECTION_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(ConnectionOperationError::Binding);
    }
    let row = &rows[0];
    let actual_id = MycConnectionId(exact_digest(row, "connection_id")?);
    let nonce = exact_digest(row, "connection_nonce")?;
    let client_public_key = MycNip46ClientPublicKey::new(bounded_text(row, "client_public_key")?)
        .map_err(|_| ConnectionOperationError::Binding)?;
    let requested_permissions = read_permissions(transaction, id, "requested").await?;
    let granted_permissions = read_permissions(transaction, id, "granted").await?;
    let requested_digest = exact_digest(row, "requested_permissions_sha256")?;
    let policy_generation = generation(row, "policy_generation")?;
    let status = MycConnectionStatus::parse(bounded_text(row, "status")?)
        .ok_or(ConnectionOperationError::Binding)?;
    let created_at = time(row, "created_at_unix_ms")?;
    let updated_at = time(row, "updated_at_unix_ms")?;
    let authorized_until = optional_time(row, "authorized_until_unix_ms", "authorized_until_type")?;
    if actual_id != id
        || derive_connection_id(&client_public_key, &MycConnectionNonce(nonce)) != id
        || requested_permissions.digest() != &requested_digest
        || !granted_permissions.is_subset_of(&requested_permissions)
        || updated_at < created_at
        || (matches!(
            status,
            MycConnectionStatus::Pending | MycConnectionStatus::Denied
        ) && !granted_permissions.permissions.is_empty())
        || (status == MycConnectionStatus::Active
            && authorized_until.is_some_and(|until| until <= updated_at))
        || (matches!(
            status,
            MycConnectionStatus::Denied | MycConnectionStatus::Expired
        ) && authorized_until.is_some())
    {
        return Err(ConnectionOperationError::Binding);
    }
    Ok(MycConnectionRecord {
        id,
        client_public_key,
        requested_permissions,
        granted_permissions,
        policy_generation,
        status,
        created_at,
        updated_at,
        authorized_until,
    })
}

async fn insert_permissions(
    transaction: &mut ServiceSqliteTransaction<'_>,
    connection_id: MycConnectionId,
    scope: &'static str,
    permissions: &MycConnectionPermissionSet,
) -> Result<(), ConnectionOperationError> {
    for permission in permissions.permissions() {
        let result = sqlx::query(INSERT_PERMISSION_SQL)
            .bind(connection_id.as_bytes().as_slice())
            .bind(scope)
            .bind(permission.code())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ConnectionOperationError::Storage)?;
        require_one(result.rows_affected())?;
    }
    Ok(())
}

async fn read_permissions(
    transaction: &mut ServiceSqliteTransaction<'_>,
    connection_id: MycConnectionId,
    scope: &'static str,
) -> Result<MycConnectionPermissionSet, ConnectionOperationError> {
    let rows = sqlx::query(READ_PERMISSIONS_SQL)
        .bind(connection_id.as_bytes().as_slice())
        .bind(scope)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    if rows.len() > MYC_CONNECTION_PERMISSION_MAX_COUNT {
        return Err(ConnectionOperationError::Binding);
    }
    let permissions = rows
        .iter()
        .map(|row| {
            bounded_text(row, "permission_code").and_then(|value| {
                MycConnectionPermission::parse(value).ok_or(ConnectionOperationError::Binding)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    MycConnectionPermissionSet::new(&permissions).map_err(|_| ConnectionOperationError::Binding)
}

async fn read_challenge(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: MycSignerOperationId,
) -> Result<Option<MycAuthorizationChallengeRecord>, ConnectionOperationError> {
    let rows = sqlx::query(READ_CHALLENGE_SQL)
        .bind(operation_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConnectionOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(ConnectionOperationError::Binding);
    }
    rows.first().map(parse_challenge).transpose()
}

fn parse_challenge(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<MycAuthorizationChallengeRecord, ConnectionOperationError> {
    let id = MycAuthorizationChallengeId(exact_digest(row, "challenge_id")?);
    let nonce = exact_digest(row, "challenge_nonce")?;
    let connection_id = MycConnectionId(exact_digest(row, "connection_id")?);
    let operation_id = MycSignerOperationId::from_persisted(exact_digest(row, "operation_id")?);
    let policy_generation = generation(row, "policy_generation")?;
    let url = MycAuthorizationChallengeUrl::new(bounded_text(row, "challenge_url")?)
        .map_err(|_| ConnectionOperationError::Binding)?;
    let state = MycAuthorizationChallengeState::parse(bounded_text(row, "state")?)
        .ok_or(ConnectionOperationError::Binding)?;
    let issued_at = time(row, "issued_at_unix_ms")?;
    let expires_at = time(row, "expires_at_unix_ms")?;
    let resolved_at = optional_time(row, "resolved_at_unix_ms", "resolved_at_type")?;
    if derive_challenge_id(
        operation_id,
        connection_id,
        &MycAuthorizationChallengeNonce(nonce),
    ) != id
        || expires_at <= issued_at
        || (state == MycAuthorizationChallengeState::Pending && resolved_at.is_some())
        || (state != MycAuthorizationChallengeState::Pending
            && resolved_at.is_none_or(|resolved| resolved < issued_at))
    {
        return Err(ConnectionOperationError::Binding);
    }
    Ok(MycAuthorizationChallengeRecord {
        id,
        operation_id,
        connection_id,
        policy_generation,
        url,
        state,
        issued_at,
        expires_at,
        resolved_at,
    })
}

fn permission_digest(permissions: &[MycConnectionPermission]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PERMISSION_SET_DOMAIN);
    hasher.update(
        u64::try_from(permissions.len())
            .expect("bounded permission count")
            .to_be_bytes(),
    );
    for permission in permissions {
        let code = permission.code();
        hasher.update(
            u64::try_from(code.len())
                .expect("bounded permission code")
                .to_be_bytes(),
        );
        hasher.update(code.as_bytes());
    }
    hasher.finalize().into()
}

fn derive_connection_id(
    client: &MycNip46ClientPublicKey,
    nonce: &MycConnectionNonce,
) -> MycConnectionId {
    let mut hasher = Sha256::new();
    hasher.update(CONNECTION_ID_DOMAIN);
    hasher.update(client.as_hex().as_bytes());
    hasher.update(nonce.0);
    MycConnectionId(hasher.finalize().into())
}

fn derive_challenge_id(
    operation_id: MycSignerOperationId,
    connection_id: MycConnectionId,
    nonce: &MycAuthorizationChallengeNonce,
) -> MycAuthorizationChallengeId {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_ID_DOMAIN);
    hasher.update(operation_id.as_bytes());
    hasher.update(connection_id.as_bytes());
    hasher.update(nonce.0);
    MycAuthorizationChallengeId(hasher.finalize().into())
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], ConnectionOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| ConnectionOperationError::Binding)?
        .ok_or(ConnectionOperationError::Binding)?
        .try_into()
        .map_err(|_| ConnectionOperationError::Binding)
}

fn optional_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<[u8; 32]>, ConnectionOperationError> {
    let kind = row
        .try_get::<&str, _>(type_column)
        .map_err(|_| ConnectionOperationError::Binding)?;
    match kind {
        "null" => Ok(None),
        "blob" => exact_digest(row, column).map(Some),
        _ => Err(ConnectionOperationError::Binding),
    }
}

fn bounded_text<'row>(
    row: &'row sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<&'row str, ConnectionOperationError> {
    row.try_get::<Option<&str>, _>(column)
        .map_err(|_| ConnectionOperationError::Binding)?
        .ok_or(ConnectionOperationError::Binding)
}

fn generation(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycConnectionPolicyGeneration, ConnectionOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| ConnectionOperationError::Binding)?;
    MycConnectionPolicyGeneration::new(
        u64::try_from(value).map_err(|_| ConnectionOperationError::Binding)?,
    )
    .map_err(|_| ConnectionOperationError::Binding)
}

fn time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<MycConnectionTimeUnixMs, ConnectionOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| ConnectionOperationError::Binding)?;
    MycConnectionTimeUnixMs::new(
        u64::try_from(value).map_err(|_| ConnectionOperationError::Binding)?,
    )
    .map_err(|_| ConnectionOperationError::Binding)
}

fn optional_time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    type_column: &str,
) -> Result<Option<MycConnectionTimeUnixMs>, ConnectionOperationError> {
    match row
        .try_get::<&str, _>(type_column)
        .map_err(|_| ConnectionOperationError::Binding)?
    {
        "null" => Ok(None),
        "integer" => time(row, column).map(Some),
        _ => Err(ConnectionOperationError::Binding),
    }
}

fn require_one(rows: u64) -> Result<(), ConnectionOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(ConnectionOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<ConnectionOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(ConnectionOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(ConnectionOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
