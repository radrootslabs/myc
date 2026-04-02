use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nostr::PublicKey;
use radroots_nostr_connect::prelude::{
    RadrootsNostrConnectMethod, RadrootsNostrConnectPermission, RadrootsNostrConnectPermissions,
    RadrootsNostrConnectRequest, RadrootsNostrConnectRequestMessage,
};
use radroots_nostr_signer::prelude::{
    RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerConnectionRecord,
    RadrootsNostrSignerManager, RadrootsNostrSignerRequestAuditRecord,
    RadrootsNostrSignerRequestDecision,
};

use crate::config::{MycConnectionApproval, MycPolicyConfig};
use crate::error::MycError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MycConnectDecision {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone)]
pub struct MycPolicyContext {
    default_connect_decision: MycConnectDecision,
    trusted_client_pubkeys: BTreeSet<String>,
    denied_client_pubkeys: BTreeSet<String>,
    permission_ceiling: RadrootsNostrConnectPermissions,
    allowed_sign_event_kinds: BTreeSet<u16>,
    auth_url: Option<String>,
    auth_pending_ttl_secs: u64,
    auth_authorized_ttl_secs: Option<u64>,
    reauth_after_inactivity_secs: Option<u64>,
    connect_rate_limiter: Option<MycPolicyRateLimiter>,
    auth_challenge_rate_limiter: Option<MycPolicyRateLimiter>,
}

#[derive(Debug, Clone)]
struct MycPolicyRateLimiter {
    window_secs: u64,
    max_attempts: usize,
    entries: Arc<Mutex<HashMap<String, VecDeque<u64>>>>,
}

impl MycPolicyContext {
    pub fn from_config(config: &MycPolicyConfig) -> Result<Self, MycError> {
        Ok(Self {
            default_connect_decision: match config.connection_approval {
                MycConnectionApproval::NotRequired => MycConnectDecision::Allow,
                MycConnectionApproval::ExplicitUser => MycConnectDecision::RequireApproval,
                MycConnectionApproval::Deny => MycConnectDecision::Deny,
            },
            trusted_client_pubkeys: normalize_public_key_set(&config.trusted_client_pubkeys)?,
            denied_client_pubkeys: normalize_public_key_set(&config.denied_client_pubkeys)?,
            permission_ceiling: normalize_permissions(config.permission_ceiling.clone()),
            allowed_sign_event_kinds: config.allowed_sign_event_kinds.iter().copied().collect(),
            auth_url: config.auth_url.clone(),
            auth_pending_ttl_secs: config.auth_pending_ttl_secs,
            auth_authorized_ttl_secs: config.auth_authorized_ttl_secs,
            reauth_after_inactivity_secs: config.reauth_after_inactivity_secs,
            connect_rate_limiter: build_rate_limiter(
                config.connect_rate_limit_window_secs,
                config.connect_rate_limit_max_attempts,
            ),
            auth_challenge_rate_limiter: build_rate_limiter(
                config.auth_challenge_rate_limit_window_secs,
                config.auth_challenge_rate_limit_max_attempts,
            ),
        })
    }

    pub fn default_approval_requirement(&self) -> RadrootsNostrSignerApprovalRequirement {
        match self.default_connect_decision {
            MycConnectDecision::Allow => RadrootsNostrSignerApprovalRequirement::NotRequired,
            MycConnectDecision::RequireApproval | MycConnectDecision::Deny => {
                RadrootsNostrSignerApprovalRequirement::ExplicitUser
            }
        }
    }

    pub fn connect_decision(&self, client_public_key: &PublicKey) -> MycConnectDecision {
        let client_public_key_hex = client_public_key.to_hex();
        if self.denied_client_pubkeys.contains(&client_public_key_hex) {
            return MycConnectDecision::Deny;
        }
        if self.trusted_client_pubkeys.contains(&client_public_key_hex) {
            return MycConnectDecision::Allow;
        }
        self.default_connect_decision
    }

    pub fn approval_requirement_for_client(
        &self,
        client_public_key: &PublicKey,
    ) -> Option<RadrootsNostrSignerApprovalRequirement> {
        match self.connect_decision(client_public_key) {
            MycConnectDecision::Allow => Some(RadrootsNostrSignerApprovalRequirement::NotRequired),
            MycConnectDecision::RequireApproval => {
                Some(RadrootsNostrSignerApprovalRequirement::ExplicitUser)
            }
            MycConnectDecision::Deny => None,
        }
    }

    pub fn connect_rate_limit_denied_reason(
        &self,
        client_public_key: &PublicKey,
    ) -> Option<String> {
        self.connect_rate_limiter.as_ref().and_then(|limiter| {
            limiter
                .check_and_record(&client_public_key.to_hex())
                .map(|retry_after_secs| throttled_reason("connect attempts", retry_after_secs))
        })
    }

    pub fn auto_granted_permissions(
        &self,
        requested_permissions: &RadrootsNostrConnectPermissions,
    ) -> RadrootsNostrConnectPermissions {
        self.filtered_requested_permissions(requested_permissions)
    }

    pub fn filtered_requested_permissions(
        &self,
        requested_permissions: &RadrootsNostrConnectPermissions,
    ) -> RadrootsNostrConnectPermissions {
        let mut filtered = Vec::new();

        for permission in requested_permissions.as_slice() {
            if permission.method == RadrootsNostrConnectMethod::SignEvent
                && permission.parameter.is_none()
                && !self.allowed_sign_event_kinds.is_empty()
            {
                for kind in &self.allowed_sign_event_kinds {
                    let candidate = RadrootsNostrConnectPermission::with_parameter(
                        RadrootsNostrConnectMethod::SignEvent,
                        format!("kind:{kind}"),
                    );
                    if self.permission_within_policy(&candidate) {
                        filtered.push(candidate);
                    }
                }
                continue;
            }

            if self.permission_within_policy(permission) {
                filtered.push(permission.clone());
            }
        }

        normalize_permissions(filtered.into())
    }

    pub fn validate_operator_grants(
        &self,
        granted_permissions: RadrootsNostrConnectPermissions,
    ) -> Result<RadrootsNostrConnectPermissions, MycError> {
        let granted_permissions = normalize_permissions(granted_permissions);
        let invalid_permissions = granted_permissions
            .as_slice()
            .iter()
            .filter(|permission| !self.permission_within_policy(permission))
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        if invalid_permissions.is_empty() {
            Ok(granted_permissions)
        } else {
            Err(MycError::InvalidOperation(format!(
                "granted permissions exceed the configured policy ceiling: {}",
                invalid_permissions.join(", ")
            )))
        }
    }

    pub fn prepare_request(
        &self,
        manager: &RadrootsNostrSignerManager,
        connection: &RadrootsNostrSignerConnectionRecord,
        request_message: &RadrootsNostrConnectRequestMessage,
    ) -> Result<Option<String>, MycError> {
        if self.client_is_denied(&connection.client_public_key) {
            return Ok(Some("client public key denied by policy".to_owned()));
        }

        if let Some(reason) = self.request_denied_reason(&request_message.request) {
            return Ok(Some(reason));
        }

        if connection.auth_state
            == radroots_nostr_signer::prelude::RadrootsNostrSignerAuthState::Pending
            && self.auth_challenge_is_expired(connection)
        {
            if self.request_uses_automatic_auth(connection, &request_message.request) {
                if let Some(reason) =
                    self.require_auth_challenge_with_guardrails(manager, connection)?
                {
                    return Ok(Some(reason));
                }
            } else {
                return Ok(Some(
                    "auth challenge expired; require a new auth challenge".to_owned(),
                ));
            }
        } else if self.should_require_fresh_auth(connection, &request_message.request) {
            if let Some(reason) =
                self.require_auth_challenge_with_guardrails(manager, connection)?
            {
                return Ok(Some(reason));
            }
        }

        Ok(None)
    }

    pub fn ensure_authorize_auth_challenge_allowed(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
    ) -> Result<(), MycError> {
        if connection.auth_state
            == radroots_nostr_signer::prelude::RadrootsNostrSignerAuthState::Pending
            && self.auth_challenge_is_expired(connection)
        {
            return Err(MycError::InvalidOperation(
                "auth challenge expired; require a new auth challenge".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn cleanup_stale_sessions(
        &self,
        manager: &RadrootsNostrSignerManager,
    ) -> Result<usize, MycError> {
        let mut cleaned = 0usize;
        for connection in manager.list_connections()? {
            if !self.stale_session_requires_cleanup(&connection) {
                continue;
            }
            self.require_auth_challenge(manager, &connection)?;
            cleaned += 1;
        }
        Ok(cleaned)
    }

    pub fn record_policy_denied_request(
        &self,
        manager: &RadrootsNostrSignerManager,
        connection: &RadrootsNostrSignerConnectionRecord,
        request_message: &RadrootsNostrConnectRequestMessage,
        reason: impl Into<String>,
    ) -> Result<RadrootsNostrSignerRequestAuditRecord, MycError> {
        let reason = reason.into();
        Ok(manager.record_request(
            &connection.connection_id,
            &request_message.id,
            request_message.request.method(),
            RadrootsNostrSignerRequestDecision::Denied,
            Some(reason.clone()),
        )?)
    }

    fn client_is_denied(&self, client_public_key: &PublicKey) -> bool {
        self.denied_client_pubkeys
            .contains(&client_public_key.to_hex())
    }

    fn client_is_trusted(&self, client_public_key: &PublicKey) -> bool {
        self.trusted_client_pubkeys
            .contains(&client_public_key.to_hex())
    }

    fn permission_within_policy(&self, permission: &RadrootsNostrConnectPermission) -> bool {
        if permission.method == RadrootsNostrConnectMethod::SignEvent
            && !self.allowed_sign_event_kinds.is_empty()
        {
            let Some(kind) = permission
                .parameter
                .as_deref()
                .and_then(parse_sign_event_kind_parameter)
            else {
                return false;
            };
            if !self.allowed_sign_event_kinds.contains(&kind) {
                return false;
            }
        }

        if self.permission_ceiling.is_empty() {
            return true;
        }

        self.permission_ceiling
            .as_slice()
            .iter()
            .any(|ceiling| permission_within_ceiling(permission, ceiling))
    }

    fn request_denied_reason(&self, request: &RadrootsNostrConnectRequest) -> Option<String> {
        if self.permission_ceiling.is_empty()
            && (self.allowed_sign_event_kinds.is_empty()
                || !matches!(request, RadrootsNostrConnectRequest::SignEvent(_)))
        {
            return None;
        }

        let required_permission = required_permission_for_request(request)?;
        if self.permission_within_policy(&required_permission) {
            None
        } else {
            Some(format!(
                "request {} is outside the configured policy ceiling",
                request.method()
            ))
        }
    }

    fn request_uses_automatic_auth(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
        request: &RadrootsNostrConnectRequest,
    ) -> bool {
        self.automatic_auth_enabled_for_connection(connection) && request_requires_auth(request)
    }

    fn should_require_fresh_auth(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
        request: &RadrootsNostrConnectRequest,
    ) -> bool {
        if !self.request_uses_automatic_auth(connection, request) {
            return false;
        }

        if connection.auth_state
            == radroots_nostr_signer::prelude::RadrootsNostrSignerAuthState::Pending
        {
            return false;
        }

        let Some(last_authenticated_at_unix) = connection.last_authenticated_at_unix else {
            return true;
        };
        let now_unix = now_unix_secs();

        if self
            .auth_authorized_ttl_secs
            .is_some_and(|ttl| now_unix > last_authenticated_at_unix.saturating_add(ttl))
        {
            return true;
        }

        self.reauth_after_inactivity_secs.is_some_and(|ttl| {
            let Some(last_request_at_unix) = connection.last_request_at_unix else {
                return false;
            };
            now_unix > last_request_at_unix.saturating_add(ttl)
        })
    }

    fn auth_challenge_is_expired(&self, connection: &RadrootsNostrSignerConnectionRecord) -> bool {
        let Some(auth_challenge) = connection.auth_challenge.as_ref() else {
            return false;
        };
        now_unix_secs()
            > auth_challenge
                .required_at_unix
                .saturating_add(self.auth_pending_ttl_secs)
    }

    fn auth_url(&self) -> Result<&str, MycError> {
        self.auth_url.as_deref().ok_or_else(|| {
            MycError::InvalidOperation(
                "automatic auth policy requires policy.auth_url to be configured".to_owned(),
            )
        })
    }

    fn automatic_auth_enabled_for_connection(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
    ) -> bool {
        self.auth_url.is_some() && self.client_is_trusted(&connection.client_public_key)
    }

    fn require_auth_challenge_with_guardrails(
        &self,
        manager: &RadrootsNostrSignerManager,
        connection: &RadrootsNostrSignerConnectionRecord,
    ) -> Result<Option<String>, MycError> {
        if let Some(retry_after_secs) = self
            .auth_challenge_rate_limiter
            .as_ref()
            .and_then(|limiter| limiter.check_and_record(&connection.client_public_key.to_hex()))
        {
            return Ok(Some(throttled_reason(
                "auth challenge issuance",
                retry_after_secs,
            )));
        }
        self.require_auth_challenge(manager, connection)?;
        Ok(None)
    }

    fn require_auth_challenge(
        &self,
        manager: &RadrootsNostrSignerManager,
        connection: &RadrootsNostrSignerConnectionRecord,
    ) -> Result<(), MycError> {
        manager.require_auth_challenge(&connection.connection_id, self.auth_url()?)?;
        Ok(())
    }

    fn stale_session_requires_cleanup(
        &self,
        connection: &RadrootsNostrSignerConnectionRecord,
    ) -> bool {
        if connection.is_terminal()
            || connection.auth_state
                != radroots_nostr_signer::prelude::RadrootsNostrSignerAuthState::Authorized
            || !self.automatic_auth_enabled_for_connection(connection)
        {
            return false;
        }

        let Some(last_authenticated_at_unix) = connection.last_authenticated_at_unix else {
            return true;
        };
        let now_unix = now_unix_secs();

        if self
            .auth_authorized_ttl_secs
            .is_some_and(|ttl| now_unix > last_authenticated_at_unix.saturating_add(ttl))
        {
            return true;
        }

        self.reauth_after_inactivity_secs.is_some_and(|ttl| {
            connection
                .last_request_at_unix
                .is_some_and(|last_request_at_unix| {
                    now_unix > last_request_at_unix.saturating_add(ttl)
                })
        })
    }
}

impl MycPolicyRateLimiter {
    fn check_and_record(&self, key: &str) -> Option<u64> {
        let now_unix = now_unix_secs();
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempts = guard.entry(key.to_owned()).or_default();
        prune_attempts(attempts, now_unix, self.window_secs);
        if attempts.len() >= self.max_attempts {
            return Some(
                attempts
                    .front()
                    .copied()
                    .map(|oldest_attempt_unix| {
                        oldest_attempt_unix
                            .saturating_add(self.window_secs)
                            .saturating_sub(now_unix)
                            .max(1)
                    })
                    .unwrap_or(1),
            );
        }
        attempts.push_back(now_unix);
        None
    }
}

fn normalize_permissions(
    permissions: RadrootsNostrConnectPermissions,
) -> RadrootsNostrConnectPermissions {
    let mut permissions = permissions.into_vec();
    permissions.sort();
    permissions.dedup();
    permissions.into()
}

fn normalize_public_key_set(values: &[String]) -> Result<BTreeSet<String>, MycError> {
    values
        .iter()
        .map(|value| normalize_public_key_hex(value))
        .collect()
}

fn normalize_public_key_hex(value: &str) -> Result<String, MycError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MycError::InvalidConfig(
            "policy client pubkeys must not contain empty values".to_owned(),
        ));
    }
    let public_key = PublicKey::parse(trimmed)
        .or_else(|_| PublicKey::from_hex(trimmed))
        .map_err(|_| {
            MycError::InvalidConfig(format!(
                "policy client pubkey `{trimmed}` is not a valid nostr public key"
            ))
        })?;
    Ok(public_key.to_hex())
}

fn required_permission_for_request(
    request: &RadrootsNostrConnectRequest,
) -> Option<RadrootsNostrConnectPermission> {
    match request {
        RadrootsNostrConnectRequest::Connect { .. }
        | RadrootsNostrConnectRequest::GetPublicKey
        | RadrootsNostrConnectRequest::GetSessionCapability
        | RadrootsNostrConnectRequest::Ping => None,
        RadrootsNostrConnectRequest::SignEvent(unsigned_event) => {
            Some(RadrootsNostrConnectPermission::with_parameter(
                RadrootsNostrConnectMethod::SignEvent,
                format!("kind:{}", unsigned_event.kind.as_u16()),
            ))
        }
        RadrootsNostrConnectRequest::Nip04Encrypt { .. } => Some(
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Encrypt),
        ),
        RadrootsNostrConnectRequest::Nip04Decrypt { .. } => Some(
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Decrypt),
        ),
        RadrootsNostrConnectRequest::Nip44Encrypt { .. } => Some(
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip44Encrypt),
        ),
        RadrootsNostrConnectRequest::Nip44Decrypt { .. } => Some(
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip44Decrypt),
        ),
        RadrootsNostrConnectRequest::SwitchRelays => Some(RadrootsNostrConnectPermission::new(
            RadrootsNostrConnectMethod::SwitchRelays,
        )),
        RadrootsNostrConnectRequest::Custom { method, .. } => {
            Some(RadrootsNostrConnectPermission::new(method.clone()))
        }
    }
}

fn permission_within_ceiling(
    permission: &RadrootsNostrConnectPermission,
    ceiling: &RadrootsNostrConnectPermission,
) -> bool {
    if permission.method != ceiling.method {
        return false;
    }

    match (
        &permission.method,
        permission.parameter.as_deref(),
        ceiling.parameter.as_deref(),
    ) {
        (RadrootsNostrConnectMethod::SignEvent, _, None) => true,
        (RadrootsNostrConnectMethod::SignEvent, Some(parameter), Some(ceiling_parameter)) => {
            sign_event_parameter_eq(parameter, ceiling_parameter)
        }
        (RadrootsNostrConnectMethod::SignEvent, None, Some(_)) => false,
        (_, _, None) => true,
        (_, Some(parameter), Some(ceiling_parameter)) => parameter == ceiling_parameter,
        (_, None, Some(_)) => false,
    }
}

fn sign_event_parameter_eq(left: &str, right: &str) -> bool {
    parse_sign_event_kind_parameter(left) == parse_sign_event_kind_parameter(right)
}

fn parse_sign_event_kind_parameter(value: &str) -> Option<u16> {
    value
        .strip_prefix("kind:")
        .unwrap_or(value)
        .parse::<u16>()
        .ok()
}

fn request_requires_auth(request: &RadrootsNostrConnectRequest) -> bool {
    !matches!(
        request,
        RadrootsNostrConnectRequest::Connect { .. }
            | RadrootsNostrConnectRequest::GetPublicKey
            | RadrootsNostrConnectRequest::GetSessionCapability
            | RadrootsNostrConnectRequest::Ping
    )
}

fn build_rate_limiter(
    window_secs: Option<u64>,
    max_attempts: Option<usize>,
) -> Option<MycPolicyRateLimiter> {
    match (window_secs, max_attempts) {
        (Some(window_secs), Some(max_attempts)) => Some(MycPolicyRateLimiter {
            window_secs,
            max_attempts,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }),
        _ => None,
    }
}

fn prune_attempts(attempts: &mut VecDeque<u64>, now_unix: u64, window_secs: u64) {
    while attempts
        .front()
        .copied()
        .is_some_and(|attempt_unix| now_unix > attempt_unix.saturating_add(window_secs))
    {
        let _ = attempts.pop_front();
    }
}

fn throttled_reason(label: &str, retry_after_secs: u64) -> String {
    format!("{label} throttled by policy; retry after {retry_after_secs}s")
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{MycConnectDecision, MycPolicyContext};
    use crate::config::{MycConnectionApproval, MycPolicyConfig};
    use nostr::PublicKey;
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_connect::prelude::{
        RadrootsNostrConnectMethod, RadrootsNostrConnectPermission,
        RadrootsNostrConnectPermissions, RadrootsNostrConnectRequest,
        RadrootsNostrConnectRequestMessage,
    };
    use radroots_nostr_signer::prelude::{
        RadrootsNostrSignerApprovalRequirement, RadrootsNostrSignerAuthState,
        RadrootsNostrSignerConnectionDraft, RadrootsNostrSignerManager,
    };
    use serde_json::json;
    use std::thread;
    use std::time::Duration;

    fn public_key(hex: &str) -> PublicKey {
        PublicKey::parse(hex).expect("public key")
    }

    fn identity(secret_key: &str) -> RadrootsIdentity {
        RadrootsIdentity::from_secret_key_str(secret_key).expect("identity")
    }

    fn in_memory_manager() -> RadrootsNostrSignerManager {
        let manager = RadrootsNostrSignerManager::new_in_memory();
        manager
            .set_signer_identity(
                identity("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .to_public(),
            )
            .expect("set signer identity");
        manager
    }

    fn register_connection(
        manager: &RadrootsNostrSignerManager,
        client_public_key: PublicKey,
    ) -> radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionRecord {
        manager
            .register_connection(
                RadrootsNostrSignerConnectionDraft::new(
                    client_public_key,
                    identity("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                        .to_public(),
                )
                .with_requested_permissions(
                    vec![RadrootsNostrConnectPermission::with_parameter(
                        RadrootsNostrConnectMethod::SignEvent,
                        "kind:1",
                    )]
                    .into(),
                )
                .with_approval_requirement(RadrootsNostrSignerApprovalRequirement::NotRequired),
            )
            .expect("register connection")
    }

    fn unsigned_event(kind: u16) -> nostr::UnsignedEvent {
        serde_json::from_value(json!({
            "pubkey": public_key("1111111111111111111111111111111111111111111111111111111111111111").to_hex(),
            "created_at": 1,
            "kind": kind,
            "tags": [],
            "content": "hello"
        }))
        .expect("unsigned event")
    }

    #[test]
    fn connect_decision_prefers_deny_then_trust_then_default() {
        let mut config = MycPolicyConfig::default();
        config.connection_approval = MycConnectionApproval::ExplicitUser;
        config.trusted_client_pubkeys =
            vec!["2222222222222222222222222222222222222222222222222222222222222222".to_owned()];
        config.denied_client_pubkeys =
            vec!["3333333333333333333333333333333333333333333333333333333333333333".to_owned()];
        let policy = MycPolicyContext::from_config(&config).expect("policy");

        assert_eq!(
            policy.connect_decision(&public_key(
                "2222222222222222222222222222222222222222222222222222222222222222"
            )),
            MycConnectDecision::Allow
        );
        assert_eq!(
            policy.connect_decision(&public_key(
                "3333333333333333333333333333333333333333333333333333333333333333"
            )),
            MycConnectDecision::Deny
        );
        assert_eq!(
            policy.connect_decision(&public_key(
                "4444444444444444444444444444444444444444444444444444444444444444"
            )),
            MycConnectDecision::RequireApproval
        );
    }

    #[test]
    fn auto_granted_permissions_apply_policy_ceiling_and_kind_limits() {
        let mut config = MycPolicyConfig::default();
        config.permission_ceiling = vec![
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Encrypt),
            RadrootsNostrConnectPermission::with_parameter(
                RadrootsNostrConnectMethod::SignEvent,
                "kind:1",
            ),
        ]
        .into();
        config.allowed_sign_event_kinds = vec![1];
        let policy = MycPolicyContext::from_config(&config).expect("policy");

        let requested_permissions: RadrootsNostrConnectPermissions = vec![
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::Nip04Encrypt),
            RadrootsNostrConnectPermission::new(RadrootsNostrConnectMethod::SignEvent),
            RadrootsNostrConnectPermission::with_parameter(
                RadrootsNostrConnectMethod::SignEvent,
                "kind:2",
            ),
        ]
        .into();
        let filtered = policy.auto_granted_permissions(&requested_permissions);

        assert_eq!(filtered.to_string(), "sign_event:kind:1,nip04_encrypt");
    }

    #[test]
    fn request_denied_reason_applies_sign_event_kind_limits() {
        let mut config = MycPolicyConfig::default();
        config.allowed_sign_event_kinds = vec![1];
        let policy = MycPolicyContext::from_config(&config).expect("policy");
        let manager = in_memory_manager();
        let connection = register_connection(
            &manager,
            public_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );

        let denied = policy
            .prepare_request(
                &manager,
                &connection,
                &RadrootsNostrConnectRequestMessage::new(
                    "request-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(2)),
                ),
            )
            .expect("prepare request");

        assert_eq!(
            denied,
            Some("request sign_event is outside the configured policy ceiling".to_owned())
        );
    }

    #[test]
    fn validate_operator_grants_rejects_out_of_policy_permissions() {
        let mut config = MycPolicyConfig::default();
        config.permission_ceiling =
            RadrootsNostrConnectPermissions::from(vec![RadrootsNostrConnectPermission::new(
                RadrootsNostrConnectMethod::Nip04Encrypt,
            )]);
        let policy = MycPolicyContext::from_config(&config).expect("policy");

        let error = policy
            .validate_operator_grants(
                vec![RadrootsNostrConnectPermission::new(
                    RadrootsNostrConnectMethod::Nip44Encrypt,
                )]
                .into(),
            )
            .expect_err("grant outside ceiling");
        assert!(
            error
                .to_string()
                .contains("granted permissions exceed the configured policy ceiling")
        );
    }

    #[test]
    fn prepare_request_requires_fresh_auth_after_authorized_ttl() {
        let client_public_key =
            public_key("2222222222222222222222222222222222222222222222222222222222222222");
        let mut config = MycPolicyConfig::default();
        config.trusted_client_pubkeys = vec![client_public_key.to_hex()];
        config.auth_url = Some("https://auth.example".to_owned());
        config.auth_authorized_ttl_secs = Some(1);
        let policy = MycPolicyContext::from_config(&config).expect("policy");
        let manager = in_memory_manager();
        let connection = register_connection(&manager, client_public_key);

        manager
            .require_auth_challenge(&connection.connection_id, "https://auth.example")
            .expect("require auth challenge");
        manager
            .authorize_auth_challenge(&connection.connection_id)
            .expect("authorize auth challenge");
        thread::sleep(Duration::from_secs(2));

        let connection = manager
            .get_connection(&connection.connection_id)
            .expect("connection lookup")
            .expect("connection");
        let denied = policy
            .prepare_request(
                &manager,
                &connection,
                &RadrootsNostrConnectRequestMessage::new(
                    "request-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(1)),
                ),
            )
            .expect("prepare request");

        assert_eq!(denied, None);
        let updated_connection = manager
            .get_connection(&connection.connection_id)
            .expect("connection lookup")
            .expect("connection");
        assert_eq!(
            updated_connection.auth_state,
            RadrootsNostrSignerAuthState::Pending
        );
        assert_eq!(
            updated_connection
                .auth_challenge
                .expect("auth challenge")
                .auth_url,
            "https://auth.example/"
        );
    }

    #[test]
    fn prepare_request_requires_fresh_auth_after_inactivity() {
        let client_public_key =
            public_key("2323232323232323232323232323232323232323232323232323232323232323");
        let mut config = MycPolicyConfig::default();
        config.trusted_client_pubkeys = vec![client_public_key.to_hex()];
        config.auth_url = Some("https://auth.example".to_owned());
        config.reauth_after_inactivity_secs = Some(1);
        let policy = MycPolicyContext::from_config(&config).expect("policy");
        let manager = in_memory_manager();
        let connection = register_connection(&manager, client_public_key);

        manager
            .require_auth_challenge(&connection.connection_id, "https://auth.example")
            .expect("require auth challenge");
        manager
            .authorize_auth_challenge(&connection.connection_id)
            .expect("authorize auth challenge");
        manager
            .record_request(
                &connection.connection_id,
                "request-0",
                RadrootsNostrConnectMethod::SignEvent,
                radroots_nostr_signer::prelude::RadrootsNostrSignerRequestDecision::Allowed,
                None,
            )
            .expect("record request");
        thread::sleep(Duration::from_secs(2));

        let connection = manager
            .get_connection(&connection.connection_id)
            .expect("connection lookup")
            .expect("connection");
        let denied = policy
            .prepare_request(
                &manager,
                &connection,
                &RadrootsNostrConnectRequestMessage::new(
                    "request-1",
                    RadrootsNostrConnectRequest::SignEvent(unsigned_event(1)),
                ),
            )
            .expect("prepare request");

        assert_eq!(denied, None);
        let updated_connection = manager
            .get_connection(&connection.connection_id)
            .expect("connection lookup")
            .expect("connection");
        assert_eq!(
            updated_connection.auth_state,
            RadrootsNostrSignerAuthState::Pending
        );
    }
}
