//! Configuration-bound NIP-46 connection and challenge policy.

use serde_json::Value;

use crate::{
    MycAuthorizationChallengeRecord, MycAuthorizationChallengeRequest,
    MycAuthorizationChallengeState, MycAuthorizationChallengeUrl, MycConnectionAdmissionPolicy,
    MycConnectionAdmissionRequest, MycConnectionOperatorDecision, MycConnectionPermission,
    MycConnectionPermissionSet, MycConnectionTimeUnixMs, MycNip46ClientPublicKey,
};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MycConnectionPolicies {
    trusted_clients: Box<[MycNip46ClientPublicKey]>,
    denied_clients: Box<[MycNip46ClientPublicKey]>,
    permission_ceiling: MycConnectionPermissionSet,
    challenge: Option<MycChallengePolicy>,
    retention: MycAuthorizationRetentionPolicy,
}

#[derive(Clone, PartialEq, Eq)]
struct MycChallengePolicy {
    url: MycAuthorizationChallengeUrl,
    pending_lifetime_ms: u64,
    authorized_lifetime_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct MycAuthorizationRetentionPolicy {
    terminal_connections_ms: u64,
    terminal_challenges_ms: u64,
    request_dedup_ms: u64,
    completed_outbox_ms: u64,
}

impl MycConnectionPolicies {
    pub(crate) fn from_normalized(document: &Value) -> Result<Self, ()> {
        let invalid = || ();
        let strings = |pointer: &str| {
            document
                .pointer(pointer)
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<Result<Vec<_>, _>>()
        };
        let clients = |pointer: &str| {
            strings(pointer)?
                .into_iter()
                .map(|value| MycNip46ClientPublicKey::new(value).map_err(|_| invalid()))
                .collect::<Result<Vec<_>, _>>()
                .map(Vec::into_boxed_slice)
        };
        let trusted_clients = clients("/policy/trusted_clients")?;
        let denied_clients = clients("/policy/denied_clients")?;
        if trusted_clients
            .iter()
            .any(|trusted| denied_clients.contains(trusted))
        {
            return Err(());
        }
        let permission_ceiling = MycConnectionPermissionSet::new(
            &strings("/policy/permission_ceiling")?
                .into_iter()
                .map(|value| MycConnectionPermission::parse(value).ok_or_else(invalid))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| ())?;
        let integer = |pointer: &str| {
            document
                .pointer(pointer)
                .and_then(Value::as_u64)
                .filter(|value| *value > 0 && i64::try_from(*value).is_ok())
                .ok_or_else(invalid)
        };
        let challenge = document
            .pointer("/policy/challenges/enabled")
            .and_then(Value::as_bool)
            .ok_or_else(invalid)?
            .then(|| {
                let url = document
                    .pointer("/policy/challenges/url")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)
                    .and_then(|value| MycAuthorizationChallengeUrl::new(value).map_err(|_| ()))?;
                let pending_lifetime_ms = integer("/policy/challenges/pending_lifetime_ms")?;
                let authorized_lifetime_ms = integer("/policy/challenges/authorized_lifetime_ms")?;
                if authorized_lifetime_ms < pending_lifetime_ms {
                    return Err(());
                }
                Ok(MycChallengePolicy {
                    url,
                    pending_lifetime_ms,
                    authorized_lifetime_ms,
                })
            })
            .transpose()?;
        let retention = MycAuthorizationRetentionPolicy {
            terminal_connections_ms: integer("/policy/retention/terminal_connections_ms")?,
            terminal_challenges_ms: integer("/policy/retention/terminal_challenges_ms")?,
            request_dedup_ms: integer("/policy/retention/request_dedup_ms")?,
            completed_outbox_ms: integer("/policy/retention/completed_outbox_ms")?,
        };
        Ok(Self {
            trusted_clients,
            denied_clients,
            permission_ceiling,
            challenge,
            retention,
        })
    }

    fn expected_admission(&self, client: &MycNip46ClientPublicKey) -> MycConnectionAdmissionPolicy {
        if self.denied_clients.contains(client) {
            MycConnectionAdmissionPolicy::Denied
        } else if self.trusted_clients.contains(client) {
            MycConnectionAdmissionPolicy::Trusted
        } else {
            MycConnectionAdmissionPolicy::ExplicitApproval
        }
    }

    pub(crate) fn admits_connection_request(
        &self,
        request: &MycConnectionAdmissionRequest,
    ) -> bool {
        let expected = self.expected_admission(request.client_public_key());
        if request.policy() != expected {
            return false;
        }
        if expected == MycConnectionAdmissionPolicy::Denied {
            return true;
        }
        if !request
            .requested_permissions()
            .is_subset_of(&self.permission_ceiling)
        {
            return false;
        }
        match expected {
            MycConnectionAdmissionPolicy::Trusted => {
                self.admits_authorized_until(request.observed_at(), request.authorized_until())
            }
            MycConnectionAdmissionPolicy::ExplicitApproval => request.authorized_until().is_none(),
            MycConnectionAdmissionPolicy::Denied => true,
        }
    }

    pub(crate) fn admits_operator_decision(
        &self,
        observed_at: MycConnectionTimeUnixMs,
        decision: &MycConnectionOperatorDecision,
    ) -> bool {
        match decision {
            MycConnectionOperatorDecision::Approve {
                granted_permissions,
                authorized_until,
            } => {
                granted_permissions.is_subset_of(&self.permission_ceiling)
                    && self.admits_authorized_until(observed_at, *authorized_until)
            }
            MycConnectionOperatorDecision::Deny => true,
        }
    }

    pub(crate) fn admits_challenge_request(
        &self,
        request: &MycAuthorizationChallengeRequest,
    ) -> bool {
        let Some(policy) = &self.challenge else {
            return false;
        };
        request.url() == &policy.url
            && request
                .expires_at()
                .get()
                .checked_sub(request.issued_at().get())
                .is_some_and(|lifetime| lifetime <= policy.pending_lifetime_ms)
    }

    pub(crate) fn challenge_is_current(
        &self,
        record: &MycAuthorizationChallengeRecord,
        observed_at: MycConnectionTimeUnixMs,
    ) -> bool {
        let Some(policy) = &self.challenge else {
            return false;
        };
        record.state() == MycAuthorizationChallengeState::Authorized
            && record.resolved_at().is_some_and(|resolved| {
                observed_at >= resolved
                    && observed_at
                        .get()
                        .checked_sub(resolved.get())
                        .is_some_and(|age| age <= policy.authorized_lifetime_ms)
            })
    }

    fn admits_authorized_until(
        &self,
        observed_at: MycConnectionTimeUnixMs,
        authorized_until: Option<MycConnectionTimeUnixMs>,
    ) -> bool {
        match (&self.challenge, authorized_until) {
            (None, None) => true,
            (Some(policy), Some(until)) => until
                .get()
                .checked_sub(observed_at.get())
                .is_some_and(|lifetime| lifetime > 0 && lifetime <= policy.authorized_lifetime_ms),
            _ => false,
        }
    }

    pub(crate) const fn retention_is_bounded(&self) -> bool {
        self.retention.terminal_connections_ms > 0
            && self.retention.terminal_challenges_ms > 0
            && self.retention.request_dedup_ms > 0
            && self.retention.completed_outbox_ms > 0
    }
}
