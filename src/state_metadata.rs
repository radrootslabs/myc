//! Immutable Myc-specific identity and policy evidence for one state host.

use core::fmt;
use std::error::Error;

use nostr::PublicKey;
use radroots_service_sqlite::{
    ServiceDatabaseIdentity, ServiceDatabaseMetadata, ServiceSqliteApplicationId,
    ServiceSqlitePaths,
};
use radroots_storage::event::SourceGeneration;
use sha2::{Digest, Sha256};

use crate::nip46_authorization::MycConnectionPolicies;
use crate::state_connection::{
    MycAuthorizationChallengeRecord, MycAuthorizationChallengeRequest,
    MycConnectionAdmissionRequest, MycConnectionOperatorDecision, MycConnectionTimeUnixMs,
};
use crate::state_delivery::{MycDeliveryPolicies, MycDeliveryPolicyMode, MycDeliveryRelayId};
use crate::state_discovery::MycDiscoveryPolicies;
use crate::state_governance::{
    MycGovernancePolicies, MycRateLimitClass, MycRateLimitPolicy, MycRateRelayId,
};
use crate::{
    MYC_CONFIG_SCHEMA_VERSION, MYC_STATE_BASE_SCHEMA_VERSION, MYC_STATE_SCHEMA_VERSION,
    MycBootstrapProfileV1, MycConfigDocumentV1, MycConfigProfile, MycRuntimeContext,
};

const NORMALIZED_CONFIG_DIGEST_DOMAIN: &[u8] = b"radroots.myc.normalized_config.v1\0";

/// SQLite application identity for Myc, encoded as ASCII `RDMY`.
pub const MYC_STATE_APPLICATION_ID: u32 = 0x5244_4d59;

/// Exact version of the governed Myc operator contract.
pub const MYC_OPERATOR_CONTRACT_VERSION: u32 = 1;
/// Exact version of the governed Myc status contract.
pub const MYC_SIGNER_STATUS_CONTRACT_VERSION: u32 = 1;

/// SHA-256 identity of one fully defaulted normalized Myc configuration.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MycNormalizedConfigDigest([u8; 32]);

impl MycNormalizedConfigDigest {
    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MycNormalizedConfigDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycNormalizedConfigDigest([redacted])")
    }
}

/// One validated canonical expected Nostr public identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MycExpectedPublicIdentity(Box<str>);

impl MycExpectedPublicIdentity {
    /// Returns the canonical lowercase 32-byte x-only public key in hex.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    fn from_hex(value: &str) -> Result<Self, MycStateMetadataError> {
        let public_key = PublicKey::from_hex(value)
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Identity))?;
        public_key
            .xonly()
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Identity))?;
        let canonical = public_key.to_hex();
        if canonical != value {
            return Err(MycStateMetadataError::new(
                MycStateMetadataErrorKind::Identity,
            ));
        }
        Ok(Self(canonical.into_boxed_str()))
    }
}

impl fmt::Debug for MycExpectedPublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycExpectedPublicIdentity([redacted])")
    }
}

/// Exact expected identities for every enabled Myc role.
#[derive(Clone, PartialEq, Eq)]
pub struct MycExpectedIdentities {
    transport: MycExpectedPublicIdentity,
    user: MycExpectedPublicIdentity,
    discovery: Option<MycExpectedPublicIdentity>,
}

impl MycExpectedIdentities {
    /// Returns the required transport identity.
    #[must_use]
    pub const fn transport(&self) -> &MycExpectedPublicIdentity {
        &self.transport
    }

    /// Returns the required user identity.
    #[must_use]
    pub const fn user(&self) -> &MycExpectedPublicIdentity {
        &self.user
    }

    /// Returns the discovery identity only when discovery is enabled.
    #[must_use]
    pub const fn discovery(&self) -> Option<&MycExpectedPublicIdentity> {
        self.discovery.as_ref()
    }
}

impl fmt::Debug for MycExpectedIdentities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycExpectedIdentities")
            .field("transport", &"[redacted]")
            .field("user", &"[redacted]")
            .field("discovery", &self.discovery.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Exact contract versions bound to one Myc state-host session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MycStatePolicyVersions {
    configuration: u32,
    state: u32,
    operator: u32,
    status: u32,
}

impl MycStatePolicyVersions {
    const fn governed() -> Self {
        Self {
            configuration: MYC_CONFIG_SCHEMA_VERSION,
            state: MYC_STATE_SCHEMA_VERSION,
            operator: MYC_OPERATOR_CONTRACT_VERSION,
            status: MYC_SIGNER_STATUS_CONTRACT_VERSION,
        }
    }

    #[must_use]
    /// Returns the exact configuration-contract version.
    pub const fn configuration(self) -> u32 {
        self.configuration
    }

    #[must_use]
    /// Returns the exact state-schema version.
    pub const fn state(self) -> u32 {
        self.state
    }

    #[must_use]
    /// Returns the exact operator-contract version.
    pub const fn operator(self) -> u32 {
        self.operator
    }

    #[must_use]
    /// Returns the exact signer-status contract version.
    pub const fn status(self) -> u32 {
        self.status
    }
}

/// Non-forgeable Myc metadata bound to one runtime context and configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct MycStateMetadata {
    paths: ServiceSqlitePaths,
    database: ServiceDatabaseMetadata,
    database_identity: ServiceDatabaseIdentity,
    configuration: MycNormalizedConfigDigest,
    identities: MycExpectedIdentities,
    governance: MycGovernancePolicies,
    authorization: MycConnectionPolicies,
    delivery: MycDeliveryPolicies,
    discovery: Option<MycDiscoveryPolicies>,
    policy_versions: MycStatePolicyVersions,
}

impl MycStateMetadata {
    /// Derives all state evidence from one sealed runtime context, one admitted
    /// normalized configuration, and caller-injected generation/time evidence.
    pub fn new(
        runtime: &MycRuntimeContext,
        configuration: &MycConfigDocumentV1,
        source_generation: SourceGeneration,
        created_at_unix_ms: u64,
    ) -> Result<Self, MycStateMetadataError> {
        require_profile_binding(runtime.profile(), configuration.profile())?;
        let paths = ServiceSqlitePaths::from_runtime_context(runtime.context())
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Paths))?;
        let application_id = ServiceSqliteApplicationId::new(MYC_STATE_APPLICATION_ID)
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?;
        let state_schema_version = core::num::NonZeroU32::new(MYC_STATE_BASE_SCHEMA_VERSION)
            .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?;
        let database = ServiceDatabaseMetadata::new(
            &paths,
            source_generation,
            state_schema_version,
            created_at_unix_ms,
            application_id,
        )
        .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Database))?;
        let supported_state_schema_version =
            core::num::NonZeroU32::new(MYC_STATE_SCHEMA_VERSION)
                .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?;
        let database_identity = ServiceDatabaseIdentity::new(
            &paths,
            source_generation,
            supported_state_schema_version,
            application_id,
        );
        let normalized = configuration.normalized();
        let governance = governance_policies(normalized)?;
        let authorization = MycConnectionPolicies::from_normalized(normalized)
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?;
        if !authorization.retention_is_bounded() {
            return Err(MycStateMetadataError::new(
                MycStateMetadataErrorKind::Invariant,
            ));
        }
        let identities = expected_identities(normalized)?;
        let delivery = delivery_policies(normalized)?;
        let discovery = MycDiscoveryPolicies::from_normalized(normalized, &identities)
            .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?;
        let configuration = normalized_config_digest(configuration.profile(), normalized)?;
        let policy_versions = MycStatePolicyVersions::governed();
        if [
            policy_versions.configuration,
            policy_versions.state,
            policy_versions.operator,
            policy_versions.status,
        ]
        .contains(&0)
        {
            return Err(MycStateMetadataError::new(
                MycStateMetadataErrorKind::Invariant,
            ));
        }
        Ok(Self {
            paths,
            database,
            database_identity,
            configuration,
            identities,
            governance,
            authorization,
            delivery,
            discovery,
            policy_versions,
        })
    }

    /// Returns the immutable shared schema-v1 initialization metadata.
    #[must_use]
    pub const fn initial_database_metadata(&self) -> &ServiceDatabaseMetadata {
        &self.database
    }

    /// Returns the reopen identity with this binary's exact schema ceiling.
    #[must_use]
    pub fn database_identity(&self) -> ServiceDatabaseIdentity {
        self.database_identity.clone()
    }

    /// Returns the normalized configuration digest.
    #[must_use]
    pub const fn configuration_digest(&self) -> MycNormalizedConfigDigest {
        self.configuration
    }

    /// Returns the exact configured identity-role bindings.
    #[must_use]
    pub const fn expected_identities(&self) -> &MycExpectedIdentities {
        &self.identities
    }

    /// Returns the exact governed policy versions.
    #[must_use]
    pub const fn policy_versions(&self) -> MycStatePolicyVersions {
        self.policy_versions
    }

    pub(crate) const fn governance_rate_policy(
        &self,
        class: MycRateLimitClass,
    ) -> MycRateLimitPolicy {
        self.governance.rate_policy(class)
    }

    pub(crate) fn admits_rate_relay(&self, relay: &MycRateRelayId) -> bool {
        self.governance.admits_relay(relay)
    }

    pub(crate) const fn governance_audit_retention_ms(&self) -> u64 {
        self.governance.audit_retention_ms()
    }

    pub(crate) fn admits_connection_request(
        &self,
        request: &MycConnectionAdmissionRequest,
    ) -> bool {
        self.authorization.admits_connection_request(request)
    }

    pub(crate) fn admits_connection_operator_decision(
        &self,
        observed_at: MycConnectionTimeUnixMs,
        decision: &MycConnectionOperatorDecision,
    ) -> bool {
        self.authorization
            .admits_operator_decision(observed_at, decision)
    }

    pub(crate) fn admits_authorization_challenge_request(
        &self,
        request: &MycAuthorizationChallengeRequest,
    ) -> bool {
        self.authorization.admits_challenge_request(request)
    }

    pub(crate) fn authorization_challenge_is_current(
        &self,
        record: &MycAuthorizationChallengeRecord,
        observed_at: MycConnectionTimeUnixMs,
    ) -> bool {
        self.authorization.challenge_is_current(record, observed_at)
    }

    pub(crate) const fn delivery_policies(&self) -> &MycDeliveryPolicies {
        &self.delivery
    }

    pub(crate) const fn discovery_policies(&self) -> Option<&MycDiscoveryPolicies> {
        self.discovery.as_ref()
    }

    pub(crate) fn matches_runtime(&self, runtime: &MycRuntimeContext) -> bool {
        ServiceSqlitePaths::from_runtime_context(runtime.context())
            .is_ok_and(|paths| paths == self.paths)
    }

    pub(crate) fn matches_configuration(
        &self,
        runtime: &MycRuntimeContext,
        configuration: &MycConfigDocumentV1,
    ) -> bool {
        self.matches_runtime(runtime)
            && require_profile_binding(runtime.profile(), configuration.profile()).is_ok()
            && normalized_config_digest(configuration.profile(), configuration.normalized())
                .is_ok_and(|digest| digest == self.configuration)
    }
}

impl fmt::Debug for MycStateMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateMetadata")
            .field("database", &self.database)
            .field("database_identity", &self.database_identity)
            .field("configuration", &self.configuration)
            .field("identities", &self.identities)
            .field("governance", &"[redacted]")
            .field("delivery", &"[redacted]")
            .field("discovery", &self.discovery.as_ref().map(|_| "[redacted]"))
            .field("policy_versions", &self.policy_versions)
            .field("paths", &"[redacted]")
            .finish()
    }
}

/// Stable source-free class for invalid Myc state metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateMetadataErrorKind {
    Profile,
    Paths,
    Configuration,
    Identity,
    Database,
    Invariant,
}

/// Source-free Myc state-metadata construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStateMetadataError {
    kind: MycStateMetadataErrorKind,
}

impl MycStateMetadataError {
    const fn new(kind: MycStateMetadataErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycStateMetadataErrorKind {
        self.kind
    }
}

impl fmt::Display for MycStateMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycStateMetadataErrorKind::Profile => "Myc configuration profile is inconsistent",
            MycStateMetadataErrorKind::Paths => "Myc state metadata paths are invalid",
            MycStateMetadataErrorKind::Configuration => {
                "Myc normalized configuration identity is invalid"
            }
            MycStateMetadataErrorKind::Identity => "Myc expected identity binding is invalid",
            MycStateMetadataErrorKind::Database => "Myc database metadata is invalid",
            MycStateMetadataErrorKind::Invariant => "Myc metadata contract is invalid",
        })
    }
}

impl fmt::Debug for MycStateMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateMetadataError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycStateMetadataError {}

fn require_profile_binding(
    runtime: MycBootstrapProfileV1,
    configuration: MycConfigProfile,
) -> Result<(), MycStateMetadataError> {
    let matches = match runtime {
        MycBootstrapProfileV1::ServiceHost | MycBootstrapProfileV1::Interactive => {
            configuration == MycConfigProfile::Production
        }
        MycBootstrapProfileV1::RepoLocal => configuration == MycConfigProfile::RepoLocal,
    };
    matches
        .then_some(())
        .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Profile))
}

fn normalized_config_digest(
    profile: MycConfigProfile,
    normalized: &serde_json::Value,
) -> Result<MycNormalizedConfigDigest, MycStateMetadataError> {
    let bytes = serde_json::to_vec(normalized)
        .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Configuration))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Configuration))?;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_CONFIG_DIGEST_DOMAIN);
    hasher.update([match profile {
        MycConfigProfile::Production => 0,
        MycConfigProfile::RepoLocal => 1,
    }]);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(MycNormalizedConfigDigest(hasher.finalize().into()))
}

fn governance_policies(
    normalized: &serde_json::Value,
) -> Result<MycGovernancePolicies, MycStateMetadataError> {
    let integer = |pointer: &str| {
        normalized
            .pointer(pointer)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))
    };
    let policy = |class, name: &str| {
        let prefix = format!("/rate_limits/{name}");
        MycRateLimitPolicy::new(
            class,
            integer(&format!("{prefix}/window_ms"))?,
            u32::try_from(integer(&format!("{prefix}/max_attempts"))?)
                .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?,
            integer(&format!("{prefix}/retention_ms"))?,
            u32::try_from(integer(&format!("{prefix}/maximum_tracked_subjects"))?)
                .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?,
        )
        .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))
    };
    let relays = normalized
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))?
        .iter()
        .map(|relay| {
            relay
                .pointer("/id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))
                .and_then(|id| {
                    MycRateRelayId::new(id).map_err(|_| {
                        MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant)
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    MycGovernancePolicies::new(
        policy(
            MycRateLimitClass::ConnectionAdmission,
            "connection_admission",
        )?,
        policy(MycRateLimitClass::ChallengeCreation, "challenge_creation")?,
        policy(
            MycRateLimitClass::ChallengeAuthorization,
            "challenge_authorization",
        )?,
        integer("/policy/retention/audit_ms")?,
        relays,
    )
    .map_err(|_| MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant))
}

fn delivery_policies(
    normalized: &serde_json::Value,
) -> Result<MycDeliveryPolicies, MycStateMetadataError> {
    let invalid = || MycStateMetadataError::new(MycStateMetadataErrorKind::Invariant);
    let integer = |pointer: &str| {
        normalized
            .pointer(pointer)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(invalid)
    };
    let mode = normalized
        .pointer("/transport/delivery_policy/mode")
        .and_then(serde_json::Value::as_str)
        .and_then(MycDeliveryPolicyMode::parse)
        .ok_or_else(invalid)?;
    let configured_quorum = normalized
        .pointer("/transport/delivery_policy/required_acknowledgements")
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(invalid)
        })
        .transpose()?;
    let targets = normalized
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .filter(|relay| relay.pointer("/write").and_then(serde_json::Value::as_bool) == Some(true))
        .map(|relay| {
            let id = relay
                .pointer("/id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(invalid)?;
            let required = relay
                .pointer("/required")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(invalid)?;
            let id = MycDeliveryRelayId::new(id).map_err(|_| invalid())?;
            Ok((id, required))
        })
        .collect::<Result<Vec<_>, MycStateMetadataError>>()?;
    MycDeliveryPolicies::new(
        mode,
        configured_quorum,
        u32::try_from(integer("/transport/publish_retry/max_attempts")?).map_err(|_| invalid())?,
        integer("/transport/publish_retry/initial_backoff_ms")?,
        integer("/transport/publish_retry/maximum_backoff_ms")?,
        integer("/transport/publish_retry/attempt_deadline_ms")?,
        targets,
    )
    .map_err(|_| invalid())
}

fn expected_identities(
    normalized: &serde_json::Value,
) -> Result<MycExpectedIdentities, MycStateMetadataError> {
    let identity = |pointer: &str| {
        normalized
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Identity))
            .and_then(MycExpectedPublicIdentity::from_hex)
    };
    let discovery_enabled = normalized
        .pointer("/identity/discovery/enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| MycStateMetadataError::new(MycStateMetadataErrorKind::Identity))?;
    Ok(MycExpectedIdentities {
        transport: identity("/identity/transport/expected_public_key")?,
        user: identity("/identity/user/expected_public_key")?,
        discovery: if discovery_enabled {
            Some(identity("/identity/discovery/binding/expected_public_key")?)
        } else {
            None
        },
    })
}
