//! Existing-only, join-owned Myc runtime foundation.

use core::fmt;
use std::{error::Error, sync::mpsc};

use radroots_service_host::{
    HostError, HostErrorKind, ShutdownPhase, TaskClassification, TaskMetadata, TaskName,
    TaskSupervisor,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};

use crate::{
    MycConfigDocumentV1, MycDecryptedIdentity, MycLocalSignerClient, MycProviderBinding,
    MycProviderKind, MycProviderRole, MycRuntimeContext, MycStateHost, MycStateMetadata,
    open_myc_encrypted_identity, open_myc_state_read_write, resolve_myc_wrapping_credential,
};

#[cfg(test)]
const RUNTIME_FOUNDATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");

/// Exact version of the Myc runtime-foundation contract.
pub const MYC_RUNTIME_FOUNDATION_CONTRACT_VERSION: u32 = 1;

/// Closed startup conditions that must all be satisfied before Myc is ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycRuntimePrerequisite {
    ExistingState,
    TransportProvider,
    UserProvider,
    DiscoveryProvider,
    OutboxRecovery,
    RequiredRelayConnectivity,
    RequiredRelaySubscription,
    AdminListener,
    OperationsListener,
}

impl MycRuntimePrerequisite {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExistingState => "existing_state",
            Self::TransportProvider => "transport_provider",
            Self::UserProvider => "user_provider",
            Self::DiscoveryProvider => "discovery_provider",
            Self::OutboxRecovery => "outbox_recovery",
            Self::RequiredRelayConnectivity => "required_relay_connectivity",
            Self::RequiredRelaySubscription => "required_relay_subscription",
            Self::AdminListener => "admin_listener",
            Self::OperationsListener => "operations_listener",
        }
    }

    const fn reason(self) -> MycRuntimeReadinessReason {
        match self {
            Self::ExistingState => MycRuntimeReadinessReason::DatabaseSchemaMismatch,
            Self::TransportProvider | Self::UserProvider | Self::DiscoveryProvider => {
                MycRuntimeReadinessReason::SignerProviderUnavailable
            }
            Self::OutboxRecovery => MycRuntimeReadinessReason::OutboxInvariantFailed,
            Self::RequiredRelayConnectivity => MycRuntimeReadinessReason::RequiredRelayUnavailable,
            Self::RequiredRelaySubscription => MycRuntimeReadinessReason::SubscriberNotActive,
            Self::AdminListener => MycRuntimeReadinessReason::AdminListenerFailed,
            Self::OperationsListener => MycRuntimeReadinessReason::OperationsListenerFailed,
        }
    }
}

/// Closed stable reason vocabulary for an unsatisfied runtime prerequisite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MycRuntimeReadinessReason {
    AdminListenerFailed,
    DatabaseSchemaMismatch,
    OperationsListenerFailed,
    OutboxInvariantFailed,
    RequiredRelayUnavailable,
    SignerProviderUnavailable,
    SubscriberNotActive,
}

impl MycRuntimeReadinessReason {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdminListenerFailed => "admin_listener_failed",
            Self::DatabaseSchemaMismatch => "database_schema_mismatch",
            Self::OperationsListenerFailed => "operations_listener_failed",
            Self::OutboxInvariantFailed => "outbox_invariant_failed",
            Self::RequiredRelayUnavailable => "required_relay_unavailable",
            Self::SignerProviderUnavailable => "signer_provider_unavailable",
            Self::SubscriberNotActive => "subscriber_not_active",
        }
    }
}

/// Immutable startup-readiness projection derived from admitted configuration.
///
/// This snapshot is passive evidence. It performs no provider, relay, SQLite,
/// DNS, listener, or filesystem probe when read.
#[derive(Clone, PartialEq, Eq)]
pub struct MycRuntimeReadiness {
    required: Box<[MycRuntimePrerequisite]>,
    satisfied: Box<[MycRuntimePrerequisite]>,
    reasons: Box<[MycRuntimeReadinessReason]>,
}

impl MycRuntimeReadiness {
    /// Returns readiness only when every exact prerequisite is satisfied.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.required.len() == self.satisfied.len()
            && self
                .required
                .iter()
                .all(|required| self.satisfied.contains(required))
    }

    /// Returns the exact ordered prerequisite inventory for this configuration.
    #[must_use]
    pub fn required(&self) -> &[MycRuntimePrerequisite] {
        &self.required
    }

    /// Returns the exact ordered prerequisites already proven at construction.
    #[must_use]
    pub fn satisfied(&self) -> &[MycRuntimePrerequisite] {
        &self.satisfied
    }

    /// Returns bounded stable reasons for every class of missing prerequisite.
    #[must_use]
    pub const fn reasons(&self) -> &[MycRuntimeReadinessReason] {
        &self.reasons
    }
}

impl fmt::Debug for MycRuntimeReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeReadiness")
            .field("ready", &self.is_ready())
            .field("required", &self.required)
            .field("satisfied", &self.satisfied)
            .field("reasons", &self.reasons)
            .finish()
    }
}

/// Stable source-free runtime-foundation failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycRuntimeFoundationErrorKind {
    InvalidBinding,
    StateOpen,
    Provider,
    TaskRegistration,
    TaskFailure,
    Readiness,
    Close,
}

impl MycRuntimeFoundationErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "runtime_binding_invalid",
            Self::StateOpen => "runtime_state_open_failed",
            Self::Provider => "runtime_provider_unavailable",
            Self::TaskRegistration => "runtime_task_registration_failed",
            Self::TaskFailure => "runtime_task_failed",
            Self::Readiness => "runtime_readiness_invalid",
            Self::Close => "runtime_close_failed",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "Myc runtime binding is invalid",
            Self::StateOpen => "Myc existing state could not be opened",
            Self::Provider => "Myc provider startup failed",
            Self::TaskRegistration => "Myc runtime task registration failed",
            Self::TaskFailure => "Myc supervised startup task failed",
            Self::Readiness => "Myc readiness prerequisites are invalid",
            Self::Close => "Myc runtime foundation could not close",
        }
    }
}

/// One redacted source-free runtime-foundation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycRuntimeFoundationError {
    kind: MycRuntimeFoundationErrorKind,
}

impl MycRuntimeFoundationError {
    const fn new(kind: MycRuntimeFoundationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> MycRuntimeFoundationErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycRuntimeFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeFoundationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycRuntimeFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycRuntimeFoundationError {}

enum MycRuntimeProvider {
    EncryptedFile {
        role: MycProviderRole,
        _identity: MycDecryptedIdentity,
    },
    LocalSigner {
        role: MycProviderRole,
        _client: Box<MycLocalSignerClient>,
    },
}

enum ProviderStartupOutcome {
    Ready(MycDecryptedIdentity),
    ProviderFailure,
    TaskFailure,
}

impl MycRuntimeProvider {
    const fn role(&self) -> MycProviderRole {
        match self {
            Self::EncryptedFile { role, .. } | Self::LocalSigner { role, .. } => *role,
        }
    }

    const fn kind(&self) -> MycProviderKind {
        match self {
            Self::EncryptedFile { .. } => MycProviderKind::EncryptedFile,
            Self::LocalSigner { .. } => MycProviderKind::LocalSigner,
        }
    }
}

/// Existing-only Myc foundation with sealed state, provider, and task ownership.
///
/// The final relay/admin/process task graph remains owned by later RCLDs. This
/// value cannot be constructed directly or used to extract raw SQLite,
/// provider-secret, task-handle, or cancellation authority.
#[must_use = "the runtime foundation must be shut down so owned tasks and state are joined"]
pub struct MycRuntimeFoundation {
    runtime: MycRuntimeContext,
    configuration: MycConfigDocumentV1,
    metadata: MycStateMetadata,
    state: MycStateHost,
    providers: Box<[MycRuntimeProvider]>,
    readiness: MycRuntimeReadiness,
    supervisor: TaskSupervisor,
}

impl MycRuntimeFoundation {
    /// Returns the immutable canonical instance context.
    #[must_use]
    pub const fn runtime_context(&self) -> &MycRuntimeContext {
        &self.runtime
    }

    /// Returns the admitted immutable configuration.
    #[must_use]
    pub const fn configuration(&self) -> &MycConfigDocumentV1 {
        &self.configuration
    }

    /// Returns metadata proven against the existing state host.
    #[must_use]
    pub const fn metadata(&self) -> &MycStateMetadata {
        &self.metadata
    }

    /// Returns the passive startup-readiness snapshot.
    #[must_use]
    pub const fn readiness(&self) -> &MycRuntimeReadiness {
        &self.readiness
    }

    /// Returns the configured retained provider kind for one enabled role.
    #[must_use]
    pub fn provider_kind(&self, role: MycProviderRole) -> Option<MycProviderKind> {
        self.providers
            .iter()
            .find(|provider| provider.role() == role)
            .map(MycRuntimeProvider::kind)
    }

    /// Requests cancellation, joins every owned task, and explicitly closes state.
    pub async fn shutdown(mut self) -> Result<(), MycRuntimeFoundationError> {
        self.supervisor.request_cancellation();
        let supervised = self.supervisor.supervise().await;
        let closed = self.state.close().await;
        if supervised.is_err() {
            Err(MycRuntimeFoundationError::new(
                MycRuntimeFoundationErrorKind::TaskFailure,
            ))
        } else if closed.is_err() {
            Err(MycRuntimeFoundationError::new(
                MycRuntimeFoundationErrorKind::Close,
            ))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for MycRuntimeFoundation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeFoundation")
            .field("runtime", &"[redacted]")
            .field("configuration", &"[redacted]")
            .field("metadata", &"[redacted]")
            .field("state", &"[sealed]")
            .field("provider_count", &self.providers.len())
            .field("readiness", &self.readiness)
            .field("task_count", &self.supervisor.task_count())
            .finish()
    }
}

/// Opens an existing Myc state host and composes its sealed startup foundation.
///
/// Missing state is never initialized. Encrypted-file providers are opened on
/// bounded one-shot worker threads that are synchronously joined by
/// `TaskSupervisor`; local-signer clients are constructed without I/O and
/// remain unready until a later governed handshake succeeds. No task handle is
/// detached or returned.
pub async fn open_myc_runtime_foundation(
    runtime: MycRuntimeContext,
    configuration: MycConfigDocumentV1,
    metadata: MycStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<MycRuntimeFoundation, MycRuntimeFoundationError> {
    if !metadata.matches_configuration(&runtime, &configuration) {
        return Err(MycRuntimeFoundationError::new(
            MycRuntimeFoundationErrorKind::InvalidBinding,
        ));
    }
    let state = open_myc_state_read_write(&runtime, &metadata, applied_at, build)
        .await
        .map_err(|_| MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::StateOpen))?;

    match compose_after_state_open(runtime, configuration, metadata, state).await {
        Ok(foundation) => Ok(foundation),
        Err((error, state)) => {
            if state.close().await.is_err() {
                Err(MycRuntimeFoundationError::new(
                    MycRuntimeFoundationErrorKind::Close,
                ))
            } else {
                Err(error)
            }
        }
    }
}

async fn compose_after_state_open(
    runtime: MycRuntimeContext,
    configuration: MycConfigDocumentV1,
    metadata: MycStateMetadata,
    state: MycStateHost,
) -> Result<MycRuntimeFoundation, (MycRuntimeFoundationError, MycStateHost)> {
    let (providers, readiness, supervisor) =
        match compose_runtime_components(&runtime, &configuration).await {
            Ok(components) => components,
            Err(error) => return Err((error, state)),
        };
    Ok(MycRuntimeFoundation {
        runtime,
        configuration,
        metadata,
        state,
        providers,
        readiness,
        supervisor,
    })
}

async fn compose_runtime_components(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> Result<
    (
        Box<[MycRuntimeProvider]>,
        MycRuntimeReadiness,
        TaskSupervisor,
    ),
    MycRuntimeFoundationError,
> {
    let mut supervisor = TaskSupervisor::new();
    let mut providers: Vec<Option<MycRuntimeProvider>> = configuration
        .provider_contract()
        .bindings()
        .iter()
        .map(|_| None)
        .collect();
    let mut encrypted = Vec::new();
    let mut pending = Vec::new();

    for (index, binding) in configuration
        .provider_contract()
        .bindings()
        .iter()
        .cloned()
        .enumerate()
    {
        match binding.kind() {
            MycProviderKind::EncryptedFile => {
                let role = binding.role();
                let task = provider_task_metadata(role)?;
                encrypted.push((index, role, binding, task));
            }
            MycProviderKind::LocalSigner => {
                let role = binding.role();
                let client = MycLocalSignerClient::new(&binding).map_err(|_| {
                    MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::Provider)
                })?;
                providers[index] = Some(MycRuntimeProvider::LocalSigner {
                    role,
                    _client: Box::new(client),
                });
            }
        }
    }

    for (index, role, binding, task) in encrypted {
        let (sender, receiver) = mpsc::sync_channel(1);
        let task_runtime = runtime.clone();
        let registered = supervisor.spawn(task, move |_cancellation| async move {
            let outcome = match std::thread::Builder::new()
                .name(provider_thread_name(role).to_owned())
                .spawn(move || open_encrypted_provider(&task_runtime, &binding))
            {
                Ok(thread) => match thread.join() {
                    Ok(Ok(identity)) => ProviderStartupOutcome::Ready(identity),
                    Ok(Err(())) => ProviderStartupOutcome::ProviderFailure,
                    Err(_) => ProviderStartupOutcome::TaskFailure,
                },
                Err(_) => ProviderStartupOutcome::TaskFailure,
            };
            let succeeded = matches!(outcome, ProviderStartupOutcome::Ready(_));
            let _ = sender.send(outcome);
            if succeeded {
                Ok(())
            } else {
                Err(HostError::new(HostErrorKind::TaskFailure))
            }
        });
        if registered.is_err() {
            supervisor.request_cancellation();
            let _ = supervisor.supervise().await;
            return Err(MycRuntimeFoundationError::new(
                MycRuntimeFoundationErrorKind::TaskRegistration,
            ));
        }
        pending.push((index, role, receiver));
    }

    let supervised = supervisor.supervise().await;
    let mut provider_failure = false;
    let mut task_failure = false;
    for (index, role, receiver) in pending {
        match receiver.recv() {
            Ok(ProviderStartupOutcome::Ready(identity)) => {
                providers[index] = Some(MycRuntimeProvider::EncryptedFile {
                    role,
                    _identity: identity,
                });
            }
            Ok(ProviderStartupOutcome::ProviderFailure) => provider_failure = true,
            Ok(ProviderStartupOutcome::TaskFailure) | Err(_) => task_failure = true,
        }
    }
    if task_failure {
        return Err(MycRuntimeFoundationError::new(
            MycRuntimeFoundationErrorKind::TaskFailure,
        ));
    }
    if provider_failure {
        return Err(MycRuntimeFoundationError::new(
            MycRuntimeFoundationErrorKind::Provider,
        ));
    }
    if supervised.is_err() {
        return Err(MycRuntimeFoundationError::new(
            MycRuntimeFoundationErrorKind::TaskFailure,
        ));
    }
    let providers = providers
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::Provider))?
        .into_boxed_slice();

    let readiness = startup_readiness(configuration, &providers)?;
    let lifetime = TaskMetadata::new(
        TaskName::new("runtime_lifetime").map_err(|_| {
            MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::TaskRegistration)
        })?,
        TaskClassification::Critical,
        Some(ShutdownPhase::RejectNewMutations),
    )
    .map_err(|_| MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::TaskRegistration))?;
    supervisor
        .spawn(lifetime, |cancellation| async move {
            cancellation.cancelled().await;
            Ok(())
        })
        .map_err(|_| {
            MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::TaskRegistration)
        })?;

    Ok((providers, readiness, supervisor))
}

fn open_encrypted_provider(
    runtime: &MycRuntimeContext,
    binding: &MycProviderBinding,
) -> Result<MycDecryptedIdentity, ()> {
    let credential = resolve_myc_wrapping_credential(runtime, binding).map_err(|_| ())?;
    open_myc_encrypted_identity(binding, &credential).map_err(|_| ())
}

fn provider_task_metadata(
    role: MycProviderRole,
) -> Result<TaskMetadata, MycRuntimeFoundationError> {
    TaskMetadata::new(
        TaskName::new(provider_task_name(role)).map_err(|_| {
            MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::TaskRegistration)
        })?,
        TaskClassification::OneShot,
        None,
    )
    .map_err(|_| MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::TaskRegistration))
}

const fn provider_task_name(role: MycProviderRole) -> &'static str {
    match role {
        MycProviderRole::Transport => "startup_transport_provider",
        MycProviderRole::User => "startup_user_provider",
        MycProviderRole::Discovery => "startup_discovery_provider",
    }
}

const fn provider_thread_name(role: MycProviderRole) -> &'static str {
    match role {
        MycProviderRole::Transport => "myc-provider-transport",
        MycProviderRole::User => "myc-provider-user",
        MycProviderRole::Discovery => "myc-provider-discovery",
    }
}

fn startup_readiness(
    configuration: &MycConfigDocumentV1,
    providers: &[MycRuntimeProvider],
) -> Result<MycRuntimeReadiness, MycRuntimeFoundationError> {
    let document = configuration.normalized();
    let mut required = vec![
        MycRuntimePrerequisite::ExistingState,
        MycRuntimePrerequisite::TransportProvider,
        MycRuntimePrerequisite::UserProvider,
    ];
    if configuration
        .provider_contract()
        .binding(MycProviderRole::Discovery)
        .is_some()
    {
        required.push(MycRuntimePrerequisite::DiscoveryProvider);
    }
    required.push(MycRuntimePrerequisite::OutboxRecovery);

    let relays = document
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(readiness_error)?;
    if relays.iter().any(|relay| {
        relay
            .pointer("/required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    }) {
        required.push(MycRuntimePrerequisite::RequiredRelayConnectivity);
    }
    if relays.iter().any(|relay| {
        relay
            .pointer("/required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
            && relay.pointer("/read").and_then(serde_json::Value::as_bool) == Some(true)
    }) {
        required.push(MycRuntimePrerequisite::RequiredRelaySubscription);
    }
    required.push(MycRuntimePrerequisite::AdminListener);
    if document
        .pointer("/operations/enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(readiness_error)?
    {
        required.push(MycRuntimePrerequisite::OperationsListener);
    }

    let mut satisfied = vec![MycRuntimePrerequisite::ExistingState];
    for provider in providers {
        if provider.kind() == MycProviderKind::EncryptedFile {
            satisfied.push(provider_prerequisite(provider.role()));
        }
    }
    satisfied.sort_by_key(|prerequisite| {
        required
            .iter()
            .position(|candidate| candidate == prerequisite)
            .unwrap_or(usize::MAX)
    });
    let mut reasons = required
        .iter()
        .filter(|prerequisite| !satisfied.contains(prerequisite))
        .map(|prerequisite| prerequisite.reason())
        .collect::<Vec<_>>();
    reasons.sort_unstable();
    reasons.dedup();
    Ok(MycRuntimeReadiness {
        required: required.into_boxed_slice(),
        satisfied: satisfied.into_boxed_slice(),
        reasons: reasons.into_boxed_slice(),
    })
}

const fn provider_prerequisite(role: MycProviderRole) -> MycRuntimePrerequisite {
    match role {
        MycProviderRole::Transport => MycRuntimePrerequisite::TransportProvider,
        MycProviderRole::User => MycRuntimePrerequisite::UserProvider,
        MycProviderRole::Discovery => MycRuntimePrerequisite::DiscoveryProvider,
    }
}

const fn readiness_error() -> MycRuntimeFoundationError {
    MycRuntimeFoundationError::new(MycRuntimeFoundationErrorKind::Readiness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_contract_and_closed_names_are_exact() {
        let contract: serde_json::Value =
            serde_json::from_str(RUNTIME_FOUNDATION_CONTRACT).expect("runtime contract");
        assert_eq!(contract["schema"], "radroots.myc.runtime-foundation");
        assert_eq!(contract["contract_version"], 1);
        let names = contract["readiness_prerequisites"]
            .as_array()
            .expect("prerequisite inventory")
            .iter()
            .map(|entry| entry["id"].as_str().expect("prerequisite id"))
            .collect::<Vec<_>>();
        let expected = [
            MycRuntimePrerequisite::ExistingState,
            MycRuntimePrerequisite::TransportProvider,
            MycRuntimePrerequisite::UserProvider,
            MycRuntimePrerequisite::DiscoveryProvider,
            MycRuntimePrerequisite::OutboxRecovery,
            MycRuntimePrerequisite::RequiredRelayConnectivity,
            MycRuntimePrerequisite::RequiredRelaySubscription,
            MycRuntimePrerequisite::AdminListener,
            MycRuntimePrerequisite::OperationsListener,
        ];
        assert_eq!(
            names,
            expected
                .into_iter()
                .map(MycRuntimePrerequisite::as_str)
                .collect::<Vec<_>>()
        );
        let reasons = contract["readiness_prerequisites"]
            .as_array()
            .expect("prerequisite inventory")
            .iter()
            .map(|entry| entry["reason"].as_str().expect("prerequisite reason"))
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            expected
                .into_iter()
                .map(MycRuntimePrerequisite::reason)
                .map(MycRuntimeReadinessReason::as_str)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn safe_errors_cover_the_closed_inventory_without_sources() {
        for kind in [
            MycRuntimeFoundationErrorKind::InvalidBinding,
            MycRuntimeFoundationErrorKind::StateOpen,
            MycRuntimeFoundationErrorKind::Provider,
            MycRuntimeFoundationErrorKind::TaskRegistration,
            MycRuntimeFoundationErrorKind::TaskFailure,
            MycRuntimeFoundationErrorKind::Readiness,
            MycRuntimeFoundationErrorKind::Close,
        ] {
            let error = MycRuntimeFoundationError::new(kind);
            assert!(!error.code().is_empty());
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("source"));
        }
    }
}
