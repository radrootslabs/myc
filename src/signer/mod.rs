//! Myc-owned signer-service state, policy, persistence, and NIP-46 execution.
//!
//! Generic signing requests and receipts come from `radroots_signing`, while
//! protocol parsing comes from `radroots_nostr_connect`. Approval, session,
//! persistence, and service execution remain local to this host.

pub mod backend;
pub mod capability;
pub mod error;
pub mod evaluation;
pub mod manager;
pub mod migrations;
pub mod model;
pub mod nip46;
pub mod sqlite;
pub mod store;

#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod test_support;

pub mod prelude {
    pub use super::backend::{
        RadrootsNostrEmbeddedSignerBackend, RadrootsNostrSignerBackend,
        RadrootsNostrSignerBackendCapabilities, RadrootsNostrSignerPublishTransition,
        RadrootsNostrSignerSignOutput,
    };
    pub use super::capability::{
        RadrootsNostrLocalSignerAvailability, RadrootsNostrLocalSignerCapability,
        RadrootsNostrRemoteSessionSignerCapability, RadrootsNostrSignerCapability,
    };
    pub use super::error::RadrootsNostrSignerError;
    pub use super::evaluation::{
        RadrootsNostrSignerConnectEvaluation, RadrootsNostrSignerConnectProposal,
        RadrootsNostrSignerRequestAction, RadrootsNostrSignerRequestEvaluation,
        RadrootsNostrSignerRequestResponseHint, RadrootsNostrSignerSessionLookup,
    };
    pub use super::manager::RadrootsNostrSignerManager;
    pub use super::model::{
        RADROOTS_NOSTR_SIGNER_STORE_VERSION, RadrootsNostrSignerApprovalRequirement,
        RadrootsNostrSignerApprovalState, RadrootsNostrSignerAuthChallenge,
        RadrootsNostrSignerAuthState, RadrootsNostrSignerAuthorizationOutcome,
        RadrootsNostrSignerConnectSecretHash, RadrootsNostrSignerConnectionDraft,
        RadrootsNostrSignerConnectionId, RadrootsNostrSignerConnectionRecord,
        RadrootsNostrSignerConnectionStatus, RadrootsNostrSignerPendingRequest,
        RadrootsNostrSignerPermissionGrant, RadrootsNostrSignerPublishWorkflowKind,
        RadrootsNostrSignerPublishWorkflowRecord, RadrootsNostrSignerPublishWorkflowState,
        RadrootsNostrSignerRequestAuditRecord, RadrootsNostrSignerRequestDecision,
        RadrootsNostrSignerRequestId, RadrootsNostrSignerSecretDigestAlgorithm,
        RadrootsNostrSignerStoreState, RadrootsNostrSignerWorkflowId,
    };
    pub use super::nip46::{
        RadrootsNostrSignerHandledRequest, RadrootsNostrSignerHandledRequestOutcome,
        RadrootsNostrSignerNip46Codec, RadrootsNostrSignerNip46ConnectDecision,
        RadrootsNostrSignerNip46Handler, RadrootsNostrSignerNip46Policy,
        RadrootsNostrSignerNip46Signer, connect_response_outcome, handled_request_for_action,
        response_from_hint,
    };
    pub use super::sqlite::RadrootsNostrSignerSqliteDb;
    pub use super::store::{
        RadrootsNostrFileSignerStore, RadrootsNostrMemorySignerStore, RadrootsNostrSignerStore,
        RadrootsNostrSqliteSignerStore,
    };
}
