#![forbid(unsafe_code)]
#![doc = include_str!("../README")]

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod admin_v1;
mod cli_v1;
mod config_v1;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod control_plane_wave_090_a;
mod diagnostics_v1;
mod doctor_v1;
mod nip46_admission;
mod nip46_authorization;
mod nip46_replay;
mod nip46_verification;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod nip46_wave_080_a;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod nip46_wave_080_b;
mod nip46_work;
mod operations_v1;
mod provider_contract;
mod provider_credential;
mod provider_envelope;
mod provider_local_signer;
mod provider_verification;
mod runtime_context;
mod runtime_foundation;
mod runtime_supervision;
mod state_catalog;
mod state_completion;
mod state_config;
mod state_connection;
mod state_delivery;
mod state_discovery;
mod state_governance;
mod state_host;
mod state_maintenance;
mod state_metadata;
mod state_recovery;
mod state_repository;
mod state_request;
mod state_response;
mod status_v1;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use admin_v1::{
    MycAdminDocumentError, MycAdminDocumentErrorKind, MycAdminFuture, MycAdminHandler,
    MycAdminHandlerError, MycAdminHandlerErrorKind, MycAdminMethod, MycAdminRequestDocument,
    MycAdminResponseDocument, MycAdminRoute, MycAdminRouter, MycAdminRouterError,
    build_myc_admin_router,
};
pub use cli_v1::{
    MycBootstrapProfileV1, MycCliAdminOperationV1, MycCliExecutionPlanV1, MycCliInvocationV1,
    MycCliOfflineOperationV1, MycCliPrimaryAuthorityV1, MycCliV1Error, MycCliV1ErrorKind,
    MycCommandV1, MycConfigCommandV1, MycIdentityCommandV1, MycStateCommandV1,
    parse_myc_cli_v1_from, plan_myc_cli_v1,
};
pub use config_v1::{
    MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, MYC_CONFIG_SCHEMA, MYC_CONFIG_SCHEMA_VERSION,
    MycConfigDocumentV1, MycConfigProfile, MycConfigV1Error, MycConfigV1ErrorKind,
    MycConfigValueSource, MycEffectiveConfigV1, parse_myc_config_v1,
};
pub use diagnostics_v1::{
    MYC_DIAGNOSTICS_CONTRACT_VERSION, MYC_LOG_RECORD_MAX_UTF8_BYTES, MycLogEvent, MycLogLevel,
    MycLogRecord, MycProcessResult,
};
pub use doctor_v1::{
    MYC_DOCTOR_CHECK_COUNT, MYC_DOCTOR_CONTRACT_VERSION, MYC_DOCTOR_REPORT_MAX_UTF8_BYTES,
    MYC_DOCTOR_SUMMARY_MAX_UTF8_BYTES, MycDoctorAggregateStatus, MycDoctorCheckDefinition,
    MycDoctorCheckId, MycDoctorCheckResult, MycDoctorCheckStatus, MycDoctorError,
    MycDoctorErrorKind, MycDoctorFuture, MycDoctorObservation, MycDoctorProbe,
    MycDoctorRemediationCode, MycDoctorReport, myc_doctor_check_definitions, run_myc_doctor,
};
pub use nip46_admission::{
    MYC_NIP46_EVENT_ID_MAX_BYTES, MYC_NIP46_PUBLIC_KEY_MAX_BYTES, MYC_NIP46_SIGNATURE_MAX_BYTES,
    MycBoundedNip46Event, MycBoundedNip46Request, MycNip46AdmissionError,
    MycNip46AdmissionErrorKind, MycNip46AdmissionLimits, admit_myc_nip46_event,
    admit_myc_nip46_request,
};
pub use nip46_replay::{
    MycNip46ConnectionIdentity, MycNip46LogicalRequestIdentity, MycNip46ReplayDisposition,
    MycNip46ReplayKey, MycReplayBoundNip46Request, bind_myc_nip46_replay,
};
pub use nip46_verification::{
    MycNip46AuthoredTimePolicy, MycNip46EncryptionContext, MycNip46ObservedAtUnixSeconds,
    MycNip46VerificationError, MycNip46VerificationErrorKind, MycVerifiedNip46Event,
    MycVerifiedNip46Request, verify_myc_nip46_event, verify_myc_nip46_request,
};
pub use nip46_work::{
    MycDecryptedNip46Request, MycNip46DecryptWork, MycNip46Work, MycNip46WorkError,
    MycNip46WorkErrorKind, MycNip46WorkKind, MycPreparedNip46Request,
    prepare_myc_nip46_decrypt_work, prepare_myc_nip46_request, prepare_myc_nip46_work,
};
pub use operations_v1::{
    MYC_LIVEZ_PATH, MYC_METRICS_PATH, MYC_OPERATIONS_CONTRACT_VERSION, MYC_READYZ_PATH,
    MycBoundOperationsServer, MycOperationsCancellationToken, MycOperationsError,
    MycOperationsErrorKind, MycOperationsServer,
};
pub use provider_contract::{
    MYC_PROVIDER_CONCURRENCY_MAX, MYC_PROVIDER_CONTRACT_VERSION, MYC_PROVIDER_INPUT_MAX_BYTES,
    MYC_PROVIDER_OUTPUT_MAX_BYTES, MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS,
    MYC_PROVIDER_REQUEST_MAX_BYTES, MYC_PROVIDER_RESPONSE_MAX_BYTES, MycLocalSignerLimits,
    MycProviderBinding, MycProviderCapability, MycProviderCapabilitySet, MycProviderContract,
    MycProviderContractError, MycProviderContractErrorKind, MycProviderCorrelationId,
    MycProviderCredentialReference, MycProviderDeadlineUnixMs, MycProviderInstanceId,
    MycProviderKind, MycProviderNip44Version, MycProviderOperation, MycProviderOperationId,
    MycProviderOperationInput, MycProviderPublicIdentity, MycProviderRole,
    MycUntrustedProviderOutput,
};
pub use provider_credential::{
    MYC_WRAPPING_CREDENTIAL_ARTIFACT_BYTES, MYC_WRAPPING_CREDENTIAL_CONTRACT_VERSION,
    MycCredentialResolutionError, MycCredentialResolutionErrorKind,
    resolve_myc_wrapping_credential,
};
pub use provider_envelope::{
    MYC_ENCRYPTED_IDENTITY_BACKUP_INCLUDED, MYC_ENCRYPTED_IDENTITY_ENVELOPE_CONTRACT_VERSION,
    MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES, MycDecryptedIdentity,
    MycEncryptedIdentityEnvelopeError, MycEncryptedIdentityEnvelopeErrorKind,
    MycEncryptedIdentityProvisioningMaterial, MycWrappingCredential, open_myc_encrypted_identity,
    provision_myc_encrypted_identity,
};
pub use provider_local_signer::{
    MYC_LOCAL_SIGNER_ENDPOINT, MYC_LOCAL_SIGNER_TRANSPORT_CONTRACT_VERSION, MycLocalSignerClient,
    MycLocalSignerTransportError, MycLocalSignerTransportErrorKind,
    MycLocalSignerUntrustedResponse,
};
pub use provider_verification::{
    MycProviderResponseObservedAtUnixMs, MycProviderVerificationError,
    MycProviderVerificationErrorKind, MycVerifiedProviderResponse,
};
pub use radroots_runtime_paths::{
    INSTANCE_ID_MAX_BYTES, InstanceId, RadrootsHostEnvironment, RadrootsPathProfile,
    RadrootsPathResolver, RadrootsPlatform, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextSource, ServiceId,
};
pub use runtime_context::{
    MycRuntimeContext, MycRuntimeContextError, MycRuntimeContextErrorKind,
    resolve_myc_runtime_context,
};
pub use runtime_foundation::{
    MYC_RUNTIME_FOUNDATION_CONTRACT_VERSION, MycRuntimeFoundation, MycRuntimeFoundationError,
    MycRuntimeFoundationErrorKind, MycRuntimePrerequisite, MycRuntimeReadiness,
    MycRuntimeReadinessReason, open_myc_runtime_foundation,
};
pub use runtime_supervision::{
    MYC_CRITICAL_TASK_MAX_COUNT, MYC_RUNTIME_SUPERVISION_CONTRACT_VERSION, MycCriticalTask,
    MycCriticalTaskError, MycRuntimeSupervisionError, MycRuntimeSupervisionErrorKind,
    MycSupervisedRuntime, MycTaskCancellation,
};
pub use state_catalog::{
    MYC_MIGRATION_CATALOG_SHA256, MYC_STATE_BASE_SCHEMA_VERSION, MYC_STATE_SCHEMA_CATALOG_SHA256,
    MYC_STATE_SCHEMA_VERSION, MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_1_SHA256, MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_2_SHA256,
    MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_3_SHA256, MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_4_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_4_SHA256,
    MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_5_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_5_SHA256, MYC_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_6_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_6_SHA256,
    MYC_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_7_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_7_SHA256, MYC_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_8_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_8_SHA256,
    MYC_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_9_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_9_SHA256, MYC_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_10_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_10_SHA256,
    MycStateCatalogError, MycStateCatalogErrorKind, myc_migration_catalog, myc_schema_catalog,
    validate_myc_state_catalogs,
};
pub use state_completion::{
    MycNip46CommitAdmission, MycNip46CommitError, MycNip46CommitErrorKind, MycNip46CommitRecord,
    MycNip46CommitRequest, MycNip46SessionEffect,
};
pub use state_config::{
    MYC_CONFIG_BINDING_MAX_GENERATIONS, MycConfigApplyError, MycConfigApplyErrorKind,
    MycConfigApplyOutcome,
};
pub use state_connection::{
    MYC_AUTHORIZATION_CHALLENGE_URL_MAX_BYTES, MYC_CONNECTION_PERMISSION_MAX_COUNT,
    MycAuthorizationChallengeAdmission, MycAuthorizationChallengeAuthorization,
    MycAuthorizationChallengeId, MycAuthorizationChallengeNonce, MycAuthorizationChallengeRecord,
    MycAuthorizationChallengeRequest, MycAuthorizationChallengeState, MycAuthorizationChallengeUrl,
    MycConnectionAdmission, MycConnectionAdmissionPolicy, MycConnectionAdmissionRequest,
    MycConnectionDecision, MycConnectionDecisionRecord, MycConnectionId, MycConnectionNonce,
    MycConnectionOperatorDecision, MycConnectionPermission, MycConnectionPermissionSet,
    MycConnectionPolicyGeneration, MycConnectionRecord, MycConnectionStateError,
    MycConnectionStateErrorKind, MycConnectionStatus, MycConnectionTimeUnixMs,
};
pub use state_delivery::{
    MYC_DELIVERY_ATTEMPT_MAX_COUNT, MYC_DELIVERY_RELAY_ID_MAX_BYTES,
    MYC_DELIVERY_RETRY_JITTER_MAX_MS, MYC_DELIVERY_TARGET_MAX_COUNT, MycDeliveryArtifactDigest,
    MycDeliveryAttemptId, MycDeliveryAttemptNonce, MycDeliveryAttemptOutcome,
    MycDeliveryAttemptRecord, MycDeliveryAttemptStatus, MycDeliveryClaim, MycDeliveryJobAdmission,
    MycDeliveryJobId, MycDeliveryJobRecord, MycDeliveryJobStatus, MycDeliveryPolicyMode,
    MycDeliveryRelayId, MycDeliveryRetryJitter, MycDeliverySourceKind, MycDeliveryStateError,
    MycDeliveryStateErrorKind, MycDeliveryTargetRecord, MycDeliveryTargetStatus,
    MycDeliveryTimeUnixMs,
};
pub use state_discovery::{
    MYC_DISCOVERY_DOCUMENT_MAX_BYTES, MYC_NIP05_DOCUMENT_MAX_BYTES, MYC_NIP05_PROJECTION_MAX_BYTES,
    MycDiscoveryCommitAdmission, MycDiscoveryCommitRecord, MycDiscoveryCommitRequest,
    MycDiscoveryDocumentDigest, MycDiscoveryDocumentRecord, MycDiscoveryGenerationId,
    MycDiscoveryPublicationState, MycDiscoveryStateError, MycDiscoveryStateErrorKind,
    MycNip05Document, MycNip05DocumentDigest, MycNip05ExportSelection, MycNip05ProjectionDigest,
};
pub use state_governance::{
    MYC_AUDIT_PAGE_MAX_ITEMS, MYC_AUDIT_RETENTION_MAX_MS, MYC_COMPACTION_MAX_ROWS,
    MYC_RATE_MAX_ATTEMPTS, MYC_RATE_MAX_TRACKED_SUBJECTS, MYC_RATE_RELAY_ID_MAX_BYTES,
    MYC_RATE_RETENTION_MAX_MS, MYC_RATE_WINDOW_MAX_MS, MycAuditCorrelationId, MycAuditKind,
    MycAuditOutcome, MycAuditPage, MycAuditPageLimit, MycAuditReasonCode, MycAuditRecord,
    MycGovernanceCompactionOutcome, MycGovernanceCompactionPolicy, MycGovernanceStateError,
    MycGovernanceStateErrorKind, MycRateLimitClass, MycRateLimitPolicy, MycRateRelayId,
};
pub use state_host::{
    MycStateHost, MycStateHostError, MycStateHostErrorKind, MycStateHostMode, initialize_myc_state,
    open_myc_state_inspection, open_myc_state_read_write,
};
pub use state_maintenance::{
    MycStagedStateRestore, MycStateMaintenanceError, MycStateMaintenanceErrorKind,
    MycVerifiedStateBackup, finalize_myc_state_restore, stage_myc_state_restore,
    verify_myc_state_backup,
};
pub use state_metadata::{
    MYC_OPERATOR_CONTRACT_VERSION, MYC_SIGNER_STATUS_CONTRACT_VERSION, MYC_STATE_APPLICATION_ID,
    MycExpectedIdentities, MycExpectedPublicIdentity, MycNormalizedConfigDigest, MycStateMetadata,
    MycStateMetadataError, MycStateMetadataErrorKind, MycStatePolicyVersions,
};
pub use state_recovery::{
    MYC_DELIVERY_RECOVERY_BATCH_MAX_COUNT, MycDeliveryRecoveryEntropy, MycDeliveryRecoveryReport,
};
pub use state_repository::{
    MycStateRepository, MycStateRepositoryError, MycStateRepositoryErrorKind,
};
pub use state_request::{
    MYC_NIP46_CANONICAL_REQUEST_MAX_BYTES, MYC_NIP46_REQUEST_ID_MAX_UTF8_BYTES,
    MycNip46ClientPublicKey, MycNip46EventId, MycNip46RequestId, MycRequestReceivedAtUnixMs,
    MycSignerCorrelationId, MycSignerOperationId, MycSignerOperationNonce, MycSignerRequest,
    MycSignerRequestAdmission, MycSignerRequestDigest, MycSignerRequestError,
    MycSignerRequestErrorKind, MycSignerRequestMethod, MycSignerRequestRecord,
};
pub use state_response::{
    MycNip46ResponseCommitAdmission, MycNip46ResponseCommitError, MycNip46ResponseCommitErrorKind,
    MycNip46ResponseCommitRecord, MycNip46ResponseCommitRequest, MycNip46ResponseRecord,
};
pub use status_v1::{
    MYC_DETAILED_STATUS_MAX_UTF8_BYTES, MYC_STATUS_CACHE_CONTRACT_VERSION,
    MYC_STATUS_REASON_CODE_COUNT, MycConnectionCountsV1, MycIdentityHealthV1, MycIntegrityStateV1,
    MycOutboxStatusV1, MycPersistenceHealthV1, MycPersistenceStatusV1, MycProviderHealthV1,
    MycProviderStatusV1, MycRelayTransportStatusV1, MycServicePhase, MycStatusBuildInfoV1,
    MycStatusBuildMode, MycStatusCommonV1, MycStatusConfigurationIdentityV1,
    MycStatusConfigurationSource, MycStatusError, MycStatusErrorKind, MycStatusObservationV1,
    MycStatusPublisher, MycStatusReader, MycStatusReasonCode, MycStatusReasonCodes,
    MycStatusSnapshot, MycStatusUnixSeconds, MycTransportHealthV1, myc_status_cache,
};
