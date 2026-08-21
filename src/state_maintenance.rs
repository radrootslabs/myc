//! Myc-bound integrity, backup, and offline restore integration.

use core::{fmt, num::NonZeroU64};
use std::{error::Error, path::Path};

use radroots_service_sqlite::{
    BackupManifestSha256, ServiceBackupManifest, ServiceDatabaseMetadata, ServiceSqliteError,
    ServiceSqliteErrorKind, StagedServiceRestore, VerifiedServiceBackup, finalize_staged_restore,
    stage_verified_restore, verify_backup_bundle,
};

use crate::{MycRuntimeContext, MycStateMetadata, state_host};

/// Stable source-free class for a Myc state-maintenance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateMaintenanceErrorKind {
    InvalidEvidence,
    InvalidMode,
    Catalog,
    Authority,
    Open,
    Metadata,
    Migration,
    Backup,
    Restore,
    Integrity,
    Recovery,
}

impl MycStateMaintenanceErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEvidence => "state_maintenance_evidence_invalid",
            Self::InvalidMode => "state_maintenance_mode_invalid",
            Self::Catalog => "state_maintenance_catalog_invalid",
            Self::Authority => "state_maintenance_authority_failed",
            Self::Open => "state_maintenance_open_failed",
            Self::Metadata => "state_maintenance_metadata_invalid",
            Self::Migration => "state_maintenance_migration_invalid",
            Self::Backup => "state_backup_failed",
            Self::Restore => "state_restore_failed",
            Self::Integrity => "state_integrity_failed",
            Self::Recovery => "state_recovery_failed",
        }
    }
}

/// Redacted Myc state-maintenance failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStateMaintenanceError {
    kind: MycStateMaintenanceErrorKind,
}

impl MycStateMaintenanceError {
    pub(crate) const fn new(kind: MycStateMaintenanceErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) fn from_sqlite(error: ServiceSqliteError) -> Self {
        let kind = match error.kind() {
            ServiceSqliteErrorKind::Authority => MycStateMaintenanceErrorKind::Authority,
            ServiceSqliteErrorKind::Open
            | ServiceSqliteErrorKind::Create
            | ServiceSqliteErrorKind::Pragma => MycStateMaintenanceErrorKind::Open,
            ServiceSqliteErrorKind::Metadata => MycStateMaintenanceErrorKind::Metadata,
            ServiceSqliteErrorKind::Migration => MycStateMaintenanceErrorKind::Migration,
            ServiceSqliteErrorKind::Backup => MycStateMaintenanceErrorKind::Backup,
            ServiceSqliteErrorKind::Restore => MycStateMaintenanceErrorKind::Restore,
            ServiceSqliteErrorKind::Integrity => MycStateMaintenanceErrorKind::Integrity,
            ServiceSqliteErrorKind::Recovery => MycStateMaintenanceErrorKind::Recovery,
        };
        Self::new(kind)
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycStateMaintenanceErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycStateMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycStateMaintenanceErrorKind::InvalidEvidence => {
                "Myc state maintenance evidence is invalid"
            }
            MycStateMaintenanceErrorKind::InvalidMode => {
                "Myc state maintenance is unavailable in this host mode"
            }
            MycStateMaintenanceErrorKind::Catalog => "Myc state catalogs are invalid",
            MycStateMaintenanceErrorKind::Authority => {
                "Myc state maintenance authority could not be established"
            }
            MycStateMaintenanceErrorKind::Open => "Myc state maintenance could not open state",
            MycStateMaintenanceErrorKind::Metadata => "Myc state metadata is invalid",
            MycStateMaintenanceErrorKind::Migration => "Myc state migration history is invalid",
            MycStateMaintenanceErrorKind::Backup => "Myc state backup failed",
            MycStateMaintenanceErrorKind::Restore => "Myc state restore failed",
            MycStateMaintenanceErrorKind::Integrity => "Myc state integrity check failed",
            MycStateMaintenanceErrorKind::Recovery => "Myc state recovery failed",
        })
    }
}

impl fmt::Debug for MycStateMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateMaintenanceError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycStateMaintenanceError {}

/// Retained exact-inode proof of one verified Myc backup.
///
/// Construction is sealed to [`verify_myc_state_backup`]. No raw descriptor or
/// pathname is exposed.
///
/// ```compile_fail
/// use myc::MycVerifiedStateBackup;
/// let _ = MycVerifiedStateBackup { inner: todo!() };
/// ```
pub struct MycVerifiedStateBackup {
    inner: VerifiedServiceBackup,
}

impl MycVerifiedStateBackup {
    /// Returns the admitted canonical manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ServiceBackupManifest {
        self.inner.manifest()
    }

    /// Returns the actual immutable database metadata read from the retained member.
    #[must_use]
    pub const fn database_metadata(&self) -> &ServiceDatabaseMetadata {
        self.inner.database_metadata()
    }
}

impl fmt::Debug for MycVerifiedStateBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycVerifiedStateBackup([redacted])")
    }
}

/// Offline staged Myc replacement that retains exclusive writer authority.
///
/// Construction is sealed to [`stage_myc_state_restore`]. Dropping this value
/// preserves the shared exact-inode cleanup and fail-closed evidence contract.
///
/// ```compile_fail
/// use myc::MycStagedStateRestore;
/// let _ = MycStagedStateRestore { inner: todo!() };
/// ```
pub struct MycStagedStateRestore {
    inner: StagedServiceRestore,
}

impl fmt::Debug for MycStagedStateRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStagedStateRestore([redacted])")
    }
}

/// Verifies an untrusted backup bundle against one sealed Myc state identity.
pub fn verify_myc_state_backup(
    manifest_bytes: &[u8],
    expected_manifest_digest: BackupManifestSha256,
    bundle_directory: &Path,
    expected: &MycStateMetadata,
    maximum_state_bytes: NonZeroU64,
) -> Result<MycVerifiedStateBackup, MycStateMaintenanceError> {
    verify_backup_bundle(
        manifest_bytes,
        expected_manifest_digest,
        bundle_directory,
        &expected.database_identity(),
        maximum_state_bytes,
    )
    .map(|inner| MycVerifiedStateBackup { inner })
    .map_err(MycStateMaintenanceError::from_sqlite)
}

/// Copies and fully reverifies a verified backup beside closed Myc state.
///
/// This operation acquires exclusive writer authority. It never creates a
/// recovery marker or replaces the live database.
pub async fn stage_myc_state_restore(
    runtime: &MycRuntimeContext,
    expected: &MycStateMetadata,
    verified: MycVerifiedStateBackup,
) -> Result<MycStagedStateRestore, MycStateMaintenanceError> {
    state_host::require_metadata(runtime, expected).map_err(|_| {
        MycStateMaintenanceError::new(MycStateMaintenanceErrorKind::InvalidEvidence)
    })?;
    let paths = state_host::state_paths(runtime).map_err(|_| {
        MycStateMaintenanceError::new(MycStateMaintenanceErrorKind::InvalidEvidence)
    })?;
    let (migrations, schema) = state_host::catalogs()
        .map_err(|_| MycStateMaintenanceError::new(MycStateMaintenanceErrorKind::Catalog))?;
    stage_verified_restore(
        &paths,
        &expected.database_identity(),
        &migrations,
        &schema,
        verified.inner,
    )
    .await
    .map(|inner| MycStagedStateRestore { inner })
    .map_err(MycStateMaintenanceError::from_sqlite)
}

/// Atomically installs a completely verified staged Myc restore.
///
/// Success intentionally returns no open host. The next writable open owns
/// exact recovery evidence reconciliation before SQLite is exposed again.
pub async fn finalize_myc_state_restore(
    staged: MycStagedStateRestore,
) -> Result<(), MycStateMaintenanceError> {
    finalize_staged_restore(staged.inner)
        .await
        .map_err(MycStateMaintenanceError::from_sqlite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_failures_map_to_the_closed_source_free_myc_vocabulary() {
        for (source, expected) in [
            (
                ServiceSqliteErrorKind::Authority,
                MycStateMaintenanceErrorKind::Authority,
            ),
            (
                ServiceSqliteErrorKind::Open,
                MycStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Create,
                MycStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Pragma,
                MycStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Metadata,
                MycStateMaintenanceErrorKind::Metadata,
            ),
            (
                ServiceSqliteErrorKind::Migration,
                MycStateMaintenanceErrorKind::Migration,
            ),
            (
                ServiceSqliteErrorKind::Backup,
                MycStateMaintenanceErrorKind::Backup,
            ),
            (
                ServiceSqliteErrorKind::Restore,
                MycStateMaintenanceErrorKind::Restore,
            ),
            (
                ServiceSqliteErrorKind::Integrity,
                MycStateMaintenanceErrorKind::Integrity,
            ),
            (
                ServiceSqliteErrorKind::Recovery,
                MycStateMaintenanceErrorKind::Recovery,
            ),
        ] {
            let mapped = MycStateMaintenanceError::from_sqlite(ServiceSqliteError::with_source(
                source,
                SensitiveSource,
            ));
            assert_eq!(mapped.kind(), expected);
            assert!(Error::source(&mapped).is_none());
            let rendered = format!("{mapped} {mapped:?}");
            assert!(!rendered.contains("sensitive"));
            assert!(!mapped.code().is_empty());
        }
    }

    #[derive(Debug)]
    struct SensitiveSource;

    impl fmt::Display for SensitiveSource {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive /tmp/state.sqlite")
        }
    }

    impl Error for SensitiveSource {}
}
