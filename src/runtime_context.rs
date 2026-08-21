//! Sealed bootstrap binding for one canonical Myc service instance.

use core::fmt;
use std::{error::Error, path::Path};

use radroots_runtime_paths::{
    RadrootsPathProfile, RadrootsPathResolver, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextBootstrap, RuntimeContextSource, ServiceId, default_service_instance_artifacts,
};

use crate::{MycBootstrapProfileV1, MycCliInvocationV1};

const MYC_SERVICE_ID: &str = "myc";

/// Stable source-free classification for Myc runtime-context failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycRuntimeContextErrorKind {
    InvalidServiceIdentity,
    InvalidBootstrapBinding,
    PathSelection,
}

impl MycRuntimeContextErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidServiceIdentity => "Myc service identity is invalid",
            Self::InvalidBootstrapBinding => "Myc bootstrap selectors are inconsistent",
            Self::PathSelection => "Myc runtime path selection failed",
        }
    }
}

/// One redacted Myc runtime-context failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycRuntimeContextError {
    kind: MycRuntimeContextErrorKind,
}

impl MycRuntimeContextError {
    const fn new(kind: MycRuntimeContextErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycRuntimeContextErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycRuntimeContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeContextError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycRuntimeContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycRuntimeContextError {}

/// Immutable canonical paths and bootstrap selection for one Myc instance.
///
/// Construction is sealed to the validated CLI invocation and the shared
/// runtime-path resolver. Callers cannot forge an alternate service identity,
/// path set, artifact name, or selected configuration path:
///
/// ```compile_fail
/// use myc::MycRuntimeContext;
///
/// let _ = MycRuntimeContext {
///     context: todo!(),
///     artifacts: todo!(),
///     selected_config_path: todo!(),
///     profile: todo!(),
/// };
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct MycRuntimeContext {
    context: RuntimeContext,
    artifacts: RadrootsServiceInstanceArtifacts,
    selected_config_path: std::path::PathBuf,
    profile: MycBootstrapProfileV1,
}

impl MycRuntimeContext {
    #[must_use]
    pub fn context(&self) -> &RuntimeContext {
        &self.context
    }

    #[must_use]
    pub fn artifacts(&self) -> &RadrootsServiceInstanceArtifacts {
        &self.artifacts
    }

    #[must_use]
    pub fn selected_config_path(&self) -> &Path {
        &self.selected_config_path
    }

    #[must_use]
    pub const fn profile(&self) -> MycBootstrapProfileV1 {
        self.profile
    }
}

impl fmt::Debug for MycRuntimeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycRuntimeContext")
            .field("profile", &self.profile)
            .field("service", &MYC_SERVICE_ID)
            .field("instance", &"[redacted]")
            .field("paths", &"[redacted]")
            .finish()
    }
}

/// Resolves one validated CLI selection into the sole Myc path authority.
pub fn resolve_myc_runtime_context(
    resolver: &RadrootsPathResolver,
    invocation: &MycCliInvocationV1,
) -> Result<MycRuntimeContext, MycRuntimeContextError> {
    let profile = invocation.profile();
    let path_profile = match profile {
        MycBootstrapProfileV1::ServiceHost => RadrootsPathProfile::ServiceHost,
        MycBootstrapProfileV1::Interactive => RadrootsPathProfile::InteractiveUser,
        MycBootstrapProfileV1::RepoLocal => RadrootsPathProfile::RepoLocal,
    };
    let bootstrap = RuntimeContextBootstrap::new(
        path_profile,
        invocation.repo_local_root().map(Path::to_path_buf),
        RuntimeContextSource::BootstrapCli,
        RuntimeContextSource::BootstrapCli,
    )
    .map_err(|_| {
        MycRuntimeContextError::new(MycRuntimeContextErrorKind::InvalidBootstrapBinding)
    })?;
    let service = ServiceId::new(MYC_SERVICE_ID).map_err(|_| {
        MycRuntimeContextError::new(MycRuntimeContextErrorKind::InvalidServiceIdentity)
    })?;
    let context =
        RuntimeContext::resolve(resolver, bootstrap, service, invocation.instance().clone())
            .map_err(|_| MycRuntimeContextError::new(MycRuntimeContextErrorKind::PathSelection))?;
    let artifacts = default_service_instance_artifacts(context.paths());
    let selected_config_path = invocation
        .config_path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| artifacts.config().to_path_buf());

    Ok(MycRuntimeContext {
        context,
        artifacts,
        selected_config_path,
        profile,
    })
}
