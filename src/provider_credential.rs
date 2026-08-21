//! Canonical wrapping-credential artifact resolution.

use core::fmt;
use std::error::Error;

use radroots_runtime_paths::{ServiceCredentialArtifactName, service_credential_artifact_path};

use crate::{
    MycBootstrapProfileV1, MycEncryptedIdentityEnvelopeErrorKind, MycProviderBinding,
    MycProviderKind, MycRuntimeContext, MycWrappingCredential,
    provider_envelope::load_resolved_wrapping_credential,
};

/// Exact fixed wrapping-credential artifact length.
pub const MYC_WRAPPING_CREDENTIAL_ARTIFACT_BYTES: usize = 32;
/// Exact Myc wrapping-credential resolution contract version.
pub const MYC_WRAPPING_CREDENTIAL_CONTRACT_VERSION: u32 = 1;

/// Stable source-free credential-resolution failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCredentialResolutionErrorKind {
    InvalidBinding,
    UnsupportedProfile,
    InvalidReference,
    MissingCredential,
    InsecureSecretsRoot,
    InsecureCredential,
    InvalidCredential,
    Io,
    UnsupportedPlatform,
}

impl MycCredentialResolutionErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "provider_credential_binding_invalid",
            Self::UnsupportedProfile => "provider_credential_profile_unsupported",
            Self::InvalidReference => "provider_credential_reference_invalid",
            Self::MissingCredential => "provider_credential_missing",
            Self::InsecureSecretsRoot => "provider_credential_root_insecure",
            Self::InsecureCredential => "provider_credential_artifact_insecure",
            Self::InvalidCredential => "provider_credential_material_invalid",
            Self::Io => "provider_credential_io_failed",
            Self::UnsupportedPlatform => "provider_credential_platform_unsupported",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "provider credential binding is invalid",
            Self::UnsupportedProfile => "provider credential profile is unsupported",
            Self::InvalidReference => "provider credential reference is invalid",
            Self::MissingCredential => "provider credential is missing",
            Self::InsecureSecretsRoot => "provider credential root is insecure",
            Self::InsecureCredential => "provider credential artifact is insecure",
            Self::InvalidCredential => "provider credential material is invalid",
            Self::Io => "provider credential storage failed",
            Self::UnsupportedPlatform => "provider credential storage is unsupported",
        }
    }
}

/// One source-free wrapping-credential resolution failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycCredentialResolutionError {
    kind: MycCredentialResolutionErrorKind,
}

impl MycCredentialResolutionError {
    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> MycCredentialResolutionErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycCredentialResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycCredentialResolutionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycCredentialResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycCredentialResolutionError {}

const fn resolution_error(kind: MycCredentialResolutionErrorKind) -> MycCredentialResolutionError {
    MycCredentialResolutionError { kind }
}

/// Resolves one existing wrapping credential from the canonical instance secrets root.
///
/// The caller supplies no path or credential bytes. Production deployment and
/// repo-local offline tooling provision the fixed artifact externally; this
/// operation is read-only and never creates a credential or parent directory.
pub fn resolve_myc_wrapping_credential(
    runtime: &MycRuntimeContext,
    binding: &MycProviderBinding,
) -> Result<MycWrappingCredential, MycCredentialResolutionError> {
    if !matches!(
        runtime.profile(),
        MycBootstrapProfileV1::ServiceHost | MycBootstrapProfileV1::RepoLocal
    ) {
        return Err(resolution_error(
            MycCredentialResolutionErrorKind::UnsupportedProfile,
        ));
    }
    if binding.kind() != MycProviderKind::EncryptedFile {
        return Err(resolution_error(
            MycCredentialResolutionErrorKind::InvalidBinding,
        ));
    }
    let reference = binding
        .credential_reference()
        .ok_or_else(|| resolution_error(MycCredentialResolutionErrorKind::InvalidBinding))?;
    let name = ServiceCredentialArtifactName::new(reference.as_str())
        .map_err(|_| resolution_error(MycCredentialResolutionErrorKind::InvalidReference))?;
    let path = service_credential_artifact_path(runtime.context().paths(), &name);
    if binding.encrypted_envelope_path() == Some(path.as_path()) {
        return Err(resolution_error(
            MycCredentialResolutionErrorKind::InvalidBinding,
        ));
    }
    load_resolved_wrapping_credential(&path).map_err(|error| {
        let kind = match error.kind() {
            MycEncryptedIdentityEnvelopeErrorKind::InvalidPath
            | MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding => {
                MycCredentialResolutionErrorKind::InvalidBinding
            }
            MycEncryptedIdentityEnvelopeErrorKind::MissingEnvelope => {
                MycCredentialResolutionErrorKind::MissingCredential
            }
            MycEncryptedIdentityEnvelopeErrorKind::InsecureParent => {
                MycCredentialResolutionErrorKind::InsecureSecretsRoot
            }
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact => {
                MycCredentialResolutionErrorKind::InsecureCredential
            }
            MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential => {
                MycCredentialResolutionErrorKind::InvalidCredential
            }
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform => {
                MycCredentialResolutionErrorKind::UnsupportedPlatform
            }
            MycEncryptedIdentityEnvelopeErrorKind::InvalidProvisioningMaterial
            | MycEncryptedIdentityEnvelopeErrorKind::AlreadyExists
            | MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion
            | MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope
            | MycEncryptedIdentityEnvelopeErrorKind::WrongCredential
            | MycEncryptedIdentityEnvelopeErrorKind::IdentityMismatch
            | MycEncryptedIdentityEnvelopeErrorKind::Io => MycCredentialResolutionErrorKind::Io,
        };
        resolution_error(kind)
    })
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::fs;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use nostr::{Keys, SecretKey};
    use sha2::{Digest, Sha256};

    use crate::{
        MycConfigProfile, MycProviderRole, RadrootsHostEnvironment, RadrootsPathResolver,
        RadrootsPlatform, parse_myc_cli_v1_from, parse_myc_config_v1, resolve_myc_runtime_context,
    };

    use super::*;

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn bytes(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn runtime(root: &Path, profile: &str) -> MycRuntimeContext {
        let root = root.to_str().expect("UTF-8 test root");
        let arguments = if profile == "repo-local" {
            vec![
                "myc",
                "--profile",
                profile,
                "--instance",
                "primary",
                "--repo-local-root",
                root,
                "run",
            ]
        } else {
            vec!["myc", "--profile", profile, "--instance", "primary", "run"]
        };
        let invocation = parse_myc_cli_v1_from(arguments).expect("test invocation");
        let environment = if profile == "interactive" {
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from(root)),
                xdg_config_home: Some(PathBuf::from(root).join("config")),
                xdg_data_home: Some(PathBuf::from(root).join("data")),
                xdg_state_home: Some(PathBuf::from(root).join("state")),
                xdg_cache_home: Some(PathBuf::from(root).join("cache")),
                xdg_runtime_dir: Some(PathBuf::from(root).join("run")),
                ..RadrootsHostEnvironment::default()
            }
        } else {
            RadrootsHostEnvironment::default()
        };
        resolve_myc_runtime_context(
            &RadrootsPathResolver::new(RadrootsPlatform::Linux, environment),
            &invocation,
        )
        .expect("runtime context")
    }

    fn binding(envelope_path: &Path) -> MycProviderBinding {
        let mut identity = bytes("radroots.myc.credential-test.identity.v1");
        while SecretKey::from_slice(&identity).is_err() {
            identity = Sha256::digest(identity).into();
        }
        let public_key = Keys::new(SecretKey::from_slice(&identity).expect("identity"))
            .public_key()
            .to_hex();
        let source = CONFIG
            .replace(
                "/var/lib/radroots/services/myc/primary/secrets/transport.identity.ncrypt",
                envelope_path.to_str().expect("UTF-8 envelope path"),
            )
            .replace(
                "4444444444444444444444444444444444444444444444444444444444444444",
                &public_key,
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::RepoLocal)
            .expect("configuration")
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding")
            .clone()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn prepare_credential(runtime: &MycRuntimeContext, name: &str, contents: &[u8]) -> PathBuf {
        let root = runtime.context().paths().secrets();
        fs::create_dir_all(root).expect("secrets root");
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("secrets mode");
        let path = root.join(name);
        fs::write(&path, contents).expect("credential artifact");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("credential mode");
        path
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn canonical_existing_artifact_resolves_without_path_or_value_exposure() {
        let directory = tempfile::tempdir().expect("test root");
        let runtime = runtime(directory.path(), "repo-local");
        let envelope_parent = directory.path().join("envelopes");
        fs::create_dir(&envelope_parent).expect("envelope parent");
        fs::set_permissions(&envelope_parent, fs::Permissions::from_mode(0o700))
            .expect("envelope parent mode");
        let binding = binding(&envelope_parent.join("transport.identity.ncrypt"));
        let credential_bytes = bytes("radroots.myc.credential-test.wrapping.v1");
        let path = prepare_credential(
            &runtime,
            binding
                .credential_reference()
                .expect("credential reference")
                .as_str(),
            &credential_bytes,
        );

        let credential =
            resolve_myc_wrapping_credential(&runtime, &binding).expect("credential resolution");
        assert_eq!(
            format!("{credential:?}"),
            "MycWrappingCredential([redacted])"
        );
        assert_eq!(
            path,
            runtime
                .context()
                .paths()
                .secrets()
                .join("transport_wrapping_key")
        );
        assert_eq!(
            fs::read(&path).expect("credential unchanged"),
            credential_bytes
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("credential metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .expect("read-only credential mode");
        fs::set_permissions(
            runtime.context().paths().secrets(),
            fs::Permissions::from_mode(0o500),
        )
        .expect("read-only secrets root mode");
        resolve_myc_wrapping_credential(&runtime, &binding)
            .expect("owner-read-only artifact and secrets root");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn missing_adjacent_short_long_zero_and_insecure_artifacts_fail_closed() {
        let directory = tempfile::tempdir().expect("test root");
        let runtime = runtime(directory.path(), "repo-local");
        let envelope_parent = directory.path().join("envelopes");
        fs::create_dir(&envelope_parent).expect("envelope parent");
        fs::set_permissions(&envelope_parent, fs::Permissions::from_mode(0o700))
            .expect("envelope parent mode");
        let envelope_path = envelope_parent.join("transport.identity.ncrypt");
        let binding = binding(&envelope_path);
        let adjacent = envelope_parent.join("transport.identity.key");
        fs::write(&adjacent, bytes("adjacent key")).expect("adjacent file");
        fs::create_dir_all(runtime.context().paths().secrets()).expect("secrets root");
        fs::set_permissions(
            runtime.context().paths().secrets(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("secrets mode");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("canonical credential is missing")
                .kind(),
            MycCredentialResolutionErrorKind::MissingCredential
        );

        let reference = binding.credential_reference().expect("reference").as_str();
        let path = prepare_credential(&runtime, reference, &[1; 31]);
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("short")
                .kind(),
            MycCredentialResolutionErrorKind::InsecureCredential
        );
        fs::write(&path, [1; 33]).expect("long");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("long")
                .kind(),
            MycCredentialResolutionErrorKind::InsecureCredential
        );
        fs::write(&path, [0; 32]).expect("zero");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("zero")
                .kind(),
            MycCredentialResolutionErrorKind::InvalidCredential
        );
        fs::write(&path, [1; 32]).expect("valid length");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("insecure mode");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("mode")
                .kind(),
            MycCredentialResolutionErrorKind::InsecureCredential
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
        let second_link = runtime.context().paths().secrets().join("second-link");
        fs::hard_link(&path, &second_link).expect("hard link");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("hard link")
                .kind(),
            MycCredentialResolutionErrorKind::InsecureCredential
        );
        fs::remove_file(&second_link).expect("remove hard link");
        fs::remove_file(&path).expect("remove credential");
        symlink(&adjacent, &path).expect("credential symlink");
        assert_eq!(
            resolve_myc_wrapping_credential(&runtime, &binding)
                .expect_err("symlink")
                .kind(),
            MycCredentialResolutionErrorKind::InsecureCredential
        );
    }

    #[test]
    fn unsupported_interactive_profile_and_errors_are_source_free() {
        let directory = tempfile::tempdir().expect("test root");
        let runtime = runtime(directory.path(), "interactive");
        let binding = binding(&directory.path().join("transport.identity.ncrypt"));
        let error =
            resolve_myc_wrapping_credential(&runtime, &binding).expect_err("interactive profile");
        assert_eq!(
            error.kind(),
            MycCredentialResolutionErrorKind::UnsupportedProfile
        );
        assert!(Error::source(&error).is_none());
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
        for kind in [
            MycCredentialResolutionErrorKind::InvalidBinding,
            MycCredentialResolutionErrorKind::UnsupportedProfile,
            MycCredentialResolutionErrorKind::InvalidReference,
            MycCredentialResolutionErrorKind::MissingCredential,
            MycCredentialResolutionErrorKind::InsecureSecretsRoot,
            MycCredentialResolutionErrorKind::InsecureCredential,
            MycCredentialResolutionErrorKind::InvalidCredential,
            MycCredentialResolutionErrorKind::Io,
            MycCredentialResolutionErrorKind::UnsupportedPlatform,
        ] {
            let error = resolution_error(kind);
            assert!(!error.code().is_empty());
            assert!(Error::source(&error).is_none());
        }
    }
}
