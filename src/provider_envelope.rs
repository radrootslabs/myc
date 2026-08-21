//! Sealed encrypted-file identity provider boundary.

use core::fmt;
use std::error::Error;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use nostr::{Keys, SecretKey};
use radroots_secrets::context::{
    EnvelopeContext, EnvelopePurpose, EnvelopeSubject, PayloadSchemaId,
};
use radroots_secrets::envelope::{
    ENVELOPE_MAX_BYTES, ENVELOPE_VERSION, Nonce, SealMaterial, SealRequest,
};
use radroots_secrets::error::Operation;
use radroots_secrets::id::{BackendKind, KeyVersion};
use radroots_secrets::wrapping::{
    BoxFuture, SecretMaterial, UnwrapRequest, WrapRequest, WrappedSecret,
};
use radroots_secrets::{EncryptedEnvelope, KeyWrapping, SecretId, SecretRef};
use zeroize::Zeroizing;

use crate::{MycProviderBinding, MycProviderKind, MycProviderPublicIdentity};

/// Exact Myc encrypted-identity envelope contract version.
pub const MYC_ENCRYPTED_IDENTITY_ENVELOPE_CONTRACT_VERSION: u32 = 1;
/// Hard encoded-envelope cap inherited from the source-locked secrets crate.
pub const MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES: usize = ENVELOPE_MAX_BYTES;
/// Myc state backups never contain encrypted identity envelopes.
pub const MYC_ENCRYPTED_IDENTITY_BACKUP_INCLUDED: bool = false;

const IDENTITY_SECRET_BYTES: usize = 32;
const WRAPPING_CREDENTIAL_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const WRAPPED_KEY_MAGIC: [u8; 4] = *b"MYWK";
const WRAPPED_KEY_VERSION: u8 = 1;
const WRAPPED_KEY_CIPHERTEXT_BYTES: usize = IDENTITY_SECRET_BYTES + 16;
const WRAPPED_KEY_BYTES: usize =
    WRAPPED_KEY_MAGIC.len() + 1 + NONCE_BYTES + WRAPPED_KEY_CIPHERTEXT_BYTES;
const WRAPPING_AAD_DOMAIN: &[u8] = b"radroots.myc.wrapped_data_key.v1\0";
const CONTEXT_PURPOSE: &str = "radroots.myc.encrypted_identity";
const CONTEXT_SUBJECT_TYPE: &str = "provider_identity";
const CONTEXT_PAYLOAD_SCHEMA: &str = "radroots.myc.identity_secret.v1";

/// Stable source-free encrypted-envelope failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycEncryptedIdentityEnvelopeErrorKind {
    InvalidBinding,
    InvalidCredential,
    InvalidProvisioningMaterial,
    InvalidPath,
    MissingEnvelope,
    AlreadyExists,
    InsecureParent,
    InsecureArtifact,
    UnsupportedEnvelopeVersion,
    MalformedEnvelope,
    WrongCredential,
    IdentityMismatch,
    Io,
    UnsupportedPlatform,
}

impl MycEncryptedIdentityEnvelopeErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBinding => "provider_envelope_binding_invalid",
            Self::InvalidCredential => "provider_envelope_credential_invalid",
            Self::InvalidProvisioningMaterial => "provider_envelope_material_invalid",
            Self::InvalidPath => "provider_envelope_path_invalid",
            Self::MissingEnvelope => "provider_envelope_missing",
            Self::AlreadyExists => "provider_envelope_already_exists",
            Self::InsecureParent => "provider_envelope_parent_insecure",
            Self::InsecureArtifact => "provider_envelope_artifact_insecure",
            Self::UnsupportedEnvelopeVersion => "provider_envelope_version_unsupported",
            Self::MalformedEnvelope => "provider_envelope_malformed",
            Self::WrongCredential => "provider_envelope_credential_rejected",
            Self::IdentityMismatch => "provider_envelope_identity_mismatch",
            Self::Io => "provider_envelope_io_failed",
            Self::UnsupportedPlatform => "provider_envelope_platform_unsupported",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidBinding => "encrypted identity provider binding is invalid",
            Self::InvalidCredential => "encrypted identity credential is invalid",
            Self::InvalidProvisioningMaterial => {
                "encrypted identity provisioning material is invalid"
            }
            Self::InvalidPath => "encrypted identity path is invalid",
            Self::MissingEnvelope => "encrypted identity envelope is missing",
            Self::AlreadyExists => "encrypted identity envelope already exists",
            Self::InsecureParent => "encrypted identity parent is insecure",
            Self::InsecureArtifact => "encrypted identity artifact is insecure",
            Self::UnsupportedEnvelopeVersion => {
                "encrypted identity envelope version is unsupported"
            }
            Self::MalformedEnvelope => "encrypted identity envelope is malformed",
            Self::WrongCredential => "encrypted identity credential was rejected",
            Self::IdentityMismatch => "encrypted identity does not match configuration",
            Self::Io => "encrypted identity storage failed",
            Self::UnsupportedPlatform => "encrypted identity storage is unsupported",
        }
    }
}

/// One source-free encrypted-envelope failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycEncryptedIdentityEnvelopeError {
    kind: MycEncryptedIdentityEnvelopeErrorKind,
}

impl MycEncryptedIdentityEnvelopeError {
    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> MycEncryptedIdentityEnvelopeErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycEncryptedIdentityEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycEncryptedIdentityEnvelopeError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycEncryptedIdentityEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycEncryptedIdentityEnvelopeError {}

const fn envelope_error(
    kind: MycEncryptedIdentityEnvelopeErrorKind,
) -> MycEncryptedIdentityEnvelopeError {
    MycEncryptedIdentityEnvelopeError { kind }
}

/// Sealed zeroizing wrapping credential resolved only by the governed credential boundary.
pub struct MycWrappingCredential(Zeroizing<[u8; WRAPPING_CREDENTIAL_BYTES]>);

/// Non-forgeable proof that owns credential bytes admitted by the governed resolver.
pub(crate) struct MycCredentialResolutionProof {
    credential: Zeroizing<[u8; WRAPPING_CREDENTIAL_BYTES]>,
}

impl fmt::Debug for MycCredentialResolutionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycCredentialResolutionProof([sealed])")
    }
}

impl MycWrappingCredential {
    pub(crate) fn from_resolution(
        proof: MycCredentialResolutionProof,
    ) -> Result<Self, MycEncryptedIdentityEnvelopeError> {
        if proof.credential.iter().all(|byte| *byte == 0) {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential,
            ));
        }
        Ok(Self(proof.credential))
    }

    fn expose<T>(&self, use_credential: impl FnOnce(&[u8; 32]) -> T) -> T {
        use_credential(&self.0)
    }

    fn matches(&self, other: &[u8; 32]) -> bool {
        self.expose(|credential| credential == other)
    }
}

impl fmt::Debug for MycWrappingCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycWrappingCredential([redacted])")
    }
}

/// Explicit single-owner material for one offline create-new provisioning operation.
pub struct MycEncryptedIdentityProvisioningMaterial {
    identity_secret: Zeroizing<[u8; IDENTITY_SECRET_BYTES]>,
    data_key: Zeroizing<[u8; IDENTITY_SECRET_BYTES]>,
    envelope_nonce: [u8; NONCE_BYTES],
    wrapping_nonce: [u8; NONCE_BYTES],
}

impl MycEncryptedIdentityProvisioningMaterial {
    /// Validates the identity secret and exact caller-supplied cryptographic material.
    pub fn new(
        identity_secret: [u8; IDENTITY_SECRET_BYTES],
        data_key: [u8; IDENTITY_SECRET_BYTES],
        envelope_nonce: [u8; NONCE_BYTES],
        wrapping_nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, MycEncryptedIdentityEnvelopeError> {
        let identity_secret = Zeroizing::new(identity_secret);
        let data_key = Zeroizing::new(data_key);
        if SecretKey::from_slice(&identity_secret[..]).is_err()
            || data_key.iter().all(|byte| *byte == 0)
            || envelope_nonce.iter().all(|byte| *byte == 0)
            || wrapping_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InvalidProvisioningMaterial,
            ));
        }
        Ok(Self {
            identity_secret,
            data_key,
            envelope_nonce,
            wrapping_nonce,
        })
    }
}

impl fmt::Debug for MycEncryptedIdentityProvisioningMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycEncryptedIdentityProvisioningMaterial([redacted])")
    }
}

/// One verified zeroizing identity released only after envelope and public-key validation.
pub struct MycDecryptedIdentity {
    secret: Zeroizing<[u8; IDENTITY_SECRET_BYTES]>,
    public_identity: MycProviderPublicIdentity,
}

impl MycDecryptedIdentity {
    /// Returns the independently verified configured public identity.
    #[must_use]
    pub fn public_identity(&self) -> &MycProviderPublicIdentity {
        &self.public_identity
    }
}

impl fmt::Debug for MycDecryptedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycDecryptedIdentity")
            .field("secret", &"[redacted]")
            .field("secret_bytes", &self.secret.len())
            .field("public_identity", &"[redacted]")
            .finish()
    }
}

/// Provisions one new encrypted identity envelope without overwriting any entry.
///
/// A wrapping credential can be obtained only through the separately governed
/// credential-resolution boundary. Ordinary service startup never calls this
/// offline provisioning operation.
pub fn provision_myc_encrypted_identity(
    binding: &MycProviderBinding,
    credential: &MycWrappingCredential,
    material: MycEncryptedIdentityProvisioningMaterial,
) -> Result<MycDecryptedIdentity, MycEncryptedIdentityEnvelopeError> {
    ensure_supported_platform()?;
    validate_encrypted_binding(binding)?;
    validate_requested_path(envelope_path(binding)?)?;
    let expected = binding.expected_identity();
    require_identity_match(&material.identity_secret, expected)?;
    if credential.matches(&material.identity_secret)
        || credential.matches(&material.data_key)
        || material.identity_secret[..] == material.data_key[..]
    {
        return Err(invalid_material());
    }

    let context = envelope_context(binding)?;
    let reference = envelope_reference(binding)?;
    let plaintext = SecretMaterial::from_slice(&material.identity_secret[..])
        .map_err(|_| invalid_material())?;
    let data_key =
        SecretMaterial::from_slice(&material.data_key[..]).map_err(|_| invalid_material())?;
    let sealer = CredentialSealer::new(credential, material.wrapping_nonce);
    let envelope = futures_executor::block_on(EncryptedEnvelope::seal(
        &sealer,
        SealRequest::new(
            reference,
            context.clone(),
            &plaintext,
            SealMaterial::new(data_key, Nonce::new(material.envelope_nonce)),
        ),
    ))
    .map_err(|_| invalid_material())?;
    let encoded = envelope
        .encode()
        .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope))?;
    let verified = futures_executor::block_on(open_decoded_envelope(
        binding, credential, envelope, &context,
    ))?;
    persist_create_new(envelope_path(binding)?, &encoded)?;
    Ok(verified)
}

/// Opens and verifies one existing encrypted identity envelope.
pub fn open_myc_encrypted_identity(
    binding: &MycProviderBinding,
    credential: &MycWrappingCredential,
) -> Result<MycDecryptedIdentity, MycEncryptedIdentityEnvelopeError> {
    ensure_supported_platform()?;
    validate_encrypted_binding(binding)?;
    validate_requested_path(envelope_path(binding)?)?;
    let encoded = read_existing(envelope_path(binding)?)?;
    require_wire_version(&encoded)?;
    let envelope = EncryptedEnvelope::decode(&encoded)
        .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope))?;
    if envelope.version() != ENVELOPE_VERSION {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion,
        ));
    }
    let context = envelope_context(binding)?;
    futures_executor::block_on(open_decoded_envelope(
        binding, credential, envelope, &context,
    ))
}

pub(crate) fn load_resolved_wrapping_credential(
    path: &Path,
) -> Result<MycWrappingCredential, MycEncryptedIdentityEnvelopeError> {
    ensure_supported_platform()?;
    validate_requested_path(path)?;
    let encoded = Zeroizing::new(read_existing_exact(path, WRAPPING_CREDENTIAL_BYTES)?);
    let mut credential = Zeroizing::new([0_u8; WRAPPING_CREDENTIAL_BYTES]);
    credential.copy_from_slice(&encoded);
    MycWrappingCredential::from_resolution(MycCredentialResolutionProof { credential })
}

fn require_wire_version(encoded: &[u8]) -> Result<(), MycEncryptedIdentityEnvelopeError> {
    if encoded.len() < 6 || &encoded[..4] != b"RRS1" {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope,
        ));
    }
    let version = u16::from_be_bytes([encoded[4], encoded[5]]);
    if version != ENVELOPE_VERSION {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion,
        ));
    }
    Ok(())
}

async fn open_decoded_envelope(
    binding: &MycProviderBinding,
    credential: &MycWrappingCredential,
    envelope: EncryptedEnvelope,
    expected_context: &EnvelopeContext,
) -> Result<MycDecryptedIdentity, MycEncryptedIdentityEnvelopeError> {
    if envelope.version() != ENVELOPE_VERSION {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion,
        ));
    }
    let reference = envelope_reference(binding)?;
    if !reference_matches(envelope.reference(), &reference)
        || envelope.context() != Some(expected_context)
    {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope,
        ));
    }
    let opener = CredentialOpener::new(credential);
    let plaintext = envelope
        .open(&opener, expected_context)
        .await
        .map_err(|_| {
            envelope_error(if opener.unwrap_succeeded() {
                MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope
            } else {
                MycEncryptedIdentityEnvelopeErrorKind::WrongCredential
            })
        })?;
    let mut secret = Zeroizing::new([0_u8; IDENTITY_SECRET_BYTES]);
    let exact = plaintext.expose_secret(|bytes| {
        if bytes.len() == IDENTITY_SECRET_BYTES {
            secret.copy_from_slice(bytes);
            true
        } else {
            false
        }
    });
    if !exact {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope,
        ));
    }
    require_identity_match(&secret, binding.expected_identity())?;
    Ok(MycDecryptedIdentity {
        secret,
        public_identity: binding.expected_identity().clone(),
    })
}

fn validate_encrypted_binding(
    binding: &MycProviderBinding,
) -> Result<(), MycEncryptedIdentityEnvelopeError> {
    if binding.kind() != MycProviderKind::EncryptedFile
        || binding.credential_reference().is_none()
        || binding.encrypted_envelope_path().is_none()
    {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding,
        ));
    }
    Ok(())
}

fn envelope_path(binding: &MycProviderBinding) -> Result<&Path, MycEncryptedIdentityEnvelopeError> {
    binding
        .encrypted_envelope_path()
        .ok_or_else(|| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding))
}

fn envelope_reference(
    binding: &MycProviderBinding,
) -> Result<SecretRef, MycEncryptedIdentityEnvelopeError> {
    let credential = binding
        .credential_reference()
        .ok_or_else(|| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding))?;
    let id = SecretId::parse(credential.as_str())
        .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential))?;
    let key_version = KeyVersion::new(1)
        .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential))?;
    Ok(SecretRef::new(id, BackendKind::External, key_version))
}

fn envelope_context(
    binding: &MycProviderBinding,
) -> Result<EnvelopeContext, MycEncryptedIdentityEnvelopeError> {
    let subject = format!(
        "{}:{}",
        binding.role().as_str(),
        binding.expected_identity().as_hex()
    );
    Ok(EnvelopeContext::new(
        EnvelopePurpose::parse(CONTEXT_PURPOSE).map_err(|_| invalid_binding())?,
        EnvelopeSubject::parse(CONTEXT_SUBJECT_TYPE, subject).map_err(|_| invalid_binding())?,
        PayloadSchemaId::parse(CONTEXT_PAYLOAD_SCHEMA).map_err(|_| invalid_binding())?,
    ))
}

fn require_identity_match(
    secret: &[u8; IDENTITY_SECRET_BYTES],
    expected: &MycProviderPublicIdentity,
) -> Result<(), MycEncryptedIdentityEnvelopeError> {
    let secret_key = SecretKey::from_slice(secret).map_err(|_| invalid_material())?;
    let actual = Keys::new(secret_key).public_key().to_hex();
    if actual != expected.as_hex() {
        return Err(envelope_error(
            MycEncryptedIdentityEnvelopeErrorKind::IdentityMismatch,
        ));
    }
    Ok(())
}

const fn invalid_binding() -> MycEncryptedIdentityEnvelopeError {
    envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding)
}

const fn invalid_material() -> MycEncryptedIdentityEnvelopeError {
    envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidProvisioningMaterial)
}

fn reference_matches(actual: &SecretRef, expected: &SecretRef) -> bool {
    actual.id().as_str() == expected.id().as_str()
        && actual.backend() == expected.backend()
        && actual.key_version() == expected.key_version()
}

struct CredentialSealer<'a> {
    credential: &'a MycWrappingCredential,
    nonce: Mutex<Option<[u8; NONCE_BYTES]>>,
}

impl<'a> CredentialSealer<'a> {
    fn new(credential: &'a MycWrappingCredential, nonce: [u8; NONCE_BYTES]) -> Self {
        Self {
            credential,
            nonce: Mutex::new(Some(nonce)),
        }
    }
}

impl KeyWrapping for CredentialSealer<'_> {
    fn wrap<'a>(
        &'a self,
        request: WrapRequest<'a>,
    ) -> BoxFuture<'a, Result<WrappedSecret, radroots_secrets::Error>> {
        Box::pin(async move {
            validate_external_reference(request.reference(), Operation::Wrap)?;
            let nonce = self
                .nonce
                .lock()
                .map_err(|_| backend_failure(Operation::Wrap))?
                .take()
                .ok_or_else(|| backend_failure(Operation::Wrap))?;
            let aad = wrapping_aad(request.reference(), request.context());
            let ciphertext = self.credential.expose(|credential| {
                request.plaintext().expose_secret(|data_key| {
                    XChaCha20Poly1305::new(Key::from_slice(credential)).encrypt(
                        XNonce::from_slice(&nonce),
                        Payload {
                            msg: data_key,
                            aad: &aad,
                        },
                    )
                })
            });
            let ciphertext = ciphertext.map_err(|_| backend_failure(Operation::Wrap))?;
            let mut encoded = Vec::with_capacity(WRAPPED_KEY_BYTES);
            encoded.extend_from_slice(&WRAPPED_KEY_MAGIC);
            encoded.push(WRAPPED_KEY_VERSION);
            encoded.extend_from_slice(&nonce);
            encoded.extend_from_slice(&ciphertext);
            WrappedSecret::from_bytes(encoded)
        })
    }

    fn unwrap<'a>(
        &'a self,
        _request: UnwrapRequest<'a>,
    ) -> BoxFuture<'a, Result<SecretMaterial, radroots_secrets::Error>> {
        Box::pin(async { Err(backend_failure(Operation::Unwrap)) })
    }
}

struct CredentialOpener<'a> {
    credential: &'a MycWrappingCredential,
    unwrap_succeeded: AtomicBool,
}

impl<'a> CredentialOpener<'a> {
    fn new(credential: &'a MycWrappingCredential) -> Self {
        Self {
            credential,
            unwrap_succeeded: AtomicBool::new(false),
        }
    }

    fn unwrap_succeeded(&self) -> bool {
        self.unwrap_succeeded.load(Ordering::Acquire)
    }
}

impl KeyWrapping for CredentialOpener<'_> {
    fn wrap<'a>(
        &'a self,
        _request: WrapRequest<'a>,
    ) -> BoxFuture<'a, Result<WrappedSecret, radroots_secrets::Error>> {
        Box::pin(async { Err(backend_failure(Operation::Wrap)) })
    }

    fn unwrap<'a>(
        &'a self,
        request: UnwrapRequest<'a>,
    ) -> BoxFuture<'a, Result<SecretMaterial, radroots_secrets::Error>> {
        Box::pin(async move {
            validate_external_reference(request.reference(), Operation::Unwrap)?;
            let encoded = request.wrapped().as_bytes();
            if encoded.len() != WRAPPED_KEY_BYTES
                || encoded[..WRAPPED_KEY_MAGIC.len()] != WRAPPED_KEY_MAGIC
                || encoded[WRAPPED_KEY_MAGIC.len()] != WRAPPED_KEY_VERSION
            {
                return Err(backend_failure(Operation::Unwrap));
            }
            let nonce_start = WRAPPED_KEY_MAGIC.len() + 1;
            let nonce_end = nonce_start + NONCE_BYTES;
            let aad = wrapping_aad(request.reference(), request.context());
            let plaintext = self.credential.expose(|credential| {
                XChaCha20Poly1305::new(Key::from_slice(credential)).decrypt(
                    XNonce::from_slice(&encoded[nonce_start..nonce_end]),
                    Payload {
                        msg: &encoded[nonce_end..],
                        aad: &aad,
                    },
                )
            });
            let plaintext =
                Zeroizing::new(plaintext.map_err(|_| backend_failure(Operation::Unwrap))?);
            let material = SecretMaterial::from_slice(&plaintext)?;
            self.unwrap_succeeded.store(true, Ordering::Release);
            Ok(material)
        })
    }
}

fn wrapping_aad(reference: &SecretRef, context: &EnvelopeContext) -> Vec<u8> {
    let id = reference.id().as_str().as_bytes();
    let mut aad = Vec::with_capacity(WRAPPING_AAD_DOMAIN.len() + 2 + id.len() + 4 + 32);
    aad.extend_from_slice(WRAPPING_AAD_DOMAIN);
    aad.extend_from_slice(
        &u16::try_from(id.len())
            .unwrap_or_else(|_| unreachable!("validated secret reference fits u16"))
            .to_be_bytes(),
    );
    aad.extend_from_slice(id);
    aad.extend_from_slice(&reference.key_version().get().to_be_bytes());
    aad.extend_from_slice(&context.authentication_digest());
    aad
}

fn validate_external_reference(
    reference: &SecretRef,
    operation: Operation,
) -> Result<(), radroots_secrets::Error> {
    if reference.backend() != BackendKind::External || reference.key_version().get() != 1 {
        return Err(backend_failure(operation));
    }
    Ok(())
}

const fn backend_failure(operation: Operation) -> radroots_secrets::Error {
    radroots_secrets::Error::BackendFailure {
        backend: BackendKind::External,
        operation,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fchmod, fstat, open, openat, unlinkat};
    use rustix::process::geteuid;

    use super::{
        MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES, MycEncryptedIdentityEnvelopeError,
        MycEncryptedIdentityEnvelopeErrorKind, envelope_error,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    struct ArtifactPath {
        parent_path: PathBuf,
        name: OsString,
    }

    impl ArtifactPath {
        fn parse(path: &Path) -> Result<Self, MycEncryptedIdentityEnvelopeError> {
            if !path.is_absolute()
                || path.as_os_str().as_bytes().len() > 4_096
                || path.components().any(|component| {
                    !matches!(component, Component::RootDir | Component::Normal(_))
                })
            {
                return Err(envelope_error(
                    MycEncryptedIdentityEnvelopeErrorKind::InvalidPath,
                ));
            }
            let name = match path.components().next_back() {
                Some(Component::Normal(name)) if !name.as_bytes().is_empty() => name.to_os_string(),
                _ => {
                    return Err(envelope_error(
                        MycEncryptedIdentityEnvelopeErrorKind::InvalidPath,
                    ));
                }
            };
            let parent_path = path
                .parent()
                .filter(|parent| parent.is_absolute())
                .ok_or_else(|| {
                    envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InvalidPath)
                })?;
            Ok(Self {
                parent_path: parent_path.to_path_buf(),
                name,
            })
        }
    }

    pub(super) fn validate_requested_path(
        path: &Path,
    ) -> Result<(), MycEncryptedIdentityEnvelopeError> {
        ArtifactPath::parse(path).map(|_| ())
    }

    pub(super) fn persist_create_new(
        path: &Path,
        encoded: &[u8],
    ) -> Result<(), MycEncryptedIdentityEnvelopeError> {
        if encoded.is_empty() || encoded.len() > MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope,
            ));
        }
        let path = ArtifactPath::parse(path)?;
        let parent = open_parent(&path.parent_path, true)?;
        let parent_identity = directory_identity(&parent, true)?;
        let descriptor = openat(
            &parent,
            &path.name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            envelope_error(if source == rustix::io::Errno::EXIST {
                MycEncryptedIdentityEnvelopeErrorKind::AlreadyExists
            } else {
                MycEncryptedIdentityEnvelopeErrorKind::Io
            })
        })?;
        let mut file = File::from(descriptor);
        let identity = owned_file_identity(&file)?;
        let result = (|| {
            fchmod(&file, Mode::RUSR | Mode::WUSR)
                .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::Io))?;
            file.write_all(encoded)
                .and_then(|()| file.sync_all())
                .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::Io))?;
            file_identity(
                &file,
                Some(encoded.len()),
                MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES,
            )?;
            validate_current_binding(
                &path,
                &parent,
                parent_identity,
                &file,
                identity,
                encoded.len(),
                MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES,
            )?;
            parent
                .sync_all()
                .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::Io))?;
            validate_current_binding(
                &path,
                &parent,
                parent_identity,
                &file,
                identity,
                encoded.len(),
                MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES,
            )
        })();
        if result.is_err() {
            cleanup_owned(&parent, &path.name, identity);
        }
        result
    }

    pub(super) fn read_existing(path: &Path) -> Result<Vec<u8>, MycEncryptedIdentityEnvelopeError> {
        read_existing_bounded(path, MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES, None)
    }

    pub(super) fn read_existing_exact(
        path: &Path,
        expected_length: usize,
    ) -> Result<Vec<u8>, MycEncryptedIdentityEnvelopeError> {
        read_existing_bounded(path, expected_length, Some(expected_length))
    }

    fn read_existing_bounded(
        path: &Path,
        maximum_length: usize,
        expected_length: Option<usize>,
    ) -> Result<Vec<u8>, MycEncryptedIdentityEnvelopeError> {
        let path = ArtifactPath::parse(path)?;
        let parent = open_parent(&path.parent_path, false)?;
        let parent_identity = directory_identity(&parent, false)?;
        let descriptor = openat(
            &parent,
            &path.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| {
            envelope_error(if source == rustix::io::Errno::NOENT {
                MycEncryptedIdentityEnvelopeErrorKind::MissingEnvelope
            } else if source == rustix::io::Errno::LOOP {
                MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact
            } else {
                MycEncryptedIdentityEnvelopeErrorKind::Io
            })
        })?;
        let mut file = File::from(descriptor);
        let status = fstat(&file)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?;
        let length = validate_file_status(&status, expected_length, maximum_length)?;
        let identity = status_identity(
            &status,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
        )?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::Io))?;
        let mut encoded = Vec::with_capacity(length);
        std::io::Read::by_ref(&mut file)
            .take(u64::try_from(length).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::Io))?;
        if encoded.len() != length {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
            ));
        }
        validate_current_binding(
            &path,
            &parent,
            parent_identity,
            &file,
            identity,
            length,
            maximum_length,
        )?;
        Ok(encoded)
    }

    fn open_parent(path: &Path, writable: bool) -> Result<File, MycEncryptedIdentityEnvelopeError> {
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InvalidPath,
            ));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut parent =
            File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|_| {
                envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureParent)
            })?);
        for component in components {
            let Component::Normal(name) = component else {
                return Err(envelope_error(
                    MycEncryptedIdentityEnvelopeErrorKind::InvalidPath,
                ));
            };
            parent = File::from(openat(&parent, name, flags, Mode::empty()).map_err(|_| {
                envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureParent)
            })?);
        }
        directory_identity(&parent, writable)?;
        Ok(parent)
    }

    fn directory_identity(
        directory: &File,
        writable: bool,
    ) -> Result<Identity, MycEncryptedIdentityEnvelopeError> {
        let status = fstat(directory)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureParent))?;
        let mode = native_mode(status.st_mode);
        let allowed_mode = if writable {
            mode & 0o777 == 0o700
        } else {
            matches!(mode & 0o777, 0o500 | 0o700)
        };
        if !FileType::from_raw_mode(status.st_mode).is_dir()
            || status.st_uid != geteuid().as_raw()
            || !allowed_mode
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureParent,
            ));
        }
        status_identity(
            &status,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureParent,
        )
    }

    fn file_identity(
        file: &File,
        expected_length: Option<usize>,
        maximum_length: usize,
    ) -> Result<Identity, MycEncryptedIdentityEnvelopeError> {
        let status = fstat(file)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?;
        validate_file_status(&status, expected_length, maximum_length)?;
        status_identity(
            &status,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
        )
    }

    fn owned_file_identity(file: &File) -> Result<Identity, MycEncryptedIdentityEnvelopeError> {
        let status = fstat(file)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?;
        let mode = native_mode(status.st_mode) & 0o777;
        let length = usize::try_from(status.st_size)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?;
        if !FileType::from_raw_mode(status.st_mode).is_file()
            || native_link_count(status.st_nlink) != 1
            || status.st_uid != geteuid().as_raw()
            || !matches!(mode, 0o400 | 0o600)
            || length > MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
            ));
        }
        status_identity(
            &status,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
        )
    }

    fn validate_file_status(
        status: &rustix::fs::Stat,
        expected_length: Option<usize>,
        maximum_length: usize,
    ) -> Result<usize, MycEncryptedIdentityEnvelopeError> {
        let mode = native_mode(status.st_mode) & 0o777;
        let length = usize::try_from(status.st_size)
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?;
        if !FileType::from_raw_mode(status.st_mode).is_file()
            || native_link_count(status.st_nlink) != 1
            || status.st_uid != geteuid().as_raw()
            || !matches!(mode, 0o400 | 0o600)
            || length == 0
            || length > maximum_length
            || expected_length.is_some_and(|expected| expected != length)
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
            ));
        }
        Ok(length)
    }

    fn validate_current_binding(
        path: &ArtifactPath,
        held_parent: &File,
        expected_parent: Identity,
        held_file: &File,
        expected_file: Identity,
        expected_length: usize,
        maximum_length: usize,
    ) -> Result<(), MycEncryptedIdentityEnvelopeError> {
        let current_parent = open_parent(&path.parent_path, false)?;
        if directory_identity(held_parent, false)? != expected_parent
            || directory_identity(&current_parent, false)? != expected_parent
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureParent,
            ));
        }
        let current_file = File::from(
            openat(
                &current_parent,
                &path.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| envelope_error(MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact))?,
        );
        if file_identity(held_file, Some(expected_length), maximum_length)? != expected_file
            || file_identity(&current_file, Some(expected_length), maximum_length)? != expected_file
        {
            return Err(envelope_error(
                MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
            ));
        }
        Ok(())
    }

    fn cleanup_owned(parent: &File, name: &std::ffi::OsStr, expected: Identity) {
        let Ok(current) = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) else {
            return;
        };
        let current = File::from(current);
        if owned_file_identity(&current) == Ok(expected)
            && unlinkat(parent, name, AtFlags::empty()).is_ok()
        {
            let _ = parent.sync_all();
        }
    }

    fn status_identity(
        status: &rustix::fs::Stat,
        invalid_kind: MycEncryptedIdentityEnvelopeErrorKind,
    ) -> Result<Identity, MycEncryptedIdentityEnvelopeError> {
        Ok(Identity {
            device: native_device(status.st_dev).map_err(|_| envelope_error(invalid_kind))?,
            inode: status.st_ino,
        })
    }

    fn native_mode<T: Into<u32>>(raw: T) -> u32 {
        raw.into()
    }

    fn native_link_count<T: Into<u64>>(raw: T) -> u64 {
        raw.into()
    }

    fn native_device<T: TryInto<u64>>(raw: T) -> Result<u64, T::Error> {
        raw.try_into()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
use native::{persist_create_new, read_existing, read_existing_exact, validate_requested_path};

#[cfg(any(target_os = "linux", target_os = "macos"))]
const fn ensure_supported_platform() -> Result<(), MycEncryptedIdentityEnvelopeError> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_requested_path(_path: &Path) -> Result<(), MycEncryptedIdentityEnvelopeError> {
    Err(envelope_error(
        MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn ensure_supported_platform() -> Result<(), MycEncryptedIdentityEnvelopeError> {
    Err(envelope_error(
        MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn persist_create_new(
    _path: &Path,
    _encoded: &[u8],
) -> Result<(), MycEncryptedIdentityEnvelopeError> {
    Err(envelope_error(
        MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_existing(_path: &Path) -> Result<Vec<u8>, MycEncryptedIdentityEnvelopeError> {
    Err(envelope_error(
        MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_existing_exact(
    _path: &Path,
    _expected_length: usize,
) -> Result<Vec<u8>, MycEncryptedIdentityEnvelopeError> {
    Err(envelope_error(
        MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::fs;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use sha2::{Digest, Sha256};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::{MycConfigProfile, MycProviderRole, parse_myc_config_v1};

    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn bytes(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn identity_secret() -> [u8; 32] {
        let mut candidate = bytes("radroots.myc.test-only.identity-secret.v1");
        while SecretKey::from_slice(&candidate).is_err() {
            candidate = Sha256::digest(candidate).into();
        }
        candidate
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn expected_identity() -> String {
        Keys::new(SecretKey::from_slice(&identity_secret()).expect("test key"))
            .public_key()
            .to_hex()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn binding(path: &Path) -> MycProviderBinding {
        let source = CONFIG
            .replace(
                "/var/lib/radroots/services/myc/primary/secrets/transport.identity.ncrypt",
                path.to_str().expect("UTF-8 test path"),
            )
            .replace(
                "4444444444444444444444444444444444444444444444444444444444444444",
                &expected_identity(),
            );
        parse_myc_config_v1(source.as_bytes(), MycConfigProfile::Production)
            .expect("test config")
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding")
            .clone()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn credential(label: &str) -> MycWrappingCredential {
        MycWrappingCredential::from_resolution(MycCredentialResolutionProof {
            credential: Zeroizing::new(bytes(label)),
        })
        .expect("test credential")
    }

    fn material_for(identity: [u8; 32]) -> MycEncryptedIdentityProvisioningMaterial {
        MycEncryptedIdentityProvisioningMaterial::new(
            identity,
            bytes("radroots.myc.test-only.data-key.v1"),
            [7; 24],
            [9; 24],
        )
        .expect("test material")
    }

    fn material() -> MycEncryptedIdentityProvisioningMaterial {
        material_for(identity_secret())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn different_identity_secret() -> [u8; 32] {
        let mut candidate = bytes("radroots.myc.test-only.different-identity-secret.v1");
        while SecretKey::from_slice(&candidate).is_err() {
            candidate = Sha256::digest(candidate).into();
        }
        candidate
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn secure_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secure mode");
        directory
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn create_new_round_trip_binds_context_identity_and_permissions() {
        let directory = secure_directory();
        let path = directory.path().join("transport.identity.ncrypt");
        let binding = binding(&path);
        let credential = credential("radroots.myc.test-only.wrapping.v1");
        let provisioned =
            provision_myc_encrypted_identity(&binding, &credential, material()).expect("provision");
        assert_eq!(provisioned.public_identity().as_hex(), expected_identity());
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        let reopened = open_myc_encrypted_identity(&binding, &credential).expect("open");
        assert_eq!(reopened.public_identity().as_hex(), expected_identity());
        let names = fs::read_dir(directory.path())
            .expect("inventory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("transport.identity.ncrypt")]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn collisions_wrong_credentials_and_identity_mismatch_fail_safely() {
        let directory = secure_directory();
        let path = directory.path().join("transport.identity.ncrypt");
        let binding = binding(&path);
        let wrong_credential = credential("radroots.myc.test-only.wrong-wrapping.v1");
        let credential = credential("radroots.myc.test-only.wrapping.v1");
        assert_eq!(
            provision_myc_encrypted_identity(
                &binding,
                &credential,
                material_for(different_identity_secret()),
            )
            .expect_err("wrong identity")
            .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::IdentityMismatch
        );
        assert!(!path.exists());
        provision_myc_encrypted_identity(&binding, &credential, material()).expect("provision");
        let before = fs::read(&path).expect("before");
        assert_eq!(
            provision_myc_encrypted_identity(&binding, &credential, material())
                .expect_err("collision")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).expect("after"), before);
        assert_eq!(
            open_myc_encrypted_identity(&binding, &wrong_credential)
                .expect_err("wrong credential")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::WrongCredential
        );

        let wrong_expected = CONFIG.replace(
            "/var/lib/radroots/services/myc/primary/secrets/transport.identity.ncrypt",
            path.to_str().expect("UTF-8 test path"),
        );
        let wrong_binding =
            parse_myc_config_v1(wrong_expected.as_bytes(), MycConfigProfile::Production)
                .expect("wrong expected config")
                .provider_contract()
                .binding(MycProviderRole::Transport)
                .expect("transport")
                .clone();
        assert_eq!(
            open_myc_encrypted_identity(&wrong_binding, &credential)
                .expect_err("context mismatch")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn malformed_oversized_and_insecure_artifacts_fail_before_secret_release() {
        let directory = secure_directory();
        let path = directory.path().join("transport.identity.ncrypt");
        let binding = binding(&path);
        let credential = credential("radroots.myc.test-only.wrapping.v1");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("missing")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::MissingEnvelope
        );
        provision_myc_encrypted_identity(&binding, &credential, material()).expect("provision");
        let valid = fs::read(&path).expect("valid envelope");
        let second_link = directory.path().join("second-link.ncrypt");
        fs::hard_link(&path, &second_link).expect("hard link");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("multiple links")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact
        );
        fs::remove_file(&second_link).expect("remove hard link");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500))
            .expect("read-only parent mode");
        open_myc_encrypted_identity(&binding, &credential).expect("0500 parent is owner-only");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restore parent mode");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("read-only mode");
        open_myc_encrypted_identity(&binding, &credential).expect("0400 is owner-only");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("writable mode");
        let mut tampered = valid.clone();
        *tampered.last_mut().expect("ciphertext byte") ^= 1;
        fs::write(&path, &tampered).expect("tamper ciphertext");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("tampered ciphertext")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope
        );
        let mut unsupported = valid;
        unsupported[4..6].copy_from_slice(&1_u16.to_be_bytes());
        fs::write(&path, &unsupported).expect("unsupported version");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("unsupported version")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion
        );
        fs::remove_file(&path).expect("remove version vector");
        fs::write(&path, b"not-an-envelope").expect("malformed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("malformed")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope
        );
        fs::remove_file(&path).expect("remove malformed");
        fs::write(
            &path,
            vec![0_u8; MYC_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES + 1],
        )
        .expect("oversized");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("oversized")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("insecure mode");
        assert_eq!(
            open_myc_encrypted_identity(&binding, &credential)
                .expect_err("permissions")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn symlink_and_insecure_parent_are_rejected_without_mutation() {
        let directory = secure_directory();
        let target = directory.path().join("target");
        fs::write(&target, b"preserve").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        let path = directory.path().join("transport.identity.ncrypt");
        symlink(&target, &path).expect("symlink");
        let provider_binding = binding(&path);
        let credential = credential("radroots.myc.test-only.wrapping.v1");
        assert_eq!(
            open_myc_encrypted_identity(&provider_binding, &credential)
                .expect_err("symlink")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact
        );
        assert_eq!(fs::read(&target).expect("preserved"), b"preserve");
        fs::remove_file(&path).expect("remove symlink");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .expect("insecure parent");
        assert_eq!(
            provision_myc_encrypted_identity(&provider_binding, &credential, material())
                .expect_err("insecure parent")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureParent
        );
        assert!(!path.exists());

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restore parent mode");
        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent");
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
            .expect("real parent mode");
        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("parent symlink");
        let linked_path = linked_parent.join("transport.identity.ncrypt");
        let linked_binding = binding(&linked_path);
        assert_eq!(
            provision_myc_encrypted_identity(&linked_binding, &credential, material())
                .expect_err("symlinked ancestor")
                .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InsecureParent
        );
        assert!(!real_parent.join("transport.identity.ncrypt").exists());
    }

    #[test]
    fn protected_models_and_errors_are_redacted_and_source_free() {
        let proof = MycCredentialResolutionProof {
            credential: Zeroizing::new(bytes("radroots.myc.test-only.wrapping.v1")),
        };
        assert_eq!(
            format!("{proof:?}"),
            "MycCredentialResolutionProof([sealed])"
        );
        let credential = MycWrappingCredential::from_resolution(proof).expect("test credential");
        let material = material();
        assert_eq!(
            format!("{credential:?}"),
            "MycWrappingCredential([redacted])"
        );
        assert_eq!(
            format!("{material:?}"),
            "MycEncryptedIdentityProvisioningMaterial([redacted])"
        );
        for kind in [
            MycEncryptedIdentityEnvelopeErrorKind::InvalidBinding,
            MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential,
            MycEncryptedIdentityEnvelopeErrorKind::InvalidProvisioningMaterial,
            MycEncryptedIdentityEnvelopeErrorKind::InvalidPath,
            MycEncryptedIdentityEnvelopeErrorKind::MissingEnvelope,
            MycEncryptedIdentityEnvelopeErrorKind::AlreadyExists,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureParent,
            MycEncryptedIdentityEnvelopeErrorKind::InsecureArtifact,
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedEnvelopeVersion,
            MycEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope,
            MycEncryptedIdentityEnvelopeErrorKind::WrongCredential,
            MycEncryptedIdentityEnvelopeErrorKind::IdentityMismatch,
            MycEncryptedIdentityEnvelopeErrorKind::Io,
            MycEncryptedIdentityEnvelopeErrorKind::UnsupportedPlatform,
        ] {
            let error = envelope_error(kind);
            assert!(!error.code().is_empty());
            assert!(!error.to_string().contains("test-only"));
            assert!(error.source().is_none());
        }
        assert_eq!(
            MycWrappingCredential::from_resolution(MycCredentialResolutionProof {
                credential: Zeroizing::new([0; 32]),
            })
            .expect_err("zero credential")
            .kind(),
            MycEncryptedIdentityEnvelopeErrorKind::InvalidCredential
        );
        assert!(
            MycEncryptedIdentityProvisioningMaterial::new([0; 32], [1; 32], [1; 24], [2; 24])
                .is_err()
        );
    }
}
