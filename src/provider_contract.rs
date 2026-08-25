//! Typed, side-effect-free Myc signer-provider contract.

use core::fmt;
use std::error::Error;
use std::path::PathBuf;

use nostr::PublicKey;
use radroots_runtime_paths::ServiceCredentialArtifactName;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Exact supported signer-provider contract version.
pub const MYC_PROVIDER_CONTRACT_VERSION: u32 = 1;
/// Maximum semantic provider input admitted before any wire encoding.
pub const MYC_PROVIDER_INPUT_MAX_BYTES: usize = 262_144;
/// Maximum untrusted provider output admitted before semantic verification.
pub const MYC_PROVIDER_OUTPUT_MAX_BYTES: usize = 1_048_576;
pub(crate) const MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES: usize = 65_536 - 128;
/// Maximum configured local-signer request deadline.
pub const MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS: u64 = 30_000;
/// Maximum configured local-signer request body.
pub const MYC_PROVIDER_REQUEST_MAX_BYTES: u64 = 65_536;
/// Maximum configured local-signer response body.
pub const MYC_PROVIDER_RESPONSE_MAX_BYTES: u64 = 1_048_576;
/// Maximum configured local-signer concurrent operations.
pub const MYC_PROVIDER_CONCURRENCY_MAX: u32 = 64;

/// One explicit Myc identity role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycProviderRole {
    Transport,
    User,
    Discovery,
}

impl MycProviderRole {
    /// Returns the exact contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::User => "user",
            Self::Discovery => "discovery",
        }
    }

    const fn config_pointer(self) -> &'static str {
        match self {
            Self::Transport => "/identity/transport",
            Self::User => "/identity/user",
            Self::Discovery => "/identity/discovery/binding",
        }
    }
}

/// The only supported provider implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycProviderKind {
    EncryptedFile,
    LocalSigner,
}

impl MycProviderKind {
    /// Returns the exact configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedFile => "encrypted_file",
            Self::LocalSigner => "local_signer",
        }
    }
}

/// The complete closed signer-provider capability inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycProviderCapability {
    Describe,
    PublicIdentity,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
}

impl MycProviderCapability {
    pub(crate) const ALL: [Self; 7] = [
        Self::Describe,
        Self::PublicIdentity,
        Self::SignEvent,
        Self::Nip04Encrypt,
        Self::Nip04Decrypt,
        Self::Nip44Encrypt,
        Self::Nip44Decrypt,
    ];

    /// Returns the exact protocol spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::PublicIdentity => "public_identity",
            Self::SignEvent => "sign_event",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Describe => 1 << 0,
            Self::PublicIdentity => 1 << 1,
            Self::SignEvent => 1 << 2,
            Self::Nip04Encrypt => 1 << 3,
            Self::Nip04Decrypt => 1 << 4,
            Self::Nip44Encrypt => 1 << 5,
            Self::Nip44Decrypt => 1 << 6,
        }
    }
}

/// One duplicate-free bounded capability set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycProviderCapabilitySet(u8);

impl MycProviderCapabilitySet {
    /// Constructs a set and rejects duplicate or empty inventories.
    pub fn new(capabilities: &[MycProviderCapability]) -> Result<Self, MycProviderContractError> {
        if capabilities.is_empty() || capabilities.len() > MycProviderCapability::ALL.len() {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidCapabilitySet,
            ));
        }
        let mut bits = 0_u8;
        for capability in capabilities {
            let bit = capability.bit();
            if bits & bit != 0 {
                return Err(contract_error(
                    MycProviderContractErrorKind::InvalidCapabilitySet,
                ));
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }

    pub(crate) const fn for_role(role: MycProviderRole) -> Self {
        let common =
            MycProviderCapability::Describe.bit() | MycProviderCapability::PublicIdentity.bit();
        match role {
            MycProviderRole::Transport => Self(
                common
                    | MycProviderCapability::SignEvent.bit()
                    | MycProviderCapability::Nip04Encrypt.bit()
                    | MycProviderCapability::Nip04Decrypt.bit()
                    | MycProviderCapability::Nip44Encrypt.bit()
                    | MycProviderCapability::Nip44Decrypt.bit(),
            ),
            MycProviderRole::User => Self(
                common
                    | MycProviderCapability::SignEvent.bit()
                    | MycProviderCapability::Nip04Encrypt.bit()
                    | MycProviderCapability::Nip04Decrypt.bit()
                    | MycProviderCapability::Nip44Encrypt.bit()
                    | MycProviderCapability::Nip44Decrypt.bit(),
            ),
            MycProviderRole::Discovery => Self(common | MycProviderCapability::SignEvent.bit()),
        }
    }

    /// Returns whether this set contains the capability.
    #[must_use]
    pub const fn contains(self, capability: MycProviderCapability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Returns the exact number of capabilities.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterates in the exact governed inventory order.
    pub fn iter(self) -> impl Iterator<Item = MycProviderCapability> {
        MycProviderCapability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}

impl fmt::Debug for MycProviderCapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

/// The role-assignment identity carried by every provider call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycProviderInstanceId {
    Transport,
    User,
    Discovery,
}

impl MycProviderInstanceId {
    /// Returns the exact stable instance spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::User => "user",
            Self::Discovery => "discovery",
        }
    }
}

impl From<MycProviderRole> for MycProviderInstanceId {
    fn from(role: MycProviderRole) -> Self {
        match role {
            MycProviderRole::Transport => Self::Transport,
            MycProviderRole::User => Self::User,
            MycProviderRole::Discovery => Self::Discovery,
        }
    }
}

/// One canonical expected or peer Nostr public identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MycProviderPublicIdentity(Box<str>);

impl MycProviderPublicIdentity {
    /// Validates exact lowercase 32-byte x-only public-key hex before allocation.
    pub fn new(value: &str) -> Result<Self, MycProviderContractError> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidIdentity,
            ));
        }
        let public_key = PublicKey::from_hex(value)
            .map_err(|_| contract_error(MycProviderContractErrorKind::InvalidIdentity))?;
        public_key
            .xonly()
            .map_err(|_| contract_error(MycProviderContractErrorKind::InvalidIdentity))?;
        if public_key.to_hex() != value {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidIdentity,
            ));
        }
        Ok(Self(value.into()))
    }

    /// Returns the exact canonical public-key hex.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MycProviderPublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycProviderPublicIdentity([redacted])")
    }
}

/// One validated logical wrapping-credential reference.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MycProviderCredentialReference(ServiceCredentialArtifactName);

impl MycProviderCredentialReference {
    /// Validates the shared service credential-artifact vocabulary.
    pub fn new(value: &str) -> Result<Self, MycProviderContractError> {
        ServiceCredentialArtifactName::new(value)
            .map(Self)
            .map_err(|_| contract_error(MycProviderContractErrorKind::InvalidCredentialReference))
    }

    /// Returns the exact logical reference, never credential material.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for MycProviderCredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycProviderCredentialReference([redacted])")
    }
}

/// Validated local-signer transport limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycLocalSignerLimits {
    request_deadline_ms: u64,
    request_max_bytes: u64,
    response_max_bytes: u64,
    concurrency: u32,
}

impl MycLocalSignerLimits {
    /// Validates every configured transport resource limit.
    pub fn new(
        request_deadline_ms: u64,
        request_max_bytes: u64,
        response_max_bytes: u64,
        concurrency: u32,
    ) -> Result<Self, MycProviderContractError> {
        if !(1..=MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS).contains(&request_deadline_ms)
            || !(1..=MYC_PROVIDER_REQUEST_MAX_BYTES).contains(&request_max_bytes)
            || !(1..=MYC_PROVIDER_RESPONSE_MAX_BYTES).contains(&response_max_bytes)
            || !(1..=MYC_PROVIDER_CONCURRENCY_MAX).contains(&concurrency)
        {
            return Err(contract_error(MycProviderContractErrorKind::InvalidLimits));
        }
        Ok(Self {
            request_deadline_ms,
            request_max_bytes,
            response_max_bytes,
            concurrency,
        })
    }

    #[must_use]
    pub const fn request_deadline_ms(self) -> u64 {
        self.request_deadline_ms
    }

    #[must_use]
    pub const fn request_max_bytes(self) -> u64 {
        self.request_max_bytes
    }

    #[must_use]
    pub const fn response_max_bytes(self) -> u64 {
        self.response_max_bytes
    }

    #[must_use]
    pub const fn concurrency(self) -> u32 {
        self.concurrency
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ProviderLocation {
    EncryptedFile {
        envelope_path: PathBuf,
        credential_reference: MycProviderCredentialReference,
    },
    LocalSigner {
        socket_path: PathBuf,
        limits: MycLocalSignerLimits,
    },
}

/// One immutable provider assignment for one explicit identity role.
#[derive(Clone, PartialEq, Eq)]
pub struct MycProviderBinding {
    role: MycProviderRole,
    instance: MycProviderInstanceId,
    kind: MycProviderKind,
    expected_identity: MycProviderPublicIdentity,
    required_capabilities: MycProviderCapabilitySet,
    location: ProviderLocation,
}

impl MycProviderBinding {
    #[must_use]
    pub const fn role(&self) -> MycProviderRole {
        self.role
    }

    #[must_use]
    pub const fn instance(&self) -> MycProviderInstanceId {
        self.instance
    }

    #[must_use]
    pub const fn kind(&self) -> MycProviderKind {
        self.kind
    }

    #[must_use]
    pub const fn expected_identity(&self) -> &MycProviderPublicIdentity {
        &self.expected_identity
    }

    #[must_use]
    pub const fn required_capabilities(&self) -> MycProviderCapabilitySet {
        self.required_capabilities
    }

    #[must_use]
    pub const fn credential_reference(&self) -> Option<&MycProviderCredentialReference> {
        match &self.location {
            ProviderLocation::EncryptedFile {
                credential_reference,
                ..
            } => Some(credential_reference),
            ProviderLocation::LocalSigner { .. } => None,
        }
    }

    #[must_use]
    pub const fn local_signer_limits(&self) -> Option<MycLocalSignerLimits> {
        match &self.location {
            ProviderLocation::EncryptedFile { .. } => None,
            ProviderLocation::LocalSigner { limits, .. } => Some(*limits),
        }
    }

    pub(crate) fn encrypted_envelope_path(&self) -> Option<&std::path::Path> {
        match &self.location {
            ProviderLocation::EncryptedFile { envelope_path, .. } => Some(envelope_path),
            ProviderLocation::LocalSigner { .. } => None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn local_signer_socket_path(&self) -> Option<&std::path::Path> {
        match &self.location {
            ProviderLocation::LocalSigner { socket_path, .. } => Some(socket_path),
            ProviderLocation::EncryptedFile { .. } => None,
        }
    }

    fn location_is_valid(&self) -> bool {
        match &self.location {
            ProviderLocation::EncryptedFile {
                envelope_path,
                credential_reference,
            } => envelope_path.is_absolute() && !credential_reference.as_str().is_empty(),
            ProviderLocation::LocalSigner {
                socket_path,
                limits,
            } => socket_path.is_absolute() && limits.concurrency() > 0,
        }
    }
}

impl fmt::Debug for MycProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderBinding")
            .field("role", &self.role)
            .field("instance", &self.instance)
            .field("kind", &self.kind)
            .field("expected_identity", &"[redacted]")
            .field("required_capabilities", &self.required_capabilities)
            .field("location", &"[redacted]")
            .field("location_valid", &self.location_is_valid())
            .finish()
    }
}

/// The exact provider assignments derived from one admitted v1 configuration.
#[derive(PartialEq, Eq)]
pub struct MycProviderContract {
    bindings: Box<[MycProviderBinding]>,
}

impl MycProviderContract {
    pub(crate) fn from_normalized(document: &Value) -> Result<Self, MycProviderContractError> {
        let mut bindings = Vec::with_capacity(3);
        bindings.push(binding_from_config(document, MycProviderRole::Transport)?);
        bindings.push(binding_from_config(document, MycProviderRole::User)?);
        if json_bool(document, "/identity/discovery/enabled")? {
            bindings.push(binding_from_config(document, MycProviderRole::Discovery)?);
        }
        if bindings.iter().enumerate().any(|(index, binding)| {
            bindings[index + 1..]
                .iter()
                .any(|other| binding.expected_identity == other.expected_identity)
        }) {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidIdentity,
            ));
        }
        Ok(Self {
            bindings: bindings.into_boxed_slice(),
        })
    }

    /// Returns all enabled bindings in transport, user, discovery order.
    #[must_use]
    pub fn bindings(&self) -> &[MycProviderBinding] {
        &self.bindings
    }

    /// Returns the binding for one enabled role.
    #[must_use]
    pub fn binding(&self, role: MycProviderRole) -> Option<&MycProviderBinding> {
        self.bindings.iter().find(|binding| binding.role == role)
    }
}

impl fmt::Debug for MycProviderContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderContract")
            .field("version", &MYC_PROVIDER_CONTRACT_VERSION)
            .field("binding_count", &self.bindings.len())
            .field(
                "roles",
                &self
                    .bindings
                    .iter()
                    .map(|binding| binding.role)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn binding_from_config(
    document: &Value,
    role: MycProviderRole,
) -> Result<MycProviderBinding, MycProviderContractError> {
    let prefix = role.config_pointer();
    let provider = json_string(document, &format!("{prefix}/provider"))?;
    let expected_identity = MycProviderPublicIdentity::new(json_string(
        document,
        &format!("{prefix}/expected_public_key"),
    )?)?;
    let (kind, location) = match provider {
        "encrypted_file" => {
            let envelope_path =
                PathBuf::from(json_string(document, &format!("{prefix}/envelope_path"))?);
            if !envelope_path.is_absolute() {
                return Err(contract_error(
                    MycProviderContractErrorKind::InvalidConfiguration,
                ));
            }
            let credential_reference = MycProviderCredentialReference::new(json_string(
                document,
                &format!("{prefix}/credential_reference"),
            )?)?;
            (
                MycProviderKind::EncryptedFile,
                ProviderLocation::EncryptedFile {
                    envelope_path,
                    credential_reference,
                },
            )
        }
        "local_signer" => {
            let socket_path =
                PathBuf::from(json_string(document, &format!("{prefix}/socket_path"))?);
            if !socket_path.is_absolute() {
                return Err(contract_error(
                    MycProviderContractErrorKind::InvalidConfiguration,
                ));
            }
            let limits = MycLocalSignerLimits::new(
                json_u64(document, &format!("{prefix}/request_deadline_ms"))?,
                json_u64(document, &format!("{prefix}/request_max_bytes"))?,
                json_u64(document, &format!("{prefix}/response_max_bytes"))?,
                u32::try_from(json_u64(document, &format!("{prefix}/concurrency"))?)
                    .map_err(|_| contract_error(MycProviderContractErrorKind::InvalidLimits))?,
            )?;
            (
                MycProviderKind::LocalSigner,
                ProviderLocation::LocalSigner {
                    socket_path,
                    limits,
                },
            )
        }
        _ => {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidConfiguration,
            ));
        }
    };
    Ok(MycProviderBinding {
        role,
        instance: role.into(),
        kind,
        expected_identity,
        required_capabilities: MycProviderCapabilitySet::for_role(role),
        location,
    })
}

/// Positive absolute UTC millisecond deadline for one provider call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MycProviderDeadlineUnixMs(u64);

impl MycProviderDeadlineUnixMs {
    /// Validates a positive deadline representable by governed storage/time types.
    pub fn new(value: u64) -> Result<Self, MycProviderContractError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(contract_error(
                MycProviderContractErrorKind::InvalidDeadline,
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! provider_identity {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps exact stable identity bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

provider_identity!(MycProviderOperationId);
provider_identity!(MycProviderCorrelationId);

/// Exact supported NIP-44 provider-operation version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MycProviderNip44Version {
    V2,
}

impl MycProviderNip44Version {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V2 => 2,
        }
    }
}

enum ProviderOperationInputKind {
    Describe,
    PublicIdentity,
    SignEvent(Zeroizing<Vec<u8>>),
    Nip04Encrypt {
        peer: MycProviderPublicIdentity,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Nip04Decrypt {
        peer: MycProviderPublicIdentity,
        ciphertext: Zeroizing<Vec<u8>>,
    },
    Nip44Encrypt {
        peer: MycProviderPublicIdentity,
        version: MycProviderNip44Version,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Nip44Decrypt {
        peer: MycProviderPublicIdentity,
        version: MycProviderNip44Version,
        ciphertext: Zeroizing<Vec<u8>>,
    },
}

/// One bounded, non-forgeable semantic provider operation input.
pub struct MycProviderOperationInput {
    kind: ProviderOperationInputKind,
}

impl MycProviderOperationInput {
    #[must_use]
    pub const fn describe() -> Self {
        Self {
            kind: ProviderOperationInputKind::Describe,
        }
    }

    #[must_use]
    pub const fn public_identity() -> Self {
        Self {
            kind: ProviderOperationInputKind::PublicIdentity,
        }
    }

    pub fn sign_event(canonical_unsigned_event: &[u8]) -> Result<Self, MycProviderContractError> {
        Ok(Self {
            kind: ProviderOperationInputKind::SignEvent(copy_input(
                canonical_unsigned_event,
                false,
            )?),
        })
    }

    pub fn nip04_encrypt(
        peer: MycProviderPublicIdentity,
        plaintext: &[u8],
    ) -> Result<Self, MycProviderContractError> {
        Ok(Self {
            kind: ProviderOperationInputKind::Nip04Encrypt {
                peer,
                plaintext: copy_input(plaintext, true)?,
            },
        })
    }

    pub fn nip04_decrypt(
        peer: MycProviderPublicIdentity,
        ciphertext: &[u8],
    ) -> Result<Self, MycProviderContractError> {
        Ok(Self {
            kind: ProviderOperationInputKind::Nip04Decrypt {
                peer,
                ciphertext: copy_input(ciphertext, false)?,
            },
        })
    }

    pub fn nip44_encrypt(
        peer: MycProviderPublicIdentity,
        version: MycProviderNip44Version,
        plaintext: &[u8],
    ) -> Result<Self, MycProviderContractError> {
        if plaintext.len() > MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES {
            return Err(contract_error(MycProviderContractErrorKind::InvalidInput));
        }
        Ok(Self {
            kind: ProviderOperationInputKind::Nip44Encrypt {
                peer,
                version,
                plaintext: copy_input(plaintext, false)?,
            },
        })
    }

    pub fn nip44_decrypt(
        peer: MycProviderPublicIdentity,
        version: MycProviderNip44Version,
        ciphertext: &[u8],
    ) -> Result<Self, MycProviderContractError> {
        Ok(Self {
            kind: ProviderOperationInputKind::Nip44Decrypt {
                peer,
                version,
                ciphertext: copy_input(ciphertext, false)?,
            },
        })
    }

    /// Returns the exact capability selected by this input.
    #[must_use]
    pub const fn capability(&self) -> MycProviderCapability {
        match &self.kind {
            ProviderOperationInputKind::Describe => MycProviderCapability::Describe,
            ProviderOperationInputKind::PublicIdentity => MycProviderCapability::PublicIdentity,
            ProviderOperationInputKind::SignEvent(_) => MycProviderCapability::SignEvent,
            ProviderOperationInputKind::Nip04Encrypt { .. } => MycProviderCapability::Nip04Encrypt,
            ProviderOperationInputKind::Nip04Decrypt { .. } => MycProviderCapability::Nip04Decrypt,
            ProviderOperationInputKind::Nip44Encrypt { .. } => MycProviderCapability::Nip44Encrypt,
            ProviderOperationInputKind::Nip44Decrypt { .. } => MycProviderCapability::Nip44Decrypt,
        }
    }

    /// Returns the peer identity for peer-bound cryptographic operations.
    #[must_use]
    pub const fn peer(&self) -> Option<&MycProviderPublicIdentity> {
        match &self.kind {
            ProviderOperationInputKind::Nip04Encrypt { peer, .. }
            | ProviderOperationInputKind::Nip04Decrypt { peer, .. }
            | ProviderOperationInputKind::Nip44Encrypt { peer, .. }
            | ProviderOperationInputKind::Nip44Decrypt { peer, .. } => Some(peer),
            ProviderOperationInputKind::Describe
            | ProviderOperationInputKind::PublicIdentity
            | ProviderOperationInputKind::SignEvent(_) => None,
        }
    }

    /// Returns the exact protected or event bytes, if any.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.kind {
            ProviderOperationInputKind::SignEvent(bytes) => Some(bytes),
            ProviderOperationInputKind::Nip04Encrypt { plaintext, .. }
            | ProviderOperationInputKind::Nip44Encrypt { plaintext, .. } => Some(plaintext),
            ProviderOperationInputKind::Nip04Decrypt { ciphertext, .. }
            | ProviderOperationInputKind::Nip44Decrypt { ciphertext, .. } => Some(ciphertext),
            ProviderOperationInputKind::Describe | ProviderOperationInputKind::PublicIdentity => {
                None
            }
        }
    }

    fn owned(&self) -> Self {
        let kind = match &self.kind {
            ProviderOperationInputKind::Describe => ProviderOperationInputKind::Describe,
            ProviderOperationInputKind::PublicIdentity => {
                ProviderOperationInputKind::PublicIdentity
            }
            ProviderOperationInputKind::SignEvent(bytes) => {
                ProviderOperationInputKind::SignEvent(bytes.clone())
            }
            ProviderOperationInputKind::Nip04Encrypt { peer, plaintext } => {
                ProviderOperationInputKind::Nip04Encrypt {
                    peer: peer.clone(),
                    plaintext: plaintext.clone(),
                }
            }
            ProviderOperationInputKind::Nip04Decrypt { peer, ciphertext } => {
                ProviderOperationInputKind::Nip04Decrypt {
                    peer: peer.clone(),
                    ciphertext: ciphertext.clone(),
                }
            }
            ProviderOperationInputKind::Nip44Encrypt {
                peer,
                version,
                plaintext,
            } => ProviderOperationInputKind::Nip44Encrypt {
                peer: peer.clone(),
                version: *version,
                plaintext: plaintext.clone(),
            },
            ProviderOperationInputKind::Nip44Decrypt {
                peer,
                version,
                ciphertext,
            } => ProviderOperationInputKind::Nip44Decrypt {
                peer: peer.clone(),
                version: *version,
                ciphertext: ciphertext.clone(),
            },
        };
        Self { kind }
    }

    #[must_use]
    pub const fn nip44_version(&self) -> Option<MycProviderNip44Version> {
        match &self.kind {
            ProviderOperationInputKind::Nip44Encrypt { version, .. }
            | ProviderOperationInputKind::Nip44Decrypt { version, .. } => Some(*version),
            _ => None,
        }
    }
}

impl fmt::Debug for MycProviderOperationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderOperationInput")
            .field("capability", &self.capability())
            .field("peer", &self.peer().map(|_| "[redacted]"))
            .field("payload", &self.bytes().map(|_| "[redacted]"))
            .field("nip44_version", &self.nip44_version())
            .finish()
    }
}

fn copy_input(
    bytes: &[u8],
    empty_allowed: bool,
) -> Result<Zeroizing<Vec<u8>>, MycProviderContractError> {
    if (!empty_allowed && bytes.is_empty()) || bytes.len() > MYC_PROVIDER_INPUT_MAX_BYTES {
        return Err(contract_error(MycProviderContractErrorKind::InvalidInput));
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// One fully bound provider operation before provider selection/execution.
pub struct MycProviderOperation {
    role: MycProviderRole,
    instance: MycProviderInstanceId,
    provider: MycProviderKind,
    operation_id: MycProviderOperationId,
    correlation_id: MycProviderCorrelationId,
    deadline: MycProviderDeadlineUnixMs,
    expected_identity: MycProviderPublicIdentity,
    input: MycProviderOperationInput,
}

impl MycProviderOperation {
    /// Binds one operation to the exact configured provider assignment.
    pub fn new(
        binding: &MycProviderBinding,
        operation_id: MycProviderOperationId,
        correlation_id: MycProviderCorrelationId,
        deadline: MycProviderDeadlineUnixMs,
        input: MycProviderOperationInput,
    ) -> Result<Self, MycProviderContractError> {
        if !binding.required_capabilities.contains(input.capability()) {
            return Err(contract_error(
                MycProviderContractErrorKind::UnsupportedOperation,
            ));
        }
        Ok(Self {
            role: binding.role,
            instance: binding.instance,
            provider: binding.kind,
            operation_id,
            correlation_id,
            deadline,
            expected_identity: binding.expected_identity.clone(),
            input,
        })
    }

    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        MYC_PROVIDER_CONTRACT_VERSION
    }

    #[must_use]
    pub const fn role(&self) -> MycProviderRole {
        self.role
    }

    #[must_use]
    pub const fn instance(&self) -> MycProviderInstanceId {
        self.instance
    }

    #[must_use]
    pub const fn provider(&self) -> MycProviderKind {
        self.provider
    }

    #[must_use]
    pub const fn operation_id(&self) -> MycProviderOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn correlation_id(&self) -> MycProviderCorrelationId {
        self.correlation_id
    }

    #[must_use]
    pub const fn deadline(&self) -> MycProviderDeadlineUnixMs {
        self.deadline
    }

    #[must_use]
    pub const fn expected_identity(&self) -> &MycProviderPublicIdentity {
        &self.expected_identity
    }

    #[must_use]
    pub const fn input(&self) -> &MycProviderOperationInput {
        &self.input
    }

    pub(crate) fn owned_for_runtime(&self) -> Self {
        Self {
            role: self.role,
            instance: self.instance,
            provider: self.provider,
            operation_id: self.operation_id,
            correlation_id: self.correlation_id,
            deadline: self.deadline,
            expected_identity: self.expected_identity.clone(),
            input: self.input.owned(),
        }
    }

    pub(crate) fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"radroots.myc.provider.operation_binding.v1\0");
        hash_framed(&mut hasher, self.role.as_str().as_bytes());
        hash_framed(&mut hasher, self.instance.as_str().as_bytes());
        hash_framed(&mut hasher, self.provider.as_str().as_bytes());
        hasher.update(self.operation_id.as_bytes());
        hasher.update(self.correlation_id.as_bytes());
        hasher.update(self.deadline.get().to_be_bytes());
        hash_framed(&mut hasher, self.expected_identity.as_hex().as_bytes());
        hash_framed(&mut hasher, self.input.capability().as_str().as_bytes());
        hash_framed(
            &mut hasher,
            self.input
                .peer()
                .map(MycProviderPublicIdentity::as_hex)
                .unwrap_or_default()
                .as_bytes(),
        );
        hasher.update(
            self.input
                .nip44_version()
                .map(MycProviderNip44Version::as_u8)
                .unwrap_or_default()
                .to_be_bytes(),
        );
        hash_framed(&mut hasher, self.input.bytes().unwrap_or_default());
        hasher.finalize().into()
    }
}

fn hash_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

impl fmt::Debug for MycProviderOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderOperation")
            .field("contract_version", &MYC_PROVIDER_CONTRACT_VERSION)
            .field("role", &self.role)
            .field("instance", &self.instance)
            .field("provider", &self.provider)
            .field("operation_id", &"[redacted]")
            .field("correlation_id", &"[redacted]")
            .field("deadline", &"[redacted]")
            .field("expected_identity", &"[redacted]")
            .field("input", &self.input)
            .finish()
    }
}

/// One bounded untrusted provider result body before independent verification.
pub struct MycUntrustedProviderOutput(Zeroizing<Vec<u8>>);

impl MycUntrustedProviderOutput {
    /// Copies only after enforcing the hard response bound.
    pub fn new(bytes: &[u8]) -> Result<Self, MycProviderContractError> {
        if bytes.len() > MYC_PROVIDER_OUTPUT_MAX_BYTES {
            return Err(contract_error(MycProviderContractErrorKind::InvalidOutput));
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Returns the untrusted bytes for the independent verifier only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MycUntrustedProviderOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycUntrustedProviderOutput([redacted])")
    }
}

/// Stable source-free provider contract failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycProviderContractErrorKind {
    InvalidConfiguration,
    InvalidIdentity,
    InvalidCredentialReference,
    InvalidLimits,
    InvalidCapabilitySet,
    InvalidDeadline,
    InvalidInput,
    InvalidOutput,
    UnsupportedOperation,
}

impl MycProviderContractErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "provider configuration is invalid",
            Self::InvalidIdentity => "provider identity is invalid",
            Self::InvalidCredentialReference => "provider credential reference is invalid",
            Self::InvalidLimits => "provider resource limits are invalid",
            Self::InvalidCapabilitySet => "provider capability set is invalid",
            Self::InvalidDeadline => "provider deadline is invalid",
            Self::InvalidInput => "provider operation input is invalid",
            Self::InvalidOutput => "provider operation output is invalid",
            Self::UnsupportedOperation => "provider operation is unsupported for the role",
        }
    }
}

/// One source-free provider contract failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycProviderContractError {
    kind: MycProviderContractErrorKind,
}

impl MycProviderContractError {
    #[must_use]
    pub const fn kind(self) -> MycProviderContractErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycProviderContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycProviderContractError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycProviderContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycProviderContractError {}

const fn contract_error(kind: MycProviderContractErrorKind) -> MycProviderContractError {
    MycProviderContractError { kind }
}

fn json_string<'a>(
    document: &'a Value,
    pointer: &str,
) -> Result<&'a str, MycProviderContractError> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| contract_error(MycProviderContractErrorKind::InvalidConfiguration))
}

fn json_u64(document: &Value, pointer: &str) -> Result<u64, MycProviderContractError> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| contract_error(MycProviderContractErrorKind::InvalidConfiguration))
}

fn json_bool(document: &Value, pointer: &str) -> Result<bool, MycProviderContractError> {
    document
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| contract_error(MycProviderContractErrorKind::InvalidConfiguration))
}

#[cfg(test)]
mod tests {
    use crate::{MycConfigProfile, parse_myc_config_v1};

    use super::*;

    const CONFIG: &[u8] = include_bytes!("../contracts/services_hardening/config.v1.example.toml");

    #[test]
    fn capability_sets_are_closed_ordered_and_duplicate_free() {
        let transport = MycProviderCapabilitySet::for_role(MycProviderRole::Transport);
        assert_eq!(transport.len(), 7);
        assert!(transport.contains(MycProviderCapability::SignEvent));
        assert_eq!(
            MycProviderCapabilitySet::for_role(MycProviderRole::User)
                .iter()
                .collect::<Vec<_>>(),
            MycProviderCapability::ALL
        );
        assert_eq!(
            MycProviderCapabilitySet::for_role(MycProviderRole::Discovery)
                .iter()
                .collect::<Vec<_>>(),
            vec![
                MycProviderCapability::Describe,
                MycProviderCapability::PublicIdentity,
                MycProviderCapability::SignEvent,
            ]
        );
        assert_eq!(
            MycProviderCapabilitySet::new(&[
                MycProviderCapability::Describe,
                MycProviderCapability::Describe,
            ])
            .unwrap_err()
            .kind(),
            MycProviderContractErrorKind::InvalidCapabilitySet
        );
        assert!(MycProviderCapabilitySet::new(&[]).is_err());
    }

    #[test]
    fn identities_references_limits_and_deadlines_are_exactly_bounded() {
        let identity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(MycProviderPublicIdentity::new(identity).is_ok());
        assert!(MycProviderPublicIdentity::new(&identity.to_uppercase()).is_err());
        assert!(MycProviderPublicIdentity::new(&"1".repeat(63)).is_err());

        assert!(MycProviderCredentialReference::new("a").is_ok());
        assert!(MycProviderCredentialReference::new(&"a".repeat(128)).is_ok());
        assert!(MycProviderCredentialReference::new(&"a".repeat(129)).is_err());
        assert!(MycProviderCredentialReference::new("../credential").is_err());

        assert!(MycLocalSignerLimits::new(1, 1, 1, 1).is_ok());
        assert!(
            MycLocalSignerLimits::new(
                MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS,
                MYC_PROVIDER_REQUEST_MAX_BYTES,
                MYC_PROVIDER_RESPONSE_MAX_BYTES,
                MYC_PROVIDER_CONCURRENCY_MAX,
            )
            .is_ok()
        );
        for result in [
            MycLocalSignerLimits::new(0, 1, 1, 1),
            MycLocalSignerLimits::new(1, 0, 1, 1),
            MycLocalSignerLimits::new(1, 1, 0, 1),
            MycLocalSignerLimits::new(1, 1, 1, 0),
            MycLocalSignerLimits::new(MYC_PROVIDER_REQUEST_DEADLINE_MAX_MS + 1, 1, 1, 1),
            MycLocalSignerLimits::new(1, MYC_PROVIDER_REQUEST_MAX_BYTES + 1, 1, 1),
            MycLocalSignerLimits::new(1, 1, MYC_PROVIDER_RESPONSE_MAX_BYTES + 1, 1),
            MycLocalSignerLimits::new(1, 1, 1, MYC_PROVIDER_CONCURRENCY_MAX + 1),
        ] {
            assert_eq!(
                result.unwrap_err().kind(),
                MycProviderContractErrorKind::InvalidLimits
            );
        }

        assert!(MycProviderDeadlineUnixMs::new(1).is_ok());
        assert!(MycProviderDeadlineUnixMs::new(i64::MAX as u64).is_ok());
        assert!(MycProviderDeadlineUnixMs::new(0).is_err());
        assert!(MycProviderDeadlineUnixMs::new(i64::MAX as u64 + 1).is_err());
    }

    #[test]
    fn operation_inputs_are_bounded_before_copy_and_redacted() {
        let peer = MycProviderPublicIdentity::new(&"2".repeat(64)).expect("peer");
        let exact = vec![b'x'; MYC_PROVIDER_INPUT_MAX_BYTES];
        assert!(MycProviderOperationInput::sign_event(&exact).is_ok());
        assert!(MycProviderOperationInput::sign_event(&[]).is_err());
        assert!(
            MycProviderOperationInput::sign_event(&vec![b'x'; MYC_PROVIDER_INPUT_MAX_BYTES + 1])
                .is_err()
        );
        let encrypt = MycProviderOperationInput::nip44_encrypt(
            peer,
            MycProviderNip44Version::V2,
            b"protected-value",
        )
        .expect("operation");
        let rendered = format!("{encrypt:?}");
        assert!(!rendered.contains("protected-value"));
        assert_eq!(encrypt.capability(), MycProviderCapability::Nip44Encrypt);
        assert_eq!(
            encrypt.nip44_version().map(MycProviderNip44Version::as_u8),
            Some(2)
        );
        assert!(
            MycProviderOperationInput::nip44_encrypt(
                MycProviderPublicIdentity::new(&"2".repeat(64)).expect("peer"),
                MycProviderNip44Version::V2,
                &vec![0; MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES]
            )
            .is_ok()
        );
        assert!(
            MycProviderOperationInput::nip44_encrypt(
                MycProviderPublicIdentity::new(&"2".repeat(64)).expect("peer"),
                MycProviderNip44Version::V2,
                &vec![0; MYC_PROVIDER_NIP44_PLAINTEXT_MAX_BYTES + 1]
            )
            .is_err()
        );

        assert!(MycUntrustedProviderOutput::new(&vec![0; MYC_PROVIDER_OUTPUT_MAX_BYTES]).is_ok());
        assert!(
            MycUntrustedProviderOutput::new(&vec![0; MYC_PROVIDER_OUTPUT_MAX_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn operation_binding_covers_every_independently_variable_request_field() {
        let config = parse_myc_config_v1(CONFIG, MycConfigProfile::RepoLocal).expect("config");
        let user = config
            .provider_contract()
            .binding(MycProviderRole::User)
            .expect("user binding");
        let transport = config
            .provider_contract()
            .binding(MycProviderRole::Transport)
            .expect("transport binding");
        let operation_id = MycProviderOperationId::from_bytes([0x11; 32]);
        let correlation_id = MycProviderCorrelationId::from_bytes([0x22; 32]);
        let deadline = MycProviderDeadlineUnixMs::new(1_900_000_000_000).expect("deadline");
        let operation =
            |binding: &MycProviderBinding, operation_id, correlation_id, deadline, input| {
                MycProviderOperation::new(binding, operation_id, correlation_id, deadline, input)
                    .expect("operation")
            };
        let base = operation(
            user,
            operation_id,
            correlation_id,
            deadline,
            MycProviderOperationInput::public_identity(),
        );
        for changed in [
            operation(
                user,
                MycProviderOperationId::from_bytes([0x12; 32]),
                correlation_id,
                deadline,
                MycProviderOperationInput::public_identity(),
            ),
            operation(
                user,
                operation_id,
                MycProviderCorrelationId::from_bytes([0x23; 32]),
                deadline,
                MycProviderOperationInput::public_identity(),
            ),
            operation(
                user,
                operation_id,
                correlation_id,
                MycProviderDeadlineUnixMs::new(deadline.get() + 1).expect("changed deadline"),
                MycProviderOperationInput::public_identity(),
            ),
            operation(
                user,
                operation_id,
                correlation_id,
                deadline,
                MycProviderOperationInput::sign_event(b"{}").expect("sign event"),
            ),
            operation(
                transport,
                operation_id,
                correlation_id,
                deadline,
                MycProviderOperationInput::public_identity(),
            ),
        ] {
            assert_ne!(base.binding_digest(), changed.binding_digest());
        }

        let first_peer = MycProviderPublicIdentity::new(&"4".repeat(64)).expect("first peer");
        let second_peer = MycProviderPublicIdentity::new(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .expect("second peer");
        let first = operation(
            user,
            operation_id,
            correlation_id,
            deadline,
            MycProviderOperationInput::nip04_encrypt(first_peer.clone(), b"first")
                .expect("first input"),
        );
        let changed_bytes = operation(
            user,
            operation_id,
            correlation_id,
            deadline,
            MycProviderOperationInput::nip04_encrypt(first_peer, b"second").expect("changed bytes"),
        );
        let changed_peer = operation(
            user,
            operation_id,
            correlation_id,
            deadline,
            MycProviderOperationInput::nip04_encrypt(second_peer, b"first").expect("changed peer"),
        );
        assert_ne!(first.binding_digest(), changed_bytes.binding_digest());
        assert_ne!(first.binding_digest(), changed_peer.binding_digest());
    }

    #[test]
    fn every_public_error_is_fixed_and_source_free() {
        for kind in [
            MycProviderContractErrorKind::InvalidConfiguration,
            MycProviderContractErrorKind::InvalidIdentity,
            MycProviderContractErrorKind::InvalidCredentialReference,
            MycProviderContractErrorKind::InvalidLimits,
            MycProviderContractErrorKind::InvalidCapabilitySet,
            MycProviderContractErrorKind::InvalidDeadline,
            MycProviderContractErrorKind::InvalidInput,
            MycProviderContractErrorKind::InvalidOutput,
            MycProviderContractErrorKind::UnsupportedOperation,
        ] {
            let error = contract_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
            assert!(!format!("{error:?}").contains('/'));
        }
    }
}
