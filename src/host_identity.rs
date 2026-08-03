//! Myc-owned secret identity container.
//!
//! `radroots_identity` deliberately exposes only public, transport-neutral
//! values. This host-private type keeps service key custody and the legacy
//! Nostr-facing profile payload inside Myc.

use std::fs;
use std::path::{Path, PathBuf};

use nostr::nips::nip19::ToBech32;
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity file missing at {0}")]
    NotFound(PathBuf),
    #[error("identity generation is not permitted for {0}")]
    GenerationNotAllowed(PathBuf),
    #[error("failed to read identity file at {0}")]
    Read(PathBuf, #[source] std::io::Error),
    #[error("failed to create identity directory {0}")]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("failed to write identity file at {0}")]
    Write(PathBuf, #[source] std::io::Error),
    #[error("invalid identity JSON")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid secret key")]
    InvalidSecretKey(#[from] nostr::key::Error),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("public key does not match secret key")]
    PublicKeyMismatch,
    #[error("invalid encrypted secret key")]
    InvalidEncryptedSecretKey,
    #[error("failed to encrypt secret key")]
    EncryptSecretKey,
    #[error("failed to decrypt encrypted secret key")]
    DecryptEncryptedSecretKey,
    #[error("unsupported identity file format")]
    InvalidIdentityFormat,
    #[error("protected identity storage error at {path}: {message}")]
    ProtectedStorage { path: PathBuf, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RadrootsIdentityId(String);

impl RadrootsIdentityId {
    pub fn from_public_key(public_key: nostr::PublicKey) -> Result<Self, IdentityError> {
        let key = radroots_nostr::key::public_key_from_nostr(public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(
            radroots_identity::IdentityId::from_public_key(key).to_hex(),
        ))
    }

    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        radroots_identity::IdentityId::from_hex(value)
            .map(|identity_id| Self(identity_id.to_hex()))
            .map_err(|_| IdentityError::InvalidPublicKey)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn to_final(&self) -> radroots_identity::IdentityId {
        radroots_identity::IdentityId::from_hex(self.0.as_str())
            .expect("host identity ids are constructed from validated keys")
    }
}

impl std::fmt::Display for RadrootsIdentityId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<radroots_identity::PublicKey> for RadrootsIdentityId {
    fn from(public_key: radroots_identity::PublicKey) -> Self {
        Self(radroots_identity::IdentityId::from_public_key(public_key).to_hex())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadrootsIdentityProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<nostr::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_handler: Option<nostr::Event>,
}

impl RadrootsIdentityProfile {
    pub fn is_empty(&self) -> bool {
        self.identifier.is_none() && self.metadata.is_none() && self.application_handler.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadrootsIdentityPublic {
    pub id: RadrootsIdentityId,
    pub public_key_hex: String,
    pub public_key_npub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<RadrootsIdentityProfile>,
}

impl PartialEq for RadrootsIdentityPublic {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.public_key_hex == other.public_key_hex
            && self.profile == other.profile
    }
}

impl Eq for RadrootsIdentityPublic {}

impl RadrootsIdentityPublic {
    pub fn new(public_key: nostr::PublicKey) -> Result<Self, IdentityError> {
        Ok(Self {
            id: RadrootsIdentityId::from_public_key(public_key)?,
            public_key_hex: public_key.to_hex(),
            public_key_npub: public_key
                .to_bech32()
                .expect("validated Nostr public keys encode as npub"),
            profile: None,
        })
    }

    pub fn with_profile(mut self, profile: RadrootsIdentityProfile) -> Self {
        self.profile = (!profile.is_empty()).then_some(profile);
        self
    }

    pub fn from_final_public_key(
        public_key: radroots_identity::PublicKey,
    ) -> Result<Self, IdentityError> {
        let public_key = radroots_nostr::key::public_key_to_nostr(public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        Self::new(public_key)
    }

    pub fn id(&self) -> &RadrootsIdentityId {
        &self.id
    }

    pub fn public_key(&self) -> radroots_identity::PublicKey {
        radroots_identity::PublicKey::from_hex(self.public_key_hex.as_str())
            .expect("host public identities are constructed from validated keys")
    }

    pub fn to_final(&self) -> radroots_identity::PublicIdentity {
        radroots_identity::PublicIdentity::new(self.public_key())
    }

    pub fn account_id(&self) -> radroots_identity::AccountId {
        self.id.to_final().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadrootsIdentityFile {
    pub secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<nostr::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_handler: Option<nostr::Event>,
}

#[derive(Debug, Clone)]
pub struct RadrootsIdentity {
    keys: Keys,
    profile: Option<RadrootsIdentityProfile>,
}

impl RadrootsIdentity {
    pub fn new(keys: Keys) -> Self {
        Self {
            keys,
            profile: None,
        }
    }

    pub fn generate() -> Self {
        Self::new(Keys::generate())
    }

    pub fn from_secret_key_str(value: &str) -> Result<Self, IdentityError> {
        let secret = SecretKey::parse(value)?;
        Ok(Self::new(Keys::new(secret)))
    }

    pub fn from_encrypted_secret_key_str(
        payload: &str,
        password: &str,
    ) -> Result<Self, IdentityError> {
        use nostr::nips::nip19::FromBech32;
        let encrypted = EncryptedSecretKey::from_bech32(payload)
            .map_err(|_| IdentityError::InvalidEncryptedSecretKey)?;
        let secret = encrypted
            .decrypt(password)
            .map_err(|_| IdentityError::DecryptEncryptedSecretKey)?;
        Ok(Self::new(Keys::new(secret)))
    }

    pub fn encrypt_secret_key_ncryptsec(&self, password: &str) -> Result<String, IdentityError> {
        let encrypted =
            EncryptedSecretKey::new(self.keys.secret_key(), password, 16, KeySecurity::Unknown)
                .map_err(|_| IdentityError::EncryptSecretKey)?;
        encrypted
            .to_bech32()
            .map_err(|_| IdentityError::EncryptSecretKey)
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn public_key(&self) -> nostr::PublicKey {
        self.keys.public_key()
    }

    pub fn final_public_key(&self) -> radroots_identity::PublicKey {
        radroots_nostr::key::public_key_from_nostr(self.public_key())
            .expect("identity keys always contain a valid public key")
    }

    pub fn id(&self) -> RadrootsIdentityId {
        RadrootsIdentityId::from_public_key(self.public_key())
            .expect("identity keys always contain a valid public key")
    }

    pub fn public_key_hex(&self) -> String {
        self.public_key().to_hex()
    }

    pub fn secret_key_hex(&self) -> String {
        self.keys.secret_key().to_secret_hex()
    }

    pub fn profile(&self) -> Option<&RadrootsIdentityProfile> {
        self.profile.as_ref()
    }

    pub fn set_profile(&mut self, profile: RadrootsIdentityProfile) {
        self.profile = (!profile.is_empty()).then_some(profile);
    }

    pub fn to_public(&self) -> RadrootsIdentityPublic {
        let mut public = RadrootsIdentityPublic::new(self.public_key())
            .expect("identity keys always contain a valid public key");
        public.profile = self.profile.clone();
        public
    }

    pub fn to_file(&self) -> RadrootsIdentityFile {
        let profile = self.profile.clone().unwrap_or_default();
        RadrootsIdentityFile {
            secret_key: self.secret_key_hex(),
            public_key: Some(self.public_key_hex()),
            identifier: profile.identifier,
            metadata: profile.metadata,
            application_handler: profile.application_handler,
        }
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|source| IdentityError::CreateDir(parent.to_path_buf(), source))?;
        }
        fs::write(path, serde_json::to_vec_pretty(&self.to_file())?)
            .map_err(|source| IdentityError::Write(path.to_path_buf(), source))
    }

    pub fn load_from_path_auto(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let encoded = fs::read(path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                IdentityError::NotFound(path.to_path_buf())
            } else {
                IdentityError::Read(path.to_path_buf(), source)
            }
        })?;
        let file: RadrootsIdentityFile = serde_json::from_slice(encoded.as_slice())?;
        Self::try_from(file)
    }
}

impl TryFrom<RadrootsIdentityFile> for RadrootsIdentity {
    type Error = IdentityError;

    fn try_from(file: RadrootsIdentityFile) -> Result<Self, Self::Error> {
        let mut identity = Self::from_secret_key_str(file.secret_key.as_str())?;
        if file
            .public_key
            .as_deref()
            .is_some_and(|public| public != identity.public_key_hex())
        {
            return Err(IdentityError::PublicKeyMismatch);
        }
        identity.set_profile(RadrootsIdentityProfile {
            identifier: file.identifier,
            metadata: file.metadata,
            application_handler: file.application_handler,
        });
        Ok(identity)
    }
}
