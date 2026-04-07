use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use getrandom::getrandom;
use radroots_identity::{RadrootsIdentity, RadrootsIdentityFile};
use radroots_protected_store::{
    RADROOTS_PROTECTED_STORE_KEY_LENGTH, RADROOTS_PROTECTED_STORE_NONCE_LENGTH,
    RadrootsProtectedStoreEnvelope,
};
use radroots_secret_vault::{RadrootsSecretKeyWrapping, RadrootsSecretVaultAccessError};
use zeroize::Zeroize;

use crate::error::MycError;

const ENCRYPTED_IDENTITY_KEY_SLOT: &str = "myc_identity";
const ENCRYPTED_IDENTITY_KEY_SUFFIX: &str = ".key";
const WRAPPED_KEY_VERSION: u8 = 1;

#[derive(Debug, Clone)]
struct MycEncryptedIdentityKeySource {
    key_path: PathBuf,
}

impl MycEncryptedIdentityKeySource {
    fn new(path: &Path) -> Self {
        Self {
            key_path: encrypted_identity_wrapping_key_path(path),
        }
    }

    fn load_or_create_wrapping_key(
        &self,
    ) -> Result<[u8; RADROOTS_PROTECTED_STORE_KEY_LENGTH], RadrootsSecretVaultAccessError> {
        if self.key_path.exists() {
            return self.load_wrapping_key();
        }

        if let Some(parent) = self.key_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(io_backend_error)?;
        }
        let mut key = [0_u8; RADROOTS_PROTECTED_STORE_KEY_LENGTH];
        getrandom(&mut key)
            .map_err(|_| RadrootsSecretVaultAccessError::Backend("entropy unavailable".into()))?;
        fs::write(&self.key_path, key.as_slice()).map_err(io_backend_error)?;
        set_secret_permissions(&self.key_path)?;
        Ok(key)
    }

    fn load_wrapping_key(
        &self,
    ) -> Result<[u8; RADROOTS_PROTECTED_STORE_KEY_LENGTH], RadrootsSecretVaultAccessError> {
        let raw = fs::read(&self.key_path).map_err(io_backend_error)?;
        if raw.len() != RADROOTS_PROTECTED_STORE_KEY_LENGTH {
            return Err(RadrootsSecretVaultAccessError::Backend(format!(
                "encrypted identity wrapping key {} has invalid length {}",
                self.key_path.display(),
                raw.len()
            )));
        }

        let mut key = [0_u8; RADROOTS_PROTECTED_STORE_KEY_LENGTH];
        key.copy_from_slice(&raw);
        Ok(key)
    }
}

impl RadrootsSecretKeyWrapping for MycEncryptedIdentityKeySource {
    type Error = RadrootsSecretVaultAccessError;

    fn wrap_data_key(&self, key_slot: &str, plaintext_key: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut master_key = self.load_or_create_wrapping_key()?;
        let mut nonce = [0_u8; RADROOTS_PROTECTED_STORE_NONCE_LENGTH];
        getrandom(&mut nonce)
            .map_err(|_| RadrootsSecretVaultAccessError::Backend("entropy unavailable".into()))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext_key,
                    aad: key_slot.as_bytes(),
                },
            )
            .map_err(|_| {
                RadrootsSecretVaultAccessError::Backend(
                    "failed to wrap encrypted identity data key".into(),
                )
            })?;
        master_key.zeroize();

        let mut encoded = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        encoded.push(WRAPPED_KEY_VERSION);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(ciphertext.as_slice());
        Ok(encoded)
    }

    fn unwrap_data_key(&self, key_slot: &str, wrapped_key: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if wrapped_key.len() <= 1 + RADROOTS_PROTECTED_STORE_NONCE_LENGTH {
            return Err(RadrootsSecretVaultAccessError::Backend(
                "wrapped encrypted identity data key is truncated".into(),
            ));
        }
        if wrapped_key[0] != WRAPPED_KEY_VERSION {
            return Err(RadrootsSecretVaultAccessError::Backend(format!(
                "unsupported encrypted identity wrapped data key version {}",
                wrapped_key[0]
            )));
        }

        let mut master_key = self.load_wrapping_key()?;
        let nonce_offset = 1;
        let ciphertext_offset = nonce_offset + RADROOTS_PROTECTED_STORE_NONCE_LENGTH;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&wrapped_key[nonce_offset..ciphertext_offset]),
                Payload {
                    msg: &wrapped_key[ciphertext_offset..],
                    aad: key_slot.as_bytes(),
                },
            )
            .map_err(|_| {
                RadrootsSecretVaultAccessError::Backend(
                    "failed to unwrap encrypted identity data key".into(),
                )
            })?;
        master_key.zeroize();
        Ok(plaintext)
    }
}

pub fn encrypted_identity_wrapping_key_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let mut value = OsString::from(path.as_os_str());
    value.push(ENCRYPTED_IDENTITY_KEY_SUFFIX);
    PathBuf::from(value)
}

pub fn store_encrypted_identity(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), MycError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let payload = serde_json::to_vec(&identity.to_file())?;
    let key_source = MycEncryptedIdentityKeySource::new(path);
    let envelope = RadrootsProtectedStoreEnvelope::seal_with_wrapped_key(
        &key_source,
        ENCRYPTED_IDENTITY_KEY_SLOT,
        &payload,
    )
    .map_err(|error| {
        MycError::InvalidOperation(format!(
            "failed to seal encrypted identity {}: {error}",
            path.display()
        ))
    })?;
    let encoded = envelope.encode_json().map_err(|error| {
        MycError::InvalidOperation(format!(
            "failed to encode encrypted identity {}: {error}",
            path.display()
        ))
    })?;
    fs::write(path, encoded).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    set_secret_permissions(path).map_err(secret_permission_error(path))?;
    Ok(())
}

pub fn load_encrypted_identity(path: impl AsRef<Path>) -> Result<RadrootsIdentity, MycError> {
    let path = path.as_ref();
    let encoded = fs::read(path).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    let key_source = MycEncryptedIdentityKeySource::new(path);
    let envelope = RadrootsProtectedStoreEnvelope::decode_json(&encoded).map_err(|error| {
        MycError::InvalidOperation(format!(
            "failed to decode encrypted identity {}: {error}",
            path.display()
        ))
    })?;
    let plaintext = envelope
        .open_with_wrapped_key(&key_source)
        .map_err(|error| {
            MycError::InvalidOperation(format!(
                "failed to open encrypted identity {}: {error}",
                path.display()
            ))
        })?;
    let file: RadrootsIdentityFile = serde_json::from_slice(&plaintext).map_err(|error| {
        MycError::InvalidOperation(format!(
            "failed to parse encrypted identity {}: {error}",
            path.display()
        ))
    })?;
    RadrootsIdentity::try_from(file).map_err(MycError::from)
}

pub fn store_plaintext_identity(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), MycError> {
    identity.save_json(path).map_err(MycError::from)
}

fn io_backend_error(source: std::io::Error) -> RadrootsSecretVaultAccessError {
    RadrootsSecretVaultAccessError::Backend(source.to_string())
}

fn secret_permission_error(
    path: &Path,
) -> impl FnOnce(RadrootsSecretVaultAccessError) -> MycError + '_ {
    move |error| {
        MycError::InvalidOperation(format!(
            "failed to update permissions for {}: {error}",
            path.display()
        ))
    }
}

#[cfg(unix)]
fn set_secret_permissions(path: &Path) -> Result<(), RadrootsSecretVaultAccessError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions).map_err(io_backend_error)
}

#[cfg(not(unix))]
fn set_secret_permissions(_path: &Path) -> Result<(), RadrootsSecretVaultAccessError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_identity_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("identity.enc.json");
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");

        store_encrypted_identity(&path, &identity).expect("store encrypted identity");

        let loaded = load_encrypted_identity(&path).expect("load encrypted identity");
        assert_eq!(loaded.id(), identity.id());
        assert_eq!(loaded.secret_key_hex(), identity.secret_key_hex());
        assert!(encrypted_identity_wrapping_key_path(&path).is_file());
    }
}
