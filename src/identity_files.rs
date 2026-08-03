use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use radroots_secrets::envelope::{Nonce, SealMaterial, SealRequest};
use radroots_secrets::error::Operation;
use radroots_secrets::id::{BackendKind, KeyVersion};
use radroots_secrets::wrapping::{
    BoxFuture, SecretMaterial, UnwrapRequest, WrapRequest, WrappedSecret,
};
use radroots_secrets::{EncryptedEnvelope, KeyWrapping, SecretId, SecretRef};
use zeroize::Zeroize;

use crate::host_identity::{
    IdentityError, RadrootsIdentity, RadrootsIdentityFile, RadrootsIdentityPublic,
};

const MYC_IDENTITY_KEY_SLOT: &str = "myc_identity";
const WRAPPING_KEY_BYTES: usize = 32;
const WRAPPING_NONCE_BYTES: usize = 24;
const WRAPPED_KEY_VERSION: u8 = 1;

struct MycFileKeyWrapping {
    key_path: PathBuf,
}

impl MycFileKeyWrapping {
    fn new(identity_path: &Path) -> Self {
        Self {
            key_path: encrypted_identity_wrapping_key_path(identity_path),
        }
    }

    fn load_or_create_key(&self) -> Result<[u8; WRAPPING_KEY_BYTES], radroots_secrets::Error> {
        if let Ok(raw) = fs::read(&self.key_path) {
            return key_from_bytes(raw.as_slice());
        }
        if let Some(parent) = self
            .key_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|_| secret_backend_failure(Operation::Provision))?;
        }
        let key: [u8; WRAPPING_KEY_BYTES] = rand::random();
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.key_path)
        {
            Ok(mut file) => {
                file.write_all(&key)
                    .map_err(|_| secret_backend_failure(Operation::Write))?;
                file.sync_all()
                    .map_err(|_| secret_backend_failure(Operation::Write))?;
                set_secret_permissions(&self.key_path)
                    .map_err(|_| secret_backend_failure(Operation::Write))?;
                Ok(key)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let raw = fs::read(&self.key_path)
                    .map_err(|_| secret_backend_failure(Operation::Read))?;
                key_from_bytes(raw.as_slice())
            }
            Err(_) => Err(secret_backend_failure(Operation::Provision)),
        }
    }

    fn load_key(&self) -> Result<[u8; WRAPPING_KEY_BYTES], radroots_secrets::Error> {
        let raw = fs::read(&self.key_path).map_err(|_| secret_backend_failure(Operation::Read))?;
        key_from_bytes(raw.as_slice())
    }
}

impl KeyWrapping for MycFileKeyWrapping {
    fn wrap<'a>(
        &'a self,
        request: WrapRequest<'a>,
    ) -> BoxFuture<'a, Result<WrappedSecret, radroots_secrets::Error>> {
        Box::pin(async move {
            let mut key = self.load_or_create_key()?;
            let nonce: [u8; WRAPPING_NONCE_BYTES] = rand::random();
            let ciphertext = request.plaintext().expose_secret(|plaintext| {
                XChaCha20Poly1305::new(Key::from_slice(&key)).encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: request.reference().id().as_str().as_bytes(),
                    },
                )
            });
            key.zeroize();
            let ciphertext = ciphertext.map_err(|_| secret_backend_failure(Operation::Wrap))?;
            let mut wrapped = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
            wrapped.push(WRAPPED_KEY_VERSION);
            wrapped.extend_from_slice(&nonce);
            wrapped.extend_from_slice(ciphertext.as_slice());
            WrappedSecret::from_bytes(wrapped)
        })
    }

    fn unwrap<'a>(
        &'a self,
        request: UnwrapRequest<'a>,
    ) -> BoxFuture<'a, Result<SecretMaterial, radroots_secrets::Error>> {
        Box::pin(async move {
            let wrapped = request.wrapped().as_bytes();
            if wrapped.len() <= 1 + WRAPPING_NONCE_BYTES || wrapped[0] != WRAPPED_KEY_VERSION {
                return Err(secret_backend_failure(Operation::Unwrap));
            }
            let mut key = self.load_key()?;
            let plaintext = XChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(
                XNonce::from_slice(&wrapped[1..1 + WRAPPING_NONCE_BYTES]),
                Payload {
                    msg: &wrapped[1 + WRAPPING_NONCE_BYTES..],
                    aad: request.reference().id().as_str().as_bytes(),
                },
            );
            key.zeroize();
            SecretMaterial::from_slice(
                &plaintext.map_err(|_| secret_backend_failure(Operation::Unwrap))?,
            )
        })
    }
}

fn identity_secret_ref() -> Result<SecretRef, radroots_secrets::Error> {
    Ok(SecretRef::new(
        SecretId::parse(MYC_IDENTITY_KEY_SLOT)?,
        BackendKind::External,
        KeyVersion::new(1)?,
    ))
}

fn secret_backend_failure(operation: Operation) -> radroots_secrets::Error {
    radroots_secrets::Error::BackendFailure {
        backend: BackendKind::External,
        operation,
    }
}

fn key_from_bytes(raw: &[u8]) -> Result<[u8; WRAPPING_KEY_BYTES], radroots_secrets::Error> {
    raw.try_into()
        .map_err(|_| secret_backend_failure(Operation::Read))
}

fn storage_error(path: &Path, operation: &str) -> IdentityError {
    IdentityError::ProtectedStorage {
        path: path.to_path_buf(),
        message: operation.to_owned(),
    }
}

pub fn encrypted_identity_wrapping_key_path(path: impl AsRef<Path>) -> PathBuf {
    let mut value = OsString::from(path.as_ref().as_os_str());
    value.push(".key");
    PathBuf::from(value)
}

pub fn store_encrypted_identity(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), IdentityError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|source| IdentityError::CreateDir(parent.to_path_buf(), source))?;
    }
    let payload = serde_json::to_vec(&identity.to_file())?;
    let plaintext = SecretMaterial::from_slice(payload.as_slice())
        .map_err(|_| storage_error(path, "validate identity secret material"))?;
    let data_key = SecretMaterial::from_slice(&rand::random::<[u8; 32]>())
        .map_err(|_| storage_error(path, "validate identity data key"))?;
    let wrapping = MycFileKeyWrapping::new(path);
    let envelope = futures_executor::block_on(EncryptedEnvelope::seal(
        &wrapping,
        SealRequest::new(
            identity_secret_ref().map_err(|_| storage_error(path, "build identity reference"))?,
            &plaintext,
            SealMaterial::new(data_key, Nonce::new(rand::random())),
        ),
    ))
    .map_err(|_| storage_error(path, "seal encrypted identity"))?;
    let encoded = envelope
        .encode()
        .map_err(|_| storage_error(path, "encode encrypted identity"))?;
    atomic_write(path, encoded.as_slice())
}

pub fn load_encrypted_identity(path: impl AsRef<Path>) -> Result<RadrootsIdentity, IdentityError> {
    let path = path.as_ref();
    let encoded = fs::read(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            IdentityError::NotFound(path.to_path_buf())
        } else {
            IdentityError::Read(path.to_path_buf(), source)
        }
    })?;
    let envelope = EncryptedEnvelope::decode(encoded.as_slice())
        .map_err(|_| storage_error(path, "decode encrypted identity"))?;
    let wrapping = MycFileKeyWrapping::new(path);
    let payload = futures_executor::block_on(envelope.open(&wrapping))
        .map_err(|_| storage_error(path, "open encrypted identity"))?;
    let file: RadrootsIdentityFile = payload
        .expose_secret(|bytes| serde_json::from_slice(bytes))
        .map_err(IdentityError::from)?;
    RadrootsIdentity::try_from(file)
}

pub fn rotate_encrypted_identity(path: impl AsRef<Path>) -> Result<(), IdentityError> {
    let path = path.as_ref();
    let identity = load_encrypted_identity(path)?;
    let key_path = encrypted_identity_wrapping_key_path(path);
    let old_key =
        fs::read(&key_path).map_err(|source| IdentityError::Read(key_path.clone(), source))?;
    fs::remove_file(&key_path).map_err(|source| IdentityError::Write(key_path.clone(), source))?;
    if let Err(error) = store_encrypted_identity(path, &identity) {
        fs::write(&key_path, old_key)
            .map_err(|source| IdentityError::Write(key_path.clone(), source))?;
        set_secret_permissions(&key_path)
            .map_err(|source| IdentityError::Write(key_path, source))?;
        return Err(error);
    }
    Ok(())
}

pub fn load_identity_profile(
    path: impl AsRef<Path>,
) -> Result<RadrootsIdentityPublic, IdentityError> {
    let path = path.as_ref();
    let encoded = fs::read(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            IdentityError::NotFound(path.to_path_buf())
        } else {
            IdentityError::Read(path.to_path_buf(), source)
        }
    })?;
    serde_json::from_slice(encoded.as_slice()).map_err(IdentityError::from)
}

pub fn store_identity_profile(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), IdentityError> {
    let encoded = serde_json::to_vec_pretty(&identity.to_public())?;
    atomic_write(path.as_ref(), encoded.as_slice())
}

fn atomic_write(path: &Path, encoded: &[u8]) -> Result<(), IdentityError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|source| IdentityError::CreateDir(parent.to_path_buf(), source))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|source| IdentityError::Write(path.to_path_buf(), source))?;
    temporary
        .write_all(encoded)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| IdentityError::Write(path.to_path_buf(), source))?;
    set_file_permissions(temporary.as_file())
        .map_err(|source| IdentityError::Write(path.to_path_buf(), source))?;
    temporary
        .persist(path)
        .map_err(|error| IdentityError::Write(path.to_path_buf(), error.error))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| IdentityError::Write(path.to_path_buf(), source))
}

#[cfg(unix)]
fn set_secret_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_secret_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn set_file_permissions(file: &fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RadrootsIdentity {
        RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity")
    }

    #[test]
    fn encrypted_identity_round_trips_and_rotates_wrapping_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("identity.enc");
        let identity = identity();
        store_encrypted_identity(&path, &identity).expect("store");
        let key_path = encrypted_identity_wrapping_key_path(&path);
        let before = fs::read(&key_path).expect("key before");
        assert_eq!(
            load_encrypted_identity(&path).expect("load").id(),
            identity.id()
        );
        rotate_encrypted_identity(&path).expect("rotate");
        assert_ne!(before, fs::read(key_path).expect("key after"));
        assert_eq!(
            load_encrypted_identity(&path).expect("load").id(),
            identity.id()
        );
    }

    #[test]
    fn public_profile_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("identity.json");
        let identity = identity();
        store_identity_profile(&path, &identity).expect("store profile");
        assert_eq!(
            load_identity_profile(path).expect("load profile").id,
            identity.id()
        );
    }
}
