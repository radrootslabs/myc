use std::fs;
use std::path::{Path, PathBuf};

use radroots_identity::{RadrootsIdentity, RadrootsIdentityFile, RadrootsIdentityPublic};
use radroots_protected_store::{
    RadrootsProtectedFileKeySource, RadrootsProtectedStoreEnvelope, sidecar_path,
};
use radroots_secret_vault::RadrootsSecretVaultAccessError;

use crate::error::MycError;

const ENCRYPTED_IDENTITY_KEY_SLOT: &str = "myc_identity";
const ENCRYPTED_IDENTITY_KEY_SUFFIX: &str = ".key";

pub fn encrypted_identity_wrapping_key_path(path: impl AsRef<Path>) -> PathBuf {
    sidecar_path(path, ENCRYPTED_IDENTITY_KEY_SUFFIX)
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
    let key_source =
        RadrootsProtectedFileKeySource::from_sidecar_suffix(path, ENCRYPTED_IDENTITY_KEY_SUFFIX);
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

pub fn rotate_encrypted_identity(path: impl AsRef<Path>) -> Result<(), MycError> {
    let path = path.as_ref();
    let identity = load_encrypted_identity(path)?;
    let envelope_backup = fs::read(path).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    let key_path = encrypted_identity_wrapping_key_path(path);
    let key_backup = if key_path.exists() {
        Some(
            fs::read(&key_path).map_err(|source| MycError::PersistenceIo {
                path: key_path.clone(),
                source,
            })?,
        )
    } else {
        None
    };

    if key_path.exists() {
        fs::remove_file(&key_path).map_err(|source| MycError::PersistenceIo {
            path: key_path.clone(),
            source,
        })?;
    }

    if let Err(error) = store_encrypted_identity(path, &identity) {
        let _ = fs::write(path, &envelope_backup);
        let _ = set_secret_permissions(path);
        match key_backup {
            Some(key_backup) => {
                let _ = fs::write(&key_path, &key_backup);
                let _ = set_secret_permissions(&key_path);
            }
            None => {
                let _ = fs::remove_file(&key_path);
            }
        }
        return Err(error);
    }

    Ok(())
}

pub fn load_encrypted_identity(path: impl AsRef<Path>) -> Result<RadrootsIdentity, MycError> {
    let path = path.as_ref();
    let encoded = fs::read(path).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    let key_source =
        RadrootsProtectedFileKeySource::from_sidecar_suffix(path, ENCRYPTED_IDENTITY_KEY_SUFFIX);
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

pub fn store_identity_profile(
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

    let encoded = serde_json::to_vec_pretty(&identity.to_public())?;
    fs::write(path, encoded).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    set_secret_permissions(path).map_err(secret_permission_error(path))?;
    Ok(())
}

pub fn load_identity_profile(path: impl AsRef<Path>) -> Result<RadrootsIdentityPublic, MycError> {
    let path = path.as_ref();
    let encoded = fs::read(path).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    if let Ok(public_identity) = serde_json::from_slice::<RadrootsIdentityPublic>(&encoded) {
        return Ok(public_identity);
    }
    RadrootsIdentity::load_from_path_auto(path)
        .map(|identity| identity.to_public())
        .map_err(MycError::from)
}

pub fn store_secret_text(path: impl AsRef<Path>, value: &str) -> Result<(), MycError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    fs::write(path, value).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    set_secret_permissions(path).map_err(secret_permission_error(path))?;
    Ok(())
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

    #[test]
    fn encrypted_identity_rotation_rewraps_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("identity.enc.json");
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");

        store_encrypted_identity(&path, &identity).expect("store encrypted identity");
        let key_path = encrypted_identity_wrapping_key_path(&path);
        let before = fs::read(&key_path).expect("key before");

        rotate_encrypted_identity(&path).expect("rotate encrypted identity");

        let after = fs::read(&key_path).expect("key after");
        assert_ne!(before, after);
        let loaded = load_encrypted_identity(&path).expect("load rotated identity");
        assert_eq!(loaded.id(), identity.id());
    }

    #[test]
    fn identity_profile_round_trips_as_public_projection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("identity.profile.json");
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");

        store_identity_profile(&path, &identity).expect("store profile");

        let encoded = fs::read_to_string(&path).expect("read profile");
        assert!(!encoded.contains("secret_key"));

        let loaded = load_identity_profile(&path).expect("load profile");
        assert_eq!(loaded.id, identity.id());
        assert_eq!(loaded.public_key_hex, identity.public_key_hex());
    }
}
