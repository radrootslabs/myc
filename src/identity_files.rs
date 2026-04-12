use std::path::{Path, PathBuf};

use radroots_identity::{
    IdentityError, RadrootsIdentity, RadrootsIdentityPublic,
    encrypted_identity_wrapping_key_path as shared_encrypted_identity_wrapping_key_path,
    load_encrypted_identity_with_key_slot, load_identity_profile as load_shared_identity_profile,
    rotate_encrypted_identity_with_key_slot, store_encrypted_identity_with_key_slot,
    store_identity_profile as store_shared_identity_profile,
};

const MYC_ENCRYPTED_IDENTITY_KEY_SLOT: &str = "myc_identity";

pub fn encrypted_identity_wrapping_key_path(path: impl AsRef<Path>) -> PathBuf {
    shared_encrypted_identity_wrapping_key_path(path)
}

pub fn store_encrypted_identity(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), IdentityError> {
    store_encrypted_identity_with_key_slot(path, MYC_ENCRYPTED_IDENTITY_KEY_SLOT, identity)
}

pub fn rotate_encrypted_identity(path: impl AsRef<Path>) -> Result<(), IdentityError> {
    rotate_encrypted_identity_with_key_slot(path, MYC_ENCRYPTED_IDENTITY_KEY_SLOT)
}

pub fn load_encrypted_identity(path: impl AsRef<Path>) -> Result<RadrootsIdentity, IdentityError> {
    load_encrypted_identity_with_key_slot(path, MYC_ENCRYPTED_IDENTITY_KEY_SLOT)
}

pub fn load_identity_profile(
    path: impl AsRef<Path>,
) -> Result<RadrootsIdentityPublic, IdentityError> {
    load_shared_identity_profile(path)
}

pub fn store_identity_profile(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), IdentityError> {
    store_shared_identity_profile(path, identity)
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
        let before = std::fs::read(&key_path).expect("key before");

        rotate_encrypted_identity(&path).expect("rotate encrypted identity");

        let after = std::fs::read(&key_path).expect("key after");
        assert_ne!(before, after);
        let loaded = load_encrypted_identity(&path).expect("load rotated identity");
        assert_eq!(loaded.secret_key_hex(), identity.secret_key_hex());
    }

    #[test]
    fn identity_profile_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("profile.json");
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");

        store_identity_profile(&path, &identity).expect("store profile");

        let loaded = load_identity_profile(&path).expect("load profile");
        assert_eq!(loaded.id, identity.id());
    }
}
