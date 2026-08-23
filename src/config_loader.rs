//! Secure descriptor-bound configuration loading and create-new initialization.

use core::fmt;
use std::{error::Error, path::Path};

use crate::{
    MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, MycConfigDocumentV1, MycConfigProfile, MycConfigV1Error,
    MycRuntimeContext, parse_myc_config_v1,
};

/// Stable source-free secure configuration I/O failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConfigLoadErrorKind {
    InvalidPath,
    Missing,
    AlreadyExists,
    InsecureParent,
    InsecureArtifact,
    TooLarge,
    Io,
    InvalidDocument,
    UnsupportedPlatform,
}

/// One path- and content-free secure configuration failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycConfigLoadError {
    kind: MycConfigLoadErrorKind,
}

impl MycConfigLoadError {
    const fn new(kind: MycConfigLoadErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycConfigLoadErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConfigLoadError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycConfigLoadErrorKind::InvalidPath => "configuration path is invalid",
            MycConfigLoadErrorKind::Missing => "configuration document is missing",
            MycConfigLoadErrorKind::AlreadyExists => "configuration document already exists",
            MycConfigLoadErrorKind::InsecureParent => "configuration parent is insecure",
            MycConfigLoadErrorKind::InsecureArtifact => "configuration artifact is insecure",
            MycConfigLoadErrorKind::TooLarge => "configuration document exceeds its size limit",
            MycConfigLoadErrorKind::Io => "configuration storage failed",
            MycConfigLoadErrorKind::InvalidDocument => "configuration document is invalid",
            MycConfigLoadErrorKind::UnsupportedPlatform => {
                "secure configuration storage is unsupported"
            }
        })
    }
}

impl Error for MycConfigLoadError {}

/// Loads one selected configuration through the governed descriptor boundary.
pub fn load_myc_config_document(
    runtime: &MycRuntimeContext,
) -> Result<MycConfigDocumentV1, MycConfigLoadError> {
    load_myc_config_document_at(runtime.selected_config_path(), profile(runtime))
}

/// Loads one absolute candidate document without changing the selected path.
pub fn load_myc_config_candidate(
    runtime: &MycRuntimeContext,
    candidate: &Path,
) -> Result<MycConfigDocumentV1, MycConfigLoadError> {
    load_myc_config_document_at(candidate, profile(runtime))
}

/// Validates and creates the selected non-secret configuration exactly once.
pub fn initialize_myc_config_document(
    runtime: &MycRuntimeContext,
    bytes: &[u8],
) -> Result<MycConfigDocumentV1, MycConfigLoadError> {
    if bytes.len() > MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES {
        return Err(MycConfigLoadError::new(MycConfigLoadErrorKind::TooLarge));
    }
    let document = parse_myc_config_v1(bytes, profile(runtime)).map_err(map_document)?;
    persist_create_new(runtime.selected_config_path(), bytes)?;
    Ok(document)
}

fn profile(runtime: &MycRuntimeContext) -> MycConfigProfile {
    match runtime.profile() {
        crate::MycBootstrapProfileV1::RepoLocal => MycConfigProfile::RepoLocal,
        crate::MycBootstrapProfileV1::ServiceHost | crate::MycBootstrapProfileV1::Interactive => {
            MycConfigProfile::Production
        }
    }
}

fn map_document(_: MycConfigV1Error) -> MycConfigLoadError {
    MycConfigLoadError::new(MycConfigLoadErrorKind::InvalidDocument)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_myc_config_document_at(
    path: &Path,
    profile: MycConfigProfile,
) -> Result<MycConfigDocumentV1, MycConfigLoadError> {
    let bytes = native::read_existing(path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)?;
    parse_myc_config_v1(&bytes, profile).map_err(map_document)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn load_myc_config_document_at(
    _path: &Path,
    _profile: MycConfigProfile,
) -> Result<MycConfigDocumentV1, MycConfigLoadError> {
    Err(MycConfigLoadError::new(
        MycConfigLoadErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn persist_create_new(path: &Path, bytes: &[u8]) -> Result<(), MycConfigLoadError> {
    native::persist_create_new(path, bytes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn persist_create_new(_path: &Path, _bytes: &[u8]) -> Result<(), MycConfigLoadError> {
    Err(MycConfigLoadError::new(
        MycConfigLoadErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn read_secure_bounded_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, MycConfigLoadError> {
    native::read_existing(path, maximum)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};

    use rustix::fs::{FileType, Mode, OFlags, fchmod, fstat, open, openat, unlinkat};
    use rustix::process::geteuid;

    use super::{MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES, MycConfigLoadError, MycConfigLoadErrorKind};

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    struct SelectedPath {
        parent: PathBuf,
        name: OsString,
    }

    impl SelectedPath {
        fn parse(path: &Path) -> Result<Self, MycConfigLoadError> {
            if !path.is_absolute()
                || path.as_os_str().as_bytes().len() > 4_096
                || path.components().any(|component| {
                    !matches!(component, Component::RootDir | Component::Normal(_))
                })
            {
                return Err(error(MycConfigLoadErrorKind::InvalidPath));
            }
            let name = match path.components().next_back() {
                Some(Component::Normal(name)) if !name.as_bytes().is_empty() => name.to_os_string(),
                _ => return Err(error(MycConfigLoadErrorKind::InvalidPath)),
            };
            let parent = path
                .parent()
                .filter(|parent| parent.is_absolute())
                .ok_or_else(|| error(MycConfigLoadErrorKind::InvalidPath))?;
            Ok(Self {
                parent: parent.to_path_buf(),
                name,
            })
        }
    }

    pub(super) fn read_existing(
        path: &Path,
        maximum: usize,
    ) -> Result<Vec<u8>, MycConfigLoadError> {
        let selected = SelectedPath::parse(path)?;
        let parent = open_parent(&selected.parent)?;
        let parent_identity = directory_identity(&parent)?;
        let descriptor = openat(
            &parent,
            &selected.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| {
            error(if source == rustix::io::Errno::NOENT {
                MycConfigLoadErrorKind::Missing
            } else {
                MycConfigLoadErrorKind::InsecureArtifact
            })
        })?;
        let mut file = File::from(descriptor);
        let status = fstat(&file).map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?;
        let (identity, length) = file_identity(&status, maximum)?;
        let mut bytes = Vec::with_capacity(length);
        Read::by_ref(&mut file)
            .take(u64::try_from(length).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| error(MycConfigLoadErrorKind::Io))?;
        if bytes.len() != length {
            return Err(error(MycConfigLoadErrorKind::InsecureArtifact));
        }
        validate_current(
            &selected,
            &parent,
            parent_identity,
            &file,
            identity,
            length,
            maximum,
        )?;
        Ok(bytes)
    }

    pub(super) fn persist_create_new(path: &Path, bytes: &[u8]) -> Result<(), MycConfigLoadError> {
        let selected = SelectedPath::parse(path)?;
        let parent = open_parent(&selected.parent)?;
        let parent_identity = directory_identity(&parent)?;
        let descriptor = openat(
            &parent,
            &selected.name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            error(if source == rustix::io::Errno::EXIST {
                MycConfigLoadErrorKind::AlreadyExists
            } else {
                MycConfigLoadErrorKind::Io
            })
        })?;
        let mut file = File::from(descriptor);
        let status = fstat(&file).map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?;
        let identity = status_identity(&status)?;
        let result = (|| {
            fchmod(&file, Mode::RUSR | Mode::WUSR)
                .map_err(|_| error(MycConfigLoadErrorKind::Io))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| error(MycConfigLoadErrorKind::Io))?;
            validate_current(
                &selected,
                &parent,
                parent_identity,
                &file,
                identity,
                bytes.len(),
                MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES,
            )?;
            parent
                .sync_all()
                .map_err(|_| error(MycConfigLoadErrorKind::Io))?;
            validate_current(
                &selected,
                &parent,
                parent_identity,
                &file,
                identity,
                bytes.len(),
                MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES,
            )
        })();
        if result.is_err() {
            cleanup(&parent, &selected.name, identity);
        }
        result
    }

    fn open_parent(path: &Path) -> Result<File, MycConfigLoadError> {
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(error(MycConfigLoadErrorKind::InvalidPath));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut parent = File::from(
            open(Path::new("/"), flags, Mode::empty())
                .map_err(|_| error(MycConfigLoadErrorKind::InsecureParent))?,
        );
        for component in components {
            let Component::Normal(name) = component else {
                return Err(error(MycConfigLoadErrorKind::InvalidPath));
            };
            parent = File::from(
                openat(&parent, name, flags, Mode::empty())
                    .map_err(|_| error(MycConfigLoadErrorKind::InsecureParent))?,
            );
        }
        directory_identity(&parent)?;
        Ok(parent)
    }

    fn directory_identity(directory: &File) -> Result<Identity, MycConfigLoadError> {
        let status = fstat(directory).map_err(|_| error(MycConfigLoadErrorKind::InsecureParent))?;
        let mode = normalize_mode(status.st_mode);
        if !FileType::from_raw_mode(status.st_mode).is_dir()
            || status.st_uid != geteuid().as_raw()
            || mode & 0o022 != 0
        {
            return Err(error(MycConfigLoadErrorKind::InsecureParent));
        }
        status_identity(&status)
    }

    fn file_identity(
        status: &rustix::fs::Stat,
        maximum: usize,
    ) -> Result<(Identity, usize), MycConfigLoadError> {
        let mode = normalize_mode(status.st_mode);
        let length =
            usize::try_from(status.st_size).map_err(|_| error(MycConfigLoadErrorKind::TooLarge))?;
        if !FileType::from_raw_mode(status.st_mode).is_file()
            || normalize_link_count(status.st_nlink) != 1
            || status.st_uid != geteuid().as_raw()
            || mode & 0o400 == 0
            || mode & 0o022 != 0
        {
            return Err(error(MycConfigLoadErrorKind::InsecureArtifact));
        }
        if length > maximum {
            return Err(error(MycConfigLoadErrorKind::TooLarge));
        }
        Ok((status_identity(status)?, length))
    }

    fn status_identity(status: &rustix::fs::Stat) -> Result<Identity, MycConfigLoadError> {
        Ok(Identity {
            device: normalize_device(status.st_dev)
                .map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?,
            inode: status.st_ino,
        })
    }

    pub(super) fn normalize_mode<T: Into<u32>>(raw: T) -> u32 {
        raw.into()
    }

    pub(super) fn normalize_link_count<T: Into<u64>>(raw: T) -> u64 {
        raw.into()
    }

    pub(super) fn normalize_device<T: TryInto<u64>>(raw: T) -> Result<u64, T::Error> {
        raw.try_into()
    }

    fn validate_current(
        selected: &SelectedPath,
        parent: &File,
        parent_identity: Identity,
        held: &File,
        held_identity: Identity,
        length: usize,
        maximum: usize,
    ) -> Result<(), MycConfigLoadError> {
        if directory_identity(parent)? != parent_identity {
            return Err(error(MycConfigLoadErrorKind::InsecureParent));
        }
        let current_parent = open_parent(&selected.parent)?;
        if directory_identity(&current_parent)? != parent_identity {
            return Err(error(MycConfigLoadErrorKind::InsecureParent));
        }
        let held_status =
            fstat(held).map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?;
        let (current_held, current_length) = file_identity(&held_status, maximum)?;
        if current_held != held_identity || current_length != length {
            return Err(error(MycConfigLoadErrorKind::InsecureArtifact));
        }
        let current = File::from(
            openat(
                &current_parent,
                &selected.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?,
        );
        let status =
            fstat(&current).map_err(|_| error(MycConfigLoadErrorKind::InsecureArtifact))?;
        let (current_identity, current_length) = file_identity(&status, maximum)?;
        if current_identity != held_identity || current_length != length {
            return Err(error(MycConfigLoadErrorKind::InsecureArtifact));
        }
        Ok(())
    }

    fn cleanup(parent: &File, name: &std::ffi::OsStr, identity: Identity) {
        let current = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .ok()
        .map(File::from);
        if current.as_ref().is_some_and(|file| {
            fstat(file)
                .ok()
                .and_then(|status| status_identity(&status).ok())
                == Some(identity)
        }) {
            let _ = unlinkat(parent, name, rustix::fs::AtFlags::empty());
            let _ = parent.sync_all();
        }
    }

    const fn error(kind: MycConfigLoadErrorKind) -> MycConfigLoadError {
        MycConfigLoadError::new(kind)
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::PermissionsExt as _;

        use super::*;

        #[test]
        fn validation_rejects_a_replaced_parent_path() {
            let root = tempfile::tempdir().expect("temporary root");
            let parent_path = root.path().join("selected");
            std::fs::create_dir(&parent_path).expect("selected parent");
            std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
                .expect("secure selected parent");
            let path = parent_path.join("config.toml");
            std::fs::write(&path, b"config").expect("selected config");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secure selected config");

            let selected = SelectedPath::parse(&path).expect("selected path");
            let parent = open_parent(&selected.parent).expect("held parent");
            let parent_identity = directory_identity(&parent).expect("parent identity");
            let held = File::from(
                openat(
                    &parent,
                    &selected.name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .expect("held config"),
            );
            let status = fstat(&held).expect("held status");
            let (identity, length) = file_identity(&status, 16).expect("held identity");

            let moved = root.path().join("moved");
            std::fs::rename(&parent_path, &moved).expect("move held parent");
            std::fs::create_dir(&parent_path).expect("replacement parent");
            std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
                .expect("secure replacement parent");
            std::fs::write(parent_path.join("config.toml"), b"config").expect("replacement config");

            assert_eq!(
                validate_current(
                    &selected,
                    &parent,
                    parent_identity,
                    &held,
                    identity,
                    length,
                    16,
                )
                .expect_err("parent replacement")
                .kind(),
                MycConfigLoadErrorKind::InsecureParent
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_source_free_and_path_free() {
        for kind in [
            MycConfigLoadErrorKind::InvalidPath,
            MycConfigLoadErrorKind::Missing,
            MycConfigLoadErrorKind::AlreadyExists,
            MycConfigLoadErrorKind::InsecureParent,
            MycConfigLoadErrorKind::InsecureArtifact,
            MycConfigLoadErrorKind::TooLarge,
            MycConfigLoadErrorKind::Io,
            MycConfigLoadErrorKind::InvalidDocument,
            MycConfigLoadErrorKind::UnsupportedPlatform,
        ] {
            let error = MycConfigLoadError::new(kind);
            assert_eq!(error.kind(), kind);
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains('/'));
            assert!(Error::source(&error).is_none());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_create_read_permissions_and_collision_are_exact() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
        let path = directory.path().join("config.toml");
        let bytes = b"schema = \"radroots.myc.config\"\n";
        native::persist_create_new(&path, bytes).expect("create-new config");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            native::read_existing(&path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES).expect("secure read"),
            bytes
        );
        assert_eq!(
            native::persist_create_new(&path, bytes)
                .expect_err("collision")
                .kind(),
            MycConfigLoadErrorKind::AlreadyExists
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_reader_rejects_insecure_parent_artifact_links_and_oversize() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, b"config").expect("config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620))
            .expect("insecure mode");
        assert_eq!(
            native::read_existing(&path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)
                .expect_err("group-write rejection")
                .kind(),
            MycConfigLoadErrorKind::InsecureArtifact
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure mode");
        let hardlink = directory.path().join("hardlink.toml");
        std::fs::hard_link(&path, &hardlink).expect("hard link");
        assert_eq!(
            native::read_existing(&path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)
                .expect_err("single-link rejection")
                .kind(),
            MycConfigLoadErrorKind::InsecureArtifact
        );
        std::fs::remove_file(&hardlink).expect("remove link");

        let symlink_path = directory.path().join("symlink.toml");
        symlink(&path, &symlink_path).expect("symlink");
        assert_eq!(
            native::read_existing(&symlink_path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)
                .expect_err("no-follow rejection")
                .kind(),
            MycConfigLoadErrorKind::InsecureArtifact
        );

        std::fs::write(&path, vec![b'x'; MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES + 1])
            .expect("oversize");
        assert_eq!(
            native::read_existing(&path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)
                .expect_err("oversize rejection")
                .kind(),
            MycConfigLoadErrorKind::TooLarge
        );

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o720))
            .expect("insecure parent");
        assert_eq!(
            native::read_existing(&path, MYC_CONFIG_DOCUMENT_MAX_UTF8_BYTES)
                .expect_err("parent rejection")
                .kind(),
            MycConfigLoadErrorKind::InsecureParent
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_metadata_normalization_preserves_width_and_signed_device_rejection() {
        assert_eq!(native::normalize_mode(0o600_u16), 0o600);
        assert_eq!(native::normalize_mode(0o700_u32), 0o700);
        assert_eq!(native::normalize_link_count(1_u16), 1);
        assert_eq!(native::normalize_link_count(1_u64), 1);
        assert_eq!(native::normalize_device(7_i32), Ok(7));
        assert!(native::normalize_device(-1_i32).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn generic_secure_reader_enforces_the_callers_exact_bound() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
        let path = directory.path().join("artifact");
        std::fs::write(&path, b"four").expect("artifact");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure artifact");

        assert_eq!(
            read_secure_bounded_file(&path, 4).expect("exact bound"),
            b"four"
        );
        assert_eq!(
            read_secure_bounded_file(&path, 3)
                .expect_err("just over bound")
                .kind(),
            MycConfigLoadErrorKind::TooLarge
        );
    }
}
