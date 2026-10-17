use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn source_root(
    manifest_root: &Path,
    build_top: Option<&Path>,
    input_source: Option<&Path>,
    store_root: &Path,
    service: &str,
    compiled_inputs: &[(&str, &[u8])],
) -> Result<PathBuf, &'static str> {
    let root = manifest_root
        .canonicalize()
        .map_err(|_| "manifest_root_unavailable")?;
    let Some(top) = build_top else {
        return Ok(root);
    };
    let top = top.canonicalize().map_err(|_| "build_top_unavailable")?;
    if root == top || !root.starts_with(&top) || root.join(".git").exists() {
        return Err("not_an_isolated_build_copy");
    }
    let source = input_source.ok_or("nix_input_source_missing")?;
    let metadata = fs::symlink_metadata(source).map_err(|_| "input_source_unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !metadata.permissions().readonly()
    {
        return Err("input_source_not_immutable_directory");
    }
    let source = source
        .canonicalize()
        .map_err(|_| "input_source_unavailable")?;
    let store = store_root
        .canonicalize()
        .map_err(|_| "store_root_unavailable")?;
    if source.parent() != Some(store.as_path())
        || source == root
        || source.starts_with(&top)
        || source.join(".git").exists()
    {
        return Err("input_source_scope_mismatch");
    }
    if fs::read(source.join(".radroots-consumer-root")).map_err(|_| "consumer_marker_missing")?
        != format!("{service}\n").as_bytes()
    {
        return Err("consumer_marker_mismatch");
    }
    for (relative, expected) in compiled_inputs {
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("compiled_input_path_invalid");
        }
        let path = source.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|_| "compiled_input_missing")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !metadata.permissions().readonly()
            || metadata.len() != expected.len() as u64
            || fs::read(path).map_err(|_| "compiled_input_unavailable")? != *expected
        {
            return Err("compiled_input_mismatch");
        }
    }
    Ok(source)
}

#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture {
        _directory: tempfile::TempDir,
        top: PathBuf,
        build: PathBuf,
        store: PathBuf,
        source: PathBuf,
    }

    const INPUTS: &[(&str, &[u8])] = &[
        ("Cargo.toml", b"manifest"),
        ("flake.lock", b"lock"),
        ("tests/guard.rs", b"guard"),
    ];

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let top = directory.path().join("build_top");
            let build = top.join("source");
            let store = directory.path().join("store");
            let source = store.join("immutable_source");
            fs::create_dir_all(build.join("target")).unwrap();
            fs::create_dir_all(source.join("tests")).unwrap();
            fs::write(source.join(".radroots-consumer-root"), b"rhi\n").unwrap();
            for (name, bytes) in INPUTS {
                let path = source.join(name);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
            }
            fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
            Self {
                _directory: directory,
                top,
                build,
                store,
                source,
            }
        }

        fn select(&self) -> Result<PathBuf, &'static str> {
            source_root(
                &self.build,
                Some(&self.top),
                Some(&self.source),
                &self.store,
                "rhi",
                INPUTS,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only this test's owned temporary input directory is made writable for cleanup.
            let _ = fs::set_permissions(&self.source, fs::Permissions::from_mode(0o755));
        }
    }

    #[test]
    fn native_context_keeps_the_working_tree_and_its_forbidden_artifacts_visible() {
        let fixture = Fixture::new();
        let selected = source_root(
            &fixture.build,
            None,
            Some(&fixture.source),
            &fixture.store,
            "rhi",
            INPUTS,
        )
        .unwrap();
        assert_eq!(selected, fixture.build.canonicalize().unwrap());
        assert!(selected.join("target").exists());
    }

    #[test]
    fn complete_isolated_context_selects_the_bound_immutable_input() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.select().unwrap(),
            fixture.source.canonicalize().unwrap()
        );
        assert!(fixture.build.join("target").exists());
        assert!(!fixture.select().unwrap().join("target").exists());
    }

    #[test]
    fn incomplete_or_git_context_cannot_select_another_source() {
        let fixture = Fixture::new();
        assert!(
            source_root(
                &fixture.build,
                Some(&fixture.top),
                None,
                &fixture.store,
                "rhi",
                INPUTS
            )
            .is_err()
        );
        assert!(
            source_root(
                &fixture.top,
                Some(&fixture.top),
                Some(&fixture.source),
                &fixture.store,
                "rhi",
                INPUTS
            )
            .is_err()
        );
        assert!(
            source_root(
                &fixture.store,
                Some(&fixture.top),
                Some(&fixture.source),
                &fixture.store,
                "rhi",
                INPUTS
            )
            .is_err()
        );
        fs::write(fixture.build.join(".git"), b"gitdir: fixture").unwrap();
        assert_eq!(fixture.select(), Err("not_an_isolated_build_copy"));
    }

    #[test]
    fn wrong_store_mutability_owner_and_compiled_bytes_are_refused() {
        let fixture = Fixture::new();
        assert!(
            source_root(
                &fixture.build,
                Some(&fixture.top),
                Some(&fixture.source),
                &fixture.top,
                "rhi",
                INPUTS
            )
            .is_err()
        );
        assert!(
            source_root(
                &fixture.build,
                Some(&fixture.top),
                Some(&fixture.source),
                &fixture.store,
                "myc",
                INPUTS
            )
            .is_err()
        );
        assert!(
            source_root(
                &fixture.build,
                Some(&fixture.top),
                Some(&fixture.source),
                &fixture.store,
                "rhi",
                &[("Cargo.toml", b"changed")]
            )
            .is_err()
        );
        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fixture.select(),
            Err("input_source_not_immutable_directory")
        );
    }

    #[test]
    fn linked_input_and_extra_canonical_artifacts_are_not_hidden() {
        let fixture = Fixture::new();
        let linked = fixture.store.join("linked_source");
        symlink(&fixture.source, &linked).unwrap();
        assert!(
            source_root(
                &fixture.build,
                Some(&fixture.top),
                Some(&linked),
                &fixture.store,
                "rhi",
                INPUTS
            )
            .is_err()
        );
        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(fixture.source.join("target")).unwrap();
        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(fixture.select().unwrap().join("target").exists());
    }
}
