#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use myc::host_identity::RadrootsIdentity;
use myc::identity_files::{load_encrypted_identity, store_encrypted_identity};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let runtime_root = runtime_root_from_args()?;
    let resolved = resolve_runtime_paths(&runtime_root)?;

    ensure_identity(&resolved.signer_identity_path)?;
    ensure_identity(&resolved.user_identity_path)?;

    println!(
        "ok bootstrap-myc-repo-local-identities {}",
        runtime_root.display()
    );
    Ok(())
}

fn runtime_root_from_args() -> Result<PathBuf, String> {
    let mut args = env::args_os();
    let _ = args.next();
    let Some(runtime_root) = args.next() else {
        return Err("usage: myc_repo_local_identity_bootstrap <runtime-root>".to_owned());
    };
    if args.next().is_some() {
        return Err("usage: myc_repo_local_identity_bootstrap <runtime-root>".to_owned());
    }
    Ok(PathBuf::from(runtime_root))
}

struct MycRuntimePaths {
    signer_identity_path: PathBuf,
    user_identity_path: PathBuf,
}

fn resolve_runtime_paths(runtime_root: &Path) -> Result<MycRuntimePaths, String> {
    let secrets = runtime_root.join("secrets").join("services").join("myc");
    Ok(MycRuntimePaths {
        signer_identity_path: secrets.join("signer-identity.json"),
        user_identity_path: secrets.join("user-identity.json"),
    })
}

fn ensure_identity(path: &Path) -> Result<(), String> {
    if path.is_file() {
        load_encrypted_identity(path)
            .map_err(|err| format!("load encrypted identity {}: {err}", path.display()))?;
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create identity dir {}: {err}", parent.display()))?;
    }
    let identity = RadrootsIdentity::generate();
    store_encrypted_identity(path, &identity)
        .map_err(|err| format!("store encrypted identity {}: {err}", path.display()))?;
    Ok(())
}
