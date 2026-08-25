#![forbid(unsafe_code)]

use std::error::Error;
use std::path::{Path, PathBuf};

use myc::{
    MycBootstrapProfileV1, MycRuntimeContextErrorKind, RadrootsHostEnvironment,
    RadrootsPathProfile, RadrootsPathResolver, RadrootsPlatform, RuntimeContextSource,
    parse_myc_cli_v1_from, resolve_myc_runtime_context,
};

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const CONTEXT_SOURCE: &str = include_str!("../src/runtime_context.rs");

fn resolve(
    resolver: &RadrootsPathResolver,
    profile: &str,
    instance: &str,
    repo_local_root: Option<&str>,
    config_path: Option<&str>,
) -> myc::MycRuntimeContext {
    let mut arguments = vec!["myc", "--profile", profile, "--instance", instance];
    if let Some(root) = repo_local_root {
        arguments.extend(["--repo-local-root", root]);
    }
    if let Some(path) = config_path {
        arguments.extend(["--config", path]);
    }
    arguments.push("run");
    let invocation = parse_myc_cli_v1_from(arguments).expect("validated CLI selection");
    resolve_myc_runtime_context(resolver, &invocation).expect("Myc runtime context")
}

fn assert_exact_roots(context: &myc::MycRuntimeContext, expected: [&str; 6]) {
    let paths = context.context().paths();
    assert_eq!(paths.config(), Path::new(expected[0]));
    assert_eq!(paths.state(), Path::new(expected[1]));
    assert_eq!(paths.cache(), Path::new(expected[2]));
    assert_eq!(paths.logs(), Path::new(expected[3]));
    assert_eq!(paths.run(), Path::new(expected[4]));
    assert_eq!(paths.secrets(), Path::new(expected[5]));
}

#[test]
fn repo_local_context_binds_typed_identity_sources_and_exact_artifacts() {
    let resolver =
        RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
    let primary = resolve(
        &resolver,
        "repo-local",
        "primary",
        Some("/repo/.local/radroots"),
        None,
    );
    let secondary = resolve(
        &resolver,
        "repo-local",
        "secondary",
        Some("/repo/.local/radroots"),
        None,
    );

    assert_eq!(primary.context().service().as_str(), "myc");
    assert_eq!(primary.context().instance().as_str(), "primary");
    assert_eq!(primary.profile(), MycBootstrapProfileV1::RepoLocal);
    assert_eq!(primary.context().profile(), RadrootsPathProfile::RepoLocal);
    assert_eq!(
        primary.context().sources().service(),
        RuntimeContextSource::SafeDefault
    );
    assert_eq!(
        primary.context().sources().instance(),
        RuntimeContextSource::BootstrapCli
    );
    assert_eq!(
        primary.context().sources().profile(),
        RuntimeContextSource::BootstrapCli
    );
    assert_eq!(
        primary.context().sources().repo_local_root(),
        Some(RuntimeContextSource::BootstrapCli)
    );
    assert_eq!(
        primary.context().sources().paths(),
        RuntimeContextSource::DerivedPath
    );
    assert_exact_roots(
        &primary,
        [
            "/repo/.local/radroots/config/services/myc/primary",
            "/repo/.local/radroots/data/services/myc/primary",
            "/repo/.local/radroots/cache/services/myc/primary",
            "/repo/.local/radroots/logs/services/myc/primary",
            "/repo/.local/radroots/run/services/myc/primary",
            "/repo/.local/radroots/secrets/services/myc/primary",
        ],
    );
    assert_eq!(
        primary.artifacts().config(),
        Path::new("/repo/.local/radroots/config/services/myc/primary/config.toml")
    );
    assert_eq!(
        primary.artifacts().state_database(),
        Path::new("/repo/.local/radroots/data/services/myc/primary/state.sqlite")
    );
    assert_eq!(
        primary.artifacts().state_lock(),
        Path::new("/repo/.local/radroots/data/services/myc/primary/state.lock")
    );
    assert_eq!(
        primary.artifacts().admin_socket(),
        Path::new("/repo/.local/radroots/run/services/myc/primary/admin.sock")
    );
    assert_eq!(primary.selected_config_path(), primary.artifacts().config());
    assert_ne!(primary.context().paths(), secondary.context().paths());
    assert_eq!(secondary.context().instance().as_str(), "secondary");
}

#[test]
fn service_host_and_interactive_profiles_use_the_shared_exact_roots() {
    let service_host = resolve(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        "service-host",
        "primary",
        None,
        None,
    );
    assert_exact_roots(
        &service_host,
        [
            "/etc/radroots/services/myc/primary",
            "/var/lib/radroots/services/myc/primary",
            "/var/cache/radroots/services/myc/primary",
            "/var/log/radroots/services/myc/primary",
            "/run/radroots/services/myc/primary",
            "/etc/radroots/secrets/services/myc/primary",
        ],
    );
    assert_eq!(
        service_host.artifacts().admin_socket(),
        Path::new("/run/radroots/services/myc/primary/admin.sock")
    );

    let linux_interactive = resolve(
        &RadrootsPathResolver::new(
            RadrootsPlatform::Linux,
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from("/home/operator")),
                xdg_config_home: Some(PathBuf::from("/xdg/config")),
                xdg_data_home: Some(PathBuf::from("/xdg/data")),
                xdg_state_home: Some(PathBuf::from("/xdg/state")),
                xdg_cache_home: Some(PathBuf::from("/xdg/cache")),
                xdg_runtime_dir: Some(PathBuf::from("/xdg/run")),
                ..RadrootsHostEnvironment::default()
            },
        ),
        "interactive",
        "primary",
        None,
        None,
    );
    assert_exact_roots(
        &linux_interactive,
        [
            "/xdg/config/radroots/services/myc/primary",
            "/xdg/data/radroots/services/myc/primary",
            "/xdg/cache/radroots/services/myc/primary",
            "/xdg/state/radroots/logs/services/myc/primary",
            "/xdg/run/radroots/services/myc/primary",
            "/xdg/config/radroots/secrets/services/myc/primary",
        ],
    );
}

#[test]
fn interactive_macos_and_windows_roots_remain_exact_and_injected() {
    let macos = resolve(
        &RadrootsPathResolver::new(
            RadrootsPlatform::Macos,
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from("/Users/operator")),
                ..RadrootsHostEnvironment::default()
            },
        ),
        "interactive",
        "primary",
        None,
        None,
    );
    assert_exact_roots(
        &macos,
        [
            "/Users/operator/Library/Application Support/Radroots/config/services/myc/primary",
            "/Users/operator/Library/Application Support/Radroots/data/services/myc/primary",
            "/Users/operator/Library/Caches/Radroots/services/myc/primary",
            "/Users/operator/Library/Logs/Radroots/services/myc/primary",
            "/Users/operator/Library/Application Support/Radroots/run/services/myc/primary",
            "/Users/operator/Library/Application Support/Radroots/secrets/services/myc/primary",
        ],
    );

    let windows = resolve(
        &RadrootsPathResolver::new(
            RadrootsPlatform::Windows,
            RadrootsHostEnvironment {
                appdata_dir: Some(PathBuf::from(r"C:\Users\operator\AppData\Roaming")),
                localappdata_dir: Some(PathBuf::from(r"C:\Users\operator\AppData\Local")),
                ..RadrootsHostEnvironment::default()
            },
        ),
        "interactive",
        "primary",
        None,
        None,
    );
    assert_exact_roots(
        &windows,
        [
            r"C:\Users\operator\AppData\Roaming/Radroots/config/services/myc/primary",
            r"C:\Users\operator\AppData\Local/Radroots/data/services/myc/primary",
            r"C:\Users\operator\AppData\Local/Radroots/cache/services/myc/primary",
            r"C:\Users\operator\AppData\Local/Radroots/logs/services/myc/primary",
            r"C:\Users\operator\AppData\Local/Radroots/run/services/myc/primary",
            r"C:\Users\operator\AppData\Roaming/Radroots/secrets/services/myc/primary",
        ],
    );
}

#[test]
fn explicit_config_path_overrides_only_the_common_config_artifact_selection() {
    let resolver =
        RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
    let context = resolve(
        &resolver,
        "repo-local",
        "primary",
        Some("/repo/.local/radroots"),
        Some("/operator/config/myc.toml"),
    );
    assert_eq!(
        context.selected_config_path(),
        Path::new("/operator/config/myc.toml")
    );
    assert_eq!(
        context.artifacts().config(),
        Path::new("/repo/.local/radroots/config/services/myc/primary/config.toml")
    );
}

#[test]
fn unsupported_profile_platform_and_diagnostics_fail_safely() {
    let invocation = parse_myc_cli_v1_from([
        "myc",
        "--profile",
        "service-host",
        "--instance",
        "secret-instance",
        "--config",
        "/private/secret-config.toml",
        "run",
    ])
    .expect("valid CLI");
    let error = resolve_myc_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Macos, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect_err("unsupported service-host platform");
    assert_eq!(error.kind(), MycRuntimeContextErrorKind::PathSelection);
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("secret-instance"));
    assert!(!rendered.contains("secret-config"));

    let context = resolve(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        "repo-local",
        "secret-instance",
        Some("/private/secret-root"),
        Some("/private/secret-config.toml"),
    );
    let debug = format!("{context:?}");
    assert!(!debug.contains("secret-instance"));
    assert!(!debug.contains("secret-root"));
    assert!(!debug.contains("secret-config"));
}

#[test]
fn shared_runtime_paths_are_the_only_path_policy_and_identity_authority() {
    assert!(MANIFEST.contains(
        "radroots_runtime_paths = { git = \"https://github.com/radrootslabs/lib\", rev = \"d287d41c2cd97cd0e455445da90f22180029f089\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(LIB_SOURCE.contains("mod runtime_context;"));
    assert!(!LIB_SOURCE.contains("pub mod runtime_context;"));
    assert!(CONTEXT_SOURCE.contains("RuntimeContext::resolve("));
    assert!(CONTEXT_SOURCE.contains("default_service_instance_artifacts("));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("src/paths.rs").exists());
    assert!(!root.join("src/config.rs").exists());
}
