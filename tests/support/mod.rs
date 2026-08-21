use std::{ffi::OsString, path::Path};

use myc::{
    MycConfig, RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform,
    parse_myc_cli_v1_from, resolve_myc_runtime_context,
};

pub fn repo_local_config(root: &Path) -> MycConfig {
    let invocation = parse_myc_cli_v1_from(vec![
        OsString::from("myc"),
        OsString::from("--profile"),
        OsString::from("repo-local"),
        OsString::from("--instance"),
        OsString::from("test"),
        OsString::from("--repo-local-root"),
        root.as_os_str().to_owned(),
        OsString::from("run"),
    ])
    .expect("test CLI selection");
    let resolver =
        RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
    let context =
        resolve_myc_runtime_context(&resolver, &invocation).expect("test runtime context");
    MycConfig::from_runtime_context(context)
}
