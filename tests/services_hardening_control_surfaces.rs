#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use myc::{
    MYC_DOCTOR_CHECK_COUNT, MYC_LIVEZ_PATH, MYC_METRICS_PATH, MYC_READYZ_PATH,
    MycAdminCancellationToken, MycAdminRoute,
};

const CONTRACT: &str = include_str!("../contracts/services_hardening/control_surfaces.v1.json");
const ADMIN_SOURCE: &str = include_str!("../src/admin_v1.rs");

#[test]
fn unit_13_contract_binds_the_complete_production_control_surface_inventory() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("control contract");
    assert_eq!(contract["schema"], "radroots.myc.control-surfaces.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 159);
    assert_eq!(contract["unit"], 13);
    assert_eq!(contract["unit_id"], "myc-control-surfaces");
    assert_eq!(contract["admin"]["route_count"], 19);
    assert_eq!(contract["admin"]["model_count"], 32);
    assert_eq!(MycAdminRoute::ALL.len(), 19);
    assert_eq!(contract["admin"]["live_identity_mutation_routes"], false);
    assert_eq!(contract["status"]["publisher_count"], 1);
    assert_eq!(contract["doctor"]["check_count"], MYC_DOCTOR_CHECK_COUNT);
    assert_eq!(
        contract["operations"]["routes"],
        serde_json::json!([MYC_LIVEZ_PATH, MYC_READYZ_PATH, MYC_METRICS_PATH])
    );
    assert_eq!(
        contract["deferred"]["authoritative_daemon_task_graph"],
        "unit_15"
    );
}

#[test]
fn admin_server_is_sealed_around_canonical_paths_limits_and_system_entropy() {
    let production = ADMIN_SOURCE
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("production source");
    for required in [
        "AdminServer::with_system_entropy(router.into_inner(), limits)",
        ".pointer(\"/resource_limits/admin\")",
        "UnixAdminSocketWriterAuthority::acquire(runtime.context().paths().run())",
        "UnixAdminSocketBinding::bind(authority, runtime.artifacts().admin_socket())",
        "pub struct MycAdminServer",
        "pub struct MycBoundAdminServer",
        "pub struct MycAdminCancellationToken",
    ] {
        assert!(
            production.contains(required),
            "admin source is missing `{required}`"
        );
    }
    for forbidden in [
        "pub fn into_inner",
        "pub const fn into_inner",
        "pub fn listener",
        "pub fn router",
        "TcpListener",
        "std::process::exit",
        "tokio::spawn",
    ] {
        assert!(
            !production.contains(forbidden),
            "admin source exposes forbidden `{forbidden}`"
        );
    }
}

#[test]
fn control_surface_cancellation_is_idempotent_and_redacted() {
    let token = MycAdminCancellationToken::new();
    assert!(!token.is_cancelled());
    token.cancel();
    token.cancel();
    assert!(token.is_cancelled());
    let rendered = format!("{token:?}");
    assert!(!rendered.contains("/private/control.sock"));
    assert!(!rendered.contains("credential"));
}
