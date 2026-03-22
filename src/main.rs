#![forbid(unsafe_code)]

use serde_json::json;

#[tokio::main]
async fn main() {
    if let Err(err) = myc::run_cli().await {
        eprintln!("myc: {err}");
        if let Some(attempt_id) = err.discovery_refresh_attempt_id() {
            eprintln!("myc: discovery repair attempt id: {attempt_id}");
            eprintln!(
                "myc: inspect with `myc audit discovery-repair-attempt --attempt-id {attempt_id}`"
            );
            let hint = json!({
                "attempt_id": attempt_id,
                "inspect_args": ["audit", "discovery-repair-attempt", "--attempt-id", attempt_id],
            });
            eprintln!(
                "myc: discovery repair attempt json: {}",
                serde_json::to_string(&hint).expect("discovery repair attempt hint json")
            );
        }
        std::process::exit(1);
    }
}
