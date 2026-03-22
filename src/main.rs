#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(err) = myc::run_cli().await {
        eprintln!("myc: {err}");
        if let Some(attempt_id) = err.discovery_refresh_attempt_id() {
            eprintln!("myc: discovery repair attempt id: {attempt_id}");
            eprintln!(
                "myc: inspect with `myc audit discovery-repair-attempt --attempt-id {attempt_id}`"
            );
        }
        std::process::exit(1);
    }
}
