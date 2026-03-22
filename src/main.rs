#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(err) = myc::run_cli().await {
        eprintln!("myc: {err}");
        std::process::exit(1);
    }
}
