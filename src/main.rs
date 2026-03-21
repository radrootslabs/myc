#![forbid(unsafe_code)]

fn main() {
    if let Err(err) = myc::run() {
        eprintln!("myc: {err}");
        std::process::exit(1);
    }
}
