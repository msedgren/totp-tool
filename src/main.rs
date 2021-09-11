use std::env;
use std::process;
use totp_tool::Config;

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = Config::new(&args).unwrap_or_else(|err| {
        eprintln!("Problem with parsing arguments: {}", err);
        process::exit(1);
    });

    if let Err(e) = totp_tool::run(config) {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}
