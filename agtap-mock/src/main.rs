use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agtap-mock", about = "Mock HTTPS API server for agtap testing")]
struct Args {
    /// Directory containing scenario TOML files
    #[arg(short, long, default_value = "scenarios")]
    scenarios_dir: PathBuf,

    /// Port to listen on (0 for random)
    #[arg(short, long, default_value = "8443")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config = agtap_mock::MockConfig {
        scenarios_dir: args.scenarios_dir,
        port: args.port,
    };

    let (addr, _handle) = agtap_mock::start_server(config).await;
    eprintln!("agtap-mock: listening on https://{}", addr);
    eprintln!("agtap-mock: press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl_c");
    eprintln!("\nagtap-mock: shutting down");
}
