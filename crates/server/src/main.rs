//! Command-line entry point of the surf-rac server.

use clap::{Parser, Subcommand};
use surf_rac_server::config::Config;

/// surf-rac signaling and account server.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands of the server binary.
#[derive(Subcommand)]
enum Command {
    /// Run the HTTP and WebSocket server.
    Serve,
}

/// Parses the command line and runs the chosen subcommand.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => {
            let config = Config::from_env()?;
            surf_rac_server::telemetry::init(config.log_json);
            surf_rac_server::run(config).await
        }
    }
}
