//! Command-line entry point of the surf-rac server.

use std::io::BufRead;

use anyhow::Context;
use clap::{Parser, Subcommand};
use surf_rac_server::admin;
use surf_rac_server::config::Config;

/// surf-rac signaling server with optional accounts.
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
    /// Create an admin account; the password comes from SURF_RAC_PASSWORD or stdin.
    CreateAdmin {
        /// Username of the new admin.
        username: String,
    },
    /// List users.
    ListUsers,
    /// Disable a user and revoke their sessions.
    DisableUser {
        /// Username to disable.
        username: String,
    },
    /// Re-enable a disabled user.
    EnableUser {
        /// Username to enable.
        username: String,
    },
    /// Set a new password; it comes from SURF_RAC_PASSWORD or stdin.
    ResetPassword {
        /// Username whose password is reset.
        username: String,
    },
    /// Revoke all sessions of a user.
    RevokeSessions {
        /// Username whose sessions are revoked.
        username: String,
    },
}

/// Parses the command line and runs the chosen subcommand.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Command::Serve = cli.command {
        let config = Config::from_env()?;
        surf_rac_server::telemetry::init(config.log_json);
        return surf_rac_server::run(config).await;
    }

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let db = surf_rac_server::connect_and_migrate(&url).await?;
    let output = match cli.command {
        Command::Serve => unreachable!("handled above"),
        Command::CreateAdmin { username } => {
            admin::create_admin(&db, &username, &read_password()?).await?
        }
        Command::ListUsers => admin::list_users(&db).await?,
        Command::DisableUser { username } => admin::set_disabled(&db, &username, true).await?,
        Command::EnableUser { username } => admin::set_disabled(&db, &username, false).await?,
        Command::ResetPassword { username } => {
            admin::reset_password(&db, &username, &read_password()?).await?
        }
        Command::RevokeSessions { username } => admin::revoke_sessions(&db, &username).await?,
    };
    println!("{}", output.trim_end());
    Ok(())
}

/// Reads a password from `SURF_RAC_PASSWORD`, or else one line from stdin.
fn read_password() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("SURF_RAC_PASSWORD") {
        return Ok(p);
    }
    eprint!("password: ");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading password from stdin")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
