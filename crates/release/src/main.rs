//! Command-line tool that generates the release key and signs client releases.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

/// Generates the surf-rac release key and signs update manifests.
#[derive(Parser)]
#[command(name = "surf-rac-release")]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// The tool's subcommands.
#[derive(Subcommand)]
enum Command {
    /// Print a new private key (base64) on stdout and its public key on stderr.
    Keygen,
    /// Write a signed update.json for an executable.
    Sign {
        /// Environment variable that holds the base64 private key.
        #[arg(long)]
        key_env: String,
        /// Release version, MAJOR.MINOR.PATCH.
        #[arg(long)]
        version: String,
        /// The executable to sign; its file name becomes the asset name.
        #[arg(long)]
        file: PathBuf,
        /// Where to write the manifest.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Runs the chosen subcommand.
fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Keygen => {
            let (private, public) = surf_rac_release::keygen();
            println!("{private}");
            eprintln!("{public}");
        }
        Command::Sign {
            key_env,
            version,
            file,
            out,
        } => {
            let seed = std::env::var(&key_env)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .with_context(|| format!("{key_env} is not set"))?;
            let key = surf_rac_release::signing_key(&seed)?;
            let json = surf_rac_release::sign_file(&key, &version, &file)?;
            std::fs::write(&out, json + "\n")
                .with_context(|| format!("cannot write {}", out.display()))?;
        }
    }
    Ok(())
}
