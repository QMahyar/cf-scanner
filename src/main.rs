use std::process::ExitCode;

mod api;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cf-scanner",
    version,
    about = "Find working Cloudflare IPs/endpoints on ISP-restricted networks"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the local API + browser UI on 127.0.0.1
    Serve {
        /// Port to bind (default 8765)
        #[arg(long, default_value_t = 8765)]
        port: u16,
    },
    /// One-shot scan; prints newline-delimited JSON results to stdout
    Scan,
    /// Manage bundled Cloudflare IP ranges
    Ranges {
        #[command(subcommand)]
        action: RangesAction,
    },
}

#[derive(Subcommand)]
enum RangesAction {
    /// Re-fetch official Cloudflare IPv4 ranges from cloudflare.com
    Refresh,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { port } => {
            tracing::info!("serve command received (port {port}); server lands in Task 6");
            Ok(())
        }
        Command::Scan => {
            tracing::info!("scan command received; engine lands in Task 5");
            Ok(())
        }
        Command::Ranges { action } => match action {
            RangesAction::Refresh => {
                tracing::info!("ranges refresh received; lands in Task 3");
                Ok(())
            }
        },
    }
}
