use std::process::ExitCode;
use std::sync::Arc;

mod api;
mod cli_wizard;
mod engine;
mod paths;
mod probe;
mod ranges;
mod server;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use api::types::{CdnPreset, Mode, ScanConfig, ScanEvent, ScanTarget, StopCondition};

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
    /// One-shot scan; prints newline-delimited JSON to stdout
    Scan(ScanArgs),
    /// Interactive wizard over the same engine the UI uses
    Wizard,
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

#[derive(clap::Args, Clone)]
struct ScanArgs {
    /// Scan mode (WARP scanner lands in a later build)
    #[arg(long, value_enum, default_value_t = ModeArg::Cdn)]
    mode: ModeArg,

    /// Candidate preset; conflicts with --count
    #[arg(long, value_enum, conflicts_with = "count")]
    preset: Option<PresetArg>,

    /// Exact number of random candidate IPs; conflicts with --preset
    #[arg(long, conflicts_with = "preset")]
    count: Option<u32>,

    /// Stop after this many working endpoints
    #[arg(long, default_value_t = 20)]
    target: u32,

    /// Hard cap on probes performed (optional)
    #[arg(long)]
    cap: Option<u32>,

    /// Comma-separated ports (default 443; WARP mode: 2408,500,...)
    #[arg(long, value_delimiter = ',')]
    ports: Option<Vec<u16>>,

    /// Parallel probes (1-1000)
    #[arg(long, default_value_t = 200)]
    concurrency: u16,

    /// Per-probe timeout in ms (100-30000)
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,

    /// Dirtied CIDRs to skip, comma-separated
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Scan these CIDRs INSTEAD of the bundled ranges, comma-separated
    #[arg(long, value_delimiter = ',')]
    custom_cidrs: Vec<String>,

    /// Deterministic sampling seed (tests, repro)
    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum ModeArg {
    Cdn,
    Warp,
}

#[derive(Copy, Clone, ValueEnum)]
enum PresetArg {
    Quick,
    Normal,
    Full,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Cdn => Mode::Cdn,
            ModeArg::Warp => Mode::Warp,
        }
    }
}

impl From<PresetArg> for CdnPreset {
    fn from(p: PresetArg) -> Self {
        match p {
            PresetArg::Quick => CdnPreset::Quick,
            PresetArg::Normal => CdnPreset::Normal,
            PresetArg::Full => CdnPreset::Full,
        }
    }
}

fn build_scan_config(args: &ScanArgs) -> Result<ScanConfig> {
    let mode = Mode::from(args.mode);
    let target = match (args.preset, args.count) {
        (Some(preset), None) => ScanTarget::Preset(CdnPreset::from(preset)),
        (None, Some(count)) => ScanTarget::Count(count),
        (None, None) => ScanTarget::Preset(CdnPreset::Quick),
        _ => unreachable!("clap enforces preset/count exclusivity"),
    };
    // Empty --custom-cidrs means "use bundled ranges"; clap's value_delimiter
    // yields Vec::new() for an absent flag, which is exactly what we want.
    let cfg = ScanConfig {
        mode,
        target,
        ports: match args.ports.clone() {
            Some(ports) if !ports.is_empty() => ports,
            _ if args.mode == ModeArg::Warp => api::types::DEFAULT_WARP_PORTS.to_vec(),
            _ => vec![api::types::DEFAULT_PORT],
        },
        stop: StopCondition {
            found: args.target,
            cap: args.cap,
        },
        exclude: args.exclude.clone(),
        custom_cidrs: args.custom_cidrs.clone(),
        concurrency: args.concurrency,
        timeout_ms: args.timeout_ms,
        ..ScanConfig::default()
    };
    cfg.validate()
        .map_err(|e| anyhow!("invalid scan config: {e}"))?;
    Ok(cfg)
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { port } => serve(port).await,
        Command::Scan(args) => run_scan(args).await,
        Command::Wizard => {
            let controller = Arc::new(engine::ScanController::new(Arc::new(
                probe::TlsTransport::new(),
            )));
            cli_wizard::run(controller).await
        }
        Command::Ranges { action } => match action {
            RangesAction::Refresh => {
                let n = ranges::refresh_to_disk(&ranges::RealHttp).await?;
                println!(
                    "refreshed {n} IPv4 ranges -> {}",
                    paths::refreshed_ranges_path()?.display()
                );
                Ok(())
            }
        },
    }
}

/// One-shot scan: results and the final summary as newline-delimited JSON on
/// stdout (the `ScanEvent` contract), human summary on stderr.
async fn run_scan(args: ScanArgs) -> Result<()> {
    let cfg = build_scan_config(&args)?;
    let controller = Arc::new(engine::ScanController::new(Arc::new(
        probe::TlsTransport::new(),
    )));
    let summary = controller
        .run_streaming(cfg, |e| match e {
            ScanEvent::Result(v) => {
                println!("{}", serde_json::to_string(&v).unwrap());
            }
            ScanEvent::Finished(s) => {
                println!("{}", serde_json::to_string(&s).unwrap());
            }
            ScanEvent::Progress(_) => {}
        })
        .await
        .map_err(|e| anyhow!("scan failed: {e:#}"))?;
    eprintln!(
        "scanned {} hosts, found {} working in {} ms",
        summary.scanned, summary.found, summary.duration_ms
    );
    Ok(())
}

async fn serve(port: u16) -> Result<()> {
    let controller = Arc::new(engine::ScanController::new(Arc::new(
        probe::TlsTransport::new(),
    )));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let url = format!("http://127.0.0.1:{port}");
    tracing::info!("CF-Scanner running at {url}");
    axum::serve(listener, server::router(controller)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::types::DEFAULT_PORT;

    fn args() -> ScanArgs {
        ScanArgs {
            mode: ModeArg::Cdn,
            preset: None,
            count: None,
            target: 20,
            cap: None,
            ports: None,
            concurrency: 200,
            timeout_ms: 3000,
            exclude: vec![],
            custom_cidrs: vec![],
            seed: None,
        }
    }

    #[test]
    fn defaults_to_quick_preset_and_port_443() {
        let cfg = build_scan_config(&args()).unwrap();
        assert_eq!(cfg.target, ScanTarget::Preset(CdnPreset::Quick));
        assert_eq!(cfg.ports, vec![DEFAULT_PORT]);
        assert_eq!(
            cfg.stop,
            StopCondition {
                found: 20,
                cap: None
            }
        );
    }

    #[test]
    fn count_target_sets_exact_count() {
        let mut a = args();
        a.count = Some(350);
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.target, ScanTarget::Count(350));
    }

    #[test]
    fn preset_wins_over_default_when_given() {
        let mut a = args();
        a.preset = Some(PresetArg::Full);
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.target, ScanTarget::Preset(CdnPreset::Full));
    }

    #[test]
    fn explicit_ports_are_used() {
        let mut a = args();
        a.ports = Some(vec![443, 8443]);
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.ports, vec![443, 8443]);
    }

    #[test]
    fn warp_mode_uses_warp_ports() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.mode, Mode::Warp);
        assert_eq!(cfg.ports, api::types::DEFAULT_WARP_PORTS);
    }

    #[test]
    fn parses_comma_delimited_flags() {
        let argv = [
            "cf-scanner",
            "scan",
            "--mode",
            "warp",
            "--ports",
            "2408,500",
            "--exclude",
            "1.2.3.0/24,2.3.4.0/24",
            "--custom-cidrs",
            "10.0.0.0/24",
            "--target",
            "5",
            "--cap",
            "100",
            "--seed",
            "42",
        ];
        let scan_args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan(a) => a,
            _ => unreachable!(),
        };
        assert_eq!(scan_args.mode, ModeArg::Warp);
        assert_eq!(scan_args.ports, Some(vec![2408, 500]));
        assert_eq!(scan_args.seed, Some(42));
        let cfg = build_scan_config(&scan_args).unwrap();
        assert_eq!(
            cfg.exclude,
            vec!["1.2.3.0/24".to_owned(), "2.3.4.0/24".to_owned()]
        );
        assert_eq!(cfg.custom_cidrs, vec!["10.0.0.0/24".to_owned()]);
        assert_eq!(
            cfg.stop,
            StopCondition {
                found: 5,
                cap: Some(100)
            }
        );
    }

    #[test]
    fn preset_and_count_conflict() {
        let argv = ["cf-scanner", "scan", "--preset", "quick", "--count", "10"];
        assert!(Cli::try_parse_from(argv).is_err());
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut a = args();
        a.concurrency = 0;
        assert!(build_scan_config(&a).is_err());
        let mut a = args();
        a.ports = Some(vec![0]);
        assert!(build_scan_config(&a).is_err());
        let mut a = args();
        a.count = Some(0);
        assert!(build_scan_config(&a).is_err());
        let mut a = args();
        a.custom_cidrs = vec!["garbage".to_owned()];
        assert!(build_scan_config(&a).is_err());
    }
}
