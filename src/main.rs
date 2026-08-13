use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use cf_scanner::api;
use cf_scanner::api::types::{CdnPreset, Mode, ScanConfig, ScanEvent, ScanTarget, StopCondition};
use cf_scanner::{cli_wizard, engine, paths, probe, ranges, server, warpgen};
use clap::{Parser, Subcommand, ValueEnum};
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
    /// One-shot scan; prints newline-delimited JSON to stdout
    Scan {
        #[command(flatten)]
        args: Box<ScanArgs>,
    },
    /// Interactive wizard over the same engine the UI uses
    Wizard,
    /// Manage bundled Cloudflare IP ranges
    Ranges {
        #[command(subcommand)]
        action: RangesAction,
    },
    /// WARP identity: register with Cloudflare, generate/export a wgconf
    WarpConfig {
        #[command(subcommand)]
        action: WarpConfigAction,
    },
}

#[derive(Subcommand)]
enum RangesAction {
    /// Re-fetch official Cloudflare IPv4 ranges from cloudflare.com
    Refresh,
}

#[derive(Subcommand)]
enum WarpConfigAction {
    /// Keygen + v0a884 registration; persist identity; write wgconf
    Generate {
        /// Output .conf path (default: print to stdout)
        #[arg(long)]
        out: Option<String>,
        /// Optional WARP+ license key to bind
        #[arg(long)]
        license: Option<String>,
        /// WireGuard endpoint `host:port` baked into the config (default:
        /// engage.cloudflareclient.com:2408)
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Reuse the persisted identity: refresh the config and write it out
    Export {
        /// Output .conf path (default: print to stdout)
        #[arg(long)]
        out: Option<String>,
        /// WireGuard endpoint `host:port` baked into the config
        #[arg(long)]
        endpoint: Option<String>,
    },
}

#[derive(clap::Args, Clone)]
struct ScanArgs {
    /// Scan mode (phase-2 via xray in CDN mode; UDP discovery in WARP)
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

    /// Enable phase-2 verification: vless/trojan/vmess/ss URIs, subscription
    /// URLs, or local xray JSON paths, comma-separated
    #[arg(long, value_delimiter = ',')]
    phase2_configs: Vec<String>,

    /// Fragment preset for phase 2 (custom needs --phase2-custom)
    #[arg(long, value_enum, requires = "phase2_configs")]
    phase2_fragment: Option<FragmentArg>,

    /// Custom fragment "length,interval" (phase2_fragment=custom only)
    #[arg(long, requires = "phase2_configs")]
    phase2_custom: Option<String>,

    /// SNI fronting variants, comma-separated (empty = each config's SNI)
    #[arg(long, value_delimiter = ',', requires = "phase2_configs")]
    phase2_snis: Vec<String>,

    /// Tiny URL fetched through the tunnel to prove connectivity
    #[arg(long, requires = "phase2_configs")]
    phase2_probe_url: Option<String>,

    /// Parallel xray instances for phase 2 (1-8)
    #[arg(long, requires = "phase2_configs")]
    phase2_concurrency: Option<u8>,

    /// WARP: handshake probes per endpoint (1-10); drives loss %
    #[arg(long, default_value_t = 3)]
    warp_probes: u8,

    /// WARP: explicit endpoints `ip` or `ip:port`, comma-separated (empty =
    /// bundled pools)
    #[arg(long, value_delimiter = ',')]
    warp_endpoints: Vec<String>,

    /// WARP: verify discovered endpoints with the user's wgconf keypair
    #[arg(long, requires = "warp_wgconf_file")]
    warp_verify: bool,

    /// WARP: path to a wg-quick / AmneziaWG config used for verification
    #[arg(long)]
    warp_wgconf_file: Option<String>,

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
enum FragmentArg {
    Off,
    Light,
    Medium,
    Heavy,
    Custom,
}

impl From<FragmentArg> for api::types::FragmentPreset {
    fn from(f: FragmentArg) -> Self {
        match f {
            FragmentArg::Off => api::types::FragmentPreset::Off,
            FragmentArg::Light => api::types::FragmentPreset::Light,
            FragmentArg::Medium => api::types::FragmentPreset::Medium,
            FragmentArg::Heavy => api::types::FragmentPreset::Heavy,
            FragmentArg::Custom => api::types::FragmentPreset::Custom,
        }
    }
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
    if mode == Mode::Warp && args.preset.is_some() {
        return Err(anyhow!("--preset is CDN-only; WARP uses --count"));
    }
    if mode == Mode::Cdn && !args.warp_endpoints.is_empty() {
        return Err(anyhow!("--warp-endpoints require --mode warp"));
    }
    if mode == Mode::Cdn && args.warp_verify {
        return Err(anyhow!("--warp-verify requires --mode warp"));
    }
    if mode == Mode::Cdn && args.warp_wgconf_file.is_some() {
        return Err(anyhow!("--warp-wgconf-file requires --mode warp"));
    }
    let target = match (args.preset, args.count) {
        (Some(preset), None) => ScanTarget::Preset(CdnPreset::from(preset)),
        (None, Some(count)) => ScanTarget::Count(count),
        (None, None) => ScanTarget::Preset(CdnPreset::Quick),
        _ => unreachable!("clap enforces preset/count exclusivity"),
    };
    // Empty --custom-cidrs means "use bundled ranges"; clap's value_delimiter
    // yields Vec::new() for an absent flag, which is exactly what we want.
    let phase2 = build_phase2(args)?;
    let wgconf = args
        .warp_wgconf_file
        .as_deref()
        .map(std::fs::read_to_string)
        .transpose()
        .map_err(|e| anyhow!("could not read --warp-wgconf-file: {e}"))?;
    let warp = (mode == Mode::Warp).then(|| api::types::WarpConfig {
        custom_endpoints: args.warp_endpoints.clone(),
        probes_per_endpoint: args.warp_probes,
        wgconf,
        verify_with_wgconf: args.warp_verify,
        ..Default::default()
    });
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
        include_v6: false,
        phase2,
        warp,
    };
    cfg.validate()
        .map_err(|e| anyhow!("invalid scan config: {e}"))?;
    Ok(cfg)
}

/// Phase-2 config from CLI flags; `None` unless `--phase2-configs` is given.
fn build_phase2(args: &ScanArgs) -> Result<Option<api::types::Phase2Config>> {
    if args.phase2_configs.is_empty() {
        return Ok(None);
    }
    let fragment = args
        .phase2_fragment
        .map(api::types::FragmentPreset::from)
        .unwrap_or(api::types::FragmentPreset::Off);
    let custom_fragment = match args.phase2_custom.as_deref() {
        Some(values) => {
            let (length, interval) = values
                .split_once(',')
                .ok_or_else(|| anyhow!("--phase2-custom must be \"length,interval\""))?;
            Some(api::types::CustomFragment {
                packets: "tlshello".to_owned(),
                length: length.trim().to_owned(),
                interval: interval.trim().to_owned(),
            })
        }
        None => None,
    };
    if fragment == api::types::FragmentPreset::Custom && custom_fragment.is_none() {
        return Err(anyhow!(
            "--phase2-fragment custom requires --phase2-custom \"length,interval\""
        ));
    }
    Ok(Some(api::types::Phase2Config {
        configs: args.phase2_configs.clone(),
        fragment,
        custom_fragment,
        snis: args.phase2_snis.clone(),
        probe_url: args
            .phase2_probe_url
            .clone()
            .unwrap_or_else(|| api::types::DEFAULT_PROBE_URL.to_owned()),
        concurrency: args.phase2_concurrency.unwrap_or(3),
    }))
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
        Command::Scan { args } => run_scan(*args).await,
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
        Command::WarpConfig { action } => match action {
            WarpConfigAction::Generate {
                out,
                license,
                endpoint,
            } => {
                let out = out.as_deref().map(PathBuf::from);
                warpgen::generate(out.as_deref(), license.as_deref(), endpoint.as_deref()).await?;
                match out {
                    Some(path) => {
                        println!("identity registered; wgconf written to {}", path.display())
                    }
                    None => eprintln!("identity registered; wgconf printed above"),
                }
                Ok(())
            }
            WarpConfigAction::Export { out, endpoint } => {
                let out = out.as_deref().map(PathBuf::from);
                warpgen::export(out.as_deref(), endpoint.as_deref()).await?;
                match out {
                    Some(path) => println!("wgconf written to {}", path.display()),
                    None => eprintln!("wgconf printed above"),
                }
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
    let streaming = |e: ScanEvent| match e {
        ScanEvent::Result(v) => {
            println!("{}", serde_json::to_string(&v).unwrap());
        }
        ScanEvent::Finished(s) => {
            println!("{}", serde_json::to_string(&s).unwrap());
        }
        ScanEvent::Failed(msg) => {
            eprintln!("scan failed: {msg}");
        }
        ScanEvent::Progress(_) => {}
    };
    let summary = match args.seed {
        Some(seed) => controller.run_streaming_seeded(cfg, seed, streaming).await,
        None => controller.run_streaming(cfg, streaming).await,
    }
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
            phase2_configs: vec![],
            phase2_fragment: None,
            phase2_custom: None,
            phase2_snis: vec![],
            phase2_probe_url: None,
            phase2_concurrency: None,
            warp_probes: 3,
            warp_endpoints: vec![],
            warp_verify: false,
            warp_wgconf_file: None,
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
            Command::Scan { args } => *args,
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
        let warp = cfg.warp.as_ref().unwrap();
        assert_eq!(warp.probes_per_endpoint, 3);
        assert!(warp.custom_endpoints.is_empty());
    }

    #[test]
    fn warp_flags_build_a_warp_config() {
        let argv = [
            "cf-scanner",
            "scan",
            "--mode",
            "warp",
            "--count",
            "50",
            "--warp-probes",
            "5",
            "--warp-endpoints",
            "8.8.8.8,1.1.1.1:500",
        ];
        let scan_args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let cfg = build_scan_config(&scan_args).unwrap();
        let warp = cfg.warp.unwrap();
        assert_eq!(warp.probes_per_endpoint, 5);
        assert_eq!(
            warp.custom_endpoints,
            vec!["8.8.8.8".to_owned(), "1.1.1.1:500".to_owned()]
        );
        assert!(cfg.phase2.is_none());
    }

    #[test]
    fn warp_mode_rejects_preset_and_cdn_rejects_warp_endpoints() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        a.preset = Some(PresetArg::Quick);
        assert!(build_scan_config(&a).is_err());
        let mut a = args();
        a.warp_endpoints = vec!["8.8.8.8".to_owned()];
        assert!(build_scan_config(&a).is_err());
        let mut a = args();
        a.warp_verify = true;
        a.warp_wgconf_file = Some("tests/fixtures/warp-wgconf.txt".to_owned());
        assert!(build_scan_config(&a).is_err(), "cdn must reject warp flags");
    }

    #[test]
    fn warp_verify_loads_the_wgconf_file() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        a.warp_verify = true;
        a.warp_wgconf_file = Some("tests/fixtures/warp-wgconf.txt".to_owned());
        let cfg = build_scan_config(&a).unwrap();
        let warp = cfg.warp.unwrap();
        assert!(warp.verify_with_wgconf);
        let wg = warp.wgconf.unwrap();
        assert!(wg.contains("[Interface]"));
        assert!(wg.contains("PrivateKey"));
    }

    #[test]
    fn warp_verify_without_wgconf_file_is_rejected() {
        let argv = ["cf-scanner", "scan", "--mode", "warp", "--warp-verify"];
        assert!(Cli::try_parse_from(argv).is_err());
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

    #[test]
    fn phase2_flags_build_a_phase2_config() {
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443,https://sub.example.com/x",
            "--phase2-fragment",
            "heavy",
            "--phase2-snis",
            "a.com,b.com",
            "--phase2-concurrency",
            "4",
        ];
        let scan_args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let cfg = build_scan_config(&scan_args).unwrap();
        let p2 = cfg.phase2.unwrap();
        assert_eq!(p2.configs.len(), 2);
        assert_eq!(p2.fragment, api::types::FragmentPreset::Heavy);
        assert_eq!(p2.snis, vec!["a.com".to_owned(), "b.com".to_owned()]);
        assert_eq!(p2.concurrency, 4);
        assert_eq!(p2.probe_url, api::types::DEFAULT_PROBE_URL);
    }

    #[test]
    fn phase2_absent_by_default_and_custom_requires_values() {
        let cfg = build_scan_config(&args()).unwrap();
        assert!(cfg.phase2.is_none());
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://a@1.2.3.4:443",
            "--phase2-fragment",
            "custom",
        ];
        let a = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        assert!(build_scan_config(&a).is_err());
    }

    #[test]
    fn phase2_custom_fragment_values_parse() {
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://a@1.2.3.4:443",
            "--phase2-fragment",
            "custom",
            "--phase2-custom",
            "100-200,10-20",
        ];
        let a = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
        assert_eq!(p2.fragment, api::types::FragmentPreset::Custom);
        let c = p2.custom_fragment.unwrap();
        assert_eq!(c.length, "100-200");
        assert_eq!(c.interval, "10-20");
    }
}
