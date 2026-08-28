use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use cf_scanner::api;
use cf_scanner::api::types::{
    CdnPreset, DEFAULT_CONCURRENCY, Mode, Port, ScanConfig, ScanEvent, ScanTarget, StopCondition,
};
use cf_scanner::{cli_wizard, engine, paths, probe, ranges, server, tray, warpgen};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser)]
#[command(
    name = "cf-scanner",
    version,
    propagate_version = true,
    about = "Find working Cloudflare IPs/endpoints on ISP-restricted networks",
    after_help = EXAMPLES
)]
struct Cli {
    /// Info-level logs (RUST_LOG, when set, still wins)
    #[arg(long, global = true)]
    verbose: bool,

    /// Print machine-readable {"error": ...} JSON to stdout on failure
    #[arg(long, global = true)]
    json_errors: bool,

    #[command(subcommand)]
    command: Command,
}

const EXAMPLES: &str = "\
Examples:
  cf-scanner serve --open                 Start API+UI and open the browser
  cf-scanner scan --preset quick          Fast CDN sweep (1 IP per /24)
  cf-scanner scan --mode warp --count 512 WARP endpoint discovery
  cf-scanner scan --phase2-configs vless://... --phase2-fragment medium
                                          Verify candidates through xray
Results print as newline-delimited JSON; pipe to jq for processing.";

#[derive(Subcommand)]
enum Command {
    /// Serve the local API + browser UI on 127.0.0.1
    Serve {
        /// Port to bind (default 8765)
        #[arg(long, default_value_t = 8765)]
        port: u16,
        /// Open the browser at the served URL once the listener is up
        #[arg(long)]
        open: bool,
        /// Keep serving from the Windows system tray; its menu drives the API
        #[arg(long)]
        tray: bool,
        /// Manage start-with-Windows registration: bare flag or `enable`
        /// registers `serve --tray` once this server is up (needs --tray);
        /// `remove` unregisters and works without --tray
        #[arg(long, num_args = 0..=1, default_missing_value = "enable")]
        autostart: Option<AutostartArg>,
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
    /// Render a verified candidate as a ready-to-use vless/trojan URI
    ExportConfig {
        /// Original vless:// or trojan:// config URI from the scan
        #[arg(long)]
        config: String,
        /// Verified candidate IPv4 dial address
        #[arg(long)]
        ip: std::net::Ipv4Addr,
        /// Verified candidate port (1-65535)
        #[arg(long)]
        port: u16,
        /// SNI fronting override (defaults to the config's own SNI)
        #[arg(long)]
        sni: Option<String>,
    },
}

#[derive(Subcommand)]
enum RangesAction {
    /// Re-fetch official Cloudflare IPv4 ranges from cloudflare.com
    Refresh {
        /// Also fetch the official IPv6 list into data/cf-ranges-v6.txt
        #[arg(long)]
        ipv6: bool,
    },
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
    #[arg(long, value_enum, default_value_t = ModeArg::Cdn, help_heading = "Candidate selection")]
    mode: ModeArg,

    /// Candidate preset; conflicts with --count
    #[arg(
        long,
        value_enum,
        conflicts_with = "count",
        help_heading = "Candidate selection"
    )]
    preset: Option<PresetArg>,

    /// Exact number of random candidate IPs; conflicts with --preset
    #[arg(long, conflicts_with = "preset", help_heading = "Candidate selection")]
    count: Option<u32>,

    /// Stop after this many working endpoints
    #[arg(
        long,
        alias = "stop-after",
        default_value_t = 20,
        help_heading = "Stopping"
    )]
    target: u32,

    /// Hard cap on probes performed (optional)
    #[arg(long, alias = "max-probes", help_heading = "Stopping")]
    cap: Option<u32>,

    /// Comma-separated ports (default 443; WARP mode: 2408,500,...)
    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    ports: Option<Vec<u16>>,

    /// Parallel probes (1-1000)
    #[arg(
        long,
        default_value_t = DEFAULT_CONCURRENCY,
        help_heading = "Tuning"
    )]
    concurrency: u16,

    /// Per-probe timeout in ms (100-30000)
    #[arg(long, default_value_t = 3000, help_heading = "Tuning")]
    timeout_ms: u64,

    /// Dirtied CIDRs to skip, comma-separated
    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    exclude: Vec<String>,

    /// Scan these CIDRs INSTEAD of the bundled ranges, comma-separated
    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    custom_cidrs: Vec<String>,

    /// Include the bundled Cloudflare IPv6 ranges in the CDN candidate pool
    #[arg(long, help_heading = "Candidate selection")]
    ipv6: bool,

    /// Enable phase-2 verification: vless/trojan/vmess/ss URIs, subscription
    /// URLs, or local xray JSON paths, comma-separated
    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_configs: Vec<String>,

    /// Skip phase-1 probing and verify the last scan's candidates (CDN only)
    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_only: bool,

    /// Fragment preset for phase 2 (custom needs --phase2-custom)
    #[arg(
        long,
        value_enum,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_fragment: Option<FragmentArg>,

    /// Custom fragment "length,interval" (phase2_fragment=custom only)
    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_custom: Option<String>,

    /// SNI fronting variants, comma-separated (empty = each config's SNI)
    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_snis: Vec<String>,

    /// Probe URLs fetched through the tunnel to prove connectivity,
    /// comma-separated (up to 8; every one must return 200 for a pass)
    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_probe_urls: Vec<String>,

    /// Single probe URL (legacy alias for --phase2-probe-urls)
    #[arg(
        long,
        hide = true,
        requires = "phase2_configs",
        conflicts_with = "phase2_probe_urls"
    )]
    phase2_probe_url: Option<String>,

    /// Parallel xray instances for phase 2 (1-8)
    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    phase2_concurrency: Option<u8>,

    /// WARP: handshake probes per endpoint (1-10, default 3); drives loss %
    #[arg(long, help_heading = "WARP")]
    warp_probes: Option<u8>,

    /// WARP: explicit endpoints `ip` or `ip:port`, comma-separated (empty =
    /// bundled pools)
    #[arg(long, value_delimiter = ',', help_heading = "WARP")]
    warp_endpoints: Vec<String>,

    /// WARP: verify discovered endpoints with the user's wgconf keypair
    #[arg(long, requires = "warp_wgconf_file", help_heading = "WARP")]
    warp_verify: bool,

    /// WARP: path to a wg-quick / AmneziaWG config used for verification
    #[arg(long, alias = "warp-wgconf", help_heading = "WARP")]
    warp_wgconf_file: Option<String>,

    /// Deterministic sampling seed (tests, repro)
    #[arg(long, help_heading = "Tuning")]
    seed: Option<u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum ModeArg {
    Cdn,
    Warp,
}

/// `--autostart` value: register or unregister the HKCU Run entry.
#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum AutostartArg {
    Enable,
    Remove,
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
    if mode == Mode::Cdn && args.warp_probes.is_some() {
        return Err(anyhow!("--warp-probes requires --mode warp"));
    }
    if mode == Mode::Warp && args.ipv6 {
        return Err(anyhow!("--ipv6 is CDN-only; WARP pools are IPv4"));
    }
    if args.phase2_only {
        return Err(anyhow!(
            "--phase2-only needs phase-1 results from a running scan; one-shot scans cannot use it"
        ));
    }
    let target = match (args.preset, args.count) {
        (Some(preset), None) => ScanTarget::Preset(CdnPreset::from(preset)),
        (None, Some(count)) => ScanTarget::Count(count),
        (None, None) if mode == Mode::Warp => {
            ScanTarget::Count(cf_scanner::warp::bundled_pool().host_count() as u32)
        }
        (None, None) => ScanTarget::Preset(CdnPreset::Quick),
        _ => unreachable!("clap enforces preset/count exclusivity"),
    };
    // Empty --custom-cidrs means "use bundled ranges"; clap's value_delimiter
    // yields Vec::new() for an absent flag, which is exactly what we want.
    let phase2 = build_phase2(args)?;
    // Capped read: the size limit is normally enforced by
    // `WarpConfig::validate`, but the file lands in memory first, so an
    // accidental `--warp-wgconf-file /dev/zero` must not OOM before that.
    let wgconf = match args.warp_wgconf_file.as_deref() {
        Some(path) => {
            use std::io::Read as _;
            let file = std::fs::File::open(path)
                .map_err(|e| anyhow!("could not open --warp-wgconf-file: {e}"))?;
            let mut buf = String::new();
            file.take(api::types::MAX_WGCONF_BYTES as u64 + 1)
                .read_to_string(&mut buf)
                .map_err(|e| anyhow!("could not read --warp-wgconf-file: {e}"))?;
            if buf.len() > api::types::MAX_WGCONF_BYTES {
                bail!(
                    "--warp-wgconf-file exceeds {} bytes",
                    api::types::MAX_WGCONF_BYTES
                );
            }
            Some(buf)
        }
        None => None,
    };
    let warp = (mode == Mode::Warp).then(|| api::types::WarpConfig {
        custom_endpoints: args.warp_endpoints.clone(),
        probes_per_endpoint: args.warp_probes.unwrap_or(3),
        wgconf,
        verify_with_wgconf: args.warp_verify,
    });
    let cfg = ScanConfig {
        mode,
        target,
        ports: match args.ports.clone() {
            Some(ports) if !ports.is_empty() => ports.into_iter().map(Port::new).collect(),
            _ if args.mode == ModeArg::Warp => api::types::DEFAULT_WARP_PORTS.to_vec(),
            _ => vec![Port::new(api::types::DEFAULT_PORT)],
        },
        stop: StopCondition {
            found: args.target,
            cap: args.cap,
        },
        exclude: args.exclude.clone(),
        custom_cidrs: args.custom_cidrs.clone(),
        include_v6: args.ipv6,
        concurrency: args.concurrency,
        timeout_ms: args.timeout_ms,
        phase2,
        phase2_only: args.phase2_only,
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
    if args.phase2_custom.is_some()
        && (args.phase2_configs.is_empty() || fragment != api::types::FragmentPreset::Custom)
    {
        return Err(anyhow!(
            "--phase2-custom requires --phase2-configs and --phase2-fragment custom"
        ));
    }
    if fragment == api::types::FragmentPreset::Custom && custom_fragment.is_none() {
        return Err(anyhow!(
            "--phase2-fragment custom requires --phase2-custom \"length,interval\""
        ));
    }
    let probe_urls = match &args.phase2_probe_url {
        Some(url) => vec![url.clone()],
        None => args.phase2_probe_urls.clone(),
    };
    Ok(Some(api::types::Phase2Config {
        configs: args.phase2_configs.clone(),
        fragment,
        custom_fragment,
        snis: args.phase2_snis.clone(),
        probe_url: api::types::DEFAULT_PROBE_URL.to_owned(),
        probe_urls,
        concurrency: args.phase2_concurrency.unwrap_or(3),
    }))
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter(
            cli.verbose,
            std::env::var("RUST_LOG").ok().as_deref(),
        ))
        .init();

    let json_errors = cli.json_errors;
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if json_errors {
                // Machine-readable failure for agents; the chain (`{err:#}`)
                // stays on stderr for humans.
                let line = serde_json::json!({ "error": err.to_string() });
                println!("{line}");
            }
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Tracing filter: `RUST_LOG` wins when set (lossy, same as the old
/// `from_default_env`); otherwise `--verbose` lifts the error-only default to
/// `info`.
fn env_filter(verbose: bool, rust_log: Option<&str>) -> EnvFilter {
    let directive = match rust_log.map(str::trim).filter(|s| !s.is_empty()) {
        Some(dirs) => dirs.to_owned(),
        None if verbose => "info".to_owned(),
        None => "error".to_owned(),
    };
    EnvFilter::builder()
        .with_default_directive(LevelFilter::ERROR.into())
        .parse_lossy(directive)
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve {
            port,
            open,
            tray,
            autostart,
        } => serve(port, open, tray, autostart).await,
        Command::Scan { args } => run_scan(*args).await,
        Command::Wizard => {
            let controller = Arc::new(engine::ScanController::new(Arc::new(
                probe::TlsTransport::new(),
            )));
            match cli_wizard::run(controller).await {
                Ok(()) => Ok(()),
                // Ctrl+C during the wizard is a user choice, not a failure;
                // downcast the typed marker instead of matching on text.
                Err(err) if err.is::<cli_wizard::WizardInterrupted>() => Ok(()),
                Err(err) => Err(err),
            }
        }
        Command::Ranges { action } => match action {
            RangesAction::Refresh { ipv6 } => {
                let (n, v6_path) = if ipv6 {
                    let n = ranges::refresh_v6_to_disk(&ranges::RealHttp).await?;
                    (n, Some(paths::refreshed_ranges_v6_path()?))
                } else {
                    let n = ranges::refresh_to_disk(&ranges::RealHttp).await?;
                    (n, None)
                };
                let family = if ipv6 { "IPv6" } else { "IPv4" };
                println!(
                    "refreshed {n} {family} ranges -> {}",
                    v6_path.unwrap_or(paths::refreshed_ranges_path()?).display()
                );
                Ok(())
            }
        },
        Command::ExportConfig {
            config,
            ip,
            port,
            sni,
        } => {
            let uri = run_export_config(&config, ip, port, sni.as_deref())?;
            println!("{uri}");
            Ok(())
        }
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
/// stdout (the `ScanEvent` contract), human summary on stderr. Ctrl+C cancels
/// the running scan so it drains and exits cleanly instead of dying mid-probe.
async fn run_scan(args: ScanArgs) -> Result<()> {
    let cfg = build_scan_config(&args)?;
    let controller = Arc::new(engine::ScanController::new(Arc::new(
        probe::TlsTransport::new(),
    )));
    let cancel_on_ctrl_c = {
        let controller = controller.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => controller.cancel(),
                // A broken signal hook must not leave the scan running
                // silently forever (mirrors the serve-path behavior).
                Err(err) => tracing::error!("could not listen for Ctrl+C: {err}"),
            }
        })
    };
    let scan_controller = controller.clone();
    let write_line = |line: &str| {
        if write_stdout_line(line).is_err() {
            eprintln!("output pipe closed; cancelling scan");
            scan_controller.cancel();
        }
    };
    let streaming = |e: ScanEvent| match e {
        ScanEvent::Result(v) => {
            if let Some(line) = serialize_event(&v) {
                write_line(&line);
            }
        }
        ScanEvent::Finished(s) => {
            if let Some(line) = serialize_event(&s) {
                write_line(&line);
            }
        }
        ScanEvent::Phase2Progress(p) => {
            eprintln!("phase 2: {}/{} verified", p.done, p.total);
        }
        ScanEvent::Failed(_) => {}
        ScanEvent::Progress(p) => {
            // TTY-only ticker: NDJSON consumers get clean stdout, humans see
            // live progress instead of silence between results.
            if std::io::stderr().is_terminal() {
                match p.total {
                    Some(total) => eprint!(
                        "\r\x1b[Kchecked {}/{} — {} working",
                        p.scanned, total, p.found
                    ),
                    None => {
                        eprint!("\r\x1b[Kchecked {} — {} working", p.scanned, p.found)
                    }
                }
            }
        }
    };
    let result = match args.seed {
        Some(seed) => controller.run_streaming_seeded(cfg, seed, streaming).await,
        None => controller.run_streaming(cfg, streaming).await,
    }
    .map_err(|e| anyhow!("scan failed: {e:#}"));
    cancel_on_ctrl_c.abort();
    let summary = result?;
    if std::io::stderr().is_terminal() {
        eprint!("\r\x1b[K");
    }
    eprintln!(
        "scanned {} hosts, found {} working in {} ms",
        summary.scanned, summary.found, summary.duration_ms
    );
    if summary.cancelled {
        eprintln!(
            "scan cancelled — {} working endpoints retained",
            summary.found
        );
    }
    Ok(())
}

/// Serialize a scan event to an NDJSON line without panicking: a serialization
/// failure (unreachable for the fixed API types, but possible) is logged to
/// stderr and the line is skipped.
fn serialize_event<T: serde::Serialize>(value: &T) -> Option<String> {
    match serde_json::to_string(value) {
        Ok(line) => Some(line),
        Err(err) => {
            eprintln!("could not serialize scan event: {err}");
            None
        }
    }
}

/// NDJSON line to stdout. A downstream pipe that closed (e.g. `head`, jq)
/// reports the write failure so the caller can cancel the pointless scan.
fn write_stdout_line(line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()
}

/// Shared export-config logic (the CLI prints the URI, the server's
/// /api/config/export returns it in JSON): parse the user's original config
/// URI, point it at the verified candidate, render the ready URI.
fn run_export_config(
    config: &str,
    ip: std::net::Ipv4Addr,
    port: u16,
    sni: Option<&str>,
) -> Result<String> {
    if port == 0 {
        return Err(anyhow!("--port must be in 1..=65535"));
    }
    let uri = cf_scanner::configs::export_config_uri(config, ip, port, sni).map_err(|e| {
        anyhow!(
            "export failed: {}",
            cf_scanner::configs::sanitize_error_text(&format!("{e:#}"))
        )
    })?;
    Ok(uri)
}

async fn serve(
    port: u16,
    open_ui: bool,
    tray_enabled: bool,
    autostart: Option<AutostartArg>,
) -> Result<()> {
    // Removal runs before bind: unregistering must not depend on the server
    // coming up (a busy port must not trap the entry in the registry).
    if autostart == Some(AutostartArg::Remove) {
        tray::set_autostart(false)?;
        if cfg!(target_os = "windows") {
            eprintln!(
                "autostart removed: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{}",
                tray::RUN_VALUE_NAME
            );
        }
    }
    ensure_autostart_valid(tray_enabled, autostart)?;
    let controller = Arc::new(engine::ScanController::new(Arc::new(
        probe::TlsTransport::new(),
    )));
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(err) => return Err(anyhow!("{}", bind_error(port, &err))),
    };
    let bind_addr = listener.local_addr()?;
    let url = serve_url(bind_addr);
    // Unconditional stderr print: the user must see where the server is even
    // without --verbose (info-level logs are hidden by default).
    eprintln!("CF-Scanner running at {url}");
    // Registered only after a successful bind: an autostart entry that keeps
    // relaunching a serve which cannot bind would fail at every logon.
    if autostart == Some(AutostartArg::Enable) {
        tray::set_autostart(true)?;
        if cfg!(target_os = "windows") {
            eprintln!(
                "autostart registered: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{}",
                tray::RUN_VALUE_NAME
            );
        }
    }
    if tray_enabled {
        // --tray never auto-opens the browser: the tray menu's "Open UI" is
        // the way in, so spawning can fail silently without hurting serve.
        if let Err(err) = tray::spawn(url.clone(), false) {
            tracing::warn!("could not start system tray: {err:#}");
        }
    } else if open_ui {
        open_browser(&url);
    }
    // Graceful shutdown waits for in-flight responses, but an idle SSE
    // stream is open forever by design — bound the wait so a connected UI
    // can never hang process exit (the stream itself ends on terminal or
    // Lagged; this only cuts idle ones at shutdown).
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    let (shutdown_fired_tx, mut shutdown_fired) = tokio::sync::watch::channel(false);
    let mut server = tokio::spawn(async move {
        axum::serve(
            listener,
            server::router(controller.clone(), bind_addr.port()),
        )
        .with_graceful_shutdown(async move {
            shutdown_signal(controller, tray_enabled).await;
            let _ = shutdown_fired_tx.send(true);
        })
        .await
    });
    tokio::select! {
        res = &mut server => {
            res.context("server task failed")??;
        }
        _ = async {
            let _ = shutdown_fired.changed().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            tracing::info!("shutdown grace elapsed; closing remaining connections");
            server.abort();
        }
    }
    Ok(())
}

/// `--autostart enable` registers a `serve --tray` entry, so it needs
/// --tray; `remove` stands alone. Clap cannot express per-value requires,
/// hence this check instead of `requires = "tray"`.
fn ensure_autostart_valid(tray_enabled: bool, autostart: Option<AutostartArg>) -> Result<()> {
    if autostart == Some(AutostartArg::Enable) && !tray_enabled {
        return Err(anyhow!("--autostart requires --tray"));
    }
    Ok(())
}

/// Open `url` in the default browser (`serve --open`). Best-effort: a
/// missing opener must never take the server down.
fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let spawned = {
        use std::os::windows::process::CommandExt as _;
        std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: no console flash
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let spawned = std::process::Command::new("xdg-open").arg(url).spawn();
    if let Err(err) = spawned {
        tracing::warn!("could not open browser at {url}: {err}");
    }
}

/// Bind failure message: a busy port gets a hint, anything else stays
/// human-readable with the attempted address.
fn bind_error(port: u16, err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::AddrInUse {
        format!("port {port} in use — try: cf-scanner serve --port <other>")
    } else {
        format!("could not bind 127.0.0.1:{port}: {err}")
    }
}

/// The URL of the bound listener; `--port 0` picks an ephemeral port, so the
/// printed URL must come from `local_addr`, not the requested port.
fn serve_url(addr: std::net::SocketAddr) -> String {
    format!("http://{addr}")
}

/// Ctrl+C (and the tray's Exit item, with --tray): cancel any in-flight scan
/// (probes drain on the next stop check), then let axum finish in-flight
/// requests. The runtime drop after `serve` returns reaps xray children via
/// their Drop::start_kill.
async fn shutdown_signal(controller: Arc<engine::ScanController>, tray_enabled: bool) {
    if tray_enabled {
        tokio::select! {
            ctrl_c = tokio::signal::ctrl_c() => {
                if let Err(err) = ctrl_c {
                    // A broken Ctrl+C hook must not hang shutdown; serve's
                    // graceful shutdown proceeds immediately.
                    tracing::error!("could not listen for Ctrl+C: {err}");
                }
            }
            _ = tray_exit_requested() => {
                tracing::info!("tray Exit requested");
            }
        }
    } else if let Err(err) = tokio::signal::ctrl_c().await {
        // A broken Ctrl+C hook must not hang shutdown; serve's graceful
        // shutdown proceeds immediately.
        tracing::error!("could not listen for Ctrl+C: {err}");
    }
    tracing::info!("shutting down; cancelling any active scan");
    controller.cancel();
}

/// Completes once the tray thread requests shutdown via its Exit menu item.
/// The tray never shares state with the server, so this only reads the shared
/// flag; when no tray is running the flag stays false forever.
async fn tray_exit_requested() {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        ticker.tick().await;
        if tray::exit_requested() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::types::{DEFAULT_CONCURRENCY, DEFAULT_PORT};

    fn args() -> ScanArgs {
        ScanArgs {
            mode: ModeArg::Cdn,
            preset: None,
            count: None,
            target: 20,
            cap: None,
            ports: None,
            concurrency: DEFAULT_CONCURRENCY,
            timeout_ms: 3000,
            exclude: vec![],
            custom_cidrs: vec![],
            ipv6: false,
            phase2_configs: vec![],
            phase2_only: false,
            phase2_fragment: None,
            phase2_custom: None,
            phase2_snis: vec![],
            phase2_probe_urls: vec![],
            phase2_probe_url: None,
            phase2_concurrency: None,
            warp_probes: None,
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
        assert_eq!(cfg.ports, vec![Port::new(DEFAULT_PORT)]);
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
    fn warp_defaults_to_the_full_pool() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(
            cfg.target,
            ScanTarget::Count(cf_scanner::warp::bundled_pool().host_count() as u32),
            "WARP without --count must scan the whole bundled pool"
        );
    }

    #[test]
    fn phase2_only_is_rejected_in_one_shot_scans() {
        let mut a = args();
        a.phase2_only = true;
        let err = build_scan_config(&a).unwrap_err();
        assert!(err.to_string().contains("--phase2-only"), "{err:#}");
    }

    #[test]
    fn phase2_custom_requires_configs_and_custom_fragment() {
        // clap: --phase2-custom without --phase2-configs never parses.
        let argv = ["cf-scanner", "scan", "--phase2-custom", "100-200,10-20"];
        assert!(Cli::try_parse_from(argv).is_err());
        // build: a custom fragment value with a non-custom preset is rejected.
        let mut a = args();
        a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
        a.phase2_custom = Some("100-200,10-20".to_owned());
        let err = build_scan_config(&a).unwrap_err();
        assert!(err.to_string().contains("--phase2-custom"), "{err:#}");
    }

    #[test]
    fn cap_zero_is_rejected() {
        let mut a = args();
        a.cap = Some(0);
        let err = build_scan_config(&a).unwrap_err();
        // Rejection moved to the single source (ScanConfig::validate); the
        // CLI no longer duplicates the check with its own message.
        assert!(err.to_string().contains("stop.cap out of range"), "{err:#}");
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
        assert_eq!(cfg.ports, vec![Port::new(443), Port::new(8443)]);
    }

    #[test]
    fn warp_mode_uses_warp_ports() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.mode, Mode::Warp);
        assert_eq!(cfg.ports.as_slice(), api::types::DEFAULT_WARP_PORTS);
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
            "--warp-endpoints",
            "203.0.113.1,203.0.113.2:2408",
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
        assert_eq!(cfg.custom_cidrs, Vec::<String>::new());
        assert_eq!(
            cfg.stop,
            StopCondition {
                found: 5,
                cap: Some(100)
            }
        );
        let warp = cfg.warp.as_ref().unwrap();
        assert_eq!(warp.probes_per_endpoint, 3);
        assert_eq!(
            warp.custom_endpoints,
            vec!["203.0.113.1".to_owned(), "203.0.113.2:2408".to_owned()]
        );
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
    fn ipv6_flag_enables_v6_ranges() {
        let argv = ["cf-scanner", "scan", "--ipv6"];
        let scan_args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        assert!(scan_args.ipv6);
        let cfg = build_scan_config(&scan_args).unwrap();
        assert!(cfg.include_v6);
        // Default stays off.
        assert!(!build_scan_config(&args()).unwrap().include_v6);
    }

    #[test]
    fn warp_mode_rejects_ipv6_flag() {
        let mut a = args();
        a.mode = ModeArg::Warp;
        a.ipv6 = true;
        let err = build_scan_config(&a).unwrap_err();
        assert!(err.to_string().contains("CDN-only"), "{err:#}");
    }

    #[test]
    fn ranges_refresh_ipv6_flag_parses() {
        let argv = ["cf-scanner", "ranges", "refresh", "--ipv6"];
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Ranges {
                action: RangesAction::Refresh { ipv6: true },
            } => {}
            _ => panic!("expected refresh --ipv6"),
        }
        let argv = ["cf-scanner", "ranges", "refresh"];
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Ranges {
                action: RangesAction::Refresh { ipv6: false },
            } => {}
            _ => panic!("expected plain refresh"),
        }
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

    #[test]
    fn phase2_probe_urls_flag_builds_the_multi_url_list() {
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://a@1.2.3.4:443",
            "--phase2-probe-urls",
            "https://cp.cloudflare.com/,https://www.cloudflare.com/",
        ];
        let a = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
        assert_eq!(
            p2.probe_urls,
            vec![
                "https://cp.cloudflare.com/".to_owned(),
                "https://www.cloudflare.com/".to_owned()
            ]
        );
        // The legacy single-URL alias stays parseable (hidden flag, same
        // name) and maps to a one-entry list so old scripts keep working.
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://a@1.2.3.4:443",
            "--phase2-probe-url",
            "https://example.com/check",
        ];
        let a = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
        assert_eq!(p2.probe_urls, vec!["https://example.com/check".to_owned()]);
        // Passing both is ambiguous and must not parse.
        let argv = [
            "cf-scanner",
            "scan",
            "--phase2-configs",
            "vless://a@1.2.3.4:443",
            "--phase2-probe-urls",
            "https://a.example/",
            "--phase2-probe-url",
            "https://b.example/",
        ];
        assert!(Cli::try_parse_from(argv).is_err());
    }

    #[test]
    fn export_config_subcommand_renders_a_ready_uri() {
        let argv = [
            "cf-scanner",
            "export-config",
            "--config",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome",
            "--ip",
            "203.0.113.7",
            "--port",
            "2096",
            "--sni",
            "b.me",
        ];
        let uri = match Cli::try_parse_from(argv).unwrap().command {
            Command::ExportConfig {
                config,
                ip,
                port,
                sni,
            } => run_export_config(&config, ip, port, sni.as_deref()).unwrap(),
            _ => unreachable!(),
        };
        assert!(
            uri.starts_with("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@203.0.113.7:2096?"),
            "{uri}"
        );
        assert!(
            uri.contains("sni=b.me") && uri.contains("fp=chrome"),
            "{uri}"
        );
    }

    #[test]
    fn export_config_rejects_bad_port_or_config() {
        let err = run_export_config(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443",
            "203.0.113.7".parse().unwrap(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--port"), "{err}");
        let err =
            run_export_config("not a uri", "203.0.113.7".parse().unwrap(), 443, None).unwrap_err();
        assert!(err.to_string().contains("export failed"), "{err}");
    }

    #[test]
    fn cdn_mode_rejects_explicit_warp_probes() {
        let mut a = args();
        a.warp_probes = Some(5);
        let err = build_scan_config(&a).unwrap_err();
        assert!(err.to_string().contains("--warp-probes"), "{err:#}");
        let mut a = args();
        a.warp_probes = Some(3);
        let err = build_scan_config(&a).unwrap_err();
        assert!(
            err.to_string().contains("--warp-probes"),
            "even the default value must not silently no-op: {err:#}"
        );
        let mut a = args();
        a.mode = ModeArg::Warp;
        a.warp_probes = Some(5);
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.warp.unwrap().probes_per_endpoint, 5);
        let mut a = args();
        a.mode = ModeArg::Warp;
        let cfg = build_scan_config(&a).unwrap();
        assert_eq!(cfg.warp.unwrap().probes_per_endpoint, 3);
    }

    #[test]
    fn cdn_mode_rejects_warp_probes_at_cli_parse_level() {
        let argv = ["cf-scanner", "scan", "--warp-probes", "5"];
        let a = match Cli::try_parse_from(argv).unwrap().command {
            Command::Scan { args } => *args,
            _ => unreachable!(),
        };
        let err = build_scan_config(&a).unwrap_err();
        assert!(err.to_string().contains("--warp-probes"), "{err:#}");
    }

    #[test]
    fn serve_tray_flags_parse_and_autostart_shapes() {
        let cli = Cli::try_parse_from(["cf-scanner", "serve", "--tray"]).unwrap();
        match cli.command {
            Command::Serve {
                port,
                open,
                tray,
                autostart,
            } => {
                assert_eq!(port, 8765);
                assert!(!open);
                assert!(tray);
                assert_eq!(autostart, None);
            }
            _ => panic!("expected serve"),
        }
        // Bare flag means enable (back-compat with the old bool --autostart).
        let cli = Cli::try_parse_from(["cf-scanner", "serve", "--tray", "--autostart"]).unwrap();
        match cli.command {
            Command::Serve {
                autostart: Some(AutostartArg::Enable),
                ..
            } => {}
            _ => panic!("bare --autostart must mean enable"),
        }
        let cli = Cli::try_parse_from(["cf-scanner", "serve", "--autostart", "enable"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Serve {
                autostart: Some(AutostartArg::Enable),
                ..
            }
        ));
        // Removal needs no --tray; the tray requirement is serve()-level.
        let cli = Cli::try_parse_from(["cf-scanner", "serve", "--autostart", "remove"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Serve {
                autostart: Some(AutostartArg::Remove),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["cf-scanner", "serve", "--autostart", "bogus"]).is_err(),
            "unknown --autostart values must be rejected"
        );
    }

    #[test]
    fn autostart_enable_requires_tray_but_remove_does_not() {
        // The old clap `requires = "tray"` moved here so `remove` can run
        // standalone; enabling without a tray would register an entry that
        // cannot bring the UI up.
        assert!(ensure_autostart_valid(false, Some(AutostartArg::Enable)).is_err());
        let err = ensure_autostart_valid(false, Some(AutostartArg::Enable)).unwrap_err();
        assert!(err.to_string().contains("--tray"), "{err:#}");
        assert!(ensure_autostart_valid(true, Some(AutostartArg::Enable)).is_ok());
        assert!(ensure_autostart_valid(false, Some(AutostartArg::Remove)).is_ok());
        assert!(ensure_autostart_valid(true, Some(AutostartArg::Remove)).is_ok());
        assert!(ensure_autostart_valid(true, None).is_ok());
        assert!(ensure_autostart_valid(false, None).is_ok());
    }

    #[test]
    fn verbose_flag_parses_before_and_after_subcommand() {
        let cli =
            Cli::try_parse_from(["cf-scanner", "--verbose", "scan", "--count", "10"]).unwrap();
        assert!(cli.verbose);
        match cli.command {
            Command::Scan { args } => assert_eq!(args.count, Some(10)),
            _ => panic!("expected scan"),
        }
        let cli =
            Cli::try_parse_from(["cf-scanner", "scan", "--count", "10", "--verbose"]).unwrap();
        assert!(cli.verbose);
        assert!(
            !Cli::try_parse_from(["cf-scanner", "serve"])
                .unwrap()
                .verbose
        );
    }

    #[test]
    fn verbose_defaults_log_filter_to_info() {
        assert_eq!(env_filter(true, None).to_string(), "info");
        assert_eq!(env_filter(false, None).to_string(), "error");
    }

    #[test]
    fn rust_log_wins_over_verbose() {
        assert_eq!(env_filter(true, Some("warn")).to_string(), "warn");
        assert_eq!(
            env_filter(false, Some("cf_scanner=debug")).to_string(),
            "cf_scanner=debug"
        );
        assert_eq!(env_filter(true, Some("")).to_string(), "info");
        assert_eq!(env_filter(false, Some("")).to_string(), "error");
        assert_eq!(env_filter(true, Some("  ")).to_string(), "info");
    }

    #[test]
    fn bind_error_hints_when_port_is_taken() {
        let taken = std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use");
        assert_eq!(
            bind_error(8765, &taken),
            "port 8765 in use — try: cf-scanner serve --port <other>"
        );
        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let msg = bind_error(8765, &denied);
        assert!(
            msg.contains("127.0.0.1:8765") && msg.contains("denied"),
            "{msg}"
        );
        assert!(!msg.contains("in use — try"), "{msg}");
    }

    #[test]
    fn serve_url_uses_the_bound_addr() {
        let v4 = "127.0.0.1:8765".parse::<std::net::SocketAddr>().unwrap();
        assert_eq!(serve_url(v4), "http://127.0.0.1:8765");
        let v6 = "[::1]:9000".parse::<std::net::SocketAddr>().unwrap();
        assert_eq!(serve_url(v6), "http://[::1]:9000");
    }

    #[test]
    fn serialize_event_never_panics() {
        struct Fails;
        impl serde::Serialize for Fails {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let verdict = api::types::Verdict {
            ip: "1.2.3.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(12),
            country: None,
            colo: None,
            phase2: None,
        };
        let line = serialize_event(&verdict).unwrap();
        assert!(line.contains("\"ip\":\"1.2.3.4\""), "{line}");
        assert!(serialize_event(&Fails).is_none());
    }
}
