use std::path::PathBuf;

use cf_scanner::api;
use cf_scanner::api::types::DEFAULT_CONCURRENCY;
use cf_scanner::export::ExportFormatArg;
use clap::{Parser, Subcommand, ValueEnum};

pub mod scan_args;

#[derive(Parser)]
#[command(
    name = "cf-scanner",
    version,
    propagate_version = true,
    about = "Find working Cloudflare IPs/endpoints on ISP-restricted networks",
    after_help = EXAMPLES
)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        help = "Verbose output: per-IP diagnostics on stderr + info logs"
    )]
    pub(crate) verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Print {\"error\": \"…\"} on stdout when the program fails (for scripts)"
    )]
    pub(crate) json_errors: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

const EXAMPLES: &str = "\
Examples:
  cf-scanner scan --preset quick           1 IP per /24 of the official ranges (fast sweep)
  cf-scanner scan --mode warp --count 512  WARP endpoint discovery
  cf-scanner scan --phase2-configs vless://uuid@host:443 --phase2-fragment medium
                                           Verify candidates through a real proxy config
  cf-scanner scan --retry-last --phase2-configs vless://uuid@host:443
                                           Re-run the last scan, re-supplying phase-2 keys

Results print as newline-delimited JSON on stdout; pipe to jq for processing.
Progress and diagnostics go to stderr.";

#[derive(Subcommand)]
pub(crate) enum Command {
    #[command(
        about = "Scan Cloudflare ranges (CDN probe + optional xray phase 2) or WARP endpoints"
    )]
    Scan {
        #[command(flatten)]
        args: Box<ScanArgs>,
    },
    #[command(about = "Interactive guided scan setup")]
    Wizard,
    #[command(about = "Refresh the bundled Cloudflare IP range lists")]
    Ranges {
        #[command(subcommand)]
        action: RangesAction,
    },
    #[command(about = "Generate or export a WARP WireGuard identity (wgconf)")]
    WarpConfig {
        #[command(subcommand)]
        action: WarpConfigAction,
    },
    #[command(
        about = "Render one config into a shareable URI with a verified IP:port override",
        long_about = "Re-render a vless/vmess/trojan/ss share link so it dials the given \nendpoint instead of its original host. Use it to turn a phase-2 \nverified scan result into a ready-to-import config."
    )]
    ExportConfig {
        #[arg(long, help = "The share URI to re-render (vless/vmess/trojan/ss)")]
        config: String,
        #[arg(
            long,
            help = "Verified endpoint IP to dial instead of the config's host"
        )]
        ip: std::net::Ipv4Addr,
        #[arg(
            long,
            help = "Verified endpoint port to dial instead of the config's port"
        )]
        port: u16,
        #[arg(
            long,
            help = "Override the TLS SNI in the rendered URI (defaults to the config's own SNI)"
        )]
        sni: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum RangesAction {
    Refresh {
        #[arg(
            long,
            help = "Also refresh the IPv6 range list (both files stay current afterwards)"
        )]
        ipv6: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum WarpConfigAction {
    Generate {
        #[arg(
            long,
            help = "Write the wgconf here (default: print to stdout; with a .conf extension the file is written with owner-only permissions)"
        )]
        out: Option<String>,
        #[arg(
            long,
            help = "Cloudflare license key from the dashboard (optional; anonymous accounts work)"
        )]
        license: Option<String>,
        #[arg(
            long,
            help = "Force a specific WARP endpoint (host:port); default is the built-in engage.cloudflareclient.com:2408"
        )]
        endpoint: Option<String>,
    },
    Export {
        #[arg(
            long,
            help = "Write the exported wgconf here (default: print to stdout)"
        )]
        out: Option<String>,
        #[arg(
            long,
            help = "Override the Endpoint line with a specific WARP endpoint (host:port)"
        )]
        endpoint: Option<String>,
    },
}

#[derive(clap::Args, Clone)]
pub(crate) struct ScanArgs {
    #[arg(
        long,
        value_enum,
        default_value_t = ModeArg::Cdn,
        help_heading = "Candidate selection",
        help = "cdn: probe Cloudflare ranges for working proxies; warp: discover usable WARP UDP endpoints"
    )]
    pub(crate) mode: ModeArg,

    #[arg(
        long,
        value_enum,
        conflicts_with = "count",
        help_heading = "Candidate selection",
        help = "Sized sweep of the official ranges: quick = 1 IP per /24, normal = 3 per /24, full = every usable host"
    )]
    pub(crate) preset: Option<PresetArg>,

    #[arg(
        long,
        conflicts_with = "preset",
        help_heading = "Candidate selection",
        help = "Probe N random candidates from the ranges instead of a preset"
    )]
    pub(crate) count: Option<u32>,

    #[arg(
        long,
        alias = "stop-after",
        default_value_t = 20,
        help_heading = "Stopping",
        help = "Stop as soon as N endpoints are found (default 20)"
    )]
    pub(crate) target: u32,

    #[arg(
        long,
        alias = "max-probes",
        help_heading = "Stopping",
        help = "Hard probe-count ceiling: stop once N probes have been sent, found or not"
    )]
    pub(crate) cap: Option<u32>,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Candidate selection",
        help = "Comma-separated TCP ports to probe (default 443 for CDN, 2408,500,1701,4500 for WARP)"
    )]
    pub(crate) ports: Option<Vec<u16>>,

    #[arg(
        long,
        default_value_t = DEFAULT_CONCURRENCY,
        help_heading = "Tuning",
        help = "Parallel probe workers (default 256, max 1000)"
    )]
    pub(crate) concurrency: u16,

    #[arg(
        long,
        default_value_t = 3000,
        help_heading = "Tuning",
        help = "Per-probe timeout in milliseconds (default 3000)"
    )]
    pub(crate) timeout_ms: u64,

    #[arg(
        long,
        value_name = "PCT",
        help_heading = "Tuning",
        long_help = "Filter results whose packet-loss rate exceeds PCT (0-100); default keeps everything"
    )]
    pub(crate) loss_threshold: Option<u32>,

    #[arg(
        long,
        value_name = "MS",
        help_heading = "Tuning",
        long_help = "Drop results whose handshake latency is below MS (throttled routes look fast but stall); default keeps everything"
    )]
    pub(crate) min_latency: Option<u32>,

    #[arg(
        long,
        value_name = "MS",
        default_value_t = 0,
        help_heading = "Tuning",
        long_help = "After the TLS handshake, hold the connection idle for MS and fail the probe if it is reset (0 = off)"
    )]
    pub(crate) idle_hold_ms: u64,

    #[arg(
        long,
        value_enum,
        default_value_t = ProbeArg::Tls,
        value_name = "MODE",
        help_heading = "Tuning",
        long_help = "Phase-1 probe protocol: tcp (connect only), tls (handshake, default), http (GET /cdn-cgi/trace over TLS)"
    )]
    pub(crate) probe: ProbeArg,

    #[arg(
        long,
        value_name = "CODES",
        value_delimiter = ',',
        help_heading = "Tuning",
        long_help = "HTTP probe mode: status codes that count as working (100-599); default 200,301,302"
    )]
    pub(crate) http_status_code: Option<Vec<u16>>,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 0,
        help_heading = "Tuning",
        long_help = "After a hit, probe up to N neighboring IPs in the same /24 through the same workers (0 = off, max 64, CDN-only)"
    )]
    pub(crate) neighbor_scan: u32,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Candidate selection",
        help = "Comma-separated CIDR blocks to skip (e.g. 10.0.0.0/8,192.168.0.0/16)"
    )]
    pub(crate) exclude: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Candidate selection",
        help = "Scan only these CIDR blocks instead of the official Cloudflare ranges"
    )]
    pub(crate) custom_cidrs: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "IATA",
        help_heading = "Candidate selection",
        long_help = "Keep only phase-2 results whose Cloudflare colo matches one of these IATA codes (e.g. HKG,NRT); results without colo data pass through with a one-time warning"
    )]
    pub(crate) colo: Vec<String>,

    #[arg(
        long,
        help_heading = "Candidate selection",
        help = "Include the IPv6 range pool (CDN mode; WARP pools are IPv4 only)"
    )]
    pub(crate) ipv6: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Phase 2 (xray verification)",
        help = "Share URIs (vless/vmess/trojan/ss) to verify candidates against; enables phase 2"
    )]
    pub(crate) phase2_configs: Vec<String>,

    #[arg(
        long,
        value_enum,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        help = "DPI-bypass fragmentation preset; values are packets=length/interval: light 100-200/10-20, medium 50-200/10-40, heavy 10-300/5-50 (tlshello)"
    )]
    pub(crate) phase2_fragment: Option<FragmentArg>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        help = "Custom fragment as \"packets,length,interval\" (e.g. 1-3,10-20,10-20); requires --phase2-fragment custom"
    )]
    pub(crate) phase2_custom: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        help = "SNI values to try for each config (first that verifies wins)"
    )]
    pub(crate) phase2_snis: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        help = "HTTPS URLs fetched through the tunnel to confirm it works; default is the built-in /cdn-cgi/trace check. Takes precedence over the single built-in URL"
    )]
    pub(crate) phase2_probe_urls: Vec<String>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        help = "Parallel phase-2 verifications (default 4, max 8)"
    )]
    pub(crate) phase2_concurrency: Option<u8>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)",
        long_help = "After the stop condition and phase-2 verification, download an 8 MiB sample \
                     through each verified endpoint (via xray) and record MB/s. CDN mode only."
    )]
    pub(crate) speed_test: bool,

    #[arg(
        long,
        value_name = "MBPS",
        requires = "phase2_configs",
        requires = "speed_test",
        help_heading = "Phase 2 (xray verification)",
        long_help = "Drop endpoints that measure below MB/s from the working set (requires --speed-test)"
    )]
    pub(crate) min_speed: Option<f32>,

    #[arg(
        long,
        help_heading = "Export",
        long_help = "After the scan, look up ASN/ISP for each working endpoint via ipwho.is and \nannotate exported results (best-effort, never fails the scan)"
    )]
    pub(crate) enrich_asn: bool,

    #[arg(
        long,
        help_heading = "WARP",
        help = "WireGuard handshake attempts per endpoint (default 3, max 10, WARP mode only)"
    )]
    pub(crate) warp_probes: Option<u8>,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "WARP",
        help = "Scan these WARP endpoints (ip:port or host:port) instead of the bundled pools"
    )]
    pub(crate) warp_endpoints: Vec<String>,

    #[arg(
        long,
        requires = "warp_wgconf_file",
        help_heading = "WARP",
        help = "After discovery, complete a full WireGuard handshake using your config (proves usable, not just reachable)"
    )]
    pub(crate) warp_verify: bool,

    #[arg(
        long,
        alias = "warp-wgconf",
        help_heading = "WARP",
        help = "Path to a WireGuard/AmneziaWG .conf used for --warp-verify (file stays local; the key is never logged)"
    )]
    pub(crate) warp_wgconf_file: Option<String>,

    #[arg(
        long,
        help_heading = "Tuning",
        help = "Deterministic RNG seed for --count sampling and neighbor probes (same seed = same plan)"
    )]
    pub(crate) seed: Option<u64>,

    #[arg(
        long,
        help_heading = "Candidate selection",
        long_help = "Replay the last scan's configuration (saved automatically after each scan). \
                     Phase-2 configs and WARP keys are never saved; re-supply them with --phase2-configs / --warp-wgconf-file."
    )]
    pub(crate) retry_last: bool,

    #[arg(
        long,
        help_heading = "Export",
        help = "Write results to this file when the scan ends (\"-\" = stdout)"
    )]
    pub(crate) export: Option<PathBuf>,

    #[arg(
        long,
        requires = "export",
        value_enum,
        default_value_t = ExportFormatArg::Csv,
        help_heading = "Export",
        help = "Export format: csv, json, base64, raw, singbox, clash, sharelinks, v2ray, shadowrocket, quantumult (default csv)"
    )]
    pub(crate) export_format: ExportFormatArg,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub(crate) enum ModeArg {
    Cdn,
    Warp,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub(crate) enum ProbeArg {
    Tcp,
    Tls,
    Http,
}

impl From<ProbeArg> for api::types::ProbeMode {
    fn from(p: ProbeArg) -> Self {
        match p {
            ProbeArg::Tcp => api::types::ProbeMode::Tcp,
            ProbeArg::Tls => api::types::ProbeMode::Tls,
            ProbeArg::Http => api::types::ProbeMode::Http,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
pub(crate) enum FragmentArg {
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
pub(crate) enum PresetArg {
    Quick,
    Normal,
    Full,
}

impl From<ModeArg> for api::types::Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Cdn => api::types::Mode::Cdn,
            ModeArg::Warp => api::types::Mode::Warp,
        }
    }
}

impl From<PresetArg> for api::types::CdnPreset {
    fn from(p: PresetArg) -> Self {
        match p {
            PresetArg::Quick => api::types::CdnPreset::Quick,
            PresetArg::Normal => api::types::CdnPreset::Normal,
            PresetArg::Full => api::types::CdnPreset::Full,
        }
    }
}

pub(crate) fn parse_error_line(err: &clap::Error, json_errors: bool) -> Option<String> {
    if !json_errors || !err.use_stderr() {
        return None;
    }
    Some(serde_json::json!({ "error": err.to_string() }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_parse_errors_cover_real_errors_but_not_help() {
        let usage = match Cli::try_parse_from(["cf-scanner", "bogus-command"]) {
            Err(e) => e,
            Ok(_) => panic!("bogus-command must fail to parse"),
        };
        assert!(usage.use_stderr());
        let line = parse_error_line(&usage, true).unwrap();
        assert!(line.contains("\"error\""), "{line}");
        assert!(parse_error_line(&usage, false).is_none());
        let help = match Cli::try_parse_from(["cf-scanner", "--help"]) {
            Err(e) => e,
            Ok(_) => panic!("--help must short-circuit as a parse error"),
        };
        assert!(!help.use_stderr(), "help output is not an error");
        assert!(parse_error_line(&help, true).is_none());
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
        assert!(!Cli::try_parse_from(["cf-scanner", "scan"]).unwrap().verbose);
    }
    #[test]
    fn every_long_scan_flag_is_documented_in_help_and_readme() {
        let readme = include_str!("../README.md");
        // Only the non-test part of this file: the test's own string literals
        // contain the markers being scanned for.
        let src = include_str!("cli.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("cli.rs must contain the test gate marker");
        let mut flags = Vec::new();
        let mut rest = src;
        while let Some(pos) = rest.find("#[arg(") {
            rest = &rest[pos + 6..];
            let end = rest.find(")]").expect("arg block must close");
            let block = &rest[..end];
            // Field decl always sits on its own line after the block:
            // `pub(crate) name: Type,` or, inside enum variants, `name: Type,`.
            let after = &rest[end + 2..];
            let field_pos = after.find('\n').map(|nl| &after[nl..]).unwrap_or(after);
            let name = field_pos
                .trim_start()
                .split(':')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .last()
                .unwrap_or("")
                .to_owned();
            if block.contains("long") && !name.is_empty() {
                // snake_case field → --kebab-case flag.
                let kebab = name.replace('_', "-");
                flags.push((kebab, block.to_owned()));
            }
            rest = after;
        }
        assert!(flags.len() >= 30, "flag extraction broke: {}", flags.len());
        for (name, block) in &flags {
            let has_help = block.contains("help =") || block.contains("long_help");
            assert!(
                has_help,
                "--{name} has no help text; every long flag needs one (T-20)"
            );
            let dash = format!("--{name}");
            assert!(
                readme.contains(&dash),
                "--{name} is documented in --help but missing from README.md's Commands reference"
            );
        }
    }
}
