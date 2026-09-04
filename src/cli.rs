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
    #[arg(long, global = true)]
    pub(crate) verbose: bool,

    #[arg(long, global = true)]
    pub(crate) json_errors: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

const EXAMPLES: &str = "\
Examples:
  cf-scanner scan --preset quick          Fast CDN sweep (1 IP per /24)
  cf-scanner scan --mode warp --count 512 WARP endpoint discovery
  cf-scanner scan --phase2-configs vless://... --phase2-fragment medium
                                          Verify candidates through xray
Results print as newline-delimited JSON; pipe to jq for processing.";

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
    #[command(about = "Render one config into a shareable URI with a verified IP:port override")]
    ExportConfig {
        #[arg(long)]
        config: String,
        #[arg(long)]
        ip: std::net::Ipv4Addr,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        sni: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum RangesAction {
    Refresh {
        #[arg(long)]
        ipv6: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum WarpConfigAction {
    Generate {
        #[arg(long)]
        out: Option<String>,
        #[arg(long)]
        license: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },
    Export {
        #[arg(long)]
        out: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },
}

#[derive(clap::Args, Clone)]
pub(crate) struct ScanArgs {
    #[arg(long, value_enum, default_value_t = ModeArg::Cdn, help_heading = "Candidate selection")]
    pub(crate) mode: ModeArg,

    #[arg(
        long,
        value_enum,
        conflicts_with = "count",
        help_heading = "Candidate selection"
    )]
    pub(crate) preset: Option<PresetArg>,

    #[arg(long, conflicts_with = "preset", help_heading = "Candidate selection")]
    pub(crate) count: Option<u32>,

    #[arg(
        long,
        alias = "stop-after",
        default_value_t = 20,
        help_heading = "Stopping"
    )]
    pub(crate) target: u32,

    #[arg(long, alias = "max-probes", help_heading = "Stopping")]
    pub(crate) cap: Option<u32>,

    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    pub(crate) ports: Option<Vec<u16>>,

    #[arg(
        long,
        default_value_t = DEFAULT_CONCURRENCY,
        help_heading = "Tuning"
    )]
    pub(crate) concurrency: u16,

    #[arg(long, default_value_t = 3000, help_heading = "Tuning")]
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

    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    pub(crate) exclude: Vec<String>,

    #[arg(long, value_delimiter = ',', help_heading = "Candidate selection")]
    pub(crate) custom_cidrs: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "IATA",
        help_heading = "Candidate selection",
        long_help = "Keep only phase-2 results whose Cloudflare colo matches one of these IATA codes (e.g. HKG,NRT); results without colo data pass through with a one-time warning"
    )]
    pub(crate) colo: Vec<String>,

    #[arg(long, help_heading = "Candidate selection")]
    pub(crate) ipv6: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_configs: Vec<String>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_only: bool,

    #[arg(
        long,
        value_enum,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_fragment: Option<FragmentArg>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_custom: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_snis: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
    )]
    pub(crate) phase2_probe_urls: Vec<String>,

    #[arg(
        long,
        requires = "phase2_configs",
        help_heading = "Phase 2 (xray verification)"
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

    #[arg(long, help_heading = "WARP")]
    pub(crate) warp_probes: Option<u8>,

    #[arg(long, value_delimiter = ',', help_heading = "WARP")]
    pub(crate) warp_endpoints: Vec<String>,

    #[arg(long, requires = "warp_wgconf_file", help_heading = "WARP")]
    pub(crate) warp_verify: bool,

    #[arg(long, alias = "warp-wgconf", help_heading = "WARP")]
    pub(crate) warp_wgconf_file: Option<String>,

    #[arg(long, help_heading = "Tuning")]
    pub(crate) seed: Option<u64>,

    #[arg(long, help_heading = "Export")]
    pub(crate) export: Option<PathBuf>,

    #[arg(
        long,
        requires = "export",
        value_enum,
        default_value_t = ExportFormatArg::Csv,
        help_heading = "Export"
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
}
