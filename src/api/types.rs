//! Shared API contract for every CF-Scanner client (CLI, wizard, browser,
//! agents). The engine returns domain types; the server maps them into these
//! wire types. Never serialize engine types directly.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_WARP_PORTS: &[u16] = &[2408, 500, 854, 880, 1701, 3138, 4500];
pub const DEFAULT_CONCURRENCY: u16 = 200;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_PROBE_URL: &str = "https://cp.cloudflare.com/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Cdn,
    Warp,
}

/// CDN-mode candidate selection. WARP mode always uses a count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnPreset {
    /// 1 random IP per /24 across all ranges (~4K probes)
    Quick,
    /// 3 IPs per /24 (~12K probes)
    Normal,
    /// Every IP in all bundled ranges (~1.5M probes)
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTarget {
    Preset(CdnPreset),
    /// Exact number of candidate IPs, sampled randomly across ranges
    Count(u32),
}

/// What terminates a scan. `cap: None` = "don't stop" until `found` is met.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopCondition {
    pub found: u32,
    pub cap: Option<u32>,
}

impl StopCondition {
    pub const fn unlimited(found: u32) -> Self {
        Self { found, cap: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FragmentPreset {
    Off,
    Light,
    Medium,
    Heavy,
    Custom,
}

/// Free-form Xray fragment values (Int32Range strings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomFragment {
    /// `"tlshello"` or `"1-3"`
    pub packets: String,
    /// e.g. `"100-200"` (bytes)
    pub length: String,
    /// e.g. `"10-20"` (ms)
    pub interval: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase2Config {
    /// vless:// trojan:// vmess:// ss:// links, subscription URLs, or local
    /// Xray JSON file paths. At least one required.
    pub configs: Vec<String>,
    pub fragment: FragmentPreset,
    pub custom_fragment: Option<CustomFragment>,
    /// SNI fronting variants; empty = use each config's own SNI.
    pub snis: Vec<String>,
    /// Tiny HTTP target fetched through the tunnel to prove connectivity.
    pub probe_url: String,
    /// Parallel xray instances (1..=8).
    pub concurrency: u8,
}

impl Default for Phase2Config {
    fn default() -> Self {
        Self {
            configs: Vec::new(),
            fragment: FragmentPreset::Off,
            custom_fragment: None,
            snis: Vec::new(),
            probe_url: DEFAULT_PROBE_URL.to_owned(),
            concurrency: 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpConfig {
    /// `ip`, `ip:port`, or CIDR lines; empty = bundled pools.
    pub custom_endpoints: Vec<String>,
    /// Handshake attempts per endpoint (1..=10); drives loss %.
    pub probes_per_endpoint: u8,
    /// Pasted WireGuard / AmneziaWG config text (verification only, opt-in).
    pub wgconf: Option<String>,
    /// Run the real handshake with the user's keypair after discovery.
    pub verify_with_wgconf: bool,
    /// Opt-in: register a fresh WARP identity and build a config.
    pub generate_config: bool,
    /// Optional WARP+ license binding during registration.
    pub warp_plus_license: Option<String>,
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self {
            custom_endpoints: Vec::new(),
            probes_per_endpoint: 3,
            wgconf: None,
            verify_with_wgconf: false,
            generate_config: false,
            warp_plus_license: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanConfig {
    pub mode: Mode,
    pub target: ScanTarget,
    pub ports: Vec<u16>,
    pub stop: StopCondition,
    /// Dirty ranges to skip (CIDRs).
    pub exclude: Vec<String>,
    /// CIDRs to scan INSTEAD of the bundled ranges; empty = bundled ranges.
    pub custom_cidrs: Vec<String>,
    /// Parallel probes (1..=1000).
    pub concurrency: u16,
    /// Per-probe timeout in ms (100..=30_000).
    pub timeout_ms: u64,
    pub phase2: Option<Phase2Config>,
    pub warp: Option<WarpConfig>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Cdn,
            target: ScanTarget::Count(350),
            ports: vec![DEFAULT_PORT],
            stop: StopCondition::unlimited(20),
            exclude: Vec::new(),
            custom_cidrs: Vec::new(),
            concurrency: DEFAULT_CONCURRENCY,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            phase2: None,
            warp: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub latency_ms: Option<u32>,
    /// WARP and phase-2 only.
    pub loss_pct: Option<f32>,
    pub country: Option<String>,
    /// Phase-2 only: colo code from /cdn-cgi/trace.
    pub colo: Option<String>,
    pub phase2: Option<Phase2Verdict>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2Verdict {
    pub passed: bool,
    /// Label of the fragment setting that worked, e.g. "light" or "custom".
    pub fragment: String,
    pub sni: String,
    pub latency_ms: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned: u64,
    pub found: u64,
    /// None when the total candidate count is unknown.
    pub total: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned: u64,
    pub found: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    Progress(ScanProgress),
    Result(Box<Verdict>),
    Finished(ScanSummary),
    /// The run aborted before finishing (e.g. phase-2 setup failed); the
    /// message is redacted and safe for the UI/stderr. No `Finished` follows.
    Failed(String),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("port {0} out of range 1-65535")]
    InvalidPort(u16),
    #[error("target count must be >= 1, got {0}")]
    InvalidCount(u32),
    #[error("stop.found must be >= 1, got {0}")]
    InvalidFound(u32),
    #[error("invalid CIDR {0:?}: {1}")]
    InvalidCidr(String, String),
    #[error("invalid endpoint {0:?}: {1}")]
    InvalidEndpoint(String, String),
    #[error("phase2 is only valid in Cdn mode")]
    Phase2WrongMode,
    #[error("warp is only valid in Warp mode")]
    WarpWrongMode,
    #[error("phase2 requires at least one config")]
    NoConfigs,
    #[error("probe_url must be a non-empty http(s) URL")]
    InvalidProbeUrl,
    #[error("fragment preset Custom requires custom_fragment")]
    MissingCustomFragment,
    #[error("concurrency {0} out of range 1-1000")]
    InvalidConcurrency(u16),
    #[error("timeout_ms {0} out of range 100-30000")]
    InvalidTimeout(u64),
    #[error("probes_per_endpoint {0} out of range 1-10")]
    InvalidProbes(u8),
    #[error("phase2 concurrency {0} out of range 1-8")]
    InvalidPhase2Concurrency(u8),
    #[error("verify_with_wgconf requires wgconf text")]
    VerifyNeedsWgconf,
}

impl ScanConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_ports(&self.ports)?;
        if let ScanTarget::Count(0) = self.target {
            return Err(ConfigError::InvalidCount(0));
        }
        if self.stop.found == 0 {
            return Err(ConfigError::InvalidFound(0));
        }
        if !(1..=1000).contains(&self.concurrency) {
            return Err(ConfigError::InvalidConcurrency(self.concurrency));
        }
        if !(100..=30_000).contains(&self.timeout_ms) {
            return Err(ConfigError::InvalidTimeout(self.timeout_ms));
        }
        for cidr in self.exclude.iter().chain(self.custom_cidrs.iter()) {
            validate_cidr(cidr)?;
        }
        match self.mode {
            Mode::Cdn => {
                if self.warp.is_some() {
                    return Err(ConfigError::WarpWrongMode);
                }
                if let Some(p2) = &self.phase2 {
                    validate_phase2(p2)?;
                }
            }
            Mode::Warp => {
                if self.phase2.is_some() {
                    return Err(ConfigError::Phase2WrongMode);
                }
                if let Some(w) = &self.warp {
                    w.validate()?;
                }
            }
        }
        Ok(())
    }
}

impl WarpConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=10).contains(&self.probes_per_endpoint) {
            return Err(ConfigError::InvalidProbes(self.probes_per_endpoint));
        }
        if self.verify_with_wgconf && self.wgconf.is_none() {
            return Err(ConfigError::VerifyNeedsWgconf);
        }
        for ep in &self.custom_endpoints {
            validate_endpoint(ep)?;
        }
        Ok(())
    }
}

fn validate_ports(ports: &[u16]) -> Result<(), ConfigError> {
    if ports.is_empty() {
        return Err(ConfigError::InvalidPort(0));
    }
    for &p in ports {
        if p == 0 {
            return Err(ConfigError::InvalidPort(p));
        }
    }
    Ok(())
}

fn validate_phase2(p2: &Phase2Config) -> Result<(), ConfigError> {
    if p2.configs.is_empty() {
        return Err(ConfigError::NoConfigs);
    }
    if !(p2.probe_url.starts_with("https://") || p2.probe_url.starts_with("http://")) {
        return Err(ConfigError::InvalidProbeUrl);
    }
    if p2.fragment == FragmentPreset::Custom && p2.custom_fragment.is_none() {
        return Err(ConfigError::MissingCustomFragment);
    }
    if p2.concurrency == 0 || p2.concurrency > 8 {
        return Err(ConfigError::InvalidPhase2Concurrency(p2.concurrency));
    }
    Ok(())
}

/// Validates `a.b.c.d/prefix` (IPv4 only by design).
fn validate_cidr(s: &str) -> Result<(), ConfigError> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| ConfigError::InvalidCidr(s.to_owned(), "missing /prefix".to_owned()))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| ConfigError::InvalidCidr(s.to_owned(), "not an IPv4 address".to_owned()))?;
    let _ = ip;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ConfigError::InvalidCidr(s.to_owned(), "prefix is not a number".to_owned()))?;
    if prefix > 32 {
        return Err(ConfigError::InvalidCidr(
            s.to_owned(),
            "prefix out of range 0-32".to_owned(),
        ));
    }
    Ok(())
}

/// Validates `ip` or `ip:port` (IPv4 only by design).
fn validate_endpoint(s: &str) -> Result<(), ConfigError> {
    let (ip, port) = match s.rsplit_once(':') {
        Some((ip, port)) => (ip, Some(port)),
        None => (s, None),
    };
    if ip.contains(':') {
        return Err(ConfigError::InvalidEndpoint(
            s.to_owned(),
            "IPv6 is not supported".to_owned(),
        ));
    }
    ip.parse::<Ipv4Addr>().map_err(|_| {
        ConfigError::InvalidEndpoint(s.to_owned(), "not an IPv4 address".to_owned())
    })?;
    if let Some(p) = port {
        let p: u16 = p.parse().map_err(|_| {
            ConfigError::InvalidEndpoint(s.to_owned(), "port is not a number".to_owned())
        })?;
        if p == 0 {
            return Err(ConfigError::InvalidEndpoint(
                s.to_owned(),
                "port is 0".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> ScanConfig {
        ScanConfig::default()
    }

    #[test]
    fn default_config_is_valid() {
        assert_eq!(valid_config().validate(), Ok(()));
    }

    #[test]
    fn rejects_zero_port() {
        let mut c = valid_config();
        c.ports = vec![0];
        assert_eq!(c.validate(), Err(ConfigError::InvalidPort(0)));
    }

    #[test]
    fn accepts_max_port() {
        let mut c = valid_config();
        c.ports = vec![u16::MAX];
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_empty_ports() {
        let mut c = valid_config();
        c.ports = vec![];
        assert_eq!(c.validate(), Err(ConfigError::InvalidPort(0)));
    }

    #[test]
    fn rejects_zero_count_target() {
        let mut c = valid_config();
        c.target = ScanTarget::Count(0);
        assert_eq!(c.validate(), Err(ConfigError::InvalidCount(0)));
    }

    #[test]
    fn accepts_preset_target() {
        let mut c = valid_config();
        c.target = ScanTarget::Preset(CdnPreset::Full);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_zero_found() {
        let mut c = valid_config();
        c.stop = StopCondition {
            found: 0,
            cap: None,
        };
        assert_eq!(c.validate(), Err(ConfigError::InvalidFound(0)));
    }

    #[test]
    fn accepts_cap_below_found() {
        // A cap below `found` is valid: the cap wins before the found-count is reached.
        let mut c = valid_config();
        c.stop = StopCondition {
            found: 20,
            cap: Some(10),
        };
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn accepts_cap_equal_to_found() {
        let mut c = valid_config();
        c.stop = StopCondition {
            found: 20,
            cap: Some(20),
        };
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn accepts_unlimited_stop() {
        let mut c = valid_config();
        c.stop = StopCondition::unlimited(50);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_malformed_cidrs() {
        for bad in ["garbage", "1.2.3.4", "1.2.3.4/33", "1.2.3.4/abc", "::1/64"] {
            let mut c = valid_config();
            c.exclude = vec![bad.to_owned()];
            assert!(c.validate().is_err(), "expected {bad} to be rejected");
        }
    }

    #[test]
    fn accepts_valid_cidrs() {
        for good in ["1.2.3.0/24", "104.16.0.0/13", "172.64.0.0/13", "0.0.0.0/0"] {
            let mut c = valid_config();
            c.exclude = vec![good.to_owned()];
            assert_eq!(c.validate(), Ok(()), "expected {good} to be accepted");
        }
    }

    #[test]
    fn rejects_phase2_in_warp_mode() {
        let mut c = valid_config();
        c.mode = Mode::Warp;
        c.phase2 = Some(Phase2Config::default());
        assert_eq!(c.validate(), Err(ConfigError::Phase2WrongMode));
    }

    #[test]
    fn rejects_warp_in_cdn_mode() {
        let mut c = valid_config();
        c.warp = Some(WarpConfig::default());
        assert_eq!(c.validate(), Err(ConfigError::WarpWrongMode));
    }

    #[test]
    fn phase2_requires_configs() {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config::default());
        assert_eq!(c.validate(), Err(ConfigError::NoConfigs));
    }

    #[test]
    fn rejects_bad_probe_url() {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            probe_url: "ftp://nope".to_owned(),
            ..Default::default()
        });
        assert_eq!(c.validate(), Err(ConfigError::InvalidProbeUrl));
    }

    #[test]
    fn custom_fragment_requires_values() {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            fragment: FragmentPreset::Custom,
            ..Default::default()
        });
        assert_eq!(c.validate(), Err(ConfigError::MissingCustomFragment));
    }

    #[test]
    fn rejects_out_of_range_concurrency_and_timeout() {
        let mut c = valid_config();
        c.concurrency = 0;
        assert_eq!(c.validate(), Err(ConfigError::InvalidConcurrency(0)));
        let mut c = valid_config();
        c.concurrency = 1001;
        assert_eq!(c.validate(), Err(ConfigError::InvalidConcurrency(1001)));
        let mut c = valid_config();
        c.timeout_ms = 50;
        assert_eq!(c.validate(), Err(ConfigError::InvalidTimeout(50)));
    }

    #[test]
    fn rejects_bad_warp_endpoints() {
        let w = WarpConfig {
            custom_endpoints: vec!["1.2.3.4:0".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            w.validate(),
            Err(ConfigError::InvalidEndpoint(
                "1.2.3.4:0".to_owned(),
                "port is 0".to_owned()
            ))
        );
        let w = WarpConfig {
            custom_endpoints: vec!["::1".to_owned()],
            ..Default::default()
        };
        assert!(w.validate().is_err());
        let w = WarpConfig {
            custom_endpoints: vec!["1.2.3.4:2408".to_owned(), "5.6.7.8".to_owned()],
            ..Default::default()
        };
        assert_eq!(w.validate(), Ok(()));
    }

    #[test]
    fn rejects_bad_probes_per_endpoint() {
        let w = WarpConfig {
            probes_per_endpoint: 0,
            ..Default::default()
        };
        assert_eq!(w.validate(), Err(ConfigError::InvalidProbes(0)));
        let w = WarpConfig {
            probes_per_endpoint: 11,
            ..Default::default()
        };
        assert_eq!(w.validate(), Err(ConfigError::InvalidProbes(11)));
    }

    #[test]
    fn verify_without_wgconf_is_rejected() {
        let w = WarpConfig {
            verify_with_wgconf: true,
            ..Default::default()
        };
        assert_eq!(w.validate(), Err(ConfigError::VerifyNeedsWgconf));
        let w = WarpConfig {
            verify_with_wgconf: true,
            wgconf: Some("anything".to_owned()),
            ..Default::default()
        };
        assert_eq!(w.validate(), Ok(()));
    }

    #[test]
    fn serde_round_trip_scan_config() {
        let c = valid_config();
        let json = serde_json::to_string(&c).unwrap();
        let back: ScanConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn serde_round_trip_scan_event() {
        for event in [
            ScanEvent::Progress(ScanProgress {
                scanned: 1,
                found: 2,
                total: None,
            }),
            ScanEvent::Result(Box::new(Verdict {
                ip: "1.2.3.4".parse().unwrap(),
                port: 443,
                latency_ms: Some(42),
                loss_pct: None,
                country: Some("IR".to_owned()),
                colo: None,
                phase2: None,
            })),
            ScanEvent::Finished(ScanSummary {
                scanned: 10,
                found: 2,
                duration_ms: 5,
            }),
        ] {
            let json = serde_json::to_string(&event).unwrap();
            let back: ScanEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, back, "round-trip failed for {json}");
        }
    }

    #[test]
    fn event_tags_are_snake_case() {
        let json = serde_json::to_string(&ScanEvent::Finished(ScanSummary {
            scanned: 0,
            found: 0,
            duration_ms: 0,
        }))
        .unwrap();
        assert!(json.contains("\"type\":\"finished\""), "{json}");
    }
}
