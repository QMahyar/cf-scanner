//! Shared API contract for every CF-Scanner client (CLI, wizard, browser,
//! agents). The engine returns domain types; the server maps them into these
//! wire types. Never serialize engine types directly.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_WARP_PORTS: &[u16] = &[2408, 500, 854, 880, 1701, 3138, 4500];
/// 64 not 200: that many parallel TLS handshakes from a residential IP is
/// aggressive and risks ISP/Cloudflare rate-limiting; power users can raise
/// it via the existing 1..=1000 range.
pub const DEFAULT_CONCURRENCY: u16 = 64;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/robots.txt";

fn default_probe_url() -> String {
    DEFAULT_PROBE_URL.to_owned()
}

pub const MAX_SCAN_COUNT: u32 = 100_000;
/// Unique ports allowed in one scan; bounds the probe fan-out (OOM guard).
pub const MAX_PORTS: usize = 64;
/// CIDR entries allowed in `exclude`/`custom_cidrs`.
pub const MAX_CIDRS: usize = 64;
/// Config/SNI entries allowed in a phase-2 plan (xray spawns per combo).
pub const MAX_PHASE2_ENTRIES: usize = 8;
/// Per-entry caps so a multi-MB paste cannot land in memory, profiles, or
/// generated configs (the count caps alone leave per-string size unbounded).
pub const MAX_CONFIG_ENTRY_BYTES: usize = 8 * 1024;
pub const MAX_SNI_BYTES: usize = 256;
pub const MAX_PROBE_URL_BYTES: usize = 2 * 1024;
pub const MAX_WGCONF_BYTES: usize = 64 * 1024;
/// Upper bound for `stop.found`/`stop.cap`, matching the frontend's field
/// validators (embed/index.html `intRange(1, 100000000, ...)`); keeps the API
/// contract and its UI honest about the same limits.
pub const MAX_STOP_VALUE: u32 = 100_000_000;
/// Per-label length cap for SNI hostnames (RFC 1035: labels max 63 chars).
pub const MAX_SNI_LABEL_CHARS: usize = 63;
/// Total hostname length cap for SNI (RFC 1035: FQDN max 253 chars).
pub const MAX_SNI_HOSTNAME_CHARS: usize = 253;

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
    /// Legacy single-probe field; new clients send `probe_urls` instead.
    #[serde(default = "default_probe_url")]
    pub probe_url: String,
    /// Tiny HTTP targets fetched through the tunnel to prove connectivity;
    /// every one must return 200 for a pass (max 8, each http(s)). Empty =
    /// fall back to the legacy `probe_url`.
    #[serde(default)]
    pub probe_urls: Vec<String>,
    /// Parallel xray instances (1..=8).
    pub concurrency: u8,
}

impl Phase2Config {
    /// The URLs the run actually targets: `probe_urls` when non-empty (new
    /// clients), else the legacy single `probe_url`. Post-validation the
    /// fallbacks are unreachable; kept so callers never dial an empty list.
    pub fn effective_probe_urls(&self) -> Vec<String> {
        if !self.probe_urls.is_empty() {
            self.probe_urls.clone()
        } else if !self.probe_url.trim().is_empty() {
            vec![self.probe_url.clone()]
        } else {
            vec![DEFAULT_PROBE_URL.to_owned()]
        }
    }
}

impl Default for Phase2Config {
    fn default() -> Self {
        Self {
            configs: Vec::new(),
            fragment: FragmentPreset::Off,
            custom_fragment: None,
            snis: Vec::new(),
            probe_url: DEFAULT_PROBE_URL.to_owned(),
            probe_urls: Vec::new(),
            concurrency: 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpConfig {
    /// `ip`, `ip:port`, or CIDR lines; empty = bundled pools.
    pub custom_endpoints: Vec<String>,
    /// Handshake attempts per endpoint (1..=10); an endpoint counts as
    /// working only when every probe responds (any dropped probe excludes it).
    pub probes_per_endpoint: u8,
    /// Pasted WireGuard / AmneziaWG config text (verification only, opt-in).
    pub wgconf: Option<String>,
    /// Run the real handshake with the user's keypair after discovery.
    pub verify_with_wgconf: bool,
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self {
            custom_endpoints: Vec::new(),
            probes_per_endpoint: 3,
            wgconf: None,
            verify_with_wgconf: false,
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
    /// Include the bundled Cloudflare IPv6 ranges in the CDN phase-1 pool.
    /// Off by default so existing scans stay IPv4-only unless requested.
    #[serde(default)]
    pub include_v6: bool,
    /// Parallel probes (1..=1000).
    pub concurrency: u16,
    /// Per-probe timeout in ms (100..=30_000).
    pub timeout_ms: u64,
    /// Verify the LAST scan's candidates only, skipping phase-1 probing
    /// entirely (requires `phase2` configs and a store with candidates).
    #[serde(default)]
    pub phase2_only: bool,
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
            include_v6: false,
            concurrency: DEFAULT_CONCURRENCY,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            phase2_only: false,
            phase2: None,
            warp: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub ip: IpAddr,
    pub port: u16,
    pub latency_ms: Option<u32>,
    /// WARP and phase-2 only. WARP rows always carry 0.0 (lossy endpoints
    /// are excluded, not reported).
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
    /// Redacted failure detail from the last failed attempt, when `passed`
    /// is false (why the candidate did not verify). Absent = no detail.
    #[serde(default)]
    pub error: Option<String>,
    /// Index into the submitted `phase2.configs` list that produced this
    /// verdict; None when unknown/legacy.
    #[serde(default)]
    pub config_index: Option<u32>,
    /// Which verifier produced the verdict: "inline" (in-process vless/trojan)
    /// or "xray" (subprocess). Absent for legacy payloads.
    #[serde(default)]
    pub verifier: Option<String>,
}

/// Phase-2 progress: how many of the total (candidate × config × SNI)
/// attempts have completed. Sent while the verification phase runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2Progress {
    pub done: u64,
    pub total: u64,
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
    /// True when the run was stopped by a cancel request instead of finishing
    /// its plan. `serde(default)` keeps old clients decoding additive fields.
    #[serde(default)]
    pub cancelled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    Progress(ScanProgress),
    Result(Box<Verdict>),
    Finished(ScanSummary),
    /// Phase-2 verification progress (additive event; old clients ignore it).
    Phase2Progress(Phase2Progress),
    /// The run aborted before finishing (e.g. phase-2 setup failed); the
    /// message is redacted and safe for the UI/stderr. No `Finished` follows.
    Failed(String),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("port {0} out of range 1-65535")]
    InvalidPort(u16),
    #[error("target count must be 1..=100000, got {0}")]
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
    #[error("phase2.probe_urls must have at most 8 entries, got {0}")]
    TooManyProbeUrls(usize),
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
    #[error("ports must have at most 64 unique entries, got {0}")]
    TooManyPorts(usize),
    #[error("exclude must have at most 64 entries, got {0}")]
    TooManyExcludes(usize),
    #[error("custom_cidrs must have at most 64 entries, got {0}")]
    TooManyCidrs(usize),
    #[error("phase2.configs must have at most 8 entries, got {0}")]
    TooManyConfigs(usize),
    #[error("phase2.snis must have at most 8 entries, got {0}")]
    TooManySnis(usize),
    #[error("phase2 config entry exceeds {0} bytes")]
    ConfigEntryTooLong(usize),
    #[error("phase2 SNI entry exceeds {0} bytes")]
    SniTooLong(usize),
    #[error("probe_url exceeds {0} bytes")]
    ProbeUrlTooLong(usize),
    #[error("wgconf exceeds {0} bytes")]
    WgconfTooLong(usize),
    #[error("phase2_only requires phase2 configs")]
    Phase2OnlyNeedsConfigs,
    #[error("phase2_only is only valid in Cdn mode")]
    Phase2OnlyWrongMode,
    #[error("preset targets are CDN-only; WARP scans take a count of endpoints")]
    WarpPresetNotAllowed,
    #[error("custom_cidrs is CDN-only; WARP takes custom_endpoints")]
    WarpCidrsNotAllowed,
    #[error("custom fragment {0} must be an integer or a range like 100-200, got {1:?}")]
    InvalidFragment(&'static str, String),
    #[error("invalid SNI {0:?}: {1}")]
    InvalidSni(String, String),
    #[error("stop.found out of range 1-100000000, got {0}")]
    InvalidFoundUpper(u32),
    #[error("stop.cap out of range 1-100000000, got {0}")]
    InvalidCap(u32),
    #[error(
        "custom fragment {0} range out of bounds (length 1-65535, interval 1-60000), got {1:?}"
    )]
    InvalidFragmentRange(&'static str, String),
}

impl ScanConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_ports(&self.ports)?;
        if let ScanTarget::Count(n) = self.target {
            if n == 0 {
                return Err(ConfigError::InvalidCount(0));
            }
            // The engine spawns one probe task per sampled host and the plan
            // pre-allocates a set of 2n entries: cap the count so an
            // unauthenticated API call cannot abort the process (OOM).
            if n > MAX_SCAN_COUNT {
                return Err(ConfigError::InvalidCount(n));
            }
        }
        if self.stop.found == 0 {
            return Err(ConfigError::InvalidFound(0));
        }
        // The frontend caps both stop fields at MAX_STOP_VALUE; the server
        // enforces the same bound so an agent cannot request a stop condition
        // the UI never offers (contract parity).
        if self.stop.found > MAX_STOP_VALUE {
            return Err(ConfigError::InvalidFoundUpper(self.stop.found));
        }
        if let Some(cap) = self.stop.cap {
            // cap 0 would stop before the first probe: the engine compares
            // scanned >= cap, which holds trivially.
            if cap == 0 || cap > MAX_STOP_VALUE {
                return Err(ConfigError::InvalidCap(cap));
            }
        }
        if self.exclude.len() > MAX_CIDRS {
            return Err(ConfigError::TooManyExcludes(self.exclude.len()));
        }
        if self.custom_cidrs.len() > MAX_CIDRS {
            return Err(ConfigError::TooManyCidrs(self.custom_cidrs.len()));
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
                if self.phase2_only && self.phase2.is_none() {
                    return Err(ConfigError::Phase2OnlyNeedsConfigs);
                }
                if let Some(p2) = &self.phase2 {
                    validate_phase2(p2)?;
                }
            }
            Mode::Warp => {
                if self.phase2_only {
                    return Err(ConfigError::Phase2OnlyWrongMode);
                }
                if self.phase2.is_some() {
                    return Err(ConfigError::Phase2WrongMode);
                }
                if let ScanTarget::Preset(_) = self.target {
                    return Err(ConfigError::WarpPresetNotAllowed);
                }
                if !self.custom_cidrs.is_empty() {
                    return Err(ConfigError::WarpCidrsNotAllowed);
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
        if self
            .wgconf
            .as_ref()
            .is_some_and(|w| w.len() > MAX_WGCONF_BYTES)
        {
            return Err(ConfigError::WgconfTooLong(MAX_WGCONF_BYTES));
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
    // Duplicate ports probe the same endpoint twice: dedupe, then cap the
    // unique set so an unauthenticated API call cannot fan out unbounded.
    let mut unique = ports.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() > MAX_PORTS {
        return Err(ConfigError::TooManyPorts(unique.len()));
    }
    Ok(())
}

fn validate_phase2(p2: &Phase2Config) -> Result<(), ConfigError> {
    if p2.configs.is_empty() {
        return Err(ConfigError::NoConfigs);
    }
    if p2.configs.len() > MAX_PHASE2_ENTRIES {
        return Err(ConfigError::TooManyConfigs(p2.configs.len()));
    }
    if p2.configs.iter().any(|c| c.len() > MAX_CONFIG_ENTRY_BYTES) {
        return Err(ConfigError::ConfigEntryTooLong(MAX_CONFIG_ENTRY_BYTES));
    }
    if p2.snis.len() > MAX_PHASE2_ENTRIES {
        return Err(ConfigError::TooManySnis(p2.snis.len()));
    }
    if p2.snis.iter().any(|s| s.len() > MAX_SNI_BYTES) {
        return Err(ConfigError::SniTooLong(MAX_SNI_BYTES));
    }
    // SNI is embedded into generated xray configs and TLS hellos verbatim:
    // restrict it to well-formed hostnames or raw IPs so a crafted value
    // cannot smuggle arbitrary text into a config file. An entry in a
    // non-empty list is always used as an override, so "" is invalid too
    // ("empty" only means an empty list, i.e. each config's own SNI).
    for sni in &p2.snis {
        validate_sni(sni)?;
    }
    // The legacy single URL stays the source of truth only when the list is
    // absent, so a probes-driven request can never trip on a stale/blank
    // legacy field (and legacy requests keep their exact validation).
    if p2.probe_urls.is_empty() {
        if p2.probe_url.len() > MAX_PROBE_URL_BYTES {
            return Err(ConfigError::ProbeUrlTooLong(MAX_PROBE_URL_BYTES));
        }
        if !(p2.probe_url.starts_with("https://") || p2.probe_url.starts_with("http://")) {
            return Err(ConfigError::InvalidProbeUrl);
        }
    } else {
        if p2.probe_urls.len() > MAX_PHASE2_ENTRIES {
            return Err(ConfigError::TooManyProbeUrls(p2.probe_urls.len()));
        }
        for url in &p2.probe_urls {
            if url.len() > MAX_PROBE_URL_BYTES {
                return Err(ConfigError::ProbeUrlTooLong(MAX_PROBE_URL_BYTES));
            }
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(ConfigError::InvalidProbeUrl);
            }
        }
    }
    if p2.fragment == FragmentPreset::Custom && p2.custom_fragment.is_none() {
        return Err(ConfigError::MissingCustomFragment);
    }
    if let Some(f) = &p2.custom_fragment {
        validate_fragment(f)?;
    }
    if p2.concurrency == 0 || p2.concurrency > 8 {
        return Err(ConfigError::InvalidPhase2Concurrency(p2.concurrency));
    }
    Ok(())
}

/// Fragment values are xray Int32Range strings: an integer or a `lo-hi`
/// range. `packets` additionally accepts the special `tlshello` value the
/// presets hardcode. `length`/`interval` also carry numeric bounds mirroring
/// the frontend's `customRange` validators (1-65535 / 1-60000, lo <= hi).
fn validate_fragment(f: &CustomFragment) -> Result<(), ConfigError> {
    validate_fragment_field("packets", &f.packets, true, None)?;
    validate_fragment_field("length", &f.length, false, Some((1, 65_535)))?;
    validate_fragment_field("interval", &f.interval, false, Some((1, 60_000)))
}

fn validate_fragment_field(
    field: &'static str,
    value: &str,
    allow_tlshello: bool,
    bounds: Option<(u64, u64)>,
) -> Result<(), ConfigError> {
    if allow_tlshello && value == "tlshello" {
        return Ok(());
    }
    let mut parts = value.split('-');
    let (lo, hi): (&str, Option<&str>) = match (parts.next(), parts.next(), parts.next()) {
        (Some(lo), None, None) => (lo, None),
        (Some(lo), Some(hi), None) => (lo, Some(hi)),
        _ => return Err(ConfigError::InvalidFragment(field, value.to_owned())),
    };
    if !is_ascii_digits(lo) || hi.is_some_and(|h| !is_ascii_digits(h)) {
        return Err(ConfigError::InvalidFragment(field, value.to_owned()));
    }
    if let Some((min, max)) = bounds {
        let lo: u64 = lo.parse().unwrap_or(0);
        let hi: u64 = hi.map(|h| h.parse().unwrap_or(0)).unwrap_or(lo);
        if lo < min || hi > max || lo > hi {
            return Err(ConfigError::InvalidFragmentRange(field, value.to_owned()));
        }
    }
    Ok(())
}

fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Validates `ip/prefix` for both address families. Delegates parsing to the
/// canonical `ranges::parse_cidr`; only the deliberate v6 /0 rejection (host
/// count exceeds u128) stays here, checked after the parse succeeds.
fn validate_cidr(s: &str) -> Result<(), ConfigError> {
    let cidr = crate::ranges::parse_cidr(s)
        .map_err(|e| ConfigError::InvalidCidr(s.to_owned(), format!("{e}")))?;
    // A v6 /0 covers 2^128 addresses: `Cidr::host_count` saturates at
    // u128::MAX, so exclusion/planning math on it would be off by one.
    if cidr.addr.is_ipv6() && cidr.prefix == 0 {
        return Err(ConfigError::InvalidCidr(
            s.to_owned(),
            "IPv6 /0 is not supported (host count exceeds u128)".to_owned(),
        ));
    }
    Ok(())
}

/// Validates an SNI value: a raw IP (v4/v6) or a hostname with RFC 1035
/// label rules (letters/digits/hyphens, no empty labels, no leading/trailing
/// hyphen, max 63 chars per label and 253 total). Shared by `phase2.snis`
/// and `POST /api/config/export`, the two places user SNI reaches the wire.
pub fn validate_sni(s: &str) -> Result<(), ConfigError> {
    if s.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if s.len() > MAX_SNI_HOSTNAME_CHARS {
        return Err(ConfigError::InvalidSni(
            s.to_owned(),
            format!("hostname exceeds {MAX_SNI_HOSTNAME_CHARS} characters"),
        ));
    }
    let well_formed = !s.is_empty()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_SNI_LABEL_CHARS
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if well_formed {
        Ok(())
    } else {
        Err(ConfigError::InvalidSni(
            s.to_owned(),
            "must be a hostname (a-z A-Z 0-9 - per label) or an IP address".to_owned(),
        ))
    }
}

/// Parses `ip` or `ip:port` endpoint entries. IPv4 only by design: WARP
/// dials raw IPv4 addresses. The port stays optional — a bare IP inherits
/// the scan's port list. Canonical parser shared with the engine.
pub(crate) fn parse_endpoint(s: &str) -> Result<(IpAddr, Option<u16>), ConfigError> {
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
    let ip: Ipv4Addr = ip.trim().parse().map_err(|_| {
        ConfigError::InvalidEndpoint(s.to_owned(), "not an IPv4 address".to_owned())
    })?;
    let port = match port {
        Some(p) => {
            let p: u16 = p.trim().parse().map_err(|_| {
                ConfigError::InvalidEndpoint(s.to_owned(), "port is not a number".to_owned())
            })?;
            if p == 0 {
                return Err(ConfigError::InvalidEndpoint(
                    s.to_owned(),
                    "port is 0".to_owned(),
                ));
            }
            Some(p)
        }
        None => None,
    };
    Ok((IpAddr::V4(ip), port))
}

/// Validates `ip` or `ip:port` (IPv4 only by design).
fn validate_endpoint(s: &str) -> Result<(), ConfigError> {
    parse_endpoint(s).map(|_| ())
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
    fn rejects_count_above_cap() {
        let mut c = valid_config();
        c.target = ScanTarget::Count(MAX_SCAN_COUNT + 1);
        assert_eq!(
            c.validate(),
            Err(ConfigError::InvalidCount(MAX_SCAN_COUNT + 1))
        );
    }

    #[test]
    fn accepts_count_at_cap() {
        let mut c = valid_config();
        c.target = ScanTarget::Count(MAX_SCAN_COUNT);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_v6_slash_zero() {
        let mut c = valid_config();
        c.custom_cidrs = vec!["::/0".to_owned()];
        assert!(matches!(c.validate(), Err(ConfigError::InvalidCidr(_, _))));
    }

    #[test]
    fn accepts_v6_slash_one() {
        let mut c = valid_config();
        c.custom_cidrs = vec!["2001:db8::/1".to_owned()];
        assert_eq!(c.validate(), Ok(()));
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
        for bad in [
            "garbage",
            "1.2.3.4",
            "1.2.3.4/33",
            "1.2.3.4/abc",
            "2606:4700::/129",
            "2001:db8::g/64",
        ] {
            let mut c = valid_config();
            c.exclude = vec![bad.to_owned()];
            assert!(c.validate().is_err(), "expected {bad} to be rejected");
        }
    }

    #[test]
    fn accepts_valid_cidrs() {
        for good in [
            "1.2.3.0/24",
            "104.16.0.0/13",
            "172.64.0.0/13",
            "0.0.0.0/0",
            "2606:4700::/32",
            "2400:cb00::/32",
            "::1/128",
        ] {
            let mut c = valid_config();
            c.exclude = vec![good.to_owned()];
            assert_eq!(c.validate(), Ok(()), "expected {good} to be accepted");
        }
    }

    #[test]
    fn include_v6_defaults_to_false() {
        assert!(!ScanConfig::default().include_v6);
        let json = r#"{
            "mode": "Cdn",
            "target": {"Count": 10},
            "ports": [443],
            "stop": {"found": 1, "cap": null},
            "exclude": [],
            "custom_cidrs": [],
            "concurrency": 10,
            "timeout_ms": 3000,
            "phase2": null,
            "warp": null
        }"#;
        let cfg: ScanConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.include_v6, "omitted field must deserialize as false");
    }

    #[test]
    fn include_v6_round_trips_through_serde() {
        let mut c = valid_config();
        c.include_v6 = true;
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"include_v6\":true"), "{json}");
        let back: ScanConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
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
    fn probe_urls_replace_the_legacy_single_url() {
        // A probes-driven request with a blank legacy field stays valid.
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            probe_urls: vec!["https://cp.cloudflare.com/".to_owned()],
            ..Default::default()
        });
        assert_eq!(c.validate(), Ok(()));
        let bad = Phase2Config {
            probe_urls: vec!["ftp://nope".to_owned()],
            ..Phase2Config::default()
        };
        assert_eq!(valid_config_with(bad), Err(ConfigError::InvalidProbeUrl));
    }

    #[test]
    fn rejects_too_many_or_oversized_probe_urls() {
        let over = Phase2Config {
            probe_urls: (0..=MAX_PHASE2_ENTRIES)
                .map(|i| format!("https://cp.cloudflare.com/{i}"))
                .collect(),
            ..Phase2Config::default()
        };
        assert_eq!(
            valid_config_with(over),
            Err(ConfigError::TooManyProbeUrls(MAX_PHASE2_ENTRIES + 1))
        );
        let long = Phase2Config {
            probe_urls: vec![format!("https://x/{}", "a".repeat(MAX_PROBE_URL_BYTES))],
            ..Phase2Config::default()
        };
        assert_eq!(
            valid_config_with(long),
            Err(ConfigError::ProbeUrlTooLong(MAX_PROBE_URL_BYTES))
        );
        let at_cap = Phase2Config {
            probe_urls: (0..MAX_PHASE2_ENTRIES)
                .map(|i| format!("https://cp.cloudflare.com/{i}"))
                .collect(),
            ..Phase2Config::default()
        };
        assert_eq!(valid_config_with(at_cap), Ok(()), "8 URLs must be accepted");
    }

    fn valid_config_with(p2: Phase2Config) -> Result<(), ConfigError> {
        // Configs are checked before probe URLs, so the probe validation
        // only runs when at least one config entry exists.
        let mut p2 = p2;
        p2.configs = vec!["vless://uuid@example.com:443".to_owned()];
        let mut c = valid_config();
        c.phase2 = Some(p2);
        c.validate()
    }

    #[test]
    fn effective_probe_urls_prefer_the_list_then_the_legacy_url() {
        assert_eq!(
            Phase2Config::default().effective_probe_urls(),
            vec![DEFAULT_PROBE_URL.to_owned()]
        );
        let legacy = Phase2Config {
            probe_url: "https://example.com/one".to_owned(),
            ..Phase2Config::default()
        };
        assert_eq!(
            legacy.effective_probe_urls(),
            vec!["https://example.com/one".to_owned()]
        );
        let listed = Phase2Config {
            probe_urls: vec![
                "https://a.example/".to_owned(),
                "https://b.example/".to_owned(),
            ],
            ..Phase2Config::default()
        };
        assert_eq!(
            listed.effective_probe_urls(),
            vec![
                "https://a.example/".to_owned(),
                "https://b.example/".to_owned()
            ]
        );
    }

    #[test]
    fn probe_urls_round_trip_through_serde() {
        let p2 = Phase2Config {
            probe_urls: vec!["https://a.example/".to_owned()],
            ..Phase2Config::default()
        };
        let json = serde_json::to_string(&p2).unwrap();
        assert!(
            json.contains("\"probe_urls\":[\"https://a.example/\"]"),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Phase2Config>(&json).unwrap(), p2);
        // Omitted fields keep old payloads decoding: probe_urls defaults to
        // the empty list and an explicit probe_url round-trips as-is.
        let legacy = r#"{"configs":["vless://uuid@example.com:443"],"fragment":"Off","snis":[],"probe_url":"https://cp.cloudflare.com/","concurrency":3}"#;
        let decoded: Phase2Config = serde_json::from_str(legacy).unwrap();
        assert!(decoded.probe_urls.is_empty());
        assert_eq!(
            decoded.probe_url, "https://cp.cloudflare.com/",
            "an explicit probe_url survives decoding"
        );
        // A payload with no probe_url at all falls back to the default.
        let bare = r#"{"configs":["vless://uuid@example.com:443"],"fragment":"Off","snis":[],"concurrency":3}"#;
        let decoded: Phase2Config = serde_json::from_str(bare).unwrap();
        assert_eq!(decoded.probe_url, DEFAULT_PROBE_URL);
    }

    #[test]
    fn phase2_verdict_config_index_defaults_to_none() {
        let legacy = r#"{"passed":true,"fragment":"light","sni":"","latency_ms":42}"#;
        let v: Phase2Verdict = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            v.config_index, None,
            "omitted field must deserialize as None"
        );
        let json = serde_json::to_string(&Phase2Verdict {
            passed: true,
            fragment: "light".to_owned(),
            sni: "a.me".to_owned(),
            latency_ms: Some(7),
            error: None,
            config_index: Some(2),
            verifier: Some("inline".to_owned()),
        })
        .unwrap();
        assert!(json.contains("\"config_index\":2"), "{json}");
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
                cancelled: false,
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
            cancelled: false,
        }))
        .unwrap();
        assert!(json.contains("\"type\":\"finished\""), "{json}");
    }

    #[test]
    fn summary_cancelled_defaults_to_false() {
        let json = r#"{"scanned":1,"found":0,"duration_ms":10}"#;
        let s: ScanSummary = serde_json::from_str(json).unwrap();
        assert!(!s.cancelled, "omitted field must deserialize as false");
        let event_json = r#"{"type":"finished","scanned":1,"found":0,"duration_ms":10}"#;
        let event: ScanEvent = serde_json::from_str(event_json).unwrap();
        assert!(matches!(event, ScanEvent::Finished(s) if !s.cancelled));
    }

    #[test]
    fn summary_cancelled_round_trips() {
        let s = ScanSummary {
            scanned: 7,
            found: 3,
            duration_ms: 42,
            cancelled: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"cancelled\":true"), "{json}");
        assert_eq!(serde_json::from_str::<ScanSummary>(&json).unwrap(), s);
    }

    #[test]
    fn ports_are_deduped_for_the_cap() {
        // 100 raw entries collapse to 2 unique ports: valid, not an error.
        let mut c = valid_config();
        c.ports = (0..100).map(|_| 443).collect();
        assert_eq!(c.validate(), Ok(()));
        let mut c = valid_config();
        c.ports = vec![443, 8443, 443, 2408, 443];
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_too_many_unique_ports() {
        let mut c = valid_config();
        c.ports = (1..=65).collect();
        assert_eq!(c.validate(), Err(ConfigError::TooManyPorts(65)));
        let mut c = valid_config();
        c.ports = (1..=MAX_PORTS as u16).collect();
        assert_eq!(c.validate(), Ok(()), "64 unique ports must be accepted");
    }

    #[test]
    fn rejects_too_many_exclude_and_custom_cidrs() {
        let mut c = valid_config();
        c.exclude = (0..=MAX_CIDRS).map(|i| format!("10.0.{i}.0/24")).collect();
        assert_eq!(
            c.validate(),
            Err(ConfigError::TooManyExcludes(MAX_CIDRS + 1))
        );
        let mut c = valid_config();
        c.custom_cidrs = (0..=MAX_CIDRS).map(|i| format!("10.0.{i}.0/24")).collect();
        assert_eq!(c.validate(), Err(ConfigError::TooManyCidrs(MAX_CIDRS + 1)));
        let mut c = valid_config();
        c.custom_cidrs = (0..MAX_CIDRS).map(|i| format!("10.0.{i}.0/24")).collect();
        assert_eq!(c.validate(), Ok(()), "64 CIDRs must be accepted");
    }

    #[test]
    fn rejects_too_many_phase2_configs_and_snis() {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: (0..=MAX_PHASE2_ENTRIES)
                .map(|i| format!("vless://uuid@example.com:{i}"))
                .collect(),
            ..Default::default()
        });
        assert_eq!(
            c.validate(),
            Err(ConfigError::TooManyConfigs(MAX_PHASE2_ENTRIES + 1))
        );
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            snis: (0..=MAX_PHASE2_ENTRIES)
                .map(|i| format!("sni{i}.example.com"))
                .collect(),
            ..Default::default()
        });
        assert_eq!(
            c.validate(),
            Err(ConfigError::TooManySnis(MAX_PHASE2_ENTRIES + 1))
        );
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: (0..MAX_PHASE2_ENTRIES)
                .map(|i| format!("vless://uuid@example.com:{i}"))
                .collect(),
            snis: (0..MAX_PHASE2_ENTRIES)
                .map(|i| format!("sni{i}.example.com"))
                .collect(),
            ..Default::default()
        });
        assert_eq!(c.validate(), Ok(()), "8 configs + 8 snis must be accepted");
    }

    #[test]
    fn rejects_malformed_custom_fragment_values() {
        for (field, bad) in [
            ("packets", "nope"),
            ("packets", ""),
            ("packets", "1-2-3"),
            ("packets", "-5"),
            ("packets", "5-"),
            ("length", "abc"),
            ("length", "100,200"),
            ("length", "1 0"),
            ("length", ""),
            ("interval", "10.5"),
            ("interval", "10-20-30"),
        ] {
            let f = CustomFragment {
                packets: "tlshello".to_owned(),
                length: "100-200".to_owned(),
                interval: "10-20".to_owned(),
            };
            let f = match field {
                "packets" => CustomFragment {
                    packets: bad.to_owned(),
                    ..f
                },
                "length" => CustomFragment {
                    length: bad.to_owned(),
                    ..f
                },
                _ => CustomFragment {
                    interval: bad.to_owned(),
                    ..f
                },
            };
            let mut c = valid_config();
            c.phase2 = Some(Phase2Config {
                configs: vec!["vless://uuid@example.com:443".to_owned()],
                fragment: FragmentPreset::Custom,
                custom_fragment: Some(f),
                ..Default::default()
            });
            assert!(
                matches!(c.validate(), Err(ConfigError::InvalidFragment(f, _)) if f == field),
                "expected {bad:?} in {field} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_valid_custom_fragment_values() {
        for (packets, length, interval) in [
            ("tlshello", "100", "10"),
            ("tlshello", "100-200", "10-20"),
            ("1-3", "100-200", "10-20"),
            ("2", "50", "5-50"),
        ] {
            let mut c = valid_config();
            c.phase2 = Some(Phase2Config {
                configs: vec!["vless://uuid@example.com:443".to_owned()],
                fragment: FragmentPreset::Custom,
                custom_fragment: Some(CustomFragment {
                    packets: packets.to_owned(),
                    length: length.to_owned(),
                    interval: interval.to_owned(),
                }),
                ..Default::default()
            });
            assert_eq!(c.validate(), Ok(()), "{packets}/{length}/{interval}");
        }
    }

    #[test]
    fn rejects_out_of_bounds_custom_fragment_ranges() {
        for (field, bad) in [
            ("length", "0"),
            ("length", "0-100"),
            ("length", "100-0"),
            ("length", "65536"),
            ("length", "1-70000"),
            ("length", "200-100"),
            ("interval", "0-10"),
            ("interval", "1-60001"),
            ("interval", "50000-100"),
        ] {
            let mut c = valid_config();
            c.phase2 = Some(Phase2Config {
                configs: vec!["vless://uuid@example.com:443".to_owned()],
                fragment: FragmentPreset::Custom,
                custom_fragment: Some(CustomFragment {
                    packets: "tlshello".to_owned(),
                    length: "100-200".to_owned(),
                    interval: "10-20".to_owned(),
                }),
                ..Default::default()
            });
            let cf = c.phase2.as_mut().unwrap().custom_fragment.as_mut().unwrap();
            match field {
                "length" => cf.length = bad.to_owned(),
                "interval" => cf.interval = bad.to_owned(),
                _ => unreachable!(),
            }
            assert!(
                matches!(c.validate(), Err(ConfigError::InvalidFragmentRange(f, _)) if f == field),
                "expected {bad:?} in {field} to be rejected"
            );
        }
        // Bounds edges are accepted.
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            fragment: FragmentPreset::Custom,
            custom_fragment: Some(CustomFragment {
                packets: "tlshello".to_owned(),
                length: "1-65535".to_owned(),
                interval: "1-60000".to_owned(),
            }),
            ..Default::default()
        });
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_stop_values_above_the_frontend_cap() {
        // The frontend's validators cap found/cap at 100_000_000; the server
        // must not accept more (contract parity, review finding).
        let mut c = valid_config();
        c.stop.found = MAX_STOP_VALUE + 1;
        assert_eq!(
            c.validate(),
            Err(ConfigError::InvalidFoundUpper(MAX_STOP_VALUE + 1))
        );
        let mut c = valid_config();
        c.stop = StopCondition {
            found: 1,
            cap: Some(0),
        };
        assert_eq!(c.validate(), Err(ConfigError::InvalidCap(0)));
        let mut c = valid_config();
        c.stop = StopCondition {
            found: 1,
            cap: Some(MAX_STOP_VALUE + 1),
        };
        assert_eq!(
            c.validate(),
            Err(ConfigError::InvalidCap(MAX_STOP_VALUE + 1))
        );
        // Edges are accepted.
        let mut c = valid_config();
        c.stop = StopCondition {
            found: MAX_STOP_VALUE,
            cap: Some(MAX_STOP_VALUE),
        };
        assert_eq!(c.validate(), Ok(()));
    }

    fn phase2_with_snis(snis: Vec<String>) -> ScanConfig {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            snis,
            ..Default::default()
        });
        c
    }

    #[test]
    fn accepts_valid_snis() {
        let max_label = "x".repeat(MAX_SNI_LABEL_CHARS);
        for good in [
            "www.cloudflare.com",
            "a",
            "a-b.c-d.e",
            "1.2.3.4",
            "2606:4700::1111",
            max_label.as_str(),
        ] {
            assert_eq!(validate_sni(good), Ok(()), "expected {good:?} to pass");
        }
        let max_host = format!(
            "{}.{}.{}.{}",
            "a".repeat(MAX_SNI_LABEL_CHARS),
            "a".repeat(MAX_SNI_LABEL_CHARS),
            "a".repeat(MAX_SNI_LABEL_CHARS),
            "a".repeat(MAX_SNI_HOSTNAME_CHARS - 3 * MAX_SNI_LABEL_CHARS - 3)
        );
        assert_eq!(max_host.len(), MAX_SNI_HOSTNAME_CHARS);
        assert_eq!(validate_sni(&max_host), Ok(()));
        let c = phase2_with_snis(vec!["www.cloudflare.com".to_owned(), "1.2.3.4".to_owned()]);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn rejects_invalid_snis() {
        let too_long = "a".repeat(MAX_SNI_HOSTNAME_CHARS + 1);
        let long_label = format!("{}.a", "a".repeat(MAX_SNI_LABEL_CHARS + 1));
        for bad in [
            "",
            "bad_sni",
            "sni with space",
            "-leading",
            "trailing-",
            "a.-b",
            "a.b-",
            "a..b",
            ".a",
            "a.",
            "ünïcode.example",
            too_long.as_str(),
            long_label.as_str(),
            "a,b",
        ] {
            assert!(
                matches!(validate_sni(bad), Err(ConfigError::InvalidSni(_, _))),
                "expected {bad:?} to be rejected"
            );
        }
        // A non-empty snis list must not smuggle "" (it becomes an override).
        let c = phase2_with_snis(vec!["".to_owned()]);
        assert!(matches!(c.validate(), Err(ConfigError::InvalidSni(_, _))));
        let c = phase2_with_snis(vec!["ok.example".to_owned(), "nope_sni".to_owned()]);
        assert!(matches!(c.validate(), Err(ConfigError::InvalidSni(_, _))));
        // An empty list stays the "use each config's own SNI" sentinel.
        let c = phase2_with_snis(vec![]);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn parse_endpoint_accepts_ip_with_and_without_port() {
        assert_eq!(
            parse_endpoint("1.2.3.4").unwrap(),
            ("1.2.3.4".parse::<IpAddr>().unwrap(), None)
        );
        assert_eq!(
            parse_endpoint("1.2.3.4:2408").unwrap(),
            ("1.2.3.4".parse::<IpAddr>().unwrap(), Some(2408))
        );
        assert_eq!(
            parse_endpoint(" 1.2.3.4 : 443 ").unwrap(),
            ("1.2.3.4".parse::<IpAddr>().unwrap(), Some(443))
        );
    }

    #[test]
    fn parse_endpoint_rejects_invalid_input() {
        for bad in [
            "garbage",
            "1.2.3.4:abc",
            "1.2.3.4:0",
            "1.2.3.4:99999",
            "::1",
            "::1:443",
            "1.2.3.4:443:443",
        ] {
            assert!(
                parse_endpoint(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn validate_endpoint_and_parse_endpoint_agree() {
        // WarpConfig validation must accept exactly what the shared parser does.
        for good in ["1.2.3.4", "1.2.3.4:2408", "1.2.3.4:443"] {
            let w = WarpConfig {
                custom_endpoints: vec![good.to_owned()],
                ..Default::default()
            };
            assert_eq!(w.validate(), Ok(()), "{good}");
        }
        for bad in ["::1", "1.2.3.4:0", "1.2.3.4:abc"] {
            let w = WarpConfig {
                custom_endpoints: vec![bad.to_owned()],
                ..Default::default()
            };
            assert!(w.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn cidr_validation_delegates_to_ranges_parser() {
        // The shared ranges parser masks host bits; validation must still
        // accept host-ful CIDRs like the legacy validator did.
        for good in ["1.2.3.99/24", "10.0.0.0/8", "2001:db8::1/64", "0.0.0.0/0"] {
            let mut c = valid_config();
            c.custom_cidrs = vec![good.to_owned()];
            assert_eq!(c.validate(), Ok(()), "{good}");
        }
        for bad in [
            "garbage",
            "1.2.3.4/33",
            "2606:4700::/129",
            "::/0",
            "1.2.3.4/abc",
        ] {
            let mut c = valid_config();
            c.custom_cidrs = vec![bad.to_owned()];
            assert!(c.validate().is_err(), "{bad}");
        }
    }
}
