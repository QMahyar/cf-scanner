//! Shared API contract for every CF-Scanner client (CLI, wizard, browser,
//! agents). The engine returns domain types; the server maps them into these
//! wire types. Never serialize engine types directly.

pub use super::error::*;
pub use super::limits::*;
pub use super::validate::*;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;

/// A validated TCP/UDP port number (1..=65535). Rejects 0 at deserialization
/// time so invalid ports never reach the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port(pub u16);

impl Port {
    pub const fn new(n: u16) -> Self {
        Port(n)
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

impl From<u16> for Port {
    fn from(n: u16) -> Self {
        Port(n)
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u16::deserialize(d)?;
        if n == 0 {
            return Err(serde::de::Error::custom("port must be > 0"));
        }
        Ok(Port(n))
    }
}

impl Serialize for Port {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

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
#[serde(rename_all = "lowercase")]
pub enum FragmentPreset {
    Off,
    Light,
    Medium,
    Heavy,
    Custom,
}

impl std::fmt::Display for FragmentPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Light => write!(f, "light"),
            Self::Medium => write!(f, "medium"),
            Self::Heavy => write!(f, "heavy"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verifier {
    Inline,
    Xray,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    pub mode: Mode,
    pub target: ScanTarget,
    pub ports: Vec<Port>,
    pub stop: StopCondition,
    /// Dirty ranges to skip (CIDRs). Validated as CIDRs by `validate_phase2()`.
    pub exclude: Vec<String>,
    /// CIDRs to scan INSTEAD of the bundled ranges; empty = bundled ranges.
    /// Validated as CIDRs by `validate_phase2()`.
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
            ports: vec![Port(DEFAULT_PORT)],
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
    pub country: Option<String>,
    /// Phase-2 only: colo code from /cdn-cgi/trace.
    pub colo: Option<String>,
    pub phase2: Option<Phase2Verdict>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2Verdict {
    pub passed: bool,
    /// Fragment preset that was used for this verdict.
    pub fragment: FragmentPreset,
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
    /// Which verifier produced the verdict: inline (in-process vless/trojan)
    /// or xray (subprocess). Absent for legacy payloads.
    #[serde(default)]
    pub verifier: Option<Verifier>,
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
pub struct FailedPayload {
    pub reason: String,
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
    Failed(FailedPayload),
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
        reject_default_warp_ports(self)?;
        reject_non_routable(self)?;
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
        if self.custom_endpoints.len() > MAX_ENDPOINTS {
            return Err(ConfigError::TooManyEndpoints(self.custom_endpoints.len()));
        }
        for ep in &self.custom_endpoints {
            validate_endpoint(ep)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
