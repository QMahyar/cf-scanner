pub use super::error::*;
pub use super::limits::*;
pub use super::validate::*;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnPreset {
    Quick,
    Normal,
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTarget {
    Preset(CdnPreset),
    Count(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    Tcp,
    #[default]
    Tls,
    Http,
}

impl std::fmt::Display for ProbeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Tls => write!(f, "tls"),
            Self::Http => write!(f, "http"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomFragment {
    pub packets: String,
    pub length: String,
    pub interval: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Config {
    pub configs: Vec<String>,
    pub fragment: FragmentPreset,
    pub custom_fragment: Option<CustomFragment>,
    pub snis: Vec<String>,
    #[serde(default = "default_probe_url")]
    pub probe_url: String,
    #[serde(default)]
    pub probe_urls: Vec<String>,
    pub concurrency: u8,
}

impl Phase2Config {
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
    pub custom_endpoints: Vec<String>,
    pub probes_per_endpoint: u8,
    pub wgconf: Option<String>,
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
    pub exclude: Vec<String>,
    pub custom_cidrs: Vec<String>,
    #[serde(default)]
    pub include_v6: bool,
    pub concurrency: u16,
    pub timeout_ms: u64,
    #[serde(default)]
    pub phase2_only: bool,
    #[serde(default)]
    pub phase2: Option<Phase2Config>,
    #[serde(default)]
    pub warp: Option<WarpConfig>,
    #[serde(default)]
    pub loss_threshold: Option<u32>,
    #[serde(default)]
    pub min_latency_ms: Option<u32>,
    #[serde(default)]
    pub idle_hold_ms: u64,
    #[serde(default)]
    pub colo_filter: Vec<String>,
    #[serde(default)]
    pub probe_mode: ProbeMode,
    #[serde(default = "default_accepted_http_codes")]
    pub accepted_http_codes: Vec<u16>,
    #[serde(default)]
    pub speed_test: bool,
    #[serde(default)]
    pub min_speed_mbps: Option<f32>,
    #[serde(default)]
    pub neighbor_count: u32,
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
            loss_threshold: None,
            min_latency_ms: None,
            idle_hold_ms: 0,
            colo_filter: Vec::new(),
            probe_mode: ProbeMode::Tls,
            accepted_http_codes: default_accepted_http_codes(),
            speed_test: false,
            min_speed_mbps: None,
            neighbor_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub ip: IpAddr,
    pub port: u16,
    pub latency_ms: Option<u32>,
    pub country: Option<String>,
    pub colo: Option<String>,
    pub phase2: Option<Phase2Verdict>,
    #[serde(default)]
    pub sent: u32,
    #[serde(default)]
    pub received: u32,
    #[serde(default)]
    pub loss_pct: Option<u32>,
    #[serde(default)]
    pub fail_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2Verdict {
    pub passed: bool,
    pub fragment: FragmentPreset,
    pub sni: String,
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub config_index: Option<u32>,
    #[serde(default)]
    pub verifier: Option<Verifier>,
    #[serde(default)]
    pub speed_test_mbps: Option<f32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Phase2Progress {
    pub done: u64,
    pub total: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned: u64,
    pub found: u64,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned: u64,
    pub found: u64,
    pub duration_ms: u64,
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
    Phase2Progress(Phase2Progress),
    Failed(FailedPayload),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultsPayload {
    pub results: Vec<Verdict>,
    pub summary: Option<ScanSummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusPayload {
    pub version: String,
    pub is_running: bool,
    pub has_candidates: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangesPayload {
    pub host_count: u64,
    pub last_updated: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XrayStatusPayload {
    pub found: bool,
    pub path: Option<String>,
    pub data_dir: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XrayDownloadResponse {
    pub success: bool,
    pub path: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResponse {
    pub wgconf: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfigRequest {
    pub config: String,
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfigResponse {
    pub uri: String,
}

impl ScanConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let result = (|| -> Result<(), ConfigError> {
            validate_ports(&self.ports)?;
            if let ScanTarget::Count(n) = self.target {
                if n == 0 {
                    return Err(ConfigError::InvalidCount(0));
                }
                if n > MAX_SCAN_COUNT {
                    return Err(ConfigError::InvalidCount(n));
                }
            }
            if self.stop.found == 0 {
                return Err(ConfigError::InvalidFound(0));
            }
            if self.stop.found > MAX_STOP_VALUE {
                return Err(ConfigError::InvalidFoundUpper(self.stop.found));
            }
            if let Some(cap) = self.stop.cap {
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
            if let Some(t) = self.loss_threshold
                && t > 100
            {
                return Err(ConfigError::InvalidLossThreshold(t));
            }
            if let Some(t) = self.min_latency_ms
                && !(1..=MAX_MIN_LATENCY_MS).contains(&t)
            {
                return Err(ConfigError::InvalidMinLatency(t));
            }
            if self.idle_hold_ms > MAX_IDLE_HOLD_MS {
                return Err(ConfigError::InvalidIdleHold(self.idle_hold_ms));
            }
            if self.colo_filter.len() > MAX_COLO_CODES {
                return Err(ConfigError::TooManyColos(self.colo_filter.len()));
            }
            for code in &self.colo_filter {
                let valid =
                    (3..=5).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphabetic());
                if !valid {
                    return Err(ConfigError::InvalidColo(code.clone()));
                }
            }
            for code in &self.accepted_http_codes {
                if !(100..=599).contains(code) {
                    return Err(ConfigError::InvalidHttpStatusCode(*code));
                }
            }
            if self.probe_mode == ProbeMode::Http && self.accepted_http_codes.is_empty() {
                return Err(ConfigError::EmptyHttpCodes);
            }
            if let Some(min) = self.min_speed_mbps {
                if !self.speed_test {
                    return Err(ConfigError::MinSpeedNeedsSpeedTest);
                }
                if !min.is_finite() || min <= 0.0 {
                    return Err(ConfigError::InvalidMinSpeed);
                }
            }
            if self.neighbor_count > MAX_NEIGHBORS {
                return Err(ConfigError::InvalidNeighbor(self.neighbor_count));
            }
            for cidr in self.exclude.iter().chain(self.custom_cidrs.iter()) {
                parse_cidr(cidr)?;
            }
            match self.mode {
                Mode::Cdn => {
                    if self.warp.is_some() {
                        return Err(ConfigError::WarpWrongMode);
                    }
                    if self.phase2_only && self.phase2.is_none() {
                        return Err(ConfigError::Phase2OnlyNeedsConfigs);
                    }
                    if self.speed_test && self.phase2.is_none() {
                        return Err(ConfigError::SpeedTestNeedsConfigs);
                    }
                    if let Some(p2) = &self.phase2 {
                        validate_phase2(p2)?;
                    }
                }
                Mode::Warp => {
                    if self.probe_mode != ProbeMode::Tls {
                        return Err(ConfigError::ProbeWrongMode);
                    }
                    if self.phase2_only {
                        return Err(ConfigError::Phase2OnlyWrongMode);
                    }
                    if self.phase2.is_some() {
                        return Err(ConfigError::Phase2WrongMode);
                    }
                    if !self.colo_filter.is_empty() {
                        return Err(ConfigError::ColoWrongMode);
                    }
                    if self.speed_test {
                        return Err(ConfigError::SpeedTestWrongMode);
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
        })();
        result.map_err(|e| {
            let sanitize = |s: String| {
                let san = crate::configs::sanitize_error_text(&s);
                san.chars().take(512).collect::<String>()
            };
            match e {
                ConfigError::InvalidCidr(s, reason) => {
                    ConfigError::InvalidCidr(sanitize(s), sanitize(reason))
                }
                ConfigError::InvalidEndpoint(s, reason) => {
                    ConfigError::InvalidEndpoint(sanitize(s), sanitize(reason))
                }
                ConfigError::InvalidSni(s, reason) => {
                    ConfigError::InvalidSni(sanitize(s), sanitize(reason))
                }
                ConfigError::InvalidFragment(field, val) => {
                    ConfigError::InvalidFragment(field, sanitize(val))
                }
                ConfigError::InvalidFragmentRange(field, val) => {
                    ConfigError::InvalidFragmentRange(field, sanitize(val))
                }
                ConfigError::NonRoutableCidr(s) => ConfigError::NonRoutableCidr(sanitize(s)),
                ConfigError::NonRoutableEndpoint(s) => {
                    ConfigError::NonRoutableEndpoint(sanitize(s))
                }
                other => {
                    let sanitized = crate::configs::sanitize_error_text(&other.to_string());
                    let _: String = sanitized.chars().take(512).collect();
                    other
                }
            }
        })
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
            parse_endpoint(ep)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
