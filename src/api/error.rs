use super::limits::{DEFAULT_PORT, MAX_ENDPOINTS};

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
    #[error("warp.custom_endpoints must have at most {MAX_ENDPOINTS} entries, got {0}")]
    TooManyEndpoints(usize),
    #[error(
        "custom_cidrs entry {0:?} is not routable (loopback, link-local, unspecified, private/RFC1918, or ULA)"
    )]
    NonRoutableCidr(String),
    #[error(
        "custom endpoint {0:?} is not routable (loopback, link-local, unspecified, private/RFC1918, or ULA)"
    )]
    NonRoutableEndpoint(String),
    #[error(
        "warp scans need explicit UDP ports; the CDN default {DEFAULT_PORT} is not valid (pass e.g. 2408,500)"
    )]
    DefaultWarpPort,
}
