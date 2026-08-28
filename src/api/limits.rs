use super::types::Port;

pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_WARP_PORTS: &[Port] = &[
    Port::new(2408),
    Port::new(500),
    Port::new(854),
    Port::new(880),
    Port::new(1701),
    Port::new(3138),
    Port::new(4500),
];
/// 64 not 200: that many parallel TLS handshakes from a residential IP is
/// aggressive and risks ISP/Cloudflare rate-limiting; power users can raise
/// it via the existing 1..=1000 range.
pub const DEFAULT_CONCURRENCY: u16 = 64;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/robots.txt";

pub fn default_probe_url() -> String {
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
/// WARP+ license key cap on the register endpoint (real keys are short).
pub const MAX_LICENSE_BYTES: usize = 256;
/// Original config URI cap for /api/config/export (one URI, not a file dump).
pub const MAX_EXPORT_CONFIG_BYTES: usize = 64 * 1024;
/// Upper bound for `stop.found`/`stop.cap`, matching the frontend's field
/// validators (embed/index.html `intRange(1, 100000000, ...)`); keeps the API
/// contract and its UI honest about the same limits.
pub const MAX_STOP_VALUE: u32 = 100_000_000;
/// Per-label length cap for SNI hostnames (RFC 1035: labels max 63 chars).
pub const MAX_SNI_LABEL_CHARS: usize = 63;
/// Total hostname length cap for SNI (RFC 1035: FQDN max 253 chars).
pub const MAX_SNI_HOSTNAME_CHARS: usize = 253;
/// Custom WARP endpoint lines allowed in one scan; bounds the UDP fan-out
/// (`warp_groups` materializes one task per endpoint × port).
pub const MAX_ENDPOINTS: usize = 2048;
/// Subscription-expanded specs allowed per entry (prevents a hostile URL
/// from expanding into an unbounded spec vector on the user's machine).
pub const MAX_SUBSCRIPTION_SPECS: usize = 2048;
/// Total specs allowed across all phase-2 entries in one scan (fan-out bound).
pub const MAX_PHASE2_TOTAL_SPECS: usize = 4096;
