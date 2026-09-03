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
pub const DEFAULT_CONCURRENCY: u16 = 64;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/robots.txt";

pub fn default_probe_url() -> String {
    DEFAULT_PROBE_URL.to_owned()
}

pub const DEFAULT_ACCEPTED_HTTP_CODES: &[u16] = &[200, 301, 302];

pub fn default_accepted_http_codes() -> Vec<u16> {
    DEFAULT_ACCEPTED_HTTP_CODES.to_vec()
}

pub const MAX_SCAN_COUNT: u32 = 100_000;
pub const MAX_PORTS: usize = 64;
pub const MAX_CIDRS: usize = 64;
pub const MAX_PHASE2_ENTRIES: usize = 8;
pub const MAX_CONFIG_ENTRY_BYTES: usize = 8 * 1024;
pub const MAX_SNI_BYTES: usize = 256;
pub const MAX_PROBE_URL_BYTES: usize = 2 * 1024;
pub const MAX_WGCONF_BYTES: usize = 64 * 1024;
pub const MAX_LICENSE_BYTES: usize = 256;
pub const MAX_EXPORT_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_STOP_VALUE: u32 = 100_000_000;
pub const MAX_IDLE_HOLD_MS: u64 = 60_000;
pub const MAX_SNI_LABEL_CHARS: usize = 63;
pub const MAX_SNI_HOSTNAME_CHARS: usize = 253;
pub const MAX_ENDPOINTS: usize = 2048;
pub const MAX_SUBSCRIPTION_SPECS: usize = 2048;
pub const MAX_PHASE2_TOTAL_SPECS: usize = 4096;
