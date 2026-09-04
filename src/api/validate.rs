use std::net::{IpAddr, Ipv4Addr};

use super::error::ConfigError;
use super::limits::*;

fn banned(net: &str) -> bool {
    net.parse::<IpAddr>()
        .map(|addr| banned_ip(&addr))
        .unwrap_or(false)
}

pub(crate) fn banned_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xC0 == 64)
                || v4.octets()[0] & 0xF0 == 240
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || (v4.octets()[0] == 100 && v4.octets()[1] & 0xC0 == 64)
                    || v4.octets()[0] & 0xF0 == 240
                    || v4.octets()[0] == 0;
            }
            v6.is_unicast_link_local() || matches!(v6.segments()[0], 0xfc00..=0xfdff)
        }
    }
}

pub(crate) fn reject_default_warp_ports(cfg: &super::types::ScanConfig) -> Result<(), ConfigError> {
    if cfg.mode == super::types::Mode::Warp
        && cfg.ports.as_slice() == [super::types::Port::new(DEFAULT_PORT)]
    {
        return Err(ConfigError::DefaultWarpPort);
    }
    Ok(())
}

pub(crate) fn reject_non_routable(cfg: &super::types::ScanConfig) -> Result<(), ConfigError> {
    match cfg.mode {
        super::types::Mode::Cdn => {
            for cidr in &cfg.custom_cidrs {
                let net = cidr.split('/').next().unwrap_or(cidr).trim();
                if banned(net) {
                    return Err(ConfigError::NonRoutableCidr(cidr.clone()));
                }
            }
        }
        super::types::Mode::Warp => {
            let endpoints = cfg
                .warp
                .as_ref()
                .map(|w| w.custom_endpoints.as_slice())
                .unwrap_or(&[]);
            for ep in endpoints {
                let ip = parse_endpoint(ep)
                    .map(|(ip, _)| ip)
                    .map_err(|_| ConfigError::NonRoutableEndpoint(ep.clone()))?;
                if banned_ip(&ip) {
                    return Err(ConfigError::NonRoutableEndpoint(ep.clone()));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_ports(ports: &[super::types::Port]) -> Result<(), ConfigError> {
    if ports.is_empty() {
        return Err(ConfigError::InvalidPort(0));
    }
    if ports.len() > MAX_PORTS * 64 {
        return Err(ConfigError::TooManyPorts(ports.len()));
    }
    for &p in ports {
        if p.get() == 0 {
            return Err(ConfigError::InvalidPort(0));
        }
    }
    let mut unique: Vec<u16> = ports.iter().map(|p| p.get()).collect();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() > MAX_PORTS {
        return Err(ConfigError::TooManyPorts(unique.len()));
    }
    Ok(())
}

pub(crate) fn validate_phase2(p2: &super::types::Phase2Config) -> Result<(), ConfigError> {
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
    for entry in &p2.configs {
        if entry.contains("://") {
            let lower = entry.to_ascii_lowercase();
            if lower.starts_with("http://") {
                return Err(ConfigError::InvalidProbeUrl);
            }
        }
    }
    for sni in &p2.snis {
        validate_sni(sni)?;
    }
    if p2.probe_urls.is_empty() {
        validate_probe_url(&p2.probe_url)?;
    } else {
        if p2.probe_urls.len() > MAX_PHASE2_ENTRIES {
            return Err(ConfigError::TooManyProbeUrls(p2.probe_urls.len()));
        }
        for url in &p2.probe_urls {
            validate_probe_url(url)?;
        }
    }
    if p2.fragment == super::types::FragmentPreset::Custom && p2.custom_fragment.is_none() {
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

fn validate_probe_url(url: &str) -> Result<(), ConfigError> {
    if url.len() > MAX_PROBE_URL_BYTES {
        return Err(ConfigError::ProbeUrlTooLong(MAX_PROBE_URL_BYTES));
    }
    if !(url.starts_with("https://")) {
        return Err(ConfigError::InvalidProbeUrl);
    }
    if crate::ranges::validate_fetch_url(url).is_err() {
        // Map to the payload-free variant on purpose: probe URLs must never surface in errors or logs.
        return Err(ConfigError::InvalidProbeUrl);
    }
    Ok(())
}

pub(crate) fn validate_fragment(f: &super::types::CustomFragment) -> Result<(), ConfigError> {
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

pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), ConfigError> {
    let (ip_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| ConfigError::InvalidCidr(s.to_owned(), "missing /prefix".to_owned()))?;
    let addr: IpAddr = ip_s
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidCidr(s.to_owned(), "invalid IP address".to_owned()))?;
    let prefix: u8 = prefix_s
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidCidr(s.to_owned(), "prefix is not a number".to_owned()))?;
    let bits: u8 = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > bits {
        return Err(ConfigError::InvalidCidr(
            s.to_owned(),
            format!("prefix out of range 0-{bits}"),
        ));
    }
    if addr.is_ipv6() && prefix == 0 {
        return Err(ConfigError::InvalidCidr(
            s.to_owned(),
            "IPv6 /0 is not supported (host count exceeds u128)".to_owned(),
        ));
    }
    Ok((addr, prefix))
}

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

pub fn parse_endpoint(s: &str) -> Result<(IpAddr, Option<u16>), ConfigError> {
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
