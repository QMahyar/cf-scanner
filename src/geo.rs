//! Offline GeoIP (Task 15): country from the embedded db-ip Lite country
//! mmdb (CC BY 4.0 — the UI footer links the license), colo from
//! /cdn-cgi/trace bodies parsed defensively (phase 2 only). An absent or
//! unreadable embedded db degrades to `None` everywhere.

use std::net::IpAddr;

use maxminddb::geoip2::Country;

/// Build-time embedded db; build.rs guarantees the file exists. Normal
/// builds embed the real db-ip Lite mmdb; `CFSCANNER_OFFLINE_BUILD` embeds a
/// small placeholder instead, so `Reader::from_source` below fails and every
/// lookup degrades to `None`.
static EMBEDDED_MMDB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/geoip.mmdb"));

pub struct Geo {
    country: Option<maxminddb::Reader<&'static [u8]>>,
}

impl Geo {
    pub fn embedded() -> Self {
        let country = match maxminddb::Reader::from_source(EMBEDDED_MMDB) {
            Ok(reader) => Some(reader),
            Err(err) => {
                tracing::warn!("embedded geoip mmdb unusable: {err}");
                None
            }
        };
        Self { country }
    }

    /// ISO-3166 alpha-2 country code for an IP (v4 or v6), when the embedded
    /// db has it.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.country.as_ref()?;
        let record = reader.lookup(ip).ok()?;
        let country = record.decode::<Country>().ok()??;
        country.country.iso_code.map(str::to_owned)
    }
}

/// Defensive parse of a /cdn-cgi/trace body: `colo=XXX` on its own line.
/// The endpoint is community-documented, so unknown keys are ignored and any
/// malformed body yields `None`.
pub fn parse_colo(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    // First matching `colo=` line wins; the community endpoint returns at
    // most one per body, but a defensive first-match is the documented pick.
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "colo" && !value.trim().is_empty()).then(|| value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colo_from_a_realistic_trace_body() {
        let body = b"ip=1.2.3.4\nloc=GB\ncolo=LHR\nhttp=http/2\ntls=TLSv1.3\n";
        assert_eq!(parse_colo(body).as_deref(), Some("LHR"));
    }

    #[test]
    fn colo_parse_ignores_garbage_and_missing_keys() {
        assert_eq!(parse_colo(b""), None);
        assert_eq!(parse_colo(b"not a trace"), None);
        assert_eq!(parse_colo(b"loc=GB\nhttp=http/2\n"), None);
        assert_eq!(parse_colo(b"colo=\n"), None);
        assert_eq!(parse_colo(b"\xff\xfe\x00 binary"), None);
    }

    #[test]
    fn embedded_geo_constructs_without_the_db() {
        // Must not panic on machines where the build-time download failed.
        let geo = Geo::embedded();
        let _ = geo.country("127.0.0.1".parse().unwrap());
    }

    #[test]
    fn fallback_state_returns_none_without_a_db() {
        // Deterministic: constructs the degraded state directly, so this runs
        // unconditionally (no build-time download, no network, no skipping).
        let geo = Geo { country: None };
        assert_eq!(geo.country("8.8.8.8".parse().unwrap()), None);
        assert_eq!(geo.country("2607:f8b0:4001::1".parse().unwrap()), None);
        assert_eq!(geo.country("127.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn embedded_db_resolves_a_known_public_ip_when_present() {
        // db-ip Lite is a real database; assert against a stable allocation.
        // Skipped implicitly when the build-time download was unavailable.
        let geo = Geo::embedded();
        if geo.country.is_none() {
            return;
        }
        let google_dns: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(geo.country(google_dns).as_deref(), Some("US"));
    }

    #[test]
    fn embedded_db_looks_up_v6_addresses_when_present() {
        let geo = Geo::embedded();
        if geo.country.is_none() {
            return;
        }
        // Google GGC v6 allocation the db-ip Lite build resolves to US.
        let google: IpAddr = "2607:f8b0:4001::1".parse().unwrap();
        assert_eq!(geo.country(google).as_deref(), Some("US"));
    }
}
