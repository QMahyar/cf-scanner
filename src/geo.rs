use std::net::IpAddr;

use maxminddb::geoip2::Country;

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

    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.country.as_ref()?;
        let record = reader.lookup(ip).ok()?;
        let country = record.decode::<Country>().ok()??;
        country.country.iso_code.map(str::to_owned)
    }
}

pub fn parse_colo(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        let value = value.trim();
        let plausible = key.trim() == "colo"
            && !value.is_empty()
            && value.len() <= 4
            && value.bytes().all(|b| b.is_ascii_alphanumeric());
        plausible.then(|| value.to_owned())
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
    fn colo_parse_accepts_only_iata_style_codes() {
        assert_eq!(parse_colo(b"colo=SJO").as_deref(), Some("SJO"));
        assert_eq!(parse_colo(b"colo=LHRA").as_deref(), Some("LHRA"));
        assert_eq!(parse_colo(b"colo=sjoo!"), None);
        assert_eq!(parse_colo(b"colo=SJ OO"), None);
        let long_junk = format!("colo={}", "x".repeat(100));
        assert_eq!(parse_colo(long_junk.as_bytes()), None);
        assert_eq!(parse_colo(b"colo=a-b"), None);
    }

    #[test]
    fn embedded_geo_constructs_without_the_db() {
        let geo = Geo::embedded();
        let _ = geo.country("127.0.0.1".parse().unwrap());
    }

    #[test]
    fn fallback_state_returns_none_without_a_db() {
        let geo = Geo { country: None };
        assert_eq!(geo.country("8.8.8.8".parse().unwrap()), None);
        assert_eq!(geo.country("2607:f8b0:4001::1".parse().unwrap()), None);
        assert_eq!(geo.country("127.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn embedded_db_resolves_a_known_public_ip_when_present() {
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
        let google: IpAddr = "2607:f8b0:4001::1".parse().unwrap();
        assert_eq!(geo.country(google).as_deref(), Some("US"));
    }
}
