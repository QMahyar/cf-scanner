use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::http::{HttpGet, OFFICIAL_IPS_URL, OFFICIAL_IPS_V6_URL};
use super::pool::{CidrPool, parse_cidr, parse_lines, rfc3339_utc, unix_now, write_pool_to};

use crate::paths;

pub async fn fetch_official(http: &impl HttpGet) -> Result<CidrPool> {
    let body = http.get(OFFICIAL_IPS_URL).await?;
    let cidrs = parse_official(&body)?;
    if cidrs.is_empty() {
        bail!("{OFFICIAL_IPS_URL} returned no IPv4 CIDRs; keeping the last-good list");
    }
    Ok(CidrPool::from_ranges(cidrs))
}

pub async fn refresh_to_disk(http: &impl HttpGet) -> Result<usize> {
    let pool = fetch_official(http).await?;
    write_pool_to(
        &paths::refreshed_ranges_path()?,
        &pool,
        &rfc3339_utc(unix_now()),
    )?;
    Ok(pool.ranges().len())
}

pub async fn refresh_v6_to_disk(http: &impl HttpGet) -> Result<usize> {
    let body = http.get(OFFICIAL_IPS_V6_URL).await?;
    let cidrs = parse_lines(&body)?;
    if let Some(bad) = cidrs.iter().find(|c| !c.addr.is_ipv6()) {
        bail!("{OFFICIAL_IPS_V6_URL} returned a non-IPv6 CIDR: {bad}");
    }
    if cidrs.is_empty() {
        bail!("{OFFICIAL_IPS_V6_URL} returned no IPv6 CIDRs; keeping the last-good list");
    }
    let pool = CidrPool::from_ranges(cidrs);
    write_pool_to(
        &paths::refreshed_ranges_v6_path()?,
        &pool,
        &rfc3339_utc(unix_now()),
    )?;
    Ok(pool.ranges().len())
}

#[derive(Deserialize)]
struct OfficialResponse {
    success: bool,
    result: Option<OfficialResult>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct OfficialResult {
    ipv4_cidrs: Vec<String>,
}

pub fn parse_official(body: &str) -> Result<Vec<super::pool::Cidr>> {
    let resp: OfficialResponse =
        serde_json::from_str(body).context("parse cloudflare API response")?;
    if !resp.success {
        bail!("cloudflare API error: {:#?}", resp.errors);
    }
    let Some(r) = resp.result else {
        bail!("cloudflare API returned no result");
    };
    r.ipv4_cidrs
        .iter()
        .filter_map(|c| {
            if c.contains(':') {
                return None;
            }
            match parse_cidr(c) {
                Ok(c) => Some(Ok(c)),
                Err(e) => Some(Err(e).with_context(|| format!("bad CIDR from API: {c}"))),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};
    use crate::ranges::pool::last_updated_of;
    use std::fs;

    struct FakeHttp(&'static str);

    impl HttpGet for FakeHttp {
        fn get<'a>(&'a self, _url: &'a str) -> crate::ranges::http::HttpFuture<'a> {
            Box::pin(async move { Ok(self.0.to_owned()) })
        }
    }

    #[test]
    fn parses_official_fixture_skipping_v6() {
        let body = r#"{
            "success": true,
            "result": {
                "ipv4_cidrs": ["104.16.0.0/13", "2001:4860::/32"]
            },
            "errors": []
        }"#;
        let cidrs = parse_official(body).unwrap();
        assert_eq!(cidrs, vec![parse_cidr("104.16.0.0/13").unwrap()]);
    }

    #[test]
    fn rejects_official_error_response() {
        let body = r#"{"success": false, "errors": [{"code": 7000, "message": "nope"}]}"#;
        assert!(parse_official(body).is_err());
    }

    #[tokio::test]
    async fn refresh_to_disk_round_trips() {
        let _guard = DATA_DIR_LOCK.lock().await;
        let _isolated = IsolatedDataDir::new();
        let body = r#"{"success":true,"result":{"ipv4_cidrs":["10.0.0.0/8"]},"errors":[]}"#;
        let http = FakeHttp(body);
        assert_eq!(refresh_to_disk(&http).await.unwrap(), 1);
        let written = fs::read_to_string(paths::refreshed_ranges_path().unwrap()).unwrap();
        assert!(written.starts_with("# last-updated: "), "{written}");
        assert!(written.ends_with("10.0.0.0/8\n"), "{written}");
        assert!(last_updated_of(&written).is_some());
        assert_eq!(CidrPool::parse(&written).unwrap().host_count(), 1 << 24);
    }

    #[tokio::test]
    async fn refresh_v6_to_disk_round_trips() {
        let _guard = DATA_DIR_LOCK.lock().await;
        let _isolated = IsolatedDataDir::new();
        let http = FakeHttp("2606:4700::/32\n2400:cb00::/32\n");
        assert_eq!(refresh_v6_to_disk(&http).await.unwrap(), 2);
        let written = fs::read_to_string(paths::refreshed_ranges_v6_path().unwrap()).unwrap();
        assert!(
            last_updated_of(&written).is_some(),
            "v6 refresh must carry a last-updated header like the v4 refresh"
        );
        let pool = CidrPool::parse(&written).unwrap();
        assert_eq!(pool.ranges().len(), 2);
    }

    #[tokio::test]
    async fn refresh_v6_rejects_non_v6_entries() {
        let http = FakeHttp("2606:4700::/32\n1.2.3.4/24\n");
        assert!(refresh_v6_to_disk(&http).await.is_err());
    }

    #[tokio::test]
    async fn refresh_keeps_last_good_file_when_api_returns_no_cidrs() {
        let _guard = DATA_DIR_LOCK.lock().await;
        let _isolated = IsolatedDataDir::new();
        let good =
            FakeHttp(r#"{"success":true,"result":{"ipv4_cidrs":["10.0.0.0/8"]},"errors":[]}"#);
        refresh_to_disk(&good).await.unwrap();
        let path = paths::refreshed_ranges_path().unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let empty = FakeHttp(r#"{"success":true,"result":{"ipv4_cidrs":[]},"errors":[]}"#);
        assert!(refresh_to_disk(&empty).await.is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "a degenerate refresh must not clobber the last-good list"
        );
    }

    #[tokio::test]
    async fn refresh_v6_keeps_last_good_file_when_api_returns_no_cidrs() {
        let _guard = DATA_DIR_LOCK.lock().await;
        let _isolated = IsolatedDataDir::new();
        let good = FakeHttp("2606:4700::/32\n");
        refresh_v6_to_disk(&good).await.unwrap();
        let path = paths::refreshed_ranges_v6_path().unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let empty = FakeHttp("\n");
        assert!(refresh_v6_to_disk(&empty).await.is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "a degenerate v6 refresh must not clobber the last-good list"
        );
    }
}
