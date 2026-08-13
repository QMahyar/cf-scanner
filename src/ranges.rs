//! Candidate ranges for CDN mode: bundled official Cloudflare space, custom
//! CIDRs, dirty-range exclusions, and preset/count sampling plans.
//! Pure logic here; the network fetch for `ranges refresh` is injected so
//! tests never touch the wire.

use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::api::types::{CdnPreset, ScanTarget};
use crate::paths;

pub const BUNDLED_RANGES: &str = include_str!("../data/cf-ranges.txt");
pub const OFFICIAL_IPS_URL: &str = "https://api.cloudflare.com/client/v4/ips";
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Cidr {
    pub fn host_count(self) -> u64 {
        1u64 << (32 - self.prefix as u64)
    }

    /// /24 sub-blocks this range covers; prefix >= 24 clamps to 1.
    fn sub24_count(self) -> u64 {
        if self.prefix >= 24 {
            1
        } else {
            1u64 << (24 - self.prefix as u64)
        }
    }

    /// Absolute IP for a host index within this range (index wraps).
    pub fn host(self, index: u64) -> Ipv4Addr {
        let base = u32::from(self.addr);
        Ipv4Addr::from(base.wrapping_add((index % self.host_count()) as u32))
    }

    fn contains(self, other: Cidr) -> bool {
        let a = u32::from(self.addr) as u64;
        let b = u32::from(other.addr) as u64;
        other.prefix >= self.prefix && b >= a && b + other.host_count() <= a + self.host_count()
    }
}

/// Validates and normalizes `a.b.c.d/prefix`; host bits are masked off.
pub fn parse_cidr(s: &str) -> Result<Cidr> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing /prefix in {s:?}"))?;
    let addr: Ipv4Addr = ip.trim().parse().context("invalid IPv4 address")?;
    let prefix: u8 = prefix.trim().parse().context("prefix is not a number")?;
    if prefix > 32 {
        bail!("prefix out of range 0-32");
    }
    let masked = if prefix == 0 {
        0
    } else {
        u32::from(addr) & (u32::MAX << (32 - prefix))
    };
    Ok(Cidr {
        addr: Ipv4Addr::from(masked),
        prefix,
    })
}

fn parse_lines(text: &str) -> Result<Vec<Cidr>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_cidr)
        .collect()
}

fn render_lines(cidrs: &[Cidr]) -> String {
    let mut out = String::new();
    for c in cidrs {
        out.push_str(&format!("{}/{}\n", c.addr, c.prefix));
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CidrPool {
    ranges: Vec<Cidr>,
}

impl CidrPool {
    pub fn bundled() -> Self {
        Self::parse(BUNDLED_RANGES).expect("bundled ranges must parse")
    }

    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self {
            ranges: parse_lines(text)?,
        })
    }

    pub fn ranges(&self) -> &[Cidr] {
        &self.ranges
    }

    pub fn host_count(&self) -> u64 {
        self.ranges.iter().map(|c| c.host_count()).sum()
    }

    pub fn extend(&mut self, more: Vec<Cidr>) {
        self.ranges.extend(more);
    }

    /// Removes every excluded range (punctured) from this pool.
    pub fn excluding(&self, excluded: &[Cidr]) -> CidrPool {
        let mut ranges = self.ranges.clone();
        for e in excluded {
            let mut next: Vec<Cidr> = Vec::new();
            for r in ranges {
                match subtract(r, *e) {
                    Subtract::Keep => next.push(r),
                    Subtract::None => {}
                    Subtract::Split(parts) => next.extend(parts),
                }
            }
            ranges = next;
        }
        CidrPool { ranges }
    }
}

enum Subtract {
    Keep,
    None,
    Split(Vec<Cidr>),
}

/// Splits `outer` around `inner` when inner is a proper sub-block.
fn subtract(outer: Cidr, inner: Cidr) -> Subtract {
    if inner == outer || inner.contains(outer) {
        return Subtract::None;
    }
    if !outer.contains(inner) {
        return Subtract::Keep;
    }
    let a = u32::from(outer.addr) as u64;
    let b = u32::from(inner.addr) as u64;
    let before = b - a;
    let after_start = b + inner.host_count() - a;
    let after = outer.host_count() - after_start;
    let mut parts = Vec::new();
    // Greedy high-bit blocks capped by the current address alignment; both
    // lengths are multiples of inner's stride, so this always lands on
    // valid CIDR boundaries.
    decompose(a, before, &mut parts);
    decompose(a + after_start, after, &mut parts);
    Subtract::Split(parts)
}

fn decompose(mut base: u64, mut len: u64, out: &mut Vec<Cidr>) {
    while len > 0 {
        let max_k = 63 - len.leading_zeros();
        let align_k = if base == 0 { 32 } else { base.trailing_zeros() };
        let k = max_k.min(align_k) as u8;
        let block = 1u64 << k;
        out.push(Cidr {
            addr: Ipv4Addr::from(base as u32),
            prefix: 32 - k,
        });
        base += block;
        len -= block;
    }
}

/// How the engine walks a pool: every host, a random subset per CIDR block,
/// or pre-rolled concrete host offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanItem {
    Every { cidr: Cidr },
    Sample { cidr: Cidr, count: u64 },
    Hosts { cidr: Cidr, offsets: Vec<u64> },
}

/// Deterministic (seeded) splitmix64; good enough for sampling.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, bound). Modulo bias (< 2^-32 for our bounds) is fine.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

/// Builds the walk plan for a target. Apply exclusions before planning.
pub fn plan(pool: &CidrPool, target: &ScanTarget, rng: &mut SplitMix64) -> Vec<PlanItem> {
    match target {
        ScanTarget::Count(n) => plan_count(pool, *n as u64, rng),
        ScanTarget::Preset(p) => match p {
            CdnPreset::Quick => plan_per24(pool, 1, rng),
            CdnPreset::Normal => plan_per24(pool, 3, rng),
            CdnPreset::Full => pool
                .ranges
                .iter()
                .map(|c| PlanItem::Every { cidr: *c })
                .collect(),
        },
    }
}

/// 1 (Quick) or 3 (Normal) random hosts per /24, network/broadcast excluded.
fn plan_per24(pool: &CidrPool, per: u64, _rng: &mut SplitMix64) -> Vec<PlanItem> {
    let mut items = Vec::new();
    for &cidr in &pool.ranges {
        if cidr.prefix >= 24 {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count()),
            });
            continue;
        }
        let base = u32::from(cidr.addr) as u64;
        for i in 0..cidr.sub24_count() {
            let sub = Cidr {
                addr: Ipv4Addr::from((base + (i << 8)) as u32),
                prefix: 24,
            };
            items.push(PlanItem::Sample {
                cidr: sub,
                count: per,
            });
        }
    }
    items
}

/// `n` distinct random offsets spread across the whole pool.
fn plan_count(pool: &CidrPool, n: u64, rng: &mut SplitMix64) -> Vec<PlanItem> {
    if n >= pool.host_count() {
        return pool
            .ranges
            .iter()
            .map(|c| PlanItem::Every { cidr: *c })
            .collect();
    }
    let total = pool.host_count();
    let mut seen = std::collections::HashSet::with_capacity(n as usize * 2);
    while seen.len() < n as usize {
        seen.insert(rng.below(total));
    }
    let mut pick: Vec<u64> = seen.into_iter().collect();
    pick.sort_unstable();
    let mut items = Vec::new();
    let mut offset = 0u64;
    let mut i = 0usize;
    for &cidr in &pool.ranges {
        let end = offset + cidr.host_count();
        let mut in_range: Vec<u64> = Vec::new();
        while i < pick.len() && pick[i] < end {
            in_range.push(pick[i] - offset);
            i += 1;
        }
        if !in_range.is_empty() {
            items.push(PlanItem::Hosts {
                cidr,
                offsets: in_range,
            });
        }
        offset = end;
    }
    items
}

/// Bundled ranges, overridden by a refreshed copy in the data dir when
/// present, plus custom CIDRs, minus exclusions. What the engine scans.
pub fn base_pool(runtime_refreshed: Option<&str>) -> Result<CidrPool> {
    match runtime_refreshed {
        Some(text) => CidrPool::parse(text),
        None => Ok(CidrPool::bundled()),
    }
}

pub fn effective_pool_from(
    custom_cidrs: &[String],
    exclude: &[String],
    runtime_refreshed: Option<&str>,
) -> Result<CidrPool> {
    // Custom CIDRs REPLACE the official pool: pasting your own ranges means
    // "scan these, not the internet". Exclusions still apply to them.
    let mut pool = if custom_cidrs.is_empty() {
        base_pool(runtime_refreshed)?
    } else {
        CidrPool { ranges: Vec::new() }
    };
    let customs: Vec<Cidr> = custom_cidrs
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<_>>()?;
    pool.extend(customs);
    let excluded: Vec<Cidr> = exclude
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<_>>()?;
    Ok(pool.excluding(&excluded))
}

pub fn effective_pool(custom_cidrs: &[String], exclude: &[String]) -> Result<CidrPool> {
    let runtime = match paths::refreshed_ranges_path() {
        Ok(p) => fs::read_to_string(p).ok(),
        Err(_) => None,
    };
    effective_pool_from(custom_cidrs, exclude, runtime.as_deref())
}

/// Fetches the official list over HTTPS and writes it to the data dir.
pub async fn refresh_to_disk(http: &impl HttpGet) -> Result<usize> {
    let body = http.get(OFFICIAL_IPS_URL).await?;
    let cidrs = parse_official(&body)?;
    let dir = paths::data_dir()?;
    fs::create_dir_all(&dir).context("create data dir")?;
    fs::write(paths::refreshed_ranges_path()?, render_lines(&cidrs))
        .context("write refreshed ranges")?;
    Ok(cidrs.len())
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

/// IPv6 entries are skipped: CF-Scanner is IPv4-only by design.
pub fn parse_official(body: &str) -> Result<Vec<Cidr>> {
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
        .filter_map(|c| match parse_cidr(c) {
            Ok(c) => Some(Ok(c)),
            // IPv6 entries are not addressable by this tool.
            Err(_) if c.contains(':') => None,
            Err(e) => Some(Err(e).with_context(|| format!("bad CIDR from API: {c}"))),
        })
        .collect()
}

#[allow(async_fn_in_trait)] // internal seam; send bounds are irrelevant here
pub trait HttpGet {
    async fn get(&self, url: &str) -> Result<String>;
}

/// Minimal HTTPS GET (HTTP/1.1, rustls roots); enough for one JSON endpoint.
pub struct RealHttp;

impl HttpGet for RealHttp {
    async fn get(&self, url: &str) -> Result<String> {
        tokio::time::timeout(FETCH_TIMEOUT, fetch_tls(url))
            .await
            .context("fetch timed out")?
    }
}

/// HTTPS GET with extra request headers (e.g. `User-Agent`), used by the
/// phase-2 subscription fetcher which must not send the bare default UA.
pub async fn fetch_tls_with_headers(url: &str, extra_headers: &str) -> Result<String> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_tls_inner(url, extra_headers))
        .await
        .context("fetch timed out")?
}

async fn fetch_tls(url: &str) -> Result<String> {
    fetch_tls_inner(url, "Accept: application/json").await
}

async fn fetch_tls_inner(url: &str, extra_headers: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https:// URLs supported"))?;
    let (host_port, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("bad port")?),
        None => (host_port, 443),
    };

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let stream = TcpStream::connect((host, port)).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).context("invalid hostname")?;
    let tls = connector.connect(server_name, stream).await?;
    let (mut rd, mut wr) = tokio::io::split(tls);

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\nConnection: close\r\n\r\n"
    );
    wr.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    rd.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .context("malformed HTTP response")?;
    if !headers.starts_with("HTTP/1.1 200") {
        bail!("HTTP error: {headers}");
    }
    Ok(body.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_masks_cidrs() {
        assert_eq!(
            parse_cidr("104.16.0.0/13").unwrap(),
            Cidr {
                addr: "104.16.0.0".parse().unwrap(),
                prefix: 13
            }
        );
        let c = parse_cidr("1.2.3.4/24").unwrap();
        assert_eq!(
            c,
            Cidr {
                addr: "1.2.3.0".parse().unwrap(),
                prefix: 24
            }
        );
    }

    #[test]
    fn rejects_malformed_cidrs() {
        for bad in ["garbage", "1.2.3.4", "1.2.3.4/33", "1.2.3.4/abc", "::1/64"] {
            assert!(parse_cidr(bad).is_err(), "expected {bad} to fail");
        }
    }

    #[test]
    fn bundled_file_parses() {
        let pool = CidrPool::bundled();
        assert!(pool.host_count() > 1_000_000);
        assert!(pool.ranges().len() >= 15);
    }

    #[test]
    fn host_indexing_wraps() {
        let c = Cidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 24,
        };
        assert_eq!(c.host_count(), 256);
        assert_eq!(c.host(0), "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.host(255), "10.0.0.255".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.host(256), "10.0.0.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn exclusion_splits_around_subnet() {
        let pool = CidrPool {
            ranges: vec![Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            }],
        };
        let ex = parse_cidr("10.1.2.0/24").unwrap();
        let out = pool.excluding(&[ex]);
        let remaining: u64 = out.ranges.iter().map(|c| c.host_count()).sum();
        assert_eq!(remaining, (1 << 24) - 256, "missing portion: {out:?}");
        for c in &out.ranges {
            assert!(!c.contains(ex), "excluded range leaked: {c:?}");
            let end = u32::from(c.addr) as u64 + c.host_count();
            assert!(
                end <= 0x0A00_0000u64 + (1 << 24),
                "{c:?} spills out of 10/8"
            );
        }
        let mut sorted = out.ranges.clone();
        sorted.sort_by_key(|c| u32::from(c.addr));
        for w in sorted.windows(2) {
            assert!(
                u32::from(w[0].addr) as u64 + w[0].host_count() <= u32::from(w[1].addr) as u64,
                "overlapping split: {:?} + {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn exclusion_keeps_disjoint_ranges() {
        let pool = CidrPool {
            ranges: vec![parse_cidr("10.0.0.0/24").unwrap()],
        };
        let ex = parse_cidr("192.168.0.0/16").unwrap();
        assert_eq!(pool.excluding(&[ex]), pool);
    }

    #[test]
    fn exclusion_removes_contained_ranges() {
        let pool = CidrPool {
            ranges: vec![parse_cidr("10.0.0.0/8").unwrap()],
        };
        let ex = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(pool.excluding(&[ex]).host_count(), 0);
    }

    #[test]
    fn sample_plan_is_deterministic_and_per24() {
        let pool = CidrPool::bundled();
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        let plan_a = plan(&pool, &ScanTarget::Preset(CdnPreset::Quick), &mut a);
        let plan_b = plan(&pool, &ScanTarget::Preset(CdnPreset::Quick), &mut b);
        assert_eq!(plan_a, plan_b);
        assert_eq!(
            plan_a.len() as u64,
            pool.ranges().iter().map(|c| c.sub24_count()).sum::<u64>()
        );
        for item in &plan_a {
            if let PlanItem::Sample { cidr, count } = item {
                assert_eq!(cidr.prefix, 24);
                assert_eq!(*count, 1);
            } else {
                panic!("quick plan must be per-/24 samples");
            }
        }
        assert_eq!(
            plan(
                &pool,
                &ScanTarget::Preset(CdnPreset::Normal),
                &mut SplitMix64::new(1)
            )
            .iter()
            .map(|i| match i {
                PlanItem::Sample { count, .. } => *count,
                _ => 0,
            })
            .sum::<u64>(),
            3 * pool.ranges().iter().map(|c| c.sub24_count()).sum::<u64>()
        );
    }

    #[test]
    fn full_preset_plans_every_host() {
        let pool = CidrPool {
            ranges: vec![parse_cidr("10.0.0.0/30").unwrap()],
        };
        let plan = plan(
            &pool,
            &ScanTarget::Preset(CdnPreset::Full),
            &mut SplitMix64::new(1),
        );
        assert_eq!(
            plan,
            vec![PlanItem::Every {
                cidr: parse_cidr("10.0.0.0/30").unwrap()
            }]
        );
    }

    #[test]
    fn count_plan_picks_distinct_hosts_inside_pool() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/24").unwrap(),
                parse_cidr("10.0.1.0/25").unwrap(),
            ],
        };
        let mut rng = SplitMix64::new(7);
        let plan = plan(&pool, &ScanTarget::Count(200), &mut rng);
        let mut ips: Vec<Ipv4Addr> = Vec::new();
        for item in &plan {
            match item {
                PlanItem::Hosts { cidr, offsets } => {
                    assert!(offsets.len() as u64 <= cidr.host_count(), "run-away sample");
                    for &o in offsets {
                        assert!(o < cidr.host_count(), "offset outside range");
                        ips.push(cidr.host(o));
                    }
                }
                _ => panic!("count plan must be concrete hosts"),
            }
        }
        assert_eq!(ips.len(), 200);
        ips.sort();
        ips.dedup();
        assert_eq!(ips.len(), 200, "samples must stay distinct");
        let pool_ips: Vec<Ipv4Addr> = (0..(128 + 256))
            .map(|i| {
                if i < 128 {
                    Cidr {
                        addr: "10.0.1.0".parse().unwrap(),
                        prefix: 25,
                    }
                    .host(i)
                } else {
                    Cidr {
                        addr: "10.0.0.0".parse().unwrap(),
                        prefix: 24,
                    }
                    .host(i - 128)
                }
            })
            .collect();
        for ip in &ips {
            assert!(pool_ips.contains(ip), "{ip} outside pool");
        }
    }

    #[test]
    fn count_over_total_degrades_to_every() {
        let pool = CidrPool {
            ranges: vec![parse_cidr("10.0.0.0/30").unwrap()],
        };
        let plan = plan(&pool, &ScanTarget::Count(4), &mut SplitMix64::new(0));
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0], PlanItem::Every { .. }));
    }

    #[test]
    fn effective_pool_applies_custom_and_exclude() {
        let pool = effective_pool_from(
            &["10.0.0.0/24".to_owned()],
            &["10.0.0.0/25".to_owned()],
            Some(""),
        )
        .unwrap();
        assert_eq!(pool.host_count(), 128);
    }

    #[test]
    fn base_pool_prefers_runtime_refresh() {
        let live = base_pool(Some("10.0.0.0/24\n")).unwrap();
        assert_eq!(live.host_count(), 256);
        assert!(base_pool(None).unwrap().host_count() > 1_000_000);
    }

    #[test]
    fn parses_official_fixture_skipping_ipv6() {
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

    struct FakeHttp(&'static str);

    impl HttpGet for FakeHttp {
        async fn get(&self, _url: &str) -> Result<String> {
            Ok(self.0.to_owned())
        }
    }

    #[tokio::test]
    async fn refresh_to_disk_round_trips() {
        let body = r#"{"success":true,"result":{"ipv4_cidrs":["10.0.0.0/8"]},"errors":[]}"#;
        let http = FakeHttp(body);
        assert_eq!(refresh_to_disk(&http).await.unwrap(), 1);
        let written = fs::read_to_string(paths::refreshed_ranges_path().unwrap()).unwrap();
        assert_eq!(written, "10.0.0.0/8\n");
        fs::remove_file(paths::refreshed_ranges_path().unwrap()).unwrap();
    }
}
