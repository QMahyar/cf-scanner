//! Candidate ranges for CDN mode: bundled official Cloudflare space, custom
//! CIDRs, dirty-range exclusions, and preset/count sampling plans.
//! Pure logic here; the network fetch for `ranges refresh` is injected so
//! tests never touch the wire.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::api::types::{CdnPreset, ScanTarget};
use crate::paths;

pub const BUNDLED_RANGES: &str = include_str!("../data/cf-ranges.txt");
pub const BUNDLED_RANGES_V6: &str = include_str!("../data/cf-ranges-v6.txt");
pub const OFFICIAL_IPS_URL: &str = "https://api.cloudflare.com/client/v4/ips";
pub const OFFICIAL_IPS_V6_URL: &str = "https://www.cloudflare.com/ips-v6/";
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Cidr {
    fn bits(self) -> u32 {
        match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    fn base(self) -> u128 {
        match self.addr {
            IpAddr::V4(a) => u32::from(a) as u128,
            IpAddr::V6(a) => u128::from(a),
        }
    }

    /// Number of addresses in the block. The v6 space can exceed u128
    /// (`/0`); those blocks saturate at [`u128::MAX`].
    pub fn host_count(self) -> u128 {
        let shift = self.bits() - self.prefix as u32;
        if shift >= 128 {
            u128::MAX
        } else {
            1u128 << shift
        }
    }

    /// /24 sub-blocks this v4 range covers; prefix >= 24 clamps to 1.
    /// v6 ranges are never decomposed this way (see `plan_preset`).
    fn sub24_count(self) -> u64 {
        debug_assert!(self.addr.is_ipv4());
        if self.prefix >= 24 {
            1
        } else {
            1u64 << (24 - self.prefix as u64)
        }
    }

    /// Absolute address for a host index within this range (index wraps).
    pub fn host(self, index: u128) -> IpAddr {
        let offset = index % self.host_count();
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a).wrapping_add(offset as u32))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a).wrapping_add(offset))),
        }
    }

    /// True when `other` is a same-family sub-block of `self`.
    fn contains(self, other: Cidr) -> bool {
        if self.addr.is_ipv4() != other.addr.is_ipv4() {
            return false;
        }
        let a = self.base();
        let b = other.base();
        other.prefix >= self.prefix
            && b >= a
            && b.saturating_add(other.host_count()) <= a.saturating_add(self.host_count())
    }
}

/// Validates and normalizes `ip/prefix`; host bits are masked off. Both v4
/// and v6 are accepted.
pub fn parse_cidr(s: &str) -> Result<Cidr> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing /prefix in {s:?}"))?;
    let addr: IpAddr = ip.trim().parse().context("invalid IP address")?;
    let prefix: u8 = prefix.trim().parse().context("prefix is not a number")?;
    let bits = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > bits {
        bail!("prefix out of range 0-{bits}");
    }
    // A v6 /0 covers 2^128 addresses: `host_count` saturates at u128::MAX,
    // so exclusion and planning math on it would be off by one. The API
    // validator has always rejected it; keep the rejection in the parser so
    // `validate_cidr` can delegate without a second rule.
    if addr.is_ipv6() && prefix == 0 {
        bail!("IPv6 /0 is not supported (host count exceeds u128)");
    }
    let masked = match addr {
        IpAddr::V4(a) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    };
    Ok(Cidr {
        addr: masked,
        prefix,
    })
}

/// Unwraps the v4 address of a range the caller has already checked is v4.
fn ipv4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!("v6 ranges are handled separately"),
    }
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

    /// The official Cloudflare IPv6 ranges; opt-in via `ScanConfig::include_v6`.
    pub fn bundled_v6() -> Self {
        Self::parse(BUNDLED_RANGES_V6).expect("bundled v6 ranges must parse")
    }

    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self {
            ranges: parse_lines(text)?,
        })
    }

    pub fn ranges(&self) -> &[Cidr] {
        &self.ranges
    }

    pub fn host_count(&self) -> u128 {
        self.ranges
            .iter()
            .map(|c| c.host_count())
            .fold(0u128, u128::saturating_add)
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

/// Splits `outer` around `inner` when inner is a proper sub-block of the
/// same family; different families never intersect, so they always Keep.
fn subtract(outer: Cidr, inner: Cidr) -> Subtract {
    if outer.addr.is_ipv4() != inner.addr.is_ipv4() {
        return Subtract::Keep;
    }
    if inner == outer || inner.contains(outer) {
        return Subtract::None;
    }
    if !outer.contains(inner) {
        return Subtract::Keep;
    }
    let bits = outer.bits();
    let a = outer.base();
    let b = inner.base();
    let before = b - a;
    let after_start = b + inner.host_count() - a;
    let after = outer.host_count() - after_start;
    let mut parts = Vec::new();
    // Greedy high-bit blocks capped by the current address alignment; both
    // lengths are multiples of inner's stride, so this always lands on
    // valid CIDR boundaries.
    decompose(a, before, bits, &mut parts);
    decompose(a + after_start, after, bits, &mut parts);
    Subtract::Split(parts)
}

/// Splits [base, base+len) into aligned same-family CIDR blocks.
fn decompose(mut base: u128, mut len: u128, bits: u32, out: &mut Vec<Cidr>) {
    while len > 0 {
        let max_k = 127 - len.leading_zeros();
        let align_k = if base == 0 {
            bits
        } else {
            base.trailing_zeros().min(bits)
        };
        let k = max_k.min(align_k);
        let block = 1u128 << k;
        let addr = if bits == 128 {
            IpAddr::V6(Ipv6Addr::from(base))
        } else {
            IpAddr::V4(Ipv4Addr::from(base as u32))
        };
        out.push(Cidr {
            addr,
            prefix: (bits - k) as u8,
        });
        base += block;
        len -= block;
    }
}

/// How the engine walks a pool: every host, a random subset per CIDR block,
/// or pre-rolled concrete host offsets (v6 host spaces need u128 offsets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanItem {
    Every { cidr: Cidr },
    Sample { cidr: Cidr, count: u64 },
    Hosts { cidr: Cidr, offsets: Vec<u128> },
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

    /// Uniform in [0, bound) for u128 bounds (v6 host spaces). Two 64-bit
    /// draws; modulo bias (< 2^-64) is negligible.
    pub fn below_u128(&mut self, bound: u128) -> u128 {
        let lo = self.next_u64() as u128;
        let hi = self.next_u64() as u128;
        ((hi << 64) | lo) % bound
    }
}

/// Builds the walk plan for a target. Apply exclusions before planning.
pub fn plan(pool: &CidrPool, target: &ScanTarget, rng: &mut SplitMix64) -> Vec<PlanItem> {
    match target {
        ScanTarget::Count(n) => plan_count(pool, *n as u64, rng),
        ScanTarget::Preset(p) => match p {
            CdnPreset::Quick => plan_preset(pool, 1, rng),
            CdnPreset::Normal => plan_preset(pool, 3, rng),
            CdnPreset::Full => pool
                .ranges
                .iter()
                .map(|c| {
                    if c.addr.is_ipv6() {
                        // Enumerating the v6 space is infeasible (2^96+ hosts
                        // per bundled range); Full samples one per range.
                        PlanItem::Sample { cidr: *c, count: 1 }
                    } else {
                        PlanItem::Every { cidr: *c }
                    }
                })
                .collect(),
        },
    }
}

/// 1 (Quick) or 3 (Normal) random hosts per /24, network/broadcast excluded.
/// v6 ranges have no /24 notion; they yield `per` random hosts from the
/// whole block.
fn plan_preset(pool: &CidrPool, per: u64, _rng: &mut SplitMix64) -> Vec<PlanItem> {
    let mut items = Vec::new();
    for &cidr in &pool.ranges {
        if cidr.addr.is_ipv6() {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count().min(u64::MAX as u128) as u64),
            });
            continue;
        }
        if cidr.prefix >= 24 {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count().min(u64::MAX as u128) as u64),
            });
            continue;
        }
        // A coarse custom CIDR (e.g. /0) would decompose into 2^24 plan
        // items: the same OOM the count path guards against. Beyond the cap
        // the whole block is sampled directly instead — one item, same
        // per-block semantics.
        if cidr.sub24_count() > MAX_PRESET_BLOCKS {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count().min(u64::MAX as u128) as u64),
            });
            continue;
        }
        let base = u32::from(ipv4(cidr.addr)) as u64;
        for i in 0..cidr.sub24_count() {
            let sub = Cidr {
                addr: IpAddr::V4(Ipv4Addr::from((base + (i << 8)) as u32)),
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

/// Plan items a preset run may materialize (one per /24 block); beyond this
/// the block is sampled whole instead of being decomposed.
const MAX_PRESET_BLOCKS: u64 = 1 << 16;

/// `n` distinct random offsets spread across the whole pool.
fn plan_count(pool: &CidrPool, n: u64, rng: &mut SplitMix64) -> Vec<PlanItem> {
    let total = pool.host_count();
    if n as u128 >= total {
        return pool
            .ranges
            .iter()
            .map(|c| PlanItem::Every { cidr: *c })
            .collect();
    }
    let mut seen = std::collections::HashSet::with_capacity(n as usize * 2);
    while seen.len() < n as usize {
        seen.insert(rng.below_u128(total));
    }
    let mut pick: Vec<u128> = seen.into_iter().collect();
    pick.sort_unstable();
    let mut items = Vec::new();
    let mut offset = 0u128;
    let mut i = 0usize;
    for &cidr in &pool.ranges {
        let end = offset + cidr.host_count();
        let mut in_range: Vec<u128> = Vec::new();
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
/// present. What the engine scans (IPv4 half of the pool). A refreshed copy
/// that fails to parse falls back to the bundled list, matching
/// `RangesState::load`: a corrupted or hand-edited file must degrade the
/// scan, never brick it.
pub fn base_pool(runtime_refreshed: Option<&str>) -> Result<CidrPool> {
    match runtime_refreshed {
        Some(text) => match CidrPool::parse(text) {
            Ok(pool) => Ok(pool),
            Err(_) => {
                tracing::warn!("refreshed IPv4 ranges failed to parse; using the bundled list");
                Ok(CidrPool::bundled())
            }
        },
        None => Ok(CidrPool::bundled()),
    }
}

/// The IPv6 half, added to the pool only when the scan opts in via
/// `include_v6`. Refreshed copy from the data dir wins when present; a copy
/// that fails to parse falls back to the bundled list like the v4 half.
pub fn base_pool_v6(runtime_refreshed: Option<&str>) -> Result<CidrPool> {
    match runtime_refreshed {
        Some(text) => match CidrPool::parse(text) {
            Ok(pool) => Ok(pool),
            Err(_) => {
                tracing::warn!("refreshed IPv6 ranges failed to parse; using the bundled list");
                Ok(CidrPool::bundled_v6())
            }
        },
        None => Ok(CidrPool::bundled_v6()),
    }
}

pub fn effective_pool_from(
    custom_cidrs: &[String],
    exclude: &[String],
    include_v6: bool,
    refreshed_v4: Option<&str>,
    refreshed_v6: Option<&str>,
) -> Result<CidrPool> {
    // Custom CIDRs REPLACE the official pool: pasting your own ranges means
    // "scan these, not the internet" (explicit v6 input is always honored,
    // the flag only gates the bundled v6 list). Exclusions still apply.
    let mut pool = if custom_cidrs.is_empty() {
        base_pool(refreshed_v4)?
    } else {
        CidrPool { ranges: Vec::new() }
    };
    if include_v6 && custom_cidrs.is_empty() {
        pool.extend(base_pool_v6(refreshed_v6)?.ranges);
    }
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

pub fn effective_pool(
    custom_cidrs: &[String],
    exclude: &[String],
    include_v6: bool,
) -> Result<CidrPool> {
    let runtime_v4 = match paths::refreshed_ranges_path() {
        Ok(p) => fs::read_to_string(p).ok(),
        Err(_) => None,
    };
    let runtime_v6 = if include_v6 {
        match paths::refreshed_ranges_v6_path() {
            Ok(p) => fs::read_to_string(p).ok(),
            Err(_) => None,
        }
    } else {
        None
    };
    effective_pool_from(
        custom_cidrs,
        exclude,
        include_v6,
        runtime_v4.as_deref(),
        runtime_v6.as_deref(),
    )
}

pub const LAST_UPDATED_PREFIX: &str = "# last-updated: ";

/// Fetches the official list, validates it, and returns the parsed pool.
pub async fn fetch_official(http: &impl HttpGet) -> Result<CidrPool> {
    let body = http.get(OFFICIAL_IPS_URL).await?;
    let cidrs = parse_official(&body)?;
    Ok(CidrPool { ranges: cidrs })
}

/// Fetches the official list over HTTPS and writes it to the data dir with a
/// fresh last-updated header. Returns the number of ranges.
pub async fn refresh_to_disk(http: &impl HttpGet) -> Result<usize> {
    let pool = fetch_official(http).await?;
    write_pool(&pool, &rfc3339_utc(unix_now()))?;
    Ok(pool.ranges().len())
}

/// Atomically replaces the data-dir ranges file with `pool` (temp file +
/// rename), tagged with the `last_updated` header that CLI refreshes and the
/// server's background refresh share as one timestamp source.
pub fn write_pool(pool: &CidrPool, last_updated: &str) -> Result<()> {
    write_pool_to(&paths::refreshed_ranges_path()?, pool, last_updated)
}

/// Atomically replaces `path` with `pool` (temp file + rename), tagged with
/// the `last_updated` header that CLI refreshes and the server's background
/// refresh share as one timestamp source.
pub fn write_pool_to(path: &std::path::Path, pool: &CidrPool, last_updated: &str) -> Result<()> {
    let dir = paths::data_dir()?;
    fs::create_dir_all(&dir).context("create data dir")?;
    let mut text = format!("{LAST_UPDATED_PREFIX}{last_updated}\n");
    text.push_str(&render_lines(pool.ranges()));
    let tmp = path.with_extension("txt.tmp");
    // Scans read this file at start; a torn write would fail the scan. Rename
    // is atomic on the same volume, so readers see old or new, never partial.
    fs::write(&tmp, text).context("write refreshed ranges")?;
    fs::rename(&tmp, path).context("replace refreshed ranges")?;
    Ok(())
}

/// The header's value if `text` is a refreshed ranges file we wrote.
pub fn last_updated_of(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix(LAST_UPDATED_PREFIX)
            .map(str::to_owned)
    })
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC3339 UTC timestamp for `unix_secs` (second precision). Civil date via
/// Howard Hinnant's epoch-days algorithm; no chrono dependency (same
/// approach as the WARP registration `tos` timestamp in warpgen).
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + (m <= 2) as i64;
    let (h, mi, s) = (
        (unix_secs % 86_400) / 3600,
        (unix_secs % 3600) / 60,
        unix_secs % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Fetches the official IPv6 list (`ranges refresh --ipv6`) and writes it to
/// the data dir. The endpoint serves plain one-CIDR-per-line text, so every
/// parsed entry must come back v6.
pub async fn refresh_v6_to_disk(http: &impl HttpGet) -> Result<usize> {
    let body = http.get(OFFICIAL_IPS_V6_URL).await?;
    let cidrs = parse_lines(&body)?;
    if let Some(bad) = cidrs.iter().find(|c| !c.addr.is_ipv6()) {
        bail!("{OFFICIAL_IPS_V6_URL} returned a non-IPv6 CIDR: {bad}");
    }
    // Same atomic replace + last-updated header as the v4 refresh, so a
    // concurrent include_v6 scan never reads a torn file.
    let pool = CidrPool { ranges: cidrs };
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

/// IPv6 entries are skipped: this JSON endpoint feeds the v4 refresh only;
/// the v6 list has its own source (`cf-ranges-v6.txt`, `ips-v6` endpoint).
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
        .filter_map(|c| {
            // The ipv4_cidrs feed is v4 by contract, but a v6 entry would
            // otherwise land in the refreshed v4 file and a v4-only scan
            // would silently scan v6 hosts: skip v6 regardless of parse
            // success.
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

/// One HTTPS GET, boxed so the seam is dyn-compatible and Send (the server
/// spawns refreshes as a background task).
pub type HttpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;

pub trait HttpGet {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a>;
}

/// Minimal HTTPS GET (HTTP/1.1, rustls roots); enough for one JSON endpoint.
pub struct RealHttp;

impl HttpGet for RealHttp {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(FETCH_TIMEOUT, fetch_tls(url))
                .await
                .context("fetch timed out")?
        })
    }
}

/// HTTPS GET with extra request headers (e.g. `User-Agent`), used by the
/// phase-2 subscription fetcher which must not send the bare default UA.
pub async fn fetch_tls_with_headers(url: &str, extra_headers: &str) -> Result<String> {
    let body = fetch_tls_parts(url, extra_headers).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// HTTPS GET returning raw bytes (binary downloads like the xray zip).
pub async fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    fetch_tls_parts(url, "Accept: */*").await
}

async fn fetch_tls_parts(url: &str, extra_headers: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_tls_inner(url, extra_headers))
        .await
        .context("fetch timed out")?
}

async fn fetch_tls(url: &str) -> Result<String> {
    let body = fetch_tls_parts(url, "Accept: application/json").await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn fetch_tls_inner(url: &str, extra_headers: &str) -> Result<Vec<u8>> {
    // GitHub release URLs and subscription links 30x to CDNs; follow up to
    // 5 redirects so downloads survive the common 302 hop. The initial URL
    // and every hop go through the same https + routable-host guard.
    validate_fetch_url(url)?;
    let mut current = url.to_owned();
    for _ in 0..5 {
        let (_fetched_url, status, headers, body) = fetch_one(&current, extra_headers).await?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = headers
                .iter()
                .find(|h| h.to_ascii_lowercase().starts_with("location:"))
                .map(|h| h.trim().strip_prefix("location:").unwrap_or("").trim())
                .filter(|l| !l.is_empty())
                .ok_or_else(|| anyhow!("redirect without Location from {current}"))?;
            current = url::Url::parse(&current)?.join(location)?.to_string();
            validate_fetch_url(&current)?;
            continue;
        }
        return Ok(body);
    }
    bail!(
        "too many redirects fetching {}",
        sanitize_url_for_error(url)
    )
}

/// URL text safe for errors/logs: userinfo (and query/fragment) stripped.
fn sanitize_url_for_error(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() || parsed.password().is_some() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => url.to_owned(),
    }
}

/// SSRF guard for every outbound fetch: https scheme only, and literal
/// loopback/link-local/unspecified IP hosts are refused. DNS names stay
/// allowed (GitHub, CDNs, subscription hosts); the API binds 127.0.0.1, so
/// only local code could have crafted a hostile URL in the first place, and
/// private LAN ranges are kept working for self-hosted subscription feeds.
fn validate_fetch_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).context("bad URL")?;
    if parsed.scheme() != "https" {
        bail!("only https:// URLs supported (got {}://)", parsed.scheme());
    }
    if let Some(host) = parsed.host() {
        // Loopback, link-local and unspecified IPs are refused; DNS names
        // pass (GitHub, CDNs, subscription hosts). Link-local ranges
        // (169.254.0.0/16, fe80::/10) are spelled out because std lacks a
        // stable is_link_local on both address types in this toolchain.
        let unroutable = match host {
            url::Host::Ipv4(v4) => {
                let [a, b, _, _] = v4.octets();
                v4.is_loopback() || v4.is_unspecified() || (a == 169 && b == 254)
            }
            url::Host::Ipv6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || v6.segments()[0] & 0xffc0 == 0xfe80
            }
            url::Host::Domain(_) => false,
        };
        if unroutable {
            bail!("refusing fetch from non-routable host {host}");
        }
    }
    Ok(())
}

/// One HTTPS GET: returns (requested_url, status, headers, body). Bodies are
/// capped (64 MiB) and chunked responses are decoded.
async fn fetch_one(url: &str, extra_headers: &str) -> Result<(String, u16, Vec<String>, Vec<u8>)> {
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

    let stream = TcpStream::connect((host, port)).await?;
    let request = http_request(host, &path, extra_headers);
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).context("invalid hostname")?;
    let tls = tls_connector().connect(server_name, stream).await?;
    let (status, headers, body) = send_http(tls, &request).await?;
    Ok((url.to_owned(), status, headers, body))
}

fn http_request(host: &str, path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\nConnection: close\r\n\r\n")
}

/// Sends `request` over the stream and parses the reply: status line,
/// headers, and body (chunked transfer decoding applied). The body is capped
/// at [`MAX_BODY_BYTES`] so untrusted responses can't exhaust memory.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

async fn send_http<S>(stream: S, request: &str) -> Result<(u16, Vec<String>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    wr.write_all(request.as_bytes()).await?;

    let bytes: Vec<u8> = {
        let mut buf = Vec::new();
        rd.take(MAX_BODY_BYTES as u64 + 64 * 1024)
            .read_to_end(&mut buf)
            .await?;
        buf
    };
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let (head, body) = bytes.split_at(split);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let status_line = lines.next().context("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let body = body[4..].to_vec();
    let body = if headers.iter().any(|h| {
        h.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    }) {
        decode_chunked(&body)?
    } else {
        body
    };
    Ok((status, headers, body))
}

/// Minimal HTTP/1.1 chunked decoder: `size\r\n data \r\n ... 0\r\n\r\n`.
fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("truncated chunk size line")?;
        let size_str = std::str::from_utf8(&input[..line_end])
            .context("chunk size line not utf-8")?
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(size_str.trim(), 16).context("malformed chunk size")?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY_BYTES - out.len() {
            bail!("chunked body exceeds the {} cap", MAX_BODY_BYTES);
        }
        if input.len() < size + 2 {
            bail!("truncated chunk data");
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

/// Phase-2 tunnel probe: SOCKS5 (no-auth) CONNECT to `url`'s host through the
/// socks inbound, then the same TLS+HTTP GET leg as a direct fetch. `Err`
/// means the tunnel did not deliver a 200.
pub async fn get_via_socks(url: &str, socks: SocketAddr, timeout_ms: u64) -> Result<Vec<u8>> {
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        get_via_socks_inner(url, socks),
    )
    .await
    .context("tunnel probe timed out")?
}

async fn get_via_socks_inner(url: &str, socks: SocketAddr) -> Result<Vec<u8>> {
    let parsed = url::Url::parse(url).context("bad probe URL")?;
    let use_tls = parsed.scheme() == "https";
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("probe URL has no host"))?
        .to_owned();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };

    let mut stream = TcpStream::connect(socks).await?;
    socks5_connect(&mut stream, &host, port).await?;
    let request = http_request(&host, &path, "Accept: */*");
    let (status, _, body) = if use_tls {
        let server_name =
            rustls::pki_types::ServerName::try_from(host).context("invalid hostname")?;
        let tls = tls_connector().connect(server_name, stream).await?;
        send_http(tls, &request).await?
    } else {
        send_http(stream, &request).await?
    };
    if status != 200 {
        bail!("tunnel probe got HTTP {status}");
    }
    Ok(body)
}

/// RFC 1928 no-auth handshake with a domain-based CONNECT.
async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        bail!("socks server refused no-auth: {method:02x?}");
    }
    let host = host.as_bytes();
    if host.len() > 255 {
        bail!("socks host too long");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        bail!("socks CONNECT failed: {head:02x?}");
    }
    let addr_len = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        0x04 => 16 + 2,
        other => bail!("socks reply has unknown addr type {other}"),
    };
    let mut rest = vec![0u8; addr_len];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};

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
    fn fetch_url_guard_rejects_non_https_and_local_hosts() {
        assert!(validate_fetch_url("https://example.com/sub").is_ok());
        assert!(validate_fetch_url("https://8.8.8.8/sub").is_ok());
        assert!(validate_fetch_url("https://10.0.0.5:8443/sub").is_ok());
        assert!(validate_fetch_url("https://example.com:8443/sub").is_ok());
        assert!(validate_fetch_url("http://example.com/sub").is_err());
        assert!(validate_fetch_url("ftp://example.com/x").is_err());
        assert!(validate_fetch_url("file:///etc/passwd").is_err());
        assert!(validate_fetch_url("https://127.0.0.1:8765/x").is_err());
        assert!(validate_fetch_url("https://[::1]/x").is_err());
        assert!(validate_fetch_url("https://169.254.0.1/x").is_err());
        assert!(validate_fetch_url("https://0.0.0.0/x").is_err());
        assert!(validate_fetch_url("not a url").is_err());
    }

    #[test]
    fn parses_and_masks_v6_cidrs() {
        assert_eq!(
            parse_cidr("2606:4700::/32").unwrap(),
            Cidr {
                addr: "2606:4700::".parse().unwrap(),
                prefix: 32
            }
        );
        let c = parse_cidr("2606:4700::1234:5678/32").unwrap();
        assert_eq!(
            c,
            Cidr {
                addr: "2606:4700::".parse().unwrap(),
                prefix: 32
            }
        );
        let c = parse_cidr("2001:db8:1::ff/64").unwrap();
        assert_eq!(
            c,
            Cidr {
                addr: "2001:db8:1::".parse().unwrap(),
                prefix: 64
            }
        );
    }

    #[test]
    fn parses_v4_zero_prefix_but_rejects_v6_zero_prefix() {
        assert_eq!(
            parse_cidr("0.0.0.0/0").unwrap(),
            Cidr {
                addr: "0.0.0.0".parse().unwrap(),
                prefix: 0
            }
        );
        // v6 /0 saturates `host_count` at u128::MAX; the API validator has
        // always rejected it, and so must the shared parser.
        assert!(parse_cidr("::/0").is_err());
    }

    #[test]
    fn rejects_malformed_cidrs() {
        for bad in [
            "garbage",
            "1.2.3.4",
            "1.2.3.4/33",
            "1.2.3.4/abc",
            "2606:4700::/129",
            "2001:db8::g/64",
            "2606:4700::",
            "1.2.3.4/-1",
            "::/0",
        ] {
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
    fn bundled_v6_file_parses() {
        let pool = CidrPool::bundled_v6();
        assert!(pool.ranges().len() >= 5, "official v6 list shrank");
        assert!(pool.ranges().iter().all(|c| c.addr.is_ipv6()));
        assert!(
            pool.ranges().iter().all(|c| c.host_count() >= 1u128 << 96),
            "every bundled v6 range must be huge"
        );
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
    fn v6_host_indexing_stays_inside_the_block() {
        let c = Cidr {
            addr: "2001:db8::".parse().unwrap(),
            prefix: 120,
        };
        assert_eq!(c.host_count(), 256);
        assert_eq!(c.host(0), "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.host(255), "2001:db8::ff".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.host(256), "2001:db8::".parse::<Ipv6Addr>().unwrap());
        // A /32 sample lands inside 2606:4700::/32.
        let big = Cidr {
            addr: "2606:4700::".parse().unwrap(),
            prefix: 32,
        };
        let host = big.host(7);
        assert!(big.contains(Cidr {
            addr: host,
            prefix: 128
        }));
        assert!(host.is_ipv6());
    }

    #[test]
    fn v6_exclusion_splits_around_subnet() {
        let pool = CidrPool {
            ranges: vec![parse_cidr("2606:4700::/32").unwrap()],
        };
        let ex = parse_cidr("2606:4700:1:2::/64").unwrap();
        let out = pool.excluding(&[ex]);
        let remaining: u128 = out.ranges.iter().map(|c| c.host_count()).sum();
        assert_eq!(remaining, (1u128 << 96) - (1u128 << 64), "missing portion");
        for c in &out.ranges {
            assert!(c.addr.is_ipv6(), "v4 range leaked into v6 split: {c:?}");
            assert!(!c.contains(ex), "excluded range leaked: {c:?}");
        }
        let mut sorted = out.ranges.clone();
        sorted.sort_by_key(|c| c.base());
        for w in sorted.windows(2) {
            assert!(
                w[0].base() + w[0].host_count() <= w[1].base(),
                "overlapping split: {:?} + {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn cross_family_exclusions_never_intersect() {
        let v4 = CidrPool {
            ranges: vec![parse_cidr("10.0.0.0/8").unwrap()],
        };
        let v6_ex = parse_cidr("2606:4700::/32").unwrap();
        assert_eq!(v4.excluding(&[v6_ex]), v4, "v6 exclude must not touch v4");

        let v6 = CidrPool {
            ranges: vec![parse_cidr("2606:4700::/32").unwrap()],
        };
        let v4_ex = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(v6.excluding(&[v4_ex]), v6, "v4 exclude must not touch v6");
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
    fn exclusion_splits_around_subnet() {
        let pool = CidrPool {
            ranges: vec![Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            }],
        };
        let ex = parse_cidr("10.1.2.0/24").unwrap();
        let out = pool.excluding(&[ex]);
        let remaining: u128 = out.ranges.iter().map(|c| c.host_count()).sum();
        assert_eq!(remaining, (1 << 24) - 256, "missing portion: {out:?}");
        for c in &out.ranges {
            assert!(!c.contains(ex), "excluded range leaked: {c:?}");
            let end = c.base() + c.host_count();
            assert!(
                end <= 0x0A00_0000u128 + (1 << 24),
                "{c:?} spills out of 10/8"
            );
        }
        let mut sorted = out.ranges.clone();
        sorted.sort_by_key(|c| c.base());
        for w in sorted.windows(2) {
            assert!(
                w[0].base() + w[0].host_count() <= w[1].base(),
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
        let mut ips: Vec<IpAddr> = Vec::new();
        for item in &plan {
            match item {
                PlanItem::Hosts { cidr, offsets } => {
                    assert!(
                        offsets.len() as u128 <= cidr.host_count(),
                        "run-away sample"
                    );
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
        let pool_ips: Vec<IpAddr> = (0..(128 + 256))
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
    fn count_plan_visits_v6_hosts_across_a_mixed_pool() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/24").unwrap(),
                parse_cidr("2606:4700::/120").unwrap(),
            ],
        };
        let mut rng = SplitMix64::new(11);
        let plan = plan(&pool, &ScanTarget::Count(100), &mut rng);
        let mut ips: Vec<IpAddr> = Vec::new();
        for item in &plan {
            match item {
                PlanItem::Hosts { cidr, offsets } => {
                    for &o in offsets {
                        assert!(o < cidr.host_count(), "offset outside range");
                        ips.push(cidr.host(o));
                    }
                }
                _ => panic!("count plan must be concrete hosts"),
            }
        }
        assert_eq!(ips.len(), 100);
        ips.sort();
        ips.dedup();
        assert_eq!(ips.len(), 100, "samples must stay distinct");
        assert!(
            ips.iter().any(|ip| ip.is_ipv6()),
            "v6 range must be sampled: {ips:?}"
        );
        for ip in &ips {
            let family_ok = ip.is_ipv6() || ip.is_ipv4();
            assert!(family_ok, "{ip} is neither family");
        }
    }

    #[test]
    fn preset_samples_cover_v6_ranges() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/24").unwrap(),
                parse_cidr("2606:4700::/32").unwrap(),
            ],
        };
        for (preset, per) in [(&CdnPreset::Quick, 1), (&CdnPreset::Normal, 3)] {
            let plan = plan(
                &pool,
                &ScanTarget::Preset((*preset).clone()),
                &mut SplitMix64::new(3),
            );
            let v6_samples: Vec<&PlanItem> = plan
                .iter()
                .filter(|i| matches!(i, PlanItem::Sample { cidr, .. } if cidr.addr.is_ipv6()))
                .collect();
            assert_eq!(v6_samples.len(), 1, "{preset:?} must sample the v6 range");
            match v6_samples[0] {
                PlanItem::Sample { count, .. } => assert_eq!(*count, per),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn full_preset_samples_v6_ranges_instead_of_enumerating() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/30").unwrap(),
                parse_cidr("2606:4700::/32").unwrap(),
            ],
        };
        let plan = plan(
            &pool,
            &ScanTarget::Preset(CdnPreset::Full),
            &mut SplitMix64::new(1),
        );
        assert_eq!(
            plan,
            vec![
                PlanItem::Every {
                    cidr: parse_cidr("10.0.0.0/30").unwrap()
                },
                PlanItem::Sample {
                    cidr: parse_cidr("2606:4700::/32").unwrap(),
                    count: 1
                },
            ]
        );
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

    // --- Property tests (seeded, no external RNG) -----------------------------

    /// Random v4 address aligned to `prefix`.
    fn random_v4_base(rng: &mut SplitMix64, prefix: u8) -> Ipv4Addr {
        let raw = rng.next_u64() as u32;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Ipv4Addr::from(raw & mask)
    }

    /// Random v6 address aligned to `prefix`.
    fn random_v6_base(rng: &mut SplitMix64, prefix: u8) -> Ipv6Addr {
        let lo = rng.next_u64() as u128;
        let hi = rng.next_u64() as u128;
        let raw = (hi << 64) | lo;
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        Ipv6Addr::from(raw & mask)
    }

    /// Half-open [start, end) span of a range.
    fn span(c: Cidr) -> (u128, u128) {
        (c.base(), c.base() + c.host_count())
    }

    /// Sorted list of every address in `pool` for containment checks.
    fn pool_hosts(pool: &CidrPool) -> Vec<IpAddr> {
        let mut hosts = Vec::new();
        for c in pool.ranges() {
            for i in 0..c.host_count() {
                hosts.push(c.host(i));
            }
        }
        hosts.sort();
        hosts
    }

    /// Collects the concrete hosts a count plan yields, panicking on non-host
    /// items.
    fn plan_hosts(plan: &[PlanItem]) -> Vec<IpAddr> {
        let mut hosts = Vec::new();
        for item in plan {
            match item {
                PlanItem::Hosts { cidr, offsets } => {
                    assert!(
                        offsets.len() as u128 <= cidr.host_count(),
                        "run-away sample"
                    );
                    for &o in offsets {
                        assert!(o < cidr.host_count(), "offset outside range");
                        hosts.push(cidr.host(o));
                    }
                }
                _ => panic!("count plan must be concrete hosts"),
            }
        }
        hosts
    }

    /// Brute-force exclusion invariant over random v4 (outer, inner) pairs:
    /// every host of `outer` must land in exactly one of {inner, output},
    /// the output must cover `outer` minus the overlap, and no output range
    /// may overlap `inner` or escape `outer`. Aligned CIDRs never partially
    /// overlap, so the span-intersection arithmetic is exact.
    #[test]
    fn exclusion_split_matches_brute_force_for_random_cidrs() {
        let mut rng = SplitMix64::new(0xC1D5_5EED);
        for _ in 0..400 {
            let outer_prefix = 18 + rng.below(11) as u8; // 18..=28: <= 16384 hosts
            let outer = Cidr {
                addr: IpAddr::V4(random_v4_base(&mut rng, outer_prefix)),
                prefix: outer_prefix,
            };
            let inner_prefix = rng.below(33) as u8;
            let inner = Cidr {
                addr: IpAddr::V4(random_v4_base(&mut rng, inner_prefix)),
                prefix: inner_prefix,
            };
            let out = CidrPool {
                ranges: vec![outer],
            }
            .excluding(&[inner]);
            let (os, oe) = span(outer);
            let (is, ie) = span(inner);
            let overlap = oe.min(ie).saturating_sub(os.max(is));
            let removed = if inner.contains(outer) {
                outer.host_count()
            } else {
                overlap
            };
            assert_eq!(
                out.ranges.iter().map(|c| c.host_count()).sum::<u128>(),
                outer.host_count() - removed,
                "host count mismatch for outer={outer} inner={inner} out={out:?}"
            );
            for idx in 0..outer.host_count() {
                let host = Cidr {
                    addr: outer.host(idx),
                    prefix: 32,
                };
                let in_inner = inner.contains(host);
                let in_out = out.ranges.iter().any(|c| c.contains(host));
                assert!(
                    in_inner != in_out,
                    "host {host} must be in exactly one of inner/output \
                     (outer={outer} inner={inner} out={out:?})"
                );
            }
            for c in &out.ranges {
                assert!(outer.contains(*c), "{c} escaped {outer}");
                assert!(!c.contains(inner), "{c} overlaps the exclusion {inner}");
            }
            let mut sorted = out.ranges.clone();
            sorted.sort_by_key(|c| c.base());
            for w in sorted.windows(2) {
                assert!(
                    w[0].base() + w[0].host_count() <= w[1].base(),
                    "overlapping parts: {:?} + {:?}",
                    w[0],
                    w[1]
                );
            }
        }
    }

    /// Same invariant for small v6 ranges (prefix 120..=126 keeps the brute
    /// force tractable), inner drawn aligned inside `outer` or equal to it.
    #[test]
    fn v6_exclusion_split_matches_brute_force_for_random_cidrs() {
        let mut rng = SplitMix64::new(0x6E5_5EED);
        for _ in 0..200 {
            let outer_prefix = 120 + rng.below(7) as u8; // 120..=126: <= 256 hosts
            let outer = Cidr {
                addr: IpAddr::V6(random_v6_base(&mut rng, outer_prefix)),
                prefix: outer_prefix,
            };
            let inner_prefix = outer_prefix + rng.below((128 - outer_prefix) as u64 + 1) as u8;
            let stride = 1u128 << (128 - inner_prefix);
            let inner = Cidr {
                addr: IpAddr::V6(Ipv6Addr::from(
                    outer.base() + rng.below_u128(outer.host_count() / stride) * stride,
                )),
                prefix: inner_prefix,
            };
            let out = CidrPool {
                ranges: vec![outer],
            }
            .excluding(&[inner]);
            let removed = if inner_prefix == outer_prefix {
                outer.host_count()
            } else {
                inner.host_count()
            };
            assert_eq!(
                out.ranges.iter().map(|c| c.host_count()).sum::<u128>(),
                outer.host_count() - removed,
                "host count mismatch for outer={outer} inner={inner} out={out:?}"
            );
            for idx in 0..outer.host_count() {
                let host = Cidr {
                    addr: outer.host(idx),
                    prefix: 128,
                };
                let in_inner = inner.contains(host);
                let in_out = out.ranges.iter().any(|c| c.contains(host));
                assert!(
                    in_inner != in_out,
                    "host {host} must be in exactly one of inner/output \
                     (outer={outer} inner={inner} out={out:?})"
                );
            }
        }
    }

    /// Count sampling must stay distinct and in-pool across many seeds and
    /// counts, including counts near the pool boundary (offset rounding).
    #[test]
    fn count_sampling_is_distinct_across_seeds_and_counts() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/22").unwrap(),
                parse_cidr("10.0.4.0/24").unwrap(),
            ],
        };
        let hosts = pool_hosts(&pool);
        assert_eq!(hosts.len(), 1024 + 256);
        for seed in 0..25 {
            for &n in &[1u32, 2, 5, 64, 128, 256, 1024, 1279] {
                let plan = plan(&pool, &ScanTarget::Count(n), &mut SplitMix64::new(seed));
                let picked = plan_hosts(&plan);
                assert_eq!(picked.len() as u32, n, "seed {seed} count {n}");
                let mut sorted = picked.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(
                    sorted.len() as u32,
                    n,
                    "seed {seed} count {n}: samples not distinct"
                );
                for ip in &picked {
                    assert!(
                        hosts.binary_search(ip).is_ok(),
                        "seed {seed} count {n}: {ip} outside the pool"
                    );
                }
            }
        }
    }

    /// The same distinctness/containment properties on a mixed v4+v6 pool.
    #[test]
    fn count_sampling_stays_distinct_on_mixed_family_pools() {
        let pool = CidrPool {
            ranges: vec![
                parse_cidr("10.0.0.0/24").unwrap(),
                parse_cidr("2606:4700::/120").unwrap(),
            ],
        };
        let hosts = pool_hosts(&pool);
        assert_eq!(hosts.len(), 512);
        for seed in 0..8 {
            for &n in &[3u32, 100, 400] {
                let plan = plan(&pool, &ScanTarget::Count(n), &mut SplitMix64::new(seed));
                let picked = plan_hosts(&plan);
                assert_eq!(picked.len() as u32, n, "seed {seed} count {n}");
                let mut sorted = picked.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(
                    sorted.len() as u32,
                    n,
                    "seed {seed} count {n}: samples not distinct"
                );
                for ip in &picked {
                    assert!(
                        hosts.binary_search(ip).is_ok(),
                        "seed {seed} count {n}: {ip} outside the pool"
                    );
                }
                // Small counts may legitimately land entirely in the v4 half
                // (512 hosts, 256 v4); only a near-total sample must reach v6.
                if n >= 400 {
                    assert!(
                        picked.iter().any(|ip| ip.is_ipv6()),
                        "seed {seed} count {n}: v6 half never sampled"
                    );
                }
            }
        }
    }

    #[test]
    fn effective_pool_applies_custom_and_exclude() {
        let pool = effective_pool_from(
            &["10.0.0.0/24".to_owned()],
            &["10.0.0.0/25".to_owned()],
            false,
            Some(""),
            None,
        )
        .unwrap();
        assert_eq!(pool.host_count(), 128);
    }

    #[test]
    fn effective_pool_includes_v6_only_when_requested() {
        let v4 = effective_pool_from(&[], &[], false, None, None).unwrap();
        assert!(
            v4.ranges().iter().all(|c| c.addr.is_ipv4()),
            "default pool must stay IPv4-only"
        );
        let v6 = effective_pool_from(&[], &[], true, None, None).unwrap();
        assert!(v6.ranges().iter().any(|c| c.addr.is_ipv6()));
        assert!(
            v6.ranges().iter().any(|c| c.addr.is_ipv4()),
            "v4 half must remain"
        );
    }

    #[test]
    fn custom_v6_cidrs_are_honored_without_the_flag() {
        let pool =
            effective_pool_from(&["2606:4700::/32".to_owned()], &[], false, None, None).unwrap();
        assert!(pool.ranges().iter().all(|c| c.addr.is_ipv6()));
    }

    #[test]
    fn effective_pool_prefers_refreshed_v6_when_included() {
        let pool = effective_pool_from(&[], &[], true, None, Some("2606:4700::/32\n")).unwrap();
        assert_eq!(pool.ranges().iter().filter(|c| c.addr.is_ipv6()).count(), 1);
        let pool = effective_pool_from(&[], &[], false, None, Some("2606:4700::/32\n")).unwrap();
        assert!(
            pool.ranges().iter().all(|c| c.addr.is_ipv4()),
            "refreshed v6 must be ignored when include_v6 is off"
        );
    }

    #[test]
    fn base_pool_prefers_runtime_refresh() {
        let live = base_pool(Some("10.0.0.0/24\n")).unwrap();
        assert_eq!(live.host_count(), 256);
        assert!(base_pool(None).unwrap().host_count() > 1_000_000);
        let live6 = base_pool_v6(Some("2606:4700::/32\n")).unwrap();
        assert_eq!(live6.ranges().len(), 1);
        assert!(base_pool_v6(None).unwrap().ranges().len() >= 5);
    }

    #[test]
    fn base_pool_falls_back_to_bundled_when_refresh_is_corrupt() {
        let pool = base_pool(Some("not a cidr\n10.0.0.0/8\n")).unwrap();
        assert_eq!(pool, CidrPool::bundled());
        let pool6 = base_pool_v6(Some("2606:4700::/32\nbroken")).unwrap();
        assert_eq!(pool6, CidrPool::bundled_v6());
    }

    #[test]
    fn effective_pool_survives_a_corrupt_refreshed_file() {
        let pool = effective_pool_from(&[], &[], false, Some("garbage\n"), None).unwrap();
        assert_eq!(pool, CidrPool::bundled());
        let pool =
            effective_pool_from(&[], &[], true, Some("garbage\n"), Some("garbage\n")).unwrap();
        assert!(
            pool.ranges().iter().any(|c| c.addr.is_ipv4()),
            "v4 half must survive a corrupt refresh"
        );
        assert!(
            pool.ranges().iter().any(|c| c.addr.is_ipv6()),
            "v6 half must survive a corrupt refresh"
        );
    }

    #[test]
    fn effective_pool_still_rejects_bad_custom_cidrs() {
        assert!(
            effective_pool_from(
                &["not-a-cidr".to_owned()],
                &[],
                false,
                Some("garbage"),
                None
            )
            .is_err(),
            "user-supplied CIDRs must fail loudly, only the refreshed file degrades"
        );
    }

    #[test]
    fn parses_official_fixture_skipping_v6() {
        // v6 entries in the response are discarded: the v4 refresh must
        // never seed v6 hosts into a v4-only scan.
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
        fn get<'a>(&'a self, _url: &'a str) -> HttpFuture<'a> {
            Box::pin(async move { Ok(self.0.to_owned()) })
        }
    }

    #[tokio::test]
    async fn refresh_to_disk_round_trips() {
        // Refresh writes the data-dir file for real; redirect the data dir to
        // a throwaway temp dir (warpgen pattern) so a developer's refreshed
        // ranges are never read, replaced, or deleted by a test run.
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

    #[test]
    fn rfc3339_utc_formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_735_689_600), "2025-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_735_734_896), "2025-01-01T12:34:56Z");
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_784_160_000), "2026-07-16T00:00:00Z");
    }

    #[test]
    fn last_updated_header_is_skipped_by_pool_and_read_back() {
        let text = "# last-updated: 2025-01-01T12:34:56Z\n10.0.0.0/8\n";
        assert_eq!(
            last_updated_of(text).as_deref(),
            Some("2025-01-01T12:34:56Z")
        );
        assert_eq!(last_updated_of("10.0.0.0/8\n"), None);
        assert_eq!(CidrPool::parse(text).unwrap().host_count(), 1 << 24);
    }

    #[test]
    fn v6_pool_skips_last_updated_header() {
        let text = "# last-updated: 2025-01-01T12:34:56Z\n2606:4700::/32\n2400:cb00::/32\n";
        let pool = CidrPool::parse(text).unwrap();
        assert_eq!(pool.ranges().len(), 2);
        assert_eq!(base_pool_v6(Some(text)).unwrap().ranges().len(), 2);
    }

    #[tokio::test]
    async fn refresh_v6_to_disk_round_trips() {
        // Same isolation as the v4 round trip: the write lands in the
        // throwaway data dir, never the developer's.
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

    /// Plays a minimal no-auth socks server that answers CONNECT and serves
    /// one `200 OK` body — enough to prove the client's wire format.
    async fn fake_socks_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                sock.read_exact(&mut byte).await.unwrap();
                req.push(byte[0]);
                if req.len() >= 5 && req[3] == 0x03 && req.len() >= 5 + req[4] as usize + 2 {
                    break;
                }
            }
            // VER REP RSV ATYP BND.ADDR BND.PORT (127.0.0.1:0)
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut http = Vec::new();
            while !http.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                sock.read_exact(&mut byte).await.unwrap();
                http.push(byte[0]);
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn tunnel_probe_gets_http_through_fake_socks() {
        let socks = fake_socks_server().await;
        let body = get_via_socks("http://example.test/check", socks, 5_000)
            .await
            .unwrap();
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn tunnel_probe_times_out_when_socks_never_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept the greeting and then stay silent: the client must give up.
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 3];
                let _ = sock.read_exact(&mut buf).await;
                let _ = tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let err = get_via_socks("http://example.test/", socks, 50)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
