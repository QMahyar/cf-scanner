//! Candidate ranges for CDN mode: bundled official Cloudflare space, custom
//! CIDRs, dirty-range exclusions, and preset/count sampling plans.
//! Pure logic here; the network fetch for `ranges refresh` is injected so
//! tests never touch the wire.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    let dir = paths::data_dir()?;
    fs::create_dir_all(&dir).context("create data dir")?;
    let path = paths::refreshed_ranges_path()?;
    let mut text = format!("{LAST_UPDATED_PREFIX}{last_updated}\n");
    text.push_str(&render_lines(pool.ranges()));
    let tmp = path.with_extension("txt.tmp");
    // Scans read this file at start; a torn write would fail the scan. Rename
    // is atomic on the same volume, so readers see old or new, never partial.
    fs::write(&tmp, text).context("write refreshed ranges")?;
    fs::rename(&tmp, &path).context("replace refreshed ranges")?;
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
    // 5 redirects so downloads survive the common 302 hop.
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
            if !current.starts_with("https://") {
                bail!("refusing non-https redirect to {current}");
            }
            continue;
        }
        return Ok(body);
    }
    bail!("too many redirects fetching {url}")
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
        assert!(written.starts_with("# last-updated: "), "{written}");
        assert!(written.ends_with("10.0.0.0/8\n"), "{written}");
        assert!(last_updated_of(&written).is_some());
        assert_eq!(CidrPool::parse(&written).unwrap().host_count(), 1 << 24);
        fs::remove_file(paths::refreshed_ranges_path().unwrap()).unwrap();
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
