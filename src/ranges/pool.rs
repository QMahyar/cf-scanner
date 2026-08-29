use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};

use crate::paths;

pub const BUNDLED_RANGES: &str = include_str!("../../data/cf-ranges.txt");
pub const BUNDLED_RANGES_V6: &str = include_str!("../../data/cf-ranges-v6.txt");

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
    /// v6 ranges are never decomposed this way (see `plan_preset` in
    /// `crate::engine::plan`).
    pub(crate) fn sub24_count(self) -> u64 {
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

/// Parses and normalizes `ip/prefix`; host bits are masked off. Delegates
/// grammar validation to the canonical `api::validate::parse_cidr` and adds
/// pool-specific host-bit masking.
pub fn parse_cidr(s: &str) -> Result<Cidr> {
    let (addr, prefix) = crate::api::types::parse_cidr(s).map_err(|e| anyhow!("{e}"))?;
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

pub(crate) fn parse_lines(text: &str) -> Result<Vec<Cidr>> {
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
        Self::parse(BUNDLED_RANGES).expect("bundled ranges must parse: data/cf-ranges.txt")
    }

    /// The official Cloudflare IPv6 ranges; opt-in via `ScanConfig::include_v6`.
    pub fn bundled_v6() -> Self {
        Self::parse(BUNDLED_RANGES_V6).expect("bundled v6 ranges must parse: data/cf-ranges-v6.txt")
    }

    pub(crate) fn from_ranges(mut ranges: Vec<Cidr>) -> Self {
        ranges.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.prefix.cmp(&b.prefix)));
        ranges.dedup();
        Self { ranges }
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

/// Atomically replaces `path` with `pool` (temp file + rename), tagged with
/// the `last_updated` header that CLI refreshes and the server's background
/// refresh share as one timestamp source.
pub fn write_pool_to(path: &std::path::Path, pool: &CidrPool, last_updated: &str) -> Result<()> {
    let _gate = paths::data_write_guard();
    let dir = paths::data_dir()?;
    fs::create_dir_all(&dir).context("create data dir")?;
    let mut text = format!("{LAST_UPDATED_PREFIX}{last_updated}\n");
    text.push_str(&render_lines(pool.ranges()));
    let tmp = path.with_extension("txt.tmp");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{CdnPreset, ScanTarget};
    use crate::engine::{PlanItem, SplitMix64, plan};
    use std::net::Ipv4Addr;

    /// Shared grammar fixture: the same cases the UI's TS mirror
    /// (ui/src/lib/validators.ts) is written against, so a server-side
    /// grammar change that strands the frontend shows up here.
    #[test]
    fn grammar_fixture_cidr_cases_match_parse_cidr() {
        let raw = include_str!("../../tests/fixtures/grammar-cases.json");
        let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        let checked = cases.iter().filter(|c| c["kind"] == "cidr").count();
        assert!(
            checked >= 15,
            "fixture must keep cidr coverage, got {checked}"
        );
        for case in cases.iter().filter(|c| c["kind"] == "cidr") {
            let input = case["input"].as_str().unwrap();
            let expect_ok = case["expect"] == "ok";
            assert_eq!(
                parse_cidr(input).is_ok(),
                expect_ok,
                "cidr {input:?} expected {expect_ok}"
            );
        }
    }

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
    fn bundled_pools_parse_non_empty() {
        assert!(!CidrPool::bundled().ranges().is_empty());
        assert!(!CidrPool::bundled_v6().ranges().is_empty());
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
        assert_eq!(
            c.host(0),
            "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            c.host(255),
            "2001:db8::ff".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            c.host(256),
            "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap()
        );
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

    fn random_v4_base(rng: &mut SplitMix64, prefix: u8) -> Ipv4Addr {
        let raw = rng.next_u64() as u32;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Ipv4Addr::from(raw & mask)
    }

    fn random_v6_base(rng: &mut SplitMix64, prefix: u8) -> std::net::Ipv6Addr {
        let lo = rng.next_u64() as u128;
        let hi = rng.next_u64() as u128;
        let raw = (hi << 64) | lo;
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        std::net::Ipv6Addr::from(raw & mask)
    }

    fn span(c: Cidr) -> (u128, u128) {
        (c.base(), c.base() + c.host_count())
    }

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

    #[test]
    fn exclusion_split_matches_brute_force_for_random_cidrs() {
        let mut rng = SplitMix64::new(0xC1D5_5EED);
        for _ in 0..400 {
            let outer_prefix = 18 + rng.below(11) as u8;
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

    #[test]
    fn v6_exclusion_split_matches_brute_force_for_random_cidrs() {
        let mut rng = SplitMix64::new(0x6E5_5EED);
        for _ in 0..200 {
            let outer_prefix = 120 + rng.below(7) as u8;
            let outer = Cidr {
                addr: IpAddr::V6(random_v6_base(&mut rng, outer_prefix)),
                prefix: outer_prefix,
            };
            let inner_prefix = outer_prefix + rng.below((128 - outer_prefix) as u64 + 1) as u8;
            let stride = 1u128 << (128 - inner_prefix);
            let inner = Cidr {
                addr: IpAddr::V6(std::net::Ipv6Addr::from(
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

    #[test]
    fn from_ranges_dedups_exact_duplicates() {
        let cidrs = vec![
            parse_cidr("10.0.0.0/24").unwrap(),
            parse_cidr("10.0.0.0/24").unwrap(),
        ];
        let pool = CidrPool::from_ranges(cidrs);
        assert_eq!(pool.ranges().len(), 1);
        assert_eq!(pool.host_count(), 256);
    }
}
