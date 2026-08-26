//! Scan-planning: turns an effective pool and target into the walk plan the
//! engine probes (every host, per-/24 random samples, or pre-rolled concrete
//! host offsets for v6 host spaces). Pure logic over `ranges::CidrPool`; the
//! seeded splitmix64 sampling keeps plan shapes deterministic across runs.

use std::net::{IpAddr, Ipv4Addr};

use crate::api::types::{CdnPreset, ScanTarget};
use crate::ranges::{Cidr, CidrPool};

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
                .ranges()
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
    for &cidr in pool.ranges() {
        if cidr.addr.is_ipv6() {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count().min(u64::MAX as u128) as u64),
            });
            continue;
        }
        // Dense sampling skips network+broadcast, so /31-/32 would draw from
        // an empty space and silently probe nothing; walk them host by host.
        if cidr.host_count() <= 2 {
            items.push(PlanItem::Every { cidr });
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
            .ranges()
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
    for &cidr in pool.ranges() {
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

/// Unwraps the v4 address of a range the caller has already checked is v4.
fn ipv4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!("v6 ranges are handled separately"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ranges::parse_cidr;

    #[test]
    fn preset_routes_tiny_cidrs_to_every() {
        for preset in [CdnPreset::Quick, CdnPreset::Normal] {
            let pool = CidrPool::parse("203.0.113.5/32").unwrap();
            let plan = plan(
                &pool,
                &ScanTarget::Preset(preset.clone()),
                &mut SplitMix64::new(1),
            );
            assert_eq!(
                plan,
                vec![PlanItem::Every {
                    cidr: parse_cidr("203.0.113.5/32").unwrap()
                }],
                "{preset:?} must walk a /32 host-by-host"
            );
            let hosts: Vec<IpAddr> =
                super::super::plan_hosts_iter(&plan[0], &mut SplitMix64::new(1)).collect();
            assert_eq!(hosts, vec![IpAddr::V4("203.0.113.5".parse().unwrap())]);
        }
    }

    #[test]
    fn preset_still_samples_dense_blocks() {
        let pool = CidrPool::parse("203.0.113.0/24").unwrap();
        let plan = plan(
            &pool,
            &ScanTarget::Preset(CdnPreset::Quick),
            &mut SplitMix64::new(1),
        );
        assert_eq!(
            plan,
            vec![PlanItem::Sample {
                cidr: parse_cidr("203.0.113.0/24").unwrap(),
                count: 1,
            }]
        );
    }
}
