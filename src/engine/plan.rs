use std::net::{IpAddr, Ipv4Addr};

use crate::api::types::{CdnPreset, Port, ScanTarget};
use crate::ranges::{Cidr, CidrPool};

pub(super) fn plan_hosts_iter<'a>(
    item: &'a PlanItem,
    rng: &'a mut SplitMix64,
) -> Box<dyn Iterator<Item = IpAddr> + Send + 'a> {
    match item {
        PlanItem::Every { cidr } => Box::new((0..cidr.host_count()).map(move |i| cidr.host(i))),
        PlanItem::Sample { cidr, count } => {
            let count = (*count as u128).min(cidr.host_count());
            let (draw_max, skip_net_bcast) = if cidr.addr.is_ipv4() && cidr.prefix >= 24 {
                (cidr.host_count().saturating_sub(2), true)
            } else {
                (cidr.host_count(), false)
            };
            let mut seen = std::collections::HashSet::new();
            let mut emitted = 0u128;
            Box::new(std::iter::from_fn(move || {
                if emitted >= count || seen.len() as u128 >= draw_max {
                    return None;
                }
                loop {
                    let idx = if skip_net_bcast {
                        (rng.below(draw_max.max(1) as u64) + 1) as u128
                    } else {
                        rng.below_u128(cidr.host_count())
                    };
                    if seen.insert(idx) {
                        emitted += 1;
                        return Some(cidr.host(idx));
                    }
                }
            }))
        }
        PlanItem::Hosts { cidr, offsets } => Box::new(offsets.iter().map(move |&o| cidr.host(o))),
    }
}

pub(super) fn plan_probe_count(plan: &[PlanItem], ports: &[Port]) -> u64 {
    let hosts: u128 = plan
        .iter()
        .map(|i| match i {
            PlanItem::Every { cidr } => cidr.host_count(),
            PlanItem::Sample { cidr, count } => (*count as u128).min(cidr.host_count()),
            PlanItem::Hosts { offsets, .. } => offsets.len() as u128,
        })
        .sum();
    let probes = hosts.saturating_mul(ports.len() as u128);
    probes.min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanItem {
    Every { cidr: Cidr },
    Sample { cidr: Cidr, count: u64 },
    Hosts { cidr: Cidr, offsets: Vec<u128> },
}

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

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    pub fn below_u128(&mut self, bound: u128) -> u128 {
        let lo = self.next_u64() as u128;
        let hi = self.next_u64() as u128;
        ((hi << 64) | lo) % bound
    }
}

pub fn plan(pool: &CidrPool, target: &ScanTarget, rng: &mut SplitMix64) -> Vec<PlanItem> {
    match target {
        ScanTarget::Count(n) => plan_count(pool, *n as u64, rng),
        ScanTarget::Preset(p) => match p {
            CdnPreset::Quick => plan_preset(pool, 1),
            CdnPreset::Normal => plan_preset(pool, 3),
            CdnPreset::Full => pool
                .ranges()
                .iter()
                .map(|c| {
                    if c.addr.is_ipv6() {
                        PlanItem::Sample { cidr: *c, count: 1 }
                    } else {
                        PlanItem::Every { cidr: *c }
                    }
                })
                .collect(),
        },
    }
}

fn plan_preset(pool: &CidrPool, per: u64) -> Vec<PlanItem> {
    let mut items = Vec::new();
    for &cidr in pool.ranges() {
        if cidr.addr.is_ipv6() {
            items.push(PlanItem::Sample {
                cidr,
                count: per.min(cidr.host_count().min(u64::MAX as u128) as u64),
            });
            continue;
        }
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

const MAX_PRESET_BLOCKS: u64 = 1 << 16;

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
        let end = offset.saturating_add(cidr.host_count());
        let mut in_range: Vec<u128> = Vec::new();
        while i < pick.len() && pick[i] < end && pick[i] >= offset {
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
            let hosts: Vec<IpAddr> = plan_hosts_iter(&plan[0], &mut SplitMix64::new(1)).collect();
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

    #[test]
    fn every_preset_covers_all_usable_hosts_of_slash31_and_slash32() {
        for prefix in [31u8, 32] {
            let net = format!("203.0.113.0/{prefix}");
            let pool = CidrPool::parse(&net).unwrap();
            for preset in [CdnPreset::Quick, CdnPreset::Normal, CdnPreset::Full] {
                let plan = plan(
                    &pool,
                    &ScanTarget::Preset(preset.clone()),
                    &mut SplitMix64::new(1),
                );
                assert_eq!(
                    plan,
                    vec![PlanItem::Every {
                        cidr: parse_cidr(&net).unwrap()
                    }],
                    "{prefix} must route to Every, never lose a usable address"
                );
            }
        }
    }
    #[test]
    fn sampled_v6_preserves_first_and_last_addresses() {
        let pool = CidrPool::parse("2001:db8::/120").unwrap();
        let quick = plan(
            &pool,
            &ScanTarget::Preset(CdnPreset::Quick),
            &mut SplitMix64::new(9),
        );
        let block = parse_cidr("2001:db8::/120").unwrap();
        let full: std::collections::HashSet<IpAddr> = (0..256u128).map(|i| block.host(i)).collect();
        let mut rng = SplitMix64::new(9);
        let mut hosts: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
        for item in &quick {
            hosts.extend(plan_hosts_iter(item, &mut rng));
        }
        assert!(!hosts.is_empty());
        assert!(
            hosts.iter().all(|h| full.contains(h)),
            "v6 sampling must stay inside the block with no broadcast-style trim"
        );
        let full_plan = plan(
            &pool,
            &ScanTarget::Preset(CdnPreset::Full),
            &mut SplitMix64::new(9),
        );
        assert!(matches!(
            full_plan.last(),
            Some(PlanItem::Sample { count: 1, .. })
        ));
    }
    #[test]
    fn count_plan_is_deterministic_for_a_seed_and_varies_across_seeds() {
        let pool = CidrPool::parse("203.0.113.0/22").unwrap();
        let run = |seed: u64| plan(&pool, &ScanTarget::Count(64), &mut SplitMix64::new(seed));
        let a = run(1234);
        let b = run(1234);
        assert_eq!(a, b, "same seed must reproduce the same plan");
        let c = run(5678);
        assert_ne!(a, c, "different seeds must diverge");
        let mut rng = SplitMix64::new(1234);
        let mut hosts: Vec<IpAddr> = Vec::new();
        for item in &a {
            hosts.extend(plan_hosts_iter(item, &mut rng));
        }
        assert_eq!(hosts.len(), 64);
        assert!(hosts.iter().all(|ip| ip.is_ipv4()));
    }

    #[test]
    fn count_plan_partition_survives_two_half_space_v6_ranges() {
        let pool = CidrPool::parse("8000::/1\n::/1\n").unwrap();
        assert_eq!(
            pool.host_count(),
            u128::MAX,
            "two half-spaces must saturate, not overflow"
        );
        for seed in 0..8u64 {
            let plan = plan(&pool, &ScanTarget::Count(8), &mut SplitMix64::new(seed));
            let mut picked = 0usize;
            for item in &plan {
                match item {
                    PlanItem::Hosts { cidr, offsets } => {
                        for &o in offsets {
                            assert!(o < cidr.host_count(), "offset escaped its range");
                            assert!(cidr.host(o).is_ipv6(), "host leaked outside the v6 ranges");
                            picked += 1;
                        }
                    }
                    _ => panic!("count plan must be concrete hosts"),
                }
            }
            assert_eq!(picked, 8, "seed {seed} must still yield eight hosts");
        }
    }

    #[test]
    fn count_one_on_a_single_host_pool_probes_exactly_it() {
        let pool = CidrPool::parse("203.0.113.7/32").unwrap();
        let p = plan(&pool, &ScanTarget::Count(1), &mut SplitMix64::new(3));
        let mut rng4 = SplitMix64::new(4);
        let mut hosts: Vec<IpAddr> = Vec::new();
        for item in &p {
            hosts.extend(plan_hosts_iter(item, &mut rng4));
        }
        assert_eq!(hosts, vec!["203.0.113.7".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn count_above_the_pool_degrades_to_every_host() {
        let pool = CidrPool::parse("203.0.113.0/30").unwrap();
        for requested in [1000u32, u32::MAX] {
            let p = plan(
                &pool,
                &ScanTarget::Count(requested),
                &mut SplitMix64::new(5),
            );
            let mut rng6 = SplitMix64::new(6);
            let mut hosts: Vec<IpAddr> = Vec::new();
            for item in &p {
                hosts.extend(plan_hosts_iter(item, &mut rng6));
            }
            assert_eq!(
                hosts.len(),
                4,
                "Every mode probes all /30 addresses (requested {requested})"
            );
            let mut sorted = hosts;
            sorted.sort();
            assert_eq!(
                sorted,
                vec![
                    "203.0.113.0".parse::<IpAddr>().unwrap(),
                    "203.0.113.1".parse::<IpAddr>().unwrap(),
                    "203.0.113.2".parse::<IpAddr>().unwrap(),
                    "203.0.113.3".parse::<IpAddr>().unwrap(),
                ],
                "Every mode probes all /30 addresses in order"
            );
        }
    }
}
