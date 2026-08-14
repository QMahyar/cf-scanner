//! Property-style tests (no proptest dep): a seeded `SplitMix64` RNG drives
//! (a) the CIDR exclusion split against a brute-force containment reference,
//! and (b) wgconf render -> parse round-trips over random-but-valid key
//! material. The split logic lives in `ranges.rs` (owned by another branch);
//! it is tested here black-box through the public `CidrPool` API.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use cf_scanner::ranges::{Cidr, CidrPool, SplitMix64};
use cf_scanner::wgconf::{AmneziaParams, WgConfig, WgPeer, parse_wgconf, render_wgconf};

// --- (a) CIDR exclusion split ----------------------------------------------

fn v4_base(c: &Cidr) -> u32 {
    match c.addr {
        IpAddr::V4(a) => u32::from(a),
        IpAddr::V6(_) => panic!("v4 test fed a v6 range"),
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn v4_contains(c: &Cidr, ip: u32) -> bool {
    ip & v4_mask(c.prefix) == v4_base(c)
}

fn v4_hosts(c: &Cidr) -> impl Iterator<Item = u32> {
    let base = v4_base(c);
    (0..c.host_count() as u32).map(move |i| base + i)
}

fn brute_force_union(outer: &Cidr, excluded: &[Cidr]) -> HashSet<u32> {
    v4_hosts(outer)
        .filter(|ip| !excluded.iter().any(|e| v4_contains(e, *ip)))
        .collect()
}

/// A random aligned sub-block of `outer` (v4); `prefix` must be within
/// `outer.prefix..=32`. Equal to the whole outer when prefix == outer.prefix.
fn aligned_v4_sub(outer: &Cidr, prefix: u8, rng: &mut SplitMix64) -> Cidr {
    let block = 1u32 << (32 - prefix as u32);
    let slots = (outer.host_count() / u128::from(block)) as u64;
    let offset = rng.below(slots) as u32 * block;
    Cidr {
        addr: IpAddr::V4(Ipv4Addr::from(v4_base(outer) + offset)),
        prefix,
    }
}

#[test]
fn v4_exclusion_split_matches_brute_force_reference() {
    let mut rng = SplitMix64::new(0xC1D);
    for round in 0..64 {
        let base = (10 << 24) | (rng.below(1 << 16) as u32) << 8;
        let outer = Cidr {
            addr: IpAddr::V4(Ipv4Addr::from(base)),
            prefix: 24,
        };
        let excluded: Vec<Cidr> = (0..1 + rng.below(3) as usize)
            .map(|_| aligned_v4_sub(&outer, 24 + rng.below(9) as u8, &mut rng))
            .collect();

        let split = CidrPool::parse(&format!("{outer}\n"))
            .unwrap()
            .excluding(&excluded);

        // Union of the split ranges == outer minus the exclusions (set
        // equality also catches any split range intersecting an exclusion).
        let got: HashSet<u32> = split.ranges().iter().flat_map(v4_hosts).collect();
        assert_eq!(
            got,
            brute_force_union(&outer, &excluded),
            "round {round} with exclusions {excluded:?}"
        );

        // Split ranges are valid aligned CIDRs inside the outer block, and
        // the host counts sum exactly to the covered set (no overlaps, no
        // gaps, no duplicates).
        let mut total = 0u64;
        for c in split.ranges() {
            assert!(c.addr.is_ipv4(), "round {round}: v6 leaked into a v4 split");
            assert!(
                c.prefix >= outer.prefix && c.prefix <= 32,
                "round {round}: split block {c} out of range"
            );
            assert_eq!(
                u128::from(v4_base(c)) % u128::from(1u32 << (32 - c.prefix as u32)),
                0,
                "round {round}: unaligned split block {c}"
            );
            assert!(
                v4_contains(&outer, v4_base(c)),
                "round {round}: {c} outside {outer}"
            );
            total += c.host_count() as u64;
        }
        assert_eq!(
            total as usize,
            got.len(),
            "round {round}: split ranges overlap or leave gaps"
        );
    }
}

#[test]
fn v6_exclusion_split_matches_brute_force_reference() {
    let mut rng = SplitMix64::new(0xC1D6);
    for round in 0..32 {
        let base = rng.below_u128(1 << 120) << 8;
        let outer = Cidr {
            addr: IpAddr::V6(Ipv6Addr::from(base)),
            prefix: 120,
        };
        let excluded: Vec<Cidr> = (0..1 + rng.below(3) as usize)
            .map(|_| {
                let prefix = 120 + rng.below(9) as u8; // 120..=128
                let block = 1u128 << (128 - prefix as u32);
                let offset = rng.below_u128(256 / block) * block;
                Cidr {
                    addr: IpAddr::V6(Ipv6Addr::from(base + offset)),
                    prefix,
                }
            })
            .collect();

        let split = CidrPool::parse(&format!("{outer}\n"))
            .unwrap()
            .excluding(&excluded);

        let mut want = HashSet::new();
        for i in 0..256 {
            let ip = base + i;
            if !excluded
                .iter()
                .any(|e| ip & v6_mask(e.prefix) == v6_base(e))
            {
                want.insert(ip);
            }
        }
        let mut got = HashSet::new();
        let mut total = 0u64;
        for c in split.ranges() {
            assert!(c.addr.is_ipv6(), "round {round}: v4 leaked into a v6 split");
            assert!(
                c.prefix >= 120 && c.prefix <= 128,
                "round {round}: {c} out of range"
            );
            let cbase = v6_base(c);
            assert_eq!(
                cbase % (1u128 << (128 - c.prefix as u32)),
                0,
                "unaligned {c}"
            );
            for i in 0..c.host_count() {
                got.insert(cbase + i);
            }
            total += c.host_count() as u64;
        }
        assert_eq!(got, want, "round {round} with exclusions {excluded:?}");
        assert_eq!(total as usize, got.len(), "round {round}: overlap or gaps");
    }
}

fn v6_base(c: &Cidr) -> u128 {
    match c.addr {
        IpAddr::V6(a) => u128::from(a),
        IpAddr::V4(_) => panic!("v6 test fed a v4 range"),
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

#[test]
fn cross_family_exclusions_never_touch_the_other_family() {
    let v4 = Cidr {
        addr: IpAddr::V4(Ipv4Addr::from(10 << 24)),
        prefix: 24,
    };
    let v6 = Cidr {
        addr: IpAddr::V6(Ipv6Addr::from(
            0x2001_0db8_0000_0000_0000_0000_0000_0000u128,
        )),
        prefix: 120,
    };
    let mixed = CidrPool::parse(&format!("{v4}\n{v6}\n")).unwrap();
    let v4_excluded = mixed.excluding(&[v6]);
    assert_eq!(
        v4_excluded.host_count(),
        v4.host_count(),
        "a v6 exclusion must not shrink a v4 pool"
    );
    assert!(v4_excluded.ranges().iter().all(|c| c.addr.is_ipv4()));
}

// --- (b) wgconf render -> parse round-trip fuzz -----------------------------

fn random_key(rng: &mut SplitMix64) -> String {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn octet(rng: &mut SplitMix64) -> u64 {
    rng.below(256)
}

/// Builds a random-but-valid config: keys are real 32-byte base64, optional
/// strings are None or non-empty (render omits the None case, so empty
/// strings would not survive the round trip).
fn random_wgconf(rng: &mut SplitMix64) -> WgConfig {
    let amnezia = AmneziaParams {
        jc: Some(rng.below(u16::MAX as u64) as u16),
        jmin: Some(rng.below(u16::MAX as u64) as u16),
        jmax: Some(rng.below(u16::MAX as u64) as u16),
        s1: Some(rng.below(256) as u8),
        s2: Some(rng.below(256) as u8),
        h1: Some(rng.below(256) as u8),
        h2: Some(rng.below(256) as u8),
        h3: Some(rng.below(256) as u8),
        h4: Some(rng.below(256) as u8),
    };
    let address = match rng.below(3) {
        0 => String::new(),
        1 => format!("172.16.{}.{}/32", octet(rng), octet(rng)),
        _ => format!(
            "172.16.{}.{}/32, 2606:4700:110::{}/128",
            octet(rng),
            octet(rng),
            octet(rng)
        ),
    };
    let allowed_ips = match rng.below(3) {
        0 => vec![],
        1 => vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()],
        _ => vec![format!("10.{}.0.0/16", octet(rng))],
    };
    WgConfig {
        private_key: random_key(rng),
        address,
        dns: (rng.below(2) == 0).then(|| {
            format!(
                "{}.{}.{}.{}",
                octet(rng),
                octet(rng),
                octet(rng),
                octet(rng)
            )
        }),
        mtu: Some(rng.below(2000) as u16 + 1000),
        amnezia,
        peer: WgPeer {
            public_key: random_key(rng),
            preshared_key: (rng.below(2) == 0).then(|| random_key(rng)),
            allowed_ips,
            endpoint: Some(format!(
                "{}.{}.{}.{}:{}",
                octet(rng),
                octet(rng),
                octet(rng),
                octet(rng),
                1000 + rng.below(5000)
            )),
            persistent_keepalive: Some(rng.below(200) as u16 + 1),
        },
    }
}

#[test]
fn wgconf_render_parse_round_trips_random_valid_configs() {
    let mut rng = SplitMix64::new(0x0006_C00F);
    for round in 0..200 {
        let wg = random_wgconf(&mut rng);
        let text = render_wgconf(&wg);
        let reparsed = parse_wgconf(&text)
            .unwrap_or_else(|e| panic!("round {round} failed to parse:\n{text}\n{e:#}"));
        assert_eq!(wg, reparsed, "round {round} drifted:\n{text}");
    }
}
