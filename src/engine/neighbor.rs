use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use tokio::sync::mpsc;

use super::ProbeContext;
use super::store::lock;

#[derive(Clone)]
pub(super) struct ProbeTask {
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

pub(super) const NEIGHBOR_CHANNEL_CAP: usize = 256;
pub(super) const NEIGHBOR_IDLE_POLL_MS: u64 = 1;

pub(super) struct NeighborHub {
    seen: Mutex<HashSet<IpAddr>>,
    tx: mpsc::Sender<ProbeTask>,
    limit: u32,
}

impl NeighborHub {
    pub(super) fn new(limit: u32, tx: mpsc::Sender<ProbeTask>) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            tx,
            limit,
        }
    }

    pub(super) fn enqueue(&self, hit: IpAddr, port: u16, ctx: &ProbeContext) {
        let mut seen = lock(&self.seen);
        seen.insert(hit);
        for ip in neighbor_candidates(hit, self.limit) {
            if ctx.should_stop() {
                break;
            }
            if seen.insert(ip) && self.tx.try_send(ProbeTask { ip, port }).is_err() {
                seen.remove(&ip);
            }
        }
    }
}

pub(super) fn neighbor_candidates(hit: IpAddr, limit: u32) -> Vec<IpAddr> {
    let IpAddr::V4(v4) = hit else {
        return Vec::new();
    };
    let [a, b, c, d] = v4.octets();
    let last = i64::from(d);
    let mut out = Vec::new();
    for dist in 1..=254i64 {
        if out.len() >= limit as usize {
            break;
        }
        for offset in [last - dist, last + dist] {
            if out.len() >= limit as usize {
                break;
            }
            if (1..=254).contains(&offset) {
                out.push(IpAddr::V4(Ipv4Addr::new(a, b, c, offset as u8)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;

    #[test]
    fn neighbor_candidates_walk_outward_and_respect_bounds() {
        let hit: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(
            neighbor_candidates(hit, 1),
            vec!["203.0.113.9".parse::<IpAddr>().unwrap(),],
            "limit counts candidates, not distances"
        );
        assert_eq!(
            neighbor_candidates(hit, 2),
            vec![
                "203.0.113.9".parse::<IpAddr>().unwrap(),
                "203.0.113.11".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(
            neighbor_candidates(hit, 3),
            vec![
                "203.0.113.9".parse::<IpAddr>().unwrap(),
                "203.0.113.11".parse::<IpAddr>().unwrap(),
                "203.0.113.8".parse::<IpAddr>().unwrap(),
            ]
        );
        let edge: IpAddr = "203.0.113.1".parse().unwrap();
        assert_eq!(
            neighbor_candidates(edge, 2),
            vec![
                "203.0.113.2".parse::<IpAddr>().unwrap(),
                "203.0.113.3".parse::<IpAddr>().unwrap(),
            ],
            "0 is skipped, outward walk continues with +dist"
        );
        let top: IpAddr = "203.0.113.254".parse().unwrap();
        assert_eq!(
            neighbor_candidates(top, 2),
            vec![
                "203.0.113.253".parse::<IpAddr>().unwrap(),
                "203.0.113.252".parse::<IpAddr>().unwrap(),
            ],
            "255 is skipped"
        );
        assert!(neighbor_candidates(hit, 0).is_empty());
        assert!(
            neighbor_candidates("2606:4700::1".parse().unwrap(), 8).is_empty(),
            "only IPv4 hits produce neighbors"
        );
        let all = neighbor_candidates(hit, 64);
        assert_eq!(
            all.len(),
            64,
            "the candidate list is capped at the limit, not the distance"
        );
        assert_eq!(
            all.iter().collect::<HashSet<_>>().len(),
            64,
            "candidates must be unique"
        );
        assert!(
            all.iter()
                .all(|ip| !ip.to_string().ends_with(".0") && !ip.to_string().ends_with(".255")),
            "network and broadcast must never appear"
        );
        let full = neighbor_candidates(hit, 300);
        assert_eq!(
            full.len(),
            253,
            "a mid-range /24 has 254 usable hosts minus the hit itself"
        );
        let limited = neighbor_candidates(top, 300);
        assert_eq!(
            limited.iter().collect::<HashSet<_>>().len(),
            limited.len(),
            "even at the /24 edge the walk must not repeat or overflow"
        );
    }
}
