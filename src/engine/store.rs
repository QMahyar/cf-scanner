use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::api::types::{Phase2Verdict, Verdict};

pub(super) type Store = Arc<Mutex<Vec<Verdict>>>;

pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(super) fn merge_sorted(store: &Store, dirty: &AtomicBool, batch: Vec<Verdict>) {
    if batch.is_empty() {
        return;
    }
    let mut results = lock(store);
    results.extend(batch);
    dirty.store(true, Ordering::Release);
}

pub(super) type PosIndex = Arc<Mutex<Arc<HashMap<(Ipv4Addr, u16), usize>>>>;

pub(super) fn update_verdict_phase2(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    p2v: Phase2Verdict,
    colo: Option<String>,
    pos_index: &PosIndex,
) -> Option<Verdict> {
    let mut results = lock(store);
    let indexed = {
        let index = lock(pos_index).clone();
        index.get(&(ip, port)).copied().filter(|&pos| {
            results
                .get(pos)
                .is_some_and(|v| v.ip == IpAddr::V4(ip) && v.port == port)
        })
    };
    let pos = match indexed {
        Some(pos) => pos,
        None => {
            let found = results
                .iter()
                .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)?;
            let mut fresh: HashMap<(Ipv4Addr, u16), usize> = HashMap::with_capacity(results.len());
            for (i, v) in results.iter().enumerate() {
                if let IpAddr::V4(ip4) = v.ip {
                    fresh.entry((ip4, v.port)).or_insert(i);
                }
            }
            *lock(pos_index) = Arc::new(fresh);
            found
        }
    };
    if results[pos].phase2.as_ref().is_some_and(|p| p.passed) {
        return None;
    }
    results[pos].phase2 = Some(p2v);
    if colo.is_some() {
        results[pos].colo = colo;
    }
    Some(results[pos].clone())
}

/// Annotates one stored verdict with ASN/ISP data. Returns false when the
/// endpoint is absent (already filtered) so callers can skip it.
pub(super) fn set_asn(store: &Store, ip: IpAddr, port: u16, asn: u32, isp: &str) -> bool {
    let mut results = lock(store);
    if let Some(v) = results.iter_mut().find(|v| v.ip == ip && v.port == port) {
        v.asn = Some(asn);
        v.isp = Some(isp.to_owned());
        true
    } else {
        false
    }
}

/// Drops a stored verdict, unless it already holds a passing phase-2 result.
/// A rejected-colo latecomer must never delete a kept-colo pass that a racing
/// worker stored first (both ops are atomic under the store lock, so the
/// check-and-remove closes the interleave).
pub(super) fn remove_verdict_unless_passed(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    pos_index: &PosIndex,
) {
    let mut results = lock(store);
    if let Some(pos) = results
        .iter()
        .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)
    {
        if results[pos].phase2.as_ref().is_some_and(|p| p.passed) {
            return;
        }
        results.remove(pos);
        *lock(pos_index) = Arc::new(HashMap::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{FragmentPreset, Phase2Verdict};

    fn verdict(ip: &str, port: u16) -> Verdict {
        Verdict {
            ip: ip.parse().unwrap(),
            port,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        }
    }

    fn passing(ip: &str, port: u16) -> Verdict {
        let mut v = verdict(ip, port);
        v.phase2 = Some(Phase2Verdict {
            passed: true,
            fragment: FragmentPreset::Off,
            sni: String::new(),
            latency_ms: Some(7),
            error: None,
            config_index: Some(0),
            verifier: None,
            speed_test_mbps: None,
        });
        v
    }

    #[test]
    fn rejected_colo_removal_keeps_a_stored_pass() {
        let store: Store = Arc::new(Mutex::new(vec![passing("1.2.3.4", 443)]));
        let pos_index: PosIndex = Arc::new(Mutex::new(Arc::new(HashMap::new())));
        remove_verdict_unless_passed(&store, "1.2.3.4".parse().unwrap(), 443, &pos_index);
        assert_eq!(
            lock(&store).len(),
            1,
            "a kept-colo pass must survive a racing rejected-colo removal"
        );
        assert!(
            lock(&store)[0].phase2.as_ref().is_some_and(|p| p.passed),
            "the surviving row must keep its passing verdict"
        );
    }

    #[test]
    fn rejected_colo_removal_drops_an_unverified_row() {
        let store: Store = Arc::new(Mutex::new(vec![verdict("1.2.3.4", 443)]));
        let pos_index: PosIndex = Arc::new(Mutex::new(Arc::new(HashMap::new())));
        remove_verdict_unless_passed(&store, "1.2.3.4".parse().unwrap(), 443, &pos_index);
        assert!(
            lock(&store).is_empty(),
            "all-rejected candidates must still be removed"
        );
    }

    #[test]
    fn set_asn_annotates_only_the_matching_endpoint() {
        let store: Store = Arc::new(Mutex::new(vec![
            verdict("1.2.3.4", 443),
            verdict("1.2.3.4", 8443),
        ]));
        assert!(set_asn(
            &store,
            "1.2.3.4".parse().unwrap(),
            443,
            13335,
            "CLOUDFLARENET"
        ));
        assert!(!set_asn(&store, "9.9.9.9".parse().unwrap(), 443, 1, "x"));
        let results = lock(&store);
        assert_eq!(results[0].asn, Some(13335));
        assert_eq!(results[0].isp.as_deref(), Some("CLOUDFLARENET"));
        assert_eq!(results[1].asn, None);
    }
}
