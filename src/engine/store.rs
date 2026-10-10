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

pub(super) type PosIndex = Arc<Mutex<HashMap<(Ipv4Addr, u16), usize>>>;

pub(super) fn update_verdict_phase2(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    p2v: Phase2Verdict,
    colo: Option<String>,
    pos_index: &PosIndex,
) -> Option<Verdict> {
    let mut results = lock(store);
    // Fast path: O(1) index hit, validated against the row (a lazy
    // `results()` sort reorders the Vec and stale entries fail validation).
    let pos = {
        let index = lock(pos_index);
        index.get(&(ip, port)).copied().filter(|&pos| {
            results
                .get(pos)
                .is_some_and(|v| v.ip == IpAddr::V4(ip) && v.port == port)
        })
    };
    let pos = match pos {
        Some(pos) => pos,
        None => {
            // Miss (sort-stale or first touch): linear fallback, then lazily
            // repair just this entry. Repeated misses converge without ever
            // paying a full-map rebuild per op.
            let found = results
                .iter()
                .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)?;
            lock(pos_index).insert((ip, port), found);
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
/// check-and-remove closes the interleave). Removal is swap-remove + patch:
/// O(1), and the position index stays valid (only the moved row is re-keyed).
/// Lock order is store-then-index everywhere; never invert it.
pub(super) fn remove_verdict_unless_passed(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    pos_index: &PosIndex,
) {
    let mut results = lock(store);
    // Fast path via the index; fall back to a linear scan when sort-stale.
    let pos = lock(pos_index)
        .get(&(ip, port))
        .copied()
        .filter(|&pos| {
            results
                .get(pos)
                .is_some_and(|v| v.ip == IpAddr::V4(ip) && v.port == port)
        })
        .or_else(|| {
            results
                .iter()
                .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)
        });
    let Some(pos) = pos else {
        return;
    };
    if results[pos].phase2.as_ref().is_some_and(|p| p.passed) {
        // Lazily repair the index entry for the surviving pass so future
        // hits stay O(1).
        lock(pos_index).insert((ip, port), pos);
        return;
    }
    results.swap_remove(pos);
    let mut index = lock(pos_index);
    index.remove(&(ip, port));
    // Patch the row swapped into the hole (if any). V6 rows are never
    // indexed (phase-2 is V4-only), so only re-key V4 occupants.
    if let Some(moved) = results.get(pos)
        && let IpAddr::V4(moved_ip) = moved.ip
    {
        index.insert((moved_ip, moved.port), pos);
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
            spec_index: None,
            verifier: None,
            speed_test_mb_s: None,
        });
        v
    }

    #[test]
    fn rejected_colo_removal_keeps_a_stored_pass() {
        let store: Store = Arc::new(Mutex::new(vec![passing("1.2.3.4", 443)]));
        let pos_index: PosIndex = Arc::new(Mutex::new(HashMap::new()));
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
        let pos_index: PosIndex = Arc::new(Mutex::new(HashMap::new()));
        remove_verdict_unless_passed(&store, "1.2.3.4".parse().unwrap(), 443, &pos_index);
        assert!(
            lock(&store).is_empty(),
            "all-rejected candidates must still be removed"
        );
    }

    fn p2v(passed: bool) -> Phase2Verdict {
        Phase2Verdict {
            passed,
            fragment: FragmentPreset::Off,
            sni: String::new(),
            latency_ms: passed.then_some(7),
            error: None,
            config_index: Some(0),
            spec_index: None,
            verifier: None,
            speed_test_mb_s: None,
        }
    }

    fn check_index(store: &Store, pos_index: &PosIndex) {
        let results = lock(store);
        let index = lock(pos_index);
        for (k, &pos) in index.iter() {
            let row = results
                .get(pos)
                .unwrap_or_else(|| panic!("index points out of bounds: {k:?} -> {pos}"));
            assert_eq!(
                (row.ip, row.port),
                (IpAddr::V4(k.0), k.1),
                "index entry must match the row it points at"
            );
        }
        // Every V4 row present in the store must resolve through the index.
        for (i, v) in results.iter().enumerate() {
            if let IpAddr::V4(ip) = v.ip {
                assert_eq!(
                    index.get(&(ip, v.port)),
                    Some(&i),
                    "every V4 row must be indexed: {ip}:{}",
                    v.port
                );
            }
        }
    }

    #[test]
    fn swap_remove_patches_the_index_without_rebuild() {
        let store: Store = Arc::new(Mutex::new(vec![
            verdict("1.2.3.4", 443),
            verdict("1.2.3.5", 443),
            verdict("1.2.3.6", 443),
        ]));
        let pos_index: PosIndex = Arc::new(Mutex::new(HashMap::from(
            [
                ("1.2.3.4".parse().unwrap(), 443, 0),
                ("1.2.3.5".parse().unwrap(), 443, 1),
                ("1.2.3.6".parse().unwrap(), 443, 2),
            ]
            .map(|(ip, port, pos)| ((ip, port), pos)),
        )));
        // Remove the head: the tail swaps into slot 0 and must be re-keyed.
        remove_verdict_unless_passed(&store, "1.2.3.4".parse().unwrap(), 443, &pos_index);
        assert_eq!(lock(&store).len(), 2);
        check_index(&store, &pos_index);
        // The survivor still updates through the O(1) index path.
        let updated = update_verdict_phase2(
            &store,
            "1.2.3.6".parse().unwrap(),
            443,
            p2v(true),
            None,
            &pos_index,
        )
        .expect("indexed survivor must update");
        assert!(updated.phase2.as_ref().is_some_and(|p| p.passed));
        check_index(&store, &pos_index);
    }

    #[test]
    fn update_repairs_a_sort_stale_index_entry() {
        let store: Store = Arc::new(Mutex::new(vec![
            verdict("1.2.3.4", 443),
            verdict("1.2.3.5", 443),
        ]));
        let pos_index: PosIndex = Arc::new(Mutex::new(HashMap::from([
            (("1.2.3.4".parse().unwrap(), 443), 1),
            (("1.2.3.5".parse().unwrap(), 443), 0),
        ])));
        // Both entries are stale (swapped): the linear fallback must still
        // find the row and lazily repair its entry.
        let updated = update_verdict_phase2(
            &store,
            "1.2.3.4".parse().unwrap(),
            443,
            p2v(false),
            None,
            &pos_index,
        )
        .expect("stale index must fall back to the row");
        assert!(!updated.phase2.as_ref().unwrap().passed);
        assert_eq!(
            lock(&pos_index).get(&("1.2.3.4".parse().unwrap(), 443)),
            Some(&0),
            "the touched entry must be repaired"
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
