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

/// Drops a stored verdict and invalidates the cached position index.
pub(super) fn remove_verdict(store: &Store, ip: Ipv4Addr, port: u16, pos_index: &PosIndex) {
    let mut results = lock(store);
    if let Some(pos) = results
        .iter()
        .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)
    {
        results.remove(pos);
        *lock(pos_index) = Arc::new(HashMap::new());
    }
}
