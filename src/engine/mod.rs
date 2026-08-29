//! The one in-process scan engine every client drives: pool planning, probe
//! fan-out, stop conditions, event stream and the last-scan results store.
//! Used by the HTTP server, wizard, and CLI.

mod cdn;
mod phase2;
mod plan;
mod warp;

pub use plan::{PlanItem, SplitMix64, plan};

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::{broadcast, watch};

use crate::api::types::{
    Mode, ScanConfig, ScanEvent, ScanProgress, ScanSummary, StopCondition, Verdict,
};
use crate::configs::{RealSubFetch, SubFetch};
use crate::geo::Geo;
use crate::probe::Transport;
use crate::ranges;
use crate::verify::{HybridTunnelProbe, TunnelProbe, XrayTunnelProbe};

/// Progress events: every 50 probes up to 10k totals, then every 500, so a
/// Full scan's event stream stays bounded.
const PROGRESS_EVERY: u64 = 50;
const PROGRESS_EVERY_COARSE: u64 = 500;
const PROGRESS_COARSE_TOTAL: u64 = 10_000;

fn progress_cadence(total: u64) -> u64 {
    if total > PROGRESS_COARSE_TOTAL {
        PROGRESS_EVERY_COARSE
    } else {
        PROGRESS_EVERY
    }
}

type Store = Arc<Mutex<Vec<Verdict>>>;

/// Reservation failure: the single run slot is already taken.
#[derive(Debug, thiserror::Error)]
#[error("a scan is already running")]
pub struct AlreadyRunning;

pub struct ScanController {
    transport: Arc<dyn Transport>,
    warp_transport: Arc<dyn Transport>,
    warp_cache: Option<Arc<crate::warp::SocketCache>>,
    sub_fetch: Arc<dyn SubFetch>,
    tunnel_probe: Arc<dyn TunnelProbe>,
    geo: Arc<Geo>,
    events: broadcast::Sender<ScanEvent>,
    store: Store,
    store_dirty: Arc<AtomicBool>,
    summary: Mutex<Option<ScanSummary>>,
    cancel_tx: Mutex<Option<watch::Sender<bool>>>,
    running: Mutex<bool>,
}

impl ScanController {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        let warp_cache = Arc::new(crate::warp::SocketCache::default());
        let warp_transport = Arc::new(
            crate::warp::WarpTransport::with_cache(warp_cache.clone())
                .expect("WARP server key must decode"),
        );
        let mut ctrl = Self::with_transports(transport, warp_transport);
        ctrl.warp_cache = Some(warp_cache);
        ctrl
    }

    /// One controller serving both modes (the server's case): CDN probes go
    /// through `transport`, WARP through `warp_transport`.
    pub fn with_transports(
        transport: Arc<dyn Transport>,
        warp_transport: Arc<dyn Transport>,
    ) -> Self {
        let (events, _) = broadcast::channel(4096);
        Self {
            transport,
            warp_transport,
            warp_cache: None,
            sub_fetch: Arc::new(RealSubFetch),
            tunnel_probe: Arc::new(HybridTunnelProbe::new(Arc::new(XrayTunnelProbe))),
            geo: Arc::new(Geo::embedded()),
            events,
            store: Arc::new(Mutex::new(Vec::new())),
            store_dirty: Arc::new(AtomicBool::new(false)),
            summary: Mutex::new(None),
            cancel_tx: Mutex::new(None),
            running: Mutex::new(false),
        }
    }

    /// Test seam: injects the subscription fetcher and tunnel probe so
    /// phase-2 runs never touch the network or spawn xray.
    pub fn with_probes(
        transport: Arc<dyn Transport>,
        sub_fetch: Arc<dyn SubFetch>,
        tunnel_probe: Arc<dyn TunnelProbe>,
    ) -> Self {
        let mut controller = Self::with_transports(transport.clone(), transport);
        controller.sub_fetch = sub_fetch;
        controller.tunnel_probe = tunnel_probe;
        controller
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.events.subscribe()
    }

    /// Summary of the last finished scan, if one has run yet.
    pub fn summary(&self) -> Option<ScanSummary> {
        self.summary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Snapshot of the last scan's working endpoints, sorted by latency.
    /// The only legitimate full-snapshot read: prefer [`Self::has_results`]
    /// for emptiness checks, [`Self::for_each_result`] for iteration.
    pub fn results(&self) -> Vec<Verdict> {
        sort_if_dirty(&self.store, &self.store_dirty);
        self.store.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// True once the last scan produced at least one working endpoint.
    pub fn has_results(&self) -> bool {
        sort_if_dirty(&self.store, &self.store_dirty);
        !self
            .store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Iterate sorted results after taking a snapshot under the lock, so the
    /// callback runs without holding the mutex. The snapshot is dropped once
    /// iteration finishes.
    pub fn for_each_result(&self, mut f: impl FnMut(&Verdict)) {
        sort_if_dirty(&self.store, &self.store_dirty);
        let snapshot = {
            let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
            store.clone()
        };
        for v in &snapshot {
            f(v);
        }
    }

    /// Rows that passed phase-2 verification (phase2_only summary semantics).
    fn phase2_passed(&self) -> u64 {
        self.store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|v| v.phase2.as_ref().is_some_and(|p| p.passed))
            .count() as u64
    }

    /// Rows still considered working after a phase-2 pass: candidates that
    /// passed verification plus candidates phase 2 never touched (v6 finds
    /// stay phase-1-only, so they keep counting as working).
    fn working_found(&self) -> u64 {
        self.store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|v| v.phase2.as_ref().is_none_or(|p| p.passed))
            .count() as u64
    }

    /// True while a run is active; the server rejects new scans then.
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Clears the last scan's results. No-op while a run is active so an
    /// in-flight run can never repopulate a store the user just cleared.
    /// The running lock is held across the check AND the clear so a run
    /// starting between them cannot lose its results to a stale reset.
    pub fn reset(&self) {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if *running {
            return;
        }
        self.clear_store();
        drop(running);
    }

    /// Internal reset for run start; bypasses the running guard (the run
    /// itself is the one clearing, not a concurrent caller).
    fn clear_store(&self) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.store_dirty.store(false, Ordering::Relaxed);
        self.summary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    pub fn cancel(&self) {
        if let Some(tx) = self
            .cancel_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = tx.send(true);
        }
    }

    /// The run's cancel signal: one watch channel per run, reused by every
    /// phase, so a cancel fired during phase 1 (or in the gap before phase
    /// 2) is still visible to phase-2 workers and to `finish` — never lost
    /// to a fresh channel install.
    fn cancel_signal(&self) -> watch::Receiver<bool> {
        let mut slot = self.cancel_tx.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = slot.as_ref() {
            return tx.subscribe();
        }
        let (tx, rx) = watch::channel(false);
        *slot = Some(tx);
        rx
    }

    pub async fn run(&self, cfg: ScanConfig) -> Result<ScanSummary> {
        self.run_seeded(cfg, OsRng.next_u64()).await
    }

    /// Runs `cfg` while invoking `on_event` as each event is emitted (the
    /// subscriber attaches before the run starts, so no event is missed).
    /// Errors abort before `Finished` is sent (a `Failed` event is emitted
    /// instead); callers still get them here.
    pub async fn run_streaming(
        self: &Arc<Self>,
        cfg: ScanConfig,
        on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        self.run_streaming_seeded(cfg, OsRng.next_u64(), on_event)
            .await
    }

    /// `run_streaming` with an explicit sampling seed (repro runs).
    pub async fn run_streaming_seeded(
        self: &Arc<Self>,
        cfg: ScanConfig,
        seed: u64,
        on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let rx = self.subscribe();
        let controller = self.clone();
        let handle = tokio::spawn(async move { controller.run_seeded(cfg, seed).await });
        self.drive_run(handle, rx, on_event).await
    }

    /// Streaming variant of [`run_reserved`] for callers that reserved the
    /// slot via [`reserve`](Self::reserve) (the server's start path reserves
    /// synchronously, then spawns this). Running it without a reservation
    /// breaks the one-run-at-a-time invariant.
    pub async fn run_reserved_streaming(
        self: &Arc<Self>,
        cfg: ScanConfig,
        on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let rx = self.subscribe();
        let controller = self.clone();
        let seed = OsRng.next_u64();
        let handle = tokio::spawn(async move { controller.run_reserved(cfg, seed).await });
        self.drive_run(handle, rx, on_event).await
    }

    /// Drives a spawned run to completion, invoking `on_event` for every
    /// broadcast event. Shared by the streaming entry points.
    async fn drive_run(
        self: &Arc<Self>,
        mut handle: tokio::task::JoinHandle<Result<ScanSummary>>,
        mut rx: broadcast::Receiver<ScanEvent>,
        mut on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        // Rows this consumer already saw; every branch records into it so the
        // end-of-run store re-sync only emits rows the consumer truly missed
        // (fast consumers get exactly-once, lagging ones get a deduped tail).
        let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
        loop {
            tokio::select! {
                done = &mut handle => {
                    let result = done?;
                    // The run may have finished with events still buffered;
                    // deliver them so callers never miss the tail. A receiver
                    // that fell behind (Lagged) has dropped events: keep
                    // draining past the gap, then re-emit store rows the
                    // drain never delivered.
                    loop {
                        match rx.try_recv() {
                            Ok(event) => {
                                if let ScanEvent::Result(verdict) = &event {
                                    seen.insert((verdict.ip, verdict.port));
                                }
                                on_event(event);
                            }
                            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                            Err(TryRecvError::Lagged(_)) => continue,
                        }
                    }
                    // Verdicts still in worker-local batches when the
                    // broadcast window overflowed are in the store, not the
                    // stream: re-emit any row the consumer never saw (deduped
                    // by (ip, port)) so a lagging consumer never loses one.
                    self.for_each_result(|v| {
                        if seen.insert((v.ip, v.port)) {
                            on_event(ScanEvent::Result(Box::new(v.clone())));
                        }
                    });
                    return result;
                }
                recv = rx.recv() => match recv {
                    Ok(event @ ScanEvent::Finished(_)) => {
                        on_event(event);
                        // The same tail reconciliation as the handle-done
                        // branch: rows dropped from the broadcast window (and
                        // not covered by an earlier re-sync) must still reach
                        // the consumer exactly once.
                        self.for_each_result(|v| {
                            if seen.insert((v.ip, v.port)) {
                                on_event(ScanEvent::Result(Box::new(v.clone())));
                            }
                        });
                        return handle.await?;
                    }
                    Ok(event) => {
                        if let ScanEvent::Result(verdict) = &event {
                            seen.insert((verdict.ip, verdict.port));
                        }
                        on_event(event);
                    }
                    Err(_) => {
                        // Lagged: the channel dropped missed events. Re-sync
                        // the authoritative store so a slow consumer never
                        // ends up with a silently incomplete stream (the
                        // store is flushed before Finished, so this can only
                        // under-report mid-run verdicts, never over-report).
                        // Duplicate rows are possible after a re-sync;
                        // consumers keyed on (ip, port) dedupe naturally.
                        self.for_each_result(|v| {
                            if seen.insert((v.ip, v.port)) {
                                on_event(ScanEvent::Result(Box::new(v.clone())));
                            }
                        });
                    }
                },
            }
        }
    }

    /// Reserves the single run slot synchronously: the caller can flip the
    /// running state and THEN spawn the run task, so a racing second caller
    /// sees the reservation instead of a false "idle" (the server's start
    /// path depends on this — a check-then-spawn gap let two POSTs through).
    pub fn reserve(&self) -> Result<(), AlreadyRunning> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if *running {
            return Err(AlreadyRunning);
        }
        *running = true;
        Ok(())
    }

    /// At most one run per controller: a second concurrent run is rejected
    /// (surfacing as a `Failed` event) so two runs can never race the shared
    /// store or the cancel slot.
    pub async fn run_seeded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        self.reserve().map_err(|err| {
            self.emit(ScanEvent::Failed(crate::api::types::FailedPayload {
                reason: format!("{err:#}"),
            }));
            anyhow!("{err}")
        })?;
        self.run_reserved(cfg, seed).await
    }

    /// Runs without re-checking the slot; the caller must have reserved it
    /// via [`reserve`](Self::reserve) (or be inside [`run_seeded`], which
    /// reserves first).
    async fn run_reserved(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        // RAII: clears the busy flag (and the cancel slot) even if the run
        // panics, so one bad run can never brick the controller for the rest
        // of the process's life. Created BEFORE the body so a panic mid-run
        // still unwinds through it.
        struct ResetGuard<'a> {
            running: &'a Mutex<bool>,
            cancel_tx: &'a Mutex<Option<watch::Sender<bool>>>,
        }
        impl Drop for ResetGuard<'_> {
            fn drop(&mut self) {
                self.cancel_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                *self.running.lock().unwrap_or_else(|e| e.into_inner()) = false;
            }
        }
        let _guard = ResetGuard {
            running: &self.running,
            cancel_tx: &self.cancel_tx,
        };
        let result = self.run_seeded_unguarded(cfg, seed).await;
        if let Err(err) = &result {
            // The chain can carry imported config material (URLs, paths);
            // sanitize before it reaches logs or the wire.
            let msg = crate::configs::sanitize_error_text(&format!("{err:#}"));
            self.emit(ScanEvent::Failed(crate::api::types::FailedPayload {
                reason: msg,
            }));
        }
        result
    }

    async fn run_seeded_unguarded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let pool = ranges::effective_pool(&cfg.custom_cidrs, &cfg.exclude, cfg.include_v6)?;
        self.run_seeded_with_pool(cfg, seed, pool).await
    }

    /// Scan over an explicit pool; tests use this to stay off the filesystem
    /// and the real Cloudflare ranges.
    async fn run_seeded_with_pool(
        &self,
        cfg: ScanConfig,
        seed: u64,
        pool: ranges::CidrPool,
    ) -> Result<ScanSummary> {
        cfg.validate()?;
        if cfg.mode == Mode::Warp {
            return self.run_warp(cfg, seed).await;
        }
        self.run_cdn(cfg, seed, pool).await
    }

    fn finish(&self, started: Instant, scanned: u64, found: u64) -> ScanSummary {
        let cancel_tx = self
            .cancel_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        // A live cancel slot holds the watch value: `true` once `cancel()`
        // fired, so the summary can distinguish stop-from-cancel.
        let cancelled = cancel_tx
            .as_ref()
            .map(|tx| *tx.subscribe().borrow())
            .unwrap_or(false);
        let summary = ScanSummary {
            scanned,
            found,
            duration_ms: started.elapsed().as_millis() as u64,
            cancelled,
        };
        *self.summary.lock().unwrap_or_else(|e| e.into_inner()) = Some(summary.clone());
        self.emit(ScanEvent::Finished(summary.clone()));
        summary
    }

    fn emit(&self, event: ScanEvent) {
        let _ = self.events.send(event);
    }
}

/// Concrete hosts a plan item yields, streamed lazily so a Full scan never
/// materializes an entire `Every` range. `Sample` rolls fresh random hosts
/// with a per-port seed so multi-port scans don't repeat the same host.
/// v6 host spaces need u128 sampling (see `SplitMix64::below_u128`).
enum PlanHosts<I1, I2, I3> {
    Every(I1),
    Sample(I2),
    Hosts(I3),
}

impl<I1, I2, I3> Iterator for PlanHosts<I1, I2, I3>
where
    I1: Iterator<Item = IpAddr>,
    I2: Iterator<Item = IpAddr>,
    I3: Iterator<Item = IpAddr>,
{
    type Item = IpAddr;
    fn next(&mut self) -> Option<IpAddr> {
        match self {
            Self::Every(i) => i.next(),
            Self::Sample(i) => i.next(),
            Self::Hosts(i) => i.next(),
        }
    }
}

fn plan_hosts_iter<'a>(
    item: &'a PlanItem,
    rng: &'a mut SplitMix64,
) -> impl Iterator<Item = IpAddr> + 'a {
    match item {
        PlanItem::Every { cidr } => {
            PlanHosts::Every((0..cidr.host_count()).map(move |i| cidr.host(i)))
        }
        PlanItem::Sample { cidr, count } => {
            let count = (*count as u128).min(cidr.host_count());
            // Dense v4 blocks (/24 and tighter) skip network and broadcast
            // addresses; every other block samples its whole host space.
            let (draw_max, skip_net_bcast) = if cidr.addr.is_ipv4() && cidr.prefix >= 24 {
                (cidr.host_count().saturating_sub(2), true)
            } else {
                (cidr.host_count(), false)
            };
            let mut seen = std::collections::HashSet::new();
            let mut emitted = 0u128;
            PlanHosts::Sample(std::iter::from_fn(move || {
                // Draws are deduped per block: sampling with replacement
                // produced duplicate verdicts and inflated `found` counts.
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
        PlanItem::Hosts { cidr, offsets } => {
            PlanHosts::Hosts(offsets.iter().map(move |&o| cidr.host(o)))
        }
    }
}

fn plan_probe_count(plan: &[PlanItem], ports: &[super::api::types::Port]) -> u64 {
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

/// Verdicts a worker accumulates before flushing to the shared store, so the
/// store lock is taken once per batch instead of once per verdict.
const BATCH_FLUSH: usize = 256;

/// Claims the cadence threshold crossed by `observed` for exactly one of the
/// concurrent workers that saw it: the CAS on the highest claimed threshold
/// makes every milestone single-winner and strictly increasing, so progress
/// never duplicates or regresses no matter how workers interleave.
fn claim_milestone(last: &AtomicU64, observed: u64, cadence: u64) -> bool {
    let threshold = observed / cadence;
    let claimed = last.load(Ordering::Relaxed);
    threshold > claimed
        && last
            .compare_exchange(claimed, threshold, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// Resolves once the run's cancel flag flips; parks forever if the sender
/// dropped without a flip (the reset guard only clears it after `finish`).
async fn cancelled_signal(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Shared state for one probe phase: stop conditions, counters, and the
/// event/store handles every worker needs. `Arc`-shared between the producer
/// and all workers of a phase.
struct ProbeContext {
    cancel: watch::Receiver<bool>,
    stop: StopCondition,
    scanned: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    last_milestone: AtomicU64,
    cadence: u64,
    total: u64,
    store: Store,
    dirty: Arc<AtomicBool>,
    events: broadcast::Sender<ScanEvent>,
    geo: Arc<Geo>,
}

impl ProbeContext {
    /// Pre-probe stop check: cancel, found reached, or hard cap reached.
    /// Overshoot beyond the stop condition is bounded by `concurrency`
    /// (each worker holds at most one in-flight probe past the check).
    fn should_stop(&self) -> bool {
        *self.cancel.borrow()
            || self.found.load(Ordering::Relaxed) >= u64::from(self.stop.found)
            || self
                .stop
                .cap
                .is_some_and(|cap| self.scanned.load(Ordering::Relaxed) >= u64::from(cap))
    }

    async fn cancelled(&self) {
        cancelled_signal(self.cancel.clone()).await;
    }

    /// Single-winner progress gate: true only for the worker that claims the
    /// next cadence threshold, so exactly one Progress event fires per
    /// milestone regardless of how many workers raced past it.
    fn milestone_due(&self, observed: u64) -> bool {
        claim_milestone(&self.last_milestone, observed, self.cadence)
    }

    fn progress(&self, scanned: u64, found: u64) {
        let _ = self.events.send(ScanEvent::Progress(ScanProgress {
            scanned,
            found,
            total: Some(self.total),
        }));
    }
}

fn merge_sorted(store: &Store, dirty: &AtomicBool, batch: Vec<Verdict>) {
    if batch.is_empty() {
        return;
    }
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    results.extend(batch);
    dirty.store(true, Ordering::Release);
}

fn sort_if_dirty(store: &Store, dirty: &AtomicBool) {
    if !dirty.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    results.sort_unstable_by(|a, b| {
        a.latency_ms
            .cmp(&b.latency_ms)
            .then_with(|| a.ip.cmp(&b.ip))
            .then_with(|| a.port.cmp(&b.port))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Port, ScanConfig, ScanTarget, StopCondition};
    use crate::probe::FakeTransport;
    use std::time::Duration;

    async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + timeout;
        while !pred() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition not met in {timeout:?}"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[test]
    fn milestone_claims_are_single_winner_and_monotonic() {
        let last = AtomicU64::new(0);
        let solo: Vec<u64> = (1..=16000u64)
            .filter(|v| claim_milestone(&last, *v, 100))
            .collect();
        assert_eq!(
            solo.len(),
            160,
            "sequential runs claim every threshold once"
        );

        let last = Arc::new(AtomicU64::new(0));
        let counter = Arc::new(AtomicU64::new(0));
        let winners = Arc::new(Mutex::new(Vec::<u64>::new()));
        std::thread::scope(|s| {
            for _ in 0..8 {
                let last = &last;
                let counter = &counter;
                let winners = &winners;
                s.spawn(move || {
                    for _ in 0..2000 {
                        let observed = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if claim_milestone(last, observed, 100) {
                            winners
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(observed);
                        }
                    }
                });
            }
        });
        let claimed = winners.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // Push order reflects thread scheduling, not claim order, so the
        // assertions must be set-shaped: the CAS guarantees one winner per
        // threshold and increasing claims, not ordered Vec appends.
        let mut seen = claimed.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), claimed.len(), "observed values must be unique");
        let mut thresholds: Vec<u64> = claimed.iter().map(|v| v / 100).collect();
        thresholds.sort_unstable();
        thresholds.dedup();
        assert_eq!(thresholds.len(), claimed.len(), "one winner per threshold");
        assert!(
            thresholds.iter().all(|t| (1..=160).contains(t)),
            "claims must land on crossed thresholds: {thresholds:?}"
        );
    }

    pub(crate) fn ok_cfg(found: u32, cap: Option<u32>) -> ScanConfig {
        // Serial probing keeps stop/cap semantics exact in tests.
        ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Count(8),
            stop: StopCondition { found, cap },
            ports: vec![Port::new(443)],
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

    /// Runs a scan over a scripted /29 pool: deterministic hosts
    /// 203.0.113.0-203.0.113.7, independent of the filesystem and bundled ranges.
    pub(crate) async fn run_local(
        c: &Arc<ScanController>,
        cfg: ScanConfig,
        seed: u64,
    ) -> Result<ScanSummary> {
        let pool = ranges::CidrPool::parse("203.0.113.0/29")?;
        c.run_seeded_with_pool(cfg, seed, pool).await
    }

    pub(crate) fn controller(
        t: Arc<dyn Transport>,
    ) -> (
        Arc<ScanController>,
        tokio::sync::broadcast::Receiver<ScanEvent>,
    ) {
        let controller = Arc::new(ScanController::new(t));
        let rx = controller.subscribe();
        (controller, rx)
    }

    #[tokio::test]
    async fn run_streaming_delivers_every_event_and_summary() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let c = Arc::new(ScanController::new(Arc::new(t)));
        // custom_cidrs keeps the scan on the scripted /29, off the filesystem.
        let mut cfg = ok_cfg(2, None);
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
        let mut events = vec![];
        let summary = c.run_streaming(cfg, |e| events.push(e)).await.unwrap();
        assert_eq!(summary.found, 2);
        let results = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Result(_)))
            .count();
        assert_eq!(
            results, 2,
            "every verdict must arrive exactly once: {events:?}"
        );
    }

    #[tokio::test]
    async fn run_streaming_reports_errors_without_finished() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        let mut cfg = ok_cfg(1, None);
        cfg.ports = vec![Port::new(0)]; // validation rejects the run before any event
        let mut events = vec![];
        let err = c.run_streaming(cfg, |e| events.push(e)).await.unwrap_err();
        assert!(err.to_string().contains("out of range"));
        // The run surfaced as a Failed event instead of Finished.
        assert!(!events.is_empty(), "the failure must reach clients");
        assert!(!events.iter().any(|e| matches!(e, ScanEvent::Finished(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Failed(_))));
    }

    #[tokio::test]
    async fn concurrent_runs_are_rejected_and_failed_event_is_emitted() {
        // Every /29 host probes slowly so the run is provably alive when the
        // second run is attempted (the count-sampled plan may draw any host).
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 150);
        }
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut events = c.subscribe();
        let mut cfg = ok_cfg(8, None);
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
        let first = tokio::spawn({
            let c = c.clone();
            let cfg = cfg.clone();
            async move { c.run(cfg).await.unwrap() }
        });
        wait_until(Duration::from_secs(2), || c.is_running()).await;
        assert!(c.is_running());

        let err = c.run(cfg.clone()).await.unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");

        // The rejected run still surfaces to UI/CLI clients as a Failed event
        // (drain past the first run's Progress events).
        let event = loop {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if matches!(event, ScanEvent::Failed(_)) {
                break event;
            }
        };
        let ScanEvent::Failed(payload) = event else {
            unreachable!("loop only breaks on Failed")
        };
        assert!(
            payload.reason.contains("already running"),
            "{}",
            payload.reason
        );

        let summary = first.await.unwrap();
        assert_eq!(summary.found, 8);
        assert!(!c.is_running());

        // After the first run finishes, a new run is accepted again.
        let again = c.run(cfg).await.unwrap();
        assert_eq!(again.found, 8);
    }

    #[tokio::test]
    async fn reset_while_running_is_a_noop() {
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 150);
        }
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut cfg = ok_cfg(8, None);
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
        let first = tokio::spawn({
            let c = c.clone();
            let cfg = cfg.clone();
            async move { c.run(cfg).await.unwrap() }
        });
        wait_until(Duration::from_secs(2), || c.is_running()).await;
        c.reset();
        let summary = first.await.unwrap();
        assert_eq!(summary.found, 8);
        assert_eq!(c.results().len(), 8, "reset must not clear an active run");
    }

    #[tokio::test]
    async fn empty_pool_finishes_with_zero_summary() {
        // A pool emptied by exclusions yields zero probes: the run must end
        // cleanly with a 0/0 summary and no probes (no fake scripting needed).
        let (c, _) = controller(Arc::new(FakeTransport::new()));
        let pool = ranges::CidrPool::parse("203.0.113.0/29")
            .unwrap()
            .excluding(&[ranges::parse_cidr("203.0.113.0/29").unwrap()]);
        let summary = c
            .run_seeded_with_pool(ok_cfg(1, None), 1, pool)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 0);
        assert_eq!(summary.found, 0);
        assert!(!summary.cancelled);
    }

    #[tokio::test]
    async fn late_subscribers_see_complete_results() {
        // The store is the authoritative snapshot: whoever subscribes whenever
        // must end up with the same found set as the summary, even if they
        // missed every live event (the store is flushed before Finished).
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10)
            .ok("203.0.113.3".parse().unwrap(), 443, 30);
        let (c, mut rx) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(3, None), 1).await.unwrap();
        let results = c.results();
        assert_eq!(summary.found as usize, results.len());
        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(matches!(events.last(), Some(ScanEvent::Finished(_))));
        // Results must be latency-sorted in the store.
        let lats: Vec<u32> = results.iter().filter_map(|v| v.latency_ms).collect();
        assert!(lats.windows(2).all(|w| w[0] <= w[1]), "{lats:?}");
    }

    #[test]
    fn sampling_skips_network_and_broadcast_for_dense_v4_blocks() {
        let mut rng = SplitMix64::new(1);
        // /25: network 203.0.113.0, broadcast 203.0.113.127; a count beyond the
        // usable space must draw every usable host and neither edge.
        let item = PlanItem::Sample {
            cidr: ranges::parse_cidr("203.0.113.0/25").unwrap(),
            count: 200,
        };
        let hosts: Vec<IpAddr> = plan_hosts_iter(&item, &mut rng).collect();
        assert_eq!(hosts.len(), 126, "all usable /25 hosts must be drawn");
        assert!(!hosts.contains(&"203.0.113.0".parse::<IpAddr>().unwrap()));
        assert!(!hosts.contains(&"203.0.113.127".parse::<IpAddr>().unwrap()));

        // /24 keeps its existing 254-usable-host behavior.
        let item = PlanItem::Sample {
            cidr: ranges::parse_cidr("203.0.113.0/24").unwrap(),
            count: 300,
        };
        let hosts: Vec<IpAddr> = plan_hosts_iter(&item, &mut rng).collect();
        assert_eq!(hosts.len(), 254);

        // /31 and /32 have no usable host left once both edges are skipped.
        for dense in ["203.0.113.0/31", "203.0.113.0/32"] {
            let item = PlanItem::Sample {
                cidr: ranges::parse_cidr(dense).unwrap(),
                count: 4,
            };
            assert!(
                plan_hosts_iter(&item, &mut rng).next().is_none(),
                "{dense} must yield no hosts"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_streaming_recovers_verdicts_an_overflowing_consumer_dropped() {
        // A /22 (1024 hosts) emits more events than the 1024-slot broadcast
        // window. The consumer parks on its first event until the scan
        // itself has finished, so the receiver provably falls behind and
        // the window drops messages before the end-of-run drain: every
        // verdict must still arrive (store re-sync), each at least once.
        let t = FakeTransport::new();
        for i in 0..1024u32 {
            t.insert(
                format!("203.0.{}.{}", 112 + i / 256, i % 256)
                    .parse()
                    .unwrap(),
                443,
                Ok(i % 100),
            );
        }
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut cfg = ok_cfg(1024, None);
        cfg.custom_cidrs = vec!["203.0.112.0/22".to_owned()];
        cfg.target = ScanTarget::Count(1024 + 100);
        cfg.concurrency = 500;

        let (park_tx, park_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let park_rx = Arc::new(std::sync::Mutex::new(park_rx));
        let handle = tokio::spawn({
            let c = c.clone();
            let cfg = cfg.clone();
            let park_rx = park_rx.clone();
            async move {
                let mut parked = false;
                let events: Arc<Mutex<Vec<ScanEvent>>> = Arc::new(Mutex::new(Vec::new()));
                let events_c = events.clone();
                let summary = c
                    .run_streaming(cfg, move |e| {
                        if !parked {
                            parked = true;
                            let rx = park_rx.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = rx.recv();
                        }
                        events_c.lock().unwrap_or_else(|e| e.into_inner()).push(e);
                    })
                    .await
                    .unwrap();
                let events = Arc::try_unwrap(events).ok().unwrap().into_inner().unwrap();
                (summary, events)
            }
        });
        wait_until(Duration::from_secs(2), || !c.is_running()).await;
        // The scan finished (store fully flushed, Finished emitted); release
        // the parked consumer and let the end-of-run drain + store re-sync run.
        let _ = park_tx.send(());
        let (summary, events) = handle.await.unwrap();
        assert_eq!(summary.found, 1024);
        let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
        for e in &events {
            if let ScanEvent::Result(v) = e {
                seen.insert((v.ip, v.port));
            }
        }
        assert_eq!(
            seen.len(),
            1024,
            "every verdict must arrive at least once ({} unique of 1024)",
            seen.len()
        );
        assert!(
            events.iter().any(|e| matches!(e, ScanEvent::Finished(_))),
            "the terminal event must arrive too"
        );
    }

    #[test]
    fn store_lazy_sort_orders_by_latency_then_ip_port() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        let v1 = Verdict {
            ip: "203.0.113.3".parse().unwrap(),
            port: 443,
            latency_ms: Some(50),
            country: None,
            colo: None,
            phase2: None,
        };
        let v2 = Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: None,
        };
        let v3 = Verdict {
            ip: "203.0.113.2".parse().unwrap(),
            port: 80,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: None,
        };
        merge_sorted(
            &c.store,
            &c.store_dirty,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );
        let results = c.results();
        assert_eq!(results.len(), 3);
        // Sorted by latency, then ip, then port: 10@203.0.113.1:443, 10@203.0.113.2:80, 50@203.0.113.3:443
        assert_eq!(results[0].ip, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(results[0].port, 443);
        assert_eq!(results[1].ip, "203.0.113.2".parse::<IpAddr>().unwrap());
        assert_eq!(results[1].port, 80);
        assert_eq!(results[2].ip, "203.0.113.3".parse::<IpAddr>().unwrap());
        // push after read dirties again
        let v4 = Verdict {
            ip: "203.0.113.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(5),
            country: None,
            colo: None,
            phase2: None,
        };
        merge_sorted(&c.store, &c.store_dirty, vec![v4.clone()]);
        let results2 = c.results();
        assert_eq!(results2.len(), 4);
        assert_eq!(results2[0].latency_ms, Some(5));
        assert_eq!(results2[0].ip, "203.0.113.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn results_accessors_avoid_full_clone() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        // Empty store: has_results is false.
        assert!(!c.has_results());

        let v1 = Verdict {
            ip: "203.0.113.3".parse().unwrap(),
            port: 443,
            latency_ms: Some(50),
            country: None,
            colo: None,
            phase2: None,
        };
        let v2 = Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: None,
        };
        let v3 = Verdict {
            ip: "203.0.113.2".parse().unwrap(),
            port: 80,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: None,
        };
        merge_sorted(
            &c.store,
            &c.store_dirty,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        // Non-empty store: has_results is true.
        assert!(c.has_results());

        // for_each_result iterates in sorted order matching results().
        let snapshot = c.results();
        let mut collected = Vec::new();
        c.for_each_result(|v| collected.push((v.ip, v.port)));
        let expected: Vec<(IpAddr, u16)> = snapshot.iter().map(|v| (v.ip, v.port)).collect();
        assert_eq!(
            collected, expected,
            "for_each_result must match results() order"
        );
    }
}
