//! The one in-process scan engine every client drives: pool planning, probe
//! fan-out, stop conditions, event stream and the last-scan results store.
//! Used by the HTTP server, wizard, and CLI.

mod cdn;
mod phase2;
mod warp;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use anyhow::{Result, anyhow};
use tokio::sync::{broadcast, watch};

use crate::api::types::{
    Mode, ScanConfig, ScanEvent, ScanProgress, ScanSummary, StopCondition, Verdict,
};
use crate::configs::{RealSubFetch, SubFetch};
use crate::geo::Geo;
use crate::probe::Transport;
use crate::ranges::{self, PlanItem, SplitMix64};
use crate::verify::{TunnelProbe, XrayTunnelProbe};

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

pub struct ScanController {
    transport: Arc<dyn Transport>,
    warp_transport: Arc<dyn Transport>,
    sub_fetch: Arc<dyn SubFetch>,
    tunnel_probe: Arc<dyn TunnelProbe>,
    geo: Arc<Geo>,
    events: broadcast::Sender<ScanEvent>,
    store: Store,
    summary: Mutex<Option<ScanSummary>>,
    cancel_tx: Mutex<Option<watch::Sender<bool>>>,
    running: Mutex<bool>,
}

impl ScanController {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self::with_transports(transport, Arc::new(crate::warp::WarpTransport))
    }

    /// One controller serving both modes (the server's case): CDN probes go
    /// through `transport`, WARP through `warp_transport`.
    pub fn with_transports(
        transport: Arc<dyn Transport>,
        warp_transport: Arc<dyn Transport>,
    ) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            transport,
            warp_transport,
            sub_fetch: Arc::new(RealSubFetch),
            tunnel_probe: Arc::new(XrayTunnelProbe),
            geo: Arc::new(Geo::embedded()),
            events,
            store: Arc::new(Mutex::new(Vec::new())),
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
    pub fn results(&self) -> Vec<Verdict> {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// True while a run is active; the server rejects new scans then.
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Clears the last scan's results. No-op while a run is active so an
    /// in-flight run can never repopulate a store the user just cleared.
    pub fn reset(&self) {
        if self.is_running() {
            return;
        }
        self.clear_store();
    }

    /// Internal reset for run start; bypasses the running guard (the run
    /// itself is the one clearing, not a concurrent caller).
    fn clear_store(&self) {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).clear();
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

    pub async fn run(&self, cfg: ScanConfig) -> Result<ScanSummary> {
        self.run_seeded(cfg, time_seed()).await
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
        self.run_streaming_seeded(cfg, time_seed(), on_event).await
    }

    /// `run_streaming` with an explicit sampling seed (repro runs).
    pub async fn run_streaming_seeded(
        self: &Arc<Self>,
        cfg: ScanConfig,
        seed: u64,
        mut on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let mut rx = self.subscribe();
        let controller = self.clone();
        let mut handle = tokio::spawn(async move { controller.run_seeded(cfg, seed).await });
        loop {
            tokio::select! {
                done = &mut handle => {
                    // The run may have finished with events still buffered;
                    // deliver them so callers never miss the tail.
                    while let Ok(e) = rx.try_recv() {
                        on_event(e);
                    }
                    return done?;
                }
                recv = rx.recv() => match recv {
                    Ok(event @ ScanEvent::Finished(_)) => {
                        on_event(event);
                        return handle.await?;
                    }
                    Ok(event) => on_event(event),
                    Err(_) => continue, // lagged: keep streaming
                },
            }
        }
    }

    /// At most one run per controller: a second concurrent run is rejected
    /// (surfacing as a `Failed` event) so two runs can never race the shared
    /// store or the cancel slot.
    pub async fn run_seeded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        {
            let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
            if *running {
                let err = anyhow!("a scan is already running");
                self.emit(ScanEvent::Failed(format!("{err:#}")));
                return Err(err);
            }
            *running = true;
        }
        let result = self.run_seeded_unguarded(cfg, seed).await;
        if let Err(err) = &result {
            self.emit(ScanEvent::Failed(format!("{err:#}")));
        }
        // RAII: clears the busy flag (and the cancel slot) even if the run
        // panics, so one bad run can never brick the controller for the rest
        // of the process's life.
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

/// Sampling seed for interactive runs (per-run entropy; explicit seeds win).
fn time_seed() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Concrete hosts a plan item yields, streamed lazily so a Full scan never
/// materializes an entire `Every` range. `Sample` rolls fresh random hosts
/// with a per-port seed so multi-port scans don't repeat the same host.
/// v6 host spaces need u128 sampling (see `SplitMix64::below_u128`).
fn plan_hosts_iter<'a>(
    item: &'a PlanItem,
    rng: &'a mut SplitMix64,
) -> Box<dyn Iterator<Item = IpAddr> + Send + 'a> {
    match item {
        PlanItem::Every { cidr } => Box::new((0..cidr.host_count()).map(move |i| cidr.host(i))),
        PlanItem::Sample { cidr, count } => {
            let count = (*count as u128).min(cidr.host_count());
            Box::new((0..count).map(move |_| {
                let idx = if cidr.addr.is_ipv4() && cidr.prefix == 24 {
                    // Skip network and broadcast addresses on full /24 blocks.
                    (rng.below(254) + 1) as u128
                } else {
                    rng.below_u128(cidr.host_count())
                };
                cidr.host(idx)
            }))
        }
        PlanItem::Hosts { cidr, offsets } => Box::new(offsets.iter().map(move |&o| cidr.host(o))),
    }
}

fn plan_probe_count(plan: &[PlanItem], ports: &[u16]) -> u64 {
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
const BATCH_FLUSH: usize = 64;

/// Shared state for one probe phase: stop conditions, counters, and the
/// event/store handles every worker needs. `Arc`-shared between the producer
/// and all workers of a phase.
struct ProbeContext {
    cancel: watch::Receiver<bool>,
    stop: StopCondition,
    scanned: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    cadence: u64,
    total: u64,
    store: Store,
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

    fn progress(&self, scanned: u64, found: u64) {
        let _ = self.events.send(ScanEvent::Progress(ScanProgress {
            scanned,
            found,
            total: Some(self.total),
        }));
    }
}

/// Sorted merge of a worker's verdict batch into the global store: one lock,
/// O(n + b) instead of b single-insert O(n) memmoves.
fn merge_sorted(store: &Store, mut batch: Vec<Verdict>) {
    if batch.is_empty() {
        return;
    }
    batch.sort_unstable_by_key(|v| v.latency_ms);
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    if results.is_empty() {
        *results = batch;
        return;
    }
    let mut merged = Vec::with_capacity(results.len() + batch.len());
    let (mut i, mut j) = (0, 0);
    while i < results.len() && j < batch.len() {
        if results[i].latency_ms <= batch[j].latency_ms {
            merged.push(results[i].clone());
            i += 1;
        } else {
            merged.push(batch[j].clone());
            j += 1;
        }
    }
    merged.extend_from_slice(&results[i..]);
    merged.extend_from_slice(&batch[j..]);
    *results = merged;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{ScanConfig, ScanTarget, StopCondition};
    use crate::probe::FakeTransport;
    use std::time::Duration;

    pub(crate) fn ok_cfg(found: u32, cap: Option<u32>) -> ScanConfig {
        // Serial probing keeps stop/cap semantics exact in tests.
        ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Count(8),
            stop: StopCondition { found, cap },
            ports: vec![443],
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

    /// Runs a scan over a scripted /29 pool: deterministic hosts
    /// 10.0.0.0-10.0.0.7, independent of the filesystem and bundled ranges.
    pub(crate) async fn run_local(
        c: &Arc<ScanController>,
        cfg: ScanConfig,
        seed: u64,
    ) -> Result<ScanSummary> {
        let pool = ranges::CidrPool::parse("10.0.0.0/29")?;
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
            .ok("10.0.0.1".parse().unwrap(), 443, 50)
            .ok("10.0.0.2".parse().unwrap(), 443, 10);
        let c = Arc::new(ScanController::new(Arc::new(t)));
        // custom_cidrs keeps the scan on the scripted /29, off the filesystem.
        let mut cfg = ok_cfg(2, None);
        cfg.custom_cidrs = vec!["10.0.0.0/29".to_owned()];
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
        cfg.ports = vec![0]; // validation rejects the run before any event
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
            t = t.ok_slow(format!("10.0.0.{i}").parse().unwrap(), 443, 25, 150);
        }
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut events = c.subscribe();
        let mut cfg = ok_cfg(8, None);
        cfg.custom_cidrs = vec!["10.0.0.0/29".to_owned()];
        let first = tokio::spawn({
            let c = c.clone();
            let cfg = cfg.clone();
            async move { c.run(cfg).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
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
        let ScanEvent::Failed(msg) = event else {
            unreachable!("loop only breaks on Failed")
        };
        assert!(msg.contains("already running"), "{msg}");

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
            t = t.ok_slow(format!("10.0.0.{i}").parse().unwrap(), 443, 25, 150);
        }
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut cfg = ok_cfg(8, None);
        cfg.custom_cidrs = vec!["10.0.0.0/29".to_owned()];
        let first = tokio::spawn({
            let c = c.clone();
            let cfg = cfg.clone();
            async move { c.run(cfg).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
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
        let pool = ranges::CidrPool::parse("10.0.0.0/29")
            .unwrap()
            .excluding(&[ranges::parse_cidr("10.0.0.0/29").unwrap()]);
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
            .ok("10.0.0.1".parse().unwrap(), 443, 50)
            .ok("10.0.0.2".parse().unwrap(), 443, 10)
            .ok("10.0.0.3".parse().unwrap(), 443, 30);
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
}
