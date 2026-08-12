//! The one in-process scan engine every client drives: pool planning, probe
//! fan-out, stop conditions, event stream and the last-scan results store.
//! Used by the HTTP server (Task 6) and CLI (Task 8).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use anyhow::{Result, anyhow};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::task::JoinSet;

use crate::api::types::{Mode, ScanConfig, ScanEvent, ScanProgress, ScanSummary, Verdict};
use crate::probe::{ProbeError, Transport};
use crate::ranges::{self, PlanItem, SplitMix64};

const PROGRESS_EVERY: u64 = 50;

type Store = Arc<Mutex<Vec<Verdict>>>;

pub struct ScanController {
    transport: Arc<dyn Transport>,
    events: broadcast::Sender<ScanEvent>,
    store: Store,
    summary: Mutex<Option<ScanSummary>>,
    cancel_tx: Mutex<Option<watch::Sender<bool>>>,
}

impl ScanController {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            transport,
            events,
            store: Arc::new(Mutex::new(Vec::new())),
            summary: Mutex::new(None),
            cancel_tx: Mutex::new(None),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.events.subscribe()
    }

    /// Summary of the last finished scan, if one has run yet.
    pub fn summary(&self) -> Option<ScanSummary> {
        self.summary.lock().unwrap().clone()
    }

    /// Snapshot of the last scan's working endpoints, sorted by latency.
    pub fn results(&self) -> Vec<Verdict> {
        self.store.lock().unwrap().clone()
    }

    pub fn reset(&self) {
        self.store.lock().unwrap().clear();
        self.summary.lock().unwrap().take();
    }

    pub fn cancel(&self) {
        if let Some(tx) = self.cancel_tx.lock().unwrap().as_ref() {
            let _ = tx.send(true);
        }
    }

    pub async fn run(&self, cfg: ScanConfig) -> Result<ScanSummary> {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.run_seeded(cfg, seed).await
    }

    /// Runs `cfg` while invoking `on_event` as each event is emitted (the
    /// subscriber attaches before the run starts, so no event is missed).
    /// Errors abort before `Finished` is sent; callers still get them here.
    pub async fn run_streaming(
        self: &Arc<Self>,
        cfg: ScanConfig,
        mut on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let mut rx = self.subscribe();
        let controller = self.clone();
        let mut handle = tokio::spawn(async move { controller.run(cfg).await });
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

    pub async fn run_seeded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let pool = ranges::effective_pool(&cfg.custom_cidrs, &cfg.exclude)?;
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
            return Err(anyhow!("WARP mode lands in Task 12"));
        }
        if cfg.phase2.is_some() {
            return Err(anyhow!("phase-2 verification lands in Task 11"));
        }

        let started = Instant::now();
        self.reset();
        let plan = ranges::plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
        let total = plan_probe_count(&plan, &cfg.ports);
        self.emit(ScanEvent::Progress(ScanProgress {
            scanned: 0,
            found: 0,
            total: Some(total),
        }));

        if total == 0 {
            return Ok(self.finish(started, 0, 0));
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        *self.cancel_tx.lock().unwrap() = Some(cancel_tx);

        let scanned = Arc::new(AtomicU64::new(0));
        let found = Arc::new(AtomicU64::new(0));
        let semaphore = Arc::new(Semaphore::new(cfg.concurrency as usize));

        let mut tasks = JoinSet::new();
        for item in &plan {
            for &port in &cfg.ports {
                for host in plan_hosts(item, &mut SplitMix64::new(seed ^ port as u64)) {
                    let transport = self.transport.clone();
                    let store = self.store.clone();
                    let events = self.events.clone();
                    let semaphore = semaphore.clone();
                    let scanned = scanned.clone();
                    let found = found.clone();
                    let stop = cfg.stop.clone();
                    let cancel = cancel_rx.clone();
                    tasks.spawn(async move {
                        let _permit = semaphore
                            .acquire_owned()
                            .await
                            .map_err(|_| anyhow!("semaphore closed"))?;
                        if *cancel.borrow()
                            || found.load(Ordering::Relaxed) >= u64::from(stop.found)
                            || stop.cap.is_some_and(|cap| {
                                scanned.load(Ordering::Relaxed) >= u64::from(cap)
                            })
                        {
                            return Ok(());
                        }
                        let ip = host;
                        let outcome = transport.probe(ip, port, cfg.timeout_ms).await;
                        scanned.fetch_add(1, Ordering::Relaxed);
                        match outcome {
                            Ok(latency_ms) => {
                                found.fetch_add(1, Ordering::Relaxed);
                                let verdict = Verdict {
                                    ip,
                                    port,
                                    latency_ms: Some(latency_ms),
                                    loss_pct: None,
                                    country: None,
                                    colo: None,
                                    phase2: None,
                                };
                                insert_sorted(&store, verdict.clone());
                                let _ = events.send(ScanEvent::Result(Box::new(verdict)));
                            }
                            Err(ProbeError::Timeout { .. }) => {
                                // counted in `scanned`; no verdict
                            }
                            Err(_) => {}
                        }
                        if scanned.load(Ordering::Relaxed) % PROGRESS_EVERY == 0 {
                            let _ = events.send(ScanEvent::Progress(ScanProgress {
                                scanned: scanned.load(Ordering::Relaxed),
                                found: found.load(Ordering::Relaxed),
                                total: Some(total),
                            }));
                        }
                        Ok::<(), anyhow::Error>(())
                    });
                }
            }
        }
        while let Some(res) = tasks.join_next().await {
            res.map_err(|e| anyhow!("probe task panicked: {e}"))??;
        }

        Ok(self.finish(
            started,
            scanned.load(Ordering::Relaxed),
            found.load(Ordering::Relaxed),
        ))
    }

    fn finish(&self, started: Instant, scanned: u64, found: u64) -> ScanSummary {
        let summary = ScanSummary {
            scanned,
            found,
            duration_ms: started.elapsed().as_millis() as u64,
        };
        *self.summary.lock().unwrap() = Some(summary.clone());
        self.emit(ScanEvent::Finished(summary.clone()));
        self.cancel_tx.lock().unwrap().take();
        summary
    }

    fn emit(&self, event: ScanEvent) {
        let _ = self.events.send(event);
    }
}

/// Concrete host addresses a plan item yields. `Sample` rolls fresh random
/// hosts with a per-port seed so multi-port scans don't repeat the same host.
fn plan_hosts(item: &PlanItem, rng: &mut SplitMix64) -> Vec<std::net::Ipv4Addr> {
    match item {
        PlanItem::Every { cidr } => (0..cidr.host_count())
            .map(|i| cidr.host(i))
            .collect::<Vec<_>>(),
        PlanItem::Sample { cidr, count } => {
            let count = (*count).min(cidr.host_count());
            let mut hosts = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let idx = if cidr.prefix == 24 {
                    // Skip network and broadcast addresses on full /24 blocks.
                    rng.below(254) + 1
                } else {
                    rng.below(cidr.host_count())
                };
                hosts.push(cidr.host(idx));
            }
            hosts
        }
        PlanItem::Hosts { cidr, offsets } => offsets.iter().map(|&o| cidr.host(o)).collect(),
    }
}

fn plan_probe_count(plan: &[PlanItem], ports: &[u16]) -> u64 {
    let hosts: u64 = plan
        .iter()
        .map(|i| match i {
            PlanItem::Every { cidr } => cidr.host_count(),
            PlanItem::Sample { cidr, count } => (*count).min(cidr.host_count()),
            PlanItem::Hosts { offsets, .. } => offsets.len() as u64,
        })
        .sum();
    hosts.saturating_mul(ports.len() as u64)
}

fn insert_sorted(store: &Store, verdict: Verdict) {
    let mut results = store.lock().unwrap();
    let pos = results
        .binary_search_by_key(&verdict.latency_ms, |v| v.latency_ms)
        .unwrap_or_else(|e| e);
    results.insert(pos, verdict);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::api::types::{ScanConfig, ScanTarget, StopCondition};
    use crate::probe::FakeTransport;

    fn ok_cfg(found: u32, cap: Option<u32>) -> ScanConfig {
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
    async fn run_local(c: &Arc<ScanController>, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let pool = ranges::CidrPool::parse("10.0.0.0/29")?;
        c.run_seeded_with_pool(cfg, seed, pool).await
    }

    fn controller(
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
    async fn collects_verdicts_until_found_stop() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 50)
            .ok("10.0.0.2".parse().unwrap(), 443, 10)
            .ok("10.0.0.3".parse().unwrap(), 443, 30);
        let (c, mut rx) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(2, None), 1).await.unwrap();
        assert_eq!(summary.found, 2);
        // 3 probes: 10.0.0.0 (refused) + two hits; the 4th task sees found == 2.
        assert_eq!(summary.scanned, 3);
        let results = c.results();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ip, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(results[1].ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(matches!(events.last(), Some(ScanEvent::Finished(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Result(_))));
    }

    #[tokio::test]
    async fn cap_limits_probes() {
        // found is unreachable; the hard cap must stop the scan.
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 1)
            .ok("10.0.0.2".parse().unwrap(), 443, 1);
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(100, Some(3)), 1).await.unwrap();
        assert_eq!(summary.scanned, 3);
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn exhausts_pool_when_found_unreachable() {
        let t = FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 5);
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(10, None), 1).await.unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(summary.scanned, 8, "all 8 hosts must be probed");
    }

    #[tokio::test]
    async fn multiplies_ports_per_host() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 1)
            .ok("10.0.0.1".parse().unwrap(), 8443, 1);
        let mut cfg = ok_cfg(2, None);
        cfg.ports = vec![443, 8443];
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn cancel_without_active_run_is_noop() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 1)
            .ok("10.0.0.2".parse().unwrap(), 443, 1);
        let (c, _) = controller(Arc::new(t));
        c.cancel();
        let summary = run_local(&c, ok_cfg(5, None), 1).await.unwrap();
        assert_eq!(summary.found, 2);
        assert_eq!(summary.scanned, 8);
    }

    #[tokio::test]
    async fn cancel_stops_mid_scan() {
        // Delayed probes keep the first outcome in flight long enough for the
        // test to observe a result and cancel before the remaining hosts start.
        let t = Arc::new(
            FakeTransport::new()
                .ok_slow("10.0.0.1".parse().unwrap(), 443, 60, 200)
                .ok_slow("10.0.0.2".parse().unwrap(), 443, 60, 200),
        );
        let (c, _) = controller(t.clone());
        let cfg = ok_cfg(10, None);
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await.unwrap() }
        });
        loop {
            if !c.results().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        c.cancel();
        let summary = handle.await.unwrap();
        // Cancel halts the scan before all 8 hosts are probed.
        assert!(summary.scanned < 8, "scanned={}", summary.scanned);
        assert!(summary.found >= 1);
    }

    #[tokio::test]
    async fn rejects_unsupported_modes() {
        let (c, _) = controller(Arc::new(FakeTransport::new()));
        let mut cfg = ok_cfg(1, None);
        cfg.mode = Mode::Warp;
        assert!(run_local(&c, cfg, 1).await.is_err());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(crate::api::types::Phase2Config::default());
        assert!(run_local(&c, cfg, 1).await.is_err());
    }

    #[tokio::test]
    async fn progress_events_report_total() {
        let t = FakeTransport::new();
        // Count(60) samples 60 random hosts from the /24 pool; scripting every
        // host makes the sample fully deterministic.
        for i in 1..=254u8 {
            t.insert(
                format!("10.0.0.{i}").parse().unwrap(),
                443,
                Ok((i % 50) as u32),
            );
        }
        let mut cfg = ok_cfg(100, None);
        cfg.target = ScanTarget::Count(60);
        let (c, mut rx) = controller(Arc::new(t));
        let pool = ranges::CidrPool::parse("10.0.0.0/24").unwrap();
        let summary = c.run_seeded_with_pool(cfg, 1, pool).await.unwrap();
        assert_eq!(summary.found, 60);
        let mut saw_progress = false;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Progress(p) = e {
                saw_progress = true;
                assert_eq!(p.total, Some(60));
            }
        }
        assert!(saw_progress, "no progress events emitted");
    }

    #[tokio::test]
    async fn new_run_replaces_previous_results() {
        let t = Arc::new(FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 5));
        let (c, _) = controller(t.clone());
        let _ = run_local(&c, ok_cfg(1, None), 1).await.unwrap();
        assert_eq!(c.results().len(), 1);
        t.clear();
        let _ = run_local(&c, ok_cfg(1, None), 1).await.unwrap();
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn rejects_invalid_config() {
        let (c, _) = controller(Arc::new(FakeTransport::new()));
        let mut cfg = ok_cfg(1, None);
        cfg.ports = vec![0];
        assert!(run_local(&c, cfg, 1).await.is_err());
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
        cfg.mode = Mode::Warp; // unsupported until Task 12; run aborts before Finished
        let mut events = vec![];
        let err = c.run_streaming(cfg, |e| events.push(e)).await.unwrap_err();
        assert!(err.to_string().contains("WARP"));
        assert!(events.is_empty());
    }
}
