mod cdn;
mod neighbor;
mod phase2;
mod plan;
mod speed;
mod store;
#[cfg(test)]
mod test_helpers;
mod warp;

#[cfg(test)]
use plan::plan_hosts_iter;
pub use plan::{PlanItem, SplitMix64, plan};
use store::{Store, lock, merge_sorted};

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
use crate::engine::speed::{RealSpeedTester, SpeedTester};
use crate::geo::Geo;
use crate::probe::Transport;
use crate::ranges;
use crate::verify::{
    HybridTunnelProbe, RealTunnelOpener, TunnelOpener, TunnelProbe, XrayTunnelProbe,
};

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

#[derive(Debug, thiserror::Error)]
#[error("a scan is already running")]
pub struct AlreadyRunning;

struct ResetGuard<'a> {
    running: &'a Mutex<bool>,
    cancel_tx: &'a Mutex<Option<watch::Sender<bool>>>,
}

impl Drop for ResetGuard<'_> {
    fn drop(&mut self) {
        lock(self.cancel_tx).take();
        *lock(self.running) = false;
    }
}

pub struct ScanController {
    transport: Arc<dyn Transport>,
    warp_transport: Arc<dyn Transport>,
    warp_cache: Option<Arc<crate::warp::SocketCache>>,
    sub_fetch: Arc<dyn SubFetch>,
    tunnel_probe: Arc<dyn TunnelProbe>,
    speed_tester: Mutex<Arc<dyn SpeedTester>>,
    session_opener: Mutex<Arc<dyn TunnelOpener>>,
    geo: Arc<Geo>,
    events: broadcast::Sender<ScanEvent>,
    store: Store,
    store_dirty: Arc<AtomicBool>,
    summary: Mutex<Option<ScanSummary>>,
    cancel_tx: Mutex<Option<watch::Sender<bool>>>,
    running: Mutex<bool>,
    last_phase2_configs: Mutex<Vec<String>>,
}

impl ScanController {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        let warp_cache = Arc::new(crate::warp::SocketCache::default());
        let warp_transport = Arc::new(
            crate::warp::WarpTransport::from_cache(warp_cache.clone())
                .expect("WARP server key must decode"),
        );
        let mut ctrl = Self::with_transports(transport, warp_transport);
        ctrl.warp_cache = Some(warp_cache);
        ctrl
    }

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
            speed_tester: Mutex::new(Arc::new(RealSpeedTester)),
            session_opener: Mutex::new(Arc::new(RealTunnelOpener)),
            geo: Arc::new(Geo::embedded()),
            events,
            store: Arc::new(Mutex::new(Vec::new())),
            store_dirty: Arc::new(AtomicBool::new(false)),
            summary: Mutex::new(None),
            cancel_tx: Mutex::new(None),
            running: Mutex::new(false),
            last_phase2_configs: Mutex::new(Vec::new()),
        }
    }

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

    pub fn set_speed_tester(&self, tester: Arc<dyn SpeedTester>) {
        *lock(&self.speed_tester) = tester;
    }

    pub fn set_tunnel_opener(&self, opener: Arc<dyn TunnelOpener>) {
        *lock(&self.session_opener) = opener;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ScanEvent> {
        self.events.subscribe()
    }

    pub fn summary(&self) -> Option<ScanSummary> {
        lock(&self.summary).clone()
    }

    pub fn results(&self) -> Vec<Verdict> {
        self.snapshot_sorted()
    }

    pub fn has_results(&self) -> bool {
        !lock(&self.store).is_empty()
    }

    pub fn for_each_result(&self, mut f: impl FnMut(&Verdict)) {
        let snapshot = self.snapshot_sorted();
        for v in &snapshot {
            f(v);
        }
    }

    fn snapshot_sorted(&self) -> Vec<Verdict> {
        let mut guard = lock(&self.store);
        if self.store_dirty.swap(false, Ordering::AcqRel) {
            guard.sort_unstable_by(|a, b| {
                a.latency_ms
                    .is_none()
                    .cmp(&b.latency_ms.is_none())
                    .then_with(|| a.latency_ms.cmp(&b.latency_ms))
                    .then_with(|| a.ip.cmp(&b.ip))
                    .then_with(|| a.port.cmp(&b.port))
            });
        }
        guard.clone()
    }

    fn phase2_passed(&self) -> u64 {
        lock(&self.store)
            .iter()
            .filter(|v| v.phase2.as_ref().is_some_and(|p| p.passed))
            .count() as u64
    }

    fn working_found(&self) -> u64 {
        lock(&self.store)
            .iter()
            .filter(|v| v.latency_ms.is_some())
            .filter(|v| v.phase2.as_ref().is_none_or(|p| p.passed))
            .count() as u64
    }

    pub fn is_running(&self) -> bool {
        *lock(&self.running)
    }

    pub fn reset(&self) {
        let running = lock(&self.running);
        if *running {
            return;
        }
        self.clear_store();
        drop(running);
    }

    fn clear_store(&self) {
        lock(&self.store).clear();
        self.store_dirty.store(false, Ordering::Relaxed);
        lock(&self.summary).take();
    }

    pub fn cancel(&self) {
        if let Some(tx) = lock(&self.cancel_tx).as_ref() {
            let _ = tx.send(true);
        }
    }

    fn cancel_signal(&self) -> watch::Receiver<bool> {
        let mut slot = lock(&self.cancel_tx);
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

    pub async fn run_streaming(
        self: &Arc<Self>,
        cfg: ScanConfig,
        on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        self.run_streaming_seeded(cfg, OsRng.next_u64(), on_event)
            .await
    }

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

    pub async fn run_reserved_streaming(
        self: &Arc<Self>,
        cfg: ScanConfig,
        on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let rx = self.subscribe();
        let controller = self.clone();
        let seed = OsRng.next_u64();
        let handle = tokio::spawn(async move {
            let _guard = controller.reset_guard();
            controller.run_reserved(cfg, seed).await
        });
        self.drive_run(handle, rx, on_event).await
    }

    async fn drive_run(
        self: &Arc<Self>,
        mut handle: tokio::task::JoinHandle<Result<ScanSummary>>,
        mut rx: broadcast::Receiver<ScanEvent>,
        mut on_event: impl FnMut(ScanEvent),
    ) -> Result<ScanSummary> {
        let mut seen: HashSet<(IpAddr, u16, bool)> = HashSet::new();
        loop {
            tokio::select! {
                done = &mut handle => {
                    let result = done?;
                    loop {
                        match rx.try_recv() {
                            Ok(event) => {
                                if let ScanEvent::Result(verdict) = &event {
                                    seen.insert((verdict.ip, verdict.port, verdict.phase2.is_some()));
                                }
                                on_event(event);
                            }
                            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                            Err(TryRecvError::Lagged(_)) => continue,
                        }
                    }
                    self.for_each_result(|v| {
                        if seen.insert((v.ip, v.port, v.phase2.is_some())) {
                            on_event(ScanEvent::Result(Box::new(v.clone())));
                        }
                    });
                    return result;
                }
                recv = rx.recv() => match recv {
                    Ok(event @ ScanEvent::Finished(_)) => {
                        on_event(event);
                        self.for_each_result(|v| {
                            if seen.insert((v.ip, v.port, v.phase2.is_some())) {
                                on_event(ScanEvent::Result(Box::new(v.clone())));
                            }
                        });
                        return handle.await?;
                    }
                    Ok(event) => {
                        if let ScanEvent::Result(verdict) = &event {
                            seen.insert((verdict.ip, verdict.port, verdict.phase2.is_some()));
                        }
                        on_event(event);
                    }
                    Err(_) => {
                        self.for_each_result(|v| {
                            if seen.insert((v.ip, v.port, v.phase2.is_some())) {
                                on_event(ScanEvent::Result(Box::new(v.clone())));
                            }
                        });
                    }
                },
            }
        }
    }

    pub fn reserve(&self) -> Result<(), AlreadyRunning> {
        let mut running = lock(&self.running);
        if *running {
            return Err(AlreadyRunning);
        }
        *running = true;
        Ok(())
    }

    fn reset_guard(&self) -> ResetGuard<'_> {
        ResetGuard {
            running: &self.running,
            cancel_tx: &self.cancel_tx,
        }
    }

    pub async fn run_seeded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        self.reserve().map_err(|err| {
            self.emit(ScanEvent::Failed(crate::api::types::FailedPayload {
                reason: format!("{err:#}"),
            }));
            anyhow!("{err}")
        })?;
        let _guard = self.reset_guard();
        self.run_reserved(cfg, seed).await
    }

    async fn run_reserved(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let result = self.run_seeded_unguarded(cfg, seed).await;
        if let Err(err) = &result {
            let msg = crate::configs::sanitize_error_text(&format!("{err:#}"));
            self.emit(ScanEvent::Failed(crate::api::types::FailedPayload {
                reason: msg,
            }));
        }
        result
    }

    async fn run_seeded_unguarded(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let pool = ranges::effective_pool(&cfg.custom_cidrs, &cfg.exclude, cfg.include_v6).await?;
        self.run_seeded_with_pool(cfg, seed, pool).await
    }

    async fn run_seeded_with_pool(
        &self,
        cfg: ScanConfig,
        seed: u64,
        pool: ranges::CidrPool,
    ) -> Result<ScanSummary> {
        cfg.validate()?;
        self.retain_phase2_configs(&cfg);
        if cfg.mode == Mode::Warp {
            return self.run_warp(cfg, seed).await;
        }
        self.run_cdn(cfg, seed, pool).await
    }

    fn retain_phase2_configs(&self, cfg: &ScanConfig) {
        let configs = cfg
            .phase2
            .as_ref()
            .map(|p| p.configs.clone())
            .unwrap_or_default();
        *lock(&self.last_phase2_configs) = configs;
    }

    pub fn phase2_configs(&self) -> Vec<String> {
        lock(&self.last_phase2_configs).clone()
    }

    pub fn set_asn(&self, ip: IpAddr, port: u16, asn: u32, isp: &str) -> bool {
        store::set_asn(&self.store, ip, port, asn, isp)
    }

    fn finish(&self, started: Instant, scanned: u64, found: u64) -> ScanSummary {
        let summary = self.finish_quiet(started, scanned, found);
        self.emit(ScanEvent::Finished(summary.clone()));
        summary
    }

    /// Records the summary without emitting Finished — used by multi-pass
    /// runs where only the last pass is terminal.
    fn finish_quiet(&self, started: Instant, scanned: u64, found: u64) -> ScanSummary {
        let cancelled = lock(&self.cancel_tx)
            .as_ref()
            .map(|tx| *tx.subscribe().borrow())
            .unwrap_or(false);
        let mut last = lock(&self.summary);
        let summary = ScanSummary {
            scanned,
            found,
            duration_ms: started.elapsed().as_millis() as u64,
            cancelled,
        };
        *last = Some(summary.clone());
        drop(last);
        summary
    }

    fn emit(&self, event: ScanEvent) {
        let _ = self.events.send(event);
    }
}

const BATCH_FLUSH: usize = 256;

fn claim_milestone(last: &AtomicU64, observed: u64, cadence: u64) -> bool {
    let threshold = observed / cadence;
    let claimed = last.load(Ordering::Relaxed);
    threshold > claimed
        && last
            .compare_exchange(claimed, threshold, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

async fn cancelled_signal(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn colo_in_filter(filter: &[String], colo: &str) -> bool {
    filter.iter().any(|f| f.eq_ignore_ascii_case(colo))
}

/// True when `colo` is known but not accepted by the filter; unknown colo never rejects.
fn colo_rejected(filter: &[String], colo: Option<&str>) -> bool {
    !filter.is_empty() && colo.is_some_and(|c| !colo_in_filter(filter, c))
}

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
    colo_filter: Arc<Vec<String>>,
    colo_warned: AtomicBool,
}

impl ProbeContext {
    fn should_stop(&self) -> bool {
        *self.cancel.borrow()
            || self.found.load(Ordering::Acquire) >= u64::from(self.stop.found)
            || self
                .stop
                .cap
                .is_some_and(|cap| self.scanned.load(Ordering::Acquire) >= u64::from(cap))
    }

    async fn cancelled(&self) {
        cancelled_signal(self.cancel.clone()).await;
    }

    fn milestone_due(&self, observed: u64) -> bool {
        claim_milestone(&self.last_milestone, observed, self.cadence)
    }

    fn colo_allowed(&self, colo: Option<&str>) -> bool {
        if self.colo_filter.is_empty() {
            return true;
        }
        match colo {
            Some(c) => colo_in_filter(&self.colo_filter, c),
            None => {
                if !self.colo_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!("--colo filter set but no colo data available for result");
                }
                true
            }
        }
    }

    fn progress(&self, scanned: u64, found: u64) {
        let _ = self.events.send(ScanEvent::Progress(ScanProgress {
            scanned,
            found,
            total: Some(self.total),
        }));
    }
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
    fn colo_filter_matching_is_case_insensitive_and_unknown_colo_passes() {
        let filter = vec!["HKG".to_owned(), "NRT".to_owned()];
        assert!(colo_in_filter(&filter, "hkg"));
        assert!(colo_in_filter(&filter, "NRT"));
        assert!(!colo_in_filter(&filter, "FRA"));
        assert!(
            !colo_rejected(&filter, None),
            "unknown colo must pass through"
        );
        assert!(!colo_rejected(&filter, Some("HKG")));
        assert!(colo_rejected(&filter, Some("fra")));
        assert!(
            !colo_rejected(&[], Some("FRA")),
            "an empty filter must reject nothing"
        );
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
                            lock(winners).push(observed);
                        }
                    }
                });
            }
        });
        let claimed = lock(&winners).clone();
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
        ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Count(8),
            stop: StopCondition { found, cap },
            ports: vec![Port::new(443)],
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

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
            results, 3,
            "two successes plus the re-emitted failure verdict must arrive exactly once: {events:?}"
        );
    }

    #[tokio::test]
    async fn run_streaming_sets_the_busy_flag() {
        let t = FakeTransport::new().ok_slow("203.0.113.1".parse().unwrap(), 443, 25, 500);
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut cfg = ok_cfg(1, None);
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
        let handle = tokio::spawn({
            let c = c.clone();
            async move { c.run_streaming(cfg, |_| {}).await.unwrap() }
        });
        wait_until(Duration::from_secs(2), || c.is_running()).await;
        assert!(
            c.is_running(),
            "the busy flag must be set during a streaming scan"
        );
        handle.await.unwrap();
        assert!(
            !c.is_running(),
            "busy flag must clear after the streaming scan"
        );
    }

    #[tokio::test]
    async fn run_streaming_reports_errors_without_finished() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        let mut cfg = ok_cfg(1, None);
        cfg.ports = vec![Port::new(0)];
        let mut events = vec![];
        let err = c.run_streaming(cfg, |e| events.push(e)).await.unwrap_err();
        assert!(err.to_string().contains("out of range"));
        assert!(!events.is_empty(), "the failure must reach clients");
        assert!(!events.iter().any(|e| matches!(e, ScanEvent::Finished(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Failed(_))));
    }

    #[tokio::test]
    async fn concurrent_runs_are_rejected_and_failed_event_is_emitted() {
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
    async fn reserved_streaming_run_resets_the_busy_flag() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 5);
        let c = Arc::new(ScanController::new(Arc::new(t)));
        let mut cfg = ok_cfg(1, None);
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
        c.reserve().unwrap();
        let summary = c.run_reserved_streaming(cfg, |_| {}).await.unwrap();
        assert_eq!(summary.found, 1);
        assert!(!c.is_running(), "guard must reset the busy flag");
        assert!(
            lock(&c.cancel_tx).is_none(),
            "guard must clear the cancel slot"
        );
    }

    #[test]
    fn poisoned_locks_do_not_wedge_the_controller() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = c.running.lock().unwrap();
            panic!("poison running");
        }));
        assert!(
            !c.is_running(),
            "poisoned busy flag must still read as idle"
        );
        assert!(c.reserve().is_ok(), "reserve must tolerate a poisoned lock");
        drop(c.reset_guard());
        assert!(!c.is_running());

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = c.store.lock().unwrap();
            panic!("poison store");
        }));
        assert!(c.results().is_empty());
        assert!(!c.has_results());
    }

    #[tokio::test]
    async fn empty_pool_finishes_with_zero_summary() {
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
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10)
            .ok("203.0.113.3".parse().unwrap(), 443, 30);
        let (c, mut rx) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(3, None), 1).await.unwrap();
        let results = c.results();
        let successes = results.iter().filter(|v| v.latency_ms.is_some()).count();
        assert_eq!(summary.found as usize, successes);
        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(matches!(events.last(), Some(ScanEvent::Finished(_))));
        let lats: Vec<u32> = results.iter().filter_map(|v| v.latency_ms).collect();
        assert!(lats.windows(2).all(|w| w[0] <= w[1]), "{lats:?}");
    }

    #[test]
    fn sampling_skips_network_and_broadcast_for_dense_v4_blocks() {
        let mut rng = SplitMix64::new(1);
        let item = PlanItem::Sample {
            cidr: ranges::parse_cidr("203.0.113.0/25").unwrap(),
            count: 200,
        };
        let hosts: Vec<IpAddr> = plan_hosts_iter(&item, &mut rng).collect();
        assert_eq!(hosts.len(), 126, "all usable /25 hosts must be drawn");
        assert!(!hosts.contains(&"203.0.113.0".parse::<IpAddr>().unwrap()));
        assert!(!hosts.contains(&"203.0.113.127".parse::<IpAddr>().unwrap()));

        let item = PlanItem::Sample {
            cidr: ranges::parse_cidr("203.0.113.0/24").unwrap(),
            count: 300,
        };
        let hosts: Vec<IpAddr> = plan_hosts_iter(&item, &mut rng).collect();
        assert_eq!(hosts.len(), 254);

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
                            let rx = lock(&park_rx);
                            let _ = rx.recv();
                        }
                        lock(&events_c).push(e);
                    })
                    .await
                    .unwrap();
                let events = Arc::try_unwrap(events).ok().unwrap().into_inner().unwrap();
                (summary, events)
            }
        });
        wait_until(Duration::from_secs(2), || !c.is_running()).await;
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
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        let v2 = Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
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
        };
        let v3 = Verdict {
            ip: "203.0.113.2".parse().unwrap(),
            port: 80,
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
        };
        merge_sorted(
            &c.store,
            &c.store_dirty,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );
        let results = c.results();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].ip, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(results[0].port, 443);
        assert_eq!(results[1].ip, "203.0.113.2".parse::<IpAddr>().unwrap());
        assert_eq!(results[1].port, 80);
        assert_eq!(results[2].ip, "203.0.113.3".parse::<IpAddr>().unwrap());
        let v4 = Verdict {
            ip: "203.0.113.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(5),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        merge_sorted(&c.store, &c.store_dirty, vec![v4.clone()]);
        let results2 = c.results();
        assert_eq!(results2.len(), 4);
        assert_eq!(results2[0].latency_ms, Some(5));
        assert_eq!(results2[0].ip, "203.0.113.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn failed_verdicts_sort_after_all_measured_ones() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        let slow = Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
            latency_ms: Some(90),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        let dead_a = Verdict {
            ip: "203.0.113.2".parse().unwrap(),
            port: 443,
            latency_ms: None,
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 0,
            loss_pct: Some(100),
            fail_reason: Some("refused".to_owned()),
            asn: None,
            isp: None,
        };
        let dead_b = Verdict {
            ip: "203.0.113.3".parse().unwrap(),
            port: 443,
            latency_ms: None,
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 0,
            loss_pct: Some(100),
            fail_reason: Some("timeout".to_owned()),
            asn: None,
            isp: None,
        };
        merge_sorted(&c.store, &c.store_dirty, vec![dead_b, slow.clone(), dead_a]);
        let results = c.results();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].latency_ms, Some(90));
        assert_eq!(results[1].fail_reason.as_deref(), Some("refused"));
        assert_eq!(results[2].fail_reason.as_deref(), Some("timeout"));
        assert_eq!(results[2].latency_ms, None);
    }

    #[test]
    fn results_accessors_avoid_full_clone() {
        let c = Arc::new(ScanController::new(Arc::new(FakeTransport::new())));
        assert!(!c.has_results());

        let v1 = Verdict {
            ip: "203.0.113.3".parse().unwrap(),
            port: 443,
            latency_ms: Some(50),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        let v2 = Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
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
        };
        let v3 = Verdict {
            ip: "203.0.113.2".parse().unwrap(),
            port: 80,
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
        };
        merge_sorted(
            &c.store,
            &c.store_dirty,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        assert!(c.has_results());

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
