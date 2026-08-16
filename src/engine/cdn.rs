//! CDN/proxy-mode phase-1 scan: TCP/TLS probes over the plan (port fan-out,
//! per-port host sampling) with stop-condition and cancel checks, then
//! optional phase-2 verification of the found candidates.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{
    BATCH_FLUSH, ProbeContext, ScanController, merge_sorted, plan_hosts_iter, plan_probe_count,
    progress_cadence,
};
use crate::api::types::{ScanConfig, ScanEvent, ScanProgress, ScanSummary, Verdict};
use crate::ranges::{self, SplitMix64};

/// One phase-1 probe unit: a concrete (host, port) pair from the plan.
#[derive(Clone)]
struct ProbeTask {
    ip: IpAddr,
    port: u16,
}

/// How long a full-queue producer sleeps between send attempts; long enough
/// to let workers drain, short enough to react to cancel promptly.
const PRODUCER_POLL: std::time::Duration = std::time::Duration::from_millis(5);

impl ScanController {
    /// CDN-mode run: pool planning, phase-1 probe fan-out, then phase-2
    /// verification of the candidates when configured.
    pub(super) async fn run_cdn(
        &self,
        mut cfg: ScanConfig,
        seed: u64,
        pool: ranges::CidrPool,
    ) -> Result<ScanSummary> {
        let phase2 = cfg.phase2.take();
        let phase2_configured = phase2.is_some();

        let started = Instant::now();
        // Verify-last-results mode: skip phase-1 probing entirely and run
        // phase-2 verification against the candidates already in the store.
        if cfg.phase2_only {
            let Some(p2) = phase2 else {
                return Err(anyhow!("phase2_only requires phase2 configs"));
            };
            if self
                .store
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            {
                return Err(anyhow!(
                    "phase2_only: no candidates to verify (run a full scan first)"
                ));
            }
            self.verify_phase(&cfg, &p2).await?;
            return Ok(self.finish(started, 0, self.phase2_passed()));
        }
        self.clear_store();
        let plan = ranges::plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
        let total = plan_probe_count(&plan, &cfg.ports);
        let cadence = progress_cadence(total);
        self.emit(ScanEvent::Progress(ScanProgress {
            scanned: 0,
            found: 0,
            total: Some(total),
        }));

        if total == 0 {
            return Ok(self.finish(started, 0, 0));
        }

        // One cancel signal per run, shared by every phase: `cancel_signal`
        // (re)creates the channel on first use and later phases subscribe to
        // the same one, so a cancel fired during phase 1 is still visible to
        // phase-2 workers and to `finish` — never lost to a fresh install.
        let cancel_rx = self.cancel_signal();

        let ctx = Arc::new(ProbeContext {
            cancel: cancel_rx,
            stop: cfg.stop.clone(),
            scanned: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicU64::new(0)),
            cadence,
            total,
            store: self.store.clone(),
            events: self.events.clone(),
            geo: self.geo.clone(),
        });

        let concurrency = usize::from(cfg.concurrency).max(1);
        let (tx, rx) = mpsc::channel::<ProbeTask>(concurrency * 2);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));

        // Producer: streams plan hosts lazily into the queue, checking the
        // stop conditions before every send. A full queue parks the producer
        // briefly instead of blocking forever: a parked `send` can never
        // resolve once every worker has exited (the last receiver is gone
        // and tokio mpsc wakes no senders on receiver drop), so the poll
        // loop re-checks stop conditions and the channel's closed state
        // instead of trusting the send to return.
        let producer = {
            let tx = tx;
            let ctx = Arc::clone(&ctx);
            let cfg = cfg.clone();
            tokio::spawn(async move {
                'outer: for item in &plan {
                    for &port in &cfg.ports {
                        let mut rng = SplitMix64::new(seed ^ port as u64);
                        for host in plan_hosts_iter(item, &mut rng) {
                            if ctx.should_stop() {
                                break 'outer;
                            }
                            let task = ProbeTask { ip: host, port };
                            loop {
                                if ctx.should_stop() {
                                    break 'outer;
                                }
                                match tx.try_send(task.clone()) {
                                    Ok(()) => break,
                                    Err(mpsc::error::TrySendError::Closed(_)) => break 'outer,
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        tokio::time::sleep(PRODUCER_POLL).await;
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        // Workers: a fixed `concurrency` set (no spawn-per-probe), each
        // holding at most one in-flight probe past the stop check, so
        // overshoot is bounded by the worker count. Verdicts are batched
        // and merged into the store under one lock per batch.
        let mut workers = JoinSet::new();
        for _ in 0..concurrency {
            let ctx = Arc::clone(&ctx);
            let rx = Arc::clone(&rx);
            let transport = self.transport.clone();
            let timeout_ms = cfg.timeout_ms;
            workers.spawn(async move {
                let mut batch: Vec<Verdict> = Vec::new();
                loop {
                    if ctx.should_stop() {
                        break;
                    }
                    let task = {
                        let mut guard = rx.lock().await;
                        if ctx.should_stop() {
                            break;
                        }
                        match guard.recv().await {
                            Some(task) => task,
                            None => break,
                        }
                    };
                    let outcome = transport.probe(task.ip, task.port, timeout_ms).await;
                    ctx.scanned.fetch_add(1, Ordering::Relaxed);
                    if let Ok(latency_ms) = outcome {
                        ctx.found.fetch_add(1, Ordering::Relaxed);
                        let verdict = Verdict {
                            ip: task.ip,
                            port: task.port,
                            latency_ms: Some(latency_ms),
                            loss_pct: None,
                            country: ctx.geo.country(task.ip),
                            colo: None,
                            phase2: None,
                        };
                        batch.push(verdict.clone());
                        if batch.len() >= BATCH_FLUSH {
                            merge_sorted(&ctx.store, std::mem::take(&mut batch));
                        }
                        let _ = ctx.events.send(ScanEvent::Result(Box::new(verdict)));
                    }
                    // Timeouts and refusals are counted in `scanned` only.
                    let scanned = ctx.scanned.load(Ordering::Relaxed);
                    if scanned % ctx.cadence == 0 {
                        ctx.progress(scanned, ctx.found.load(Ordering::Relaxed));
                    }
                }
                merge_sorted(&ctx.store, batch);
            });
        }

        while let Some(res) = workers.join_next().await {
            if let Err(join_err) = res {
                self.cancel();
                return Err(anyhow!("probe worker panicked: {join_err}"));
            }
        }
        producer
            .await
            .map_err(|e| anyhow!("probe producer panicked: {e}"))?;

        if let Some(p2) = phase2 {
            self.verify_phase(&cfg, &p2).await?;
        }

        // With phase 2 configured, the summary reflects verified working
        // endpoints (candidates phase 2 failed are excluded; v6 finds phase 2
        // never touched keep counting), mirroring the phase2_only path.
        let found = if phase2_configured {
            self.working_found()
        } else {
            ctx.found.load(Ordering::Relaxed)
        };
        Ok(self.finish(
            started,
            ctx.scanned.load(Ordering::Relaxed),
            found,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::ScanTarget;
    use crate::engine::tests::{controller, ok_cfg, run_local};
    use crate::probe::{FakeTransport, ProbeError, Transport};
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::time::Duration;

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
    async fn scans_v6_hosts_from_an_explicit_pool() {
        // Count(8) >= the /126 pool's 3 usable hosts, so the plan enumerates
        // every host; script the v6 addresses deterministically. (::0 is the
        // network address and comes back unanswered.)
        let t = FakeTransport::new()
            .ok("2606:4700::1".parse().unwrap(), 443, 20)
            .ok("2606:4700::2".parse().unwrap(), 443, 30)
            .ok("2606:4700::3".parse().unwrap(), 443, 10);
        let (c, _) = controller(Arc::new(t));
        let pool = ranges::CidrPool::parse("2606:4700::/126").unwrap();
        let summary = c
            .run_seeded_with_pool(ok_cfg(100, None), 1, pool)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 4);
        assert_eq!(summary.found, 3);
        let results = c.results();
        assert!(results.iter().all(|v| v.ip.is_ipv6()));
        assert_eq!(results[0].ip, "2606:4700::3".parse::<IpAddr>().unwrap());
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
        // Results are observed via the event stream: workers batch verdicts
        // into the store, so `results()` only catches up at flush/scan end.
        let t = Arc::new(
            FakeTransport::new()
                .ok_slow("10.0.0.1".parse().unwrap(), 443, 60, 200)
                .ok_slow("10.0.0.2".parse().unwrap(), 443, 60, 200),
        );
        let (c, mut rx) = controller(t.clone());
        let cfg = ok_cfg(10, None);
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await.unwrap() }
        });
        loop {
            let mut saw_result = false;
            while let Ok(e) = rx.try_recv() {
                if matches!(e, ScanEvent::Result(_)) {
                    saw_result = true;
                }
            }
            if saw_result {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        c.cancel();
        let summary = handle.await.unwrap();
        // Cancel halts the scan before all 8 hosts are probed.
        assert!(summary.scanned < 8, "scanned={}", summary.scanned);
        assert!(summary.found >= 1);
        assert!(summary.cancelled);
    }

    #[tokio::test]
    async fn cap_overshoot_is_bounded_by_worker_count() {
        // All hosts refuse; only the hard cap can end the run. Four workers
        // may each hold one in-flight probe past the cap check, so scanned
        // lands in [cap, cap + concurrency] = [3, 7] — bounded, no runaway.
        let (c, _) = controller(Arc::new(FakeTransport::new()));
        let mut cfg = ok_cfg(100, Some(3));
        cfg.concurrency = 4;
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 0);
        assert!(
            (3..=7).contains(&summary.scanned),
            "scanned={}",
            summary.scanned
        );
    }

    #[tokio::test]
    async fn cancel_racing_in_flight_probes_ends_consistently() {
        // 60ms probes leave a 60ms window between the 7th result and the
        // last probe finishing; cancel lands inside it. The summary must
        // agree with the store and end with Finished, not Failed.
        let mut t = FakeTransport::new();
        // The run_local /29 pool is hosts 10.0.0.0..=10.0.0.7: script every
        // one so the last probe is still in flight when the test cancels.
        for i in 0..=7u8 {
            t = t.ok_slow(format!("10.0.0.{i}").parse().unwrap(), 443, 60, 60);
        }
        let t = Arc::new(t);
        let (c, mut rx) = controller(t.clone());
        let cfg = ok_cfg(10, None);
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await.unwrap() }
        });
        let mut seen = 0;
        loop {
            while let Ok(e) = rx.try_recv() {
                if matches!(e, ScanEvent::Result(_)) {
                    seen += 1;
                }
            }
            if seen >= 7 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        c.cancel();
        let summary = handle.await.unwrap();
        assert!(
            summary.cancelled,
            "scanned={} found={} results={} seen={}",
            summary.scanned,
            summary.found,
            c.results().len(),
            seen
        );
        assert_eq!(
            summary.scanned, 8,
            "in-flight probe must finish before finish()"
        );
        assert_eq!(summary.found, 8);
        assert_eq!(
            c.results().len(),
            summary.found as usize,
            "store must match the summary"
        );
        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished(_))),
            "cancel must end with Finished, not Failed: {events:?}"
        );
    }

    #[tokio::test]
    async fn worker_panic_surfaces_as_failed_event() {
        struct PanicTransport;

        impl Transport for PanicTransport {
            fn probe(
                &self,
                _ip: IpAddr,
                _port: u16,
                _timeout_ms: u64,
            ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>> {
                Box::pin(async { panic!("probe blew up") })
            }
        }

        let c = Arc::new(ScanController::new(Arc::new(PanicTransport)));
        let mut cfg = ok_cfg(1, None);
        cfg.custom_cidrs = vec!["10.0.0.0/29".to_owned()];
        let err = c.run(cfg).await.unwrap_err();
        assert!(err.to_string().contains("panicked"), "{err:#}");
        assert!(!c.is_running(), "the reset guard must clear the busy flag");
    }

    #[tokio::test]
    async fn rejects_unsupported_modes() {
        let (c, _) = controller(Arc::new(FakeTransport::new()));
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
}
