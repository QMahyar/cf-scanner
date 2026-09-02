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
use crate::engine::plan::{SplitMix64, plan};
use crate::ranges;

#[derive(Clone)]
struct ProbeTask {
    ip: IpAddr,
    port: u16,
}

impl ScanController {
    pub(super) async fn run_cdn(
        &self,
        mut cfg: ScanConfig,
        seed: u64,
        pool: ranges::CidrPool,
    ) -> Result<ScanSummary> {
        let phase2 = cfg.phase2.take();
        let phase2_configured = phase2.is_some();

        let started = Instant::now();
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
        let plan = plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
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

        let cancel_rx = self.cancel_signal();

        let ctx = Arc::new(ProbeContext {
            cancel: cancel_rx,
            stop: cfg.stop.clone(),
            scanned: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicU64::new(0)),
            last_milestone: AtomicU64::new(0),
            cadence,
            total,
            store: self.store.clone(),
            dirty: self.store_dirty.clone(),
            events: self.events.clone(),
            geo: self.geo.clone(),
        });

        let concurrency = usize::from(cfg.concurrency).max(1);
        let per_worker_cap: usize = 4;
        let mut worker_txs = Vec::with_capacity(concurrency);
        let mut worker_rxs = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let (tx, rx) = mpsc::channel::<ProbeTask>(per_worker_cap);
            worker_txs.push(tx);
            worker_rxs.push(rx);
        }

        let producer = {
            let ctx = Arc::clone(&ctx);
            let cfg = cfg.clone();
            let plan = plan.clone();
            tokio::spawn(async move {
                let mut rngs: Vec<SplitMix64> = cfg
                    .ports
                    .iter()
                    .map(|p| SplitMix64::new(seed ^ p.get() as u64))
                    .collect();
                let mut idx: usize = 0;
                'outer: for item in &plan {
                    for (port_idx, port) in cfg.ports.iter().enumerate() {
                        let rng = &mut rngs[port_idx];
                        for host in plan_hosts_iter(item, rng) {
                            let task = ProbeTask {
                                ip: host,
                                port: port.get(),
                            };
                            let w = idx % concurrency;
                            idx = idx.wrapping_add(1);
                            if ctx.should_stop() {
                                break 'outer;
                            }
                            tokio::select! {
                                r = worker_txs[w].send(task) => {
                                    if r.is_err() {
                                        break 'outer;
                                    }
                                }
                                _ = ctx.cancelled() => break 'outer,
                            }
                        }
                    }
                }
            })
        };

        let mut workers = JoinSet::new();
        for mut rx in worker_rxs {
            let ctx = Arc::clone(&ctx);
            let transport = self.transport.clone();
            let timeout_ms = cfg.timeout_ms;
            workers.spawn(async move {
                let mut batch: Vec<Verdict> = Vec::new();
                loop {
                    if ctx.should_stop() {
                        break;
                    }
                    let task = tokio::select! {
                        maybe = rx.recv() => match maybe {
                            Some(task) => task,
                            None => break,
                        },
                        _ = ctx.cancelled() => break,
                    };
                    let outcome = tokio::select! {
                        outcome = transport.probe(task.ip, task.port, timeout_ms) => Some(outcome),
                        _ = ctx.cancelled() => None,
                    };
                    let Some(outcome) = outcome else {
                        break;
                    };
                    ctx.scanned.fetch_add(1, Ordering::Relaxed);
                    if let Ok(latency_ms) = outcome {
                        ctx.found.fetch_add(1, Ordering::Relaxed);
                        let verdict = Box::new(Verdict {
                            ip: task.ip,
                            port: task.port,
                            latency_ms: Some(latency_ms),
                            country: ctx.geo.country(task.ip),
                            colo: None,
                            phase2: None,
                        });
                        let _ = ctx.events.send(ScanEvent::Result(verdict.clone()));
                        batch.push(*verdict);
                        if batch.len() >= BATCH_FLUSH {
                            merge_sorted(&ctx.store, &ctx.dirty, std::mem::take(&mut batch));
                        }
                    }
                    let scanned = ctx.scanned.load(Ordering::Relaxed);
                    if ctx.milestone_due(scanned) {
                        ctx.progress(scanned, ctx.found.load(Ordering::Relaxed));
                    }
                }
                merge_sorted(&ctx.store, &ctx.dirty, batch);
            });
        }

        while let Some(res) = workers.join_next().await {
            if let Err(join_err) = res {
                producer.abort();
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

        let found = if phase2_configured {
            self.working_found()
        } else {
            ctx.found.load(Ordering::Relaxed)
        };
        Ok(self.finish(started, ctx.scanned.load(Ordering::Relaxed), found))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Port, ScanTarget};
    use crate::engine::tests::{controller, ok_cfg, run_local};
    use crate::probe::{FakeTransport, ProbeError, Transport};
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::time::Duration;

    #[tokio::test]
    async fn collects_verdicts_until_found_stop() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10)
            .ok("203.0.113.3".parse().unwrap(), 443, 30);
        let (c, mut rx) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(2, None), 1).await.unwrap();
        assert_eq!(summary.found, 2);
        assert_eq!(summary.scanned, 3);
        let results = c.results();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ip, "203.0.113.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(results[1].ip, "203.0.113.1".parse::<Ipv4Addr>().unwrap());
        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(matches!(events.last(), Some(ScanEvent::Finished(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Result(_))));
    }

    #[tokio::test]
    async fn progress_milestones_are_monotonic_and_unique() {
        let t = FakeTransport::new();
        for i in 0..1024u32 {
            t.insert(
                format!("203.0.{}.{}", 113 + i / 256, i % 256)
                    .parse()
                    .unwrap(),
                443,
                Ok(i % 97),
            );
        }
        let (c, mut rx) = controller(Arc::new(t));
        let mut cfg = ok_cfg(1024, None);
        cfg.custom_cidrs = vec!["203.0.113.0/22".to_owned()];
        cfg.target = ScanTarget::Count(1024);
        cfg.concurrency = 16;
        let pool = ranges::CidrPool::parse("203.0.113.0/22").unwrap();
        let summary = c.run_seeded_with_pool(cfg, 1, pool).await.unwrap();
        assert_eq!(summary.scanned, 1024);
        let mut progress = Vec::new();
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Progress(p) = e {
                progress.push(p.scanned);
            }
        }
        assert!(
            progress.len() >= 2,
            "several milestones expected: {progress:?}"
        );
        assert!(
            progress.windows(2).all(|w| w[0] < w[1]),
            "scanned values must strictly increase: {progress:?}"
        );
    }

    #[tokio::test]
    async fn cap_limits_probes() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 1)
            .ok("203.0.113.2".parse().unwrap(), 443, 1);
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(100, Some(3)), 1).await.unwrap();
        assert_eq!(summary.scanned, 3);
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn exhausts_pool_when_found_unreachable() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 5);
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, ok_cfg(10, None), 1).await.unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(summary.scanned, 8, "all 8 hosts must be probed");
    }

    #[tokio::test]
    async fn scans_v6_hosts_from_an_explicit_pool() {
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
            .ok("203.0.113.1".parse().unwrap(), 443, 1)
            .ok("203.0.113.1".parse().unwrap(), 8443, 1);
        let mut cfg = ok_cfg(2, None);
        cfg.ports = vec![Port::new(443), Port::new(8443)];
        let (c, _) = controller(Arc::new(t));
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn cancel_without_active_run_is_noop() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 1)
            .ok("203.0.113.2".parse().unwrap(), 443, 1);
        let (c, _) = controller(Arc::new(t));
        c.cancel();
        let summary = run_local(&c, ok_cfg(5, None), 1).await.unwrap();
        assert_eq!(summary.found, 2);
        assert_eq!(summary.scanned, 8);
    }

    #[tokio::test]
    async fn cancel_stops_mid_scan() {
        let t = Arc::new(
            FakeTransport::new()
                .ok_slow("203.0.113.1".parse().unwrap(), 443, 60, 200)
                .ok_slow("203.0.113.2".parse().unwrap(), 443, 60, 200),
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
        assert!(summary.scanned < 8, "scanned={}", summary.scanned);
        assert!(summary.found >= 1);
        assert!(summary.cancelled);
    }

    #[tokio::test]
    async fn cap_overshoot_is_bounded_by_worker_count() {
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
        let mut t = FakeTransport::new();
        for i in 0..=7u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 60, 60);
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
        assert!(
            (7..=8).contains(&summary.scanned),
            "scanned={}",
            summary.scanned
        );
        assert_eq!(summary.found, summary.scanned);
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
        cfg.custom_cidrs = vec!["203.0.113.0/29".to_owned()];
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
        for i in 1..=254u8 {
            t.insert(
                format!("203.0.113.{i}").parse().unwrap(),
                443,
                Ok((i % 50) as u32),
            );
        }
        let mut cfg = ok_cfg(100, None);
        cfg.target = ScanTarget::Count(60);
        let (c, mut rx) = controller(Arc::new(t));
        let pool = ranges::CidrPool::parse("203.0.113.0/24").unwrap();
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
        let t = Arc::new(FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 5));
        let (c, _) = controller(t.clone());
        let _ = run_local(&c, ok_cfg(1, None), 1).await.unwrap();
        assert_eq!(c.results().len(), 1);
        t.clear();
        let _ = run_local(&c, ok_cfg(1, None), 1).await.unwrap();
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn same_seed_resamples_identical_hosts() {
        let mut cfg = ok_cfg(8, None);
        cfg.target = ScanTarget::Count(8);
        let mut sampled: Vec<Vec<IpAddr>> = Vec::new();
        for _ in 0..2 {
            let t = FakeTransport::new();
            for i in 1..=254u8 {
                t.insert(
                    format!("203.0.113.{i}").parse().unwrap(),
                    443,
                    Ok(u32::from(i) % 100),
                );
            }
            let (c, _) = controller(Arc::new(t));
            let pool = ranges::CidrPool::parse("203.0.113.0/24").unwrap();
            let summary = c.run_seeded_with_pool(cfg.clone(), 42, pool).await.unwrap();
            assert_eq!(summary.scanned, 8, "found stop must fire after 8 probes");
            sampled.push(c.results().iter().map(|v| v.ip).collect());
        }
        assert_eq!(
            sampled[0], sampled[1],
            "the same seed must sample the same host set"
        );
    }

    #[tokio::test]
    async fn rejects_invalid_config() {
        let (c, _) = controller(Arc::new(FakeTransport::new()));
        let mut cfg = ok_cfg(1, None);
        cfg.ports = vec![Port::new(0)];
        assert!(run_local(&c, cfg, 1).await.is_err());
    }
}
