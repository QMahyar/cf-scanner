//! CDN/proxy-mode phase-1 scan: TCP/TLS probes over the plan (port fan-out,
//! per-port host sampling) with stop-condition and cancel checks, then
//! optional phase-2 verification of the found candidates.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Result, anyhow};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::{ScanController, insert_sorted, plan_hosts, plan_probe_count, progress_cadence};
use crate::api::types::{ScanConfig, ScanEvent, ScanProgress, ScanSummary, Verdict};
use crate::probe::ProbeError;
use crate::ranges::{self, SplitMix64};

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

        let started = Instant::now();
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

        let (cancel_tx, cancel_rx) = watch::channel(false);
        *self.cancel_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancel_tx);

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
                    let geo = self.geo.clone();
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
                                    country: geo.country(ip),
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
                        if scanned.load(Ordering::Relaxed) % cadence == 0 {
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

        if let Some(p2) = phase2 {
            self.verify_phase(&cfg, &p2).await?;
        }

        Ok(self.finish(
            started,
            scanned.load(Ordering::Relaxed),
            found.load(Ordering::Relaxed),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::ScanTarget;
    use crate::engine::tests::{controller, ok_cfg, run_local};
    use crate::probe::FakeTransport;
    use std::net::{IpAddr, Ipv4Addr};
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
