use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{
    BATCH_FLUSH, ProbeContext, ScanController, merge_sorted, plan_hosts_iter, progress_cadence,
};
use crate::api::types::{
    ScanConfig, ScanEvent, ScanProgress, ScanSummary, ScanTarget, Verdict, WarpConfig,
};
use crate::engine::plan::{SplitMix64, plan};
use crate::probe::Transport;
use crate::ranges;

#[derive(Clone)]
struct WarpTask {
    ip: IpAddr,
    port: u16,
}

impl ScanController {
    pub(super) async fn run_warp(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let warp = cfg.warp.clone().unwrap_or_default();
        let probes_per_endpoint = warp.probes_per_endpoint.max(1) as u64;
        let transport: Arc<dyn Transport> = if warp.verify_with_wgconf {
            let text = warp
                .wgconf
                .as_deref()
                .ok_or_else(|| anyhow!("verify_with_wgconf requires a wgconf"))?;
            let wg = crate::wgconf::parse_wg_entry(text)
                .map_err(|e| anyhow!("invalid wgconf: {e:#}"))?;
            if let Some(cache) = &self.warp_cache {
                Arc::new(crate::warp::WgVerifyTransport::with_cache(cache.clone(), &wg).await?)
            } else {
                Arc::new(crate::warp::WgVerifyTransport::from_config(&wg)?)
            }
        } else if let Some(cache) = &self.warp_cache {
            Arc::new(crate::warp::WarpTransport::with_cache(cache.clone()).await?)
        } else {
            self.warp_transport.clone()
        };

        let started = Instant::now();
        self.clear_store();
        let groups = self.warp_groups(&cfg, &warp, seed)?;
        let total = groups
            .iter()
            .map(|(_, ports)| ports.len() as u64)
            .sum::<u64>();
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
            let (tx, rx) = mpsc::channel::<WarpTask>(per_worker_cap);
            worker_txs.push(tx);
            worker_rxs.push(rx);
        }

        let producer = {
            let ctx = Arc::clone(&ctx);
            let groups = groups.clone();
            tokio::spawn(async move {
                let mut idx: usize = 0;
                'outer: for (ip, ports) in &groups {
                    let ip = IpAddr::from(*ip);
                    for &port in ports.iter() {
                        let task = WarpTask { ip, port };
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
            })
        };

        let mut workers = JoinSet::new();
        for mut rx in worker_rxs {
            let ctx = Arc::clone(&ctx);
            let transport = transport.clone();
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
                    let mut latency_ms: Option<u32> = None;
                    let mut failed = 0u64;
                    let mut cancelled = false;
                    for _ in 0..probes_per_endpoint {
                        if ctx.should_stop() {
                            cancelled = true;
                            break;
                        }
                        let outcome = tokio::select! {
                            outcome = transport.probe(task.ip, task.port, timeout_ms) => Some(outcome),
                            _ = ctx.cancelled() => None,
                        };
                        let Some(outcome) = outcome else {
                            cancelled = true;
                            break;
                        };
                        match outcome {
                            Ok(latency) => {
                                latency_ms = Some(latency_ms.map_or(latency, |m| m.min(latency)));
                            }
                            Err(_) => failed += 1,
                        }
                    }
                    if cancelled {
                        break;
                    }
                    ctx.scanned.fetch_add(1, Ordering::Relaxed);
                    if let Some(latency) = latency_ms.filter(|_| failed == 0) {
                        ctx.found.fetch_add(1, Ordering::Relaxed);
                        let verdict = Box::new(Verdict {
                            ip: task.ip,
                            port: task.port,
                            latency_ms: Some(latency),
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
                return Err(anyhow!("WARP probe worker panicked: {join_err}"));
            }
        }
        producer
            .await
            .map_err(|e| anyhow!("WARP probe producer panicked: {e}"))?;

        Ok(self.finish(
            started,
            ctx.scanned.load(Ordering::Relaxed),
            ctx.found.load(Ordering::Relaxed),
        ))
    }

    fn warp_groups(
        &self,
        cfg: &ScanConfig,
        warp: &WarpConfig,
        seed: u64,
    ) -> Result<Vec<(std::net::Ipv4Addr, Arc<Vec<u16>>)>> {
        let ports = Arc::new(cfg.ports.iter().map(|p| p.get()).collect::<Vec<u16>>());
        let mut groups = Vec::new();
        if warp.custom_endpoints.is_empty() {
            let excluded = cfg
                .exclude
                .iter()
                .map(|c| {
                    ranges::parse_cidr(c).with_context(|| format!("invalid exclusion CIDR {c:?}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let pool = crate::warp::bundled_pool().excluding(&excluded);
            let plan = plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
            let mut rng = SplitMix64::new(seed);
            for item in &plan {
                for host in plan_hosts_iter(item, &mut rng) {
                    match host {
                        IpAddr::V4(ip) => groups.push((ip, ports.clone())),
                        IpAddr::V6(_) => bail!("WARP pools must stay IPv4"),
                    }
                }
            }
        } else {
            let mut seen: HashSet<(std::net::Ipv4Addr, u16)> = HashSet::new();
            for ep in &warp.custom_endpoints {
                let (ip, port) = parse_endpoint(ep)?;
                let claimed = match port {
                    Some(p) => vec![p],
                    None => (*ports).clone(),
                };
                let fresh: Vec<u16> = claimed
                    .into_iter()
                    .filter(|p| seen.insert((ip, *p)))
                    .collect();
                if !fresh.is_empty() {
                    groups.push((ip, Arc::new(fresh)));
                }
            }
            if let ScanTarget::Count(n) = cfg.target {
                let mut rng = SplitMix64::new(seed ^ 0x5EED);
                while groups.len() > n as usize {
                    let idx = rng.below(groups.len() as u64) as usize;
                    groups.swap_remove(idx);
                }
            }
        }
        Ok(groups)
    }
}

fn parse_endpoint(s: &str) -> Result<(std::net::Ipv4Addr, Option<u16>)> {
    let (ip, port) = crate::api::types::parse_endpoint(s).map_err(|e| anyhow!("{e}"))?;
    let IpAddr::V4(ip) = ip else {
        bail!("invalid endpoint {s:?}");
    };
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{
        CdnPreset, MAX_SCAN_COUNT, Mode, Port, ScanConfig, ScanEvent, ScanTarget, StopCondition,
        WarpConfig,
    };
    use crate::engine::tests::run_local;
    use crate::probe::{FakeTransport, ProbeError};

    fn warp_cfg(probes: u8, endpoints: &[&str]) -> ScanConfig {
        ScanConfig {
            mode: Mode::Warp,
            target: ScanTarget::Count(10),
            stop: StopCondition {
                found: 5,
                cap: None,
            },
            ports: vec![Port::new(2408)],
            concurrency: 1,
            warp: Some(WarpConfig {
                probes_per_endpoint: probes,
                custom_endpoints: endpoints.iter().map(|s| (*s).to_owned()).collect(),
                ..Default::default()
            }),
            ..ScanConfig::default()
        }
    }

    fn warp_controller(
        t: FakeTransport,
    ) -> (
        Arc<ScanController>,
        tokio::sync::broadcast::Receiver<ScanEvent>,
    ) {
        let t = Arc::new(t);
        let controller = Arc::new(ScanController::with_transports(t.clone(), t.clone()));
        let rx = controller.subscribe();
        (controller, rx)
    }

    #[tokio::test]
    async fn warp_measures_loss_and_min_latency() {
        let t = FakeTransport::new()
            .seq(
                "203.0.113.1".parse().unwrap(),
                2408,
                vec![Ok(5), Ok(7), Ok(6)],
            )
            .seq(
                "203.0.113.2".parse().unwrap(),
                2408,
                vec![
                    Ok(9),
                    Err(ProbeError::Timeout { timeout_ms: 3000 }),
                    Err(ProbeError::Timeout { timeout_ms: 3000 }),
                ],
            );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, warp_cfg(3, &["203.0.113.1", "203.0.113.2"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(summary.scanned, 2);
        let results = c.results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].latency_ms, Some(5));
    }

    #[tokio::test]
    async fn warp_custom_endpoint_port_overrides_cfg_ports() {
        let t = FakeTransport::new().ok("203.0.113.9".parse().unwrap(), 1234, 12);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["203.0.113.9:1234"]);
        cfg.ports = vec![Port::new(2408)];
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(c.results()[0].port, 1234);
    }

    #[tokio::test]
    async fn warp_closed_endpoints_produce_no_verdicts() {
        let (c, _) = warp_controller(FakeTransport::new());
        let summary = run_local(&c, warp_cfg(2, &["203.0.113.5"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0);
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn warp_stop_condition_stops_early() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 2408, 5)
            .ok("203.0.113.2".parse().unwrap(), 2408, 5)
            .ok("203.0.113.3".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
        cfg.stop = StopCondition {
            found: 1,
            cap: None,
        };
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(summary.scanned, 1, "later groups must not start");
    }

    #[tokio::test]
    async fn warp_full_pool_scan_visits_every_endpoint() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &[]);
        cfg.target = ScanTarget::Count(MAX_SCAN_COUNT);
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 8 * 256, "all bundled pool hosts");
        assert_eq!(summary.found, 0);
    }

    #[test]
    fn warp_plan_shares_rng_across_items() {
        let pool = crate::warp::bundled_pool();
        let blocks = pool.ranges().to_vec();
        assert!(
            blocks.len() >= 2,
            "bundled pool must decompose to >=2 items"
        );
        assert!(
            blocks.iter().all(|b| b.prefix >= 24),
            "test assumes per-block /24 sampling"
        );
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &[]);
        cfg.target = ScanTarget::Preset(CdnPreset::Quick);
        let groups = c.warp_groups(&cfg, cfg.warp.as_ref().unwrap(), 42).unwrap();
        assert_eq!(groups.len(), blocks.len(), "one sampled host per block");
        let offsets: HashSet<u8> = groups
            .iter()
            .map(|(ip, _)| (u32::from(*ip) & 0xff) as u8)
            .collect();
        assert!(
            offsets.len() > 1,
            "sampled offsets must differ across items: {offsets:?}"
        );
    }

    #[test]
    fn warp_rejects_unparsable_exclusion_cidrs() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &[]);
        cfg.exclude = vec!["203.0.113.0/33".to_owned()];
        let err = c
            .warp_groups(&cfg, cfg.warp.as_ref().unwrap(), 1)
            .expect_err("an unparsable --exclude CIDR must fail the plan");
        assert!(err.to_string().contains("203.0.113.0/33"), "{err:#}");
    }

    #[tokio::test]
    async fn warp_exclusion_removes_space_from_the_bundled_pool() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &[]);
        cfg.exclude = vec!["0.0.0.0/0".to_owned()];
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 0, "excluded space must never be probed");
        assert_eq!(summary.found, 0);
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn warp_duplicate_custom_endpoints_probe_once() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let cfg = warp_cfg(1, &["203.0.113.1", "203.0.113.1", "203.0.113.1:2408"]);
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 1, "duplicate endpoints must probe once");
        assert_eq!(summary.found, 1);
    }

    #[tokio::test]
    async fn warp_overlapping_endpoint_entries_dedupe_at_port_granularity() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 2408, 5)
            .ok("203.0.113.1".parse().unwrap(), 2409, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["203.0.113.1", "203.0.113.1:2408"]);
        cfg.ports = vec![Port::new(2408), Port::new(2409)];
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 2, "(ip, 2408) once, (ip, 2409) once");
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn warp_progress_total_counts_endpoint_port_pairs() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 2408, 5)
            .ok("203.0.113.1".parse().unwrap(), 2409, 5);
        let (c, mut rx) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["203.0.113.1"]);
        cfg.ports = vec![Port::new(2408), Port::new(2409)];
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 2, "scanned counts (endpoint, port) tasks");
        let mut progress = Vec::new();
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Progress(p) = e {
                progress.push(p);
            }
        }
        assert!(!progress.is_empty(), "the initial progress event must fire");
        assert!(
            progress.iter().all(|p| p.total == Some(2)),
            "progress total must count (endpoint, port) tasks, got {progress:?}"
        );
    }

    #[tokio::test]
    async fn warp_count_caps_custom_endpoints_by_sampling() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 2408, 5)
            .ok("203.0.113.2".parse().unwrap(), 2408, 5)
            .ok("203.0.113.3".parse().unwrap(), 2408, 5)
            .ok("203.0.113.4".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(
            1,
            &["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
        );
        cfg.target = ScanTarget::Count(2);
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            summary.scanned, 2,
            "Count caps the explicit list by sampling"
        );
        assert_eq!(summary.found, 2);
    }

    #[tokio::test]
    async fn warp_verify_fails_fast_without_a_wgconf() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &["203.0.113.1"]);
        cfg.warp = Some(WarpConfig {
            verify_with_wgconf: true,
            ..Default::default()
        });
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("requires wgconf"), "{err:#}");
    }

    #[tokio::test]
    async fn warp_verify_rejects_an_invalid_wgconf_before_probing() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &["203.0.113.1"]);
        cfg.warp = Some(WarpConfig {
            verify_with_wgconf: true,
            wgconf: Some("not a wgconf at all".to_owned()),
            ..Default::default()
        });
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("invalid wgconf"), "{err:#}");
        assert!(c.results().is_empty());
    }
}
