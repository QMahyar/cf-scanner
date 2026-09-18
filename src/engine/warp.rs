use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use super::plan::plan_hosts_iter;
use super::{ProbeContext, ScanController, cancelled_signal, merge_sorted, progress_cadence};
use crate::api::types::{
    DEFAULT_PROBES_PER_ENDPOINT, DEFAULT_WARP_PORTS, Port, ScanConfig, ScanEvent, ScanProgress,
    ScanSummary, ScanTarget, Verdict, WarpConfig,
};
use crate::engine::plan::{SplitMix64, plan};
use crate::probe::Transport;
use crate::ranges;

#[derive(Clone)]
struct WarpTask {
    ip: IpAddr,
    port: u16,
}

/// P0-6 torn-down signal: endpoints that answer the handshake then die
/// mid-stream are stored export-only (never working). Active only when the
/// probe budget allows a trailing-run read; the default-3 path stays dormant
/// and byte-identical.
const TORN_MIN_PROBES: u64 = 4;
/// Trailing unanswered run that marks a mid-stream death.
const TORN_TRAILING_UNANSWERED: u32 = 3;
/// Minimum total burst (initial probes + confirm probes) before calling torn.
const TORN_MIN_BURST: u32 = 5;
/// Shared torn-down wording: the WARP export-only fail_reason, and (by
/// wording) the phase-2 / wgconf verify errors for the same mid-stream
/// death. Latency stays None so latency.is_some() <=> working holds.
pub(crate) const TORN_DOWN_REASON: &str = "torn_down";

/// P0-7 adaptive pre-flight (`--adaptive-retries`, WARP-only, never
/// default-on): exactly this many single handshake probes over the bundled
/// pool plan before the scan, each bounded by the scan timeout. Zero
/// verdicts are recorded; the only effect is a raised probe budget.
pub(crate) const ADAPTIVE_PREFLIGHT_SAMPLES: usize = 100;
/// Ladder thresholds (spec P0-7(a)): loss/p50/jitter past these raise the
/// budget. Jitter is p90-p50 over successful probes only.
const ADAPTIVE_LOSS_BUMP: u32 = 10;
const ADAPTIVE_LOSS_HIGH: u32 = 25;
const ADAPTIVE_P50_MS: u32 = 800;
const ADAPTIVE_JITTER_MS: u32 = 1500;
const ADAPTIVE_BUMPED_PROBES: u8 = 5;
const ADAPTIVE_HIGH_PROBES: u8 = 7;
/// The ladder never recommends above this (== the WarpConfig 1..=10 cap).
const ADAPTIVE_MAX_PROBES: u8 = 10;
/// Domain-separates pre-flight sampling from the main scan plan.
const ADAPTIVE_SEED_XOR: u64 = 0x51ab3c0ffee77aa;
/// Domain-separates port-gate sampling from the main scan plan.
const GATE_SEED_XOR: u64 = 0x9e3779b97f4a7c15;

/// Outcome of the adaptive pre-flight. `None` from `warp_preflight` means a
/// clean Ctrl+C abort: nothing was recorded and the scan must stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreflightReport {
    pub samples: usize,
    pub failed: u32,
    pub loss_pct: u32,
    pub p50_ms: u32,
    pub p90_ms: u32,
    pub jitter_ms: u32,
    pub previous_probes: u8,
    pub applied_probes: u8,
}

impl PreflightReport {
    fn build(samples: usize, failed: u32, mut latencies: Vec<u32>, previous: u8) -> Self {
        let loss_pct = if samples == 0 {
            0
        } else {
            failed.saturating_mul(100) / samples as u32
        };
        latencies.sort_unstable();
        let (p50_ms, p90_ms) = match latencies.len() {
            0 => (0, 0),
            _ => (percentile(&latencies, 50), percentile(&latencies, 90)),
        };
        let jitter_ms = p90_ms.saturating_sub(p50_ms);
        let applied_probes = adaptive_recommendation(previous, loss_pct, p50_ms, jitter_ms);
        Self {
            samples,
            failed,
            loss_pct,
            p50_ms,
            p90_ms,
            jitter_ms,
            previous_probes: previous,
            applied_probes,
        }
    }

    /// The exact stderr lines for a pre-flight outcome: what was measured
    /// plus the reusable re-run command. stdout NDJSON is never touched.
    pub(crate) fn stderr_lines(&self) -> [String; 2] {
        let summary = if self.samples == 0 {
            format!(
                "warp pre-flight: 0 samples (pool fully excluded) → probes {} (unchanged)",
                self.previous_probes
            )
        } else if self.applied_probes == self.previous_probes {
            format!(
                "warp pre-flight: {} samples, loss {}%, p50 {}ms, p90 {}ms, jitter {}ms → probes {} (unchanged)",
                self.samples,
                self.loss_pct,
                self.p50_ms,
                self.p90_ms,
                self.jitter_ms,
                self.previous_probes
            )
        } else {
            format!(
                "warp pre-flight: {} samples, loss {}%, p50 {}ms, p90 {}ms, jitter {}ms → probes {} → {}",
                self.samples,
                self.loss_pct,
                self.p50_ms,
                self.p90_ms,
                self.jitter_ms,
                self.previous_probes,
                self.applied_probes
            )
        };
        [summary, preflight_rerun_line(self.applied_probes)]
    }
}

/// Reusable re-run command: repeats the scan with the adapted budget so the
/// pre-flight can be skipped next time. Pure so the wording stays pinned.
pub(crate) fn preflight_rerun_line(probes: u8) -> String {
    format!("re-run: cf-scanner scan --mode warp --warp-probes {probes}")
}

/// Nearest-rank percentile over ascending-sorted latencies.
fn percentile(sorted: &[u32], pct: usize) -> u32 {
    let n = sorted.len();
    debug_assert!(n > 0);
    if n == 0 {
        return 0;
    }
    let rank = (pct * n).div_ceil(100);
    sorted[rank.saturating_sub(1).min(n - 1)]
}

/// Pure ladder: loss/p50/jitter past threshold raises the budget, the
/// current budget is never lowered, and the result never exceeds 10.
/// Unit-tested at every threshold edge; the CLI guarantees `current` is
/// never an explicit user value (explicit wins skips the pre-flight).
pub(crate) fn adaptive_recommendation(
    current: u8,
    loss_pct: u32,
    p50_ms: u32,
    jitter_ms: u32,
) -> u8 {
    let ladder = if loss_pct > ADAPTIVE_LOSS_HIGH || jitter_ms > ADAPTIVE_JITTER_MS {
        ADAPTIVE_HIGH_PROBES
    } else if loss_pct > ADAPTIVE_LOSS_BUMP || p50_ms > ADAPTIVE_P50_MS {
        ADAPTIVE_BUMPED_PROBES
    } else {
        DEFAULT_PROBES_PER_ENDPOINT
    };
    ladder.max(current).min(ADAPTIVE_MAX_PROBES)
}

impl ScanController {
    pub(super) async fn run_warp(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        let mut cfg = cfg;
        let warp = cfg.warp.clone().unwrap_or_default();
        let mut probes_per_endpoint = warp.probes_per_endpoint.max(1);
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
            // WHY: junk knobs travel WarpConfig -> transport constructor so the
            // discovery probe honors them; junk-off builds exactly what
            // with_cache built before (cleared cache, OFF profile).
            let junk = crate::warp::JunkConfig::from_warp_config(&warp);
            Arc::new(crate::warp::WarpTransport::with_cache_and_junk(cache.clone(), junk).await?)
        } else {
            self.warp_transport.clone()
        };

        let started = Instant::now();
        if Self::gate_applies(&warp, &cfg.ports) {
            let cancel = self.cancel_signal();
            match Self::warp_port_gate(&transport, &cfg, seed, cfg.timeout_ms, &cancel).await? {
                Some(narrowed) => {
                    eprintln!(
                        "port gate: narrowed scan ports to [{}] ({} samples)",
                        narrowed
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                        crate::warp::PORT_GATE_SAMPLE
                    );
                    cfg.ports = narrowed.into_iter().map(Port::new).collect();
                }
                None => {
                    eprintln!(
                        "port gate: no WARP port answered on {} sampled endpoints; scan skipped",
                        crate::warp::PORT_GATE_SAMPLE
                    );
                    return Ok(self.finish(started, 0, 0));
                }
            }
            if *cancel.borrow() {
                return Ok(self.finish(started, 0, 0));
            }
        } else if warp.port_gate {
            eprintln!(
                "port gate skipped: explicit ports, custom endpoints, or wgconf verify in use"
            );
        }
        if cfg.adaptive_retries {
            let cancel = self.cancel_signal();
            match self
                .warp_preflight(&cfg, &transport, seed, probes_per_endpoint, &cancel)
                .await?
            {
                Some(report) => {
                    for line in report.stderr_lines() {
                        eprintln!("{line}");
                    }
                    probes_per_endpoint = report.applied_probes;
                }
                None => return Ok(self.finish(started, 0, 0)),
            }
        }
        let probes_per_endpoint = u64::from(probes_per_endpoint);
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
            store: self.progress.store.clone(),
            dirty: self.progress.store_dirty.clone(),
            events: self.events.clone(),
            geo: self.geo.clone(),
            colo_filter: Arc::new(Vec::new()),
            colo_warned: AtomicBool::new(false),
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
        let torn_active = probes_per_endpoint >= TORN_MIN_PROBES;
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
                    let mut sent: u32 = 0;
                    let mut received: u32 = 0;
                    let mut failed: u32 = 0;
                    let mut trailing_failed: u32 = 0;
                    let mut cancelled = false;
                    for _ in 0..probes_per_endpoint {
                        // Only a real cancel aborts mid-endpoint: a found/cap
                        // stop lets the in-flight endpoint finish so its work
                        // is counted and recorded, matching the CDN drain.
                        if ctx.is_cancelled() {
                            cancelled = true;
                            break;
                        }
                        let outcome = tokio::select! {
                            outcome = transport.probe(task.ip, task.port, timeout_ms, 0) => Some(outcome),
                            _ = ctx.cancelled() => None,
                        };
                        let Some(outcome) = outcome else {
                            cancelled = true;
                            break;
                        };
                        match outcome {
                            Ok(probe) => {
                                latency_ms =
                                    Some(latency_ms.map_or(probe.latency_ms, |m| {
                                        m.min(probe.latency_ms)
                                    }));
                                sent += probe.sent;
                                received += probe.received;
                                trailing_failed = 0;
                            }
                            Err(_) => {
                                sent += 1;
                                failed += 1;
                                trailing_failed += 1;
                            }
                        }
                    }
                    if cancelled {
                        break;
                    }
                    if torn_active
                        && latency_ms.is_some()
                        && trailing_failed >= TORN_TRAILING_UNANSWERED
                    {
                        // Confirm burst: top up to a minimum total burst so a
                        // transient tail is not mistaken for a torn-down path.
                        // Same select!+cancel race as the main probes; a cancel
                        // aborts without storing anything.
                        while sent < TORN_MIN_BURST && !ctx.is_cancelled() {
                            let outcome = tokio::select! {
                                outcome = transport.probe(task.ip, task.port, timeout_ms, 0) => Some(outcome),
                                _ = ctx.cancelled() => None,
                            };
                            let Some(outcome) = outcome else {
                                cancelled = true;
                                break;
                            };
                            match outcome {
                                Ok(probe) => {
                                    sent += probe.sent;
                                    received += probe.received;
                                    trailing_failed = 0;
                                }
                                Err(_) => {
                                    sent += 1;
                                    failed += 1;
                                    trailing_failed += 1;
                                }
                            }
                        }
                    }
                    if cancelled {
                        break;
                    }
                    // Release pairs with the Acquire reads in should_stop (see cdn.rs).
                    ctx.scanned.fetch_add(1, Ordering::Release);
                    if let Some(latency) = latency_ms.filter(|_| failed == 0) {
                        super::driver::record_and_batch(
                            &ctx,
                            &mut batch,
                            Verdict {
                                ip: task.ip,
                                port: task.port,
                                latency_ms: Some(latency),
                                country: ctx.geo.country(task.ip),
                                colo: None,
                                phase2: None,
                                sent,
                                received,
                                loss_pct: Some(0),
                                fail_reason: None,
                                asn: None,
                                isp: None,
                            },
                        );
                    } else if torn_active
                        && latency_ms.is_some()
                        && trailing_failed >= TORN_TRAILING_UNANSWERED
                    {
                        // Export-only torn row: latency None keeps it out of
                        // found/stop, live Result emission (record_and_batch
                        // gates both on latency), best/conf/bundle selection,
                        // and the speed-test shortlist; the end-of-scan store
                        // flush still carries it to csv/json + diagnostics.
                        let loss_pct =
                            failed.saturating_mul(100).checked_div(sent).unwrap_or(100);
                        super::driver::record_and_batch(
                            &ctx,
                            &mut batch,
                            Verdict {
                                ip: task.ip,
                                port: task.port,
                                latency_ms: None,
                                country: ctx.geo.country(task.ip),
                                colo: None,
                                phase2: None,
                                sent,
                                received,
                                loss_pct: Some(loss_pct),
                                fail_reason: Some(TORN_DOWN_REASON.to_owned()),
                                asn: None,
                                isp: None,
                            },
                        );
                    }
                    let scanned = ctx.scanned.load(Ordering::Relaxed);
                    if ctx.milestone_due(scanned) {
                        ctx.progress(scanned, ctx.found.load(Ordering::Relaxed));
                    }
                }
                merge_sorted(&ctx.store, &ctx.dirty, batch);
            });
        }

        super::driver::drain_workers(workers, producer, || self.cancel(), "WARP").await?;

        Ok(self.finish(
            started,
            ctx.scanned.load(Ordering::Relaxed),
            ctx.found.load(Ordering::Relaxed),
        ))
    }

    /// Opt-in adaptive pre-flight: exactly 100 single handshake probes over
    /// the bundled pool plan through the already-built transport (same
    /// ShapeOnly discovery semantics, per-controller SocketCache, junk
    /// profile as the scan itself). Each probe is bounded by the scan
    /// timeout; zero verdicts are recorded. Returns `None` on a clean
    /// Ctrl+C abort (the caller stops the scan with nothing recorded).
    async fn warp_preflight(
        &self,
        cfg: &ScanConfig,
        transport: &Arc<dyn Transport>,
        seed: u64,
        current: u8,
        cancel: &watch::Receiver<bool>,
    ) -> Result<Option<PreflightReport>> {
        let targets = Self::preflight_targets(cfg, seed)?;
        let timeout_ms = cfg.timeout_ms;
        let mut latencies: Vec<u32> = Vec::new();
        let mut failed: u32 = 0;
        for (ip, port) in &targets {
            // Pre-scan there is nothing to drain: found/cap cannot fire with
            // zero scanned/found, so the user-cancel latch is the whole stop
            // condition here. Checked every step, raced per probe below.
            if *cancel.borrow() {
                return Ok(None);
            }
            let outcome = tokio::select! {
                outcome = transport.probe(IpAddr::V4(*ip), *port, timeout_ms, 0) => Some(outcome),
                _ = cancelled_signal(cancel.clone()) => None,
            };
            let Some(outcome) = outcome else {
                return Ok(None);
            };
            match outcome {
                Ok(probe) => latencies.push(probe.latency_ms),
                Err(_) => failed += 1,
            }
        }
        if *cancel.borrow() {
            return Ok(None);
        }
        Ok(Some(PreflightReport::build(
            targets.len(),
            failed,
            latencies,
            current.max(1),
        )))
    }

    /// The pre-flight sample plan: 100 distinct bundled-pool hosts (same
    /// exclusion path as the scan), each paired with one configured port by
    /// rotation, so the probe count is exactly 100 whatever the port list.
    fn preflight_targets(cfg: &ScanConfig, seed: u64) -> Result<Vec<(Ipv4Addr, u16)>> {
        let ports: Vec<u16> = cfg.ports.iter().map(|p| p.get()).collect();
        if ports.is_empty() {
            bail!("adaptive pre-flight needs at least one port");
        }
        let pf_seed = seed ^ ADAPTIVE_SEED_XOR;
        Ok(
            Self::sample_pool_hosts(cfg, pf_seed, ADAPTIVE_PREFLIGHT_SAMPLES)?
                .into_iter()
                .enumerate()
                .map(|(i, ip)| (ip, ports[i % ports.len()]))
                .collect(),
        )
    }

    /// Sample up to n IPv4 hosts from the bundled WARP pool minus exclusions,
    /// on the given seed. Shared by the adaptive pre-flight and the port gate
    /// so both sample the same way; callers pair ports themselves.
    fn sample_pool_hosts(cfg: &ScanConfig, seed: u64, n: usize) -> Result<Vec<Ipv4Addr>> {
        let excluded = cfg
            .exclude
            .iter()
            .map(|c| ranges::parse_cidr(c).with_context(|| format!("invalid exclusion CIDR {c:?}")))
            .collect::<Result<Vec<_>>>()?;
        let pool = crate::warp::bundled_pool().excluding(&excluded);
        let plan = plan(
            &pool,
            &ScanTarget::Count(n as u32),
            &mut SplitMix64::new(seed),
        );
        let mut rng = SplitMix64::new(seed);
        let mut hosts: Vec<Ipv4Addr> = Vec::with_capacity(n);
        for item in &plan {
            for host in plan_hosts_iter(item, &mut rng) {
                match host {
                    IpAddr::V4(ip) => hosts.push(ip),
                    IpAddr::V6(_) => bail!("WARP pools must stay IPv4"),
                }
                if hosts.len() >= n {
                    break;
                }
            }
            if hosts.len() >= n {
                break;
            }
        }
        Ok(hosts)
    }

    /// Whether the opt-in port gate runs: default ports and pool sampling
    /// only. Explicit `--ports`/`--warp-endpoints` already narrow the scan,
    /// and wgconf verify does full sessions rather than shape probes, so all
    /// three skip it (warpscout's skip conditions).
    fn gate_applies(warp: &WarpConfig, ports: &[Port]) -> bool {
        warp.port_gate
            && warp.custom_endpoints.is_empty()
            && !warp.verify_with_wgconf
            && ports == DEFAULT_WARP_PORTS
    }

    /// Gate sample addresses: up to PORT_GATE_SAMPLE hosts on a
    /// domain-separated seed (same sampling path as the pre-flight).
    fn gate_sample_addrs(cfg: &ScanConfig, seed: u64) -> Result<Vec<Ipv4Addr>> {
        Self::sample_pool_hosts(cfg, seed ^ GATE_SEED_XOR, crate::warp::PORT_GATE_SAMPLE)
    }

    /// Probe one port tier: each (addr, port) once through the built
    /// transport. A port counts as open when any sample answers with a
    /// received packet. Cancel-safe: a fired cancel abandons the tier; the
    /// caller re-checks cancel before acting on the result.
    async fn gate_open_ports(
        transport: &Arc<dyn Transport>,
        addrs: &[Ipv4Addr],
        ports: &[u16],
        timeout_ms: u64,
        cancel: &watch::Receiver<bool>,
    ) -> Vec<u16> {
        let mut pending = JoinSet::new();
        'spawn: for &ip in addrs {
            for &port in ports {
                if *cancel.borrow() {
                    break 'spawn;
                }
                let transport = transport.clone();
                pending.spawn(async move {
                    let open = matches!(
                        transport.probe(ip.into(), port, timeout_ms, 0).await,
                        Ok(outcome) if outcome.received > 0
                    );
                    (port, open)
                });
            }
        }
        let mut open_ports = Vec::new();
        while !pending.is_empty() {
            tokio::select! {
                joined = pending.join_next() => {
                    let Some(joined) = joined else { break };
                    if let Ok((port, true)) = joined {
                        if !open_ports.contains(&port) {
                            open_ports.push(port);
                        }
                    }
                }
                _ = super::cancelled_signal(cancel.clone()) => {
                    pending.abort_all();
                    break;
                }
            }
        }
        open_ports.sort_unstable();
        open_ports
    }

    /// Run the gate: primaries first, extended escalation on total failure.
    /// Returns the narrowed scan ports, or None for total failure (the caller
    /// aborts with an empty summary, never an error). An empty sample (pool
    /// fully excluded) keeps the configured ports; the normal empty-pool
    /// path below reports it.
    async fn warp_port_gate(
        transport: &Arc<dyn Transport>,
        cfg: &ScanConfig,
        seed: u64,
        timeout_ms: u64,
        cancel: &watch::Receiver<bool>,
    ) -> Result<Option<Vec<u16>>> {
        use crate::warp::{EXTENDED_WARP_PORTS, PRIMARY_WARP_PORTS};
        let addrs = Self::gate_sample_addrs(cfg, seed)?;
        if addrs.is_empty() {
            return Ok(Some(cfg.ports.iter().map(|p| p.get()).collect()));
        }
        let open =
            Self::gate_open_ports(transport, &addrs, PRIMARY_WARP_PORTS, timeout_ms, cancel).await;
        if !open.is_empty() {
            return Ok(Some(open));
        }
        let open =
            Self::gate_open_ports(transport, &addrs, EXTENDED_WARP_PORTS, timeout_ms, cancel).await;
        Ok(if open.is_empty() { None } else { Some(open) })
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

    fn gate_cfg() -> ScanConfig {
        ScanConfig {
            mode: Mode::Warp,
            target: ScanTarget::Count(20),
            stop: StopCondition {
                found: 1000,
                cap: None,
            },
            ports: DEFAULT_WARP_PORTS.to_vec(),
            concurrency: 1,
            warp: Some(WarpConfig {
                probes_per_endpoint: 3,
                port_gate: true,
                ..Default::default()
            }),
            ..ScanConfig::default()
        }
    }

    #[test]
    fn gate_applies_only_to_default_pool_scans() {
        let on = WarpConfig {
            port_gate: true,
            ..Default::default()
        };
        assert!(ScanController::gate_applies(&on, DEFAULT_WARP_PORTS));
        assert!(!ScanController::gate_applies(
            &WarpConfig::default(),
            DEFAULT_WARP_PORTS
        ));
        let customs = WarpConfig {
            port_gate: true,
            custom_endpoints: vec!["203.0.113.1:2408".to_owned()],
            ..Default::default()
        };
        assert!(!ScanController::gate_applies(&customs, DEFAULT_WARP_PORTS));
        assert!(!ScanController::gate_applies(&on, &[Port::new(443)]));
        let verify = WarpConfig {
            port_gate: true,
            verify_with_wgconf: true,
            ..Default::default()
        };
        assert!(!ScanController::gate_applies(&verify, DEFAULT_WARP_PORTS));
    }

    #[test]
    fn gate_samples_are_bounded_unique_v4() {
        let cfg = gate_cfg();
        let addrs = ScanController::gate_sample_addrs(&cfg, 7).unwrap();
        assert_eq!(addrs.len(), crate::warp::PORT_GATE_SAMPLE);
        let uniq: HashSet<Ipv4Addr> = addrs.iter().copied().collect();
        assert_eq!(uniq.len(), addrs.len(), "samples must not repeat");
    }

    #[tokio::test]
    async fn gate_returns_narrowed_ports_or_none() {
        let cfg = gate_cfg();
        let gate_addrs = ScanController::gate_sample_addrs(&cfg, 9).unwrap();
        let mut t = FakeTransport::new();
        for ip in gate_addrs.iter().take(3) {
            t = t.ok((*ip).into(), 2408, 5);
        }
        t = t.ok(gate_addrs[3].into(), 500, 5);
        let transport: Arc<dyn Transport> = Arc::new(t);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let open = ScanController::warp_port_gate(&transport, &cfg, 9, 3000, &rx)
            .await
            .unwrap();
        assert_eq!(open, Some(vec![500, 2408]), "open ports in ascending order");

        let transport: Arc<dyn Transport> = Arc::new(FakeTransport::new());
        let open = ScanController::warp_port_gate(&transport, &cfg, 9, 3000, &rx)
            .await
            .unwrap();
        assert_eq!(open, None, "total failure on both tiers aborts");
    }

    #[tokio::test]
    async fn gate_total_failure_aborts_with_empty_summary() {
        let mut cfg = gate_cfg();
        cfg.target = ScanTarget::Count(10);
        let (c, _) = warp_controller(FakeTransport::new());
        let summary = run_local(&c, cfg, 3).await.unwrap();
        assert_eq!((summary.found, summary.scanned), (0, 0));
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn gate_narrows_the_scan_to_answering_ports() {
        let seed = 11u64;
        let cfg = gate_cfg();
        let warp = cfg.warp.clone().unwrap();
        // Deterministic samples: scripting the exact addresses both stages
        // draw pins the whole run offline.
        let gate_addrs: HashSet<Ipv4Addr> = ScanController::gate_sample_addrs(&cfg, seed)
            .unwrap()
            .into_iter()
            .collect();
        let dummy = Arc::new(ScanController::with_transports(
            Arc::new(FakeTransport::new()),
            Arc::new(FakeTransport::new()),
        ));
        let groups = dummy.warp_groups(&cfg, &warp, seed).unwrap();
        let main_addrs: HashSet<Ipv4Addr> = groups.iter().map(|(ip, _)| *ip).collect();
        let mut t = FakeTransport::new();
        for ip in main_addrs.union(&gate_addrs) {
            t = t.ok((*ip).into(), 2408, 5);
        }
        // 500 stays closed everywhere: the gate must drop the other defaults.
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, cfg, seed).await.unwrap();
        assert_eq!(
            summary.scanned,
            main_addrs.len() as u64,
            "narrowed scan probes each sampled endpoint once (port 2408 only)"
        );
        assert_eq!(summary.found, main_addrs.len() as u64);
        assert!(c.results().iter().all(|v| v.port == 2408));
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
    async fn warp_stop_condition_counts_only_zero_loss_endpoints() {
        let t = FakeTransport::new()
            .seq(
                "203.0.113.1".parse().unwrap(),
                2408,
                vec![Ok(5), Err(ProbeError::Timeout { timeout_ms: 3000 })],
            )
            .ok("203.0.113.2".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(2, &["203.0.113.1", "203.0.113.2"]);
        cfg.stop = StopCondition {
            found: 1,
            cap: None,
        };
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            summary.scanned, 2,
            "a lossy endpoint must not satisfy stop.found"
        );
        assert_eq!(summary.found, 1);
        assert_eq!(c.results()[0].ip, "203.0.113.2".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn warp_found_stop_lets_the_in_flight_endpoint_finish() {
        let t = FakeTransport::new()
            .ok_slow("203.0.113.1".parse().unwrap(), 2408, 5, 30)
            .ok_slow("203.0.113.2".parse().unwrap(), 2408, 7, 150);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(2, &["203.0.113.1", "203.0.113.2"]);
        cfg.stop = StopCondition {
            found: 1,
            cap: None,
        };
        cfg.concurrency = 2;
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            summary.scanned, 2,
            "the endpoint mid-flight at the found stop must still be counted"
        );
        assert_eq!(summary.found, 2);
        let ips: HashSet<IpAddr> = c.results().iter().map(|v| v.ip).collect();
        assert!(
            ips.contains(&"203.0.113.2".parse::<IpAddr>().unwrap()),
            "the in-flight endpoint must be recorded, got {ips:?}"
        );
    }

    #[tokio::test]
    async fn warp_cancel_races_in_flight_probes() {
        let mut t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 2408, 5);
        t.rendezvous = Some(Arc::new(tokio::sync::Barrier::new(2)));
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(2, &["203.0.113.1"]);
        cfg.stop = StopCondition {
            found: 100,
            cap: None,
        };
        cfg.concurrency = 1;
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c.cancel();
        let summary = handle.await.unwrap();
        assert!(
            summary.cancelled,
            "the run must report the cancel: scanned={} found={}",
            summary.scanned, summary.found
        );
        assert_eq!(summary.scanned, 0, "the parked probe must never complete");
        assert_eq!(summary.found, 0);
        assert!(c.results().is_empty(), "no verdict from an aborted probe");
    }

    #[tokio::test]
    async fn warp_completed_endpoints_keep_store_in_sync_with_summary() {
        let mut t = FakeTransport::new();
        for i in 1..=4u8 {
            t = t.ok(format!("203.0.113.{i}").parse().unwrap(), 2408, 5);
        }
        let (c, _) = warp_controller(t);
        let cfg = warp_cfg(
            1,
            &["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
        );
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert!(!summary.cancelled);
        assert_eq!(summary.found, 4);
        assert_eq!(summary.scanned, 4);
        assert_eq!(
            c.results().len(),
            summary.found as usize,
            "store must match the summary"
        );
    }

    #[tokio::test]
    async fn warp_full_pool_scan_visits_every_endpoint() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = warp_cfg(1, &[]);
        cfg.target = ScanTarget::Count(MAX_SCAN_COUNT);
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 15 * 256, "all bundled pool hosts");
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

    fn torn_timeout() -> Result<u32, ProbeError> {
        Err(ProbeError::Timeout { timeout_ms: 3000 })
    }

    #[tokio::test]
    async fn warp_torn_endpoint_stored_export_only_with_probes_4() {
        // One answer then death: the main burst [ok, err, err, err] trips the
        // trailing-3 read, and the confirm burst (5th probe, served by the
        // sequence repeat) seals it as torn down.
        let t = FakeTransport::new().seq(
            "203.0.113.1".parse().unwrap(),
            2408,
            vec![Ok(5), torn_timeout(), torn_timeout(), torn_timeout()],
        );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, warp_cfg(4, &["203.0.113.1"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0, "a torn row must never count as found");
        let results = c.results();
        assert_eq!(results.len(), 1);
        let torn = &results[0];
        assert_eq!(torn.latency_ms, None, "latency.is_some() <=> working");
        assert_eq!(torn.fail_reason.as_deref(), Some(TORN_DOWN_REASON));
        assert_eq!(
            TORN_DOWN_REASON, "torn_down",
            "shared wording with the phase-2/wgconf verify errors"
        );
        assert_eq!(
            (torn.sent, torn.received),
            (5, 1),
            "the confirm burst tops the total up to 5"
        );
        assert_eq!(torn.loss_pct, Some(80));
    }

    #[tokio::test]
    async fn warp_torn_pattern_stays_dropped_with_default_3_probes() {
        // The same death shape at the default budget: dormant, identical to
        // the old drop-lossy path — nothing stored.
        let t = FakeTransport::new().seq(
            "203.0.113.1".parse().unwrap(),
            2408,
            vec![Ok(5), torn_timeout(), torn_timeout()],
        );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, warp_cfg(3, &["203.0.113.1"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0);
        assert!(
            c.results().is_empty(),
            "default-3 lossy endpoints stay dropped"
        );
    }

    #[tokio::test]
    async fn warp_confirm_burst_recovery_is_not_torn() {
        // The tail answers the confirm probe: transient loss, not a
        // torn-down path — dropped like any other lossy endpoint.
        let t = FakeTransport::new().seq(
            "203.0.113.1".parse().unwrap(),
            2408,
            vec![Ok(5), torn_timeout(), torn_timeout(), torn_timeout(), Ok(9)],
        );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, warp_cfg(4, &["203.0.113.1"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0);
        assert!(
            c.results().is_empty(),
            "a recovered tail is lossy, not torn"
        );
    }

    #[tokio::test]
    async fn warp_torn_rows_skip_found_stop_and_live_working_events() {
        let t = FakeTransport::new()
            .seq(
                "203.0.113.1".parse().unwrap(),
                2408,
                vec![Ok(5), torn_timeout(), torn_timeout(), torn_timeout()],
            )
            .ok("203.0.113.2".parse().unwrap(), 2408, 7);
        let (c, mut rx) = warp_controller(t);
        let mut cfg = warp_cfg(4, &["203.0.113.1", "203.0.113.2"]);
        cfg.stop = StopCondition {
            found: 1,
            cap: None,
        };
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.scanned, 2, "a torn row must not satisfy stop.found");
        assert_eq!(summary.found, 1);
        let results = c.results();
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|v| v.fail_reason.as_deref() == Some("torn_down") && v.latency_ms.is_none()),
            "the torn row must be stored: {results:?}"
        );
        let mut live: Vec<IpAddr> = Vec::new();
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Result(v) = e {
                live.push(v.ip);
            }
        }
        assert_eq!(
            live,
            vec!["203.0.113.2".parse::<IpAddr>().unwrap()],
            "torn rows never emit a live Result-as-working"
        );
    }

    #[tokio::test]
    async fn warp_torn_row_renders_in_exports_but_never_in_bundles_or_shortlist() {
        let t = FakeTransport::new().seq(
            "203.0.113.1".parse().unwrap(),
            2408,
            vec![Ok(5), torn_timeout(), torn_timeout(), torn_timeout()],
        );
        let (c, _) = warp_controller(t);
        run_local(&c, warp_cfg(4, &["203.0.113.1"]), 1)
            .await
            .unwrap();
        let results = c.results();
        assert_eq!(results.len(), 1);

        let csv = crate::export::render_results("csv", &results).unwrap();
        let row: Vec<&str> = csv.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(row[2], "", "torn rows carry null latency: {row:?}");
        assert_eq!((row[8], row[9], row[10]), ("5", "1", "80"), "{row:?}");
        assert_eq!(row[11], "torn_down", "{row:?}");

        let json = crate::export::render_results("json", &results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["results"][0]["fail_reason"], "torn_down");
        assert!(parsed["results"][0]["latency_ms"].is_null(), "{json}");

        let diag = crate::export::diagnostic_line(&results[0]);
        assert!(diag.contains("torn_down"), "{diag}");

        // Bundles key off phase-2 passes: a torn row exports to nothing.
        let bundle = crate::export::render_bundle("raw", &results, &[], &[]).unwrap();
        assert!(bundle.is_empty(), "torn rows must never enter bundles");

        // The speed shortlist collects phase-2 passes only: torn rows never
        // enter it (read-only check against the shortlist index).
        let index = super::super::speed::build_passing_index(&results, &[]);
        assert!(index.is_empty(), "torn rows must never enter the shortlist");
    }

    fn adaptive_cfg() -> ScanConfig {
        let mut cfg = warp_cfg(3, &["203.0.113.1"]);
        cfg.adaptive_retries = true;
        cfg
    }

    fn adaptive_targets(cfg: &ScanConfig, seed: u64) -> Vec<(std::net::Ipv4Addr, u16)> {
        ScanController::preflight_targets(cfg, seed).unwrap()
    }

    fn script_all(targets: &[(std::net::Ipv4Addr, u16)], latency_ms: u32) -> FakeTransport {
        let mut t = FakeTransport::new();
        for (ip, port) in targets {
            t = t.ok(IpAddr::V4(*ip), *port, latency_ms);
        }
        t
    }

    #[test]
    fn adaptive_preflight_samples_exactly_100_distinct_pool_endpoints() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 1);
        assert_eq!(
            targets.len(),
            ADAPTIVE_PREFLIGHT_SAMPLES,
            "the pre-flight is exactly 100 probes"
        );
        let uniq: HashSet<IpAddr> = targets.iter().map(|(ip, _)| IpAddr::V4(*ip)).collect();
        assert_eq!(
            uniq.len(),
            ADAPTIVE_PREFLIGHT_SAMPLES,
            "one probe per distinct host"
        );
        assert!(
            targets.iter().all(|(_, port)| *port == 2408),
            "single configured port pairs straight through: {targets:?}"
        );
        assert_eq!(
            targets,
            adaptive_targets(&cfg, 1),
            "same seed must reproduce the sample plan"
        );
    }

    #[tokio::test]
    async fn adaptive_lossy_pool_bumps_probes_to_7() {
        let (c, _) = warp_controller(FakeTransport::new());
        let cfg = adaptive_cfg();
        let transport: Arc<dyn Transport> = Arc::new(FakeTransport::new());
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 1, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.samples, ADAPTIVE_PREFLIGHT_SAMPLES);
        assert_eq!(report.failed, ADAPTIVE_PREFLIGHT_SAMPLES as u32);
        assert_eq!(report.loss_pct, 100);
        assert_eq!((report.p50_ms, report.p90_ms, report.jitter_ms), (0, 0, 0));
        assert_eq!(report.applied_probes, 7);
    }

    #[tokio::test]
    async fn adaptive_clean_pool_keeps_default_probes() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 7);
        let (c, _) = warp_controller(FakeTransport::new());
        let transport: Arc<dyn Transport> = Arc::new(script_all(&targets, 45));
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 7, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.loss_pct, 0);
        assert_eq!((report.p50_ms, report.p90_ms), (45, 45));
        assert_eq!(report.jitter_ms, 0);
        assert_eq!(report.previous_probes, 3);
        assert_eq!(report.applied_probes, 3);
    }

    #[tokio::test]
    async fn adaptive_mid_loss_bumps_probes_to_5() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 11);
        let mut t = FakeTransport::new();
        for (ip, port) in targets.iter().take(85) {
            t = t.ok(IpAddr::V4(*ip), *port, 60);
        }
        let (c, _) = warp_controller(FakeTransport::new());
        let transport: Arc<dyn Transport> = Arc::new(t);
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 11, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.loss_pct, 15);
        assert_eq!(report.applied_probes, 5);
    }

    #[tokio::test]
    async fn adaptive_slow_p50_bumps_probes_to_5() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 13);
        let (c, _) = warp_controller(FakeTransport::new());
        let transport: Arc<dyn Transport> = Arc::new(script_all(&targets, 900));
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 13, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.loss_pct, 0);
        assert_eq!(report.p50_ms, 900);
        assert_eq!(report.applied_probes, 5);
    }

    #[tokio::test]
    async fn adaptive_high_jitter_bumps_probes_to_7() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 17);
        let mut t = FakeTransport::new();
        for (i, (ip, port)) in targets.iter().enumerate() {
            let lat = if i < 85 { 50 } else { 2000 };
            t = t.ok(IpAddr::V4(*ip), *port, lat);
        }
        let (c, _) = warp_controller(FakeTransport::new());
        let transport: Arc<dyn Transport> = Arc::new(t);
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 17, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.loss_pct, 0);
        assert_eq!((report.p50_ms, report.p90_ms), (50, 2000));
        assert_eq!(report.jitter_ms, 1950);
        assert_eq!(report.applied_probes, 7);
    }

    #[test]
    fn adaptive_ladder_pins_every_threshold_edge() {
        assert_eq!(adaptive_recommendation(3, 0, 50, 10), 3);
        assert_eq!(adaptive_recommendation(3, 10, 50, 10), 3);
        assert_eq!(adaptive_recommendation(3, 11, 50, 10), 5);
        assert_eq!(adaptive_recommendation(3, 25, 50, 10), 5);
        assert_eq!(adaptive_recommendation(3, 26, 50, 10), 7);
        assert_eq!(adaptive_recommendation(3, 0, 800, 10), 3);
        assert_eq!(adaptive_recommendation(3, 0, 801, 10), 5);
        assert_eq!(adaptive_recommendation(3, 0, 50, 1500), 3);
        assert_eq!(adaptive_recommendation(3, 0, 50, 1501), 7);
        assert_eq!(
            adaptive_recommendation(9, 100, 5000, 9000),
            9,
            "an already-high budget is never lowered"
        );
        assert_eq!(
            adaptive_recommendation(10, 100, 5000, 9000),
            10,
            "the ladder never recommends above max 10"
        );
        assert_eq!(
            adaptive_recommendation(7, 0, 50, 10),
            7,
            "a clean network never lowers a raised budget"
        );
    }

    #[test]
    fn adaptive_output_lines_are_pinned() {
        let bumped = PreflightReport {
            samples: 100,
            failed: 30,
            loss_pct: 30,
            p50_ms: 120,
            p90_ms: 200,
            jitter_ms: 80,
            previous_probes: 3,
            applied_probes: 7,
        };
        assert_eq!(
            bumped.stderr_lines(),
            [
                "warp pre-flight: 100 samples, loss 30%, p50 120ms, p90 200ms, jitter 80ms → probes 3 → 7"
                    .to_owned(),
                "re-run: cf-scanner scan --mode warp --warp-probes 7".to_owned(),
            ]
        );
        let kept = PreflightReport {
            samples: 100,
            failed: 0,
            loss_pct: 0,
            p50_ms: 45,
            p90_ms: 60,
            jitter_ms: 15,
            previous_probes: 3,
            applied_probes: 3,
        };
        assert_eq!(
            kept.stderr_lines(),
            [
                "warp pre-flight: 100 samples, loss 0%, p50 45ms, p90 60ms, jitter 15ms → probes 3 (unchanged)"
                    .to_owned(),
                "re-run: cf-scanner scan --mode warp --warp-probes 3".to_owned(),
            ]
        );
        assert_eq!(
            preflight_rerun_line(5),
            "re-run: cf-scanner scan --mode warp --warp-probes 5"
        );
    }

    #[tokio::test]
    async fn adaptive_abort_records_nothing() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 21);
        let mut t = FakeTransport::new();
        for (ip, port) in &targets {
            t = t.ok_slow(IpAddr::V4(*ip), *port, 5, 10);
        }
        let t: Arc<dyn Transport> = Arc::new(t);
        let (c, _) = warp_controller(FakeTransport::new());
        let handle = tokio::spawn({
            let c = c.clone();
            let t = t.clone();
            async move {
                let cancel = c.cancel_signal();
                c.warp_preflight(&cfg, &t, 21, 3, &cancel).await.unwrap()
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        c.cancel();
        assert!(
            handle.await.unwrap().is_none(),
            "a mid-pre-flight abort must yield no report"
        );
        assert!(
            c.results().is_empty(),
            "an aborted pre-flight records nothing"
        );
    }

    #[tokio::test]
    async fn adaptive_cancelled_run_scans_nothing() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 33);
        let mut t = FakeTransport::new();
        for (ip, port) in &targets {
            t = t.ok_slow(IpAddr::V4(*ip), *port, 5, 10);
        }
        t = t.ok("203.0.113.1".parse().unwrap(), 2408, 7);
        let (c, _) = warp_controller(t);
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 33).await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        c.cancel();
        let summary = handle.await.unwrap();
        assert!(
            summary.cancelled,
            "a mid-pre-flight Ctrl+C must cancel the scan"
        );
        assert_eq!(summary.scanned, 0);
        assert_eq!(summary.found, 0);
        assert!(
            c.results().is_empty(),
            "an aborted pre-flight records nothing"
        );
    }

    #[tokio::test]
    async fn adaptive_lossy_preflight_raises_the_main_scan_budget() {
        // Pre-flight: the bundled pool is unscripted, so all 100 samples fail
        // and the budget rises 3 → 7. Main scan: one answer then death needs
        // >= 4 probes to read as torn — unreachable at the default budget.
        let t = FakeTransport::new().seq(
            "203.0.113.1".parse().unwrap(),
            2408,
            vec![
                Ok(5),
                torn_timeout(),
                torn_timeout(),
                torn_timeout(),
                torn_timeout(),
                torn_timeout(),
                torn_timeout(),
            ],
        );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, adaptive_cfg(), 1).await.unwrap();
        assert!(!summary.cancelled);
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0);
        let results = c.results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fail_reason.as_deref(), Some(TORN_DOWN_REASON));
        assert_eq!(
            results[0].sent, 7,
            "the adapted budget must drive the main scan"
        );
    }

    #[tokio::test]
    async fn adaptive_clean_preflight_runs_a_normal_scan() {
        let cfg = adaptive_cfg();
        let targets = adaptive_targets(&cfg, 5);
        let mut t = script_all(&targets, 45);
        t = t.ok("203.0.113.1".parse().unwrap(), 2408, 7);
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, cfg, 5).await.unwrap();
        assert!(!summary.cancelled);
        assert_eq!((summary.scanned, summary.found), (1, 1));
        assert_eq!(c.results().len(), 1);
        assert_eq!(c.results()[0].latency_ms, Some(7));
    }

    #[tokio::test]
    async fn adaptive_empty_pool_keeps_probes() {
        let (c, _) = warp_controller(FakeTransport::new());
        let mut cfg = adaptive_cfg();
        cfg.exclude = vec!["0.0.0.0/0".to_owned()];
        let transport: Arc<dyn Transport> = Arc::new(FakeTransport::new());
        let cancel = c.cancel_signal();
        let report = c
            .warp_preflight(&cfg, &transport, 1, 3, &cancel)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.samples, 0);
        assert_eq!(report.applied_probes, 3);
    }
}
