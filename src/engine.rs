//! The one in-process scan engine every client drives: pool planning, probe
//! fan-out, stop conditions, event stream and the last-scan results store.
//! Used by the HTTP server (Task 6) and CLI (Task 8).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::task::JoinSet;

use crate::api::types::{
    FragmentPreset, Mode, Phase2Config, Phase2Verdict, ScanConfig, ScanEvent, ScanProgress,
    ScanSummary, ScanTarget, Verdict, WarpConfig,
};
use crate::configs::{
    OutboundSpec, RealSubFetch, SubFetch, parse_subscription, parse_uri, parse_xray_json,
};
use crate::geo::Geo;
use crate::probe::{ProbeError, Transport};
use crate::ranges::{self, PlanItem, SplitMix64};
use crate::verify::{ProbeRequest, TunnelProbe, XrayTunnelProbe};
use crate::warp;

const PROGRESS_EVERY: u64 = 50;

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
        Self::with_transports(transport, Arc::new(warp::WarpTransport))
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
        mut cfg: ScanConfig,
        seed: u64,
        pool: ranges::CidrPool,
    ) -> Result<ScanSummary> {
        cfg.validate()?;
        if cfg.mode == Mode::Warp {
            return self.run_warp(cfg, seed).await;
        }
        let phase2 = cfg.phase2.take();

        let started = Instant::now();
        self.clear_store();
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

        if let Some(p2) = phase2 {
            self.verify_phase(&cfg, &p2).await?;
        }

        Ok(self.finish(
            started,
            scanned.load(Ordering::Relaxed),
            found.load(Ordering::Relaxed),
        ))
    }

    // --- WARP: UDP endpoint discovery ----------------------------------------

    /// WARP run: every (endpoint, port) group gets `probes_per_endpoint`
    /// handshake probes; open (Response/Cookie) groups emit a verdict with
    /// min latency and loss %. `scanned` counts completed groups, so totals
    /// stay readable in the UI.
    async fn run_warp(&self, cfg: ScanConfig, seed: u64) -> Result<ScanSummary> {
        cfg.validate()?;
        let warp = cfg.warp.clone().unwrap_or_default();
        let probes_per_endpoint = warp.probes_per_endpoint.max(1) as u64;
        // Verification (Task 13): probe under the user's keypair from their
        // wgconf instead of the dummy key. Parsing fails fast here, before
        // any probe is sent.
        let transport: Arc<dyn Transport> = if warp.verify_with_wgconf {
            let text = warp
                .wgconf
                .as_deref()
                .ok_or_else(|| anyhow!("verify_with_wgconf requires a wgconf"))?;
            let wg = crate::wgconf::parse_wg_entry(text)
                .map_err(|e| anyhow!("invalid wgconf: {e:#}"))?;
            Arc::new(warp::WgVerifyTransport::from_config(&wg)?)
        } else {
            self.warp_transport.clone()
        };

        let started = Instant::now();
        self.clear_store();
        let groups = self.warp_groups(&cfg, &warp, seed)?;
        let total = groups.len() as u64;
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
        for (ip, ports) in &groups {
            let ip = IpAddr::from(*ip);
            for &port in ports {
                let transport = transport.clone();
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
                        || stop
                            .cap
                            .is_some_and(|cap| scanned.load(Ordering::Relaxed) >= u64::from(cap))
                    {
                        return Ok(());
                    }
                    let mut latency_ms: Option<u32> = None;
                    let mut failed = 0u64;
                    for _ in 0..probes_per_endpoint {
                        if *cancel.borrow() {
                            return Ok(());
                        }
                        match transport.probe(ip, port, cfg.timeout_ms).await {
                            Ok(latency) => {
                                latency_ms = Some(latency_ms.map_or(latency, |m| m.min(latency)));
                            }
                            Err(_) => failed += 1,
                        }
                    }
                    scanned.fetch_add(1, Ordering::Relaxed);
                    if let Some(latency) = latency_ms {
                        found.fetch_add(1, Ordering::Relaxed);
                        let verdict = Verdict {
                            ip,
                            port,
                            latency_ms: Some(latency),
                            loss_pct: Some(failed as f32 / probes_per_endpoint as f32 * 100.0),
                            country: geo.country(ip),
                            colo: None,
                            phase2: None,
                        };
                        insert_sorted(&store, verdict.clone());
                        let _ = events.send(ScanEvent::Result(Box::new(verdict)));
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
        while let Some(res) = tasks.join_next().await {
            res.map_err(|e| anyhow!("WARP probe task panicked: {e}"))??;
        }

        Ok(self.finish(
            started,
            scanned.load(Ordering::Relaxed),
            found.load(Ordering::Relaxed),
        ))
    }

    /// (endpoint, ports) groups: custom endpoints (with optional per-endpoint
    /// ports) when given, else the bundled pools sampled per `cfg.target`.
    fn warp_groups(
        &self,
        cfg: &ScanConfig,
        warp: &WarpConfig,
        seed: u64,
    ) -> Result<Vec<(std::net::Ipv4Addr, Vec<u16>)>> {
        let ports = cfg.ports.clone();
        let mut groups = Vec::new();
        if warp.custom_endpoints.is_empty() {
            let excluded = cfg
                .exclude
                .iter()
                .filter_map(|c| ranges::parse_cidr(c).ok())
                .collect::<Vec<_>>();
            let pool = warp::bundled_pool().excluding(&excluded);
            let plan = ranges::plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
            for item in &plan {
                for host in plan_hosts(item, &mut SplitMix64::new(seed)) {
                    match host {
                        IpAddr::V4(ip) => groups.push((ip, ports.clone())),
                        IpAddr::V6(_) => bail!("WARP pools must stay IPv4"),
                    }
                }
            }
        } else {
            for ep in &warp.custom_endpoints {
                let (ip, port) = parse_endpoint(ep)?;
                groups.push((ip, port.map_or_else(|| ports.clone(), |p| vec![p])));
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

    // --- phase 2: real-config verification through xray --------------------

    /// Verifies every phase-1 candidate through the user's configs, trying
    /// (config, SNI) combos until one passes per candidate. Updates verdicts
    /// in place and re-emits them so clients see the fragment/SNI detail.
    async fn verify_phase(&self, cfg: &ScanConfig, p2: &Phase2Config) -> Result<()> {
        let specs = self.parse_phase2_configs(p2).await?;
        if specs.is_empty() {
            bail!("phase 2: no usable configs (every entry failed to parse)");
        }
        let snis: Vec<Option<String>> = if p2.snis.is_empty() {
            vec![None]
        } else {
            p2.snis.iter().map(|s| Some(s.clone())).collect()
        };
        let candidates = self.store.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if candidates.is_empty() {
            return Ok(());
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        *self.cancel_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancel_tx);
        let semaphore = Arc::new(Semaphore::new(p2.concurrency as usize));
        let passed_ips: Arc<Mutex<HashSet<std::net::Ipv4Addr>>> =
            Arc::new(Mutex::new(HashSet::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let spawned = Arc::new(AtomicU64::new(0));
        let first_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        let mut tasks = JoinSet::new();
        for v in &candidates {
            // Phase 2 dials the candidate through xray, which takes a raw
            // IPv4 address; v6 phase-1 finds stay phase-1-only for now.
            let IpAddr::V4(ip) = v.ip else { continue };
            for spec in &specs {
                for sni in &snis {
                    let probe = self.tunnel_probe.clone();
                    let store = self.store.clone();
                    let events = self.events.clone();
                    let semaphore = semaphore.clone();
                    let cancel = cancel_rx.clone();
                    let passed_ips = passed_ips.clone();
                    let attempts = attempts.clone();
                    let spawned = spawned.clone();
                    let first_error = first_error.clone();
                    let spec = spec.clone();
                    let sni = sni.clone();
                    let p2 = p2.clone();
                    let timeout_ms = cfg.timeout_ms;
                    tasks.spawn(async move {
                        let _permit = semaphore
                            .acquire_owned()
                            .await
                            .map_err(|_| anyhow!("semaphore closed"))?;
                        if *cancel.borrow()
                            || passed_ips
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .contains(&ip)
                        {
                            return Ok(());
                        }
                        attempts.fetch_add(1, Ordering::Relaxed);
                        match probe
                            .probe(ProbeRequest {
                                spec: &spec,
                                dial_ip: ip,
                                preset: &p2.fragment,
                                custom: p2.custom_fragment.as_ref(),
                                sni: sni.as_deref(),
                                probe_url: &p2.probe_url,
                                timeout_ms,
                            })
                            .await
                        {
                            Ok(result) => {
                                spawned.fetch_add(1, Ordering::Relaxed);
                                let colo = result.colo.clone();
                                let verdict = Phase2Verdict {
                                    passed: result.passed,
                                    fragment: fragment_label(&p2.fragment),
                                    sni: sni.unwrap_or_default(),
                                    latency_ms: result.latency_ms,
                                };
                                if result.passed {
                                    passed_ips
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .insert(ip);
                                }
                                if let Some(updated) =
                                    update_verdict_phase2(&store, ip, verdict, colo)
                                {
                                    let _ = events.send(ScanEvent::Result(Box::new(updated)));
                                }
                            }
                            Err(err) => {
                                let mut slot =
                                    first_error.lock().unwrap_or_else(|e| e.into_inner());
                                if slot.is_none() {
                                    *slot = Some(err.to_string());
                                }
                            }
                        }
                        Ok::<(), anyhow::Error>(())
                    });
                }
            }
        }
        while let Some(res) = tasks.join_next().await {
            res.map_err(|e| anyhow!("phase-2 task panicked: {e}"))??;
        }

        if attempts.load(Ordering::Relaxed) > 0 && spawned.load(Ordering::Relaxed) == 0 {
            let reason = first_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_default();
            bail!("phase 2: every attempt failed before a probe ran: {reason}");
        }
        Ok(())
    }

    /// Configs entries are vless/trojan/vmess/ss URIs, http(s) subscription
    /// URLs, or local xray JSON file paths. Keeps every parse result so one
    /// bad entry never sinks a good batch.
    async fn parse_phase2_configs(&self, p2: &Phase2Config) -> Result<Vec<OutboundSpec>> {
        let mut specs = Vec::new();
        for entry in &p2.configs {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.starts_with("http://") || entry.starts_with("https://") {
                let body = self
                    .sub_fetch
                    .fetch(entry)
                    .await
                    .with_context(|| format!("subscription {} failed", redact_entry(entry)))?;
                let parsed = parse_subscription(&body);
                tracing::debug!(
                    url = %redact_entry(entry),
                    ok = parsed.specs.len(),
                    ignored = parsed.ignored,
                    "subscription fetched"
                );
                specs.extend(parsed.specs);
            } else if entry.contains("://") {
                specs.push(
                    parse_uri(entry).with_context(|| {
                        format!("config {} failed to parse", redact_entry(entry))
                    })?,
                );
            } else {
                let text = std::fs::read_to_string(entry)
                    .with_context(|| format!("config file {entry} unreadable"))?;
                specs.push(
                    parse_xray_json(&text)
                        .with_context(|| format!("config file {entry} has no usable outbound"))?,
                );
            }
        }
        Ok(specs)
    }

    fn finish(&self, started: Instant, scanned: u64, found: u64) -> ScanSummary {
        let summary = ScanSummary {
            scanned,
            found,
            duration_ms: started.elapsed().as_millis() as u64,
        };
        *self.summary.lock().unwrap_or_else(|e| e.into_inner()) = Some(summary.clone());
        self.emit(ScanEvent::Finished(summary.clone()));
        self.cancel_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
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

/// Renders a config entry safe for logs/errors: userinfo and query/fragment
/// are stripped, and hosts that look like opaque payloads (ss:// base64,
/// VMess UUIDs) are masked. Local file paths keep only the file name.
fn redact_entry(entry: &str) -> String {
    // Windows drive-letter paths ("C:\...") must not be mistaken for URLs.
    let looks_like_path = entry.len() > 2
        && entry.as_bytes()[0].is_ascii_alphabetic()
        && entry.as_bytes()[1] == b':'
        && matches!(entry.as_bytes().get(2), Some(b'\\') | Some(b'/'));
    let Ok(mut url) = url::Url::parse(entry) else {
        return entry.rsplit(['/', '\\']).next().unwrap_or(entry).to_owned();
    };
    if looks_like_path {
        return entry.rsplit(['/', '\\']).next().unwrap_or(entry).to_owned();
    }
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("***");
        let _ = url.set_password(Some("***"));
    }
    if let Some(host) = url.host_str() {
        if host.len() > 24 && !host.contains('.') {
            let _ = url.set_host(Some("redacted"));
        }
    }
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Concrete host addresses a plan item yields. `Sample` rolls fresh random
/// hosts with a per-port seed so multi-port scans don't repeat the same host.
/// v6 host spaces need u128 sampling (see `SplitMix64::below_u128`).
fn plan_hosts(item: &PlanItem, rng: &mut SplitMix64) -> Vec<IpAddr> {
    match item {
        PlanItem::Every { cidr } => (0..cidr.host_count())
            .map(|i| cidr.host(i))
            .collect::<Vec<_>>(),
        PlanItem::Sample { cidr, count } => {
            let count = (*count).min(cidr.host_count().min(u64::MAX as u128) as u64);
            let mut hosts = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let idx = if cidr.addr.is_ipv4() && cidr.prefix == 24 {
                    // Skip network and broadcast addresses on full /24 blocks.
                    (rng.below(254) + 1) as u128
                } else {
                    rng.below_u128(cidr.host_count())
                };
                hosts.push(cidr.host(idx));
            }
            hosts
        }
        PlanItem::Hosts { cidr, offsets } => offsets.iter().map(|&o| cidr.host(o)).collect(),
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

fn insert_sorted(store: &Store, verdict: Verdict) {
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    let pos = results
        .binary_search_by_key(&verdict.latency_ms, |v| v.latency_ms)
        .unwrap_or_else(|e| e);
    results.insert(pos, verdict);
}

/// `ip` or `ip:port`; the API validator already ran, so this only returns
/// errors for impossible input.
fn parse_endpoint(s: &str) -> Result<(std::net::Ipv4Addr, Option<u16>)> {
    let (ip, port) = match s.rsplit_once(':') {
        Some((ip, port)) => (ip, Some(port)),
        None => (s, None),
    };
    let ip: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid endpoint {s:?}"))?;
    let port = match port {
        Some(p) => Some(
            p.trim()
                .parse()
                .map_err(|_| anyhow!("invalid endpoint port in {s:?}"))?,
        ),
        None => None,
    };
    Ok((ip, port))
}

/// Stable fragment label for verdicts: `off`/`light`/`medium`/`heavy`/`custom`.
fn fragment_label(preset: &FragmentPreset) -> String {
    match preset {
        FragmentPreset::Off => "off",
        FragmentPreset::Light => "light",
        FragmentPreset::Medium => "medium",
        FragmentPreset::Heavy => "heavy",
        FragmentPreset::Custom => "custom",
    }
    .to_owned()
}

/// Attaches a phase-2 verdict (and the colo observed during verification) to
/// the stored row and returns the updated verdict for re-emission. `None`
/// when the row vanished (reset mid-phase).
fn update_verdict_phase2(
    store: &Store,
    ip: Ipv4Addr,
    p2v: Phase2Verdict,
    colo: Option<String>,
) -> Option<Verdict> {
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    let pos = results.iter().position(|v| v.ip == ip)?;
    results[pos].phase2 = Some(p2v);
    if colo.is_some() {
        results[pos].colo = colo;
    }
    Some(results[pos].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::MAX_SCAN_COUNT;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use crate::api::types::{Phase2Config, ScanConfig, ScanTarget, StopCondition};
    use crate::probe::FakeTransport;
    use crate::verify::{TunnelProbe, TunnelResult};

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

    fn p2_cfg(configs: &[&str], snis: &[&str]) -> Phase2Config {
        Phase2Config {
            configs: configs.iter().map(|s| (*s).to_owned()).collect(),
            snis: snis.iter().map(|s| (*s).to_owned()).collect(),
            concurrency: 2,
            ..Default::default()
        }
    }

    struct FakeSub(&'static str);

    impl SubFetch for FakeSub {
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
            Box::pin(async move { Ok(self.0.to_owned()) })
        }
    }

    #[derive(Clone)]
    struct FakeTunnelProbe {
        passed: std::sync::Arc<std::sync::Mutex<HashSet<Ipv4Addr>>>,
        attempts: std::sync::Arc<AtomicU64>,
        sni_pass: Option<&'static str>,
        always_err: std::sync::Arc<AtomicBool>,
    }

    impl FakeTunnelProbe {
        fn new() -> Self {
            Self {
                passed: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                attempts: std::sync::Arc::new(AtomicU64::new(0)),
                sni_pass: None,
                always_err: std::sync::Arc::new(AtomicBool::new(false)),
            }
        }

        fn pass(self, ip: Ipv4Addr) -> Self {
            self.passed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(ip);
            self
        }
    }

    impl TunnelProbe for FakeTunnelProbe {
        fn probe(
            &self,
            req: ProbeRequest<'_>,
        ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
            let this = self.clone();
            let sni = req.sni.map(str::to_owned);
            let dial_ip = req.dial_ip;
            Box::pin(async move {
                this.attempts.fetch_add(1, Ordering::Relaxed);
                if this.always_err.load(Ordering::Relaxed) {
                    return Err(anyhow!("simulated spawn failure"));
                }
                if let Some(want) = this.sni_pass {
                    if sni.as_deref() != Some(want) {
                        return Ok(TunnelResult {
                            passed: false,
                            latency_ms: None,
                            colo: None,
                        });
                    }
                }
                let passed = this
                    .passed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&dial_ip);
                Ok(TunnelResult {
                    passed,
                    latency_ms: passed.then_some(7),
                    colo: None,
                })
            })
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

    // --- WARP ----------------------------------------------------------------

    fn warp_cfg(probes: u8, endpoints: &[&str]) -> ScanConfig {
        ScanConfig {
            mode: Mode::Warp,
            target: ScanTarget::Count(10),
            stop: StopCondition {
                found: 5,
                cap: None,
            },
            ports: vec![2408],
            concurrency: 1,
            warp: Some(WarpConfig {
                probes_per_endpoint: probes,
                custom_endpoints: endpoints.iter().map(|s| (*s).to_owned()).collect(),
                ..Default::default()
            }),
            ..ScanConfig::default()
        }
    }

    /// WARP tests script the fake into the warp transport slot.
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
            .seq("10.0.0.1".parse().unwrap(), 2408, vec![Ok(5), Ok(7), Ok(6)])
            .seq(
                "10.0.0.2".parse().unwrap(),
                2408,
                vec![
                    Ok(9),
                    Err(ProbeError::Timeout { timeout_ms: 3000 }),
                    Err(ProbeError::Timeout { timeout_ms: 3000 }),
                ],
            );
        let (c, _) = warp_controller(t);
        let summary = run_local(&c, warp_cfg(3, &["10.0.0.1", "10.0.0.2"]), 1)
            .await
            .unwrap();
        assert_eq!(summary.found, 2);
        assert_eq!(summary.scanned, 2);
        let results = c.results();
        assert_eq!(results[0].latency_ms, Some(5));
        assert_eq!(results[0].loss_pct, Some(0.0));
        assert_eq!(results[1].latency_ms, Some(9));
        let loss = results[1].loss_pct.unwrap();
        assert!((loss - 66.67).abs() < 0.1, "loss={loss}");
    }

    #[tokio::test]
    async fn warp_custom_endpoint_port_overrides_cfg_ports() {
        let t = FakeTransport::new().ok("10.0.0.9".parse().unwrap(), 1234, 12);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["10.0.0.9:1234"]);
        cfg.ports = vec![2408];
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(summary.found, 1);
        assert_eq!(c.results()[0].port, 1234);
    }

    #[tokio::test]
    async fn warp_closed_endpoints_produce_no_verdicts() {
        let (c, _) = warp_controller(FakeTransport::new());
        let summary = run_local(&c, warp_cfg(2, &["10.0.0.5"]), 1).await.unwrap();
        assert_eq!(summary.scanned, 1);
        assert_eq!(summary.found, 0);
        assert!(c.results().is_empty());
    }

    #[tokio::test]
    async fn warp_stop_condition_stops_early() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 2408, 5)
            .ok("10.0.0.2".parse().unwrap(), 2408, 5)
            .ok("10.0.0.3".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
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

    #[tokio::test]
    async fn warp_count_caps_custom_endpoints_by_sampling() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 2408, 5)
            .ok("10.0.0.2".parse().unwrap(), 2408, 5)
            .ok("10.0.0.3".parse().unwrap(), 2408, 5)
            .ok("10.0.0.4".parse().unwrap(), 2408, 5);
        let (c, _) = warp_controller(t);
        let mut cfg = warp_cfg(1, &["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]);
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
        let mut cfg = warp_cfg(1, &["10.0.0.1"]);
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
        let mut cfg = warp_cfg(1, &["10.0.0.1"]);
        cfg.warp = Some(WarpConfig {
            verify_with_wgconf: true,
            wgconf: Some("not a wgconf at all".to_owned()),
            ..Default::default()
        });
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("invalid wgconf"), "{err:#}");
        assert!(c.results().is_empty());
    }

    // --- phase 2 ------------------------------------------------------------

    fn p2_controller(
        transport: FakeTransport,
        sub: FakeSub,
        probe: FakeTunnelProbe,
    ) -> Arc<ScanController> {
        Arc::new(ScanController::with_probes(
            Arc::new(transport),
            Arc::new(sub),
            Arc::new(probe),
        ))
    }

    const VLESS: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443";

    #[tokio::test]
    async fn phase2_skips_v6_candidates() {
        // v6 phase-1 finds stay phase-1-only: xray dials a raw v4 address.
        let t = FakeTransport::new()
            .ok("2606:4700::1".parse().unwrap(), 443, 20)
            .ok("2606:4700::2".parse().unwrap(), 443, 30)
            .ok("10.0.0.1".parse().unwrap(), 443, 40);
        let probe = FakeTunnelProbe::new().pass("10.0.0.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(100, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        let pool = ranges::CidrPool::parse("2606:4700::/126\n10.0.0.0/30").unwrap();
        c.run_seeded_with_pool(cfg, 1, pool).await.unwrap();
        // Only the v4 candidate went through the tunnel probe.
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 1);
        let results = c.results();
        let v4 = results.iter().find(|v| !v.ip.is_ipv6()).unwrap();
        assert!(v4.phase2.as_ref().unwrap().passed);
        assert_eq!(results.iter().filter(|v| v.ip.is_ipv6()).count(), 2);
        assert!(
            results
                .iter()
                .filter(|v| v.ip.is_ipv6())
                .all(|v| v.phase2.is_none())
        );
    }

    #[tokio::test]
    async fn phase2_attaches_verdicts_and_reemits_results() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 50)
            .ok("10.0.0.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .pass("10.0.0.1".parse().unwrap())
            .pass("10.0.0.2".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();

        let results = c.results();
        assert_eq!(results.len(), 2);
        for v in &results {
            let p2 = v.phase2.as_ref().expect("phase-2 verdict attached");
            assert!(p2.passed, "{v:?}");
            assert_eq!(p2.fragment, "off");
            assert_eq!(p2.sni, "");
            assert_eq!(p2.latency_ms, Some(7));
        }
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 2);

        let mut phase2_events = 0;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Result(v) = e {
                if v.phase2.is_some() {
                    phase2_events += 1;
                }
            }
        }
        assert_eq!(phase2_events, 2, "updated verdicts must be re-emitted");
    }

    #[tokio::test]
    async fn phase2_marks_failed_attempts_without_aborting() {
        let t = FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new(); // nothing passes
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(!p2.passed);
        assert_eq!(p2.fragment, "off");
        assert_eq!(p2.latency_ms, None);
    }

    #[tokio::test]
    async fn phase2_tries_sni_combos_until_one_passes() {
        let t = FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new().pass("10.0.0.1".parse().unwrap());
        probe.sni_pass = Some("b.me");
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &["a.me", "b.me"]));
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(p2.passed);
        assert_eq!(p2.sni, "b.me");
        // One failed combo + one pass per candidate.
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn phase2_fetches_subscriptions_through_the_seam() {
        let t = FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("10.0.0.1".parse().unwrap());
        let sub = FakeSub("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443\nnot-a-uri\n");
        let c = p2_controller(t, sub, probe);
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["https://sub.example.com/x"], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        assert!(c.results()[0].phase2.as_ref().unwrap().passed);
    }

    #[tokio::test]
    async fn phase2_without_candidates_is_a_noop() {
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(FakeTransport::new(), FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(5, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn phase2_bad_config_aborts_the_run() {
        let t = FakeTransport::new().ok("10.0.0.1".parse().unwrap(), 443, 50);
        let c = p2_controller(t, FakeSub(""), FakeTunnelProbe::new());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["ftp://nope"], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("failed to parse"), "{err}");
    }

    #[tokio::test]
    async fn phase2_local_failures_abort_with_a_reason() {
        let t = FakeTransport::new()
            .ok("10.0.0.1".parse().unwrap(), 443, 50)
            .ok("10.0.0.2".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new();
        probe
            .always_err
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let c = p2_controller(t, FakeSub(""), probe);
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("every attempt failed"), "{err}");
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

    #[test]
    fn redact_entry_strips_secrets_from_uris() {
        assert_eq!(
            redact_entry("vless://deadbeef-0000-0000-0000-000000000000@1.2.3.4:443?type=tcp"),
            "vless://***:***@1.2.3.4:443"
        );
        assert_eq!(
            redact_entry("https://sub.example.com/sub?token=abc123"),
            "https://sub.example.com/sub"
        );
        assert_eq!(
            redact_entry("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM0NTY3ODkw@1.2.3.4:8388"),
            "ss://***:***@1.2.3.4:8388"
        );
        // Opaque hosts (no userinfo, no dots) get masked outright.
        assert_eq!(
            redact_entry("vmess://Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA"),
            "vmess://redacted"
        );
        // Non-URLs (local file paths) degrade to the file name only.
        assert_eq!(redact_entry("C:\\users\\me\\config.json"), "config.json");
    }
}
