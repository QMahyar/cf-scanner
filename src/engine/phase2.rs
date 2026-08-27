//! Phase-2 real-config verification: parses user configs (URIs, subscriptions,
//! local xray JSON) and verifies phase-1 candidates through tunnel probes with
//! fragment presets and SNI combos, updating verdicts in place.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::{ScanController, Store, cancelled_signal, claim_milestone};
use crate::api::types::{
    FragmentPreset, Phase2Config, Phase2Progress, Phase2Verdict, ScanConfig, ScanEvent, Verdict,
};
use crate::configs::{OutboundSpec, parse_subscription, parse_uri, parse_xray_json};
use crate::verify::ProbeRequest;

/// Phase-2 progress events: every 32 completed attempts (plus the final
/// one), so a long verification run stays observable without flooding.
const PROGRESS_EVERY_P2: u64 = 32;

impl ScanController {
    /// Verifies every phase-1 candidate through the user's configs, trying
    /// (config, SNI) combos until one passes per candidate. Updates verdicts
    /// in place and re-emits them so clients see the fragment/SNI detail.
    ///
    /// Combos are never materialized: a fixed set of `concurrency` workers
    /// pull combo indices off a shared counter, so memory stays bounded
    /// regardless of candidates × configs × SNIs, and stop conditions
    /// (cancel, hard cap) are honored before every attempt.
    pub(super) async fn verify_phase(&self, cfg: &ScanConfig, p2: &Phase2Config) -> Result<()> {
        // One cancel signal per run, shared by parsing and the workers below:
        // when phase 2 follows a phase 1 this is the same channel phase 1
        // used, so a cancel fired during phase 1 (or mid-parse) stops
        // verification immediately.
        let cancel_rx = self.cancel_signal();
        let (specs, parse_cancelled) = self.parse_phase2_configs(p2, &cancel_rx).await?;
        if parse_cancelled {
            // The normal cancelled-summary path: `finish` reports the cancel,
            // so a mid-parse abort must not surface as a config error.
            return Ok(());
        }
        if specs.is_empty() {
            bail!("phase 2: no usable configs (every entry failed to parse)");
        }
        let snis: Vec<Option<String>> = if p2.snis.is_empty() {
            vec![None]
        } else {
            p2.snis.iter().map(|s| Some(s.clone())).collect()
        };
        // Probe-target list is fixed for the whole run: every combo dials
        // the same URLs, so resolve the effective list exactly once.
        let probe_urls = p2.effective_probe_urls();
        let candidates = self.store.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // Phase 2 dials the candidate through xray, which takes a raw IPv4
        // address; v6 phase-1 finds stay phase-1-only for now. Rows are
        // keyed by (ip, port) so multi-port scans update the right row.
        let v4_candidates: Vec<(Ipv4Addr, u16)> = candidates
            .iter()
            .filter_map(|v| match v.ip {
                IpAddr::V4(ip) => Some((ip, v.port)),
                IpAddr::V6(_) => None,
            })
            .collect();
        if v4_candidates.is_empty() {
            return Ok(());
        }

        let combos_per_candidate = (specs.len() * snis.len()) as u64;
        let total = v4_candidates.len() as u64 * combos_per_candidate;
        let next = Arc::new(AtomicU64::new(0));
        let passed: Arc<Mutex<HashSet<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicU64::new(0));
        let milestones = Arc::new(AtomicU64::new(0));
        let terminal_sent = Arc::new(AtomicBool::new(false));
        let first_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let cap = cfg.stop.cap;

        let specs = Arc::new(specs);
        let snis = Arc::new(snis);
        let probe_urls = Arc::new(probe_urls);
        let v4_candidates = Arc::new(v4_candidates);
        let mut tasks = JoinSet::new();
        for _ in 0..p2.concurrency {
            let probe = self.tunnel_probe.clone();
            let store = self.store.clone();
            let events = self.events.clone();
            let cancel = cancel_rx.clone();
            let passed = passed.clone();
            let attempts = attempts.clone();
            let completed = completed.clone();
            let milestones = milestones.clone();
            let terminal_sent = terminal_sent.clone();
            let first_error = first_error.clone();
            let next = next.clone();
            let candidates = v4_candidates.clone();
            let specs = specs.clone();
            let snis = snis.clone();
            let probe_urls = probe_urls.clone();
            let p2 = p2.clone();
            let timeout_ms = cfg.timeout_ms;
            tasks.spawn(async move {
                loop {
                    if *cancel.borrow()
                        || cap.is_some_and(|c| attempts.load(Ordering::Relaxed) >= u64::from(c))
                    {
                        break;
                    }
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    if idx >= total {
                        break;
                    }
                    let (ci, rest) = (idx / combos_per_candidate, idx % combos_per_candidate);
                    let (si, ni) = (rest / snis.len() as u64, rest % snis.len() as u64);
                    let (ip, port) = candidates[ci as usize];
                    let (spec, config_idx) = &specs[si as usize];
                    let sni = &snis[ni as usize];
                    if passed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&(ip, port))
                    {
                        continue;
                    }
                    attempts.fetch_add(1, Ordering::Relaxed);
                    match probe
                        .probe(ProbeRequest {
                            spec,
                            dial_ip: ip,
                            preset: &p2.fragment,
                            custom: p2.custom_fragment.as_ref(),
                            sni: sni.as_deref(),
                            probe_urls: &probe_urls,
                            timeout_ms,
                        })
                        .await
                    {
                        Ok(result) => {
                            completed.fetch_add(1, Ordering::Relaxed);
                            let colo = result.colo.clone();
                            let verdict = Phase2Verdict {
                                passed: result.passed,
                                fragment: fragment_label(&p2.fragment),
                                sni: sni.clone().unwrap_or_default(),
                                latency_ms: result.latency_ms,
                                error: None,
                                config_index: Some(*config_idx),
                                verifier: result.verifier.map(str::to_owned),
                            };
                            if result.passed {
                                passed
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert((ip, port));
                            }
                            if let Some(updated) =
                                update_verdict_phase2(&store, ip, port, verdict, colo)
                            {
                                let _ = events.send(ScanEvent::Result(Box::new(updated)));
                            }
                        }
                        Err(err) => {
                            // Local failures (spawn, config build) are kept
                            // redacted and surfaced on the row so clients see
                            // why the candidate did not verify.
                            let msg = crate::configs::sanitize_error_text(&err.to_string());
                            let mut slot = first_error.lock().unwrap_or_else(|e| e.into_inner());
                            if slot.is_none() {
                                *slot = Some(msg.clone());
                            }
                            let verdict = Phase2Verdict {
                                passed: false,
                                fragment: fragment_label(&p2.fragment),
                                sni: sni.clone().unwrap_or_default(),
                                latency_ms: None,
                                error: Some(msg),
                                config_index: Some(*config_idx),
                                verifier: None,
                            };
                            if let Some(updated) =
                                update_verdict_phase2(&store, ip, port, verdict, None)
                            {
                                let _ = events.send(ScanEvent::Result(Box::new(updated)));
                            }
                        }
                    }
                    let done = completed.load(Ordering::Relaxed);
                    let terminal = done == total;
                    // The terminal event is claimed once (a worker that saw
                    // `done == total` beats the post-loop emit); intermediate
                    // milestones go through the shared single-winner gate so
                    // concurrent completions cannot duplicate or regress.
                    if (terminal && !terminal_sent.swap(true, Ordering::Relaxed))
                        || (!terminal && claim_milestone(&milestones, done, PROGRESS_EVERY_P2))
                    {
                        let _ =
                            events.send(ScanEvent::Phase2Progress(Phase2Progress { done, total }));
                    }
                }
                Ok::<(), anyhow::Error>(())
            });
        }
        while let Some(res) = tasks.join_next().await {
            res.map_err(|e| anyhow!("phase-2 task panicked: {e}"))??;
        }
        // Terminal progress: workers short-circuit combos of already-passed
        // candidates, so `done` can land below `total`; emit the final
        // numbers regardless so clients always resolve to a final event.
        // Suppressed when a worker already claimed the terminal event.
        let done = completed.load(Ordering::Relaxed);
        if (done > 0 || attempts.load(Ordering::Relaxed) > 0)
            && !terminal_sent.swap(true, Ordering::Relaxed)
        {
            let _ = self
                .events
                .send(ScanEvent::Phase2Progress(Phase2Progress { done, total }));
        }

        let attempts_val = attempts.load(Ordering::Relaxed);
        let completed_val = completed.load(Ordering::Relaxed);
        if attempts_val > 0 && completed_val == 0 {
            let reason_opt = first_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            match reason_opt {
                Some(reason) => {
                    bail!("phase 2: every attempt failed before a probe ran: {reason}")
                }
                None => {
                    bail!(
                        "phase 2: every verification attempt completed but none passed (0/{attempts_val})"
                    )
                }
            }
        }
        Ok(())
    }

    /// Configs entries are vless/trojan/vmess/ss URIs, http(s) subscription
    /// URLs, or local xray JSON file paths. One bad entry is skipped (and
    /// counted) so a typo'd line never sinks a good batch; only a batch
    /// with zero usable entries aborts the phase. Each spec carries the
    /// index of the config entry it came from, so verdicts can name the
    /// submitted config that produced them (a subscription expands to many
    /// specs sharing one entry index). A cancel stops the loop between
    /// entries and aborts an in-flight subscription fetch; the returned
    /// flag marks the batch partial and unusable.
    async fn parse_phase2_configs(
        &self,
        p2: &Phase2Config,
        cancel: &watch::Receiver<bool>,
    ) -> Result<(Vec<(OutboundSpec, u32)>, bool)> {
        let mut specs = Vec::new();
        let mut skipped = 0u32;
        for (idx, entry) in p2.configs.iter().enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if *cancel.borrow() {
                return Ok((specs, true));
            }
            let result = if entry.starts_with("http://") || entry.starts_with("https://") {
                let body = tokio::select! {
                    body = self.sub_fetch.fetch(entry) => body,
                    _ = cancelled_signal(cancel.clone()) => return Ok((specs, true)),
                }
                .with_context(|| format!("subscription {} failed", redact_entry(entry)));
                body.map(|body| {
                    let parsed = parse_subscription(&body);
                    tracing::debug!(
                        url = %redact_entry(entry),
                        ok = parsed.specs.len(),
                        ignored = parsed.ignored,
                        "subscription fetched"
                    );
                    parsed.specs
                })
            } else if entry.contains("://") {
                parse_uri(entry)
                    .with_context(|| format!("config {} failed to parse", redact_entry(entry)))
                    .map(|spec| vec![spec])
            } else {
                // File reads are blocking; keep them off the tokio workers.
                let path = entry.to_owned();
                let text = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
                    .await
                    .context("config file read task panicked")?
                    .with_context(|| format!("config file {} unreadable", redact_entry(entry)));
                text.and_then(|text| {
                    parse_xray_json(&text).with_context(|| {
                        format!("config file {} has no usable outbound", redact_entry(entry))
                    })
                })
                .map(|spec| vec![spec])
            };
            match result {
                Ok(parsed) => {
                    if parsed.len() > crate::api::types::MAX_SUBSCRIPTION_SPECS {
                        anyhow::bail!(
                            "subscription expands to more than {} configs",
                            crate::api::types::MAX_SUBSCRIPTION_SPECS
                        );
                    }
                    if specs.len() + parsed.len() > crate::api::types::MAX_PHASE2_TOTAL_SPECS {
                        anyhow::bail!(
                            "phase 2: too many expanded configs (limit {})",
                            crate::api::types::MAX_PHASE2_TOTAL_SPECS
                        );
                    }
                    specs.extend(parsed.into_iter().map(|spec| (spec, idx as u32)));
                }
                Err(err) => {
                    skipped += 1;
                    tracing::warn!("phase-2 config skipped: {err:#}");
                }
            }
        }
        if specs.is_empty() {
            if skipped > 0 {
                bail!(
                    "phase 2: no usable configs ({skipped} of {} entries failed to parse)",
                    p2.configs.len()
                );
            }
            bail!("phase 2: no configs to verify with");
        }
        Ok((specs, false))
    }
}

/// Attaches a phase-2 verdict (and the colo observed during verification) to
/// the stored row and returns the updated verdict for re-emission. `None`
/// when the row vanished (reset mid-phase) or a passing verdict is already
/// recorded: concurrent combos race, and a pass must never be downgraded.
fn update_verdict_phase2(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    p2v: Phase2Verdict,
    colo: Option<String>,
) -> Option<Verdict> {
    let mut results = store.lock().unwrap_or_else(|e| e.into_inner());
    let pos = results
        .iter()
        .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)?;
    if results[pos].phase2.as_ref().is_some_and(|p| p.passed) {
        return None;
    }
    results[pos].phase2 = Some(p2v);
    if colo.is_some() {
        results[pos].colo = colo;
    }
    Some(results[pos].clone())
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
        // Not a URL: keep only the trailing segment and strip anything
        // before the last '@' (plus query/fragment), so a malformed URI can
        // never surface its userinfo (uuid/password) in an error or log.
        let tail = entry.rsplit(['/', '\\']).next().unwrap_or(entry);
        return tail
            .rsplit_once('@')
            .map(|(_, hostish)| hostish)
            .unwrap_or(tail)
            .split(['?', '#'])
            .next()
            .unwrap_or(tail)
            .to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::Phase2Config;
    use crate::configs::SubFetch;
    use crate::engine::tests::{ok_cfg, run_local};
    use crate::probe::FakeTransport;
    use crate::ranges;
    use crate::verify::{ProbeRequest, TunnelProbe, TunnelResult};
    use std::future::Future;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;

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
        /// Every URL list each probe call received (assert spells the
        /// multi-URL plumbing through the engine).
        url_lists: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
    }

    impl FakeTunnelProbe {
        fn new() -> Self {
            Self {
                passed: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                attempts: std::sync::Arc::new(AtomicU64::new(0)),
                sni_pass: None,
                always_err: std::sync::Arc::new(AtomicBool::new(false)),
                url_lists: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
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
            let urls = req.probe_urls.to_vec();
            Box::pin(async move {
                this.attempts.fetch_add(1, Ordering::Relaxed);
                this.url_lists
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(urls);
                if this.always_err.load(Ordering::Relaxed) {
                    return Err(anyhow!("simulated spawn failure"));
                }
                if let Some(want) = this.sni_pass {
                    if sni.as_deref() != Some(want) {
                        return Ok(TunnelResult {
                            passed: false,
                            latency_ms: None,
                            colo: None,
                            verifier: None,
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
                    verifier: None,
                })
            })
        }
    }

    fn p2_controller(
        transport: FakeTransport,
        sub: impl SubFetch + 'static,
        probe: FakeTunnelProbe,
    ) -> Arc<ScanController> {
        Arc::new(ScanController::with_probes(
            Arc::new(transport),
            Arc::new(sub),
            Arc::new(probe),
        ))
    }

    /// Subscription fetch that never resolves: stands in for a
    /// never-responding subscription endpoint.
    struct HangingSub;

    impl SubFetch for HangingSub {
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
            Box::pin(async { std::future::pending::<Result<String>>().await })
        }
    }

    const VLESS: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443";

    #[tokio::test]
    async fn phase2_skips_v6_candidates() {
        // v6 phase-1 finds stay phase-1-only: xray dials a raw v4 address.
        let t = FakeTransport::new()
            .ok("2606:4700::1".parse().unwrap(), 443, 20)
            .ok("2606:4700::2".parse().unwrap(), 443, 30)
            .ok("203.0.113.1".parse().unwrap(), 443, 40);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(100, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        let pool = ranges::CidrPool::parse("2606:4700::/126\n203.0.113.0/30").unwrap();
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
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .pass("203.0.113.1".parse().unwrap())
            .pass("203.0.113.2".parse().unwrap());
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
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
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
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
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
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let sub = FakeSub("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443\nnot-a-uri\n");
        let c = p2_controller(t, sub, probe);
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["https://sub.example.com/x"], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(p2.passed);
        // A subscription-expanded spec still names its config entry.
        assert_eq!(p2.config_index, Some(0));
    }

    #[tokio::test]
    async fn phase2_probes_every_url_with_one_spawn_per_combo() {
        // Multiple probe URLs ride ONE tunnel spawn per (candidate, config,
        // preset, sni) combo: attempts stay at candidate count and every
        // probe call carries the full URL list.
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .pass("203.0.113.1".parse().unwrap())
            .pass("203.0.113.2".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec![
                "https://cp.cloudflare.com/".to_owned(),
                "https://www.cloudflare.com/".to_owned(),
            ],
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            2,
            "one spawn per candidate, not per probe URL"
        );
        let want = vec![
            "https://cp.cloudflare.com/".to_owned(),
            "https://www.cloudflare.com/".to_owned(),
        ];
        let lists = probe.url_lists.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(lists.len(), 2);
        assert!(lists.iter().all(|l| l == &want), "{lists:?}");
        // The verdict names the submitted config entry that passed.
        for v in c.results() {
            assert_eq!(v.phase2.as_ref().unwrap().config_index, Some(0));
        }
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
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let c = p2_controller(t, FakeSub(""), FakeTunnelProbe::new());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["ftp://nope"], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("no usable configs"), "{err}");
    }

    #[tokio::test]
    async fn phase2_local_failures_abort_with_a_reason() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 50);
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
        // Parseable URIs keep their (masked) scheme so diagnostics stay readable.
        assert_eq!(
            redact_entry("vless://deadbeef-0000-0000-0000-000000000000@1.2.3.4:443?type=tcp"),
            "vless://***:***@1.2.3.4:443"
        );
        assert_eq!(redact_entry("not a uri at all"), "not a uri at all");
    }

    #[tokio::test]
    async fn phase2_one_bad_config_entry_is_skipped_not_fatal() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["ftp://nope", VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        assert!(c.results()[0].phase2.as_ref().unwrap().passed);
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn phase2_all_config_entries_bad_aborts_with_count() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let c = p2_controller(t, FakeSub(""), FakeTunnelProbe::new());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["ftp://nope"], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(err.to_string().contains("no usable configs"), "{err}");
    }

    #[test]
    fn update_verdict_phase2_never_downgrades_a_pass() {
        let store: Store = Arc::new(Mutex::new(vec![Verdict {
            ip: "203.0.113.1".parse().unwrap(),
            port: 443,
            latency_ms: Some(5),
            country: None,
            colo: Some("FRA".to_owned()),
            phase2: Some(Phase2Verdict {
                passed: true,
                fragment: "light".to_owned(),
                sni: "".to_owned(),
                latency_ms: Some(42),
                error: None,
                config_index: Some(0),
                verifier: Some("xray".to_owned()),
            }),
        }]));
        // A racing failed combo must not clobber the passing verdict.
        let failed = Phase2Verdict {
            passed: false,
            fragment: "off".to_owned(),
            sni: "".to_owned(),
            latency_ms: None,
            error: Some("spawn failed".to_owned()),
            config_index: None,
            verifier: None,
        };
        let updated =
            update_verdict_phase2(&store, "203.0.113.1".parse().unwrap(), 443, failed, None);
        assert!(updated.is_none(), "a pass must never be downgraded");
        let row = &store.lock().unwrap_or_else(|e| e.into_inner())[0];
        assert!(row.phase2.as_ref().unwrap().passed);
        assert_eq!(row.colo.as_deref(), Some("FRA"));
    }

    #[tokio::test]
    async fn cancel_during_phase1_stops_phase2_work() {
        // A cancel fired while phase-1 probes are still in flight must be
        // visible to phase-2 workers: verification runs zero tunnel probes
        // and the summary reports the cancel.
        let t = FakeTransport::new()
            .ok_slow("203.0.113.1".parse().unwrap(), 443, 50, 200)
            .ok_slow("203.0.113.2".parse().unwrap(), 443, 50, 200);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
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
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        c.cancel();
        let summary = handle.await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            0,
            "phase-2 workers must see the phase-1 cancel signal"
        );
        assert!(summary.cancelled, "summary must report the cancel");
    }

    #[tokio::test]
    async fn phase2_terminal_progress_emitted_once() {
        // Nothing passes, so every combo completes and `done` reaches
        // `total`: the winning worker and the post-loop emit must yield
        // exactly one terminal Phase2Progress, not two.
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &["a.me", "b.me"]));
        run_local(&c, cfg, 1).await.unwrap();
        let mut terminal = 0u32;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Phase2Progress(p) = e {
                if p.done == p.total {
                    terminal += 1;
                }
            }
        }
        assert_eq!(terminal, 1, "terminal progress must fire exactly once");
    }

    #[tokio::test]
    async fn cancel_during_config_parse_aborts_promptly() {
        // The first entry hangs forever on its subscription fetch; a cancel
        // fired mid-parse must abort the fetch and finish as a cancelled run
        // without touching the remaining entries or any tunnel probe.
        let t = FakeTransport::new();
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(t, HangingSub, probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&["https://hang.example.com/sub", VLESS], &[]));
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c.cancel();
        let summary = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("cancel must abort the hanging subscription fetch")
            .unwrap()
            .unwrap();
        assert!(summary.cancelled, "summary must report the cancel");
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            0,
            "verification must not start with a partial config batch"
        );
    }

    #[tokio::test]
    async fn phase2_progress_events_track_attempts() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .pass("203.0.113.1".parse().unwrap())
            .pass("203.0.113.2".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &["a.me", "b.me"]));
        run_local(&c, cfg, 1).await.unwrap();
        let mut events: Vec<ScanEvent> = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        let mut progress = 0u64;
        let mut total = 0u64;
        for e in &events {
            if let ScanEvent::Phase2Progress(p) = e {
                progress = progress.max(p.done);
                total = p.total;
            }
        }
        assert_eq!(total, 4, "2 candidates x 2 SNIs — events: {events:?}");
        // Pass-short-circuit: once a candidate passes, its remaining SNI
        // combos are skipped, so the final event reports the probes that
        // actually ran (one per candidate).
        assert_eq!(
            progress, 2,
            "the terminal progress event must report done == executed combos"
        );
    }
}
