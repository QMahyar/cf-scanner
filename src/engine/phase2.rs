use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::store::{PosIndex, Store, remove_verdict_unless_passed, update_verdict_phase2};
use super::{ScanController, cancelled_signal, claim_milestone, colo_rejected, lock};
use crate::api::types::{
    Phase2Config, Phase2Progress, Phase2Verdict, ScanConfig, ScanEvent, Verdict, Verifier,
};
use crate::configs::{OutboundSpec, parse_subscription, parse_uri, parse_xray_json};
use crate::verify::ProbeRequest;

const PROGRESS_EVERY_P2: u64 = 32;

/// Fixed phase-2 fallback tier (spec P1-2): a public Cloudflare trace URL
/// (edge reachability + colo) plus a real data-path page (payload delivery,
/// not just status). Both must 200 over one tunnel, like any probe-URL tier.
/// Fixed with no config surface, so single-tier configs behave exactly as
/// today. Both URLs return HTTP 200, which is what the tunnel probes require.
const FALLBACK_TIER_PROBE_URLS: &[&str] = &[
    "https://cloudflare.com/cdn-cgi/trace",
    "https://www.cloudflare.com/",
];

impl ScanController {
    pub(super) async fn verify_phase(&self, cfg: &ScanConfig, p2: &Phase2Config) -> Result<()> {
        let cancel_rx = self.cancel_signal();
        let (specs, parse_cancelled) = self.parse_phase2_configs(p2, &cancel_rx).await?;
        if parse_cancelled {
            return Ok(());
        }
        if specs.is_empty() {
            bail!("phase 2: no usable configs (every entry failed to parse)");
        }
        // Paired write: fill the specs side retained (empty) at run start. On
        // failure/cancellation the run-start reset already guarantees the pair
        // stays consistent (configs set, specs empty) — never stale.
        self.retain_phase2_state(p2.configs.clone(), specs.clone());
        let snis: Vec<Option<String>> = if p2.snis.is_empty() {
            vec![None]
        } else {
            p2.snis.iter().map(|s| Some(s.clone())).collect()
        };
        let tiers = phase2_tiers(p2.effective_probe_urls());
        let candidates = lock(&self.progress.store).clone();
        if phase2_candidates_in(&candidates).is_empty() {
            return Ok(());
        }
        let pos_index: PosIndex = Arc::new(Mutex::new(Arc::new({
            let mut map: HashMap<(Ipv4Addr, u16), usize> = HashMap::new();
            for (i, v) in candidates.iter().enumerate() {
                if let IpAddr::V4(ip) = v.ip {
                    map.entry((ip, v.port)).or_insert(i);
                }
            }
            map
        })));

        let specs = Arc::new(specs);
        let snis = Arc::new(snis);
        // Shared across tiers: the cap budget, the stop budget, the kept-pass
        // set, and the first error span the whole ladder, so cost stays
        // bounded exactly as in a single wave.
        let passed: Arc<Mutex<HashSet<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicU64::new(0));
        let errored = Arc::new(AtomicU64::new(0));
        let first_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let cap = cfg.stop.cap;
        let stop_found = cfg.stop.found as usize;
        let colo_filter = cfg.colo_filter.clone();

        let tier_count = tiers.len();
        for (tier_idx, tier_urls) in tiers.iter().enumerate() {
            // A tier-1 colo rejection removes the row, so recompute from the live
            // store: later tiers skip removed candidates instead of burning probes
            // on rows that can no longer hold a verdict.
            let v4_candidates = Arc::new(phase2_candidates(&self.progress.store));
            if v4_candidates.is_empty() {
                break;
            }
            let combos_per_candidate = (specs.len() * snis.len()) as u64;
            let total = v4_candidates.len() as u64 * combos_per_candidate;
            // Cumulative counters stay shared (final accounting spans the ladder);
            // progress events below report this tier's wave only.
            let base_done = completed.load(Ordering::Relaxed) + errored.load(Ordering::Relaxed);
            let base_attempts = attempts.load(Ordering::Relaxed);
            let next = Arc::new(AtomicU64::new(0));
            let milestones = Arc::new(AtomicU64::new(0));
            let terminal_sent = Arc::new(AtomicBool::new(false));
            let tier_urls = Arc::new(tier_urls.clone());
            let mut tasks = JoinSet::new();
            for _ in 0..p2.concurrency {
                let probe = self.handles.tunnel_probe.clone();
                let store = self.progress.store.clone();
                let events = self.events.clone();
                let cancel = cancel_rx.clone();
                let passed = passed.clone();
                let attempts = attempts.clone();
                let completed = completed.clone();
                let errored = errored.clone();
                let milestones = milestones.clone();
                let terminal_sent = terminal_sent.clone();
                let first_error = first_error.clone();
                let next = next.clone();
                let candidates = v4_candidates.clone();
                let pos_index = pos_index.clone();
                let specs = specs.clone();
                let snis = snis.clone();
                let tier_urls = tier_urls.clone();
                let p2 = p2.clone();
                let colo_filter = colo_filter.clone();
                let timeout_ms = cfg.timeout_ms;
                tasks.spawn(async move {
                    loop {
                        if *cancel.borrow()
                            || cap.is_some_and(|c| attempts.load(Ordering::Relaxed) >= u64::from(c))
                            || lock(&passed).len() >= stop_found
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
                        if lock(&passed).contains(&(ip, port)) {
                            continue;
                        }
                        if lock(&passed).len() >= stop_found {
                            break;
                        }
                        attempts.fetch_add(1, Ordering::Relaxed);
                        let probe_result = tokio::select! {
                            r = probe.probe(ProbeRequest {
                                spec,
                                dial_ip: ip,
                                preset: &p2.fragment,
                                custom: p2.custom_fragment.as_ref(),
                                sni: sni.as_deref(),
                                probe_urls: &tier_urls,
                                timeout_ms,
                            }) => Some(r),
                            _ = cancelled_signal(cancel.clone()) => None,
                        };
                        let Some(probe_result) = probe_result else {
                            break;
                        };
                        match probe_result {
                            Ok(result) => {
                                completed.fetch_add(1, Ordering::Relaxed);
                                let colo = result.colo.clone();
                                let colo_kept = !colo_rejected(&colo_filter, colo.as_deref());
                                let verdict = Phase2Verdict {
                                    passed: result.passed,
                                    fragment: p2.fragment.clone(),
                                    sni: sni.clone().unwrap_or_default(),
                                    latency_ms: result.latency_ms,
                                    error: None,
                                    config_index: Some(*config_idx),
                                    spec_index: Some(si as u32),
                                    verifier: result.verifier.and_then(parse_verifier),
                                    speed_test_mb_s: None,
                                };
                                if lock(&passed).len() >= stop_found && !result.passed {
                                    break;
                                }
                                let overshoot = lock(&passed).len() > stop_found;
                                if !colo_kept {
                                    remove_verdict_unless_passed(&store, ip, port, &pos_index);
                                } else if let Some(updated) = update_verdict_phase2(
                                    &store, ip, port, verdict, colo, &pos_index,
                                ) {
                                    if result.passed {
                                        // A kept pass counts toward the stop budget only
                                        // when its verdict is visible in the store: a row
                                        // removed by a racing colo rejection yields no row
                                        // to update, and such an invisible pass must not
                                        // consume stop budget.
                                        lock(&passed).insert((ip, port));
                                    }
                                    let _ = events.send(ScanEvent::Result(Box::new(updated)));
                                }
                                if overshoot {
                                    break;
                                }
                            }
                            Err(err) => {
                                // Record the failure before any stop check: a probe that
                                // errored after the stop budget filled must still count
                                // toward `errored` and `first_error` (the terminal
                                // `done == total` accounting depends on it). Only the
                                // verdict store/emit is skipped once stopped, matching
                                // the ok-but-failed path above.
                                errored.fetch_add(1, Ordering::Relaxed);
                                let msg = crate::configs::sanitize_error_text(&format!("{err:#}"));
                                let mut slot = lock(&first_error);
                                if slot.is_none() {
                                    *slot = Some(msg.clone());
                                }
                                if lock(&passed).len() >= stop_found {
                                    break;
                                }
                                let verdict = Phase2Verdict {
                                    passed: false,
                                    fragment: p2.fragment.clone(),
                                    sni: sni.clone().unwrap_or_default(),
                                    latency_ms: None,
                                    error: Some(msg),
                                    config_index: Some(*config_idx),
                                    spec_index: Some(si as u32),
                                    verifier: None,
                                    speed_test_mb_s: None,
                                };
                                if lock(&passed).len() >= stop_found {
                                    break;
                                }
                                if let Some(updated) = update_verdict_phase2(
                                    &store, ip, port, verdict, None, &pos_index,
                                ) {
                                    let _ = events.send(ScanEvent::Result(Box::new(updated)));
                                }
                            }
                        }
                        let done = completed.load(Ordering::Relaxed)
                            + errored.load(Ordering::Relaxed)
                            - base_done;
                        // Terminal only when the ladder ends here: a zero-pass
                        // non-final tier advances instead of finishing, so its
                        // 100% would read as completion. `passed` is final
                        // exactly when done == total (every combo accounted);
                        // the tier-end re-check below stays authoritative.
                        let terminal = done == total
                            && (!lock(&passed).is_empty() || tier_idx + 1 == tier_count);
                        if (terminal && !terminal_sent.swap(true, Ordering::Relaxed))
                            || (!terminal && claim_milestone(&milestones, done, PROGRESS_EVERY_P2))
                        {
                            let _ = events
                                .send(ScanEvent::Phase2Progress(Phase2Progress { done, total }));
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                });
            }
            while let Some(res) = tasks.join_next().await {
                res.map_err(|e| anyhow!("phase-2 task panicked: {e}"))??;
            }
            let tier_done =
                completed.load(Ordering::Relaxed) + errored.load(Ordering::Relaxed) - base_done;
            let tier_attempts = attempts.load(Ordering::Relaxed) - base_attempts;
            // Same ladder rule as the in-wave terminal above: only the final
            // tier (or a tier with kept passes, which stops the ladder)
            // reports completion. Post-join `passed` is race-free.
            let ladder_done = !lock(&passed).is_empty() || tier_idx + 1 == tier_count;
            if (tier_done > 0 || tier_attempts > 0)
                && ladder_done
                && !terminal_sent.swap(true, Ordering::Relaxed)
            {
                let _ = self.events.send(ScanEvent::Phase2Progress(Phase2Progress {
                    done: tier_done,
                    total,
                }));
            }

            if *cancel_rx.borrow() {
                return Ok(());
            }
            if cap.is_some_and(|c| attempts.load(Ordering::Relaxed) >= u64::from(c)) {
                break;
            }
            // Stop at the first tier with a kept pass; advance only on zero-pass
            // tiers. Every probe loop above already races cancellation via
            // select! + cancelled(), so an empty pass set here means the tier
            // genuinely yielded nothing.
            if !lock(&passed).is_empty() {
                break;
            }
            if tier_idx + 1 < tiers.len() {
                tracing::debug!("phase-2 tier yielded zero passes; advancing to the fallback tier");
            }
        }

        let attempts_val = attempts.load(Ordering::Relaxed);
        let completed_val = completed.load(Ordering::Relaxed);
        if attempts_val > 0 && completed_val == 0 {
            let reason_opt = lock(&first_error).clone();
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
        self.speed_test_phase(cfg, p2, &specs).await?;
        Ok(())
    }

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
                    body = self.handles.sub_fetch.fetch(entry) => body,
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
                let path = entry.to_owned();
                let text = tokio::task::spawn_blocking(move || {
                    read_config_file(std::path::Path::new(&path))
                })
                .await
                .unwrap_or_else(|e| Err(anyhow!("config file read task failed: {e}")))
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

fn parse_verifier(tag: &str) -> Option<Verifier> {
    match tag {
        "inline" => Some(Verifier::Inline),
        "xray" => Some(Verifier::Xray),
        _ => None,
    }
}

/// Engine-level tier list: the user's effective probe URLs first, then the
/// fixed public-trace + data-path fallback tier — unless the user already
/// configured exactly that tier, which stays single-tier. URL order is
/// significant (it decides which response yields the colo), so only an exact
/// ordered match dedupes.
fn phase2_tiers(user_urls: Vec<String>) -> Vec<Vec<String>> {
    let fallback: Vec<String> = FALLBACK_TIER_PROBE_URLS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if user_urls == fallback {
        vec![user_urls]
    } else {
        vec![user_urls, fallback]
    }
}

fn phase2_candidates_in(candidates: &[Verdict]) -> Vec<(Ipv4Addr, u16)> {
    candidates
        .iter()
        .filter(|v| v.latency_ms.is_some())
        .filter(|v| !v.phase2.as_ref().is_some_and(|p| p.passed))
        .filter_map(|v| match v.ip {
            IpAddr::V4(ip) => Some((ip, v.port)),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn phase2_candidates(store: &Store) -> Vec<(Ipv4Addr, u16)> {
    let guard = lock(store);
    phase2_candidates_in(&guard)
}

/// Mirrors cli/scan_args.rs load_wgconf_file: read at most one byte past the
/// cap so an oversized or pathological file cannot balloon memory inside the
/// blocking pool.
fn read_config_file(path: &std::path::Path) -> Result<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut buf = String::new();
    file.take(crate::api::types::MAX_WGCONF_BYTES as u64 + 1)
        .read_to_string(&mut buf)?;
    if buf.len() > crate::api::types::MAX_WGCONF_BYTES {
        bail!(
            "config file exceeds {} bytes",
            crate::api::types::MAX_WGCONF_BYTES
        );
    }
    Ok(buf)
}

fn redact_entry(entry: &str) -> String {
    let looks_like_path = entry.len() > 2
        && entry.as_bytes()[0].is_ascii_alphabetic()
        && entry.as_bytes()[1] == b':'
        && matches!(entry.as_bytes().get(2), Some(b'\\') | Some(b'/'));
    let Ok(mut url) = url::Url::parse(entry) else {
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
    if let Some(host) = url.host_str()
        && host.len() > 24
        && !host.contains('.')
    {
        let _ = url.set_host(Some("redacted"));
    }
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{FragmentPreset, Phase2Config, Verdict};
    use crate::configs::SubFetch;
    use crate::engine::store::Store;
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

    use crate::engine::test_helpers::FakeSub;

    #[derive(Clone)]
    struct FakeTunnelProbe {
        passed: std::sync::Arc<std::sync::Mutex<HashSet<Ipv4Addr>>>,
        attempts: std::sync::Arc<AtomicU64>,
        sni_pass: Option<&'static str>,
        always_err: std::sync::Arc<AtomicBool>,
        err_text: Option<&'static str>,
        err_ips: std::sync::Arc<std::sync::Mutex<HashSet<Ipv4Addr>>>,
        err_gate: Option<Arc<tokio::sync::Notify>>,
        rendezvous: Option<Arc<tokio::sync::Barrier>>,
        url_lists: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
        colo_for_all: Option<String>,
        colo_by_server: std::collections::HashMap<String, String>,
        gated_server: Option<String>,
        gate: Option<Arc<tokio::sync::Barrier>>,
        /// When set, a probe passes only if its URL list equals this tier
        /// (combined with the `passed` IP set). Pins ladder tests to a tier.
        pass_tier: Option<Vec<String>>,
        /// When set, a probe whose URL list equals this tier pends forever, so
        /// cancellation must win the select! race. Never real network.
        hang_tier: Option<Vec<String>>,
    }

    impl FakeTunnelProbe {
        fn new() -> Self {
            Self {
                passed: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                attempts: std::sync::Arc::new(AtomicU64::new(0)),
                sni_pass: None,
                always_err: std::sync::Arc::new(AtomicBool::new(false)),
                err_text: None,
                err_ips: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                err_gate: None,
                rendezvous: None,
                url_lists: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                colo_for_all: None,
                colo_by_server: std::collections::HashMap::new(),
                gated_server: None,
                gate: None,
                pass_tier: None,
                hang_tier: None,
            }
        }

        fn with_colo(self, colo: &str) -> Self {
            Self {
                colo_for_all: Some(colo.to_owned()),
                ..self
            }
        }

        fn pass(self, ip: Ipv4Addr) -> Self {
            lock(&self.passed).insert(ip);
            self
        }

        fn err_ip(self, ip: Ipv4Addr) -> Self {
            lock(&self.err_ips).insert(ip);
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
            let server = req.spec.server.clone();
            let urls = req.probe_urls.to_vec();
            Box::pin(async move {
                if let Some(barrier) = &this.rendezvous {
                    barrier.wait().await;
                }
                if this.gated_server.as_deref() == Some(server.as_str())
                    && let Some(gate) = &this.gate
                {
                    gate.wait().await;
                }
                this.attempts.fetch_add(1, Ordering::Relaxed);
                lock(&this.url_lists).push(urls.clone());
                if this.hang_tier.as_ref().is_some_and(|t| *t == urls) {
                    return std::future::pending::<Result<TunnelResult>>().await;
                }
                if this.always_err.load(Ordering::Relaxed) {
                    return Err(anyhow!("simulated spawn failure"));
                }
                if let Some(text) = this.err_text {
                    return Err(anyhow!("{text}"));
                }
                if lock(&this.err_ips).contains(&dial_ip) {
                    if let Some(gate) = &this.err_gate {
                        gate.notified().await;
                    }
                    return Err(anyhow!("simulated probe failure"));
                }
                if let Some(want) = this.sni_pass
                    && sni.as_deref() != Some(want)
                {
                    return Ok(TunnelResult {
                        passed: false,
                        latency_ms: None,
                        colo: None,
                        verifier: None,
                    });
                }
                let tier_ok = this.pass_tier.as_ref().is_none_or(|t| *t == urls);
                let passed = tier_ok && lock(&this.passed).contains(&dial_ip);
                let colo = this
                    .colo_by_server
                    .get(&server)
                    .cloned()
                    .or_else(|| this.colo_for_all.clone());
                Ok(TunnelResult {
                    passed,
                    latency_ms: passed.then_some(7),
                    colo,
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

    struct HangingSub;

    impl SubFetch for HangingSub {
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
            Box::pin(async { std::future::pending::<Result<String>>().await })
        }
    }

    const VLESS: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443";
    const VLESS_B: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0001@5.6.7.8:443";

    fn fallback_tier() -> Vec<String> {
        super::FALLBACK_TIER_PROBE_URLS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[tokio::test]
    async fn colo_filter_drops_known_foreign_colo_results_in_phase2() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .with_colo("FRA")
            .pass("203.0.113.1".parse().unwrap())
            .pass("203.0.113.2".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(2, None);
        cfg.colo_filter = vec!["HKG".to_owned()];
        // Single-tier pin: the user tier IS the fixed fallback tier, so the
        // ladder collapses to today's single wave and the attempt count stays
        // exact (ladder coverage lives in the tier tests below).
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: fallback_tier(),
            concurrency: 2,
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 2);
        assert!(
            c.results().iter().all(|v| v.colo.as_deref() != Some("FRA")),
            "known foreign-colo verdicts must never be stored: {:#?}",
            c.results()
        );
        assert!(
            c.results().iter().all(|v| v.phase2.is_none()),
            "rejected candidates must not keep a phase-2 verdict row"
        );
    }

    #[tokio::test]
    async fn colo_filter_keeps_matching_and_unknown_colo_results_in_phase2() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new()
            .with_colo("hkg")
            .pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe);
        let mut cfg = ok_cfg(2, None);
        cfg.colo_filter = vec!["HKG".to_owned()];
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let kept = results
            .iter()
            .find(|v| v.ip == "203.0.113.1".parse::<IpAddr>().unwrap())
            .expect("the matching-colo endpoint must be kept");
        assert_eq!(kept.colo.as_deref(), Some("hkg"));
        assert!(kept.phase2.as_ref().is_some_and(|p| p.passed));
    }

    /// F-02 regression: a kept-colo pass stored by one worker must survive a
    /// rejected-colo removal by a racing worker. Deterministic: both workers
    /// rendezvous past the dedup check, the rejected probe is gated until the
    /// kept pass is observed in the event stream, then released.
    #[tokio::test]
    async fn kept_colo_pass_survives_racing_rejected_colo_removal() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let mut probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        probe.rendezvous = Some(rendezvous);
        probe
            .colo_by_server
            .insert("1.2.3.4".to_owned(), "DFW".to_owned());
        probe
            .colo_by_server
            .insert("5.6.7.8".to_owned(), "FRA".to_owned());
        probe.gated_server = Some("5.6.7.8".to_owned());
        probe.gate = Some(gate.clone());
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(8, None);
        cfg.colo_filter = vec!["DFW".to_owned()];
        cfg.phase2 = Some(p2_cfg(&[VLESS, VLESS_B], &[]));
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Ok(ScanEvent::Result(v)) if v.phase2.as_ref().is_some_and(|p| p.passed) => {
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => panic!("event stream closed before the kept pass landed"),
                }
            }
        })
        .await
        .expect("kept-colo pass must be stored and emitted");
        gate.wait().await;
        handle
            .await
            .expect("scan task panicked")
            .expect("scan failed");
        let results = c.results();
        let kept = results
            .iter()
            .find(|v| v.ip == "203.0.113.1".parse::<IpAddr>().unwrap())
            .expect("the kept-colo verdict row must survive the racing removal");
        assert_eq!(kept.colo.as_deref(), Some("DFW"));
        assert!(kept.phase2.as_ref().is_some_and(|p| p.passed));
        assert!(
            results.iter().all(|v| v.colo.as_deref() != Some("FRA")),
            "no rejected-colo verdict may be stored: {results:#?}"
        );
    }

    /// Reverse order pins the decided contract: a rejected-colo removal first,
    /// then a kept pass with no row to update, leaves no phantom row and
    /// consumes no stop budget (the pass is neither stored nor counted).
    #[tokio::test]
    async fn rejected_colo_first_then_kept_pass_leaves_no_phantom_row() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let rendezvous = Arc::new(tokio::sync::Barrier::new(2));
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let mut probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        probe.rendezvous = Some(rendezvous);
        probe
            .colo_by_server
            .insert("1.2.3.4".to_owned(), "DFW".to_owned());
        probe
            .colo_by_server
            .insert("5.6.7.8".to_owned(), "FRA".to_owned());
        probe.gated_server = Some("1.2.3.4".to_owned());
        probe.gate = Some(gate.clone());
        let c = p2_controller(t, FakeSub(""), probe);
        let mut cfg = ok_cfg(8, None);
        cfg.colo_filter = vec!["DFW".to_owned()];
        cfg.phase2 = Some(p2_cfg(&[VLESS, VLESS_B], &[]));
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let gone = c
                    .results()
                    .iter()
                    .all(|v| v.ip != "203.0.113.1".parse::<IpAddr>().unwrap());
                if gone {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rejected-colo removal must drop the phase-1 row");
        gate.wait().await;
        let summary = handle
            .await
            .expect("scan task panicked")
            .expect("scan failed");
        let results = c.results();
        assert!(
            results
                .iter()
                .all(|v| v.ip != "203.0.113.1".parse::<IpAddr>().unwrap()),
            "no phantom row may appear for the removed candidate: {results:#?}"
        );
        assert!(
            results
                .iter()
                .all(|v| !v.phase2.as_ref().is_some_and(|p| p.passed)),
            "nothing may count as verified: {results:#?}"
        );
        assert_eq!(
            summary.found, 0,
            "the invisible pass must not consume the stop budget"
        );
    }

    /// F-03 regression: a probe that errors after the stop budget filled must
    /// still count toward `errored` (terminal done == total accounting).
    /// Deterministic under any candidate order: phase-1 workers rendezvous so
    /// both rows are stored; phase-2 workers rendezvous past the take/dedup
    /// checks; the error probe then pends on a Notify until the pass is
    /// observed in the event stream, so the error always lands post-stop.
    #[tokio::test]
    async fn phase2_error_after_stop_still_counts_into_progress_done() {
        let mut t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        t.rendezvous = Some(Arc::new(tokio::sync::Barrier::new(2)));
        let gate = Arc::new(tokio::sync::Notify::new());
        let phase2_rendezvous = Arc::new(tokio::sync::Barrier::new(2));
        let mut probe = FakeTunnelProbe::new()
            .pass("203.0.113.1".parse().unwrap())
            .err_ip("203.0.113.2".parse().unwrap());
        probe.rendezvous = Some(phase2_rendezvous);
        probe.err_gate = Some(gate.clone());
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(1, None);
        cfg.concurrency = 2;
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            concurrency: 2,
            ..Default::default()
        });
        let pool = ranges::CidrPool::parse("203.0.113.1/32\n203.0.113.2/32").unwrap();
        let handle = tokio::spawn({
            let c = c.clone();
            async move { c.run_seeded_with_pool(cfg, 1, pool).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Ok(ScanEvent::Result(v)) if v.phase2.as_ref().is_some_and(|p| p.passed) => {
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => panic!("event stream closed before the pass landed"),
                }
            }
        })
        .await
        .expect("the passing verdict must be stored and emitted");
        gate.notify_one();
        handle
            .await
            .expect("scan task panicked")
            .expect("scan failed");
        let mut max_done = 0u64;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Phase2Progress(p) = ev {
                max_done = max_done.max(p.done);
            }
        }
        // completed(.1 pass) = 1 + errored(.2) = 1 → done must reach total (2).
        assert_eq!(
            max_done, 2,
            "post-stop errors must count toward progress done"
        );
    }

    #[tokio::test]
    async fn phase2_skips_v6_candidates() {
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
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 1);
        let results = c.results();
        let v4 = results.iter().find(|v| !v.ip.is_ipv6()).unwrap();
        assert!(v4.phase2.as_ref().unwrap().passed);
        assert_eq!(
            results
                .iter()
                .filter(|v| v.ip.is_ipv6())
                .filter(|v| v.latency_ms.is_some())
                .count(),
            2
        );
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
        assert_eq!(results.len(), 3, "two successes plus the failure row");
        let succeeded = results.iter().filter(|v| v.latency_ms.is_some()).count();
        assert_eq!(succeeded, 2);
        for v in results.iter().filter(|v| v.latency_ms.is_some()) {
            let p2 = v.phase2.as_ref().expect("phase-2 verdict attached");
            assert!(p2.passed, "{v:?}");
            assert_eq!(p2.fragment, FragmentPreset::Off);
            assert_eq!(p2.sni, "");
            assert_eq!(p2.latency_ms, Some(7));
        }
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 2);

        let mut phase2_events = 0;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Result(v) = e
                && v.phase2.is_some()
            {
                phase2_events += 1;
            }
        }
        assert_eq!(phase2_events, 2, "updated verdicts must be re-emitted");
    }

    #[tokio::test]
    async fn phase2_marks_failed_attempts_without_aborting() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(!p2.passed);
        assert_eq!(p2.fragment, FragmentPreset::Off);
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
        assert_eq!(p2.config_index, Some(0));
    }

    #[tokio::test]
    async fn phase2_probes_every_url_with_one_spawn_per_combo() {
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
        let lists = lock(&probe.url_lists);
        assert_eq!(lists.len(), 2);
        assert!(lists.iter().all(|l| l == &want), "{lists:?}");
        for v in c.results().iter().filter(|v| v.latency_ms.is_some()) {
            assert_eq!(v.phase2.as_ref().unwrap().config_index, Some(0));
        }
    }

    #[test]
    fn phase2_tiers_dedupes_an_exact_fallback_config_into_one_tier() {
        let fb = fallback_tier();
        assert_eq!(phase2_tiers(fb.clone()), vec![fb]);
        let user = vec!["https://example.com/".to_owned()];
        assert_eq!(
            phase2_tiers(user.clone()),
            vec![user, fallback_tier()],
            "any other user tier ladders into the fixed fallback tier"
        );
    }

    #[tokio::test]
    async fn phase2_zero_pass_tier_advances_to_the_fallback_tier() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        probe.pass_tier = Some(fallback_tier());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec!["https://example.com/".to_owned()],
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            2,
            "one sweep per tier: the zero-pass user tier plus the fallback tier"
        );
        let lists = lock(&probe.url_lists);
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0], vec!["https://example.com/".to_owned()]);
        assert_eq!(lists[1], fallback_tier());
        drop(lists);
        let results = c.results();
        let p2 = results[0]
            .phase2
            .as_ref()
            .expect("the tier-2 pass must upgrade the tier-1 fail verdict");
        assert!(p2.passed);
        assert_eq!(p2.latency_ms, Some(7));
    }

    #[tokio::test]
    async fn phase2_first_pass_tier_never_runs_the_fallback() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec!["https://example.com/".to_owned()],
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            1,
            "a passing first tier must stop the ladder with today's single-wave cost"
        );
        let lists = lock(&probe.url_lists);
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0], vec!["https://example.com/".to_owned()]);
        drop(lists);
        assert!(c.results()[0].phase2.as_ref().unwrap().passed);
    }

    #[tokio::test]
    async fn phase2_ladder_emits_a_single_terminal_progress_event() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        probe.pass_tier = Some(fallback_tier());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec!["https://example.com/".to_owned()],
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            2,
            "both tiers ran: the zero-pass user tier plus the fallback tier"
        );
        let mut terminals = 0u32;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Phase2Progress(p) = ev {
                if p.done == p.total {
                    terminals += 1;
                }
            }
        }
        assert_eq!(
            terminals, 1,
            "one terminal event for the whole ladder, on the final tier"
        );
    }

    #[tokio::test]
    async fn phase2_fallback_config_is_single_tier_identical_to_today() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: fallback_tier(),
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            1,
            "a user tier equal to the fallback tier runs exactly one wave"
        );
        let lists = lock(&probe.url_lists);
        assert_eq!(*lists, vec![fallback_tier()]);
        drop(lists);
        assert!(c.results()[0].phase2.as_ref().unwrap().passed);
    }

    #[tokio::test]
    async fn phase2_tier_advance_is_cancel_safe() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new();
        probe.hang_tier = Some(fallback_tier());
        // Tier 1 fails fast (nothing passes); tier 2 hangs, so cancellation
        // must win the select! race exactly as in a single wave.
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec!["https://example.com/".to_owned()],
            concurrency: 2,
            ..Default::default()
        });
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if lock(&probe.url_lists).iter().any(|l| *l == fallback_tier()) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tier 2 must start after the zero-pass tier 1");
        c.cancel();
        let summary = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("cancel must abort the hanging tier-2 probe")
            .unwrap()
            .unwrap();
        assert!(summary.cancelled, "summary must report the cancel");
        assert_eq!(summary.found, 0);
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            2,
            "tier-1 sweep plus the single started tier-2 probe"
        );
    }

    #[tokio::test]
    async fn phase2_colo_rejected_zero_pass_tier_skips_removed_candidates() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new()
            .with_colo("FRA")
            .pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(2, None);
        cfg.colo_filter = vec!["HKG".to_owned()];
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            probe_urls: vec!["https://example.com/".to_owned()],
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        // The tier-1 pass is colo-rejected: its row is removed, zero passes are
        // kept, and the recomputed tier-2 candidate list is empty — no probe
        // may burn on a row that can no longer hold a verdict.
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 1);
        let results = c.results();
        assert!(
            results
                .iter()
                .all(|v| v.ip != "203.0.113.1".parse::<IpAddr>().unwrap()),
            "the colo-rejected row stays removed: {results:#?}"
        );
        assert!(
            results.iter().all(|v| v.phase2.is_none()),
            "nothing may hold a phase-2 verdict: {results:#?}"
        );
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
        assert_eq!(
            redact_entry("vmess://Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA"),
            "vmess://redacted"
        );
        assert_eq!(redact_entry("C:\\users\\me\\config.json"), "config.json");
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
    fn read_config_file_caps_at_max_wgconf_bytes() {
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-p2-readcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let at_cap = dir.join("at-cap.json");
        std::fs::write(&at_cap, vec![b' '; crate::api::types::MAX_WGCONF_BYTES]).unwrap();
        assert!(
            read_config_file(&at_cap).is_ok(),
            "a file exactly at the cap must read fine"
        );
        let over = dir.join("over-cap.json");
        std::fs::write(&over, vec![b' '; crate::api::types::MAX_WGCONF_BYTES + 1]).unwrap();
        let err = read_config_file(&over).unwrap_err().to_string();
        assert!(
            err.contains(&format!(
                "config file exceeds {} bytes",
                crate::api::types::MAX_WGCONF_BYTES
            )),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F11 regression: a valid-but-oversized config file must be rejected at
    /// the read boundary, not parsed. Padded with whitespace so the JSON
    /// itself is well-formed — only the size cap may refuse it.
    #[tokio::test]
    async fn phase2_config_file_over_the_byte_cap_is_rejected() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-p2-overcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000"}]}]}}]}"#
            .to_owned();
        body.push_str(&" ".repeat(crate::api::types::MAX_WGCONF_BYTES + 1 - body.len()));
        let path = dir.join("padded.json");
        std::fs::write(&path, &body).unwrap();
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[path.to_str().unwrap()], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        assert!(
            err.to_string().contains("no usable configs"),
            "an over-cap config file must be rejected, got: {err:#}"
        );
        assert_eq!(
            probe.attempts.load(Ordering::Relaxed),
            0,
            "an over-cap config file must never reach probing"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
                fragment: FragmentPreset::Light,
                sni: "".to_owned(),
                latency_ms: Some(42),
                error: None,
                config_index: Some(0),
                spec_index: None,
                verifier: Some(Verifier::Xray),
                speed_test_mb_s: None,
            }),
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        }]));
        let failed = Phase2Verdict {
            passed: false,
            fragment: FragmentPreset::Off,
            sni: "".to_owned(),
            latency_ms: None,
            error: Some("spawn failed".to_owned()),
            config_index: None,
            spec_index: None,
            verifier: None,
            speed_test_mb_s: None,
        };
        let index: PosIndex = PosIndex::new(Mutex::new(Arc::new(HashMap::from([(
            ("203.0.113.1".parse().unwrap(), 443),
            0,
        )]))));
        let updated = update_verdict_phase2(
            &store,
            "203.0.113.1".parse().unwrap(),
            443,
            failed.clone(),
            None,
            &index,
        );
        assert!(updated.is_none(), "a pass must never be downgraded");
        {
            let row = &lock(&store)[0];
            assert!(row.phase2.as_ref().unwrap().passed);
            assert_eq!(row.colo.as_deref(), Some("FRA"));
        }

        let stale_index = PosIndex::new(Mutex::new(Arc::new(HashMap::from([(
            ("203.0.113.1".parse().unwrap(), 443),
            7_usize,
        )]))));
        let via_fallback = update_verdict_phase2(
            &store,
            "203.0.113.1".parse().unwrap(),
            443,
            failed.clone(),
            None,
            &stale_index,
        );
        assert!(
            via_fallback.is_none(),
            "fallback must find the row and honor the pass guard"
        );
        let rebuilt = lock(&stale_index);
        assert_eq!(
            rebuilt.get(&("203.0.113.1".parse::<Ipv4Addr>().unwrap(), 443)),
            Some(&0),
            "fallback must rebuild the index from the store"
        );
    }

    #[tokio::test]
    async fn cancel_during_phase1_stops_phase2_work() {
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
    async fn phase2_records_the_overshoot_pass_past_the_found_stop() {
        let mut t = FakeTransport::new()
            .ok("203.0.113.0".parse().unwrap(), 443, 50)
            .ok("203.0.113.1".parse().unwrap(), 443, 50);
        t.rendezvous = Some(Arc::new(tokio::sync::Barrier::new(2)));
        let mut probe = FakeTunnelProbe::new()
            .pass("203.0.113.0".parse().unwrap())
            .pass("203.0.113.1".parse().unwrap());
        probe.rendezvous = Some(Arc::new(tokio::sync::Barrier::new(2)));
        let c = p2_controller(t, FakeSub(""), probe);
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        cfg.concurrency = 2;
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|v| v.phase2.as_ref().is_some_and(|p| p.passed)),
            "every pass must land its verdict, even past the stop quota"
        );
    }

    #[tokio::test]
    async fn phase2_terminal_progress_emitted_once() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(1, None);
        // Single-tier pin: the user tier IS the fixed fallback tier, so the
        // failing wave runs once and the terminal event fires exactly once
        // (multi-tier terminal accounting is pinned by the ladder tests).
        cfg.phase2 = Some(Phase2Config {
            configs: vec![VLESS.to_owned()],
            snis: vec!["a.me".to_owned(), "b.me".to_owned()],
            probe_urls: fallback_tier(),
            concurrency: 2,
            ..Default::default()
        });
        run_local(&c, cfg, 1).await.unwrap();
        let mut terminal = 0u32;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Phase2Progress(p) = e
                && p.done == p.total
            {
                terminal += 1;
            }
        }
        assert_eq!(terminal, 1, "terminal progress must fire exactly once");
    }

    #[tokio::test]
    async fn cancel_during_config_parse_aborts_promptly() {
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
        assert_eq!(
            progress, 2,
            "the terminal progress event must report done == executed combos"
        );
    }

    #[tokio::test]
    async fn cancel_during_tunnel_probe_aborts_promptly() {
        struct HangingProbe;
        impl TunnelProbe for HangingProbe {
            fn probe(
                &self,
                _req: ProbeRequest<'_>,
            ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
                Box::pin(async { std::future::pending::<Result<TunnelResult>>().await })
            }
        }
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 10);
        let c = Arc::new(ScanController::with_probes(
            Arc::new(t),
            Arc::new(FakeSub("")),
            Arc::new(HangingProbe),
        ));
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        let handle = tokio::spawn({
            let c = c.clone();
            async move { run_local(&c, cfg, 1).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c.cancel();
        let summary = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("cancel must abort hanging tunnel probe")
            .unwrap()
            .unwrap();
        assert!(summary.cancelled, "summary must report the cancel");
    }

    #[tokio::test]
    async fn phase2_error_attempts_count_into_progress_done() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let mut probe = FakeTunnelProbe::new();
        probe.err_text = Some("dial vless://SecretUser:SecretPass123@1.2.3.4:443: refused");
        let c = p2_controller(t, FakeSub(""), probe);
        let mut rx = c.subscribe();
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        assert!(
            run_local(&c, cfg, 1).await.is_err(),
            "an all-error phase 2 must still fail the run"
        );
        let mut terminal_done = None;
        while let Ok(e) = rx.try_recv() {
            if let ScanEvent::Phase2Progress(p) = e
                && p.done == p.total
            {
                terminal_done = Some(p.done);
            }
        }
        assert_eq!(
            terminal_done,
            Some(2),
            "errored attempts are executed combos and must reach done == total"
        );
    }

    #[tokio::test]
    async fn phase2_error_verdicts_redact_config_credentials() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 50);
        let mut probe = FakeTunnelProbe::new();
        probe.err_text = Some("dial vless://SecretUser:SecretPass123@1.2.3.4:443: refused");
        let c = p2_controller(t, FakeSub(""), probe);
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        let _ = run_local(&c, cfg, 1).await;
        let results = c.results();
        let p2 = results[0].phase2.as_ref().expect("error verdict stored");
        assert!(!p2.passed);
        assert_eq!(
            p2.config_index,
            Some(0),
            "error verdicts keep config attribution"
        );
        assert_eq!(
            p2.verifier, None,
            "a probe that never ran claims no verifier"
        );
        let err = p2.error.as_deref().expect("error text present");
        assert!(!err.contains("SecretUser"), "{err}");
        assert!(!err.contains("SecretPass123"), "{err}");
        assert!(err.contains("***@1.2.3.4:443"), "{err}");
    }

    #[test]
    fn verifier_tag_parsing_is_strict_and_unknown_tags_are_none() {
        assert_eq!(parse_verifier("inline"), Some(Verifier::Inline));
        assert_eq!(parse_verifier("xray"), Some(Verifier::Xray));
        assert_eq!(parse_verifier("XRay"), None, "tags are lowercase");
        assert_eq!(parse_verifier(""), None);
        assert_eq!(parse_verifier("hybrid"), None);
        assert_eq!(parse_verifier("xray "), None, "no implicit trim");
    }

    #[test]
    fn mixed_ok_and_err_probe_sequences_count_both_and_stop_on_found() {
        // The verdict store must record every outcome, not just successes:
        // errors carry diagnostics, oks carry progress.
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        let ok = Verdict {
            ip: IpAddr::V4("203.0.113.1".parse().unwrap()),
            port: 443,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: Some(Phase2Verdict {
                passed: true,
                fragment: FragmentPreset::Off,
                sni: String::new(),
                latency_ms: Some(30),
                error: None,
                config_index: Some(0),
                spec_index: None,
                verifier: Some(Verifier::Xray),
                speed_test_mb_s: None,
            }),
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        let mut err = ok.clone();
        err.ip = IpAddr::V4("203.0.113.2".parse().unwrap());
        err.phase2 = Some(Phase2Verdict {
            passed: false,
            latency_ms: None,
            error: Some("handshake failed".to_owned()),
            ..err.phase2.clone().unwrap()
        });
        crate::engine::store_seed(&c, vec![ok, err]);
        let results = c.results();
        assert_eq!(results.len(), 2, "both outcomes are stored");
        assert!(results[0].phase2.as_ref().unwrap().passed);
        assert!(!results[1].phase2.as_ref().unwrap().passed);
        assert!(results[1].phase2.as_ref().unwrap().error.is_some());
    }

    // --- retained parsed specs for export (F2) ---

    #[tokio::test]
    async fn successful_phase2_retains_parsed_specs_with_raw_entry_indexes() {
        let sub_vless = "vless://11112222-3333-4444-5555-666677778888@origin.example.com:443?security=tls#sub-tag";
        let sub_body: &'static str = Box::leak(format!("{sub_vless}\n").into_boxed_str());
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(sub_body), probe);
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&["https://sub.example.com/x", VLESS], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        let specs = c.phase2_specs();
        assert_eq!(specs.len(), 2, "subscription expands + direct URI");
        assert_eq!(specs[0].1, 0, "expanded spec keeps its raw entry index");
        assert_eq!(specs[1].1, 1);
        assert_eq!(specs[0].0.tag.as_deref(), Some("sub-tag"));
        assert_eq!(specs[1].0.user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000");
        // The raw configs remain available for the direct-URI fast path.
        assert_eq!(c.phase2_configs()[1], VLESS);
    }

    #[tokio::test]
    async fn failed_parse_leaves_retained_specs_empty() {
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub("vless://bad"), probe);
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&["https://sub.example.com/x"], &[]));
        let err = run_local(&c, cfg, 1).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no usable configs") || msg.contains("no configs to verify with"),
            "{err:#}"
        );
        assert!(
            c.phase2_specs().is_empty(),
            "failed parse must leave the paired state with empty specs, \
             never specs retained from a previous run"
        );
        assert_eq!(
            c.phase2_configs(),
            vec!["https://sub.example.com/x".to_owned()],
            "the raw configs side of the pair is still retained"
        );
    }

    // The stale-pair regression: a successful phase-2 run retains specs, then
    // a run whose parse fails (or a WARP run) must reset the pair — the old
    // code wrote configs unconditionally but specs only on parse success, so
    // run 1's specs dangled next to run 2's configs.
    #[tokio::test]
    async fn failed_parse_run_resets_specs_retained_by_a_previous_run() {
        let sub_vless = "vless://11112222-3333-4444-5555-666677778888@origin.example.com:443?security=tls#sub-tag";
        let sub_body: &'static str = Box::leak(format!("{sub_vless}\n").into_boxed_str());
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new().pass("203.0.113.1".parse().unwrap());
        let c = p2_controller(t, FakeSub(sub_body), probe);
        // Run 1: parse succeeds, specs retained.
        let mut cfg = ok_cfg(2, None);
        cfg.phase2 = Some(p2_cfg(&["https://sub.example.com/x"], &[]));
        run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(c.phase2_specs().len(), 1, "run 1 retains its parsed spec");
        // Run 2: every entry fails to parse — specs must not survive.
        let mut cfg2 = ok_cfg(2, None);
        cfg2.phase2 = Some(p2_cfg(&["vless://bad"], &[]));
        let err = run_local(&c, cfg2, 1).await.unwrap_err();
        assert!(err.to_string().contains("no usable configs"), "{err:#}");
        assert!(
            c.phase2_specs().is_empty(),
            "run 2 must reset the pair, not keep run 1's specs"
        );
        assert_eq!(
            c.phase2_configs(),
            vec!["vless://bad".to_owned()],
            "run 2's raw configs are retained alongside the reset specs"
        );
    }
}
