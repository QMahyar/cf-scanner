use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::store::{PosIndex, remove_verdict, update_verdict_phase2};
use super::{ScanController, cancelled_signal, claim_milestone, colo_rejected, lock};
use crate::api::types::{
    Phase2Config, Phase2Progress, Phase2Verdict, ScanConfig, ScanEvent, Verifier,
};
use crate::configs::{OutboundSpec, parse_subscription, parse_uri, parse_xray_json};
use crate::verify::ProbeRequest;

const PROGRESS_EVERY_P2: u64 = 32;

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
        let snis: Vec<Option<String>> = if p2.snis.is_empty() {
            vec![None]
        } else {
            p2.snis.iter().map(|s| Some(s.clone())).collect()
        };
        let probe_urls = p2.effective_probe_urls();
        let candidates = lock(&self.store).clone();
        let v4_candidates: Vec<(Ipv4Addr, u16)> = candidates
            .iter()
            .filter(|v| v.latency_ms.is_some())
            .filter(|v| !v.phase2.as_ref().is_some_and(|p| p.passed))
            .filter_map(|v| match v.ip {
                IpAddr::V4(ip) => Some((ip, v.port)),
                IpAddr::V6(_) => None,
            })
            .collect();
        if v4_candidates.is_empty() {
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

        let combos_per_candidate = (specs.len() * snis.len()) as u64;
        let total = v4_candidates.len() as u64 * combos_per_candidate;
        let next = Arc::new(AtomicU64::new(0));
        let passed: Arc<Mutex<HashSet<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicU64::new(0));
        let errored = Arc::new(AtomicU64::new(0));
        let milestones = Arc::new(AtomicU64::new(0));
        let terminal_sent = Arc::new(AtomicBool::new(false));
        let first_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let cap = cfg.stop.cap;
        let stop_found = cfg.stop.found as usize;
        let colo_filter = cfg.colo_filter.clone();

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
            let errored = errored.clone();
            let milestones = milestones.clone();
            let terminal_sent = terminal_sent.clone();
            let first_error = first_error.clone();
            let next = next.clone();
            let candidates = v4_candidates.clone();
            let pos_index = pos_index.clone();
            let specs = specs.clone();
            let snis = snis.clone();
            let probe_urls = probe_urls.clone();
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
                            probe_urls: &probe_urls,
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
                                verifier: result.verifier.and_then(parse_verifier),
                                speed_test_mbps: None,
                            };
                            if result.passed && colo_kept {
                                lock(&passed).insert((ip, port));
                            }
                            if lock(&passed).len() >= stop_found && !result.passed {
                                break;
                            }
                            let overshoot = lock(&passed).len() > stop_found;
                            if !colo_kept {
                                remove_verdict(&store, ip, port, &pos_index);
                            } else if let Some(updated) =
                                update_verdict_phase2(&store, ip, port, verdict, colo, &pos_index)
                            {
                                let _ = events.send(ScanEvent::Result(Box::new(updated)));
                            }
                            if overshoot {
                                break;
                            }
                        }
                        Err(err) => {
                            if lock(&passed).len() >= stop_found {
                                break;
                            }
                            errored.fetch_add(1, Ordering::Relaxed);
                            let msg = crate::configs::sanitize_error_text(&format!("{err:#}"));
                            let mut slot = lock(&first_error);
                            if slot.is_none() {
                                *slot = Some(msg.clone());
                            }
                            let verdict = Phase2Verdict {
                                passed: false,
                                fragment: p2.fragment.clone(),
                                sni: sni.clone().unwrap_or_default(),
                                latency_ms: None,
                                error: Some(msg),
                                config_index: Some(*config_idx),
                                verifier: None,
                                speed_test_mbps: None,
                            };
                            if lock(&passed).len() >= stop_found {
                                break;
                            }
                            if let Some(updated) =
                                update_verdict_phase2(&store, ip, port, verdict, None, &pos_index)
                            {
                                let _ = events.send(ScanEvent::Result(Box::new(updated)));
                            }
                        }
                    }
                    let done = completed.load(Ordering::Relaxed) + errored.load(Ordering::Relaxed);
                    let terminal = done == total;
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
        let done = completed.load(Ordering::Relaxed) + errored.load(Ordering::Relaxed);
        if (done > 0 || attempts.load(Ordering::Relaxed) > 0)
            && !terminal_sent.swap(true, Ordering::Relaxed)
        {
            let _ = self
                .events
                .send(ScanEvent::Phase2Progress(Phase2Progress { done, total }));
        }

        if *cancel_rx.borrow() {
            return Ok(());
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
                let path = entry.to_owned();
                let text = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
                    .await
                    .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
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
        rendezvous: Option<Arc<tokio::sync::Barrier>>,
        url_lists: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
        colo_for_all: Option<String>,
    }

    impl FakeTunnelProbe {
        fn new() -> Self {
            Self {
                passed: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
                attempts: std::sync::Arc::new(AtomicU64::new(0)),
                sni_pass: None,
                always_err: std::sync::Arc::new(AtomicBool::new(false)),
                err_text: None,
                rendezvous: None,
                url_lists: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                colo_for_all: None,
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
                if let Some(barrier) = &this.rendezvous {
                    barrier.wait().await;
                }
                this.attempts.fetch_add(1, Ordering::Relaxed);
                lock(&this.url_lists).push(urls);
                if this.always_err.load(Ordering::Relaxed) {
                    return Err(anyhow!("simulated spawn failure"));
                }
                if let Some(text) = this.err_text {
                    return Err(anyhow!("{text}"));
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
                let passed = lock(&this.passed).contains(&dial_ip);
                Ok(TunnelResult {
                    passed,
                    latency_ms: passed.then_some(7),
                    colo: this.colo_for_all.clone(),
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
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
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
                verifier: Some(Verifier::Xray),
                speed_test_mbps: None,
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
            verifier: None,
            speed_test_mbps: None,
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
        cfg.phase2 = Some(p2_cfg(&[VLESS], &["a.me", "b.me"]));
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

    #[tokio::test]
    async fn phase2_only_summary_counts_verified_endpoints_only() {
        let t = FakeTransport::new()
            .ok("203.0.113.1".parse().unwrap(), 443, 50)
            .ok("203.0.113.2".parse().unwrap(), 443, 10);
        let probe = FakeTunnelProbe::new();
        let c = p2_controller(t, FakeSub(""), probe.clone());
        let mut cfg = ok_cfg(2, None);
        run_local(&c, cfg.clone(), 1).await.unwrap();
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 0);
        cfg.phase2 = Some(p2_cfg(&[VLESS], &[]));
        cfg.phase2_only = true;
        let summary = run_local(&c, cfg, 1).await.unwrap();
        assert_eq!(
            summary.found, 0,
            "failed verification must not count as found"
        );
        assert_eq!(
            summary.scanned, 0,
            "phase2_only runs add no phase-1 probe counts"
        );
        assert_eq!(probe.attempts.load(Ordering::Relaxed), 2);
    }
}
