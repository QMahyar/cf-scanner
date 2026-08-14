//! Phase-2 real-config verification: parses user configs (URIs, subscriptions,
//! local xray JSON) and verifies phase-1 candidates through tunnel probes with
//! fragment presets and SNI combos, updating verdicts in place.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::{ScanController, Store};
use crate::api::types::{
    FragmentPreset, Phase2Config, Phase2Verdict, ScanConfig, ScanEvent, Verdict,
};
use crate::configs::{OutboundSpec, parse_subscription, parse_uri, parse_xray_json};
use crate::verify::ProbeRequest;

impl ScanController {
    /// Verifies every phase-1 candidate through the user's configs, trying
    /// (config, SNI) combos until one passes per candidate. Updates verdicts
    /// in place and re-emits them so clients see the fragment/SNI detail.
    pub(super) async fn verify_phase(&self, cfg: &ScanConfig, p2: &Phase2Config) -> Result<()> {
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
        let passed_ips: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::new(Mutex::new(HashSet::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicU64::new(0));
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
                    let completed = completed.clone();
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
                                completed.fetch_add(1, Ordering::Relaxed);
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

        if attempts.load(Ordering::Relaxed) > 0 && completed.load(Ordering::Relaxed) == 0 {
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
                // File reads are blocking; keep them off the tokio workers.
                let path = entry.to_owned();
                let text = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
                    .await
                    .context("config file read task panicked")?
                    .with_context(|| format!("config file {entry} unreadable"))?;
                specs.push(
                    parse_xray_json(&text)
                        .with_context(|| format!("config file {entry} has no usable outbound"))?,
                );
            }
        }
        Ok(specs)
    }
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
