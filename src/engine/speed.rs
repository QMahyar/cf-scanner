use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};

use super::{ScanController, Store, cancelled_signal, lock};
use crate::api::types::{FragmentPreset, Phase2Config, ScanConfig, ScanEvent, Verdict};
use crate::configs::OutboundSpec;
use crate::verify::TunnelOpener;
use tokio::sync::watch;

/// 8 MiB download cap per endpoint.
pub const SPEED_TEST_BYTES: usize = 8 * 1024 * 1024;
/// Hard wall-clock timeout per endpoint.
pub const SPEED_TEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Parallel speed-test tasks.
const SPEED_TEST_CONCURRENCY: usize = 4;
/// Sample source fetched through the tunnel.
pub const SPEED_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=8000000";
/// Small-sample source for the stall fallback: same endpoint, 16 KiB body.
pub const SPEED_BURST_URL: &str = "https://speed.cloudflare.com/__down?bytes=16384";
/// Bytes per burst fetch.
pub const SPEED_BURST_BYTES: usize = 16 * 1024;
/// Parallel burst fetches per stalled endpoint.
pub const SPEED_BURST_COUNT: usize = 8;
/// Per-burst timeout: generous for 16 KiB, far below the full-sample wall.
pub const SPEED_BURST_TIMEOUT: Duration = Duration::from_secs(10);
/// Join arity of one burst wave. Waves are additionally capped at
/// `SPEED_TEST_CONCURRENCY`, so the bound holds however either const moves.
const BURST_WAVE_WIDTH: usize = 4;

/// The exact probe parameters that made a candidate pass phase 2, so the
/// speed test can recreate an identical tunnel.
#[derive(Clone)]
pub(crate) struct PassingSpec {
    pub spec: OutboundSpec,
    pub fragment: FragmentPreset,
    pub sni: Option<String>,
}

/// Seam for the timed download so tests never touch the network.
pub type SpeedDownload<'a> = Pin<Box<dyn Future<Output = Result<(u64, f64)>> + Send + 'a>>;

pub trait SpeedTester: Send + Sync {
    fn download<'a>(
        &'a self,
        url: &'a str,
        socks: SocketAddr,
        max_bytes: usize,
        timeout: Duration,
    ) -> SpeedDownload<'a>;
}

pub struct RealSpeedTester;

impl SpeedTester for RealSpeedTester {
    fn download<'a>(
        &'a self,
        url: &'a str,
        socks: SocketAddr,
        max_bytes: usize,
        timeout: Duration,
    ) -> SpeedDownload<'a> {
        Box::pin(crate::socks::timed_download_via_socks(
            url, socks, max_bytes, timeout,
        ))
    }
}

/// Every candidate endpoint that passed phase 2, keyed by (ip, port).
pub(crate) type PassingIndex = HashMap<(Ipv4Addr, u16), PassingSpec>;

pub(crate) fn build_passing_index(
    candidates: &[Verdict],
    specs: &[(OutboundSpec, u32)],
) -> PassingIndex {
    let mut index = PassingIndex::new();
    for v in candidates {
        let Some(p2) = v.phase2.as_ref().filter(|p| p.passed) else {
            continue;
        };
        let IpAddr::V4(ip) = v.ip else {
            continue;
        };
        // spec_index is the position within the EXPANDED specs vec; config_index
        // is the raw p2.configs entry index. Verdicts written before spec_index
        // existed fall back to the raw index (exact for direct-URI entries).
        let idx = p2.spec_index.or(p2.config_index);
        let Some((spec, _)) = idx.and_then(|i| specs.get(i as usize)) else {
            continue;
        };
        index.insert(
            (ip, v.port),
            PassingSpec {
                spec: spec.clone(),
                fragment: p2.fragment.clone(),
                sni: if p2.sni.is_empty() {
                    None
                } else {
                    Some(p2.sni.clone())
                },
            },
        );
    }
    index
}

pub(crate) fn mb_s(bytes: u64, seconds: f64) -> Option<f32> {
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Some((bytes as f64 / (1024.0 * 1024.0) / seconds) as f32)
}

/// Record a measured throughput on the verdict, and when `min_speed` is set
/// flip a below-threshold verdict to failed so it leaves the working set.
pub(crate) fn apply_speed_result(
    store: &Store,
    ip: Ipv4Addr,
    port: u16,
    outcome: &Result<f32>,
    min_speed: Option<f32>,
) -> Option<Verdict> {
    let mut results = lock(store);
    let pos = results
        .iter()
        .position(|v| v.ip == IpAddr::V4(ip) && v.port == port)?;
    let p2 = results[pos].phase2.as_mut()?;
    match outcome {
        Ok(m) => {
            p2.speed_test_mb_s = Some(*m);
            if let Some(min) = min_speed
                && *m < min
            {
                p2.passed = false;
                p2.error = Some(format!("below --min-speed threshold ({m:.2} < {min})"));
            }
        }
        Err(err) => {
            p2.error = Some(crate::configs::sanitize_error_text(&format!("{err:#}")));
        }
    }
    Some(results[pos].clone())
}

async fn measure_endpoint(tester: &dyn SpeedTester, socks: SocketAddr) -> Result<f32> {
    match tester
        .download(SPEED_TEST_URL, socks, SPEED_TEST_BYTES, SPEED_TEST_TIMEOUT)
        .await
    {
        Ok((bytes, seconds)) => mb_s(bytes, seconds)
            .ok_or_else(|| anyhow::anyhow!("speed test returned an invalid duration")),
        Err(full_err) => {
            // WHY: only stalls degrade. Deterministic failures (HTTP status,
            // bad URL, refused handshake) propagate exactly as before, so fast
            // paths stay byte-identical and dead endpoints still error.
            if !crate::socks::is_stall_or_timeout(&full_err) {
                return Err(full_err);
            }
            match burst_lower_bound(tester, socks).await {
                Some(bound) => Ok(bound),
                None => Err(full_err),
            }
        }
    }
}

/// Stall fallback: `SPEED_BURST_COUNT` small fetches in waves of at most
/// `SPEED_TEST_CONCURRENCY`, reusing the `SpeedTester` seam (tests stay
/// offline) and the already-open tunnel. Returns a conservative lower bound —
/// successful bytes over summed burst times (the sequential-equivalent rate,
/// so parallel delivery can only have been faster) — or `None` when no burst
/// produced a usable sample, in which case the caller keeps the original
/// stall error.
async fn burst_lower_bound(tester: &dyn SpeedTester, socks: SocketAddr) -> Option<f32> {
    let width = SPEED_TEST_CONCURRENCY.clamp(1, BURST_WAVE_WIDTH);
    let mut remaining = SPEED_BURST_COUNT;
    let mut total_bytes: u64 = 0;
    let mut total_secs = 0.0f64;
    while remaining > 0 {
        let wave = remaining.min(width);
        remaining -= wave;
        for sample in burst_wave(tester, socks, wave).await {
            let Ok((bytes, secs)) = sample else {
                continue;
            };
            if bytes == 0 || !secs.is_finite() || secs <= 0.0 {
                continue;
            }
            total_bytes = total_bytes.saturating_add(bytes);
            total_secs += secs;
        }
    }
    if total_bytes == 0 {
        return None;
    }
    mb_s(total_bytes, total_secs)
}

/// One wave of at most `BURST_WAVE_WIDTH` concurrent burst fetches. Fixed
/// `join!` arity keeps the futures on this task (no `spawn`, so the caller's
/// cancel-`select!` drops them without leaking) while the caller caps the
/// wave at the concurrency bound.
async fn burst_wave(
    tester: &dyn SpeedTester,
    socks: SocketAddr,
    n: usize,
) -> Vec<Result<(u64, f64)>> {
    debug_assert!((1..=BURST_WAVE_WIDTH).contains(&n));
    fn burst(tester: &dyn SpeedTester, socks: SocketAddr) -> SpeedDownload<'_> {
        tester.download(
            SPEED_BURST_URL,
            socks,
            SPEED_BURST_BYTES,
            SPEED_BURST_TIMEOUT,
        )
    }
    match n {
        1 => vec![burst(tester, socks).await],
        2 => {
            let (a, b) = tokio::join!(burst(tester, socks), burst(tester, socks),);
            vec![a, b]
        }
        3 => {
            let (a, b, c) = tokio::join!(
                burst(tester, socks),
                burst(tester, socks),
                burst(tester, socks),
            );
            vec![a, b, c]
        }
        _ => {
            let (a, b, c, d) = tokio::join!(
                burst(tester, socks),
                burst(tester, socks),
                burst(tester, socks),
                burst(tester, socks),
            );
            vec![a, b, c, d]
        }
    }
}

impl ScanController {
    /// Opt-in shortlist speed test: re-open a tunnel per phase-2-passing
    /// endpoint, pull a capped sample, record MB/s in the verdict store.
    pub(super) async fn speed_test_phase(
        &self,
        cfg: &ScanConfig,
        p2: &Phase2Config,
        specs: &[(OutboundSpec, u32)],
    ) -> Result<()> {
        if !cfg.speed_test {
            return Ok(());
        }
        let min_speed = cfg.min_speed_mbps;
        let candidates = lock(&self.progress.store).clone();
        let index = build_passing_index(&candidates, specs);
        if index.is_empty() {
            tracing::info!("speed test: no phase-2 passing endpoints to measure");
            return Ok(());
        }
        let tester: Arc<dyn SpeedTester> = lock(&self.handles.speed_tester).clone();
        let opener: Arc<dyn TunnelOpener> = lock(&self.handles.session_opener).clone();
        let cancel_rx = self.cancel_signal();
        tracing::info!(
            count = index.len(),
            cap_bytes = SPEED_TEST_BYTES,
            "speed test: measuring phase-2 passing endpoints"
        );

        let measured = Arc::new(AtomicU64::new(0));
        let mut entries: Vec<((Ipv4Addr, u16), PassingSpec)> = index.into_iter().collect();
        entries.sort_by_key(|a| a.0);
        for chunk in entries.chunks(SPEED_TEST_CONCURRENCY.max(1)) {
            let mut tasks = tokio::task::JoinSet::new();
            for ((ip, port), entry) in chunk {
                let tester = tester.clone();
                let opener = opener.clone();
                let store = self.progress.store.clone();
                let events = self.events.clone();
                let cancel = cancel_rx.clone();
                let measured = measured.clone();
                let ip = *ip;
                let port = *port;
                let entry = entry.clone();
                let custom = p2.custom_fragment.clone();
                tasks.spawn(async move {
                    if *cancel.borrow() {
                        return;
                    }
                    let outcome = measure_through_tunnel(
                        &opener,
                        &tester,
                        &entry,
                        custom.as_ref(),
                        ip,
                        &cancel,
                    )
                    .await;
                    if *cancel.borrow() {
                        // Cancelled mid-download: the tunnel was already torn
                        // down inside; record nothing (as before).
                        return;
                    }
                    measured.fetch_add(1, Ordering::Relaxed);
                    if let Some(updated) = apply_speed_result(&store, ip, port, &outcome, min_speed)
                    {
                        let _ = events.send(ScanEvent::Result(Box::new(updated)));
                    }
                });
            }
            while let Some(res) = tasks.join_next().await {
                if let Err(e) = res {
                    tracing::warn!("speed test task panicked: {e}");
                }
            }
        }
        tracing::info!(
            measured = measured.load(Ordering::Relaxed),
            "speed test: done"
        );
        Ok(())
    }
}

async fn measure_through_tunnel(
    opener: &Arc<dyn TunnelOpener>,
    tester: &Arc<dyn SpeedTester>,
    entry: &PassingSpec,
    custom: Option<&crate::api::types::CustomFragment>,
    ip: Ipv4Addr,
    cancel: &watch::Receiver<bool>,
) -> Result<f32> {
    let tunnel = opener
        .open(
            &entry.spec,
            &entry.fragment,
            custom,
            entry.sni.as_deref(),
            ip,
        )
        .await?;
    // The select lives INSIDE so every path awaits tunnel.cleanup():
    // dropping this future mid-download (the old caller-side select) leaked
    // the xray child and its credential-bearing trial dir.
    let download = measure_endpoint(tester.as_ref(), tunnel.socks_addr);
    tokio::select! {
        biased;
        _ = cancelled_signal(cancel.clone()) => {
            tunnel.cleanup().await;
            bail!("speed test cancelled");
        }
        result = download => {
            let result = result;
            tunnel.cleanup().await;
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{FragmentPreset, Phase2Verdict, Verifier};

    fn passing(ip: Ipv4Addr, port: u16, cfg_idx: u32) -> Verdict {
        Verdict {
            ip: IpAddr::V4(ip),
            port,
            latency_ms: Some(10),
            country: None,
            colo: None,
            phase2: Some(Phase2Verdict {
                passed: true,
                fragment: FragmentPreset::Medium,
                sni: "b.me".to_owned(),
                latency_ms: Some(20),
                error: None,
                config_index: Some(cfg_idx),
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
        }
    }

    fn spec_for(idx: u32) -> OutboundSpec {
        OutboundSpec {
            protocol: crate::configs::Protocol::Vless,
            server: "example.com".to_owned(),
            port: 443,
            user_id: format!("uuid-{idx}"),
            method: None,
            security: "tls".to_owned(),
            tls_server_name: None,
            fingerprint: None,
            ws: None,
            grpc: None,
            xhttp: None,
            tag: None,
            alter_id: 0,
            vmess_security: None,
        }
    }

    #[test]
    fn passing_index_collects_only_phase2_passes_with_resolvable_specs() {
        let specs = vec![(spec_for(0), 0u32), (spec_for(1), 1u32)];
        let candidates = vec![
            passing("203.0.113.1".parse().unwrap(), 443, 0),
            passing("203.0.113.2".parse().unwrap(), 443, 1),
            {
                let mut failed = passing("203.0.113.3".parse().unwrap(), 443, 0);
                failed.phase2.as_mut().unwrap().passed = false;
                failed
            },
            {
                let mut nocfg = passing("203.0.113.4".parse().unwrap(), 443, 9);
                nocfg.phase2.as_mut().unwrap().config_index = None;
                nocfg
            },
            {
                let mut v6 = passing("203.0.113.5".parse().unwrap(), 443, 0);
                v6.ip = "2001:db8::1".parse().unwrap();
                v6
            },
        ];
        let index = build_passing_index(&candidates, &specs);
        assert_eq!(index.len(), 2, "only resolvable v4 passes enter the index");
        assert!(index.contains_key(&("203.0.113.1".parse::<Ipv4Addr>().unwrap(), 443)));
        assert!(index.contains_key(&("203.0.113.2".parse::<Ipv4Addr>().unwrap(), 443)));
        let entry = &index[&("203.0.113.1".parse::<Ipv4Addr>().unwrap(), 443)];
        assert_eq!(entry.sni.as_deref(), Some("b.me"));
        assert_eq!(entry.fragment, FragmentPreset::Medium);
    }

    /// Opener that records the (dial_ip, spec.user_id) of every open so tests
    /// can assert each endpoint's speed test ran through its OWN spec.
    struct RecordingOpener {
        opened: Arc<std::sync::Mutex<Vec<(Ipv4Addr, String)>>>,
    }

    impl crate::verify::TunnelOpener for RecordingOpener {
        fn open(
            &self,
            spec: &OutboundSpec,
            _preset: &FragmentPreset,
            _custom: Option<&crate::api::types::CustomFragment>,
            _sni: Option<&str>,
            dial_ip: Ipv4Addr,
        ) -> Pin<Box<dyn Future<Output = Result<crate::verify::OpenedTunnel>> + Send + '_>>
        {
            lock(&self.opened).push((dial_ip, spec.user_id.clone()));
            Box::pin(async {
                Ok(crate::verify::OpenedTunnel::new(
                    SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 1),
                    Box::pin(async {}),
                ))
            })
        }
    }

    #[tokio::test]
    async fn speed_test_opens_each_endpoints_own_expanded_spec() {
        // One subscription entry expanding to two specs (same raw idx 0):
        // endpoint .1 passed the spec at expanded position 1, .2 at position 0.
        let specs = vec![(spec_for(0), 0u32), (spec_for(1), 0u32)];
        let mut first = passing("203.0.113.1".parse().unwrap(), 443, 0);
        first.phase2.as_mut().unwrap().spec_index = Some(1);
        let second = passing("203.0.113.2".parse().unwrap(), 443, 0);
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![first, second]);
        let opener = Arc::new(RecordingOpener {
            opened: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        c.set_tunnel_opener(opener.clone());
        c.set_speed_tester(Arc::new(FakeTester {
            bytes: 1024,
            seconds: 1.0,
            fail: false,
        }));
        let cfg = speed_cfg();
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &specs).await.unwrap();
        let mut opened = lock(&opener.opened).clone();
        opened.sort();
        assert_eq!(
            opened,
            vec![
                ("203.0.113.1".parse().unwrap(), "uuid-1".to_owned()),
                ("203.0.113.2".parse().unwrap(), "uuid-0".to_owned()),
            ],
            "each endpoint's speed test must open its own expanded spec"
        );
    }

    #[tokio::test]
    async fn skipped_entry_does_not_drop_endpoints_from_the_speed_test() {
        // Raw entries: [unparseable, valid URI]; the valid spec sits at raw
        // idx 1 / expanded position 0. config_index (raw) must not be used to
        // index the expanded vec — spec_index resolves the pass.
        let specs = vec![(spec_for(0), 1u32)];
        let mut v = passing("203.0.113.1".parse().unwrap(), 443, 1);
        v.phase2.as_mut().unwrap().spec_index = Some(0);
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![v]);
        let opener = Arc::new(CountingOpener::new());
        c.set_tunnel_opener(opener.clone());
        c.set_speed_tester(Arc::new(FakeTester {
            bytes: 1024,
            seconds: 1.0,
            fail: false,
        }));
        let cfg = speed_cfg();
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &specs).await.unwrap();
        assert_eq!(
            opener.opens.load(Ordering::Relaxed),
            1,
            "the pass behind a skipped entry must still be measured"
        );
    }

    #[test]
    fn mb_s_math_and_degenerate_inputs() {
        let one_mib_per_sec = mb_s(1024 * 1024, 1.0).unwrap();
        assert!((one_mib_per_sec - 1.0).abs() < 1e-4, "{one_mib_per_sec}");
        assert_eq!(mb_s(8 * 1024 * 1024, 2.0), Some(4.0));
        assert_eq!(mb_s(1024, 0.0), None);
        assert_eq!(mb_s(1024, f64::NEG_INFINITY), None);
        assert_eq!(mb_s(1024, f64::NAN), None);
    }

    #[test]
    fn apply_speed_result_records_the_measurement() {
        let store: Store = Arc::new(std::sync::Mutex::new(vec![passing(
            "203.0.113.1".parse().unwrap(),
            443,
            0,
        )]));
        let ip = "203.0.113.1".parse().unwrap();
        let updated = apply_speed_result(&store, ip, 443, &Ok(7.5), None).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert_eq!(p2.speed_test_mb_s, Some(7.5));
        assert!(p2.passed, "no threshold: the pass must stand");
    }

    #[test]
    fn min_speed_flips_slow_endpoints_out_of_the_working_set() {
        let ip = "203.0.113.1".parse().unwrap();
        let below: Store = Arc::new(std::sync::Mutex::new(vec![passing(ip, 443, 0)]));
        let updated = apply_speed_result(&below, ip, 443, &Ok(1.0), Some(5.0)).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert!(!p2.passed, "below the threshold must not stay passed");
        assert_eq!(p2.speed_test_mb_s, Some(1.0));
        assert!(p2.error.as_deref().unwrap().contains("--min-speed"));

        let above: Store = Arc::new(std::sync::Mutex::new(vec![passing(ip, 443, 0)]));
        let updated = apply_speed_result(&above, ip, 443, &Ok(6.0), Some(5.0)).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert!(p2.passed, "above the threshold must keep the pass");
        assert_eq!(p2.speed_test_mb_s, Some(6.0));
        assert!(p2.error.is_none());
    }

    #[test]
    fn speed_test_errors_are_sanitized_onto_the_verdict() {
        let store: Store = Arc::new(std::sync::Mutex::new(vec![passing(
            "203.0.113.1".parse().unwrap(),
            443,
            0,
        )]));
        let ip = "203.0.113.1".parse().unwrap();
        let outcome: Result<f32> = Err(anyhow::anyhow!(
            "dial vless://SecretUser:SecretPass123@1.2.3.4:443: refused"
        ));
        let updated = apply_speed_result(&store, ip, 443, &outcome, None).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert_eq!(p2.speed_test_mb_s, None);
        let err = p2.error.as_deref().unwrap();
        assert!(!err.contains("SecretPass123"), "{err}");
    }

    #[test]
    fn apply_speed_result_is_a_noop_for_unknown_rows() {
        let store: Store = Arc::new(std::sync::Mutex::new(vec![passing(
            "203.0.113.1".parse().unwrap(),
            443,
            0,
        )]));
        let missing =
            apply_speed_result(&store, "203.0.113.9".parse().unwrap(), 443, &Ok(1.0), None);
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn speed_test_phase_is_a_noop_when_not_enabled() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        let cfg = ScanConfig::default();
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &[]).await.unwrap();
        assert!(c.results().is_empty());
    }

    struct FakeTester {
        bytes: u64,
        seconds: f64,
        fail: bool,
    }

    impl SpeedTester for FakeTester {
        fn download<'a>(
            &'a self,
            _url: &'a str,
            _socks: SocketAddr,
            _max_bytes: usize,
            _timeout: Duration,
        ) -> SpeedDownload<'a> {
            Box::pin(async move {
                if self.fail {
                    Err(anyhow::anyhow!("simulated download failure"))
                } else {
                    Ok((self.bytes, self.seconds))
                }
            })
        }
    }

    struct FakeOpener;

    impl crate::verify::TunnelOpener for FakeOpener {
        fn open(
            &self,
            _spec: &OutboundSpec,
            _preset: &FragmentPreset,
            _custom: Option<&crate::api::types::CustomFragment>,
            _sni: Option<&str>,
            _dial_ip: Ipv4Addr,
        ) -> Pin<Box<dyn Future<Output = Result<crate::verify::OpenedTunnel>> + Send + '_>>
        {
            Box::pin(async {
                Ok(crate::verify::OpenedTunnel::new(
                    SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 1),
                    Box::pin(async {}),
                ))
            })
        }
    }

    /// Opener that counts opens and cleanups so tests can prove teardown runs.
    struct CountingOpener {
        opens: Arc<AtomicU64>,
        cleanups: Arc<AtomicU64>,
    }

    impl CountingOpener {
        fn new() -> Self {
            Self {
                opens: Arc::new(AtomicU64::new(0)),
                cleanups: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    impl crate::verify::TunnelOpener for CountingOpener {
        fn open(
            &self,
            _spec: &OutboundSpec,
            _preset: &FragmentPreset,
            _custom: Option<&crate::api::types::CustomFragment>,
            _sni: Option<&str>,
            _dial_ip: Ipv4Addr,
        ) -> Pin<Box<dyn Future<Output = Result<crate::verify::OpenedTunnel>> + Send + '_>>
        {
            self.opens.fetch_add(1, Ordering::Relaxed);
            let cleanups = self.cleanups.clone();
            Box::pin(async move {
                Ok(crate::verify::OpenedTunnel::new(
                    SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 1),
                    Box::pin(async move {
                        cleanups.fetch_add(1, Ordering::Relaxed);
                    }),
                ))
            })
        }
    }

    /// Tester whose download never resolves, so cancel always wins the race.
    struct HangingTester;

    impl SpeedTester for HangingTester {
        fn download<'a>(
            &'a self,
            _url: &'a str,
            _socks: SocketAddr,
            _max_bytes: usize,
            _timeout: Duration,
        ) -> SpeedDownload<'a> {
            Box::pin(async { std::future::pending::<Result<(u64, f64)>>().await })
        }
    }

    #[tokio::test]
    async fn cancelled_download_still_runs_tunnel_cleanup() {
        let opener = Arc::new(CountingOpener::new());
        let opener_dyn: Arc<dyn TunnelOpener> = opener.clone();
        let tester: Arc<dyn SpeedTester> = Arc::new(HangingTester);
        let spec =
            crate::configs::parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443")
                .unwrap();
        let entry = PassingSpec {
            spec,
            fragment: FragmentPreset::Off,
            sni: None,
        };
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let handle = tokio::spawn({
            let opener_dyn = opener_dyn.clone();
            let tester = tester.clone();
            let entry = entry.clone();
            let cancel_rx = cancel_rx.clone();
            async move {
                measure_through_tunnel(&opener_dyn, &tester, &entry, None, ip, &cancel_rx).await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while opener.opens.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the tunnel must open before cancel fires");
        cancel_tx.send(true).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("cancelled download must resolve")
            .expect("task panicked");
        assert!(outcome.is_err(), "cancel must surface as an error");
        assert_eq!(
            opener.cleanups.load(Ordering::Relaxed),
            1,
            "the tunnel must be torn down even when cancel wins mid-download"
        );
    }

    #[tokio::test]
    async fn successful_download_runs_tunnel_cleanup_exactly_once() {
        let opener = Arc::new(CountingOpener::new());
        let opener_dyn: Arc<dyn TunnelOpener> = opener.clone();
        let tester: Arc<dyn SpeedTester> = Arc::new(FakeTester {
            bytes: 1024,
            seconds: 1.0,
            fail: false,
        });
        let spec =
            crate::configs::parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443")
                .unwrap();
        let entry = PassingSpec {
            spec,
            fragment: FragmentPreset::Off,
            sni: None,
        };
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
        measure_through_tunnel(&opener_dyn, &tester, &entry, None, ip, &cancel_rx)
            .await
            .unwrap();
        assert_eq!(opener.opens.load(Ordering::Relaxed), 1);
        assert_eq!(
            opener.cleanups.load(Ordering::Relaxed),
            1,
            "success path must also tear down exactly once"
        );
    }

    #[tokio::test]
    async fn measure_endpoint_computes_mb_s_from_the_sample() {
        let tester = FakeTester {
            bytes: 8 * 1024 * 1024,
            seconds: 4.0,
            fail: false,
        };
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let m = measure_endpoint(&tester, socks).await.unwrap();
        assert!((m - 2.0).abs() < 1e-4, "{m}");
        let tester = FakeTester {
            bytes: 0,
            seconds: 0.0,
            fail: true,
        };
        assert!(measure_endpoint(&tester, socks).await.is_err());
    }

    struct PassAllProbe;

    impl crate::verify::TunnelProbe for PassAllProbe {
        fn probe(
            &self,
            _req: crate::verify::ProbeRequest<'_>,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = anyhow::Result<crate::verify::TunnelResult>> + Send + '_>,
        > {
            Box::pin(async {
                Ok(crate::verify::TunnelResult {
                    passed: true,
                    latency_ms: Some(7),
                    colo: None,
                    verifier: Some("inline"),
                })
            })
        }
    }

    use crate::engine::test_helpers::FakeSub;

    #[tokio::test]
    async fn scan_with_speed_test_records_mb_s_on_passing_verdicts() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        use crate::api::types::Phase2Config;
        use crate::engine::tests::{ok_cfg, run_local};
        use crate::probe::FakeTransport;

        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 20);
        let c = Arc::new(ScanController::with_probes(
            Arc::new(t),
            Arc::new(FakeSub("")),
            Arc::new(PassAllProbe),
        ));
        c.set_tunnel_opener(Arc::new(FakeOpener));
        c.set_speed_tester(Arc::new(FakeTester {
            bytes: 8 * 1024 * 1024,
            seconds: 4.0,
            fail: false,
        }));
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec!["vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443".to_owned()],
            ..Default::default()
        });
        cfg.speed_test = true;
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(p2.passed);
        assert!(
            (p2.speed_test_mb_s.unwrap() - 2.0).abs() < 1e-4,
            "the injected FakeTester measures 2 MB/s: {p2:?}"
        );
        assert!(
            p2.error.as_deref().is_none(),
            "a passing sample records no error"
        );
    }

    #[tokio::test]
    async fn injected_slow_tester_flips_the_verdict_below_min_speed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        use crate::api::types::Phase2Config;
        use crate::engine::tests::{ok_cfg, run_local};
        use crate::probe::FakeTransport;

        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 20);
        let c = Arc::new(ScanController::with_probes(
            Arc::new(t),
            Arc::new(FakeSub("")),
            Arc::new(PassAllProbe),
        ));
        c.set_tunnel_opener(Arc::new(FakeOpener));
        c.set_speed_tester(Arc::new(FakeTester {
            bytes: 1024 * 1024,
            seconds: 8.0,
            fail: false,
        }));
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec!["vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443".to_owned()],
            ..Default::default()
        });
        cfg.speed_test = true;
        cfg.min_speed_mbps = Some(2.0);
        run_local(&c, cfg, 1).await.unwrap();
        let results = c.results();
        let p2 = results[0].phase2.as_ref().unwrap();
        assert!(!p2.passed, "0.125 MB/s must fail a 2.0 MB/s gate: {p2:?}");
        assert!(
            p2.error.as_deref().unwrap().contains("min-speed"),
            "the error names the gate: {p2:?}"
        );
    }

    #[tokio::test]
    async fn speed_test_without_passing_endpoints_is_a_noop() {
        use crate::engine::tests::{ok_cfg, run_local};
        use crate::probe::FakeTransport;

        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 20);
        let c = Arc::new(ScanController::with_probes(
            Arc::new(t),
            Arc::new(FakeSub("")),
            Arc::new(PassAllProbe),
        ));
        let mut cfg = ok_cfg(1, None);
        cfg.phase2 = Some(Phase2Config {
            configs: vec!["vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443".to_owned()],
            ..Default::default()
        });
        cfg.speed_test = true;
        run_local(&c, cfg, 1).await.unwrap();
        assert!(c.results()[0].phase2.as_ref().unwrap().passed);
    }

    #[tokio::test]
    async fn quality_gated_stop_tops_up_until_min_speed_is_met() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        use crate::api::types::Phase2Config;
        use crate::engine::tests::{ok_cfg, run_local};
        use crate::probe::FakeTransport;

        // One OK endpoint per seed. Each top-up round probes a fresh sample,
        // so the scan needs multiple rounds to bank 2 fast endpoints.
        let t = FakeTransport::new().ok("203.0.113.1".parse().unwrap(), 443, 20);
        let c = Arc::new(ScanController::with_probes(
            Arc::new(t),
            Arc::new(FakeSub("")),
            Arc::new(PassAllProbe),
        ));
        c.set_tunnel_opener(Arc::new(FakeOpener));
        c.set_speed_tester(Arc::new(FakeTester {
            bytes: 16 * 1024 * 1024,
            seconds: 1.0,
            fail: false,
        }));
        let mut cfg = ok_cfg(2, Some(12));
        cfg.phase2 = Some(Phase2Config {
            configs: vec!["vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443".to_owned()],
            ..Default::default()
        });
        cfg.speed_test = true;
        cfg.min_speed_mbps = Some(4.0);
        let summary = run_local(&c, cfg, 7).await.unwrap();
        let fast = c
            .results()
            .iter()
            .filter(|v| v.phase2.as_ref().is_some_and(|p| p.passed))
            .count();
        assert_eq!(
            summary.found as usize, fast,
            "summary.found counts only quality-passing endpoints"
        );
        assert!(
            summary.scanned >= 2,
            "top-up rounds must have run: {summary:?}"
        );
        assert!(fast >= 1, "at least one fast endpoint was banked");
    }

    /// Opener whose open() always fails (xray missing / spawn exhausted).
    struct FailingOpener;

    impl crate::verify::TunnelOpener for FailingOpener {
        fn open(
            &self,
            _spec: &OutboundSpec,
            _preset: &FragmentPreset,
            _custom: Option<&crate::api::types::CustomFragment>,
            _sni: Option<&str>,
            _dial_ip: Ipv4Addr,
        ) -> Pin<Box<dyn Future<Output = Result<crate::verify::OpenedTunnel>> + Send + '_>>
        {
            Box::pin(async { Err(anyhow::anyhow!("no verified xray binary")) })
        }
    }

    fn speed_cfg() -> ScanConfig {
        ScanConfig {
            speed_test: true,
            ..ScanConfig::default()
        }
    }

    #[tokio::test]
    async fn opener_failure_records_a_sanitized_error_and_keeps_going() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("203.0.113.1".parse().unwrap(), 443, 0)]);
        c.set_tunnel_opener(Arc::new(FailingOpener));
        let cfg = speed_cfg();
        let p2 = Phase2Config::default();
        let spec =
            crate::configs::parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443")
                .unwrap();
        c.speed_test_phase(&cfg, &p2, &[(spec, 0)]).await.unwrap();
        let results = c.results();
        assert_eq!(results.len(), 1);
        let p2v = results[0].phase2.as_ref().unwrap();
        assert!(
            p2v.error
                .as_deref()
                .is_some_and(|e| e.contains("xray binary")),
            "opener failure must be recorded on the verdict: {:?}",
            p2v.error
        );
        assert_eq!(p2v.speed_test_mb_s, None, "no measurement was possible");
    }

    #[tokio::test]
    async fn speed_test_with_no_passing_endpoints_is_a_clean_noop() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        // No stored verdicts at all: the empty-index path.
        c.set_tunnel_opener(Arc::new(FailingOpener));
        let cfg = speed_cfg();
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &[]).await.unwrap();
        assert!(c.results().is_empty());
    }

    #[test]
    fn nan_min_speed_never_flips_a_verdict_and_nan_mb_s_is_not_recorded() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("203.0.113.5".parse().unwrap(), 443, 0)]);
        // mb_s() rejects a non-finite/zero duration: None, so no measurement.
        assert_eq!(mb_s(1000, 0.0), None);
        assert_eq!(mb_s(1000, f64::NAN), None);
        // min_speed = NaN: comparison is false, verdict stays passed.
        let updated = apply_speed_result(
            &c.progress.store,
            "203.0.113.5".parse().unwrap(),
            443,
            &Ok(0.5),
            Some(f32::NAN),
        )
        .unwrap();
        let p2v = updated.phase2.as_ref().unwrap();
        assert_eq!(p2v.speed_test_mb_s, Some(0.5));
        assert!(p2v.passed, "NaN threshold must not fail the endpoint");
    }

    /// Tester that fails the full capped sample on demand and answers bursts
    /// programmably, recording every call plus peak in-flight downloads.
    struct BurstMock {
        full_err: Option<String>,
        full_ok: (u64, f64),
        burst_err: Option<String>,
        burst_ok: (u64, f64),
        delay_full: Duration,
        delay_burst: Duration,
        calls: Arc<std::sync::Mutex<Vec<(String, usize)>>>,
        current: Arc<AtomicU64>,
        peak: Arc<AtomicU64>,
    }

    impl BurstMock {
        fn stall_then_ok() -> Self {
            Self {
                full_err: Some("speed test timed out".to_owned()),
                full_ok: (0, 0.0),
                burst_err: None,
                burst_ok: (SPEED_BURST_BYTES as u64, 0.1),
                delay_full: Duration::ZERO,
                delay_burst: Duration::ZERO,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
                current: Arc::new(AtomicU64::new(0)),
                peak: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    impl SpeedTester for BurstMock {
        fn download<'a>(
            &'a self,
            url: &'a str,
            _socks: SocketAddr,
            max_bytes: usize,
            _timeout: Duration,
        ) -> SpeedDownload<'a> {
            Box::pin(async move {
                lock(&self.calls).push((url.to_owned(), max_bytes));
                let full = max_bytes == SPEED_TEST_BYTES;
                let delay = if full {
                    self.delay_full
                } else {
                    self.delay_burst
                };
                self.current.fetch_add(1, Ordering::Relaxed);
                self.peak
                    .fetch_max(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
                if delay.is_zero() {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(delay).await;
                }
                self.current.fetch_sub(1, Ordering::Relaxed);
                if full {
                    match &self.full_err {
                        Some(e) => Err(anyhow::anyhow!("{e}")),
                        None => Ok(self.full_ok),
                    }
                } else {
                    match &self.burst_err {
                        Some(e) => Err(anyhow::anyhow!("{e}")),
                        None => Ok(self.burst_ok),
                    }
                }
            })
        }
    }

    #[tokio::test]
    async fn stall_falls_back_to_burst_lower_bound() {
        let mock = BurstMock::stall_then_ok();
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let m = measure_endpoint(&mock, socks).await.unwrap();
        // 8 bursts x 16 KiB over the summed 0.8 s sequential-equivalent time.
        let expected = mb_s(8 * SPEED_BURST_BYTES as u64, 0.8).unwrap();
        assert!(
            (m - expected).abs() < 1e-4,
            "lower bound {m} != sequential-equivalent {expected}"
        );
        let calls = lock(&mock.calls).clone();
        assert_eq!(
            calls.len(),
            1 + SPEED_BURST_COUNT,
            "one full sample plus every burst"
        );
        assert_eq!(calls[0].1, SPEED_TEST_BYTES, "the full sample runs first");
        assert!(
            calls[1..].iter().all(|(_, b)| *b == SPEED_BURST_BYTES),
            "every fallback fetch is burst-sized"
        );
        assert!(
            calls[1..].iter().all(|(u, _)| u == SPEED_BURST_URL),
            "bursts hit the small-sample URL"
        );
    }

    #[tokio::test]
    async fn non_stall_error_never_triggers_bursts() {
        let mut mock = BurstMock::stall_then_ok();
        mock.full_err = Some("speed test got HTTP 403".to_owned());
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = measure_endpoint(&mock, socks).await.unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
        assert_eq!(
            lock(&mock.calls).len(),
            1,
            "a hard error must not spend burst traffic"
        );
    }

    #[tokio::test]
    async fn failed_bursts_keep_the_original_stall_error() {
        let mut mock = BurstMock::stall_then_ok();
        mock.burst_err = Some("speed test timed out".to_owned());
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = measure_endpoint(&mock, socks).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(
            lock(&mock.calls).len(),
            1 + SPEED_BURST_COUNT,
            "bursts were attempted before giving up"
        );
    }

    #[tokio::test]
    async fn successful_full_sample_spends_no_burst_traffic() {
        let mut mock = BurstMock::stall_then_ok();
        mock.full_err = None;
        mock.full_ok = (8 * 1024 * 1024, 4.0);
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let m = measure_endpoint(&mock, socks).await.unwrap();
        assert!((m - 2.0).abs() < 1e-4, "{m}");
        assert_eq!(
            lock(&mock.calls).len(),
            1,
            "the fast path is byte-identical: no burst traffic"
        );
    }

    #[tokio::test]
    async fn burst_waves_honor_the_concurrency_bound() {
        let mut mock = BurstMock::stall_then_ok();
        mock.delay_burst = Duration::from_millis(5);
        let socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
        measure_endpoint(&mock, socks).await.unwrap();
        let peak = mock.peak.load(Ordering::Relaxed);
        assert!(
            peak <= SPEED_TEST_CONCURRENCY as u64,
            "peak in-flight bursts {peak} exceed the bound"
        );
        assert_eq!(
            peak,
            SPEED_TEST_CONCURRENCY.min(BURST_WAVE_WIDTH) as u64,
            "bursts actually run in parallel ({peak})"
        );
    }

    #[tokio::test]
    async fn cancel_during_bursts_still_cleans_up_the_tunnel() {
        let opener = Arc::new(CountingOpener::new());
        let opener_dyn: Arc<dyn TunnelOpener> = opener.clone();
        // The full sample stalls at once; bursts hang until cancel wins.
        let mut mock = BurstMock::stall_then_ok();
        mock.delay_burst = Duration::from_secs(60);
        let calls = mock.calls.clone();
        let tester: Arc<dyn SpeedTester> = Arc::new(mock);
        let spec =
            crate::configs::parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443")
                .unwrap();
        let entry = PassingSpec {
            spec,
            fragment: FragmentPreset::Off,
            sni: None,
        };
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let handle = tokio::spawn({
            let opener_dyn = opener_dyn.clone();
            let tester = tester.clone();
            let entry = entry.clone();
            let cancel_rx = cancel_rx.clone();
            async move {
                measure_through_tunnel(&opener_dyn, &tester, &entry, None, ip, &cancel_rx).await
            }
        });
        // Wait until the first burst wave is in flight, then cancel.
        tokio::time::timeout(Duration::from_secs(10), async {
            while lock(&calls).len() < 1 + SPEED_TEST_CONCURRENCY.min(BURST_WAVE_WIDTH) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bursts must start before cancel fires");
        cancel_tx.send(true).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("cancelled bursts must resolve")
            .expect("task panicked");
        assert!(outcome.is_err(), "cancel must surface as an error");
        assert_eq!(
            opener.cleanups.load(Ordering::Relaxed),
            1,
            "the tunnel must be torn down even when cancel wins mid-burst"
        );
    }

    #[tokio::test]
    async fn speed_test_phase_records_burst_lower_bound_on_the_verdict() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("203.0.113.1".parse().unwrap(), 443, 0)]);
        c.set_tunnel_opener(Arc::new(FakeOpener));
        c.set_speed_tester(Arc::new(BurstMock::stall_then_ok()));
        let cfg = speed_cfg();
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &[(spec_for(0), 0)])
            .await
            .unwrap();
        let results = c.results();
        assert_eq!(results.len(), 1);
        let p2v = results[0].phase2.as_ref().unwrap();
        let expected = mb_s(8 * SPEED_BURST_BYTES as u64, 0.8).unwrap();
        assert!(
            (p2v.speed_test_mb_s.unwrap() - expected).abs() < 1e-4,
            "stall converts to a lower-bound record: {p2v:?}"
        );
        assert!(p2v.passed, "no threshold: the pass must stand");
        assert!(p2v.error.is_none(), "a lower-bound record carries no error");
    }

    #[tokio::test]
    async fn min_speed_still_gates_burst_lower_bounds() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("203.0.113.1".parse().unwrap(), 443, 0)]);
        c.set_tunnel_opener(Arc::new(FakeOpener));
        c.set_speed_tester(Arc::new(BurstMock::stall_then_ok()));
        let mut cfg = speed_cfg();
        cfg.min_speed_mbps = Some(2.0);
        let p2 = Phase2Config::default();
        c.speed_test_phase(&cfg, &p2, &[(spec_for(0), 0)])
            .await
            .unwrap();
        let results = c.results();
        let p2v = results[0].phase2.as_ref().unwrap();
        assert!(
            !p2v.passed,
            "a 0.16 MB/s bound must fail a 2.0 MB/s gate: {p2v:?}"
        );
        assert!(
            p2v.error.as_deref().unwrap().contains("min-speed"),
            "the error names the gate: {p2v:?}"
        );
    }
}
