use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;

use super::{ScanController, Store, cancelled_signal, lock};
use crate::api::types::{FragmentPreset, Phase2Config, ScanConfig, ScanEvent, Verdict};
use crate::configs::OutboundSpec;

/// 8 MiB download cap per endpoint.
pub const SPEED_TEST_BYTES: usize = 8 * 1024 * 1024;
/// Hard wall-clock timeout per endpoint.
pub const SPEED_TEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Parallel speed-test tasks.
const SPEED_TEST_CONCURRENCY: usize = 4;
/// Sample source fetched through the tunnel.
pub const SPEED_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=8000000";

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
        let Some(cfg_idx) = p2.config_index else {
            continue;
        };
        let Some((spec, _)) = specs.get(cfg_idx as usize) else {
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

pub(crate) fn mbps(bytes: u64, seconds: f64) -> Option<f32> {
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
            p2.speed_test_mbps = Some(*m);
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
    let (bytes, seconds) = tester
        .download(SPEED_TEST_URL, socks, SPEED_TEST_BYTES, SPEED_TEST_TIMEOUT)
        .await?;
    mbps(bytes, seconds).ok_or_else(|| anyhow::anyhow!("speed test returned an invalid duration"))
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
        let candidates = lock(&self.store).clone();
        let index = build_passing_index(&candidates, specs);
        if index.is_empty() {
            tracing::info!("speed test: no phase-2 passing endpoints to measure");
            return Ok(());
        }
        let cancel_rx = self.cancel_signal();
        tracing::info!(
            count = index.len(),
            cap_bytes = SPEED_TEST_BYTES,
            "speed test: measuring phase-2 passing endpoints"
        );

        let tester: Arc<dyn SpeedTester> = Arc::new(RealSpeedTester);
        let measured = Arc::new(AtomicU64::new(0));
        let mut entries: Vec<((Ipv4Addr, u16), PassingSpec)> = index.into_iter().collect();
        entries.sort_by_key(|a| a.0);
        for chunk in entries.chunks(SPEED_TEST_CONCURRENCY.max(1)) {
            let mut tasks = tokio::task::JoinSet::new();
            for ((ip, port), entry) in chunk {
                let tester = tester.clone();
                let store = self.store.clone();
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
                    let outcome = tokio::select! {
                        r = measure_through_tunnel(&tester, &entry, custom.as_ref(), ip) => r,
                        _ = cancelled_signal(cancel.clone()) => return,
                    };
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
    tester: &Arc<dyn SpeedTester>,
    entry: &PassingSpec,
    custom: Option<&crate::api::types::CustomFragment>,
    ip: Ipv4Addr,
) -> Result<f32> {
    let session = crate::verify::XrayTunnelProbe::open_tunnel_session(
        &entry.spec,
        &entry.fragment,
        custom,
        entry.sni.as_deref(),
        ip,
    )
    .await?;
    let result = measure_endpoint(tester.as_ref(), session.proc.socks_addr).await;
    session.cleanup().await;
    result
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
                verifier: Some(Verifier::Xray),
                speed_test_mbps: None,
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

    #[test]
    fn mbps_math_and_degenerate_inputs() {
        let one_mib_per_sec = mbps(1024 * 1024, 1.0).unwrap();
        assert!((one_mib_per_sec - 1.0).abs() < 1e-4, "{one_mib_per_sec}");
        assert_eq!(mbps(8 * 1024 * 1024, 2.0), Some(4.0));
        assert_eq!(mbps(1024, 0.0), None);
        assert_eq!(mbps(1024, f64::NEG_INFINITY), None);
        assert_eq!(mbps(1024, f64::NAN), None);
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
        assert_eq!(p2.speed_test_mbps, Some(7.5));
        assert!(p2.passed, "no threshold: the pass must stand");
    }

    #[test]
    fn min_speed_flips_slow_endpoints_out_of_the_working_set() {
        let ip = "203.0.113.1".parse().unwrap();
        let below: Store = Arc::new(std::sync::Mutex::new(vec![passing(ip, 443, 0)]));
        let updated = apply_speed_result(&below, ip, 443, &Ok(1.0), Some(5.0)).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert!(!p2.passed, "below the threshold must not stay passed");
        assert_eq!(p2.speed_test_mbps, Some(1.0));
        assert!(p2.error.as_deref().unwrap().contains("--min-speed"));

        let above: Store = Arc::new(std::sync::Mutex::new(vec![passing(ip, 443, 0)]));
        let updated = apply_speed_result(&above, ip, 443, &Ok(6.0), Some(5.0)).unwrap();
        let p2 = updated.phase2.as_ref().unwrap();
        assert!(p2.passed, "above the threshold must keep the pass");
        assert_eq!(p2.speed_test_mbps, Some(6.0));
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
        assert_eq!(p2.speed_test_mbps, None);
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

    #[tokio::test]
    async fn measure_endpoint_computes_mbps_from_the_sample() {
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
    async fn scan_with_speed_test_records_mbps_on_passing_verdicts() {
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
            p2.speed_test_mbps.is_none(),
            "the engine uses the real tester which fails without a live xray: {p2:?}"
        );
        assert!(
            p2.error.as_deref().is_some(),
            "the download failure must be recorded, not silently dropped"
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
}
