use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};

use std::sync::Arc;

use crate::api::types::{CustomFragment, FragmentPreset};
use crate::configs::{OutboundSpec, Protocol};
use crate::inline_verify::InlineTunnelProbe;
use crate::paths;
use crate::socks;
use crate::xray;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelResult {
    pub passed: bool,
    pub latency_ms: Option<u32>,
    pub colo: Option<String>,
    pub verifier: Option<&'static str>,
}

#[derive(Clone)]
pub struct ProbeRequest<'a> {
    pub spec: &'a OutboundSpec,
    pub dial_ip: Ipv4Addr,
    pub preset: &'a FragmentPreset,
    pub custom: Option<&'a CustomFragment>,
    pub sni: Option<&'a str>,
    pub probe_urls: &'a [String],
    pub timeout_ms: u64,
}

pub trait TunnelProbe: Send + Sync {
    fn probe(
        &self,
        req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>>;
}

#[cfg(test)]
pub struct PassAllProbe;

#[cfg(test)]
impl TunnelProbe for PassAllProbe {
    fn probe(
        &self,
        _req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
        Box::pin(async move {
            Ok(TunnelResult {
                passed: true,
                latency_ms: Some(7),
                colo: Some("LAX".to_owned()),
                verifier: None,
            })
        })
    }
}

pub struct XrayTunnelProbe;

impl XrayTunnelProbe {
    /// Open a one-shot xray tunnel session for `spec` dialing `dial_ip`.
    /// Finish with `cleanup().await` (or `proc.stop()`, with the drop guard as
    /// a fire-and-forget fallback) so the trial config dir is removed.
    pub async fn open_tunnel_session(
        spec: &OutboundSpec,
        preset: &FragmentPreset,
        custom: Option<&CustomFragment>,
        sni: Option<&str>,
        dial_ip: Ipv4Addr,
    ) -> Result<TunnelSession> {
        let work_dir = paths::data_dir().context("no data directory for trial configs")?;
        sweep_stale_trial_dirs_async(&work_dir).await;
        let trial_dir = make_trial_dir(&work_dir).await?;

        let fetch = xray::RealFetch;
        let xray_bin = xray::ensure_binary(&fetch).await.with_context(|| {
            "no verified xray binary (cached copy failed its checksum or the download failed)"
        })?;
        let proc = spawn_with_retry(dial_ip, |socks_port| {
            let spec = spec.clone();
            let preset = preset.clone();
            let custom = custom.cloned();
            let sni = sni.map(str::to_owned);
            let trial_dir = trial_dir.clone();
            let xray_bin = xray_bin.clone();
            async move {
                let cfg = xray::build_config(
                    &spec,
                    dial_ip,
                    &preset,
                    custom.as_ref(),
                    sni.as_deref(),
                    socks_port,
                )?;
                xray::spawn(&trial_dir, &xray_bin, &cfg).await
            }
        })
        .await?;
        Ok(TunnelSession {
            proc,
            trial_dir: trial_dir.clone(),
            _guard: TrialDirGuard(trial_dir),
        })
    }
}

pub struct TunnelSession {
    pub proc: xray::XrayProcess,
    trial_dir: PathBuf,
    _guard: TrialDirGuard,
}

impl TunnelSession {
    pub(crate) async fn cleanup(mut self) {
        self.proc.stop().await;
        cleanup_trial_dir(&self.trial_dir).await;
    }
}

impl TunnelProbe for XrayTunnelProbe {
    fn probe(
        &self,
        req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
        let spec = req.spec.clone();
        let preset = req.preset.clone();
        let custom = req.custom.cloned();
        let sni = req.sni.map(str::to_owned);
        let probe_urls = req.probe_urls.to_vec();
        let ProbeRequest {
            dial_ip,
            timeout_ms,
            ..
        } = req;
        Box::pin(async move {
            let work_dir = paths::data_dir().context("no data directory for trial configs")?;
            sweep_stale_trial_dirs_async(&work_dir).await;
            let trial_dir = make_trial_dir(&work_dir).await?;

            let _guard = TrialDirGuard(trial_dir.clone());
            let fetch = xray::RealFetch;
            let xray_bin = xray::ensure_binary(&fetch).await.with_context(|| {
                "no verified xray binary (cached copy failed its checksum or the download failed)"
            })?;
            let outcome: Result<TunnelResult> =
                match tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                    let mut proc = spawn_with_retry(dial_ip, |socks_port| {
                        let spec = spec.clone();
                        let preset = preset.clone();
                        let custom = custom.clone();
                        let sni = sni.clone();
                        let trial_dir = trial_dir.clone();
                        let xray_bin = xray_bin.clone();
                        async move {
                            let cfg = xray::build_config(
                                &spec,
                                dial_ip,
                                &preset,
                                custom.as_ref(),
                                sni.as_deref(),
                                socks_port,
                            )?;
                            xray::spawn(&trial_dir, &xray_bin, &cfg).await
                        }
                    })
                    .await?;

                    let started = Instant::now();
                    let mut all_ok = true;
                    let mut colo = None;
                    for url in &probe_urls {
                        match socks::get_via_socks(url, proc.socks_addr, timeout_ms).await {
                            Ok(body) if colo.is_none() => colo = crate::geo::parse_colo(&body),
                            Ok(_) => {}
                            Err(err) => {
                                let clean_url = url.split(['?', '#']).next().unwrap_or(url);
                                tracing::debug!(
                                    err = %crate::configs::sanitize_error_text(&err.to_string()),
                                    ip = %dial_ip,
                                    url = %clean_url,
                                    "phase-2 probe did not deliver 200"
                                );
                                all_ok = false;
                            }
                        }
                    }
                    let latency_ms = started.elapsed().as_millis() as u32;
                    proc.stop().await;

                    if all_ok {
                        Ok(TunnelResult {
                            passed: true,
                            latency_ms: Some(latency_ms),
                            colo,
                            verifier: Some("xray"),
                        })
                    } else {
                        Ok(TunnelResult {
                            passed: false,
                            latency_ms: None,
                            colo: None,
                            verifier: Some("xray"),
                        })
                    }
                })
                .await
                {
                    Ok(res) => res,
                    Err(_) => {
                        tracing::debug!(ip = %dial_ip, "xray probe timed out");
                        Ok(TunnelResult {
                            passed: false,
                            latency_ms: None,
                            colo: None,
                            verifier: Some("xray"),
                        })
                    }
                };

            cleanup_trial_dir(&trial_dir).await;
            outcome
        })
    }
}

fn fresh_trial_dir(work_dir: &Path) -> PathBuf {
    use rand_core::RngCore;
    let salt = rand_core::OsRng.next_u32();
    let dir = work_dir.join(format!(
        "trial-{}-{}-{salt:08x}",
        next_trial_id(),
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

async fn make_trial_dir(work_dir: &Path) -> Result<PathBuf> {
    let work_dir = work_dir.to_path_buf();
    let dir = tokio::task::spawn_blocking(move || -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&work_dir)?;
        Ok(fresh_trial_dir(&work_dir))
    })
    .await
    .context("trial dir creation task failed")??;
    Ok(dir)
}

async fn cleanup_trial_dir(trial_dir: &Path) {
    let dir = trial_dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&dir)).await;
}

struct TrialDirGuard(PathBuf);

impl TrialDirGuard {
    #[cfg(test)]
    pub(crate) fn cleanup_blocking(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Drop for TrialDirGuard {
    fn drop(&mut self) {
        let path = self.0.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                let _ = std::fs::remove_dir_all(path);
            });
        } else {
            std::thread::spawn(move || {
                let _ = std::fs::remove_dir_all(path);
            });
        }
    }
}

const STALE_TRIAL_AGE: Duration = Duration::from_secs(60 * 60);

fn sweep_stale_trial_dirs(work_dir: &Path) {
    sweep_stale_trial_dirs_before(work_dir, std::time::SystemTime::now() - STALE_TRIAL_AGE);
}

static LAST_SWEEP_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn sweep_stale_trial_dirs_async(work_dir: &Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_SWEEP_SECS.load(std::sync::atomic::Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < STALE_TRIAL_AGE.as_secs() {
        return;
    }
    if LAST_SWEEP_SECS
        .compare_exchange(
            last,
            now,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        return;
    }
    let work_dir = work_dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || sweep_stale_trial_dirs(&work_dir)).await;
}

fn sweep_stale_trial_dirs_before(work_dir: &Path, cutoff: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(work_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("trial-") {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
            continue;
        };
        if modified < cutoff {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

static TRIAL_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_trial_id() -> u64 {
    TRIAL_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn pick_ephemeral_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| anyhow!("no free ephemeral port ({}): {e}", e.kind()))?;
    Ok(listener.local_addr()?.port())
}

async fn spawn_with_retry<T, Fut>(ip: Ipv4Addr, mut attempt: impl FnMut(u16) -> Fut) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    let mut tried: Vec<u16> = Vec::new();
    for attempt_no in 1..=3u32 {
        let socks_port = {
            let mut picked = None;
            for _ in 0..16 {
                let candidate = pick_ephemeral_port().context("no free port for xray inbound")?;
                if !tried.contains(&candidate) {
                    picked = Some(candidate);
                    break;
                }
            }
            picked.ok_or_else(|| anyhow!("no distinct ephemeral port after 16 picks"))?
        };
        tried.push(socks_port);
        match attempt(socks_port).await {
            Ok(value) => return Ok(value),
            Err(err) if attempt_no < 3 => {
                tracing::debug!(
                    %err, ip = %ip, attempt = attempt_no,
                    "xray spawn failed; retrying with a fresh port"
                );
                last_err = Some(err);
            }
            Err(err) => return Err(err).context("xray spawn failed after 3 attempts"),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("xray spawn failed after 3 attempts")))
}

pub fn require_xray_binary() -> Result<PathBuf> {
    xray::find_binary()
        .ok_or_else(|| anyhow!("xray binary not found; it will be downloaded at phase 2"))
}

pub struct HybridTunnelProbe {
    inline: InlineTunnelProbe,
    xray: Arc<dyn TunnelProbe>,
}

impl HybridTunnelProbe {
    pub fn new(xray: Arc<dyn TunnelProbe>) -> Self {
        Self {
            inline: InlineTunnelProbe::new(),
            xray,
        }
    }

    pub fn supports_inline(
        spec: &OutboundSpec,
        preset: &FragmentPreset,
        custom: Option<&CustomFragment>,
    ) -> bool {
        if *preset != FragmentPreset::Off || custom.is_some() || spec.ws.is_some() {
            return false;
        }
        if !(spec.security.eq_ignore_ascii_case("tls")
            || spec.security.eq_ignore_ascii_case("none"))
        {
            return false;
        }
        match spec.protocol {
            Protocol::Vless => crate::inline_verify::parse_uuid(&spec.user_id).is_some(),
            Protocol::Trojan => true,
            _ => false,
        }
    }
}

impl TunnelProbe for HybridTunnelProbe {
    fn probe(
        &self,
        req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
        if Self::supports_inline(req.spec, req.preset, req.custom) {
            self.inline.probe(req)
        } else {
            self.xray.probe(req)
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use crate::configs::parse_uri;

    #[test]
    fn inline_tunnel_result_never_carries_the_raw_user_id() {
        let secret = "SecretUser:SecretPass123";
        let trojan = parse_uri(&format!("trojan://{secret}@1.2.3.4:443?security=tls")).unwrap();
        let probe = InlineTunnelProbe::new();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                probe
                    .probe(ProbeRequest {
                        spec: &trojan,
                        dial_ip: "127.0.0.1".parse().unwrap(),
                        preset: &FragmentPreset::Off,
                        custom: None,
                        sni: None,
                        probe_urls: &["http://probe.test/x".to_owned()],
                        timeout_ms: 150,
                    })
                    .await
                    .unwrap()
            });
        let debug = format!("{result:?}");
        assert!(
            !debug.contains("SecretPass123"),
            "a failed inline verdict must never echo the credential: {debug}"
        );
        assert!(!result.passed, "refused connection must fail the probe");
        assert_eq!(result.verifier, Some("inline"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ports_are_in_range_and_reusable() {
        for _ in 0..4 {
            let port = pick_ephemeral_port().unwrap();
            assert!(port > 0);
            let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)));
            assert!(listener.is_ok(), "port {port} should be free after pick");
        }
    }

    #[test]
    fn trial_dirs_are_unique() {
        let dir = std::env::temp_dir().join("cf-scanner-verify-unique-test");
        let _ = std::fs::create_dir_all(&dir);
        let a = fresh_trial_dir(&dir);
        let b = fresh_trial_dir(&dir);
        assert_ne!(a, b, "concurrent trials must never share a config dir");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trial_dir_guard_removes_the_dir_on_drop() {
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-verify-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut guard = TrialDirGuard(dir.clone());
            assert!(dir.exists());
            guard.cleanup_blocking();
            assert!(
                !dir.exists(),
                "cleanup_blocking must remove the credential dir"
            );
        }
        assert!(!dir.exists());
        let guard = TrialDirGuard(dir.clone());
        drop(guard);
        std::thread::sleep(Duration::from_millis(20));
        assert!(!dir.exists());
    }

    #[test]
    fn sweep_removes_stale_trial_dirs_and_keeps_others() {
        let dir = std::env::temp_dir().join("cf-scanner-verify-sweep-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("trial-0")).unwrap();
        std::fs::create_dir_all(dir.join("trial-1")).unwrap();
        std::fs::create_dir_all(dir.join("not-a-trial")).unwrap();
        std::fs::write(dir.join("trial-0/config.json"), "{}").unwrap();
        let cutoff = std::time::SystemTime::now() + Duration::from_secs(60);
        sweep_stale_trial_dirs_before(&dir, cutoff);
        assert!(!dir.join("trial-0").exists());
        assert!(!dir.join("trial-1").exists());
        assert!(dir.join("not-a-trial").exists());
        sweep_stale_trial_dirs_before(&dir.join("missing"), cutoff);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn spawn_retry_succeeds_on_the_first_attempt() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = calls.clone();
        let out = spawn_with_retry(Ipv4Addr::LOCALHOST, move |port| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(port);
                Ok(port)
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1, "no retry on success");
        assert_eq!(
            out,
            calls.lock().unwrap()[0],
            "the closure's value survives"
        );
    }

    #[tokio::test]
    async fn spawn_retry_succeeds_after_two_failures_with_fresh_ports() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = calls.clone();
        let out = spawn_with_retry(Ipv4Addr::LOCALHOST, move |port| {
            let seen = seen.clone();
            async move {
                let mut v = seen.lock().unwrap();
                v.push(port);
                if v.len() < 3 {
                    Err(anyhow!("stolen ephemeral port"))
                } else {
                    Ok(port)
                }
            }
        })
        .await
        .unwrap();
        let v = calls.lock().unwrap();
        assert_eq!(v.len(), 3, "exactly 3 closure calls before success");
        assert!(
            v.windows(2).all(|w| w[0] != w[1]),
            "fresh port per attempt: {v:?}"
        );
        assert_eq!(out, *v.last().unwrap());
    }

    #[tokio::test]
    async fn spawn_retry_reports_the_last_error_after_three_failures() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = calls.clone();
        let err = spawn_with_retry(Ipv4Addr::LOCALHOST, move |port| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(port);
                Err::<u16, _>(anyhow!("boom {port}"))
            }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.lock().unwrap().len(), 3, "no more than 3 attempts");
        assert!(
            err.to_string().contains("after 3 attempts"),
            "context must name the retry limit: {err}"
        );
        assert!(err.chain().any(|e| e.to_string().contains("boom")));
    }
}
