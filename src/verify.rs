//! Phase-2 tunnel verifier (Task 11): one real attempt per
//! (candidate IP, config, fragment preset, SNI) combo — dial the candidate,
//! prove connectivity with a tiny HTTP GET through the tunnel, tear down.
//! The probe itself is injectable so engine tests never spawn subprocesses.
//! Combo routing is hybrid: vless/trojan over plain tcp/tls with the
//! fragment preset Off verify IN-PROCESS (`InlineTunnelProbe`, no subprocess
//! and no ~50-200ms spawn); everything else — vmess, shadowsocks, ws
//! transports, and every DPI-fragmentation preset — spawns xray, which can
//! fragment the TLS ClientHello in ways stock rustls cannot.

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

/// Outcome of one tunnel attempt. `passed: false` means the tunnel came up
/// but the probe HTTP GET did not deliver a 200 (or the candidate refused
/// the handshake); `Err` from `probe` is reserved for local failures
/// (missing xray binary, config build errors) that should abort the phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelResult {
    pub passed: bool,
    /// Round-trip of the probe GET through the tunnel.
    pub latency_ms: Option<u32>,
    /// Cloudflare colo code from the trace body, when present.
    pub colo: Option<String>,
    /// Which verifier produced the result: `Some("inline")` (in-process
    /// vless/trojan) or `Some("xray")` (subprocess). Test fakes leave it
    /// `None`.
    pub verifier: Option<&'static str>,
}

/// Everything one tunnel attempt needs (kept as a single argument so the
/// trait stays under the arg-count lint).
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

/// Injectable one-attempt tunnel probe; the engine drives it over the combos.
/// BoxFuture style (like `Transport`) so it is dyn-compatible for `Arc<dyn ..>`.
pub trait TunnelProbe: Send + Sync {
    fn probe(
        &self,
        req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>>;
}

/// Test-only probe that passes every dial: lets server-level tests fill the
/// verdict store and phase-2 configs without spawning xray.
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

/// Real probe: writes an xray config dialing `dial_ip` into a fresh trial
/// directory, spawns `xray run`, GETs the probe URL through its socks
/// inbound, and kills the subprocess. Trial dirs live under the data dir so
/// configs (which embed the user's id/password) never hit the system temp.
/// The binary and work dir are resolved per attempt so a download made after
/// server start is picked up.
pub struct XrayTunnelProbe;

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
            // Hard kills leave stale trial dirs holding plaintext credentials;
            // sweep them before creating the next trial (off the executor).
            sweep_stale_trial_dirs_async(&work_dir).await;
            let trial_dir = make_trial_dir(&work_dir).await?;

            // Trial dirs hold configs embedding the user's id/password; the
            // guard removes them even when the attempt dies mid-flight (the
            // explicit cleanup below handles the normal resolve path).
            let _guard = TrialDirGuard(trial_dir.clone());
            // Binary resolution is bounded by its own step — the download
            // carries a 60 s HTTP timeout and concurrent attempts share one
            // download — NOT by the per-probe budget: on a cold cache a slow
            // link cannot pull the zip inside one probe timeout, and the
            // timeout arm below would silently convert the abort into a
            // failed verdict for every xray-routed combo.
            let fetch = xray::RealFetch;
            let xray_bin = xray::ensure_binary(&fetch).await.with_context(|| {
                "no verified xray binary (cached copy failed its checksum or the download failed)"
            })?;
            let outcome: Result<TunnelResult> =
                match tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                    // The picked port can be stolen between the ephemeral bind
                    // probe and xray's own bind; retry with a fresh port instead
                    // of failing the whole probe on that race.
                    let mut proc = spawn_with_retry(dial_ip, |socks_port| {
                        // Clones keep the retry closure self-contained (it may
                        // run up to 3 times); the originals stay for cleanup.
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

                    // One xray spawn serves the WHOLE probe list: every URL is
                    // GET through the same socks inbound (fresh SOCKS5 stream per
                    // URL, one process), so multi-URL verification costs one
                    // spawn instead of one per URL. A pass needs every URL to
                    // deliver 200; the colo comes from the first trace body that
                    // carries one.
                    let started = Instant::now();
                    let mut all_ok = true;
                    let mut colo = None;
                    for url in &probe_urls {
                        match socks::get_via_socks(url, proc.socks_addr, timeout_ms).await {
                            Ok(body) if colo.is_none() => colo = crate::geo::parse_colo(&body),
                            Ok(_) => {}
                            Err(err) => {
                                // Probe URLs are user-supplied and may carry
                                // tokens in their query: strip query/fragment
                                // and sanitize the error text before logging.
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

/// One dir per trial so concurrent probes never race on config.json. The
/// name carries the per-process counter plus pid + randomness so two app
/// instances sharing a data dir cannot collide on `trial-N` (one instance's
/// sweep/guard must never delete the other's credential-bearing dir).
fn fresh_trial_dir(work_dir: &Path) -> PathBuf {
    // rand_core (already a dependency) supplies the salt — no new crate.
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

/// mkdir + trial dir creation on the blocking pool (per-attempt fs).
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

/// Trial-dir removal off the async executor; best-effort.
async fn cleanup_trial_dir(trial_dir: &Path) {
    let dir = trial_dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&dir)).await;
}

/// Removes the trial dir on drop so a hard teardown (engine cancel, server
/// shutdown) never leaves a plaintext-credential config behind. The normal
/// path removes the dir explicitly first; a drop after that is a cheap no-op
/// (`remove_dir_all` of a missing path returns Ok).
struct TrialDirGuard(PathBuf);

impl TrialDirGuard {
    /// Deterministic blocking removal for tests that assert the dir is gone
    /// (the tokio `Drop` impl must not block the runtime, so it detaches).
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

/// Stale `trial-*` dirs older than this are swept at the next attempt.
const STALE_TRIAL_AGE: Duration = Duration::from_secs(60 * 60);

/// Best-effort removal of stale trial dirs; never fails the attempt.
fn sweep_stale_trial_dirs(work_dir: &Path) {
    sweep_stale_trial_dirs_before(work_dir, std::time::SystemTime::now() - STALE_TRIAL_AGE);
}

/// Throttle for the per-attempt sweep: 30k attempts must not do 30k
/// `read_dir`+`metadata` sweeps. The real cost is paid once per top-level
/// verify call; subsequent probes in the same scan see a cheap early return.
/// Uses wall-clock secs so no extra state is threaded through callers.
static LAST_SWEEP_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The sweep runs off the async executor (per-attempt blocking fs) but is
/// throttled to once per `STALE_TRIAL_AGE`.
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

/// Binds 127.0.0.1:0 to learn a free port, then drops the listener so xray
/// can bind it. A tiny race, mitigated by the socks readiness poll failing
/// the attempt (never the process).
fn pick_ephemeral_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| anyhow!("no free ephemeral port ({}): {e}", e.kind()))?;
    Ok(listener.local_addr()?.port())
}

/// Retries a spawn that failed (usually a stolen ephemeral port), with a
/// fresh port per attempt; the last error wins after 3 tries. Generic over
/// the spawned value so tests can synthesize results without a real child
/// process.
async fn spawn_with_retry<T, Fut>(ip: Ipv4Addr, mut attempt: impl FnMut(u16) -> Fut) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for attempt_no in 1..=3u32 {
        let socks_port = pick_ephemeral_port().context("no free port for xray inbound")?;
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
    // Unreachable: the 3rd failure returns above. Keep the last error so the
    // compiler never forces an `expect` into the refactor.
    Err(last_err.unwrap_or_else(|| anyhow!("xray spawn failed after 3 attempts")))
}

/// Discovers the xray binary and fails with a hint if it is absent. Exposed
/// for the CLI/server to pre-flight before a phase-2 scan starts (the real
/// probe auto-downloads a checksum-verified binary when missing).
pub fn require_xray_binary() -> Result<PathBuf> {
    xray::find_binary()
        .ok_or_else(|| anyhow!("xray binary not found; it will be downloaded at phase 2"))
}

/// Routes every attempt to whichever verifier can handle it: the in-process
/// vless/trojan speaker when the combo needs no fragmentation, the xray
/// subprocess otherwise. The engine's default tunnel probe.
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

    /// xray keeps everything the inline verifier cannot do: vmess/ss and ws
    /// transports (differing wire formats), fragment presets (stock rustls
    /// cannot fragment a TLS ClientHello), and vless configs whose id is not
    /// a parseable UUID.
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
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ports_are_in_range_and_reusable() {
        for _ in 0..4 {
            let port = pick_ephemeral_port().unwrap();
            assert!(port > 0);
            // The listener is dropped, so binding again must succeed.
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
            // Drop after explicit cleanup is a detached no-op.
        }
        assert!(!dir.exists());
        // Detached Drop on a missing dir must not panic; give the thread a moment.
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
        // A cutoff in the future makes every dir stale by definition.
        let cutoff = std::time::SystemTime::now() + Duration::from_secs(60);
        sweep_stale_trial_dirs_before(&dir, cutoff);
        assert!(!dir.join("trial-0").exists());
        assert!(!dir.join("trial-1").exists());
        assert!(dir.join("not-a-trial").exists());
        // Sweeping a missing dir is a silent no-op.
        sweep_stale_trial_dirs_before(&dir.join("missing"), cutoff);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- spawn_with_retry (review r6) ----------------------------------------

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
