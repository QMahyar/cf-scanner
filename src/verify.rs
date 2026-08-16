//! Phase-2 tunnel verifier (Task 11): one real attempt per
//! (candidate IP, config, fragment preset, SNI) combo — spawn xray dialing
//! the candidate, prove connectivity with a tiny HTTP GET through the socks
//! inbound, tear down. The probe itself is injectable so engine tests never
//! spawn subprocesses.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};

use crate::api::types::{CustomFragment, FragmentPreset};
use crate::configs::OutboundSpec;
use crate::paths;
use crate::ranges;
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
    pub probe_url: &'a str,
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
        let probe_url = req.probe_url.to_owned();
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
            let outcome = async {
                let fetch = xray::RealFetch;
                let xray_bin = xray::ensure_binary(&fetch).await.with_context(|| {
                    "no verified xray binary (cached copy failed its checksum or the download failed)"
                })?;
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

                let started = Instant::now();
                let outcome = ranges::get_via_socks(&probe_url, proc.socks_addr, timeout_ms).await;
                let latency_ms = started.elapsed().as_millis() as u32;
                proc.stop().await;

                match outcome {
                    Ok(body) => Ok(TunnelResult {
                        passed: true,
                        latency_ms: Some(latency_ms),
                        colo: crate::geo::parse_colo(&body),
                    }),
                    Err(err) => {
                        tracing::debug!(%err, ip = %dial_ip, "phase-2 probe did not deliver 200");
                        Ok(TunnelResult {
                            passed: false,
                            latency_ms: None,
                            colo: None,
                        })
                    }
                }
            }
            .await;

            cleanup_trial_dir(&trial_dir).await;
            outcome
        })
    }
}

/// One dir per trial so concurrent probes never race on config.json.
fn fresh_trial_dir(work_dir: &Path) -> PathBuf {
    let dir = work_dir.join(format!("trial-{}", next_trial_id()));
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

impl Drop for TrialDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Stale `trial-*` dirs older than this are swept at the next attempt.
const STALE_TRIAL_AGE: Duration = Duration::from_secs(60 * 60);

/// Best-effort removal of stale trial dirs; never fails the attempt.
fn sweep_stale_trial_dirs(work_dir: &Path) {
    sweep_stale_trial_dirs_before(work_dir, std::time::SystemTime::now() - STALE_TRIAL_AGE);
}

/// The sweep runs off the async executor (per-attempt blocking fs).
async fn sweep_stale_trial_dirs_async(work_dir: &Path) {
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
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
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
        let dir = std::env::temp_dir().join(format!(
            "cf-scanner-verify-guard-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let guard = TrialDirGuard(dir.clone());
            assert!(dir.exists());
            drop(guard);
        }
        assert!(!dir.exists(), "drop must remove the credential dir");
        // Dropping after an explicit cleanup is a no-op, not an error.
        let _ = TrialDirGuard(dir.clone());
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
