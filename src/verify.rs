//! Phase-2 tunnel verifier (Task 11): one real attempt per
//! (candidate IP, config, fragment preset, SNI) combo — spawn xray dialing
//! the candidate, prove connectivity with a tiny HTTP GET through the socks
//! inbound, tear down. The probe itself is injectable so engine tests never
//! spawn subprocesses.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Instant;

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
            let xray_bin = xray::find_binary().ok_or_else(|| {
                anyhow!("xray binary not found; bundle or download it into the data dir first")
            })?;
            let work_dir = paths::data_dir().context("no data directory for trial configs")?;
            std::fs::create_dir_all(&work_dir)?;
            let socks_port = pick_ephemeral_port().context("no free port for xray inbound")?;
            let cfg = xray::build_config(
                &spec,
                dial_ip,
                &preset,
                custom.as_ref(),
                sni.as_deref(),
                socks_port,
            )?;
            let trial_dir = fresh_trial_dir(&work_dir);
            let mut proc = xray::spawn(&trial_dir, &xray_bin, &cfg).await?;

            let started = Instant::now();
            let outcome = ranges::get_via_socks(&probe_url, proc.socks_addr, timeout_ms).await;
            let latency_ms = started.elapsed().as_millis() as u32;
            proc.stop().await;
            let _ = std::fs::remove_dir_all(&trial_dir);

            match outcome {
                Ok(_) => Ok(TunnelResult {
                    passed: true,
                    latency_ms: Some(latency_ms),
                }),
                Err(err) => {
                    tracing::debug!(%err, ip = %dial_ip, "phase-2 probe did not deliver 200");
                    Ok(TunnelResult {
                        passed: false,
                        latency_ms: None,
                    })
                }
            }
        })
    }
}

/// One dir per trial so concurrent probes never race on config.json.
fn fresh_trial_dir(work_dir: &Path) -> PathBuf {
    let dir = work_dir.join(format!("trial-{}", next_trial_id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
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

/// Discovers the xray binary and fails with a hint if it is absent. Exposed
/// for the CLI/server to pre-flight before a phase-2 scan starts.
pub fn require_xray_binary() -> Result<PathBuf> {
    xray::find_binary()
        .ok_or_else(|| anyhow!("xray binary not found; run the checksum-verified download first"))
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
        let a = fresh_trial_dir(Path::new("unused"));
        let b = fresh_trial_dir(Path::new("unused"));
        assert_ne!(a, b, "concurrent trials must never share a config dir");
    }
}
