//! Shared server state: the profiles store, ranges snapshot with its
//! background refresh, SSE accounting, and the WARP registration gate.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::RwLock as TokioRwLock;

use crate::api::types::ScanConfig;
use crate::engine::ScanController;
use crate::paths;
use crate::ranges::{self, CidrPool, HttpGet};

pub(crate) const DEFAULT_RANGES_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Cap on saved profiles so an unauthenticated local caller cannot grow the
/// in-memory map without bound (memory-DoS guard; review Domain 7).
pub(crate) const MAX_PROFILES: usize = 50;
/// WARP registration hits Cloudflare's registration endpoint; one attempt per
/// 60 s keeps a stuck page from hammering it (process-wide, single-user app).
pub(crate) const REGISTER_COOLDOWN: Duration = Duration::from_secs(60);
/// Xray download endpoint: same 60 s gate so a stuck client cannot loop
/// download attempts indefinitely (mirrors the register-cooldown pattern).
pub(crate) const XRAY_DOWNLOAD_COOLDOWN: Duration = Duration::from_secs(60);
/// Persisted profiles file inside the data dir (identity.json lives
/// alongside it); written on every mutation, loaded at serve start so saved
/// profiles survive restarts (review Domain 2, rec 10).
pub(crate) const PROFILES_FILE: &str = "profiles.json";

pub(crate) fn load_profiles(dir: &std::path::Path) -> HashMap<String, ScanConfig> {
    let path = dir.join(PROFILES_FILE);
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    match serde_json::from_str(&text) {
        Ok(profiles) => profiles,
        Err(err) => {
            tracing::warn!("profiles: ignoring unreadable {PROFILES_FILE}: {err:#}");
            HashMap::new()
        }
    }
}

/// Best-effort disk write on a blocking thread; a failure is logged, never
/// fatal (the in-memory store stays authoritative for the session).
pub(crate) async fn persist_profiles(
    dir: &std::path::Path,
    profiles: &HashMap<String, ScanConfig>,
) {
    let path = dir.join(PROFILES_FILE);
    let Ok(json) = serde_json::to_string_pretty(profiles) else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        let _gate = paths::data_write_guard();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // tmp + rename under the write gate: a concurrent reader (or the
        // next writer) must never observe a half-written profiles.json.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            // Profiles can hold sensitive scan configs: keep the file
            // user-only where the filesystem supports permissions (mirrors
            // warpgen::write_private).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                paths::lock_down_to_owner(&tmp).ok();
            }
            let _ = std::fs::rename(&tmp, &path);
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    })
    .await;
}

/// A named ScanConfig persisted to profiles.json (wgconf stripped via
/// sanitize_config) and held in memory for the session; loaded at serve start.
#[derive(Serialize)]
pub(crate) struct ProfilePayload {
    pub(crate) name: String,
    pub(crate) config: crate::api::types::ScanConfig,
}

/// WARP registration seam: production drives warpgen::register (the
/// Cloudflare v0a884 flow) on a blocking thread; tests inject a fake so the
/// endpoint never touches the network (mirrors the ranges::HttpGet
/// injectability).
pub(crate) type WarpRegistrar = Arc<dyn Fn(Option<String>) -> anyhow::Result<String> + Send + Sync>;

/// Xray binary fetch seam: production drives `xray::ensure_binary` with the
/// real HTTP fetcher; tests inject a fake that returns a dummy path so the
/// cooldown gate can be tested without touching the network.
pub(crate) type XrayFetcher = Arc<dyn Fn() -> anyhow::Result<std::path::PathBuf> + Send + Sync>;

pub(crate) struct AppState {
    pub(crate) controller: Arc<ScanController>,
    pub(crate) profiles: TokioRwLock<HashMap<String, crate::api::types::ScanConfig>>,
    pub(crate) ranges: Arc<RangesState>,
    pub(crate) sse_connections: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) warp_register: WarpRegistrar,
    /// Where profiles.json lives; production = the data dir, tests = an
    /// isolated temp dir so no test touches a real user's profiles.
    pub(crate) profiles_dir: PathBuf,
    /// Epoch of the latest started run; terminal events are tagged with it
    /// so an SSE reconnect replays the current run's terminal only.
    pub(crate) run_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// Terminal (Finished/Failed) of the latest finished run, tagged with
    /// its epoch; replayed to SSE clients that connect after the run ended.
    pub(crate) last_terminal: Arc<Mutex<Option<(u64, crate::api::types::ScanEvent)>>>,
    /// Serializes WARP registrations end-to-end and carries the last
    /// attempt for the 1-per-60s limit. The overwrite-consent check and the
    /// registration must be ONE critical section: two concurrent first-time
    /// registers would both see "no identity" and both clobber it. Held
    /// across the network call; the cooldown already limits registrations to
    /// 1/60 s, so serializing them costs nothing.
    pub(crate) register_gate: tokio::sync::Mutex<Option<Instant>>,
    /// Serializes xray downloads end-to-end and carries the last attempt
    /// for the 60 s limit (mirrors the register_gate pattern).
    pub(crate) xray_download_gate: tokio::sync::Mutex<Option<Instant>>,
    /// Xray binary fetch seam: production drives `xray::ensure_binary` with
    /// the real HTTP fetcher; tests inject a fake.
    pub(crate) xray_fetch: XrayFetcher,
}

/// What /api/ranges serves: the current pool plus when it was last refreshed.
struct RangesInner {
    pool: CidrPool,
    last_updated: Option<String>,
}

/// Arc so the persist closure can be cloned into spawn_blocking.
type Persist = Arc<dyn Fn(&CidrPool, &str) -> anyhow::Result<()> + Send + Sync>;

pub(crate) struct RangesState {
    inner: RwLock<RangesInner>,
    persist: Persist,
}

impl RangesState {
    /// Production state: the refreshed data-dir file when present, else the
    /// bundled list; the embedded-list load time stands in for last_updated
    /// until the first successful refresh.
    pub(crate) fn load() -> Arc<Self> {
        let text = paths::refreshed_ranges_path()
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        let now = ranges::rfc3339_utc(ranges::unix_now());
        let (pool, last_updated) = match text {
            Some(text) => (
                CidrPool::parse(&text).unwrap_or_else(|_| CidrPool::bundled()),
                ranges::last_updated_of(&text).or(Some(now)),
            ),
            None => (CidrPool::bundled(), Some(now)),
        };
        Arc::new(Self {
            inner: RwLock::new(RangesInner { pool, last_updated }),
            persist: Arc::new(ranges::write_pool),
        })
    }

    /// Test constructor: persistence is a no-op so background-refresh tests
    /// never touch the data dir.
    #[cfg(test)]
    pub(crate) fn load_text(text: &str, last_updated: Option<&str>) -> Arc<Self> {
        let pool = CidrPool::parse(text).unwrap_or_else(|_| CidrPool::bundled());
        Arc::new(Self {
            inner: RwLock::new(RangesInner {
                pool,
                last_updated: last_updated.map(str::to_owned),
            }),
            persist: Arc::new(|_, _| Ok(())),
        })
    }

    /// One refresh cycle: fetch + validate, persist (best-effort, logged),
    /// then swap the in-memory snapshot. Errors leave the last good data.
    /// The disk write runs on a blocking thread so a slow filesystem cannot
    /// stall the async runtime.
    pub(crate) async fn refresh(&self, http: &impl HttpGet) -> anyhow::Result<()> {
        let pool = ranges::fetch_official(http).await?;
        let last_updated = ranges::rfc3339_utc(ranges::unix_now());
        let persist = Arc::clone(&self.persist);
        let pool_for_disk = pool.clone();
        let stamp = last_updated.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(err) = persist(&pool_for_disk, &stamp) {
                tracing::warn!("ranges refresh: could not persist to disk: {err:#}");
            }
        })
        .await
        .ok();
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.pool = pool;
        inner.last_updated = Some(last_updated);
        Ok(())
    }

    /// Snapshot accessor for handlers; poisons are recovered from.
    pub(crate) fn snapshot(&self) -> (CidrPool, Option<String>) {
        let inner = self.inner.read().unwrap_or_else(|p| p.into_inner());
        (inner.pool.clone(), inner.last_updated.clone())
    }

    /// Spawns the refresh loop; `interval` overrides the 24h default (tests
    /// use a short one). Never ends; a failed cycle is logged and the last
    /// good data stays in place. The first tick fires immediately.
    pub(crate) fn spawn_refresh<H>(self: &Arc<Self>, interval: Option<Duration>, http: Arc<H>)
    where
        H: HttpGet + Send + Sync + 'static,
    {
        let interval = interval.unwrap_or(DEFAULT_RANGES_REFRESH_INTERVAL);
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(err) = this.refresh(http.as_ref()).await {
                    tracing::warn!(
                        "ranges background refresh failed (keeping last good data): {err:#}"
                    );
                }
            }
        });
    }
}
