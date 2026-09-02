use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::engine::ScanController;
use crate::paths;
use crate::ranges::{self, CidrPool, HttpGet};

pub(crate) const DEFAULT_RANGES_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub(crate) const REGISTER_COOLDOWN: Duration = Duration::from_secs(60);
pub(crate) const XRAY_DOWNLOAD_COOLDOWN: Duration = Duration::from_secs(60);

pub(crate) type WarpRegistrar = Arc<dyn Fn(Option<String>) -> anyhow::Result<String> + Send + Sync>;

pub(crate) type XrayFetcher = Arc<dyn Fn() -> anyhow::Result<std::path::PathBuf> + Send + Sync>;

pub(crate) struct AppState {
    pub(crate) controller: Arc<ScanController>,
    pub(crate) ranges: Arc<RangesState>,
    pub(crate) sse_connections: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) warp_register: WarpRegistrar,
    pub(crate) run_epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) last_terminal: Arc<Mutex<Option<(u64, crate::api::types::ScanEvent)>>>,
    pub(crate) register_gate: tokio::sync::Mutex<Option<Instant>>,
    pub(crate) xray_download_gate: tokio::sync::Mutex<Option<Instant>>,
    pub(crate) xray_fetch: XrayFetcher,
}

struct RangesInner {
    pool: CidrPool,
    last_updated: Option<String>,
}

type Persist = Arc<dyn Fn(&CidrPool, &str) -> anyhow::Result<()> + Send + Sync>;

pub(crate) struct RangesState {
    inner: RwLock<RangesInner>,
    persist: Persist,
}

impl RangesState {
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
            persist: Arc::new(|pool, last_updated| {
                ranges::write_pool_to(&paths::refreshed_ranges_path()?, pool, last_updated)
            }),
        })
    }

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

    pub(crate) fn snapshot(&self) -> (CidrPool, Option<String>) {
        let inner = self.inner.read().unwrap_or_else(|p| p.into_inner());
        (inner.pool.clone(), inner.last_updated.clone())
    }

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
