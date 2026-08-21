//! Localhost HTTP API + embedded browser UI, both thin clients of the one
//! ScanController. Routes map engine state into the `api::types` contract
//! directly (those types ARE the wire contract); no engine type is
//! serialized.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, Request, State};
#[cfg(debug_assertions)]
use axum::http::header;
use axum::http::{StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock as TokioRwLock;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use crate::api::types::{DEFAULT_PORT, Mode, ScanConfig, ScanEvent, ScanSummary, Verdict};
use crate::engine::ScanController;
use crate::paths;
use crate::ranges::{self, CidrPool, HttpGet};
use crate::warpgen;
use crate::xray;

const EMBEDDED_INDEX: &str = include_str!("../embed/index.html");
const DEFAULT_RANGES_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Cap on concurrent SSE event streams so hung tabs cannot hoard broadcast
/// receivers; the UI needs one, extras are an abuse signal.
const MAX_SSE_CONNECTIONS: usize = 4;
/// Cap on saved profiles so an unauthenticated local caller cannot grow the
/// in-memory map without bound (memory-DoS guard; review Domain 7).
const MAX_PROFILES: usize = 50;
/// WARP registration hits Cloudflare's registration endpoint; one attempt per
/// 60 s keeps a stuck page from hammering it (process-wide, single-user app).
const REGISTER_COOLDOWN: Duration = Duration::from_secs(60);
/// Persisted profiles file inside the data dir (identity.json lives
/// alongside it); written on every mutation, loaded at serve start so saved
/// profiles survive restarts (review Domain 2, rec 10).
const PROFILES_FILE: &str = "profiles.json";

fn load_profiles(dir: &std::path::Path) -> HashMap<String, ScanConfig> {
    let path = dir.join(PROFILES_FILE);
    let Ok(text) = fs::read_to_string(path) else {
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
async fn persist_profiles(dir: &std::path::Path, profiles: &HashMap<String, ScanConfig>) {
    let path = dir.join(PROFILES_FILE);
    let Ok(json) = serde_json::to_string_pretty(profiles) else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&path, json).is_ok() {
            // Profiles can hold sensitive scan configs: keep the file
            // user-only where the filesystem supports permissions (mirrors
            // warpgen::write_private).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                crate::paths::lock_down_to_owner(&path).ok();
            }
        }
    })
    .await;
}

/// Host header values the API answers to. Anything else is rejected before
/// routing (DNS-rebinding / drive-by protection); the server only ever binds
/// 127.0.0.1.
const ALLOWED_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

fn host_allowed(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(addr, _)| addr).unwrap_or(host)
    } else if let Some((addr, _)) = host.rsplit_once(':') {
        addr
    } else {
        host
    };
    ALLOWED_HOSTS.contains(&host)
}

fn origin_allowed(origin: &str) -> bool {
    let host = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin);
    host_allowed(host)
}

/// Rejects requests that are not from the local UI: a foreign Host header,
/// a cross-origin browser request (Origin / Sec-Fetch-Site), or no Host at
/// all. Browsers and curl always send Host; the UI is same-origin.
async fn localhost_only(request: Request, next: Next) -> Result<Response, ApiError> {
    let headers = request.headers();
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return Err(ApiError::forbidden("missing Host header"));
    };
    if !host_allowed(host) {
        return Err(ApiError::forbidden("Host header not allowed"));
    }
    if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
        if origin != "null" && !origin_allowed(origin) {
            return Err(ApiError::forbidden("Origin not allowed"));
        }
    }
    if let Some(site) = headers.get("sec-fetch-site").and_then(|h| h.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            return Err(ApiError::forbidden("cross-site request rejected"));
        }
    }
    Ok(next.run(request).await)
}

/// Json extractor with the uniform ApiError envelope on rejection, so
/// malformed bodies answer `{"error","message"}` JSON instead of axum's
/// plain-text default.
struct JsonBody<T>(T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => Err(ApiError {
                status: rejection.status(),
                message: rejection.body_text(),
            }),
        }
    }
}

/// A named ScanConfig held for the current session only. Never persisted.
#[derive(Serialize)]
struct ProfilePayload {
    name: String,
    config: ScanConfig,
}

/// WARP registration seam: production drives warpgen::register (the
/// Cloudflare v0a884 flow) on a blocking thread; tests inject a fake so the
/// endpoint never touches the network (mirrors the ranges::HttpGet
/// injectability).
type WarpRegistrar = Arc<dyn Fn(Option<String>) -> anyhow::Result<String> + Send + Sync>;

struct AppState {
    controller: Arc<ScanController>,
    profiles: TokioRwLock<HashMap<String, ScanConfig>>,
    ranges: Arc<RangesState>,
    /// Serializes scan start: the check-and-spawn in start_scan must be
    /// atomic, else two concurrent POSTs both pass `is_running()`.
    start_lock: tokio::sync::Mutex<()>,
    sse_connections: Arc<AtomicUsize>,
    warp_register: WarpRegistrar,
    /// Where profiles.json lives; production = the data dir, tests = an
    /// isolated temp dir so no test touches a real user's profiles.
    profiles_dir: PathBuf,
    /// Epoch of the latest started run; terminal events are tagged with it
    /// so an SSE reconnect replays the current run's terminal only.
    run_epoch: Arc<AtomicU64>,
    /// Terminal (Finished/Failed) of the latest finished run, tagged with
    /// its epoch; replayed to SSE clients that connect after the run ended.
    last_terminal: Arc<Mutex<Option<(u64, ScanEvent)>>>,
    /// Last WARP registration attempt, for the 1-per-60s limit.
    last_register: Mutex<Option<Instant>>,
}

/// What /api/ranges serves: the current pool plus when it was last refreshed.
struct RangesInner {
    pool: CidrPool,
    last_updated: Option<String>,
}

/// Arc so the persist closure can be cloned into spawn_blocking.
type Persist = Arc<dyn Fn(&CidrPool, &str) -> anyhow::Result<()> + Send + Sync>;

struct RangesState {
    inner: RwLock<RangesInner>,
    persist: Persist,
}

impl RangesState {
    /// Production state: the refreshed data-dir file when present, else the
    /// bundled list; the embedded-list load time stands in for last_updated
    /// until the first successful refresh.
    fn load() -> Arc<Self> {
        let text = paths::refreshed_ranges_path()
            .ok()
            .and_then(|p| fs::read_to_string(p).ok());
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
    fn load_text(text: &str, last_updated: Option<&str>) -> Arc<Self> {
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
    async fn refresh(&self, http: &impl HttpGet) -> anyhow::Result<()> {
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

    /// Spawns the refresh loop; `interval` overrides the 24h default (tests
    /// use a short one). Never ends; a failed cycle is logged and the last
    /// good data stays in place. The first tick fires immediately.
    fn spawn_refresh<H>(self: &Arc<Self>, interval: Option<Duration>, http: Arc<H>)
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

pub fn router(controller: Arc<ScanController>) -> Router {
    let ranges = RangesState::load();
    ranges.spawn_refresh(None, Arc::new(ranges::RealHttp));
    let profiles_dir =
        paths::data_dir().unwrap_or_else(|_| std::env::temp_dir().join("cf-scanner-profiles"));
    router_with_dir(controller, ranges, default_registrar(), profiles_dir)
}

/// Every test server persists to its own throwaway dir, so no test can read
/// another test's profiles (and none touches a real user's data dir).
#[cfg(test)]
fn unique_test_profiles_dir() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cf-scanner-server-profiles-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn router_with_dir(
    controller: Arc<ScanController>,
    ranges_state: Arc<RangesState>,
    registrar: WarpRegistrar,
    profiles_dir: PathBuf,
) -> Router {
    let state = Arc::new(AppState {
        controller,
        profiles: TokioRwLock::new(load_profiles(&profiles_dir)),
        ranges: ranges_state,
        start_lock: tokio::sync::Mutex::new(()),
        sse_connections: Arc::new(AtomicUsize::new(0)),
        warp_register: registrar,
        profiles_dir,
        run_epoch: Arc::new(AtomicU64::new(0)),
        last_terminal: Arc::new(Mutex::new(None)),
        last_register: Mutex::new(None),
    });
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status_handler))
        .route("/api/xray/status", get(xray_status))
        .route("/api/xray/download", post(xray_download))
        .route("/api/scan", post(start_scan))
        .route("/api/events", get(events))
        .route("/api/results", get(results))
        .route("/api/cancel", post(cancel))
        .route("/api/reset", post(reset))
        .route("/api/ranges", get(ranges))
        .route("/api/warp/register", post(warp_register))
        .route("/api/config/export", post(export_config))
        .route("/api/profiles", get(list_profiles))
        .route(
            "/api/profiles/{name}",
            get(get_profile).put(put_profile).delete(delete_profile),
        )
        .with_state(state)
        .fallback(fallback)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(localhost_only))
}

/// Unmatched paths keep the uniform JSON error envelope: `/api/*` always,
/// everything else in release builds (the UI is a single embedded page).
/// Dev builds serve `embed/` from disk so the UI can be iterated without
/// rebuilding.
async fn fallback(uri: Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return ApiError::not_found(format!("no such endpoint: {}", uri.path())).into_response();
    }
    debug_fallback(uri)
}

/// Dev builds serve the single-page UI from disk so it can be iterated
/// without rebuilding; the page is fully self-contained (inline CSS/JS).
#[cfg(debug_assertions)]
fn debug_fallback(uri: Uri) -> Response {
    if matches!(uri.path(), "/" | "/index.html") {
        return serve_index_file();
    }
    ApiError::not_found("not found").into_response()
}

#[cfg(not(debug_assertions))]
fn debug_fallback(_uri: Uri) -> Response {
    ApiError::not_found("not found").into_response()
}

/// Directives every HTML response must carry; the single inline script and
/// styles need 'unsafe-inline' (the UI is one self-contained file, no external
/// resources), everything else stays locked down.
const SECURITY_CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; script-src-attr 'none'";

/// Adds the security headers every response should carry, leaving any header
/// the handler already set untouched (the HTML handlers set their own CSP).
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers
        .entry("referrer-policy")
        .or_insert(axum::http::HeaderValue::from_static("no-referrer"));
    headers
        .entry("x-content-type-options")
        .or_insert(axum::http::HeaderValue::from_static("nosniff"));
    response
}

/// Dev-only: read `embed/index.html` from the working directory (the release
/// binary embeds it via include_str!; a debug build run from the repo root
/// finds it on disk).
#[cfg(debug_assertions)]
fn serve_index_file() -> Response {
    match fs::read("embed/index.html") {
        Ok(bytes) => {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            headers.insert("content-security-policy", SECURITY_CSP.parse().unwrap());
            headers.insert("x-content-type-options", "nosniff".parse().unwrap());
            headers.insert("referrer-policy", "no-referrer".parse().unwrap());
            (headers, bytes).into_response()
        }
        Err(err) => {
            tracing::warn!("could not read embed/index.html: {err}");
            ApiError::internal("embedded UI missing (run from the repo root)").into_response()
        }
    }
}

/// Wrong method on a known path: 405 with the same JSON envelope as every
/// other error. axum 0.8 passes no Allow header to this handler; the status
/// alone is the contract the UI and CLI rely on.
async fn method_not_allowed() -> Response {
    ApiError::method_not_allowed("method not allowed for this path").into_response()
}

/// 202 with no body; the run's progress is observable on /api/events. 409
/// when another scan is already running. A local `start_lock` closes the
/// check-then-spawn window between concurrent POSTs.
async fn start_scan(
    State(state): State<Arc<AppState>>,
    JsonBody(cfg): JsonBody<ScanConfig>,
) -> Result<StatusCode, ApiError> {
    cfg.validate().map_err(ApiError::bad_request)?;
    reject_default_warp_ports(&cfg).map_err(ApiError::bad_request)?;
    reject_non_routable(&cfg).map_err(ApiError::bad_request)?;
    if let Some(phase2) = &cfg.phase2 {
        if let Some(local) = phase2.configs.iter().find(|c| !c.contains("://")) {
            return Err(ApiError::bad_request(format!(
                "phase2 config {local:?} is not a URL; local file paths are CLI-only"
            )));
        }
    }
    let _guard = state
        .start_lock
        .try_lock()
        .map_err(|_| ApiError::conflict("a scan is already starting"))?;
    if state.controller.is_running() {
        return Err(ApiError::conflict("a scan is already running"));
    }
    let epoch = state.run_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    let controller = state.controller.clone();
    let last_terminal = Arc::clone(&state.last_terminal);
    tokio::spawn(async move {
        let outcome = controller.run(cfg).await;
        // Record the terminal event so a client connecting after this run
        // can replay it; the engine already broadcast it live.
        let terminal = match outcome {
            Ok(summary) => ScanEvent::Finished(summary),
            Err(err) => {
                let msg = crate::configs::sanitize_error_text(&format!("{err:#}"));
                tracing::error!("scan failed: {msg}");
                ScanEvent::Failed(msg)
            }
        };
        *last_terminal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((epoch, terminal));
    });
    // The engine's running flag is set inside the spawned task, so keep the
    // lock until it lands; a racing second POST must see either the lock or
    // the flag (or 409 via try_lock) rather than a false "not running".
    for _ in 0..100 {
        if state.controller.is_running() {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(StatusCode::ACCEPTED)
}

/// API guard (the CLI documents its own WARP default): silently rewriting
/// `ports: [443]` into the WARP set would break the contract — the caller
/// sent port X and got Y without being told. Reject the CDN default instead
/// and surface the requirement for explicit UDP ports in the error message.
fn reject_default_warp_ports(cfg: &ScanConfig) -> Result<(), String> {
    if cfg.mode == Mode::Warp && cfg.ports.as_slice() == [DEFAULT_PORT] {
        return Err(format!(
            "warp scans need explicit UDP ports; the CDN default {DEFAULT_PORT} is not valid (pass e.g. 2408,500)"
        ));
    }
    Ok(())
}

/// API-only guard against self-scanning non-routable custom input (the CLI
/// stays unrestricted): custom CIDRs (CDN) and custom endpoints (WARP) must
/// not name loopback, link-local, unspecified, private/RFC1918 or ULA space.
fn reject_non_routable(cfg: &ScanConfig) -> Result<(), String> {
    match cfg.mode {
        Mode::Cdn => {
            for cidr in &cfg.custom_cidrs {
                let net = cidr.split('/').next().unwrap_or(cidr);
                if banned(net) {
                    return Err(format!(
                        "custom_cidrs entry {cidr:?} is not routable over the API (CLI is unrestricted)"
                    ));
                }
            }
        }
        Mode::Warp => {
            let endpoints = cfg
                .warp
                .as_ref()
                .map(|w| w.custom_endpoints.as_slice())
                .unwrap_or(&[]);
            for ep in endpoints {
                let ip = crate::api::types::parse_endpoint(ep)
                    .map(|(ip, _)| ip)
                    .map_err(|_| format!("bad endpoint {ep:?}"))?;
                if banned_ip(&ip) {
                    return Err(format!(
                        "custom endpoint {ep:?} is not routable over the API (CLI is unrestricted)"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// True when `net` (a CIDR's network part) falls in a banned network. The
/// explicit 0.0.0.0/8 check is needed because `is_unspecified` covers only
/// exactly 0.0.0.0.
fn banned(net: &str) -> bool {
    net.parse::<std::net::IpAddr>()
        .map(|addr| banned_ip(&addr))
        .unwrap_or(false)
}

fn banned_ip(ip: &std::net::IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.octets()[0] == 0,
        std::net::IpAddr::V6(v6) => {
            // ULA is fc00::/7 = first segment 0xfc00..=0xfdff.
            v6.is_unicast_link_local() || matches!(v6.segments()[0], 0xfc00..=0xfdff)
        }
    }
}

/// One concurrent SSE stream per app slot; the slot is held by the returned
/// stream for the connection's lifetime, so a dropped connection frees it.
async fn events(
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let Some(_slot) = try_acquire_sse_slot(&state.sse_connections) else {
        return Err(ApiError::too_many("too many open event streams"));
    };
    // A client connecting after the run ended gets its terminal event once:
    // the broadcast tail would replay the whole finished run (terminal
    // included), so the replay REPLACES the live stream instead of chaining
    // onto it, keeping the terminal exactly-once per run. A run in progress
    // (or starting) streams live with no replay.
    let replay = if state.controller.is_running() {
        None
    } else {
        state
            .last_terminal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .filter(|(epoch, _)| *epoch == state.run_epoch.load(Ordering::SeqCst))
            .map(|(_, ev)| ev)
    };
    let stream: Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> = match replay {
        Some(ev) => Box::pin(tokio_stream::once((_slot, ev)).map(|(slot, event)| {
            let _ = &slot;
            Ok(map_event(event).unwrap_or_default())
        })),
        None => Box::pin(
            BroadcastStream::new(state.controller.subscribe())
                .take_while(|item| item.is_ok())
                .filter_map(move |event| {
                    let _ = &_slot;
                    match event {
                        Ok(ev) => map_event(ev).map(Ok),
                        // A Lagged receiver has irrecoverably lost events;
                        // take_while above ends the stream on the first one.
                        Err(_lagged) => None,
                    }
                }),
        ),
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Maps an engine-domain event onto the SSE wire shape; None when the
/// payload cannot serialize (never expected; the live path drops silently).
fn map_event(ev: ScanEvent) -> Option<Event> {
    match ev {
        ScanEvent::Progress(p) => Event::default().event("progress").json_data(p).ok(),
        ScanEvent::Result(v) => Event::default().event("result").json_data(*v).ok(),
        ScanEvent::Finished(s) => Event::default().event("finished").json_data(s).ok(),
        ScanEvent::Phase2Progress(p) => Event::default().event("phase2-progress").json_data(p).ok(),
        ScanEvent::Failed(msg) => Event::default().event("failed").json_data(msg).ok(),
    }
}

/// RAII SSE slot: acquire bumps the counter, drop releases it. The caller
/// moves the guard into the event stream so release happens when the
/// connection dies, not when the handler returns.
fn try_acquire_sse_slot(total: &Arc<AtomicUsize>) -> Option<SseSlot> {
    if total.fetch_add(1, Ordering::SeqCst) >= MAX_SSE_CONNECTIONS {
        total.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(SseSlot(Arc::clone(total)))
}

struct SseSlot(Arc<AtomicUsize>);

impl Drop for SseSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Serialize)]
struct ResultsPayload {
    results: Vec<Verdict>,
    summary: Option<ScanSummary>,
}

async fn results(State(state): State<Arc<AppState>>) -> Json<ResultsPayload> {
    Json(ResultsPayload {
        results: state.controller.results(),
        summary: state.controller.summary(),
    })
}

async fn cancel(State(state): State<Arc<AppState>>) -> StatusCode {
    state.controller.cancel();
    StatusCode::NO_CONTENT
}

async fn reset(State(state): State<Arc<AppState>>) -> StatusCode {
    state.controller.reset();
    StatusCode::NO_CONTENT
}

/// `POST /api/warp/register` body: the optional WARP+ license key; null or
/// missing means a free account. `overwrite: true` is required to replace an
/// identity that is already persisted (a first registration never needs it).
#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    overwrite: Option<bool>,
}

#[derive(Serialize)]
struct RegisterResponse {
    wgconf: String,
}

/// Production registrar: the Cloudflare flow has its own per-attempt timeout
/// and retries (warpgen); the captured runtime handle lets the handler push
/// it onto a blocking thread.
fn default_registrar() -> WarpRegistrar {
    let handle = tokio::runtime::Handle::current();
    Arc::new(move |license| handle.block_on(warpgen::register(license.as_deref())))
}

/// Opt-in WARP registration (review Domain 2): registers a fresh identity
/// with Cloudflare and returns the rendered wgconf. The UI contract is
/// `{"license": <string|null>} -> {"wgconf": "..."}`. The network flow can
/// take up to ~45 s (3 attempts x 15 s), so it runs on a blocking thread;
/// failures answer the uniform error envelope.
async fn warp_register(
    State(state): State<Arc<AppState>>,
    JsonBody(req): JsonBody<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    // Refuse to silently clobber an existing identity; the caller must
    // explicitly opt in (first-time registration has no identity → proceeds).
    if crate::warpgen::has_identity() && !req.overwrite.unwrap_or(false) {
        return Err(ApiError::conflict(
            "identity already registered; pass {\"overwrite\":true} to replace it",
        ));
    }
    // Check-and-set before doing any work: the limit counts every attempt
    // that gets past the overwrite guard (the guard rejection above does
    // not consume the budget).
    {
        let mut last = state
            .last_register
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_some_and(|at| at.elapsed() < REGISTER_COOLDOWN) {
            return Err(ApiError::too_many(
                "registration is rate-limited to one attempt per 60 s",
            ));
        }
        *last = Some(Instant::now());
    }
    let license = req
        .license
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty());
    let registrar = Arc::clone(&state.warp_register);
    let wgconf = tokio::task::spawn_blocking(move || registrar(license))
        .await
        .map_err(|_| ApiError::internal("registration task panicked"))?
        .map_err(|err| {
            ApiError::bad_gateway(format!(
                "registration failed: {}",
                crate::configs::sanitize_error_text(&format!("{err:#}"))
            ))
        })?;
    Ok(Json(RegisterResponse { wgconf }))
}

/// `POST /api/config/export` body: one of the user's ORIGINAL config URIs as
/// submitted to the scan, plus the verified candidate's dial endpoint. Never
/// touches the engine — pure parse/render over the submitted URI.
#[derive(Deserialize)]
struct ExportConfigRequest {
    config: String,
    ip: String,
    port: u16,
    #[serde(default)]
    sni: Option<String>,
}

#[derive(Serialize)]
struct ExportConfigResponse {
    uri: String,
}

/// Renders a verified candidate as a ready-to-use vless/trojan URI the user
/// can drop straight into v2rayN/Hiddify. The candidate IP/port replace the
/// config's original server; the id, security, SNI, fingerprint and ws
/// settings are preserved. Failures (unparseable config, unsupported
/// protocol, oversized SNI) answer the uniform ApiError envelope with
/// redacted messages.
async fn export_config(
    JsonBody(req): JsonBody<ExportConfigRequest>,
) -> Result<Json<ExportConfigResponse>, ApiError> {
    let ip: Ipv4Addr = req
        .ip
        .parse()
        .map_err(|_| ApiError::bad_request("ip must be an IPv4 address"))?;
    if req.port == 0 {
        return Err(ApiError::bad_request("port must be in 1..=65535"));
    }
    if req
        .sni
        .as_ref()
        .is_some_and(|s| s.len() > crate::api::types::MAX_SNI_BYTES)
    {
        return Err(ApiError::bad_request(format!(
            "sni must be at most {} bytes",
            crate::api::types::MAX_SNI_BYTES
        )));
    }
    if let Some(sni) = &req.sni {
        crate::api::types::validate_sni(sni).map_err(ApiError::bad_request)?;
    }
    let uri = crate::configs::export_config_uri(&req.config, ip, req.port, req.sni.as_deref())
        .map_err(|err| {
            ApiError::bad_request(crate::configs::sanitize_error_text(&format!("{err:#}")))
        })?;
    Ok(Json(ExportConfigResponse { uri }))
}

#[derive(Serialize)]
struct StatusPayload {
    version: &'static str,
    is_running: bool,
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusPayload> {
    Json(StatusPayload {
        version: env!("CARGO_PKG_VERSION"),
        is_running: state.controller.is_running(),
    })
}

#[derive(Serialize)]
struct XrayStatusPayload {
    found: bool,
    path: Option<String>,
    data_dir: String,
    version: &'static str,
}

async fn xray_status() -> Json<XrayStatusPayload> {
    let found = xray::find_binary();
    let data_dir = paths::data_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    Json(XrayStatusPayload {
        found: found.is_some(),
        path: found.map(|p| p.display().to_string()),
        data_dir,
        version: xray::VERSION.trim(),
    })
}

#[derive(Serialize)]
struct XrayDownloadResponse {
    success: bool,
    path: Option<String>,
    error: Option<String>,
}

async fn xray_download() -> Json<XrayDownloadResponse> {
    match xray::ensure_binary(&xray::RealFetch).await {
        Ok(path) => Json(XrayDownloadResponse {
            success: true,
            path: Some(path.display().to_string()),
            error: None,
        }),
        Err(err) => Json(XrayDownloadResponse {
            success: false,
            path: None,
            error: Some(format!("{err:#}")),
        }),
    }
}

#[derive(Serialize)]
struct RangesPayload {
    host_count: u64,
    /// RFC3339 UTC of the last successful refresh (or the embedded-list load
    /// time); None before anything has been loaded.
    last_updated: Option<String>,
}

async fn ranges(State(state): State<Arc<AppState>>) -> Json<RangesPayload> {
    let inner = state
        .ranges
        .inner
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Json(RangesPayload {
        host_count: inner.pool.host_count().min(u64::MAX as u128) as u64,
        last_updated: inner.last_updated.clone(),
    })
}

/// Session-lifetime profiles in name order (inert data; the UI decides how to
/// load them into the scan form).
async fn list_profiles(State(state): State<Arc<AppState>>) -> Json<Vec<ProfilePayload>> {
    let profiles = state.profiles.read().await;
    let mut out: Vec<ProfilePayload> = profiles
        .iter()
        .map(|(name, config)| ProfilePayload {
            name: name.clone(),
            config: config.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Json(out)
}

fn sanitize_config(mut cfg: ScanConfig) -> ScanConfig {
    // Profiles must never carry WARP key material (review Domain 7): the
    // wgconf is stripped on the way in and the verification flag that depends
    // on it is cleared, so stored/returned profiles stay valid. The scan path
    // (POST /api/scan) still accepts wgconf-bearing configs.
    if let Some(warp) = &mut cfg.warp {
        if warp.wgconf.take().is_some() {
            warp.verify_with_wgconf = false;
        }
    }
    cfg
}

/// Upsert: 201 when the name is new, 200 when it replaces an existing
/// profile; the body is always the stored profile. New names are rejected
/// with 413 once MAX_PROFILES is reached; updating an existing name stays
/// allowed. The check and insert share the write lock, so concurrent PUTs
/// cannot exceed the cap.
async fn put_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    JsonBody(cfg): JsonBody<ScanConfig>,
) -> Result<(StatusCode, Json<ProfilePayload>), ApiError> {
    validate_profile_name(&name).map_err(ApiError::bad_request)?;
    cfg.validate().map_err(ApiError::bad_request)?;
    let cfg = sanitize_config(cfg);
    let mut profiles = state.profiles.write().await;
    if !profiles.contains_key(&name) && profiles.len() >= MAX_PROFILES {
        return Err(ApiError::payload_too_large(format!(
            "profile limit reached ({MAX_PROFILES} max)"
        )));
    }
    let created = profiles.insert(name.clone(), cfg.clone()).is_none();
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let snapshot = profiles.clone();
    drop(profiles);
    persist_profiles(&state.profiles_dir, &snapshot).await;
    Ok((status, Json(ProfilePayload { name, config: cfg })))
}

async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_profile_name(&name).map_err(ApiError::bad_request)?;
    let (removed, snapshot) = {
        let mut profiles = state.profiles.write().await;
        let removed = profiles.remove(&name).is_some();
        (removed, profiles.clone())
    };
    if removed {
        persist_profiles(&state.profiles_dir, &snapshot).await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "profile {name:?} does not exist"
        )))
    }
}

/// One stored profile, or 404. The UI loads a saved profile by name.
async fn get_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProfilePayload>, ApiError> {
    validate_profile_name(&name).map_err(ApiError::bad_request)?;
    let cfg = state.profiles.read().await.get(&name).cloned();
    match cfg {
        Some(cfg) => Ok(Json(ProfilePayload { name, config: cfg })),
        None => Err(ApiError::not_found(format!(
            "profile {name:?} does not exist"
        ))),
    }
}

fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("profile name must not be empty".to_owned());
    }
    if name.chars().count() > 64 {
        return Err("profile name must be at most 64 characters".to_owned());
    }
    if name.chars().any(char::is_control) {
        return Err("profile name must not contain control characters".to_owned());
    }
    if name.contains('/') {
        return Err("profile name must not contain '/'".to_owned());
    }
    Ok(())
}

async fn index() -> impl IntoResponse {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("content-security-policy", SECURITY_CSP.parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    (headers, Html(EMBEDDED_INDEX))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

impl ApiError {
    fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn method_not_allowed(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn too_many(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.status.canonical_reason().unwrap_or("Error").to_owned(),
            message: self.message,
        });
        (self.status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::api::types::{DEFAULT_WARP_PORTS, MAX_STOP_VALUE};
    use crate::api::types::{Mode, Phase2Config, ScanTarget, StopCondition, WarpConfig};
    use crate::probe::FakeTransport;
    use crate::ranges::BUNDLED_RANGES;
    use base64::Engine as _;

    const OFFICIAL_FIXTURE: &str =
        r#"{"success":true,"result":{"ipv4_cidrs":["10.1.0.0/16"]},"errors":[]}"#;

    struct FakeHttp(&'static str);

    impl HttpGet for FakeHttp {
        fn get<'a>(&'a self, _url: &'a str) -> ranges::HttpFuture<'a> {
            Box::pin(async move { Ok(self.0.to_owned()) })
        }
    }

    struct FailingHttp;

    impl HttpGet for FailingHttp {
        fn get<'a>(&'a self, _url: &'a str) -> ranges::HttpFuture<'a> {
            Box::pin(async { Err(anyhow::anyhow!("network down")) })
        }
    }

    fn cfg(count: u32, found: u32) -> ScanConfig {
        ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Count(count),
            stop: StopCondition { found, cap: None },
            // Explicit pool input keeps tests off the filesystem ranges.
            custom_cidrs: vec!["203.0.113.0/29".to_owned()],
            ports: vec![443],
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

    /// Spawns the router on an ephemeral port with a scripted transport and
    /// returns its address. Ranges are the bundled list with no timestamp.
    async fn serve(t: FakeTransport) -> SocketAddr {
        serve_with_ranges(t, RangesState::load_text(BUNDLED_RANGES, None)).await
    }

    async fn serve_with_ranges(t: FakeTransport, ranges: Arc<RangesState>) -> SocketAddr {
        serve_with_registrar(t, ranges, canned_registrar()).await
    }

    async fn serve_with_registrar(
        t: FakeTransport,
        ranges: Arc<RangesState>,
        registrar: WarpRegistrar,
    ) -> SocketAddr {
        serve_with_dir(t, ranges, registrar, unique_test_profiles_dir()).await
    }

    async fn serve_with_dir(
        t: FakeTransport,
        ranges: Arc<RangesState>,
        registrar: WarpRegistrar,
        profiles_dir: PathBuf,
    ) -> SocketAddr {
        let controller = Arc::new(ScanController::new(Arc::new(t)));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router_with_dir(controller, ranges, registrar, profiles_dir),
            )
            .await
            .unwrap();
        });
        addr
    }

    /// Registration fakes never touch the network.
    fn canned_registrar() -> WarpRegistrar {
        Arc::new(|_| Ok("fake-wgconf".to_owned()))
    }

    fn failing_registrar() -> WarpRegistrar {
        Arc::new(|_| Err(anyhow::anyhow!("upstream unreachable")))
    }

    /// Points `CF_SCANNER_DATA_DIR` at a throwaway dir and returns a guard
    /// that removes any identity file when dropped. Serialized against
    /// warpgen's identity tests (which flip the same process-global
    /// variable), so no register test ever reads another test's identity —
    /// or a real user's.
    fn isolate_identity_dir() -> impl Drop {
        let guard = crate::warpgen::tests::IDENTITY_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
        unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        struct Cleanup {
            _guard: std::sync::MutexGuard<'static, ()>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
                let _ = fs::remove_file(dir.join("identity.json"));
            }
        }
        Cleanup { _guard: guard }
    }

    /// Registrar that persists a minimal identity file on success, as the
    /// real warpgen register flow does, so the overwrite guard sees it.
    fn identity_persisting_registrar() -> WarpRegistrar {
        let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
        Arc::new(move |_| {
            fs::write(
                dir.join("identity.json"),
                r#"{"id":"t","token":"t","private_key":"aGFo","client_id":"c","account_type":"free","created_at":0}"#,
            )
            .unwrap();
            Ok("fake-wgconf".to_owned())
        })
    }

    /// Records the license each call received; returns the canned wgconf.
    fn recording_registrar(wgconf: &'static str) -> (WarpRegistrar, Arc<Mutex<Option<String>>>) {
        let seen = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&seen);
        let registrar: WarpRegistrar = Arc::new(move |license| {
            *capture.lock().unwrap() = license;
            Ok(wgconf.to_owned())
        });
        (registrar, seen)
    }

    /// Raw HTTP/1.1 over a throwaway TCP connection. Reads until EOF or
    /// `until` (for endless streams like SSE) or a 2 s deadline, and returns
    /// the status code plus what was read. The write half is NOT shutdown:
    /// hyper closes the connection without responding when the client FINs
    /// immediately after the request.
    async fn request(addr: SocketAddr, req: &str, until: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![];
        let mut chunk = [0u8; 4096];
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        loop {
            if until.is_some_and(|needle| String::from_utf8_lossy(&buf).contains(needle)) {
                break;
            }
            tokio::select! {
                _ = &mut deadline => break,
                read = stream.read(&mut chunk) => match read {
                    Ok(0) => break, // EOF
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                },
            }
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        (
            text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0),
            text,
        )
    }

    async fn post_scan(addr: SocketAddr, body: &str) -> u16 {
        post_scan_full(addr, body).await.0
    }

    /// POST /api/scan returning the status AND the raw response text, so
    /// tests can assert on the error envelope's message.
    async fn post_scan_full(addr: SocketAddr, body: &str) -> (u16, String) {
        let req = format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await
    }

    async fn get_profiles(addr: SocketAddr) -> (u16, String) {
        request(
            addr,
            "GET /api/profiles HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await
    }

    /// Response body without the HTTP header block.
    fn response_body(text: &str) -> &str {
        text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(text)
    }

    async fn put_profile(addr: SocketAddr, name: &str, body: &str) -> (u16, String) {
        let req = format!(
            "PUT /api/profiles/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            name,
            body.len(),
            body
        );
        request(addr, &req, None).await
    }

    async fn delete_profile(addr: SocketAddr, name: &str) -> (u16, String) {
        let req = format!(
            "DELETE /api/profiles/{name} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        request(addr, &req, None).await
    }

    async fn post_register(addr: SocketAddr, body: &str) -> (u16, String) {
        let req = format!(
            "POST /api/warp/register HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await
    }

    /// Scripts every host of the /29 so count-sampled runs are deterministic
    /// regardless of which hosts the seeded RNG draws.
    fn script_all_hosts(t: &FakeTransport, latency: u32) {
        for i in 0..8u8 {
            t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(latency));
        }
    }

    #[tokio::test]
    async fn serves_index_html() {
        let addr = serve(FakeTransport::new()).await;
        let (status, body) = request(
            addr,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("CF-Scanner"));
    }

    #[tokio::test]
    async fn index_carries_hardened_security_headers() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        let headers = text.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or("");
        let lower = headers.to_ascii_lowercase();
        assert!(
            lower.contains("referrer-policy: no-referrer"),
            "missing Referrer-Policy: {headers}"
        );
        assert!(
            lower.contains("x-content-type-options: nosniff"),
            "missing nosniff: {headers}"
        );
        let csp = headers
            .lines()
            .find(|l| {
                l.to_ascii_lowercase()
                    .starts_with("content-security-policy")
            })
            .expect("CSP header present");
        for directive in [
            "form-action 'self'",
            "script-src-attr 'none'",
            "base-uri 'self'",
            "object-src 'none'",
            "script-src 'unsafe-inline'",
            "style-src 'unsafe-inline'",
        ] {
            assert!(csp.contains(directive), "CSP missing {directive}: {csp}");
        }
    }

    #[tokio::test]
    async fn api_responses_carry_security_headers() {
        // "ideally all responses": the middleware adds the safe defaults to
        // API payloads and SSE too, not just the HTML page.
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        let headers = text.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or("");
        let lower = headers.to_ascii_lowercase();
        assert!(
            lower.contains("referrer-policy: no-referrer"),
            "missing Referrer-Policy: {headers}"
        );
        assert!(
            lower.contains("x-content-type-options: nosniff"),
            "missing nosniff: {headers}"
        );
    }

    #[tokio::test]
    async fn rejects_invalid_scan_config() {
        let addr = serve(FakeTransport::new()).await;
        let body = r#"{"mode":"Cdn","target":{"Preset":"Quick"},"ports":[0],"stop":{"found":1,"cap":null},"exclude":[],"custom_cidrs":[],"concurrency":1,"timeout_ms":3000,"phase2":null,"warp":null}"#;
        let status = post_scan(addr, body).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn accepts_include_v6_scan_config() {
        let addr = serve(FakeTransport::new()).await;
        let mut c = cfg(1, 1);
        c.include_v6 = true;
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202
        );
    }

    #[tokio::test]
    async fn scan_config_without_include_v6_field_still_posts() {
        // The field is serde-defaulted so older clients keep working.
        let addr = serve(FakeTransport::new()).await;
        let c = cfg(1, 1);
        let mut json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"include_v6\":false"), "{json}");
        json = json.replacen("\"include_v6\":false,", "", 1);
        assert!(!json.contains("include_v6"), "{json}");
        assert_eq!(post_scan(addr, &json).await, 202);
    }

    #[tokio::test]
    async fn scan_results_and_summary_roundtrip() {
        let t = FakeTransport::new();
        script_all_hosts(&t, 25);
        let addr = serve(t).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(post_scan(addr, &body).await, 202);

        // The scan runs in a background task; poll until it finishes.
        let results_body = async {
            for _ in 0..50 {
                let (status, text) = request(
                    addr,
                    "GET /api/results HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    None,
                )
                .await;
                if status == 200 && text.contains("\"latency_ms\":25") {
                    return text;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("scan did not produce results in time");
        }
        .await;
        assert!(results_body.contains("\"found\":1"), "{results_body}");
        assert!(results_body.contains("\"summary\""));
    }

    #[tokio::test]
    async fn events_stream_emits_progress_and_finished() {
        // Every host probes slowly so the run outlives the SSE subscription
        // attach window (no fixed sleeps: fast machines would flake).
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr = serve(t).await;
        let events = tokio::spawn(request(
            addr,
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Some("event: finished"),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let body = cfg(1, 1);
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
            202
        );
        let (_, text) = events.await.unwrap();
        assert!(text.contains("event: progress"), "{text}");
        assert!(text.contains("event: result"), "{text}");
        assert!(text.contains("event: finished"), "{text}");
    }

    /// Polls /api/status until the spawned run task has reached the running
    /// guard (replaces fixed sleeps that flake on slow machines).
    async fn wait_until_running(addr: SocketAddr) {
        for _ in 0..200 {
            let (status, text) = request(
                addr,
                "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                None,
            )
            .await;
            if status == 200 && text.contains("\"is_running\":true") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("scan did not reach the running guard in time");
    }

    /// Polls /api/status until the spawned run task has fully finished
    /// (running flag cleared), then one more beat so the terminal-event
    /// store — which lands microseconds after the flag clears — is visible
    /// to a replaying connection.
    async fn wait_until_idle(addr: SocketAddr) {
        for _ in 0..200 {
            let (status, text) = request(
                addr,
                "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                None,
            )
            .await;
            if status == 200 && text.contains("\"is_running\":false") {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("scan did not finish in time");
    }

    #[tokio::test]
    async fn events_replay_the_terminal_of_the_latest_finished_run() {
        // Fast hosts: the run ends quickly and the terminal store lands
        // right after the running flag clears.
        let t = FakeTransport::new();
        for i in 0..8u8 {
            t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(10));
        }
        let addr = serve(t).await;
        let body = cfg(1, 1);
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
            202
        );
        wait_until_idle(addr).await;
        // A connection after the run ended replays exactly one terminal
        // event (not the whole finished-run tail).
        let (status, text) = request(
            addr,
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Some("event: finished"),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(text.matches("event: finished").count(), 1, "{text}");
    }

    #[tokio::test]
    async fn second_scan_while_running_is_conflict() {
        // All /29 hosts probe slowly so the count-sampled plan keeps the run
        // alive while the second POST arrives.
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr = serve(t).await;
        let body = cfg(1, 1);
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
            202
        );
        wait_until_running(addr).await;
        let body = cfg(1, 1);
        let status = post_scan(addr, &serde_json::to_string(&body).unwrap()).await;
        assert_eq!(status, 409);
    }

    #[tokio::test]
    async fn cancel_and_reset_are_noops_without_scan() {
        let addr = serve(FakeTransport::new()).await;
        let (status, _) = request(addr, "POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", None).await;
        assert_eq!(status, 204);
        let (status, _) = request(addr, "POST /api/reset HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", None).await;
        assert_eq!(status, 204);
    }

    async fn get_ranges(addr: SocketAddr) -> (u16, String) {
        request(
            addr,
            "GET /api/ranges HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await
    }

    /// The JSON body after the HTTP header block.
    fn json_body(text: &str) -> &str {
        text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(text)
    }

    #[tokio::test]
    async fn ranges_endpoint_reports_bundled_pool() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(text.contains("\"host_count\":"));
        assert!(text.contains("\"last_updated\":null"), "{text}");
    }

    #[tokio::test]
    async fn ranges_endpoint_reports_last_updated() {
        let ranges = RangesState::load_text(BUNDLED_RANGES, Some("2026-08-13T12:34:56Z"));
        let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(
            text.contains("\"last_updated\":\"2026-08-13T12:34:56Z\""),
            "{text}"
        );
    }

    #[tokio::test]
    async fn profiles_list_starts_empty() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        assert_eq!(response_body(&text).trim(), "[]", "{text}");
    }

    #[tokio::test]
    async fn put_creates_profile_with_201() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let (status, text) = put_profile(addr, "quick", &body).await;
        assert_eq!(status, 201, "{text}");
        assert!(text.contains("\"name\":\"quick\""), "{text}");
        assert!(text.contains("\"mode\":\"Cdn\""), "{text}");
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        assert!(text.contains("\"name\":\"quick\""), "{text}");
    }

    #[tokio::test]
    async fn put_upserts_existing_profile_with_200() {
        let addr = serve(FakeTransport::new()).await;
        let first = serde_json::to_string(&cfg(1, 1)).unwrap();
        let second = serde_json::to_string(&cfg(2, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &first).await.0, 201);
        let (status, text) = put_profile(addr, "quick", &second).await;
        assert_eq!(status, 200, "{text}");
        assert!(text.contains("\"Count\":2"), "{text}");
        let (_, text) = get_profiles(addr).await;
        assert!(text.contains("\"Count\":2"), "{text}");
    }

    #[tokio::test]
    async fn delete_removes_profile_then_404s() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &body).await.0, 201);
        let (status, _) = delete_profile(addr, "quick").await;
        assert_eq!(status, 204);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(response_body(&text).trim(), "[]", "{text}");
        let (status, _) = delete_profile(addr, "quick").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn get_single_profile_returns_stored_config_then_404s() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(7, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &body).await.0, 201);
        let req =
            "GET /api/profiles/quick HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, text) = request(addr, req, None).await;
        assert_eq!(status, 200, "{text}");
        assert!(text.contains("\"name\":\"quick\""), "{text}");
        assert!(text.contains("\"Count\":7"), "{text}");
        let req = "GET /api/profiles/nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, _) = request(addr, req, None).await;
        assert_eq!(status, 404);
    }
    #[tokio::test]
    async fn put_rejects_invalid_config() {
        let addr = serve(FakeTransport::new()).await;
        let mut bad = cfg(1, 1);
        bad.ports = vec![0];
        let body = serde_json::to_string(&bad).unwrap();
        let (status, _) = put_profile(addr, "quick", &body).await;
        assert_eq!(status, 400);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(
            response_body(&text).trim(),
            "[]",
            "invalid config must not be stored"
        );
    }

    #[tokio::test]
    async fn background_refresh_populates_last_updated() {
        let ranges = RangesState::load_text("203.0.113.0/24", None);
        ranges.spawn_refresh(
            Some(Duration::from_millis(20)),
            Arc::new(FakeHttp(OFFICIAL_FIXTURE)),
        );
        let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
        for _ in 0..50 {
            let (status, text) = get_ranges(addr).await;
            if status == 200 {
                let payload: serde_json::Value =
                    serde_json::from_str(json_body(&text)).expect("ranges payload JSON");
                if let Some(ts) = payload["last_updated"].as_str() {
                    assert!(ts.ends_with('Z'), "{ts}");
                    // host_count should be > 0 after refresh
                    assert!(payload["host_count"].as_u64().unwrap_or(0) > 0);
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("background refresh did not update the ranges payload");
    }

    #[tokio::test]
    async fn background_refresh_failure_keeps_last_good_data() {
        let ranges = RangesState::load_text("203.0.113.0/24", Some("2026-01-01T00:00:00Z"));
        ranges.spawn_refresh(Some(Duration::from_millis(20)), Arc::new(FailingHttp));
        let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
        // Let several failed cycles elapse; the state must not move.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(
            text.contains("\"last_updated\":\"2026-01-01T00:00:00Z\""),
            "{text}"
        );
    }

    #[tokio::test]
    async fn put_rejects_invalid_names() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        // 65 characters.
        let long = "a".repeat(65);
        assert_eq!(put_profile(addr, &long, &body).await.0, 400);
        // Percent-encoded control character.
        assert_eq!(put_profile(addr, "bad%01name", &body).await.0, 400);
        // Percent-encoded slash would make the name unroutable.
        assert_eq!(put_profile(addr, "a%2Fb", &body).await.0, 400);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(
            response_body(&text).trim(),
            "[]",
            "invalid names must not be stored"
        );
    }

    #[test]
    fn profile_name_validation() {
        assert!(validate_profile_name("quick").is_ok());
        assert!(validate_profile_name(&"a".repeat(64)).is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
        assert!(validate_profile_name("has\tcontrol").is_err());
        assert!(validate_profile_name("a/b").is_err());
    }

    #[tokio::test]
    async fn concurrent_profile_access_is_safe() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let mut writers = Vec::new();
        for i in 0..50 {
            let body = body.clone();
            writers.push(tokio::spawn(async move {
                let name = format!("profile-{i:02}");
                let (status, _) = put_profile(addr, &name, &body).await;
                assert_eq!(status, 201);
            }));
        }
        let reader = tokio::spawn(async move {
            for _ in 0..20 {
                let (status, text) = get_profiles(addr).await;
                assert_eq!(status, 200);
                let parsed: Vec<serde_json::Value> =
                    serde_json::from_str(response_body(&text)).unwrap();
                assert!(parsed.len() <= 50, "{text}");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        for writer in writers {
            writer.await.unwrap();
        }
        reader.await.unwrap();
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(response_body(&text)).unwrap();
        assert_eq!(parsed.len(), 50, "{text}");
        for i in 0..50 {
            let name = format!("profile-{i:02}");
            assert!(
                parsed.iter().any(|p| p["name"] == name),
                "missing {name}: {text}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_foreign_host_header() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403, "{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
        assert_eq!(parsed["error"], "Forbidden");
    }

    #[tokio::test]
    async fn accepts_localhost_with_port_and_ipv6_host() {
        let addr = serve(FakeTransport::new()).await;
        for host in ["localhost:8765", "[::1]:8765", "127.0.0.1:1"] {
            let (status, _) = request(
                addr,
                &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                None,
            )
            .await;
            assert_eq!(status, 200, "host {host:?} must be allowed");
        }
    }

    #[tokio::test]
    async fn rejects_foreign_origin() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403, "{text}");
    }

    #[tokio::test]
    async fn rejects_cross_site_fetch() {
        let addr = serve(FakeTransport::new()).await;
        let (status, _) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn rejects_missing_host_header() {
        let addr = serve(FakeTransport::new()).await;
        let (status, _) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn malformed_json_gets_uniform_error_envelope() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{nojson",
            None,
        )
        .await;
        assert_eq!(status, 400, "{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
        assert_eq!(parsed["error"], "Bad Request");
        assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[tokio::test]
    async fn phase2_file_paths_are_rejected_over_http() {
        let addr = serve(FakeTransport::new()).await;
        let mut c = cfg(1, 1);
        c.phase2 = Some(Phase2Config {
            configs: vec!["C:\\secret\\config.json".to_owned()],
            ..Phase2Config::default()
        });
        let status = post_scan(addr, &serde_json::to_string(&c).unwrap()).await;
        assert_eq!(status, 400);
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            ..Phase2Config::default()
        });
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202
        );
    }

    #[tokio::test]
    async fn concurrent_scan_starts_do_not_double_spawn() {
        // Two POSTs racing each other must yield exactly one running scan
        // (one 202, one 409), never two accepted runs.
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr = serve(t).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let a = tokio::spawn(async move {
            let req = format!(
                "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            request(addr, &req, None).await.0
        });
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let b = tokio::spawn(async move {
            let req = format!(
                "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            request(addr, &req, None).await.0
        });
        let (sa, sb) = (a.await.unwrap(), b.await.unwrap());
        let mut codes = [sa, sb];
        codes.sort_unstable();
        assert_eq!(codes, [202, 409], "one scan must win, one must 409");
    }

    #[tokio::test]
    async fn sse_connection_cap_rejects_fifth_stream() {
        // The four connections must be held open concurrently: each request
        // reads until its own deadline, so a sequential loop would let slots
        // free up before the fifth attempt.
        let addr = serve(FakeTransport::new()).await;
        let req = "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let mut streams = Vec::new();
        for _ in 0..MAX_SSE_CONNECTIONS {
            streams.push(tokio::spawn(request(addr, req, None)));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, _) = request(addr, req, None).await;
        assert_eq!(status, 429);
        for stream in streams {
            stream.abort();
        }
    }

    #[tokio::test]
    async fn profiles_persist_across_servers() {
        // Two server instances sharing one profiles dir simulate a restart:
        // the second must reload what the first stored.
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-server-persist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let addr = serve_with_dir(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            canned_registrar(),
            dir.clone(),
        )
        .await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &body).await.0, 201);
        let addr2 = serve_with_dir(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            canned_registrar(),
            dir.clone(),
        )
        .await;
        let (status, text) = get_profiles(addr2).await;
        assert_eq!(status, 200);
        assert!(text.contains("\"name\":\"quick\""), "{text}");
        let on_disk = fs::read_to_string(dir.join(PROFILES_FILE)).expect("profiles.json exists");
        assert!(on_disk.contains("\"quick\""), "{on_disk}");
        assert!(on_disk.contains("\"mode\": \"Cdn\""), "{on_disk}");
    }

    #[tokio::test]
    async fn persisted_profiles_are_masked() {
        // Key material must not survive the round trip to disk.
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-server-mask-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let addr = serve_with_dir(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            canned_registrar(),
            dir.clone(),
        )
        .await;
        let mut c = cfg(1, 1);
        c.mode = crate::api::types::Mode::Warp;
        c.custom_cidrs = vec![]; // CDN-only; WARP takes custom_endpoints
        c.warp = Some(crate::api::types::WarpConfig {
            wgconf: Some(
                "PrivateKey = SECRETKEY123\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = kkk\nAllowedIPs = 0.0.0.0/0"
                    .to_owned(),
            ),
            verify_with_wgconf: true,
            ..Default::default()
        });
        let body = serde_json::to_string(&c).unwrap();
        assert_eq!(put_profile(addr, "warpy", &body).await.0, 201);
        let on_disk = fs::read_to_string(dir.join(PROFILES_FILE)).expect("profiles.json exists");
        assert!(!on_disk.contains("SECRETKEY123"), "{on_disk}");
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        assert!(!text.contains("SECRETKEY123"), "{text}");
    }

    #[tokio::test]
    async fn warp_register_with_null_license_returns_wgconf() {
        let _isolated = isolate_identity_dir();
        let (registrar, seen) = recording_registrar("fake-wgconf-text");
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            registrar,
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(json_body(&text), r#"{"wgconf":"fake-wgconf-text"}"#);
        assert_eq!(*seen.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn warp_register_forwards_the_license_string() {
        let _isolated = isolate_identity_dir();
        let (registrar, seen) = recording_registrar("fake-wgconf-text");
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            registrar,
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":"WARP-PLUS-ABC"}"#).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("WARP-PLUS-ABC"));
    }

    #[tokio::test]
    async fn warp_register_absent_or_blank_license_is_none() {
        let _isolated = isolate_identity_dir();
        let (registrar, seen) = recording_registrar("fake-wgconf-text");
        for body in [
            r#"{}"#,
            r#"{"license":null}"#,
            r#"{"license":""}"#,
            r#"{"license":"   "}"#,
        ] {
            // A fresh app state per attempt: the 60 s registration cooldown
            // would 429 a second POST on the same server.
            let addr = serve_with_registrar(
                FakeTransport::new(),
                RangesState::load_text(BUNDLED_RANGES, None),
                Arc::clone(&registrar),
            )
            .await;
            let (status, text) = post_register(addr, body).await;
            assert_eq!(status, 200, "{text}");
            assert_eq!(
                *seen.lock().unwrap(),
                None,
                "body {body} must pass license None"
            );
        }
    }

    #[tokio::test]
    async fn warp_register_failure_returns_uniform_envelope() {
        let _isolated = isolate_identity_dir();
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            failing_registrar(),
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 502, "{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
        assert_eq!(parsed["error"], "Bad Gateway");
        assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[tokio::test]
    async fn warp_register_malformed_body_gets_uniform_400() {
        let _isolated = isolate_identity_dir();
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            failing_registrar(),
        )
        .await;
        let (status, text) = post_register(addr, "{nope").await;
        assert_eq!(status, 400, "{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
        assert_eq!(parsed["error"], "Bad Request");
        assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[tokio::test]
    async fn register_is_rate_limited() {
        let _isolated = isolate_identity_dir();
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            canned_registrar(),
        )
        .await;
        let (status, _) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 200);
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 429, "{text}");
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["error"], "Too Many Requests");
    }

    #[tokio::test]
    async fn register_refuses_overwrite_without_consent() {
        let _isolated = isolate_identity_dir();
        // First registration on a fresh app state: no identity yet → 200.
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            identity_persisting_registrar(),
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 200, "{text}");
        // The persisted identity now exists: a plain re-register must 409...
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 409, "{text}");
        // ...and explicit consent replaces it (fresh app state: the 60 s
        // cooldown is per app state, not per identity).
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            canned_registrar(),
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null,"overwrite":true}"#).await;
        assert_eq!(status, 200, "{text}");
    }

    #[tokio::test]
    async fn scan_rejects_non_routable_custom_cidrs() {
        let addr = serve(FakeTransport::new()).await;
        for cidr in [
            "127.0.0.1/32",   // loopback
            "169.254.0.0/16", // link-local
            "0.0.0.0/8",      // unspecified block
            "10.0.0.0/8",     // RFC1918
            "172.16.0.0/12",  // RFC1918
            "192.168.1.0/24", // RFC1918
            "::1/128",        // loopback v6
            "::/128",         // unspecified v6
            "fc00::/7",       // ULA
            "fe80::/10",      // link-local v6
        ] {
            let mut c = cfg(1, 1);
            c.custom_cidrs = vec![cidr.to_owned()];
            let status = post_scan(addr, &serde_json::to_string(&c).unwrap()).await;
            assert_eq!(status, 400, "custom_cidrs {cidr} must be rejected");
        }
        // TEST-NET ranges stay routable over the API.
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
            202
        );
        // WARP endpoints: loopback rejected, TEST-NET accepted.
        let mut c = cfg(1, 1);
        c.mode = Mode::Warp;
        c.custom_cidrs = vec![];
        c.ports = vec![2408]; // WARP needs explicit ports (no defaulting)
        c.warp = Some(WarpConfig {
            custom_endpoints: vec!["127.0.0.1".to_owned()],
            ..WarpConfig::default()
        });
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            400
        );
        c.warp.as_mut().unwrap().custom_endpoints = vec!["203.0.113.1".to_owned()];
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202
        );
    }

    #[tokio::test]
    async fn scan_rejects_stop_values_above_the_frontend_cap() {
        let addr = serve(FakeTransport::new()).await;
        let mut c = cfg(1, 1);
        c.stop = StopCondition {
            found: MAX_STOP_VALUE + 1,
            cap: None,
        };
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            400,
            "found above the frontend cap must be rejected"
        );
        c.stop = StopCondition {
            found: 1,
            cap: Some(0),
        };
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            400,
            "cap 0 must be rejected"
        );
        c.stop = StopCondition {
            found: 1,
            cap: Some(MAX_STOP_VALUE),
        };
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202,
            "cap at the frontend limit must be accepted"
        );
    }

    #[tokio::test]
    async fn warp_scan_with_cdn_default_port_is_rejected_not_substituted() {
        // The review found the server silently rewrote ports [443] into
        // DEFAULT_WARP_PORTS; the contract now rejects it with a clear error.
        let addr = serve(FakeTransport::new()).await;
        let mut c = cfg(1, 1);
        c.mode = Mode::Warp;
        c.custom_cidrs = vec![];
        c.warp = Some(WarpConfig {
            custom_endpoints: vec!["203.0.113.1".to_owned()],
            ..Default::default()
        });
        let (status, text) = post_scan_full(addr, &serde_json::to_string(&c).unwrap()).await;
        assert_eq!(status, 400, "{text}");
        assert!(text.contains("explicit UDP ports"), "{text}");
        // A real WARP port list passes (the scan itself runs in the
        // background against real UDP timeouts; only the accept matters).
        c.ports = DEFAULT_WARP_PORTS.to_vec();
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202
        );
        // CDN keeps accepting the default port (fresh server: the WARP run
        // above is still probing real endpoints).
        let cdn = serve(FakeTransport::new()).await;
        assert_eq!(
            post_scan(cdn, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
            202
        );
    }

    #[tokio::test]
    async fn profile_cap_rejects_new_names_but_allows_updates() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        for i in 0..MAX_PROFILES {
            let (status, text) = put_profile(addr, &format!("p{i:02}"), &body).await;
            assert_eq!(status, 201, "{text}");
        }
        let (status, text) = put_profile(addr, "overflow", &body).await;
        assert_eq!(status, 413, "{text}");
        let parsed: serde_json::Value =
            serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
        assert_eq!(parsed["error"], "Payload Too Large");
        // Updates of existing names stay allowed at the cap.
        assert_eq!(put_profile(addr, "p00", &body).await.0, 200);
        let (_, text) = get_profiles(addr).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(response_body(&text)).unwrap();
        assert_eq!(parsed.len(), MAX_PROFILES, "{text}");
        assert!(!parsed.iter().any(|p| p["name"] == "overflow"), "{text}");
    }

    /// A valid WARP-mode config carrying wgconf key material, as the UI sends
    /// it before masking.
    fn warp_cfg_with_wgconf() -> ScanConfig {
        let mut c = cfg(1, 1);
        c.mode = Mode::Warp;
        c.custom_cidrs = vec![]; // CDN-only; WARP takes custom_endpoints
        c.ports = vec![2408];
        c.warp = Some(WarpConfig {
            custom_endpoints: vec!["203.0.113.1".to_owned()],
            wgconf: Some(
                "PrivateKey = TOP-SECRET-WG-KEY\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                    .to_owned(),
            ),
            verify_with_wgconf: true,
            ..WarpConfig::default()
        });
        c
    }

    #[tokio::test]
    async fn profiles_never_store_or_return_warp_wgconf() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&warp_cfg_with_wgconf()).unwrap();
        let (status, text) = put_profile(addr, "warp-verify", &body).await;
        assert_eq!(status, 201, "{text}");
        assert!(
            !text.contains("TOP-SECRET-WG-KEY"),
            "PUT response must not echo the wgconf: {text}"
        );
        assert!(text.contains("\"verify_with_wgconf\":false"), "{text}");
        let (_, text) = get_profiles(addr).await;
        assert!(
            !text.contains("TOP-SECRET-WG-KEY"),
            "profile list must not expose the wgconf: {text}"
        );
        let req = "GET /api/profiles/warp-verify HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, text) = request(addr, req, None).await;
        assert_eq!(status, 200, "{text}");
        assert!(
            !text.contains("TOP-SECRET-WG-KEY"),
            "single profile must not expose the wgconf: {text}"
        );
        // The stored profile is valid and loadable without the key.
        let parsed: serde_json::Value = serde_json::from_str(response_body(&text)).unwrap();
        let stored: ScanConfig = serde_json::from_value(parsed["config"].clone()).unwrap();
        assert_eq!(stored.validate(), Ok(()));
        assert_eq!(stored.warp.unwrap().wgconf, None);
    }

    #[tokio::test]
    async fn scan_path_still_accepts_wgconf_configs() {
        // Masking is profile-only: the engine's scan path keeps accepting
        // verification configs (review Domain 7: the real config stays in the
        // engine's scan path).
        let addr = serve(FakeTransport::new()).await;
        let mut c = warp_cfg_with_wgconf();
        c.warp.as_mut().unwrap().verify_with_wgconf = false;
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
            202
        );
    }

    #[test]
    fn sanitize_config_masks_wgconf_and_keeps_other_fields() {
        let mut c = cfg(1, 1);
        c.mode = Mode::Warp;
        c.warp = Some(WarpConfig {
            custom_endpoints: vec!["1.2.3.4:2408".to_owned()],
            wgconf: Some("secret-key".to_owned()),
            verify_with_wgconf: true,
            ..WarpConfig::default()
        });
        let masked = sanitize_config(c);
        let warp = masked.warp.unwrap();
        assert_eq!(warp.wgconf, None);
        assert!(!warp.verify_with_wgconf);
        assert_eq!(warp.custom_endpoints, vec!["1.2.3.4:2408"]);
        // Configs without a warp section pass through untouched.
        let c = cfg(1, 1);
        assert_eq!(sanitize_config(c.clone()), c);
    }

    async fn post_export(addr: SocketAddr, body: &str) -> (u16, String) {
        let req = format!(
            "POST /api/config/export HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await
    }

    const EXPORT_VLESS: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome";

    #[tokio::test]
    async fn export_renders_a_ready_uri_for_a_verified_candidate() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::json!({
            "config": EXPORT_VLESS,
            "ip": "203.0.113.7",
            "port": 2096,
            "sni": "b.me"
        });
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 200, "{text}");
        let payload: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        let uri = payload["uri"].as_str().unwrap();
        assert!(
            uri.starts_with("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@203.0.113.7:2096?"),
            "{uri}"
        );
        assert!(
            uri.contains("sni=b.me") && uri.contains("fp=chrome"),
            "{uri}"
        );
        // The exported URI parses and targets the candidate.
        let spec = crate::configs::parse_uri(uri).unwrap();
        assert_eq!(spec.server, "203.0.113.7");
        assert_eq!(spec.port, 2096);
        assert_eq!(spec.tls_server_name.as_deref(), Some("b.me"));
    }

    #[tokio::test]
    async fn export_without_sni_keeps_the_configs_own_sni() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::json!({
            "config": EXPORT_VLESS,
            "ip": "203.0.113.7",
            "port": 2096
        });
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 200, "{text}");
        let payload: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert!(
            payload["uri"]
                .as_str()
                .unwrap()
                .contains("sni=orig.example.com"),
            "{payload}"
        );
    }

    #[tokio::test]
    async fn export_rejects_bad_ip_port_and_oversized_sni() {
        let addr = serve(FakeTransport::new()).await;
        let oversized_sni = "a".repeat(crate::api::types::MAX_SNI_BYTES + 1);
        for (body, expected) in [
            (
                serde_json::to_string(&serde_json::json!({
                    "config": EXPORT_VLESS,
                    "ip": "not-an-ip",
                    "port": 443
                }))
                .unwrap(),
                "ip must be an IPv4 address",
            ),
            (
                serde_json::to_string(&serde_json::json!({
                    "config": EXPORT_VLESS,
                    "ip": "203.0.113.7",
                    "port": 0
                }))
                .unwrap(),
                "port must be in 1..=65535",
            ),
            (
                serde_json::to_string(&serde_json::json!({
                    "config": EXPORT_VLESS,
                    "ip": "203.0.113.7",
                    "port": 443,
                    "sni": oversized_sni
                }))
                .unwrap(),
                "sni must be at most",
            ),
        ] {
            let (status, text) = post_export(addr, &body).await;
            assert_eq!(status, 400, "{text}");
            assert!(text.contains(expected), "{text}");
        }
    }

    #[tokio::test]
    async fn export_rejects_malformed_sni() {
        let addr = serve(FakeTransport::new()).await;
        for bad in ["bad_sni", "-bad", "bad-", "a..b", "has space"] {
            let body = serde_json::json!({
                "config": EXPORT_VLESS,
                "ip": "203.0.113.7",
                "port": 443,
                "sni": bad
            });
            let (status, text) = post_export(addr, &body.to_string()).await;
            assert_eq!(status, 400, "{bad}: {text}");
            assert!(text.contains("invalid SNI"), "{bad}: {text}");
        }
        // Raw IPs and valid hostnames stay accepted.
        for good in ["1.2.3.4", "2606:4700::1111", "front.example.com"] {
            let body = serde_json::json!({
                "config": EXPORT_VLESS,
                "ip": "203.0.113.7",
                "port": 443,
                "sni": good
            });
            let (status, text) = post_export(addr, &body.to_string()).await;
            assert_eq!(status, 200, "{good}: {text}");
        }
    }

    #[tokio::test]
    async fn export_rejects_unsupported_configs_with_a_redacted_envelope() {
        let addr = serve(FakeTransport::new()).await;
        // vmess export is out of scope; the id inside the base64 must never
        // leak into the error envelope.
        let vmess = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                r#"{"v":"2","add":"1.2.3.4","port":"443","id":"vmess-secret-id","net":"tcp","tls":"none"}"#
            )
        );
        let body = serde_json::json!({"config": vmess, "ip": "203.0.113.7", "port": 443});
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 400, "{text}");
        assert!(text.contains("export not supported"), "{text}");
        assert!(!text.contains("vmess-secret-id"), "{text}");
        // Garbage configs error through the same envelope with no echo.
        let body = serde_json::json!({"config": "http://evil.example/x?id=sec", "ip": "203.0.113.7", "port": 443});
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 400, "{text}");
        assert!(!text.contains("sec"), "the config must never echo: {text}");
    }
}
