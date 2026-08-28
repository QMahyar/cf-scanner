//! Localhost HTTP API + embedded browser UI, both thin clients of the one
//! ScanController. Routes map engine state into the `api::types` contract
//! directly (those types ARE the wire contract); no engine type is
//! serialized.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::middleware::{self};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock as TokioRwLock;

use crate::api::types::{ScanConfig, ScanEvent, ScanSummary, Verdict};
use crate::engine::ScanController;
use crate::paths;
use crate::ranges;
use crate::warpgen;
use crate::xray;

mod error;
mod guard;
mod sse;
mod state;

use self::error::{ApiError, map_register_error};
use self::guard::{JsonBody, SECURITY_CSP, localhost_only, security_headers};
use self::sse::events;
use self::state::{
    AppState, MAX_PROFILES, ProfilePayload, REGISTER_COOLDOWN, RangesState, WarpRegistrar,
    XRAY_DOWNLOAD_COOLDOWN, XrayFetcher, load_profiles, persist_profiles,
};

const EMBEDDED_INDEX: &str = "index.html";

/// The compiled Svelte UI (`ui/dist`, committed so a plain `cargo build`
/// works without Node). Release builds embed it into the binary; debug
/// builds read from disk on every request, so `npm run build` output shows
/// up on browser refresh.
#[derive(rust_embed::RustEmbed)]
#[folder = "ui/dist"]
struct UiAssets;

pub fn router(controller: Arc<ScanController>, bound_port: u16) -> Router {
    let ranges = RangesState::load();
    ranges.spawn_refresh(None, Arc::new(ranges::RealHttp));
    let profiles_dir =
        paths::data_dir().unwrap_or_else(|_| std::env::temp_dir().join("cf-scanner-profiles"));
    let xray_fetch: XrayFetcher = Arc::new(|| {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(xray::ensure_binary(&xray::RealFetch))
    });
    router_with_dir(
        controller,
        ranges,
        default_registrar(),
        profiles_dir,
        bound_port,
        xray_fetch,
    )
}

/// Every test server persists to its own throwaway dir, so no test can read
/// another test's profiles (and none touches a real user's data dir).
#[cfg(test)]
fn unique_test_profiles_dir() -> PathBuf {
    use std::fs;
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
    bound_port: u16,
    xray_fetch: XrayFetcher,
) -> Router {
    let state = Arc::new(AppState {
        controller,
        profiles: TokioRwLock::new(load_profiles(&profiles_dir)),
        ranges: ranges_state,
        sse_connections: Arc::new(AtomicUsize::new(0)),
        warp_register: registrar,
        profiles_dir,
        run_epoch: Arc::new(AtomicU64::new(0)),
        last_terminal: Arc::new(Mutex::new(None)),
        register_gate: tokio::sync::Mutex::new(None),
        xray_download_gate: tokio::sync::Mutex::new(None),
        xray_fetch,
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
        .layer(middleware::from_fn_with_state(
            guard::GuardConfig { port: bound_port },
            localhost_only,
        ))
}

/// Unmatched paths serve the embedded Svelte UI: `/` and `/index.html` the
/// page shell, hashed asset files by exact path; everything else (including
/// any `/api/*` miss) keeps the uniform JSON error envelope. The UI is a
/// single page with no client-side routing, so unknown paths stay 404 —
/// no SPA fallback widening the surface.
async fn fallback(uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        return ApiError::not_found(format!("no such endpoint: {path}")).into_response();
    }
    let file = match path {
        "/" | "/index.html" => EMBEDDED_INDEX,
        p => p.trim_start_matches('/'),
    };
    ui_response(file).unwrap_or_else(|| ApiError::not_found("not found").into_response())
}

fn ui_response(file: &str) -> Option<Response> {
    let data = UiAssets::get(file)?;
    let mime = match file.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        _ => "application/octet-stream",
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, mime.parse().unwrap());
    headers.insert("content-security-policy", SECURITY_CSP.parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    Some((headers, data.data).into_response())
}

/// Wrong method on a known path: 405 with the same JSON envelope as every
/// other error. axum 0.8 passes no Allow header to this handler; the status
/// alone is the contract the UI and CLI rely on.
async fn method_not_allowed() -> Response {
    ApiError::method_not_allowed("method not allowed for this path").into_response()
}

/// 202 with no body; the run's progress is observable on /api/events. 409
/// when another scan is already running or starting. The controller slot is
/// reserved synchronously under its own lock BEFORE the run task is spawned,
/// so a racing second POST sees the reservation instead of a false "not
/// running" (the old check-then-spawn gap let a second run slip through and
/// emit a phantom `Failed` mid-scan).
async fn start_scan(
    State(state): State<Arc<AppState>>,
    JsonBody(cfg): JsonBody<ScanConfig>,
) -> Result<StatusCode, ApiError> {
    cfg.validate().map_err(ApiError::invalid_config)?;
    if let Some(phase2) = &cfg.phase2 {
        if let Some(local) = phase2.configs.iter().find(|c| !c.contains("://")) {
            return Err(ApiError::bad_request(format!(
                "phase2 config {local:?} is not a URL; local file paths are CLI-only"
            )));
        }
    }
    state
        .controller
        .reserve()
        .map_err(|_| ApiError::conflict("a scan is already running"))?;
    let epoch = state.run_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    let controller = Arc::clone(&state.controller);
    let last_terminal = Arc::clone(&state.last_terminal);
    tokio::spawn(async move {
        // Record the terminal the moment the engine emits it — before the
        // running flag clears — so an SSE client deciding replay-vs-live from
        // last_terminal can never land in a window where the terminal was
        // broadcast but is not yet observable.
        let outcome = controller
            .run_reserved_streaming(cfg, |ev| {
                if matches!(ev, ScanEvent::Finished(_) | ScanEvent::Failed(_)) {
                    *last_terminal
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some((epoch, ev.clone()));
                }
            })
            .await;
        if let Err(err) = &outcome {
            tracing::error!(
                "scan failed: {}",
                crate::configs::sanitize_error_text(&format!("{err:#}"))
            );
        }
    });
    Ok(StatusCode::ACCEPTED)
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
    if req
        .license
        .as_ref()
        .is_some_and(|l| l.len() > crate::api::types::MAX_LICENSE_BYTES)
    {
        return Err(ApiError::bad_request(format!(
            "license must be at most {} bytes",
            crate::api::types::MAX_LICENSE_BYTES
        )));
    }
    // One critical section across the overwrite-consent check, the cooldown
    // bookkeeping, and the registration itself (see register_gate).
    let mut last_attempt = state.register_gate.lock().await;
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
    if last_attempt.is_some_and(|at| at.elapsed() < REGISTER_COOLDOWN) {
        return Err(ApiError::too_many(
            "registration is rate-limited to one attempt per 60 s",
        ));
    }
    *last_attempt = Some(Instant::now());
    let license = req
        .license
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty());
    let registrar = Arc::clone(&state.warp_register);
    let wgconf = tokio::task::spawn_blocking(move || registrar(license))
        .await
        .map_err(|_| ApiError::internal("registration task panicked"))?
        .map_err(map_register_error)?;
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
    if req.config.len() > crate::api::types::MAX_EXPORT_CONFIG_BYTES {
        return Err(ApiError::bad_request(format!(
            "config must be at most {} bytes",
            crate::api::types::MAX_EXPORT_CONFIG_BYTES
        )));
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
    /// True while banked candidates exist server-side; lets the UI offer a
    /// phase-2-only verify after a page reload, when the client store is
    /// empty but the controller still holds last-scan results.
    has_candidates: bool,
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusPayload> {
    Json(StatusPayload {
        version: env!("CARGO_PKG_VERSION"),
        is_running: state.controller.is_running(),
        has_candidates: state.controller.has_results(),
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

async fn xray_download(
    State(state): State<Arc<AppState>>,
) -> Result<Json<XrayDownloadResponse>, ApiError> {
    // Cooldown gate: mirrors the register handler's 1-per-60s pattern so a
    // stuck client cannot loop download attempts indefinitely.
    {
        let mut last = state.xray_download_gate.lock().await;
        if last.is_some_and(|at| at.elapsed() < XRAY_DOWNLOAD_COOLDOWN) {
            return Err(ApiError::too_many(
                "xray download is rate-limited to one attempt per 60 s",
            ));
        }
        *last = Some(Instant::now());
    }
    let fetch = Arc::clone(&state.xray_fetch);
    let result = tokio::task::spawn_blocking(move || fetch())
        .await
        .map_err(|_| ApiError::internal("xray fetch task panicked"))?;
    match result {
        Ok(path) => Ok(Json(XrayDownloadResponse {
            success: true,
            path: Some(path.display().to_string()),
            error: None,
        })),
        Err(err) => {
            let sanitized = crate::configs::sanitize_error_text(&format!("{err:#}"));
            let truncated: String = sanitized.chars().take(512).collect();
            // Network/upstream failures surface as 502; unexpected internal as 500.
            // xray download is network-bound, so default to upstream_error.
            Err(ApiError::bad_gateway(truncated))
        }
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
    let (pool, last_updated) = state.ranges.snapshot();
    Json(RangesPayload {
        host_count: pool.host_count().min(u64::MAX as u128) as u64,
        last_updated,
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
    cfg.validate().map_err(ApiError::invalid_config)?;
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

async fn index() -> Response {
    ui_response(EMBEDDED_INDEX).expect("ui/dist/index.html is embedded at compile time")
}

#[cfg(test)]
mod tests;
