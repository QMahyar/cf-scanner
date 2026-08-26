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

use crate::api::types::{DEFAULT_PORT, Mode, ScanConfig, ScanEvent, ScanSummary, Verdict};
use crate::engine::ScanController;
use crate::paths;
use crate::ranges;
#[allow(unused_imports)]
use crate::ranges::HttpGet;
use crate::warpgen;
use crate::xray;

mod error;
mod guard;
mod sse;
mod state;

#[allow(unused_imports)]
use self::error::{ApiError, map_register_error, sanitize_truncate, status_to_code};
#[allow(unused_imports)]
use self::guard::{JsonBody, SECURITY_CSP, localhost_only, security_headers};
#[allow(unused_imports)]
use self::sse::{MAX_SSE_CONNECTIONS, TerminalBounded, events, try_acquire_sse_slot};
#[allow(unused_imports)]
use self::state::{
    AppState, DEFAULT_RANGES_REFRESH_INTERVAL, MAX_PROFILES, PROFILES_FILE, ProfilePayload,
    REGISTER_COOLDOWN, RangesState, WarpRegistrar, load_profiles, persist_profiles,
};

const EMBEDDED_INDEX: &str = "index.html";

/// The compiled Svelte UI (`ui/dist`, committed so a plain `cargo build`
/// works without Node). Release builds embed it into the binary; debug
/// builds read from disk on every request, so `npm run build` output shows
/// up on browser refresh.
#[derive(rust_embed::RustEmbed)]
#[folder = "ui/dist"]
struct UiAssets;

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
    reject_default_warp_ports(&cfg).map_err(ApiError::invalid_config)?;
    reject_non_routable(&cfg).map_err(ApiError::invalid_config)?;
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
            // Mapped-v6 spellings (::ffff:a.b.c.d) of v4 specials must not
            // pass this gate by hiding behind their v6 form: they connect
            // as the embedded v4 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.octets()[0] == 0;
            }
            // ULA is fc00::/7 = first segment 0xfc00..=0xfdff.
            v6.is_unicast_link_local() || matches!(v6.segments()[0], 0xfc00..=0xfdff)
        }
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
        // /api/status is fetched once per page load (not polled), so the
        // snapshot clone in results() is cheap enough here.
        has_candidates: !state.controller.results().is_empty(),
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

async fn xray_download() -> Result<Json<XrayDownloadResponse>, ApiError> {
    match xray::ensure_binary(&xray::RealFetch).await {
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
mod tests {
    use super::*;
    use std::fs;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio_stream::StreamExt as _;
    use tokio_stream::wrappers::BroadcastStream;

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
            "script-src 'self'",
            "style-src 'self'",
            "font-src 'self' data:",
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
    async fn events_stream_ends_after_the_terminal_event() {
        // Every host probes slowly so the run outlives the SSE subscription
        // attach window (no fixed sleeps: fast machines would flake). The
        // stream must END after `finished`: an ever-pending body would hold
        // hyper's graceful shutdown open forever.
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr = serve(t).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let started = Instant::now();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
            202
        );
        let mut buf = vec![];
        let mut chunk = [0u8; 4096];
        let eof = loop {
            if String::from_utf8_lossy(&buf).contains("event: finished") {
                break true;
            }
            let deadline = tokio::time::sleep(Duration::from_secs(2));
            tokio::pin!(deadline);
            tokio::select! {
                _ = &mut deadline => break false,
                read = stream.read(&mut chunk) => match read {
                    Ok(0) => break false,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break false,
                },
            }
        };
        assert!(eof, "no terminal event within 2 s");
        // The connection must close right after the terminal event, not hang:
        // read to EOF and require it to land well before the request helper's
        // own 2 s deadline (the old contract pended forever here).
        loop {
            let deadline = tokio::time::sleep(Duration::from_secs(2));
            tokio::pin!(deadline);
            tokio::select! {
                _ = &mut deadline => panic!("stream did not end after the terminal event"),
                read = stream.read(&mut chunk) => match read {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                },
            }
        }
        assert!(started.elapsed() < Duration::from_millis(1500));
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("event: progress"), "{text}");
        assert!(text.contains("event: result"), "{text}");
        assert!(text.contains("event: finished"), "{text}");
    }

    #[tokio::test]
    async fn concurrent_scan_starts_emit_no_phantom_failed() {
        // Racing POSTs must resolve via 409 conflicts alone: the old
        // check-then-spawn gap let a second run through, whose engine-level
        // rejection surfaced as a spurious `Failed` event mid-scan.
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
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let mut posts = Vec::new();
        for _ in 0..3 {
            let body = body.clone();
            posts.push(tokio::spawn(async move {
                let req = format!(
                    "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                request(addr, &req, None).await.0
            }));
        }
        let mut codes: Vec<u16> = Vec::new();
        for post in posts {
            codes.push(post.await.unwrap());
        }
        codes.sort_unstable();
        assert_eq!(codes, vec![202, 409, 409], "exactly one start may win");
        let (_, text) = events.await.unwrap();
        assert!(text.contains("event: finished"), "{text}");
        assert!(
            !text.contains("event: failed"),
            "no phantom Failed may reach clients: {text}"
        );
    }

    #[tokio::test]
    async fn terminal_bounded_stream_stops_after_finished() {
        // Unit-level contract of the live SSE adapter: items flow until the
        // terminal event, then the stream ends (None) even though the
        // broadcast sender stays alive.
        let (tx, rx) = tokio::sync::broadcast::channel(8);
        let mut stream = TerminalBounded {
            rx: BroadcastStream::new(rx),
            _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
            done: false,
            replay: None,
            last_terminal: Arc::new(Mutex::new(None)),
            epoch: 0,
        };
        tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
            scanned: 1,
            found: 0,
            total: Some(8),
        }))
        .unwrap();
        tx.send(ScanEvent::Finished(ScanSummary {
            scanned: 8,
            found: 1,
            duration_ms: 5,
            cancelled: false,
        }))
        .unwrap();
        // axum's Event exposes no getters; item-count + termination is the
        // adapter's contract (event names are asserted over the wire in
        // events_stream_ends_after_the_terminal_event).
        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert!(first.is_ok(), "progress item must arrive");
        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert!(second.is_ok(), "finished item must arrive");
        let third = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(
            matches!(&third, Err(_) | Ok(None)),
            "stream must end after the terminal event: {third:?}"
        );
    }

    #[tokio::test]
    async fn replayed_terminal_does_not_close_the_stream() {
        // A stale terminal delivered as context must not terminate the
        // connection (idle browser EventSources would reconnect-storm);
        // only a fresh LIVE terminal from a later run ends it.
        let (tx, rx) = tokio::sync::broadcast::channel(8);
        let mut stream = TerminalBounded {
            rx: BroadcastStream::new(rx),
            _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
            done: false,
            replay: Some((
                ScanEvent::Finished(ScanSummary {
                    scanned: 4,
                    found: 2,
                    duration_ms: 3,
                    cancelled: false,
                }),
                false,
            )),
            last_terminal: Arc::new(Mutex::new(None)),
            epoch: 0,
        };
        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert!(first.is_ok(), "replayed finished item must arrive");
        let second = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
        assert!(
            second.is_err(),
            "the stream must stay open after a REPLAYED terminal: {second:?}"
        );
        tx.send(ScanEvent::Finished(ScanSummary {
            scanned: 8,
            found: 3,
            duration_ms: 9,
            cancelled: false,
        }))
        .unwrap();
        let third = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert!(third.is_ok(), "live finished item must arrive");
        let fourth = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
        assert!(
            matches!(&fourth, Err(_) | Ok(None)),
            "a LIVE terminal must end the stream: {fourth:?}"
        );
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
    async fn accepts_localhost_case_insensitively_and_rejects_ipv6_host() {
        // The server binds IPv4 loopback only, so [::1] is not an answerable
        // Host and must be rejected like any foreign host.
        let addr = serve(FakeTransport::new()).await;
        for host in ["localhost:8765", "LOCALHOST:8765", "127.0.0.1:1"] {
            let (status, _) = request(
                addr,
                &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                None,
            )
            .await;
            assert_eq!(status, 200, "host {host:?} must be allowed");
        }
        for host in ["[::1]:8765", "[::1]"] {
            let (status, _) = request(
                addr,
                &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                None,
            )
            .await;
            assert_eq!(status, 403, "host {host:?} must be rejected");
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

    /// Registrar that lingers before persisting the identity, widening the
    /// check-vs-write window so the registration gate's serialization is
    /// observable (two racing first-time registers must not both succeed).
    fn slow_identity_registrar() -> WarpRegistrar {
        let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
        Arc::new(move |_| {
            std::thread::sleep(Duration::from_millis(150));
            fs::write(
                dir.join("identity.json"),
                r#"{"id":"t","token":"t","private_key":"aGFo","client_id":"c","account_type":"free","created_at":0}"#,
            )
            .unwrap();
            Ok("fake-wgconf".to_owned())
        })
    }

    #[tokio::test]
    async fn concurrent_registers_serialize_overwrite_consent() {
        let _isolated = isolate_identity_dir();
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            slow_identity_registrar(),
        )
        .await;
        let (a, b) = tokio::join!(
            post_register(addr, r#"{"license":null}"#),
            post_register(addr, r#"{"license":null}"#),
        );
        let mut codes = [a.0, b.0];
        codes.sort_unstable();
        assert_eq!(
            codes,
            [200, 409],
            "the second register must see the identity the first wrote"
        );
    }

    #[tokio::test]
    async fn register_rejects_oversized_license() {
        let _isolated = isolate_identity_dir();
        let (registrar, seen) = recording_registrar("fake-wgconf-text");
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            registrar,
        )
        .await;
        let big = "a".repeat(crate::api::types::MAX_LICENSE_BYTES + 1);
        let (status, text) = post_register(addr, &format!(r#"{{"license":"{big}"}}"#)).await;
        assert_eq!(status, 400, "{text}");
        assert!(
            text.contains(&format!(
                "at most {} bytes",
                crate::api::types::MAX_LICENSE_BYTES
            )),
            "{text}"
        );
        // At the cap the license goes through to the registrar untouched.
        let at_cap = "a".repeat(crate::api::types::MAX_LICENSE_BYTES);
        let (status, text) = post_register(addr, &format!(r#"{{"license":"{at_cap}"}}"#)).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(seen.lock().unwrap().as_deref(), Some(at_cap.as_str()));
    }

    #[tokio::test]
    async fn export_rejects_oversized_config() {
        let addr = serve(FakeTransport::new()).await;
        let big = format!(
            "vless://x@1.2.3.4:443?{}",
            "a".repeat(crate::api::types::MAX_EXPORT_CONFIG_BYTES)
        );
        let body = serde_json::json!({"config": big, "ip": "203.0.113.7", "port": 443});
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 400, "{text}");
        assert!(
            text.contains(&format!(
                "at most {} bytes",
                crate::api::types::MAX_EXPORT_CONFIG_BYTES
            )),
            "{text}"
        );
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
            // IPv4-mapped IPv6 spellings of the same specials must fail
            // exactly like their v4 forms.
            "::ffff:127.0.0.1/128",   // loopback, mapped
            "::ffff:169.254.0.1/128", // link-local, mapped
            "::ffff:10.0.0.0/104",    // RFC1918 10/8, mapped
            "::ffff:192.168.1.0/120", // RFC1918 /24, mapped
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

    // --- A9 / A13 / A17 new coverage ---

    #[tokio::test]
    async fn rejects_null_origin() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: null\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403, "{text}");
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "forbidden");
        // absent Origin stays allowed
        let (status, _) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        // normal same-origin still allowed
        let (status, _) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:8765\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn json_rejection_is_sanitized_and_truncated() {
        let addr = serve(FakeTransport::new()).await;
        // Oversized multiline body with control chars; rejection body_text flows
        // through sanitize_error_text and 512-char truncation.
        let big = "x".repeat(2000);
        let body = format!(
            "{{\"mode\":\"Cdn\",\"target\":{{\"Preset\":\"Quick\"}},\"ports\":[443],\"bad\":\"{big}\"\nsecond line with control \x07 and https://user:pass@example.com/secret?token=abc#frag"
        );
        let req = format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (status, text) = request(addr, &req, None).await;
        // The unknown "bad" field trips deny_unknown_fields (a serde DATA
        // error) before the trailing syntax garbage matters -> 422.
        assert_eq!(status, 422, "{text}");
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        let msg = parsed["message"].as_str().unwrap();
        assert!(
            msg.chars().count() <= 512,
            "message must be truncated to 512 chars: {}",
            msg.chars().count()
        );
        assert!(!msg.contains('\x07'), "control chars must be stripped");
        assert!(
            !msg.contains("secret"),
            "query secrets must be redacted via sanitize"
        );
        assert_eq!(parsed["code"], "invalid_config");
    }

    #[tokio::test]
    async fn error_responses_carry_machine_readable_codes() {
        let addr = serve(FakeTransport::new()).await;
        // 404 code
        let (status, text) = request(
            addr,
            "GET /api/profiles/nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 404);
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "not_found");

        // 403 forbidden
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 403);
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "forbidden");

        // 409 conflict (scan already running)
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr2 = serve(t).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(post_scan(addr2, &body).await, 202);
        wait_until_running(addr2).await;
        let (status, text) = post_scan_full(addr2, &body).await;
        assert_eq!(status, 409);
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "conflict");

        // invalid_config vs bad_request: cfg.validate failure is invalid_config
        let addr3 = serve(FakeTransport::new()).await;
        let mut bad = cfg(1, 1);
        bad.ports = vec![0];
        let (status, text) = post_scan_full(addr3, &serde_json::to_string(&bad).unwrap()).await;
        assert_eq!(status, 400);
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "invalid_config");

        // generic bad_request stays bad_request (export oversized)
        let big = format!(
            "vless://x@1.2.3.4:443?{}",
            "a".repeat(crate::api::types::MAX_EXPORT_CONFIG_BYTES)
        );
        let body = serde_json::json!({"config": big, "ip": "203.0.113.7", "port": 443});
        let (status, text) = post_export(addr3, &body.to_string()).await;
        assert_eq!(status, 400);
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "bad_request");
    }

    #[test]
    fn map_register_error_maps_variants() {
        use crate::warpgen::WarpRegisterError;
        // Timeout -> gateway_timeout 504
        let err = anyhow::Error::from(WarpRegisterError::Timeout);
        let api = map_register_error(err);
        assert_eq!(api.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(api.code, "gateway_timeout");

        // RateLimited -> rate_limited 429
        let err = anyhow::Error::from(WarpRegisterError::RateLimited);
        let api = map_register_error(err);
        assert_eq!(api.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(api.code, "rate_limited");

        // Unauthorized -> upstream_error 502 with status in message
        let err = anyhow::Error::from(WarpRegisterError::Unauthorized { status: 401 });
        let api = map_register_error(err);
        assert_eq!(api.status, StatusCode::BAD_GATEWAY);
        assert_eq!(api.code, "upstream_error");
        assert!(api.message.contains("401"), "{}", api.message);

        // Server -> upstream_error with sanitized detail, truncated
        let long_detail =
            "https://user:secret@example.com/x?token=abc ".to_string() + &"y".repeat(1000);
        let err = anyhow::Error::from(WarpRegisterError::Server {
            status: 500,
            detail: long_detail,
        });
        let api = map_register_error(err);
        assert_eq!(api.status, StatusCode::BAD_GATEWAY);
        assert!(api.message.contains("500"));
        assert!(!api.message.contains("secret"), "detail must be sanitized");
        assert!(
            api.message.chars().count() <= 600,
            "sanitized detail truncated"
        );

        // Wrapped via context -> still maps (chain)
        let err = anyhow::Error::from(WarpRegisterError::Timeout).context("outer wrap");
        let api = map_register_error(err);
        assert_eq!(api.code, "gateway_timeout");

        // Unknown -> fallback upstream_error
        let err = anyhow::anyhow!("some other network failure https://user:pass@example.com/q?x=1");
        let api = map_register_error(err);
        assert_eq!(api.code, "upstream_error");
        assert!(!api.message.contains("pass"), "fallback must sanitize");
    }

    #[tokio::test]
    async fn warp_register_maps_typed_errors_over_http() {
        let _isolated = isolate_identity_dir();
        // Timeout variant via injected registrar
        let timeout_reg: WarpRegistrar = Arc::new(|_| {
            Err(anyhow::Error::from(
                crate::warpgen::WarpRegisterError::Timeout,
            ))
        });
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            timeout_reg,
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 504, "{text}");
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "gateway_timeout");

        // RateLimited -> 429
        let rl_reg: WarpRegistrar = Arc::new(|_| {
            Err(anyhow::Error::from(
                crate::warpgen::WarpRegisterError::RateLimited,
            ))
        });
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            rl_reg,
        )
        .await;
        let (status, text) = post_register(addr, r#"{"license":null}"#).await;
        assert_eq!(status, 429, "{text}");
        let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
        assert_eq!(parsed["code"], "rate_limited");
    }

    #[tokio::test]
    async fn lagged_stream_stays_alive_with_terminal_snapshot() {
        // Lagged must not close the stream; instead it re-emits the terminal
        // snapshot and continues listening.
        let (tx, rx) = tokio::sync::broadcast::channel(2);
        let last = Arc::new(Mutex::new(Some((
            1u64,
            ScanEvent::Finished(ScanSummary {
                scanned: 8,
                found: 1,
                duration_ms: 5,
                cancelled: false,
            }),
        ))));
        let mut stream = TerminalBounded {
            rx: BroadcastStream::new(rx),
            _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
            done: false,
            replay: None,
            last_terminal: Arc::clone(&last),
            epoch: 1,
        };
        // Fill and overflow the 2-slot channel so the receiver lags.
        tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
            scanned: 1,
            found: 0,
            total: Some(8),
        }))
        .unwrap();
        tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
            scanned: 2,
            found: 0,
            total: Some(8),
        }))
        .unwrap();
        tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
            scanned: 3,
            found: 0,
            total: Some(8),
        }))
        .unwrap();
        // Receiver has missed events -> Lagged. It must yield the terminal snapshot and stay open.
        let item = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(item);
        // After the Lagged replay the broadcast may still deliver retained
        // events (e.g. the newest progress) — the invariant is that the
        // stream NEVER ends: drain until the window goes quiet.
        let mut stayed_open = true;
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
                Err(_quiet) => break,
                Ok(None) => {
                    stayed_open = false;
                    break;
                }
                Ok(Some(_)) => continue,
            }
        }
        assert!(stayed_open, "stream must stay alive after Lagged replay");
    }
}
