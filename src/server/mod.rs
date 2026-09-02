use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, Uri};
use axum::middleware::{self};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::api::types::{
    ExportConfigRequest, ExportConfigResponse, RangesPayload, RegisterRequest, RegisterResponse,
    ResultsPayload, ScanConfig, ScanEvent, StatusPayload, XrayDownloadResponse, XrayStatusPayload,
};
use crate::engine::ScanController;
use crate::paths;
use crate::ranges;
use crate::warpgen;
use crate::xray;

mod error;
mod export;
mod guard;
mod sse;
mod state;

use self::error::{ApiError, map_register_error};
use self::guard::{JsonBody, localhost_only, security_headers};
use self::sse::events;
use self::state::{
    AppState, REGISTER_COOLDOWN, RangesState, WarpRegistrar, XRAY_DOWNLOAD_COOLDOWN, XrayFetcher,
};

pub fn router(controller: Arc<ScanController>, bound_port: u16) -> Router {
    let ranges = RangesState::load();
    ranges.spawn_refresh(None, Arc::new(ranges::RealHttp));
    let xray_fetch: XrayFetcher = Arc::new(|| {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(xray::ensure_binary(&xray::RealFetch))
    });
    router_with_dir(
        controller,
        ranges,
        default_registrar(),
        bound_port,
        xray_fetch,
    )
}

fn router_with_dir(
    controller: Arc<ScanController>,
    ranges_state: Arc<RangesState>,
    registrar: WarpRegistrar,
    bound_port: u16,
    xray_fetch: XrayFetcher,
) -> Router {
    let state = Arc::new(AppState {
        controller,
        ranges: ranges_state,
        sse_connections: Arc::new(AtomicUsize::new(0)),
        warp_register: registrar,
        run_epoch: Arc::new(AtomicU64::new(0)),
        last_terminal: Arc::new(Mutex::new(None)),
        register_gate: tokio::sync::Mutex::new(None),
        xray_download_gate: tokio::sync::Mutex::new(None),
        xray_fetch,
    });
    Router::new()
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
        .route("/api/bundle", get(export::bundle))
        .route("/api/results/export", get(export::result_export))
        .with_state(state)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            guard::GuardConfig { port: bound_port },
            localhost_only,
        ))
        .layer(middleware::from_fn(security_headers))
}

async fn not_found(uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        ApiError::not_found(format!("no such endpoint: {path}")).into_response()
    } else {
        ApiError::not_found("not found").into_response()
    }
}

async fn method_not_allowed() -> Response {
    ApiError::method_not_allowed("method not allowed for this path").into_response()
}

async fn start_scan(
    State(state): State<Arc<AppState>>,
    JsonBody(cfg): JsonBody<ScanConfig>,
) -> Result<StatusCode, ApiError> {
    cfg.validate().map_err(|e| {
        let sanitized = crate::configs::sanitize_error_text(&e.to_string());
        let truncated: String = sanitized.chars().take(512).collect();
        ApiError::invalid_config(truncated)
    })?;
    if let Some(phase2) = &cfg.phase2
        && let Some(local) = phase2.configs.iter().find(|c| {
            c.is_empty() || c.to_ascii_lowercase().starts_with("file://") || !c.contains("://")
        })
    {
        return Err(ApiError::invalid_config(format!(
            "phase2 config {local:?} is not a URL; local file paths are CLI-only"
        )));
    }
    state
        .controller
        .reserve()
        .map_err(|_| ApiError::conflict("a scan is already running"))?;
    let epoch = state.run_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    let controller = Arc::clone(&state.controller);
    let last_terminal = Arc::clone(&state.last_terminal);
    tokio::spawn(async move {
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
    *state
        .last_terminal
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    state.run_epoch.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

fn default_registrar() -> WarpRegistrar {
    let handle = tokio::runtime::Handle::current();
    Arc::new(move |license| handle.block_on(warpgen::register(license.as_deref())))
}

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
    let overwrite = req.overwrite;
    let mut last_attempt = state.register_gate.lock().await;
    if crate::warpgen::has_identity() && !overwrite {
        return Err(ApiError::conflict(
            "identity already registered; pass {\"overwrite\":true} to replace it",
        ));
    }
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
    let uri =
        crate::configs::export_config_uri(&req.config, ip, req.port, req.sni.as_deref(), None)
            .map_err(|err| {
                ApiError::bad_request(crate::configs::sanitize_error_text(&format!("{err:#}")))
            })?;
    Ok(Json(ExportConfigResponse { uri }))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusPayload> {
    Json(StatusPayload {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        is_running: state.controller.is_running(),
        has_candidates: state.controller.has_results(),
    })
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
        version: xray::VERSION.trim().to_owned(),
    })
}

async fn xray_download(
    State(state): State<Arc<AppState>>,
) -> Result<Json<XrayDownloadResponse>, ApiError> {
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
            Err(ApiError::bad_gateway(truncated))
        }
    }
}

async fn ranges(State(state): State<Arc<AppState>>) -> Json<RangesPayload> {
    let (pool, last_updated) = state.ranges.snapshot();
    Json(RangesPayload {
        host_count: pool.host_count().min(u64::MAX as u128) as u64,
        last_updated,
    })
}

#[cfg(test)]
mod tests;
