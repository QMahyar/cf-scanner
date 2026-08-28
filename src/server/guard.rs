//! Request screening: Host allowlist, Origin/Sec-Fetch-Site rejection, and
//! the security-header layer every response passes through.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::error::ApiError;
use super::error::status_to_code;

/// Host header values the API answers to. Anything else is rejected before
/// routing (DNS-rebinding / drive-by protection); the server only ever binds
/// IPv4 loopback, so v6 loopback hosts are not answerable and stay rejected.
const ALLOWED_HOSTS: [&str; 2] = ["127.0.0.1", "localhost"];

pub(crate) fn host_allowed(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(addr, _)| addr).unwrap_or(host)
    } else if let Some((addr, _)) = host.rsplit_once(':') {
        addr
    } else {
        host
    };
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
}

/// The served port, threaded into the Origin check so "first-party" means
/// this process's UI and not any other loopback listener (for IP hosts,
/// browsers classify a different port as same-site, so only the port match
/// can tell them apart).
#[derive(Clone, Copy)]
pub(crate) struct GuardConfig {
    pub(crate) port: u16,
}

pub(crate) fn origin_allowed(origin: &str, cfg: GuardConfig) -> bool {
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // Browsers omit the scheme-default port (http 80 / https 443); normalize
    // so a server pinned to such a port still matches its own UI's origin.
    host_allowed(host) && parsed.port_or_known_default() == Some(cfg.port)
}

/// Rejects requests that are not from the local UI: a foreign Host header,
/// a cross-origin browser request (Origin / Sec-Fetch-Site), or no Host at
/// all. Browsers and curl always send Host; the UI is same-origin.
pub(crate) async fn localhost_only(
    State(cfg): State<GuardConfig>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let headers = request.headers();
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return Err(ApiError::forbidden("missing Host header"));
    };
    // The Host header keeps its bare-host comparison: it legitimately omits
    // or varies the port (curl, proxies), so over-tightening it would break
    // callers the Origin pin below does not affect.
    if !host_allowed(host) {
        return Err(ApiError::forbidden("Host header not allowed"));
    }
    if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
        if origin == "null" || !origin_allowed(origin, cfg) {
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
pub(crate) struct JsonBody<T>(pub(super) T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => {
                let status = rejection.status();
                let raw = rejection.body_text();
                let sanitized = crate::configs::sanitize_error_text(&raw);
                let truncated: String = sanitized.chars().take(512).collect();
                let code = status_to_code(status);
                Err(ApiError {
                    status,
                    code,
                    message: truncated,
                })
            }
        }
    }
}

/// Directives every HTML response must carry. The compiled UI ships real
/// asset files, so everything stays 'self' — no inline script or style.
/// Runtime-dynamic Svelte styles cannot be hash-pinned, so `style-src` allows `'unsafe-inline'`; `script-src`/`script-src-attr` stay locked, so style injection adds no script-execution path.
pub(crate) const SECURITY_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; script-src-attr 'none'";

/// Adds the security headers every response should carry, leaving any header
/// the handler already set untouched (the HTML handlers set their own CSP).
pub(crate) async fn security_headers(request: Request, next: Next) -> Response {
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
