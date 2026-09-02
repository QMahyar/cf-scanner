use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::error::ApiError;
use super::error::status_to_code;

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
    host_allowed(host) && parsed.port_or_known_default() == Some(cfg.port)
}

pub(crate) async fn localhost_only(
    State(cfg): State<GuardConfig>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let headers = request.headers();
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return Err(ApiError::forbidden("missing Host header"));
    };
    if !host_allowed(host) {
        return Err(ApiError::forbidden("Host header not allowed"));
    }
    if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok())
        && (origin == "null" || !origin_allowed(origin, cfg))
    {
        return Err(ApiError::forbidden("Origin not allowed"));
    }
    if let Some(site) = headers.get("sec-fetch-site").and_then(|h| h.to_str().ok())
        && site != "same-origin"
        && site != "none"
    {
        return Err(ApiError::forbidden("cross-site request rejected"));
    }
    if matches!(
        *request.method(),
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::DELETE
            | axum::http::Method::PATCH
    ) {
        let marker = headers
            .get("x-requested-with")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        if marker != Some("cf-scanner") {
            return Err(ApiError::forbidden(
                "missing X-Requested-With marker for a state-changing request",
            ));
        }
    }
    Ok(next.run(request).await)
}

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
