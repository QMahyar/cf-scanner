//! Uniform API error envelope: every non-2xx answers
//! `{"error": <reason>, "message": <human>, "code": <machine>}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    code: &'static str,
}

pub(crate) fn status_to_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNPROCESSABLE_ENTITY => "invalid_config",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::CONFLICT => "conflict",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::BAD_GATEWAY => "upstream_error",
        StatusCode::GATEWAY_TIMEOUT => "gateway_timeout",
        StatusCode::INTERNAL_SERVER_ERROR => "internal",
        _ => "internal",
    }
}

impl ApiError {
    pub(crate) fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: err.to_string(),
        }
    }

    pub(crate) fn invalid_config(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_config",
            message: err.to_string(),
        }
    }

    pub(crate) fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "upstream_error",
            message: message.into(),
        }
    }

    pub(crate) fn gateway_timeout(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: "gateway_timeout",
            message: message.into(),
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: message.into(),
        }
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    pub(crate) fn method_not_allowed(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message: message.into(),
        }
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
        }
    }

    pub(crate) fn too_many(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.status.canonical_reason().unwrap_or("Error").to_owned(),
            message: self.message,
            code: self.code,
        });
        (self.status, body).into_response()
    }
}

pub(crate) fn sanitize_truncate(text: &str) -> String {
    let sanitized = crate::configs::sanitize_error_text(text);
    sanitized.chars().take(512).collect()
}

/// Maps a failed registration onto the uniform envelope by downcasting the
/// typed [`crate::warpgen::WarpRegisterError`] out of the anyhow chain.
pub(crate) fn map_register_error(err: anyhow::Error) -> ApiError {
    for cause in err.chain() {
        if let Some(warp_err) = cause.downcast_ref::<crate::warpgen::WarpRegisterError>() {
            match warp_err {
                crate::warpgen::WarpRegisterError::Timeout => {
                    return ApiError::gateway_timeout("registration timed out");
                }
                crate::warpgen::WarpRegisterError::RateLimited => {
                    return ApiError::too_many(
                        "registration rate-limited by Cloudflare, try again later",
                    );
                }
                crate::warpgen::WarpRegisterError::Unauthorized { status } => {
                    return ApiError::bad_gateway(format!(
                        "Cloudflare rejected the registration (HTTP {status})"
                    ));
                }
                crate::warpgen::WarpRegisterError::Server { status, detail } => {
                    let detail = sanitize_truncate(detail);
                    return ApiError::bad_gateway(format!(
                        "registration failed (HTTP {status}): {detail}"
                    ));
                }
            }
        }
    }
    ApiError::bad_gateway(format!(
        "registration failed: {}",
        sanitize_truncate(&format!("{err:#}"))
    ))
}
