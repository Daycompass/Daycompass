//! A single JSON error shape for every non-2xx response this server
//! sends, so handlers and middleware never leak internal details (SQL
//! errors, file paths, panics) to a client.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

/// A client-facing error: a status code plus a short, generic code and
/// message. Never construct one from a raw internal error's `Display` -
/// pick a fixed, safe message instead.
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Builds the generic error for `status` from its own canonical
    /// reason phrase (e.g. 404 -> code "not_found", message
    /// "not found"). Used as the safe fallback for any response this
    /// server did not deliberately construct.
    pub fn from_status(status: StatusCode) -> Self {
        let message = status
            .canonical_reason()
            .unwrap_or("error")
            .to_ascii_lowercase();
        let code = message.replace(' ', "_");
        Self::new(status, code, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

/// Router fallback for any request that matches no route.
pub async fn not_found() -> ApiError {
    ApiError::from_status(StatusCode::NOT_FOUND)
}
