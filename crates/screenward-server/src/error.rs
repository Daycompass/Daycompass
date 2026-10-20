//! A single JSON error shape for every non-2xx response this server
//! sends, so handlers and middleware never leak internal details (SQL
//! errors, file paths, panics) to a client.

use std::time::Duration;

use axum::http::{header, HeaderValue, StatusCode};
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

/// Marks a response this server constructed on purpose, so the
/// normalizing middleware passes it through instead of rebuilding it.
///
/// Without this, every deliberate error response would be flattened to
/// its status code's generic form - discarding both a useful error code
/// and, more importantly, headers like `Retry-After`.
#[derive(Clone, Copy)]
pub struct Deliberate;

/// A client-facing error: a status code plus a short, generic code and
/// message. Never construct one from a raw internal error's `Display` -
/// pick a fixed, safe message instead.
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    retry_after: Option<Duration>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            retry_after: None,
        }
    }

    /// Adds a `Retry-After` header, for a request that was shed rather
    /// than refused: a rate limit or a shed hashing request.
    pub fn retry_after(mut self, after: Duration) -> Self {
        self.retry_after = Some(after);
        self
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
        let retry_after = self.retry_after;
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };

        let mut response = (self.status, Json(body)).into_response();
        response.extensions_mut().insert(Deliberate);

        if let Some(after) = retry_after {
            // Whole seconds, and at least one: "Retry-After: 0" invites
            // an immediate retry, which defeats the point of shedding.
            let seconds = after.as_secs().max(1);
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }

        response
    }
}

/// Router fallback for any request that matches no route.
pub async fn not_found() -> ApiError {
    ApiError::from_status(StatusCode::NOT_FOUND)
}
