//! Cross-cutting HTTP middleware: request ID, structured logging,
//! timeout, body size limit, security headers, and error-response
//! normalization.
//!
//! CORS is deliberately absent: with no `tower_http::cors` layer added,
//! browsers enforce same-origin by default, which is "CORS off" for an
//! API that otherwise has no need to speak to it.

use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::auth::origin;
use crate::error::{ApiError, Deliberate};
use crate::state::AppState;

/// Small default: this milestone has no file uploads, just tiny JSON
/// bodies on future endpoints.
const MAX_BODY_BYTES: usize = 64 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_ID_HEADER_NAME: &str = "x-request-id";

/// Wraps `router` with the full middleware stack. Order matters: each
/// `.layer()` call wraps everything added before it, so the request
/// flows through these top-to-bottom and the response flows back
/// bottom-to-top.
pub fn apply(router: Router) -> Router {
    let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER_NAME);

    router
        // Runs first on the way in, so it sees the x-request-id header
        // already set below, and last on the way out, so it can rewrite
        // *any* error response produced further in (handlers, the 404
        // fallback, the timeout below) into the one uniform JSON shape.
        .layer(middleware::from_fn(normalize_error_responses))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        ))
        .layer(
            ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    handle_timeout_error,
                ))
                .layer(TimeoutLayer::new(REQUEST_TIMEOUT)),
        )
        .layer(middleware::from_fn(log_request))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
}

/// Converts a `TimeoutLayer` timeout into the uniform error shape. Any
/// other error reaching here is unexpected; treated the same way rather
/// than risking a detail leak.
async fn handle_timeout_error(_err: tower::BoxError) -> ApiError {
    ApiError::from_status(StatusCode::REQUEST_TIMEOUT)
}

/// Logs exactly one line per request: method, path (never the query
/// string), the request ID, status, and duration. No header values, no
/// request/response bodies.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let start = Instant::now();

    async move {
        let response = next.run(request).await;
        tracing::info!(
            status = response.status().as_u16(),
            duration_ms = start.elapsed().as_millis() as u64,
            "request completed"
        );
        response
    }
    .instrument(tracing::info_span!(
        "request",
        method = %method,
        path = %path,
        request_id = %request_id,
    ))
    .await
}

/// Rewrites every non-2xx/3xx response into the uniform JSON error
/// shape, discarding whatever body the handler, the 404 fallback, or an
/// infrastructure layer (timeout, body limit) produced. This is the
/// single place that guarantees no internal detail ever reaches a
/// client, regardless of where the error came from.
///
/// Responses carrying [`Deliberate`] are left alone. Those were built
/// by this server's own error type, which already produces the uniform
/// shape, and rebuilding them would throw away their specific error
/// code and any `Retry-After` header they set. Anything else - a serde
/// rejection quoting part of the request body, a timeout, the body-size
/// limit - is still replaced wholesale.
async fn normalize_error_responses(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    let deliberate = response.extensions().get::<Deliberate>().is_some();

    if (status.is_client_error() || status.is_server_error()) && !deliberate {
        ApiError::from_status(status).into_response()
    } else {
        response
    }
}

/// Rejects a state-changing request whose `Origin` names someone else.
///
/// Applied only to the routes that can be cookie-authenticated; see
/// [`crate::routes::router`] for why the exemption is structural. The
/// rule itself lives in [`crate::auth::origin`], which is where it is
/// tested.
pub async fn require_matching_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().get_all(header::ORIGIN);
    let mut values = headers.iter();
    let first = values.next();

    // More than one Origin header is not something a browser does, and
    // picking one of several would be a way to smuggle the wrong answer
    // past this check.
    if values.next().is_some() {
        return reject_origin();
    }

    let origin = match first {
        None => None,
        Some(value) => match value.to_str() {
            Ok(text) => Some(text),
            // Present but not text: refuse rather than fall through to
            // the "absent" case, which is deliberately permissive.
            Err(_) => return reject_origin(),
        },
    };

    if !origin::is_allowed(request.method().as_str(), origin, &state.public_url) {
        return reject_origin();
    }

    next.run(request).await
}

/// The one response an Origin failure produces. The message does not
/// echo the offending value, and does not state the expected one.
fn reject_origin() -> Response {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "origin_mismatch",
        "this request did not come from an allowed origin",
    )
    .into_response()
}
