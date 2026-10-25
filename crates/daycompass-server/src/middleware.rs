//! Cross-cutting HTTP middleware: request ID, structured logging,
//! timeout, body size limit, security headers, and error-response
//! normalization.
//!
//! CORS is deliberately absent: with no `tower_http::cors` layer added,
//! browsers enforce same-origin by default, which is "CORS off" for an
//! API that otherwise has no need to speak to it.

use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::Instrument;

use crate::error::{ApiError, Deliberate, ErrorKind};

/// Small default: this milestone has no file uploads, just tiny JSON
/// bodies on future endpoints.
const MAX_BODY_BYTES: usize = 64 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_ID_HEADER_NAME: &str = "x-request-id";

/// The Content-Security-Policy sent on every response. See [`apply`].
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

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
        // `if_not_present` rather than `overriding`, for one reason: the
        // dashboard's static assets (`routes::pages::assets`) answer
        // `no-cache` with an ETag, so a browser can keep them. Nothing
        // else sets the header, so every API response and every page -
        // which carry the CSRF token and the account's own stats - is
        // still `no-store`. `tests/dashboard.rs` pins both halves.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        ))
        // On every response, not only on pages: a JSON body or an SVG
        // opened directly is a document too, and should run nothing.
        // Same-origin scripts, styles, fonts, images and requests only,
        // no inline script or style, no framing, no <base>, and forms
        // may only post back here.
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
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
    ApiError::of(ErrorKind::RequestTimeout)
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

// The `Origin` check used to live here. It is now attached per route
// from the route inventory, in `crate::routes::access`, so that which
// routes are checked is decided by the table rather than by which
// router a route was registered in.
