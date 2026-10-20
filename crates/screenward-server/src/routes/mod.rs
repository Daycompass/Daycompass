//! Route definitions and the HTTP-facing views of domain types.
//!
//! Handlers here parse input, call the service layer in
//! [`crate::auth`], and map results onto status codes. No rules live in
//! this module: per `CLAUDE.md`, the JSON handlers and the later HTML
//! handlers must share one service layer.

mod auth;
mod health;
mod setup;

use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;

use axum::http::StatusCode;

use crate::auth::store::UserRecord;
use crate::error::{not_found, ApiError};
use crate::middleware::require_matching_origin;
use crate::ratelimit::Decision;
use crate::state::AppState;

/// Builds the route table.
///
/// Split into two groups so the `Origin` exemption is structural rather
/// than a path string compared at runtime: a route is exempt because of
/// which router it is registered in, which is much harder to get subtly
/// wrong than a list of paths to skip.
pub fn router(state: AppState) -> Router {
    // Everything that may be state-changing and cookie-authenticated.
    let origin_checked = Router::new()
        .route("/api/v1/auth/login", post(auth::log_in))
        .route("/api/v1/auth/logout", post(auth::log_out))
        .route("/api/v1/auth/me", get(auth::me))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_matching_origin,
        ));

    // Exempt. `/healthz` is a GET, so the check would pass it anyway.
    // `/api/v1/setup` carries no cookie: there is no ambient credential
    // for a hostile page to ride on, and its protection is the
    // unguessable setup token.
    let origin_exempt = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/api/v1/setup", post(setup::create_first_admin));

    Router::new()
        .merge(origin_checked)
        .merge(origin_exempt)
        .fallback(not_found)
        .with_state(state)
}

/// What a client is told about an account.
///
/// Deliberately not the full [`UserRecord`]: the password hash has no
/// business leaving the server, and `created_at` is not something any
/// current endpoint needs.
#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub role: &'static str,
}

impl From<&UserRecord> for UserView {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.as_str().to_owned(),
            role: user.role.as_str(),
        }
    }
}

/// Turns a limiter decision into the one response every rate limit
/// produces.
///
/// Identical whichever bucket refused, and it never says which. "This
/// account is rate limited" would be an account oracle, and a far
/// cheaper one than timing a password check.
fn rate_limited(decision: Decision) -> Option<ApiError> {
    match decision {
        Decision::Allowed => None,
        Decision::Limited { retry_after } => Some(
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests; please try again later",
            )
            .retry_after(retry_after),
        ),
    }
}
