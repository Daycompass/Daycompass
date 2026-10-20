//! Route definitions and the HTTP-facing views of domain types.
//!
//! Handlers here parse input, call the service layer in
//! [`crate::auth`], and map results onto status codes. No rules live in
//! this module: per `CLAUDE.md`, the JSON handlers and the later HTML
//! handlers must share one service layer.

mod health;
mod setup;

use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;

use crate::auth::store::UserRecord;
use crate::error::not_found;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/api/v1/setup", post(setup::create_first_admin))
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
