//! Route definitions. Middleware lives in [`crate::middleware`], applied
//! once over the whole router in [`crate::build_app`].

mod health;

use axum::routing::get;
use axum::Router;
use sqlx::SqlitePool;

use crate::error::not_found;

pub fn router(pool: SqlitePool) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .fallback(not_found)
        .with_state(pool)
}
