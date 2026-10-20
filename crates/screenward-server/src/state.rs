//! Shared application state.
//!
//! Handlers receive this and nothing else. It holds the database pool
//! and the long-lived services built from configuration at startup, so
//! that nothing security-relevant is re-derived per request and nothing
//! reads the environment after startup.

use axum::extract::FromRef;
use sqlx::SqlitePool;

use crate::auth::password::Hasher;
use crate::config::Config;

/// Cloned once per request by axum. Every field is cheap to clone: the
/// pool and the hasher are handles to shared state, not copies of it,
/// which is what keeps the Argon2 concurrency cap global.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub hasher: Hasher,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: &Config) -> Self {
        Self {
            pool,
            hasher: Hasher::new(
                config.argon2,
                config.argon2_max_concurrent,
                config.argon2_wait_timeout,
            ),
        }
    }
}

/// Lets a handler ask for just the pool with `State<SqlitePool>`.
impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
