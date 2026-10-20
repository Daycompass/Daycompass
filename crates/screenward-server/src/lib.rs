//! Screenward backend library.
//!
//! Exposes the pieces `main.rs` wires together, and lets integration
//! tests under `tests/` exercise them without going through a spawned
//! process. No users, auth, or domain tables yet - see `CLAUDE.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;

use axum::Router;
use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;

use config::Config;

/// Builds the full axum app (routes plus middleware) over `pool`.
pub fn build_app(pool: SqlitePool) -> Router {
    middleware::apply(routes::router(pool))
}

/// Initializes JSON structured logging at the level given by
/// `log_level` (already validated by [`Config::from_env`]).
pub fn init_tracing(log_level: &str) {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::new(log_level))
        .init();
}

/// Opens the database (creating/hardening the data directory as
/// needed), runs migrations, and returns the pool.
pub async fn setup_db(config: &Config) -> Result<SqlitePool, db::DbError> {
    let target = db::DbTarget::File {
        data_dir: config.data_dir.clone(),
    };
    let pool = db::connect(&target).await?;
    db::migrate(&pool).await?;
    Ok(pool)
}

/// Waits for Ctrl-C or, on Unix, SIGTERM - whichever comes first - so
/// `axum::serve(..).with_graceful_shutdown(shutdown_signal())` lets
/// in-flight requests finish instead of dropping them.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install the Ctrl-C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install the SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received Ctrl-C, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
