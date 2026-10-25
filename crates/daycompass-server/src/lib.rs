//! Daycompass backend library.
//!
//! Exposes the pieces `main.rs` wires together, and lets integration
//! tests under `tests/` exercise them without going through a spawned
//! process. No users, auth, or domain tables yet - see `CLAUDE.md`.
#![forbid(unsafe_code)]

pub mod auth;
pub mod categories;
pub mod clientip;
pub mod config;
pub mod db;
pub mod devices;
pub mod error;
pub mod events;
pub mod legacy;
pub mod middleware;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod stats;

use axum::Router;
use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;

use config::Config;
use state::AppState;

/// Builds the full axum app (routes plus middleware) over `state`.
pub fn build_app(state: AppState) -> Router {
    middleware::apply(routes::router(state))
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

/// Serves `app` on `listener` until `shutdown` resolves.
///
/// The `into_make_service_with_connect_info` call lives here, in one
/// place, because it is what puts the peer address on every request.
/// Without it the `ClientAddr` extractor fails closed and nothing can
/// be rate limited - a wiring mistake no handler test can catch,
/// because handler tests inject the peer address themselves. That is
/// why this function exists as a seam rather than being inlined in
/// `main`, and why `tests/serve_over_tcp.rs` drives it over a real
/// socket.
pub async fn serve<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// How often the background sweep runs.
///
/// An hour is frequent enough that expired rows do not accumulate and
/// infrequent enough to be invisible in load. Expiry itself does not
/// depend on this task: a session is also checked, and deleted, on every
/// request that presents it. This only catches the ones nobody comes
/// back for.
const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Spawns the task that deletes expired sessions, spent setup tokens
/// and dead pairing codes.
///
/// Runs one sweep immediately, so a restart cleans up whatever expired
/// while the process was down, then on a fixed interval. A failed sweep
/// is logged and retried at the next tick rather than ending the task,
/// since a transient database error must not silently stop cleanup for
/// the lifetime of the process.
///
/// Two sweeps, not one: [`auth::session::sweep_expired`] owns the auth
/// tables and [`devices::service::sweep_expired_codes`] owns the
/// pairing codes. Each is reported separately and a failure in one
/// does not skip the other, so a problem with one table cannot quietly
/// stop the other from being collected.
///
/// Expiry does not depend on this task. A session is checked and
/// deleted on every request that presents it, and a pairing code's
/// `expires_at` is compared inside the redemption transaction, so a
/// code that outlives the sweep is still unusable. This only reclaims
/// the rows nobody comes back for.
pub fn spawn_cleanup_task(pool: SqlitePool, policy: auth::session::SessionPolicy) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            ticker.tick().await;
            let now = auth::time::UnixTime::now();

            match auth::session::sweep_expired(&pool, policy, now).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "cleaned up expired auth rows"),
                Err(err) => tracing::error!(error = %err, "the auth cleanup sweep failed"),
            }

            match devices::service::sweep_expired_codes(&pool, now).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "cleaned up dead pairing codes"),
                Err(err) => {
                    tracing::error!(error = %err, "the pairing code cleanup sweep failed");
                }
            }
        }
    });
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
