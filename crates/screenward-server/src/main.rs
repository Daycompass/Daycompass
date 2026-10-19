//! Screenward backend entry point: loads configuration, opens and
//! migrates the database, and serves the HTTP API until it is told to
//! shut down.
#![forbid(unsafe_code)]

use screenward_server::config::Config;

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            // Config errors never contain values (see config.rs), so this
            // is safe to print before logging is even set up.
            eprintln!("screenward-server: invalid configuration: {err}");
            std::process::exit(1);
        }
    };

    screenward_server::init_tracing(&config.log_level);
    tracing::info!(config = ?config, "starting screenward-server");

    let pool = match screenward_server::setup_db(&config).await {
        Ok(pool) => pool,
        Err(err) => {
            tracing::error!(error = %err, "failed to set up the database");
            std::process::exit(1);
        }
    };

    let app = screenward_server::build_app(pool);

    let listener = match tokio::net::TcpListener::bind(config.bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, addr = %config.bind_addr, "failed to bind");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %config.bind_addr, "listening");

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(screenward_server::shutdown_signal())
        .await
    {
        tracing::error!(error = %err, "server error");
        std::process::exit(1);
    }

    tracing::info!("shut down cleanly");
}
