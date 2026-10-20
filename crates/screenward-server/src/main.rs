//! Screenward backend entry point: loads configuration, opens and
//! migrates the database, and serves the HTTP API until it is told to
//! shut down.
#![forbid(unsafe_code)]

use std::io::Write;

use screenward_server::auth::setup;
use screenward_server::auth::time::UnixTime;
use screenward_server::config::Config;
use screenward_server::state::AppState;

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

    // While no admin exists the instance cannot authenticate anybody,
    // so it issues a bootstrap token and prints it. Any token from an
    // earlier run is invalidated here, so only the line printed by this
    // start is live.
    match setup::issue_token_if_unprovisioned(&pool, UnixTime::now()).await {
        Ok(Some(token)) => {
            print_setup_instructions(&setup::setup_instructions(
                &token,
                config.public_url.as_str(),
            ));
        }
        // The normal case from the second start onwards.
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "failed to prepare the first-time setup token");
            std::process::exit(1);
        }
    }

    let app = screenward_server::build_app(AppState::new(pool, &config));

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

/// Writes the setup instructions straight to stdout, not through
/// `tracing`.
///
/// Three reasons: a log level must never be able to hide it, JSON log
/// output would bury the token inside a field an operator then has to
/// dig out, and the value must not pass through the logging pipeline at
/// all. Flushed explicitly, because a container's stdout may be block
/// buffered and this line has to appear immediately.
fn print_setup_instructions(message: &str) {
    let mut stdout = std::io::stdout().lock();
    // Nothing useful can be done if stdout is gone; the server should
    // still come up.
    let _ = writeln!(stdout, "{message}");
    let _ = stdout.flush();
}
