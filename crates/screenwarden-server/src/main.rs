//! Screenwarden backend entry point: loads configuration, opens and
//! migrates the database, and serves the HTTP API until it is told to
//! shut down.
#![forbid(unsafe_code)]

use std::io::Write;

use screenwarden_server::auth::setup;
use screenwarden_server::auth::time::UnixTime;
use screenwarden_server::config::{self, Config};
use screenwarden_server::state::AppState;

#[tokio::main]
async fn main() {
    // Checked before anything else, including `Config::from_env`: a
    // stray `SCREENWARD_*` variable must never be silently ignored in
    // favor of a default (loopback bind, no trusted proxies, the
    // compiled-in rate limits).
    if let Err(err) = config::check_for_legacy_env() {
        eprintln!("screenwarden-server: {err}");
        std::process::exit(1);
    }

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            // Config errors never contain values (see config.rs), so this
            // is safe to print before logging is even set up.
            eprintln!("screenwarden-server: invalid configuration: {err}");
            std::process::exit(1);
        }
    };

    screenwarden_server::init_tracing(&config.log_level);
    tracing::info!(config = ?config, "starting screenwarden-server");

    let pool = match screenwarden_server::setup_db(&config).await {
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

    let state = match AppState::new(pool.clone(), &config).await {
        Ok(state) => state,
        Err(err) => {
            // Argon2 cannot run at all. Better to refuse to start than
            // to discover this at the first login attempt.
            tracing::error!(error = %err, "failed to initialize password hashing");
            std::process::exit(1);
        }
    };

    screenwarden_server::spawn_cleanup_task(pool, state.session_policy);

    let app = screenwarden_server::build_app(state);

    let listener = match tokio::net::TcpListener::bind(config.bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, addr = %config.bind_addr, "failed to bind");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %config.bind_addr, "listening");

    // `serve` is what attaches the peer address to each request; see
    // its documentation. Previously this called `axum::serve` directly
    // and therefore attached nothing, which made every request needing
    // a client address fail closed with 500.
    if let Err(err) =
        screenwarden_server::serve(listener, app, screenwarden_server::shutdown_signal()).await
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
