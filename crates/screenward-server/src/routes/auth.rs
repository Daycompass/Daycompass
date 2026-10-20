//! `POST /api/v1/auth/login`, `POST /api/v1/auth/logout` and
//! `GET /api/v1/auth/me`.
//!
//! These handlers parse input, call [`crate::auth`], and map the result
//! onto HTTP. The rules - no account enumeration, how a session expires,
//! what the cookie looks like - all live in the service layer, so the
//! later dashboard can reuse them unchanged.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::cookie;
use crate::auth::extract::AuthSession;
use crate::auth::login::{self, LoginError};
use crate::auth::password::HashError;
use crate::auth::secret::SecretString;
use crate::auth::session;
use crate::auth::time::UnixTime;
use crate::error::ApiError;
use crate::routes::UserView;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: SecretString,
}

/// What a successful login returns.
///
/// The session token is not in here - it goes into the `__Host-sws`
/// cookie, so page JavaScript never has to hold it. The CSRF token is,
/// because the client has to echo it back in a header, which is exactly
/// what a hostile page cannot do.
#[derive(Serialize)]
struct SessionResponse {
    user: UserView,
    csrf_token: String,
}

pub async fn log_in(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Response {
    let result = login::log_in(
        &state.pool,
        &state.hasher,
        &state.decoy_password_hash,
        state.session_policy,
        &request.username,
        request.password,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(outcome) => {
            let body = SessionResponse {
                user: UserView::from(&outcome.user),
                csrf_token: outcome.session.csrf_token,
            };
            (
                StatusCode::OK,
                [(
                    header::SET_COOKIE,
                    cookie::set(outcome.session.token.expose()),
                )],
                Json(body),
            )
                .into_response()
        }

        Err(LoginError::InvalidCredentials) => {
            login::log_failure();
            invalid_credentials().into_response()
        }

        Err(LoginError::Hash(HashError::Busy)) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "the server is too busy to process this request",
        )
        .retry_after(state.hasher.wait_timeout())
        .into_response(),

        Err(err) => {
            tracing::error!(error = %err, "login failed unexpectedly");
            ApiError::from_status(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

/// The one response a failed login produces.
///
/// Identical for a wrong password, an unknown account, and input that
/// could not name an account at all, so the response body and status
/// reveal nothing about which accounts exist.
fn invalid_credentials() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credentials",
        "the username or password is incorrect",
    )
}

/// Ends the session server side and clears the cookie.
///
/// Taking [`AuthSession`] is what makes this require a valid CSRF token:
/// the extractor checks it before the handler runs.
pub async fn log_out(State(state): State<AppState>, auth: AuthSession) -> Response {
    if let Err(err) = session::end(&state.pool, &auth.session.id).await {
        tracing::error!(error = %err, "could not delete a session on logout");
        return ApiError::from_status(StatusCode::INTERNAL_SERVER_ERROR).into_response();
    }

    tracing::info!(user_id = %auth.user.id, "logout");
    // The cookie is cleared as well as the row deleted. Deleting the row
    // is what actually ends the session; clearing the cookie just stops
    // the client from sending a token that can no longer work.
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, cookie::clear())],
    )
        .into_response()
}

/// Reports who the caller is, and hands back the CSRF token.
///
/// Returning the CSRF token from a `GET` is what makes it survive a
/// reload or a new tab: the value is derived from the session cookie, so
/// any tab holding the cookie can ask for it. Same-origin policy keeps
/// another origin from reading this response.
pub async fn me(auth: AuthSession) -> Response {
    let body = SessionResponse {
        user: UserView::from(&auth.user),
        csrf_token: auth.csrf_token(),
    };
    (StatusCode::OK, Json(body)).into_response()
}
