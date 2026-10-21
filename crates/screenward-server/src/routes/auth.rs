//! `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`,
//! `GET /api/v1/auth/me` and `POST /api/v1/auth/password`.
//!
//! These handlers parse input, call [`crate::auth`], and map the result
//! onto HTTP. The rules - no account enumeration, how a session expires,
//! what the cookie looks like, what a password change revokes - all live
//! in the service layer, so the later dashboard can reuse them
//! unchanged.
//!
//! Every rate limit on these routes except one is attached from the
//! route's entry in [`crate::routes::INVENTORY`]. The exception is the
//! per-username login bucket, whose key is a field of the request body:
//! a layer cannot see the body without buffering it, so [`log_in`] is
//! the first place that key exists.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::cookie;
use crate::auth::login::{self, LoginError};
use crate::auth::password::{HashError, PasswordPolicyError};
use crate::auth::secret::SecretString;
use crate::auth::session;
use crate::auth::time::UnixTime;
use crate::auth::users::{self, PasswordChangeError};
use crate::error::{ApiError, ErrorKind};
use crate::ratelimit::UsernameKey;
use crate::routes::{rate_limited, SessionContext, UserView};
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
    let now = UnixTime::now();

    // The per-address bucket has already been checked by the layer the
    // route's inventory entry attached, which is what caps how many
    // distinct usernames one client can even introduce before anything
    // bounds them.
    //
    // This is the per-username bucket, which protects one account
    // against a guessing attack spread across many addresses.
    if let Some(error) = rate_limited(
        state
            .limits
            .login_username
            .check(UsernameKey::new(&request.username), now),
    ) {
        return error.into_response();
    }

    // Only now is Argon2 work reached: the hasher's semaphore and its
    // wait timeout are the third and last line of defence.
    let result = login::log_in(
        &state.pool,
        &state.hasher,
        &state.decoy_password_hash,
        state.session_policy,
        &request.username,
        request.password,
        now,
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

        Err(LoginError::Hash(HashError::Busy)) => ApiError::of(ErrorKind::ServerBusy)
            .retry_after(state.hasher.wait_timeout())
            .into_response(),

        Err(err) => {
            tracing::error!(error = %err, "login failed unexpectedly");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

/// The one response a failed login produces.
///
/// Identical for a wrong password, an unknown account, and input that
/// could not name an account at all, so the response body and status
/// reveal nothing about which accounts exist.
fn invalid_credentials() -> ApiError {
    ApiError::of(ErrorKind::InvalidCredentials)
}

/// Ends the session server side and clears the cookie.
///
/// The session, the CSRF check and the `Origin` check all come from the
/// route's inventory entry; [`SessionContext`] is how this handler reads
/// the result, and it fails closed if no access layer ran.
pub async fn log_out(State(state): State<AppState>, session_context: SessionContext) -> Response {
    let auth = session_context.auth();

    if let Err(err) = session::end(&state.pool, &auth.session.id).await {
        tracing::error!(error = %err, "could not delete a session on logout");
        return ApiError::of(ErrorKind::InternalError).into_response();
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
pub async fn me(session_context: SessionContext) -> Response {
    let auth = session_context.auth();
    let body = SessionResponse {
        // Both read from the account row this request resolved, so a
        // role changed a moment ago is reported correctly here.
        user: UserView::from(&auth.user),
        csrf_token: auth.csrf_token(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    current_password: SecretString,
    new_password: SecretString,
}

/// What a successful password change reports.
#[derive(Serialize)]
struct PasswordChangeResponse {
    /// How many other sessions of this account were ended. The one that
    /// made the request is not counted, and still works.
    other_sessions_ended: u64,
}

/// Changes the caller's own password.
///
/// Only ever the caller's own: there is no account parameter, so no
/// request can aim this at somebody else. An admin resetting another
/// account's password is deliberately not part of this - it would need
/// its own endpoint and its own decisions about what to revoke.
///
/// The per-session rate limit, the CSRF check and the `Origin` check are
/// attached from the route's inventory entry, and the limit is counted
/// before this handler runs - that is, before the Argon2 semaphore is
/// reached.
pub async fn change_password(
    State(state): State<AppState>,
    session_context: SessionContext,
    Json(request): Json<ChangePasswordRequest>,
) -> Response {
    let auth = session_context.auth();

    let result = users::change_own_password(
        &state.pool,
        &state.hasher,
        &auth.user.id,
        &auth.session.id,
        request.current_password,
        request.new_password,
    )
    .await;

    match result {
        Ok(report) => (
            StatusCode::OK,
            Json(PasswordChangeResponse {
                other_sessions_ended: report.other_sessions_ended,
            }),
        )
            .into_response(),

        Err(PasswordChangeError::CurrentPasswordInvalid) => {
            // No username, no password, no indication of which account
            // in the message - only the id, and only in the log.
            tracing::info!(user_id = %auth.user.id, "password change refused");
            ApiError::of(ErrorKind::CurrentPasswordInvalid).into_response()
        }

        Err(PasswordChangeError::InvalidNewPassword(reason)) => ApiError::of(match reason {
            PasswordPolicyError::Blank => ErrorKind::PasswordBlank,
            PasswordPolicyError::Length => ErrorKind::PasswordLength,
        })
        .into_response(),

        Err(PasswordChangeError::Conflict) => {
            ApiError::of(ErrorKind::PasswordChangeConflict).into_response()
        }

        // The account was deleted between the session being resolved
        // and the change being applied. The caller is no longer
        // authenticated by anything.
        Err(PasswordChangeError::AccountGone) => {
            ApiError::of(ErrorKind::Unauthenticated).into_response()
        }

        Err(PasswordChangeError::Hash(HashError::Busy)) => ApiError::of(ErrorKind::ServerBusy)
            .retry_after(state.hasher.wait_timeout())
            .into_response(),

        Err(err) => {
            tracing::error!(error = %err, "changing a password failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
