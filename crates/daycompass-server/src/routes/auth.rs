//! `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`,
//! `GET /api/v1/auth/me` and `POST /api/v1/auth/password`.
//!
//! These handlers parse input, call [`crate::auth`], and map the result
//! onto HTTP. The rules - no account enumeration, how a session expires,
//! what the cookie looks like, what a password change revokes - all live
//! in the service layer, so the dashboard reuses them
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
use utoipa::ToSchema;

use crate::auth::cookie;
use crate::auth::login::{self, LoginError, LoginOutcome};
use crate::auth::password::{HashError, PasswordPolicyError};
use crate::auth::secret::SecretString;
use crate::auth::session;
use crate::auth::time::UnixTime;
use crate::auth::users::{self, PasswordChangeError};
use crate::error::{ApiError, ErrorKind};
use crate::ratelimit::UsernameKey;
use crate::routes::{rate_limited, SessionContext, UserView};
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    username: String,
    #[schema(value_type = String, format = Password)]
    password: SecretString,
}

/// What a successful login returns.
///
/// The session token is not in here - it goes into the `__Host-dcs`
/// cookie, so page JavaScript never has to hold it. The CSRF token is,
/// because the client has to echo it back in a header, which is exactly
/// what a hostile page cannot do.
#[derive(Serialize, ToSchema)]
struct SessionResponse {
    user: UserView,
    csrf_token: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "sessions",
    operation_id = "login",
    summary = "Log in; sets the session cookie",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in. The session cookie is in `Set-Cookie`; send `csrf_token` as `X-CSRF-Token` on writes.", body = SessionResponse),
        (status = 401, description = "`invalid_credentials`, whatever was wrong.", body = crate::error::ErrorBody),
        (status = 503, description = "`server_busy`. Honour `Retry-After`.", body = crate::error::ErrorBody),
    )
)]
pub async fn log_in(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Response {
    match attempt_login(&state, &request.username, request.password).await {
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
        Err(error) => error.into_response(),
    }
}

/// One login attempt, from the per-username bucket to the error the
/// caller is shown.
///
/// Shared by the JSON route above and the dashboard's login form, so
/// both spend the *same* buckets and refuse in the same way: a second
/// login route with its own budget would double what a guessing attack
/// gets to try. Both routes' inventory entries attach the per-address
/// bucket; this is the per-username one, which only a handler can
/// check because its key is in the body.
pub(super) async fn attempt_login(
    state: &AppState,
    username: &str,
    password: SecretString,
) -> Result<LoginOutcome, ApiError> {
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
            .check(UsernameKey::new(username), now),
    ) {
        return Err(error);
    }

    // Only now is Argon2 work reached: the hasher's semaphore and its
    // wait timeout are the third and last line of defence.
    let result = login::log_in(
        &state.pool,
        &state.hasher,
        &state.decoy_password_hash,
        state.session_policy,
        username,
        password,
        now,
    )
    .await;

    match result {
        Ok(outcome) => Ok(outcome),

        Err(LoginError::InvalidCredentials) => {
            login::log_failure();
            Err(invalid_credentials())
        }

        Err(LoginError::Hash(HashError::Busy)) => {
            Err(ApiError::of(ErrorKind::ServerBusy).retry_after(state.hasher.wait_timeout()))
        }

        Err(err) => {
            tracing::error!(error = %err, "login failed unexpectedly");
            Err(ApiError::of(ErrorKind::InternalError))
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
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "sessions",
    operation_id = "logout",
    summary = "End this session; clears the cookie",
    responses(
        (status = 204, description = "Logged out."),
    )
)]
pub async fn log_out(State(state): State<AppState>, session_context: SessionContext) -> Response {
    if let Err(error) = end_session(&state, &session_context).await {
        return error.into_response();
    }

    // The cookie is cleared as well as the row deleted. Deleting the row
    // is what actually ends the session; clearing the cookie just stops
    // the client from sending a token that can no longer work.
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, cookie::clear())],
    )
        .into_response()
}

/// Ends the caller's session server side. Shared with the dashboard's
/// logout, which clears the cookie the same way afterwards.
pub(super) async fn end_session(
    state: &AppState,
    session_context: &SessionContext,
) -> Result<(), ApiError> {
    let auth = session_context.auth();

    if let Err(err) = session::end(&state.pool, &auth.session.id).await {
        tracing::error!(error = %err, "could not delete a session on logout");
        return Err(ApiError::of(ErrorKind::InternalError));
    }

    tracing::info!(user_id = %auth.user.id, "logout");
    Ok(())
}

/// Reports who the caller is, and hands back the CSRF token.
///
/// Returning the CSRF token from a `GET` is what makes it survive a
/// reload or a new tab: the value is derived from the session cookie, so
/// any tab holding the cookie can ask for it. Same-origin policy keeps
/// another origin from reading this response.
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "sessions",
    operation_id = "me",
    summary = "The account behind this session, and its CSRF token",
    responses(
        (status = 200, description = "The current account.", body = SessionResponse),
    )
)]
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

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    #[schema(value_type = String, format = Password)]
    current_password: SecretString,
    #[schema(value_type = String, format = Password)]
    new_password: SecretString,
}

/// What a successful password change reports.
#[derive(Serialize, ToSchema)]
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
#[utoipa::path(
    post,
    path = "/api/v1/auth/password",
    tag = "sessions",
    operation_id = "change_password",
    summary = "Change your own password; ends every other session",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Changed.", body = PasswordChangeResponse),
        (status = 400, description = "`invalid_password`.", body = crate::error::ErrorBody),
        (status = 403, description = "`invalid_current_password`.", body = crate::error::ErrorBody),
        (status = 409, description = "`password_change_conflict`: another change won the race.", body = crate::error::ErrorBody),
        (status = 503, description = "`server_busy`. Honour `Retry-After`.", body = crate::error::ErrorBody),
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    session_context: SessionContext,
    Json(request): Json<ChangePasswordRequest>,
) -> Response {
    match attempt_password_change(
        &state,
        &session_context,
        request.current_password,
        request.new_password,
    )
    .await
    {
        Ok(other_sessions_ended) => (
            StatusCode::OK,
            Json(PasswordChangeResponse {
                other_sessions_ended,
            }),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

/// Changes the caller's own password and returns how many *other*
/// sessions were ended. Shared with the dashboard's account page, which
/// is limited by the same per-session bucket, so both refuse alike.
pub(super) async fn attempt_password_change(
    state: &AppState,
    session_context: &SessionContext,
    current_password: SecretString,
    new_password: SecretString,
) -> Result<u64, ApiError> {
    let auth = session_context.auth();

    let result = users::change_own_password(
        &state.pool,
        &state.hasher,
        &auth.user.id,
        &auth.session.id,
        current_password,
        new_password,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(report) => Ok(report.other_sessions_ended),

        Err(PasswordChangeError::CurrentPasswordInvalid) => {
            // No username, no password, no indication of which account
            // in the message - only the id, and only in the log.
            tracing::info!(user_id = %auth.user.id, "password change refused");
            Err(ApiError::of(ErrorKind::CurrentPasswordInvalid))
        }

        Err(PasswordChangeError::InvalidNewPassword(reason)) => Err(ApiError::of(match reason {
            PasswordPolicyError::Blank => ErrorKind::PasswordBlank,
            PasswordPolicyError::Length => ErrorKind::PasswordLength,
        })),

        Err(PasswordChangeError::Conflict) => Err(ApiError::of(ErrorKind::PasswordChangeConflict)),

        // The account was deleted between the session being resolved
        // and the change being applied. The caller is no longer
        // authenticated by anything.
        Err(PasswordChangeError::AccountGone) => Err(ApiError::of(ErrorKind::Unauthenticated)),

        Err(PasswordChangeError::Hash(HashError::Busy)) => {
            Err(ApiError::of(ErrorKind::ServerBusy).retry_after(state.hasher.wait_timeout()))
        }

        Err(err) => {
            tracing::error!(error = %err, "changing a password failed");
            Err(ApiError::of(ErrorKind::InternalError))
        }
    }
}
