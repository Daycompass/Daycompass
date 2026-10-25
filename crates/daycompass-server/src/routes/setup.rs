//! `POST /api/v1/setup` - redeem the bootstrap token, create the first
//! admin.
//!
//! This handler only parses input, calls the service layer, and maps the
//! result onto HTTP. The rules live in [`crate::auth::setup`], so the
//! later dashboard can drive the same flow without restating any of
//! them.
//!
//! No CSRF token and no `Origin` check here, unlike every other
//! state-changing endpoint: this request carries no cookie, so there is
//! no ambient credential for a hostile page to ride on. Its protection
//! is the unguessable setup token, plus the per-address rate limit -
//! which is attached from the route's entry in
//! [`crate::routes::INVENTORY`], along with the two exemptions above.
//! The token is unguessable, so that limit bounds noise rather than
//! guessing, but it also stops an unauthenticated caller from spending
//! Argon2 work at will while setup is still open.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::password::{HashError, PasswordPolicyError};
use crate::auth::secret::SecretString;
use crate::auth::setup::{self, SetupError};
use crate::auth::store::UserRecord;
use crate::auth::time::UnixTime;
use crate::auth::username::UsernameError;
use crate::error::{ApiError, ErrorKind};
use crate::routes::UserView;
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
pub struct SetupRequest {
    /// The token printed to stdout at startup.
    #[schema(value_type = String, format = Password)]
    setup_token: SecretString,
    username: String,
    #[schema(value_type = String, format = Password)]
    password: SecretString,
}

#[derive(Serialize, ToSchema)]
struct SetupResponse {
    user: UserView,
}

#[utoipa::path(
    post,
    path = "/api/v1/setup",
    tag = "setup",
    operation_id = "setup",
    summary = "Create the first admin with the one-time setup token",
    request_body = SetupRequest,
    responses(
        (status = 201, description = "The first admin exists.", body = SetupResponse),
        (status = 400, description = "`invalid_username` or `invalid_password`.", body = crate::error::ErrorBody),
        (status = 401, description = "`invalid_setup_token`.", body = crate::error::ErrorBody),
        (status = 404, description = "Setup is already complete; same answer as a route that does not exist.", body = crate::error::ErrorBody),
        (status = 503, description = "`server_busy`: password hashing capacity exhausted. Honour `Retry-After`.", body = crate::error::ErrorBody),
    )
)]
pub async fn create_first_admin(
    State(state): State<AppState>,
    Json(request): Json<SetupRequest>,
) -> Response {
    match attempt_setup(
        &state,
        &request.setup_token,
        &request.username,
        request.password,
    )
    .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(SetupResponse {
                user: UserView::from(&user),
            }),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

/// Redeems the setup token and creates the first admin. Shared with the
/// dashboard's setup page; the order of checks is the service's, so the
/// 404 once an admin exists holds for both.
pub(super) async fn attempt_setup(
    state: &AppState,
    setup_token: &SecretString,
    username: &str,
    password: SecretString,
) -> Result<UserRecord, ApiError> {
    let result = setup::complete_setup(
        &state.pool,
        &state.hasher,
        setup_token,
        username,
        password,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(user) => {
            tracing::info!(user_id = %user.id, "first admin account created");
            Ok(user)
        }
        Err(err) => Err(to_api_error(err, state)),
    }
}

/// Whether the first admin exists, for the setup page's `GET`, which
/// must answer 404 exactly when `POST` would.
pub(super) async fn setup_is_complete(state: &AppState) -> Result<bool, ApiError> {
    setup::is_complete(&state.pool).await.map_err(|err| {
        tracing::error!(error = %err, "checking whether setup is complete failed");
        ApiError::of(ErrorKind::InternalError)
    })
}

fn to_api_error(err: SetupError, state: &AppState) -> ApiError {
    match err {
        // Byte-for-byte the response an unknown route gives, so a
        // provisioned instance is indistinguishable from one that never
        // had this endpoint.
        SetupError::AlreadyCompleted => ApiError::of(ErrorKind::NotFound),

        SetupError::InvalidToken => ApiError::of(ErrorKind::InvalidSetupToken),

        // The policies are public rules, so naming which one failed is
        // useful rather than leaky. Each variant maps to one fixed
        // message; the policy error's own `Display` goes to the log,
        // never to the client.
        SetupError::InvalidUsername(reason) => ApiError::of(match reason {
            UsernameError::Length => ErrorKind::UsernameLength,
            UsernameError::Charset => ErrorKind::UsernameCharset,
        }),
        SetupError::InvalidPassword(reason) => ApiError::of(match reason {
            PasswordPolicyError::Blank => ErrorKind::PasswordBlank,
            PasswordPolicyError::Length => ErrorKind::PasswordLength,
        }),

        // Shed, not refused: the client should come back.
        SetupError::Hash(HashError::Busy) => {
            ApiError::of(ErrorKind::ServerBusy).retry_after(state.hasher.wait_timeout())
        }

        // Everything left is an internal fault. The detail is logged,
        // never returned.
        SetupError::Hash(_) | SetupError::Store(_) | SetupError::Rng(_) => {
            tracing::error!(error = %err, "setup failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}
