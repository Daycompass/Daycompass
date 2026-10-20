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
//! is the unguessable setup token, plus the per-address rate limit.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::password::HashError;
use crate::auth::secret::SecretString;
use crate::auth::setup::{self, SetupError};
use crate::auth::time::UnixTime;
use crate::error::ApiError;
use crate::routes::UserView;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SetupRequest {
    /// The token printed to stdout at startup.
    setup_token: SecretString,
    username: String,
    password: SecretString,
}

#[derive(Serialize)]
struct SetupResponse {
    user: UserView,
}

pub async fn create_first_admin(
    State(state): State<AppState>,
    Json(request): Json<SetupRequest>,
) -> Response {
    let result = setup::complete_setup(
        &state.pool,
        &state.hasher,
        &request.setup_token,
        &request.username,
        request.password,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(user) => {
            tracing::info!(user_id = %user.id, "first admin account created");
            (
                StatusCode::CREATED,
                Json(SetupResponse {
                    user: UserView::from(&user),
                }),
            )
                .into_response()
        }
        Err(err) => to_api_error(err, &state).into_response(),
    }
}

fn to_api_error(err: SetupError, state: &AppState) -> ApiError {
    match err {
        // Byte-for-byte the response an unknown route gives, so a
        // provisioned instance is indistinguishable from one that never
        // had this endpoint.
        SetupError::AlreadyCompleted => ApiError::from_status(StatusCode::NOT_FOUND),

        SetupError::InvalidToken => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_setup_token",
            "the setup token is not valid",
        ),

        // The policies are public rules, so naming which one failed is
        // useful rather than leaky. Neither message echoes the input.
        SetupError::InvalidUsername(reason) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_username",
            reason.to_string(),
        ),
        SetupError::InvalidPassword(reason) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            reason.to_string(),
        ),

        // Shed, not refused: the client should come back.
        SetupError::Hash(HashError::Busy) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_busy",
            "the server is too busy to process this request",
        )
        .retry_after(state.hasher.wait_timeout()),

        // Everything left is an internal fault. The detail is logged,
        // never returned.
        SetupError::Hash(_) | SetupError::Store(_) | SetupError::Rng(_) => {
            tracing::error!(error = %err, "setup failed");
            ApiError::from_status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
