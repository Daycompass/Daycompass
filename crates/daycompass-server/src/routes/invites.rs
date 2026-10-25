//! `POST /api/v1/invites/redeem`.
//!
//! This handler only parses input, calls the service layer, and maps
//! the result onto HTTP. The rules live in [`crate::auth::invite`], so
//! the later dashboard can drive the same flow.
//!
//! No CSRF token here: the request carries no cookie, so there is no
//! session for a token to be checked against. The `Origin` check stays
//! on, unlike setup and pairing - see the inventory entry in
//! [`crate::routes::INVENTORY`] for why - and the per-address and
//! global rate limits are attached from that same entry.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::auth::invite::{self, RedeemError};
use crate::auth::password::{HashError, PasswordPolicyError};
use crate::auth::secret::SecretString;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RedeemInviteRequest {
    /// The token handed over by an admin.
    #[schema(value_type = String, format = Password)]
    invite_token: SecretString,
    #[schema(value_type = String, format = Password)]
    new_password: SecretString,
}

/// Redeems an invite token and sets the account's first password.
///
/// No session is created: the response is `204 No Content`, and the
/// person logs in normally afterwards through `POST /api/v1/auth/login`.
#[utoipa::path(
    post,
    path = "/api/v1/invites/redeem",
    tag = "accounts",
    operation_id = "redeem_invite",
    summary = "Redeem an invite by choosing a password",
    request_body = RedeemInviteRequest,
    responses(
        (status = 204, description = "Redeemed; the account is active. Log in next."),
        (status = 400, description = "`invalid_password`.", body = crate::error::ErrorBody),
        (status = 401, description = "`invalid_invite_token`.", body = crate::error::ErrorBody),
        (status = 503, description = "`server_busy`. Honour `Retry-After`.", body = crate::error::ErrorBody),
    )
)]
pub async fn redeem(
    State(state): State<AppState>,
    Json(request): Json<RedeemInviteRequest>,
) -> Response {
    let result = invite::redeem(
        &state.pool,
        &state.hasher,
        &request.invite_token,
        request.new_password,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => to_api_error(err, &state).into_response(),
    }
}

fn to_api_error(err: RedeemError, state: &AppState) -> ApiError {
    match err {
        // Unknown, expired, malformed or already used all collapse to
        // this one response - see `RedeemError::Rejected`.
        RedeemError::Rejected => ApiError::of(ErrorKind::InvalidInviteToken),

        // A public rule, so naming which one failed is useful rather
        // than leaky.
        RedeemError::InvalidPassword(reason) => ApiError::of(match reason {
            PasswordPolicyError::Blank => ErrorKind::PasswordBlank,
            PasswordPolicyError::Length => ErrorKind::PasswordLength,
        }),

        // Shed, not refused: the client should come back.
        RedeemError::Hash(HashError::Busy) => {
            ApiError::of(ErrorKind::ServerBusy).retry_after(state.hasher.wait_timeout())
        }

        RedeemError::Hash(_) | RedeemError::Store(_) => {
            tracing::error!(error = %err, "redeeming an invite failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}
