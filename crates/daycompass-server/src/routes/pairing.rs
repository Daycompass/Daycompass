//! `POST /api/v1/pairing-codes` - an owner mints a code.
//! `POST /api/v1/pair` - a native client redeems one.
//!
//! Two halves of one flow with opposite threat models, which is why
//! they are different kinds of route in the inventory.
//!
//! Minting is an ordinary cookie route: a logged-in person asks their
//! dashboard for a code, so it carries a session, a CSRF token and the
//! `Origin` check.
//!
//! Redeeming is `Access::BodySecret` and exempt from the `Origin`
//! check. A native client sends no `Origin` and has no cookie; the
//! request authenticates itself with the code, and the token it gets
//! back goes into the client's own storage rather than a cookie jar.
//! That exemption is a named property of the entry, not a flag set
//! here - see [`crate::routes::OriginRule`].
//!
//! Thin adapters: every rule lives in [`crate::devices::service`].

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::secret::SecretString;
use crate::auth::time::UnixTime;
use crate::devices::name::DeviceNameError;
use crate::devices::service::{self, CreateCodeError, PairError};
use crate::error::{ApiError, ErrorKind};
use crate::routes::{DeviceView, SessionContext};
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
struct NewCodeResponse {
    /// Grouped for reading aloud: `XXXXX-XXXXX`. Shown once; the
    /// server stores only a hash and cannot show it again.
    pairing_code: String,
    expires_at: i64,
    /// So a client can tell a person how long they have without
    /// having to trust its own clock against the server's.
    server_time: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/pairing-codes",
    tag = "devices",
    operation_id = "create_pairing_code",
    summary = "Mint a one-time pairing code for a new device",
    responses(
        (status = 201, description = "A code, shown exactly once.", body = NewCodeResponse),
        (status = 409, description = "`pairing_code_limit_reached`: too many live codes.", body = crate::error::ErrorBody),
    )
)]
pub async fn create_code(State(state): State<AppState>, session: SessionContext) -> Response {
    let now = UnixTime::now();
    let user_id = &session.auth().user.id;

    match service::create_pairing_code(&state.pool, user_id, now).await {
        Ok(created) => {
            let shown = created.code.display();
            (
                StatusCode::CREATED,
                Json(NewCodeResponse {
                    // The one place the plaintext leaves the server.
                    pairing_code: shown.expose().to_owned(),
                    expires_at: created.expires_at.as_secs(),
                    server_time: now.as_secs(),
                }),
            )
                .into_response()
        }
        Err(err) => create_code_error(err).into_response(),
    }
}

/// Shared with the dashboard's device page, so both answer alike.
pub(super) fn create_code_error(err: CreateCodeError) -> ApiError {
    match err {
        // The caller owns these codes and can see their own, so being
        // told the cap is reached is useful rather than leaky.
        CreateCodeError::TooManyActive => ApiError::of(ErrorKind::PairingCodeLimitReached),
        err @ (CreateCodeError::Rng(_) | CreateCodeError::Store(_)) => {
            tracing::error!(error = %err, "creating a pairing code failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    /// Accepted in any spelling a person might type; normalized in
    /// [`crate::devices::code`].
    #[schema(value_type = String, format = Password)]
    pairing_code: SecretString,
    device_name: String,
    /// Taken as a string and parsed in the service layer, so an
    /// unknown value becomes this server's own `invalid_platform`
    /// rather than serde's rejection text quoting what was sent.
    platform: String,
}

#[derive(Serialize, ToSchema)]
struct PairResponse {
    /// Returned exactly once. The server keeps only its hash.
    device_token: String,
    device: DeviceView,
    server_time: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/pair",
    tag = "devices",
    operation_id = "pair_device",
    summary = "Redeem a pairing code; returns the device's bearer token",
    request_body = PairRequest,
    responses(
        (status = 201, description = "Paired. `device_token` is shown exactly once.", body = PairResponse),
        (status = 400, description = "`invalid_device_name` or `invalid_platform`.", body = crate::error::ErrorBody),
        (status = 401, description = "`invalid_pairing_code`, whatever was wrong with it.", body = crate::error::ErrorBody),
        (status = 409, description = "`device_limit_reached`.", body = crate::error::ErrorBody),
    )
)]
pub async fn pair_device(
    State(state): State<AppState>,
    Json(request): Json<PairRequest>,
) -> Response {
    let now = UnixTime::now();

    let result = service::pair_device(
        &state.pool,
        request.pairing_code.expose(),
        &request.device_name,
        &request.platform,
        state.device_policy,
        now,
    )
    .await;

    match result {
        Ok(paired) => (
            StatusCode::CREATED,
            Json(PairResponse {
                device_token: paired.token.expose().to_owned(),
                device: DeviceView::from(&paired.device),
                server_time: now.as_secs(),
            }),
        )
            .into_response(),
        Err(err) => pair_error(err).into_response(),
    }
}

fn pair_error(err: PairError) -> ApiError {
    match err {
        // Unknown, expired, already redeemed and malformed all land
        // here, as one response. The caller is unauthenticated, and
        // distinguishing these would say whether a code ever existed.
        PairError::CodeRejected => ApiError::of(ErrorKind::InvalidPairingCode),

        // Different on purpose: only reachable with a *valid* code, so
        // it is not an oracle, and the person pairing has to be told
        // why an otherwise good code did not work.
        PairError::DeviceLimitReached => ApiError::of(ErrorKind::DeviceLimitReached),

        // Public rules, stated without echoing the input.
        PairError::InvalidName(reason) => ApiError::of(match reason {
            DeviceNameError::Length => ErrorKind::DeviceNameLength,
            DeviceNameError::Charset => ErrorKind::DeviceNameCharset,
        }),
        PairError::UnknownPlatform => ApiError::of(ErrorKind::PlatformUnknown),

        PairError::Rng(_) | PairError::Store(_) => {
            tracing::error!(error = %err, "pairing a device failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}
