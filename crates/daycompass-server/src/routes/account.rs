//! `GET /api/v1/account/log`.
//!
//! The one read path onto [`crate::auth::account_log`]. There is no id
//! parameter and no admin variant: a caller always reads their own log,
//! which is the whole point of the endpoint - see
//! `docs/design-decisions.md` for why an admin password reset has to be
//! visible here rather than silent.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::account_log::{self, LogEntry, LogKind};
use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

/// One entry of an account's log, as shown to the account itself.
#[derive(Serialize, ToSchema)]
pub struct AccountLogEntryView {
    pub kind: &'static str,
    /// The acting admin's id, for `password_reset_by_admin`. `None` for
    /// the other two kinds, which are the account acting on itself.
    pub actor_id: Option<String>,
    pub at: i64,
}

impl From<&LogEntry> for AccountLogEntryView {
    fn from(entry: &LogEntry) -> Self {
        Self {
            kind: match entry.kind {
                LogKind::InviteRedeemed => "invite_redeemed",
                LogKind::PasswordResetByAdmin => "password_reset_by_admin",
                LogKind::PasswordChanged => "password_changed",
            },
            actor_id: entry.actor_id.clone(),
            at: entry.at.as_secs(),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct AccountLogResponse {
    entries: Vec<AccountLogEntryView>,
}

#[utoipa::path(
    get,
    path = "/api/v1/account/log",
    tag = "accounts",
    operation_id = "account_log",
    summary = "Your own account log, newest 200 first",
    responses(
        (status = 200, description = "The log.", body = AccountLogResponse),
    )
)]
pub async fn log(State(state): State<AppState>, session: SessionContext) -> Response {
    let user_id = &session.auth().user.id;

    match account_log::list_for_user(&state.pool, user_id).await {
        Ok(entries) => {
            let body = AccountLogResponse {
                entries: entries.iter().map(AccountLogEntryView::from).collect(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "reading the account log failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

#[derive(Serialize, ToSchema)]
struct TimeZoneResponse {
    /// An IANA name such as `Europe/Berlin`; `UTC` until one is set.
    timezone: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/account/timezone",
    tag = "accounts",
    operation_id = "account_timezone",
    summary = "Your account's time zone",
    responses(
        (status = 200, description = "The time zone.", body = TimeZoneResponse),
    )
)]
pub async fn get_timezone(State(state): State<AppState>, session: SessionContext) -> Response {
    let user_id = &session.auth().user.id;

    match timezone::get_for_user(&state.pool, user_id).await {
        Ok(zone) => timezone_response(&zone),
        Err(err) => {
            tracing::error!(error = %err, user_id = %user_id, "reading the time zone failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetTimeZoneRequest {
    /// An IANA name such as `Europe/Berlin`.
    timezone: String,
}

#[utoipa::path(
    patch,
    path = "/api/v1/account/timezone",
    tag = "accounts",
    operation_id = "set_account_timezone",
    summary = "Set your account's time zone",
    request_body = SetTimeZoneRequest,
    responses(
        (status = 200, description = "The time zone, as stored.", body = TimeZoneResponse),
        (status = 400, description = "`invalid_timezone`.", body = crate::error::ErrorBody),
    )
)]
pub async fn set_timezone(
    State(state): State<AppState>,
    session: SessionContext,
    Json(request): Json<SetTimeZoneRequest>,
) -> Response {
    match change_timezone(&state, &session, &request.timezone).await {
        Ok(zone) => timezone_response(&zone),
        Err(error) => error.into_response(),
    }
}

/// Validates and stores `raw` for the session's own account. Shared by
/// the JSON route and the dashboard's form.
pub async fn change_timezone(
    state: &AppState,
    session: &SessionContext,
    raw: &str,
) -> Result<TimeZoneName, ApiError> {
    let user_id = &session.auth().user.id;
    let zone = TimeZoneName::parse(raw).map_err(|_| ApiError::of(ErrorKind::TimeZoneUnknown))?;

    timezone::set_for_user(&state.pool, user_id, &zone)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, user_id = %user_id, "storing the time zone failed");
            ApiError::of(ErrorKind::InternalError)
        })?;
    Ok(zone)
}

fn timezone_response(zone: &TimeZoneName) -> Response {
    (
        StatusCode::OK,
        Json(TimeZoneResponse {
            timezone: zone.as_str().to_owned(),
        }),
    )
        .into_response()
}
