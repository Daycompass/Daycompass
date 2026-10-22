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
use serde::Serialize;

use crate::auth::account_log::{self, LogEntry, LogKind};
use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;

/// One entry of an account's log, as shown to the account itself.
#[derive(Serialize)]
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

#[derive(Serialize)]
struct AccountLogResponse {
    entries: Vec<AccountLogEntryView>,
}

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
