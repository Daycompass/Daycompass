//! `GET /account` and `POST /account/password`: the caller's own
//! account - changing the password, reading the account log, and the
//! link to the export.
//!
//! The export is a plain link to `GET /api/v1/export`, not a page route
//! of its own: that route is already a same-origin `GET` authenticated
//! by the session cookie, answers with a download, and carries its own
//! per-session rate limit. A second route would be a second read into
//! events for nothing.
//!
//! The account log is the one `GET /api/v1/account/log` returns, for the
//! caller alone. An admin reading their own page sees their own log.

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{format_utc, render, render_fragment, Shell};
use crate::auth::account_log::{self, LogKind};
use crate::auth::secret::SecretString;
use crate::error::{ApiError, ErrorKind};
use crate::routes::{auth, SessionContext};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    shell: Shell,
    is_admin: bool,
    form: PasswordForm,
    log: Vec<LogRow>,
}

/// The password form on its own: the page's, and a change's answer.
#[derive(Template)]
#[template(path = "partials/password_form.html")]
struct PasswordForm {
    /// How many other sessions the last change ended, after a change.
    changed: Option<u64>,
}

struct LogRow {
    what: &'static str,
    at: String,
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    let auth = session.auth();
    let entries = match account_log::list_for_user(&state.pool, &auth.user.id).await {
        Ok(entries) => entries,
        Err(err) => {
            tracing::error!(error = %err, "reading the account log failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };

    render(&AccountPage {
        shell: Shell::for_session(auth, "account"),
        is_admin: auth.user.role.is_admin(),
        form: PasswordForm { changed: None },
        log: entries
            .iter()
            .map(|entry| LogRow {
                what: match entry.kind {
                    LogKind::InviteRedeemed => "Invite redeemed, account activated",
                    LogKind::PasswordResetByAdmin => "Password reset by an admin",
                    LogKind::PasswordChanged => "Password changed",
                },
                at: format_utc(entry.at.as_secs()),
            })
            .collect(),
    })
}

/// The change-password form. Same field names as the JSON body.
#[derive(Deserialize)]
pub struct ChangePasswordForm {
    current_password: SecretString,
    new_password: SecretString,
}

pub async fn change_password(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    match auth::attempt_password_change(&state, &session, form.current_password, form.new_password)
        .await
    {
        // A fresh, empty form: the passwords never travel back to the
        // page, not even as field values.
        Ok(other_sessions_ended) => render_fragment(&PasswordForm {
            changed: Some(other_sessions_ended),
        }),
        Err(error) => error.into_response(),
    }
}
