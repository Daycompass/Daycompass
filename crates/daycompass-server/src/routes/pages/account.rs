//! `GET /account` and its writes: the caller's own account - changing
//! the password, the time zone and the review day, reading the account
//! log, and the link to the export.
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
use crate::missions::service as missions;
use crate::routes::{account, auth, SessionContext};
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    shell: Shell,
    is_admin: bool,
    form: PasswordForm,
    timezone_form: String,
    review_day_form: ReviewDayForm,
    log: Vec<LogRow>,
}

/// The password form on its own: the page's, and a change's answer.
#[derive(Template)]
#[template(path = "partials/password_form.html")]
struct PasswordForm {
    /// How many other sessions the last change ended, after a change.
    changed: Option<u64>,
}

/// The time zone form on its own: the page's, and a save's answer.
#[derive(Template)]
#[template(path = "partials/timezone_form.html")]
struct TimeZoneForm {
    current: String,
    names: Vec<String>,
    saved: bool,
}

impl TimeZoneForm {
    fn new(zone: &TimeZoneName, saved: bool) -> Self {
        Self {
            current: zone.as_str().to_owned(),
            names: timezone::available_names(),
            saved,
        }
    }
}

/// The review day form on its own: the page's, and a save's answer.
#[derive(Template)]
#[template(path = "partials/review_day_form.html")]
struct ReviewDayForm {
    /// 1 (Monday) to 7.
    current: i8,
    days: [(i8, &'static str); 7],
    saved: bool,
}

impl ReviewDayForm {
    fn new(current: i8, saved: bool) -> Self {
        Self {
            current,
            days: [
                (1, "Monday"),
                (2, "Tuesday"),
                (3, "Wednesday"),
                (4, "Thursday"),
                (5, "Friday"),
                (6, "Saturday"),
                (7, "Sunday"),
            ],
            saved,
        }
    }
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

    let zone = match timezone::get_for_user(&state.pool, &auth.user.id).await {
        Ok(zone) => zone,
        Err(err) => {
            tracing::error!(error = %err, "reading the time zone failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };
    let timezone_form = match TimeZoneForm::new(&zone, false).render() {
        Ok(html) => html,
        Err(err) => {
            tracing::error!(error = %err, "rendering a template failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };

    let review_day = match missions::review_day(&state.pool, &auth.user.id).await {
        Ok(day) => day,
        Err(err) => {
            tracing::error!(error = %err, "reading the review day failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };

    render(&AccountPage {
        shell: Shell::load(&state.pool, auth, "account").await,
        is_admin: auth.user.role.is_admin(),
        form: PasswordForm { changed: None },
        timezone_form,
        review_day_form: ReviewDayForm::new(review_day, false),
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

/// The time zone form. Same field name as the JSON body.
#[derive(Deserialize)]
pub struct TimeZoneFormInput {
    timezone: String,
}

pub async fn change_timezone(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<TimeZoneFormInput>,
) -> Response {
    match account::change_timezone(&state, &session, &form.timezone).await {
        Ok(zone) => render_fragment(&TimeZoneForm::new(&zone, true)),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
pub struct ReviewDayInput {
    day: i8,
}

pub async fn change_review_day(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<ReviewDayInput>,
) -> Response {
    match missions::set_review_day(&state.pool, &session.auth().user.id, form.day).await {
        Ok(true) => render_fragment(&ReviewDayForm::new(form.day, true)),
        Ok(false) => ApiError::of(ErrorKind::ReviewInvalid).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "saving the review day failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
