//! `GET /account` and its writes: the caller's own account - changing
//! the password, the time zone, the review day and the Missions screen
//! time settings, reading the account log, and the link to the export.
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
use crate::categories::palette;
use crate::error::{ApiError, ErrorKind};
use crate::missions::screen_time::{self, Settings};
use crate::missions::service as missions;
use crate::routes::{account, auth, SessionContext};
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    shell: Shell,
    is_admin: bool,
    /// [`crate::build::label`], shown to admins.
    version: String,
    form: PasswordForm,
    timezone_form: String,
    review_day_form: ReviewDayForm,
    screen_time_form: ScreenTimeForm,
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

/// The screen time form on its own: the page's, and a save's answer.
#[derive(Template)]
#[template(path = "partials/screen_time_form.html")]
struct ScreenTimeForm {
    enabled: bool,
    categories: Vec<CategoryChoice>,
    saved: bool,
}

struct CategoryChoice {
    name: String,
    slot: u32,
    marked: bool,
}

impl ScreenTimeForm {
    fn new(settings: &Settings, offered: Vec<String>, saved: bool) -> Self {
        Self {
            enabled: settings.enabled,
            categories: offered
                .into_iter()
                .map(|name| CategoryChoice {
                    slot: palette::slot_for(&name),
                    marked: settings.distraction.contains(&name),
                    name,
                })
                .collect(),
            saved,
        }
    }
}

/// The settings and the categories to offer, for the form.
async fn screen_time_form(
    state: &AppState,
    user_id: &str,
    saved: Option<Settings>,
) -> Result<ScreenTimeForm, crate::auth::store::StoreError> {
    let offered = screen_time::categories_offered(&state.pool, user_id).await?;
    let is_save = saved.is_some();
    let settings = match saved {
        Some(settings) => settings,
        None => screen_time::settings(&state.pool, user_id).await?,
    };
    Ok(ScreenTimeForm::new(&settings, offered, is_save))
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

    let screen_time_form = match screen_time_form(&state, &auth.user.id, None).await {
        Ok(form) => form,
        Err(err) => {
            tracing::error!(error = %err, "reading the screen time settings failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };

    render(&AccountPage {
        shell: Shell::load(&state.pool, auth, "account").await,
        is_admin: auth.user.role.is_admin(),
        version: crate::build::label(),
        form: PasswordForm { changed: None },
        timezone_form,
        review_day_form: ReviewDayForm::new(review_day, false),
        screen_time_form,
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

/// `enabled=true` if the box is ticked (absent otherwise), and one
/// `distraction` field per marked category.
pub async fn change_screen_time(
    State(state): State<AppState>,
    session: SessionContext,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let user_id = &session.auth().user.id;
    let enabled = fields
        .iter()
        .any(|(name, value)| name == "enabled" && value == "true");
    let distraction: Vec<String> = fields
        .into_iter()
        .filter(|(name, _)| name == "distraction")
        .map(|(_, value)| value)
        .collect();
    let saved = match screen_time::save_settings(&state.pool, user_id, enabled, &distraction).await
    {
        Ok(saved) => saved,
        Err(err) => {
            tracing::error!(error = %err, "saving the screen time settings failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };
    match screen_time_form(&state, user_id, Some(saved)).await {
        Ok(form) => render_fragment(&form),
        Err(err) => {
            tracing::error!(error = %err, "reading the screen time settings failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
