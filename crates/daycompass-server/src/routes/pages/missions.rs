//! `GET /missions/manage` and its writes: the caller's own missions -
//! creating, editing and archiving them - and the North Star above them.
//!
//! Thin, like every page handler: the form is turned into
//! [`MissionFields`] and handed to [`crate::missions::service`], which
//! writes through the same sync rules a device's push goes through.
//! Every mission write answers with the re-rendered list, the North Star
//! with its own card.
//!
//! Weeks are ISO weeks (Monday to Sunday) in the account's time zone.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{format_duration, render, render_fragment, Shell};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::service::{self, MissionFields, MissionView, SaveOutcome};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone;

/// The palette slots' names, in slot order (`--cat-0` to `--cat-7`).
const COLOUR_NAMES: [&str; 8] = [
    "Amber", "Berry", "Green", "Blue", "Violet", "Orange", "Teal", "Brown",
];

/// Above this many active missions the page suggests archiving some.
/// A hint only; nothing refuses a fourth.
const ACTIVE_HINT_ABOVE: usize = 3;

#[derive(Template)]
#[template(path = "missions_manage.html")]
struct ManagePage {
    shell: Shell,
    north_star: NorthStarCard,
    list: MissionList,
}

#[derive(Template)]
#[template(path = "partials/north_star.html")]
struct NorthStarCard {
    text: Option<String>,
}

#[derive(Template)]
#[template(path = "partials/mission_list.html")]
struct MissionList {
    missions: Vec<MissionRow>,
    /// How many are not archived.
    active: usize,
    hint_above: usize,
    zone: String,
    new_form: MissionForm,
}

struct MissionRow {
    id: String,
    title: String,
    colour: i64,
    description: Option<String>,
    why: Option<String>,
    period: Option<String>,
    archived: bool,
    week_secs: i64,
    week: String,
    goal_secs: i64,
    goal: String,
    total: String,
    form: MissionForm,
}

/// The values a create or edit form starts with.
struct MissionForm {
    /// Prefix for element ids, unique on the page.
    prefix: String,
    action: String,
    submit: &'static str,
    title: String,
    colours: Vec<ColourChoice>,
    goal_hours: String,
    description: String,
    why: String,
    starts_on: String,
    ends_on: String,
}

struct ColourChoice {
    slot: usize,
    name: &'static str,
    checked: bool,
}

impl MissionForm {
    fn blank() -> Self {
        Self {
            prefix: "new".to_owned(),
            action: "/missions/manage".to_owned(),
            submit: "Add mission",
            title: String::new(),
            colours: colour_choices(0),
            goal_hours: String::new(),
            description: String::new(),
            why: String::new(),
            starts_on: String::new(),
            ends_on: String::new(),
        }
    }
}

fn colour_choices(selected: i64) -> Vec<ColourChoice> {
    COLOUR_NAMES
        .iter()
        .enumerate()
        .map(|(slot, name)| ColourChoice {
            slot,
            name,
            checked: i64::try_from(slot) == Ok(selected),
        })
        .collect()
}

/// `7.5` for a goal of 7 h 30 min; empty for no goal.
fn goal_hours(secs: i64) -> String {
    if secs == 0 {
        return String::new();
    }
    // Exact for any whole number of seconds this can hold.
    #[allow(clippy::cast_precision_loss)]
    let hours = secs as f64 / 3600.0;
    hours.to_string()
}

fn period(starts_on: Option<&str>, ends_on: Option<&str>) -> Option<String> {
    match (starts_on, ends_on) {
        (Some(start), Some(end)) => Some(format!("{start} to {end}")),
        (Some(start), None) => Some(format!("From {start}")),
        (None, Some(end)) => Some(format!("Until {end}")),
        (None, None) => None,
    }
}

impl From<MissionView> for MissionRow {
    fn from(view: MissionView) -> Self {
        let m = view.mission;
        Self {
            form: MissionForm {
                prefix: format!("m-{}", m.id),
                action: format!("/missions/{}/edit", m.id),
                submit: "Save",
                title: m.title.clone(),
                colours: colour_choices(m.colour),
                goal_hours: goal_hours(m.weekly_goal_secs),
                description: m.description.clone().unwrap_or_default(),
                why: m.why.clone().unwrap_or_default(),
                starts_on: m.starts_on.clone().unwrap_or_default(),
                ends_on: m.ends_on.clone().unwrap_or_default(),
            },
            period: period(m.starts_on.as_deref(), m.ends_on.as_deref()),
            week: format_duration(view.week_secs),
            week_secs: view.week_secs,
            goal: format_duration(m.weekly_goal_secs),
            goal_secs: m.weekly_goal_secs,
            total: format_duration(view.total_secs),
            id: m.id,
            title: m.title,
            colour: m.colour,
            description: m.description,
            why: m.why,
            archived: m.archived,
        }
    }
}

fn internal(err: &StoreError, what: &'static str) -> ApiError {
    tracing::error!(error = %err, "{what} failed");
    ApiError::of(ErrorKind::InternalError)
}

async fn own_list(state: &AppState, session: &SessionContext) -> Result<MissionList, ApiError> {
    let user_id = &session.auth().user.id;
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let now = UnixTime::now();
    let week = zone.week_bounds(now.as_secs());
    let views = service::list_own(&state.pool, user_id, week, now)
        .await
        .map_err(|err| internal(&err, "listing missions"))?;

    let missions: Vec<MissionRow> = views.into_iter().map(MissionRow::from).collect();
    Ok(MissionList {
        active: missions.iter().filter(|m| !m.archived).count(),
        hint_above: ACTIVE_HINT_ABOVE,
        missions,
        zone: zone.as_str().to_owned(),
        new_form: MissionForm::blank(),
    })
}

async fn list_fragment(state: &AppState, session: &SessionContext) -> Response {
    match own_list(state, session).await {
        Ok(list) => render_fragment(&list),
        Err(error) => error.into_response(),
    }
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    let user_id = &session.auth().user.id;
    let north_star = match service::north_star(&state.pool, user_id).await {
        Ok(text) => NorthStarCard { text },
        Err(err) => return internal(&err, "reading the North Star").into_response(),
    };
    match own_list(&state, &session).await {
        Ok(list) => render(&ManagePage {
            shell: Shell::load(&state.pool, session.auth(), "missions").await,
            north_star,
            list,
        }),
        Err(error) => error.into_response(),
    }
}

/// The create and edit form. Optional fields arrive empty when unset.
#[derive(Deserialize)]
pub struct MissionFormData {
    title: String,
    colour: i64,
    #[serde(default)]
    weekly_goal_hours: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    why: String,
    #[serde(default)]
    starts_on: String,
    #[serde(default)]
    ends_on: String,
}

impl MissionFormData {
    /// `None` if the goal is not a number of hours; everything else is
    /// left to the service's validation.
    fn into_fields(self) -> Option<MissionFields> {
        let hours = self.weekly_goal_hours.trim();
        let hours: f64 = if hours.is_empty() {
            0.0
        } else {
            hours.parse().ok()?
        };
        if !hours.is_finite() || hours < 0.0 {
            return None;
        }
        // Saturates on overflow, which validation then refuses.
        #[allow(clippy::cast_possible_truncation)]
        let weekly_goal_secs = (hours * 3600.0).round() as i64;
        Some(MissionFields {
            title: self.title,
            colour: self.colour,
            weekly_goal_secs,
            description: text(self.description),
            why: text(self.why),
            starts_on: optional(self.starts_on),
            ends_on: optional(self.ends_on),
        })
    }
}

/// Browsers send a textarea's line breaks as CRLF; the stored form is LF.
fn text(raw: String) -> Option<String> {
    optional(raw.replace("\r\n", "\n"))
}

fn optional(raw: String) -> Option<String> {
    (!raw.trim().is_empty()).then_some(raw)
}

async fn answer(
    state: &AppState,
    session: &SessionContext,
    saved: Result<SaveOutcome, StoreError>,
) -> Response {
    match saved {
        Ok(SaveOutcome::Saved) => list_fragment(state, session).await,
        // One answer for "no such mission" and "not yours", as on the API.
        Ok(SaveOutcome::NotFound) => ApiError::of(ErrorKind::NotFound).into_response(),
        // A mission has no position and no timer, so `NoRoom` and
        // `Running` cannot happen here.
        Ok(SaveOutcome::Invalid(_) | SaveOutcome::NoRoom | SaveOutcome::Running) => {
            ApiError::of(ErrorKind::MissionInvalid).into_response()
        }
        Err(err) => internal(&err, "saving a mission").into_response(),
    }
}

pub async fn create(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<MissionFormData>,
) -> Response {
    let Some(fields) = form.into_fields() else {
        return ApiError::of(ErrorKind::MissionInvalid).into_response();
    };
    let user_id = &session.auth().user.id;
    let saved = service::save_own(&state.pool, user_id, None, fields, UnixTime::now()).await;
    answer(&state, &session, saved).await
}

pub async fn edit(
    State(state): State<AppState>,
    session: SessionContext,
    Path(mission_id): Path<String>,
    Form(form): Form<MissionFormData>,
) -> Response {
    let Some(fields) = form.into_fields() else {
        return ApiError::of(ErrorKind::MissionInvalid).into_response();
    };
    let user_id = &session.auth().user.id;
    let saved = service::save_own(
        &state.pool,
        user_id,
        Some(&mission_id),
        fields,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, saved).await
}

#[derive(Deserialize)]
pub struct ArchiveForm {
    archived: bool,
}

pub async fn archive(
    State(state): State<AppState>,
    session: SessionContext,
    Path(mission_id): Path<String>,
    Form(form): Form<ArchiveForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::set_archived_own(
        &state.pool,
        user_id,
        &mission_id,
        form.archived,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, saved).await
}

#[derive(Deserialize)]
pub struct NorthStarForm {
    #[serde(default)]
    north_star: String,
}

pub async fn set_north_star(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<NorthStarForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    match service::set_north_star(&state.pool, user_id, &form.north_star).await {
        Ok(Ok(())) => match service::north_star(&state.pool, user_id).await {
            Ok(text) => render_fragment(&NorthStarCard { text }),
            Err(err) => internal(&err, "reading the North Star").into_response(),
        },
        Ok(Err(_)) => ApiError::of(ErrorKind::NorthStarInvalid).into_response(),
        Err(err) => internal(&err, "saving the North Star").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(goal: &str) -> MissionFormData {
        MissionFormData {
            title: "Maths".to_owned(),
            colour: 3,
            weekly_goal_hours: goal.to_owned(),
            description: "one\r\ntwo".to_owned(),
            why: "  ".to_owned(),
            starts_on: String::new(),
            ends_on: "2027-07-31".to_owned(),
        }
    }

    #[test]
    fn a_form_becomes_fields_with_seconds_and_lf_text() {
        let fields = form("7.5").into_fields().expect("a valid goal");
        assert_eq!(fields.weekly_goal_secs, 27_000);
        assert_eq!(fields.description.as_deref(), Some("one\ntwo"));
        assert_eq!(fields.why, None);
        assert_eq!(fields.starts_on, None);
        assert_eq!(fields.ends_on.as_deref(), Some("2027-07-31"));
        assert_eq!(form("").into_fields().unwrap().weekly_goal_secs, 0);
    }

    #[test]
    fn a_goal_that_is_not_a_number_of_hours_is_refused() {
        for goal in ["NaN", "inf", "-1", "abc"] {
            assert!(form(goal).into_fields().is_none(), "{goal}");
        }
    }

    #[test]
    fn a_goal_reads_back_as_the_hours_it_was_entered_as() {
        assert_eq!(goal_hours(27_000), "7.5");
        assert_eq!(goal_hours(36_000), "10");
        assert_eq!(goal_hours(0), "");
    }
}
