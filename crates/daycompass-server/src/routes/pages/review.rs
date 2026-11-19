//! `GET /missions/review` and its writes: one week looked back on -
//! Mission Hours per day, each mission against its goal, what got done -
//! with the three questions of the review, next week's goals and the
//! weeks reviewed before. `GET /missions/review/markdown` is the same
//! week as a Markdown file.
//!
//! Thin, like every page handler: the numbers and both writes come from
//! [`crate::missions::service`], and the writes go through the sync
//! rules a device's push goes through. Every write answers with the
//! whole `#review` block.
//!
//! The query: `week`, any `YYYY-MM-DD` of the week (this week without
//! it). Weeks are ISO weeks in the account's time zone.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Form;
use jiff::civil::Date;
use jiff::ToSpan;
use serde::Deserialize;

use super::missions::{goal_hours, goal_secs};
use super::plan::week_of;
use super::today::internal;
use super::{format_duration, render, render_fragment, Shell};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::service::{self, Answers, ReviewData, SaveOutcome};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

#[derive(Template)]
#[template(path = "missions_review.html")]
struct ReviewPage {
    shell: Shell,
    heading: String,
    content: ReviewContent,
}

#[derive(Template)]
#[template(path = "partials/review.html")]
struct ReviewContent {
    /// `?week=<Monday>`, which every link and write keeps.
    query: String,
    previous: String,
    next: String,
    mission_total: String,
    tracked_total: String,
    /// `None`: screen time is off, or no category counts as distraction.
    distraction: Option<String>,
    /// Mission Hours as a share of all tracked time, in percent; `None`
    /// if nothing was tracked.
    share: Option<i64>,
    days: Vec<DayBar>,
    /// The longest day, which every day's bar is measured against.
    day_max: i64,
    missions: Vec<GoalRow>,
    /// Whether the goals are the review's snapshot, or today's.
    snapshot: bool,
    done: Vec<DoneRow>,
    went_well: String,
    went_badly: String,
    change_next: String,
    /// Set on the answer to a write.
    saved: bool,
    goals: Vec<GoalInput>,
    history: Vec<HistoryRow>,
    zone: String,
}

struct DayBar {
    /// `Monday 16 Nov`.
    name: String,
    duration: String,
    secs: i64,
}

struct GoalRow {
    title: String,
    colour: i64,
    actual: String,
    actual_secs: i64,
    goal: String,
    goal_secs: i64,
}

struct DoneRow {
    title: String,
    mission: Option<(String, i64)>,
    /// `Tue 17 Nov`.
    day: String,
}

/// A mission's goal in the next-week form.
struct GoalInput {
    id: String,
    title: String,
    colour: i64,
    /// [`goal_hours`]: empty for none.
    hours: String,
}

struct HistoryRow {
    href: String,
    label: String,
    current: bool,
}

#[derive(Deserialize)]
pub struct View {
    week: Option<String>,
}

/// The week a request is about, in the account's time zone.
struct Week {
    zone: TimeZoneName,
    days: Vec<Date>,
    /// Each day's `[start, end)`, Unix seconds.
    bounds: Vec<(i64, i64)>,
    now: UnixTime,
}

impl Week {
    fn start(&self) -> String {
        self.days[0].to_string()
    }
}

async fn week(state: &AppState, user_id: &str, view: &View) -> Result<Week, ApiError> {
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let now = UnixTime::now();
    let Some(today) = zone.date(now.as_secs()) else {
        tracing::error!("working out today's date failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    let days = week_of(view.week.as_deref(), today).ok_or(ApiError::of(ErrorKind::BadRequest))?;
    // Noon is inside its day whatever the clocks do around midnight.
    let bounds: Option<Vec<(i64, i64)>> = days
        .iter()
        .map(|day| {
            zone.timestamp_of(day.at(12, 0, 0, 0))
                .map(|noon| zone.day_bounds(noon))
        })
        .collect();
    let Some(bounds) = bounds else {
        tracing::error!("working out the week's bounds failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    Ok(Week {
        zone,
        days,
        bounds,
        now,
    })
}

async fn data(state: &AppState, user_id: &str, week: &Week) -> Result<ReviewData, ApiError> {
    service::review_of(&state.pool, user_id, &week.start(), &week.bounds, week.now)
        .await
        .map_err(|err| internal(&err, "reading the week's review"))
}

/// `Week of 16 November 2026`.
fn heading(monday: Date) -> String {
    format!("Week of {}", monday.strftime("%-d %B %Y"))
}

fn build(data: ReviewData, week: &Week, saved: bool) -> ReviewContent {
    let monday = week.days[0];
    let query_of = |weeks: i64| {
        monday
            .checked_add(weeks.weeks())
            .map(|date| format!("?week={date}"))
            .unwrap_or_default()
    };
    let days: Vec<DayBar> = week
        .days
        .iter()
        .zip(&data.day_secs)
        .map(|(date, &secs)| DayBar {
            name: date.strftime("%A %-d %b").to_string(),
            duration: format_duration(secs),
            secs,
        })
        .collect();
    let (went_well, went_badly, change_next) =
        data.review
            .as_ref()
            .map_or_else(Default::default, |review| {
                let text = |text: &Option<String>| text.clone().unwrap_or_default();
                (
                    text(&review.went_well),
                    text(&review.went_badly),
                    text(&review.change_next),
                )
            });
    let this_week = week.start();

    ReviewContent {
        query: query_of(0),
        previous: query_of(-1),
        next: query_of(1),
        mission_total: format_duration(data.mission_secs),
        tracked_total: format_duration(data.tracked_secs),
        distraction: data.distraction_secs.map(format_duration),
        share: (data.tracked_secs > 0).then(|| data.mission_secs * 100 / data.tracked_secs),
        day_max: days.iter().map(|day| day.secs).max().unwrap_or(0).max(1),
        days,
        missions: data
            .missions
            .into_iter()
            .map(|row| GoalRow {
                title: row.mission.title,
                colour: row.mission.colour,
                actual: format_duration(row.actual_secs),
                actual_secs: row.actual_secs,
                goal: format_duration(row.goal_secs),
                goal_secs: row.goal_secs,
            })
            .collect(),
        snapshot: data.review.is_some(),
        done: data
            .done
            .into_iter()
            .map(|(task, mission)| DoneRow {
                day: task
                    .done_at
                    .and_then(|at| week.zone.date(at))
                    .map(|date| date.strftime("%a %-d %b").to_string())
                    .unwrap_or_default(),
                title: task.title,
                mission: mission.map(|mission| (mission.title, mission.colour)),
            })
            .collect(),
        went_well,
        went_badly,
        change_next,
        saved,
        goals: data
            .active
            .into_iter()
            .map(|mission| GoalInput {
                hours: goal_hours(mission.weekly_goal_secs),
                id: mission.id,
                title: mission.title,
                colour: mission.colour,
            })
            .collect(),
        history: data
            .history
            .into_iter()
            .map(|week_start| HistoryRow {
                href: format!("/missions/review?week={week_start}"),
                label: week_start
                    .parse::<Date>()
                    .map(heading)
                    .unwrap_or_else(|_| week_start.clone()),
                current: week_start == this_week,
            })
            .collect(),
        zone: week.zone.as_str().to_owned(),
    }
}

pub async fn page(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
) -> Response {
    let user_id = &session.auth().user.id;
    let week = match week(&state, user_id, &view).await {
        Ok(week) => week,
        Err(error) => return error.into_response(),
    };
    match data(&state, user_id, &week).await {
        Ok(data) => render(&ReviewPage {
            shell: Shell::load(&state.pool, session.auth(), "missions").await,
            heading: heading(week.days[0]),
            content: build(data, &week, false),
        }),
        Err(error) => error.into_response(),
    }
}

/// The answer to every write: the re-rendered block, or the refusal.
async fn answer(
    state: &AppState,
    session: &SessionContext,
    week: &Week,
    saved: Result<SaveOutcome, StoreError>,
) -> Response {
    let kind = match saved {
        Ok(SaveOutcome::Saved) => {
            return match data(state, &session.auth().user.id, week).await {
                Ok(data) => render_fragment(&build(data, week, true)),
                Err(error) => error.into_response(),
            };
        }
        // One answer for "no such mission" and "not yours", as on the API.
        Ok(SaveOutcome::NotFound) => ErrorKind::NotFound,
        // A review has no position and no timer, so only `Invalid` is
        // really possible here.
        Ok(SaveOutcome::Invalid(_) | SaveOutcome::NoRoom | SaveOutcome::Running) => {
            ErrorKind::ReviewInvalid
        }
        Err(err) => return internal(&err, "saving a review").into_response(),
    };
    ApiError::of(kind).into_response()
}

/// The three answers. Same names as the sync record's fields.
#[derive(Deserialize)]
pub struct AnswersForm {
    #[serde(default)]
    went_well: String,
    #[serde(default)]
    went_badly: String,
    #[serde(default)]
    change_next: String,
}

pub async fn save(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
    Form(form): Form<AnswersForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let week = match week(&state, user_id, &view).await {
        Ok(week) => week,
        Err(error) => return error.into_response(),
    };
    let answers = Answers {
        went_well: form.went_well,
        went_badly: form.went_badly,
        change_next: form.change_next,
    };
    let saved = service::save_review(&state.pool, user_id, &week.start(), answers, week.now).await;
    answer(&state, &session, &week, saved).await
}

/// The prefix of a goal field's name; the rest is the mission's id.
const GOAL_FIELD: &str = "goal_";

/// `goal_<mission id>` = hours, one per mission. Fields of any other
/// name are ignored.
pub async fn set_goals(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let user_id = &session.auth().user.id;
    let week = match week(&state, user_id, &view).await {
        Ok(week) => week,
        Err(error) => return error.into_response(),
    };
    let goals: Option<Vec<(String, i64)>> = fields
        .iter()
        .filter_map(|(name, value)| {
            let id = name.strip_prefix(GOAL_FIELD)?;
            Some(goal_secs(value).map(|secs| (id.to_owned(), secs)))
        })
        .collect();
    let Some(goals) = goals else {
        return ApiError::of(ErrorKind::ReviewInvalid).into_response();
    };
    let saved = service::set_goals(&state.pool, user_id, &week.start(), &goals, week.now).await;
    answer(&state, &session, &week, saved).await
}

/// The week as a Markdown file, for keeping or sharing outside
/// Daycompass.
pub async fn markdown_file(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
) -> Response {
    let user_id = &session.auth().user.id;
    let week = match week(&state, user_id, &view).await {
        Ok(week) => week,
        Err(error) => return error.into_response(),
    };
    let content = match data(&state, user_id, &week).await {
        Ok(data) => build(data, &week, false),
        Err(error) => return error.into_response(),
    };
    // The date is from `week_of`, so the header value is plain ASCII.
    let disposition = format!(
        "attachment; filename=\"daycompass-review-{}.md\"",
        week.start()
    );
    (
        [
            (
                header::CONTENT_TYPE,
                "text/markdown; charset=utf-8".to_owned(),
            ),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        markdown(&heading(week.days[0]), &content),
    )
        .into_response()
}

/// The week in Markdown. What the account holder wrote goes in as
/// written: it is their own file.
fn markdown(heading: &str, content: &ReviewContent) -> String {
    use std::fmt::Write;

    let mut out = format!("# {heading}\n\n");
    let share = content
        .share
        .map(|share| format!(", {share}% of {} tracked", content.tracked_total))
        .unwrap_or_default();
    let _ = writeln!(out, "Mission Hours: {}{share}", content.mission_total);
    if let Some(distraction) = &content.distraction {
        let _ = writeln!(out, "Distraction: {distraction}");
    }
    out.push('\n');

    out.push_str("## Mission Hours per day\n\n");
    for day in &content.days {
        let _ = writeln!(out, "- {}: {}", day.name, day.duration);
    }

    if !content.missions.is_empty() {
        out.push_str("\n## Missions\n\n");
        for row in &content.missions {
            let goal = if row.goal_secs > 0 {
                format!(" of {}", row.goal)
            } else {
                String::new()
            };
            let _ = writeln!(out, "- {}: {}{goal}", row.title, row.actual);
        }
    }

    if !content.done.is_empty() {
        out.push_str("\n## Done\n\n");
        for row in &content.done {
            let mission = row
                .mission
                .as_ref()
                .map(|(title, _)| format!(" ({title})"))
                .unwrap_or_default();
            let _ = writeln!(out, "- {}{mission}, {}", row.title, row.day);
        }
    }

    for (title, text) in [
        ("What went well", &content.went_well),
        ("What went badly, and why", &content.went_badly),
        ("What changes next week", &content.change_next),
    ] {
        if !text.is_empty() {
            let _ = write!(out, "\n## {title}\n\n{text}\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_markdown_has_the_numbers_and_leaves_out_empty_sections() {
        let content = ReviewContent {
            query: String::new(),
            previous: String::new(),
            next: String::new(),
            mission_total: "5h 0m".to_owned(),
            tracked_total: "10h 0m".to_owned(),
            distraction: Some("1h 0m".to_owned()),
            share: Some(50),
            days: vec![DayBar {
                name: "Monday 16 Nov".to_owned(),
                duration: "5h 0m".to_owned(),
                secs: 18_000,
            }],
            day_max: 18_000,
            missions: vec![GoalRow {
                title: "Maths".to_owned(),
                colour: 0,
                actual: "5h 0m".to_owned(),
                actual_secs: 18_000,
                goal: "10h 0m".to_owned(),
                goal_secs: 36_000,
            }],
            snapshot: true,
            done: Vec::new(),
            went_well: "Exercises\nevery day".to_owned(),
            went_badly: String::new(),
            change_next: String::new(),
            saved: false,
            goals: Vec::new(),
            history: Vec::new(),
            zone: "UTC".to_owned(),
        };
        let text = markdown("Week of 16 November 2026", &content);
        assert_eq!(
            text,
            "# Week of 16 November 2026\n\n\
             Mission Hours: 5h 0m, 50% of 10h 0m tracked\n\
             Distraction: 1h 0m\n\n\
             ## Mission Hours per day\n\n\
             - Monday 16 Nov: 5h 0m\n\n\
             ## Missions\n\n\
             - Maths: 5h 0m of 10h 0m\n\n\
             ## What went well\n\n\
             Exercises\nevery day\n"
        );
    }
}
