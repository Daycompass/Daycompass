//! `GET /missions/log` and its writes: one week of tracked time, a row
//! per day, where an entry can be corrected, deleted or stopped, and
//! time can be added by hand.
//!
//! Thin, like every page handler: each write is one call into
//! [`crate::missions::service`], which goes through the sync rules a
//! device's push goes through. Every write answers with the whole
//! `#log` block, editor closed, plus the layout's timer pill out of
//! band, since stopping an entry changes both.
//!
//! The query: `week` (any `YYYY-MM-DD` of the week; this week without
//! it) and `entry` (the entry whose editor is open). Writes carry
//! `week` along.
//!
//! Times are wall-clock times in the account's time zone, both shown
//! and entered; weeks are ISO weeks there.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use jiff::civil::Date;
use jiff::ToSpan;
use serde::Deserialize;

use super::plan::{month_label, week_of};
use super::today::{focus_of, internal, timeline_of, window_around, Timeline};
use super::{format_duration, render, render_fragment, Shell, TimerPill, TimerSlot};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::screen_time;
use crate::missions::service::{self, LogData, SaveOutcome};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

/// What a `datetime-local` input shows and sends, to the second.
const LOCAL_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

#[derive(Template)]
#[template(path = "missions_log.html")]
struct LogPage {
    shell: Shell,
    heading: String,
    content: LogContent,
}

#[derive(Template)]
#[template(path = "partials/log.html")]
struct LogContent {
    /// `?week=<Monday>`, which every link and write keeps.
    query: String,
    previous: String,
    next: String,
    week_total: String,
    days: Vec<DayRow>,
    /// The open entry's id, empty if none: its block is outlined.
    picked: String,
    editor: Option<Editor>,
    /// The tasks time can be put on: the backlog, the week's days, and
    /// any other task the week's entries are on.
    groups: Vec<Group>,
    zone: String,
    /// On an htmx answer: the timer pill, replaced out of band.
    timer_slot: Option<TimerSlot>,
}

struct DayRow {
    /// `Monday`.
    name: String,
    /// `16 Nov`.
    date: String,
    total: String,
    today: bool,
    timeline: Timeline,
}

/// The open entry.
struct Editor {
    id: String,
    task_id: String,
    task_title: String,
    running: bool,
    /// [`LOCAL_FORMAT`]; `end` is empty while it runs.
    start: String,
    end: String,
    /// [`focus_of`].
    focus: String,
}

struct Group {
    label: String,
    tasks: Vec<(String, String)>,
}

#[derive(Deserialize)]
pub struct View {
    week: Option<String>,
    entry: Option<String>,
}

/// The `#log` block and the page heading, for the caller right now.
async fn content(
    state: &AppState,
    session: &SessionContext,
    view: &View,
    htmx: bool,
) -> Result<(LogContent, String), ApiError> {
    let user_id = &session.auth().user.id;
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let now = UnixTime::now();
    let Some(today) = zone.date(now.as_secs()) else {
        tracing::error!("working out today's date failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    let days = week_of(view.week.as_deref(), today).ok_or(ApiError::of(ErrorKind::BadRequest))?;
    // Noon is on the Monday whatever the clocks do around midnight.
    let Some(noon) = zone.timestamp_of(days[0].at(12, 0, 0, 0)) else {
        tracing::error!("working out the week's bounds failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    let week = zone.week_bounds(noon);
    let dates: Vec<String> = days.iter().map(Date::to_string).collect();
    let data = service::log_of(&state.pool, user_id, &dates, week, now)
        .await
        .map_err(|err| internal(&err, "reading the week's time"))?;
    let timer_slot = if htmx {
        let timer = service::running_timer(&state.pool, user_id)
            .await
            .map_err(|err| internal(&err, "reading the running timer"))?;
        Some(TimerSlot {
            timer: timer.map(|timer| TimerPill::new(timer, now.as_secs())),
            oob: true,
        })
    } else {
        None
    };
    let window = window_around(&data.entries, week, now.as_secs());
    let screen = screen_time::load(&state.pool, user_id, window)
        .await
        .map_err(|err| internal(&err, "reading screen time"))?;
    let focus: std::collections::HashMap<String, String> = data
        .entries
        .iter()
        .map(|entry| {
            let focus = focus_of(entry, screen.as_ref(), now.as_secs());
            (entry.id.clone(), focus)
        })
        .collect();
    let mut content = build(data, &days, week.0, today, &zone, view, now.as_secs());
    for block in content
        .days
        .iter_mut()
        .flat_map(|day| day.timeline.blocks.iter_mut())
    {
        if let Some(focus) = focus.get(&block.id) {
            block.title = format!("{}, {focus}", block.title);
        }
    }
    if let Some(editor) = content.editor.as_mut() {
        editor.focus = focus.get(&editor.id).cloned().unwrap_or_default();
    }
    content.timer_slot = timer_slot;
    Ok((content, month_label(days[0], days[6])))
}

fn build(
    data: LogData,
    days: &[Date],
    week_start: i64,
    today: Date,
    zone: &TimeZoneName,
    view: &View,
    now: i64,
) -> LogContent {
    let LogData { plan, entries } = data;
    let monday = days[0];
    let query_of = |weeks: i64| {
        monday
            .checked_add(weeks.weeks())
            .map(|date| format!("?week={date}"))
            .unwrap_or_default()
    };

    let mut day_start = week_start;
    let rows: Vec<DayRow> = days
        .iter()
        .map(|&date| {
            let bounds = zone.day_bounds(day_start);
            day_start = bounds.1;
            let timeline = timeline_of(&entries, bounds, zone, now);
            DayRow {
                name: date.strftime("%A").to_string(),
                date: date.strftime("%-d %b").to_string(),
                total: format_duration(timeline.total_secs),
                today: date == today,
                timeline,
            }
        })
        .collect();
    let week_total = format_duration(rows.iter().map(|row| row.timeline.total_secs).sum());

    let local = |ts: i64| {
        zone.datetime(ts)
            .map(|local| local.strftime(LOCAL_FORMAT).to_string())
            .unwrap_or_default()
    };
    let editor = view
        .entry
        .as_deref()
        .and_then(|id| entries.iter().find(|entry| entry.id == id))
        .map(|entry| Editor {
            id: entry.id.clone(),
            task_id: entry.task_id.clone(),
            task_title: entry.task_title.clone(),
            running: entry.end_ts.is_none(),
            start: local(entry.start_ts),
            end: entry.end_ts.map(local).unwrap_or_default(),
            focus: String::new(),
        });

    let heads = std::iter::once("Backlog".to_owned()).chain(
        days.iter()
            .map(|date| date.strftime("%A %-d %b").to_string()),
    );
    let mut groups: Vec<Group> = heads
        .zip(plan.columns)
        .map(|(label, tasks)| Group {
            label,
            tasks: tasks
                .into_iter()
                .map(|task| (task.id, task.title))
                .collect(),
        })
        .collect();
    let mut other = Group {
        label: "Other weeks".to_owned(),
        tasks: Vec::new(),
    };
    for entry in &entries {
        let lists = |group: &Group| group.tasks.iter().any(|(id, _)| *id == entry.task_id);
        if !groups.iter().any(lists) && !lists(&other) {
            other
                .tasks
                .push((entry.task_id.clone(), entry.task_title.clone()));
        }
    }
    groups.push(other);
    groups.retain(|group| !group.tasks.is_empty());

    LogContent {
        query: query_of(0),
        previous: query_of(-1),
        next: query_of(1),
        week_total,
        days: rows,
        picked: editor
            .as_ref()
            .map(|editor| editor.id.clone())
            .unwrap_or_default(),
        editor,
        groups,
        zone: zone.as_str().to_owned(),
        timer_slot: None,
    }
}

pub async fn page(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
) -> Response {
    match content(&state, &session, &view, false).await {
        Ok((content, heading)) => render(&LogPage {
            shell: Shell::load(&state.pool, session.auth(), "missions").await,
            heading,
            content,
        }),
        Err(error) => error.into_response(),
    }
}

/// The answer to every write: the re-rendered block, or the refusal.
async fn answer(
    state: &AppState,
    session: &SessionContext,
    view: &View,
    saved: Result<SaveOutcome, StoreError>,
) -> Response {
    let kind = match saved {
        Ok(SaveOutcome::Saved) => {
            let view = View {
                week: view.week.clone(),
                entry: None,
            };
            return match content(state, session, &view, true).await {
                Ok((content, _heading)) => render_fragment(&content),
                Err(error) => error.into_response(),
            };
        }
        // One answer for "no such entry or task" and "not yours", as on
        // the API.
        Ok(SaveOutcome::NotFound) => ErrorKind::NotFound,
        // An entry has no position, so `NoRoom` cannot happen here.
        Ok(SaveOutcome::Invalid(_) | SaveOutcome::NoRoom) => ErrorKind::TimeEntryInvalid,
        Ok(SaveOutcome::Running) => ErrorKind::TimeEntryRunning,
        Err(err) => return internal(&err, "saving a time entry").into_response(),
    };
    ApiError::of(kind).into_response()
}

#[derive(Deserialize)]
pub struct EntryForm {
    task: String,
    start: String,
    end: String,
}

/// The form's start and end as Unix seconds, read as wall-clock times
/// in the account's zone; `None` if either is not a date and time.
async fn span_of(
    state: &AppState,
    user_id: &str,
    form: &EntryForm,
) -> Result<Option<(i64, i64)>, ApiError> {
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let read = |raw: &str| zone.timestamp_of(raw.parse().ok()?);
    Ok(read(&form.start).zip(read(&form.end)))
}

pub async fn add(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
    Form(form): Form<EntryForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let (start, end) = match span_of(&state, user_id, &form).await {
        Ok(Some(span)) => span,
        Ok(None) => return ApiError::of(ErrorKind::TimeEntryInvalid).into_response(),
        Err(error) => return error.into_response(),
    };
    let saved = service::add_entry(
        &state.pool,
        user_id,
        &form.task,
        start,
        end,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, &view, saved).await
}

pub async fn correct(
    State(state): State<AppState>,
    session: SessionContext,
    Path(entry_id): Path<String>,
    Query(view): Query<View>,
    Form(form): Form<EntryForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let (start, end) = match span_of(&state, user_id, &form).await {
        Ok(Some(span)) => span,
        Ok(None) => return ApiError::of(ErrorKind::TimeEntryInvalid).into_response(),
        Err(error) => return error.into_response(),
    };
    let saved = service::correct_entry(
        &state.pool,
        user_id,
        &entry_id,
        &form.task,
        start,
        end,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, &view, saved).await
}

pub async fn delete(
    State(state): State<AppState>,
    session: SessionContext,
    Path(entry_id): Path<String>,
    Query(view): Query<View>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::delete_entry(&state.pool, user_id, &entry_id, UnixTime::now()).await;
    answer(&state, &session, &view, saved).await
}

pub async fn stop(
    State(state): State<AppState>,
    session: SessionContext,
    Path(entry_id): Path<String>,
    Query(view): Query<View>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::stop_entry(&state.pool, user_id, &entry_id, UnixTime::now()).await;
    answer(&state, &session, &view, saved).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_time_reads_with_or_without_seconds() {
        let utc = TimeZoneName::utc();
        let read = |raw: &str| raw.parse().ok().and_then(|dt| utc.timestamp_of(dt));
        assert_eq!(read("1970-01-02T00:01:05"), Some(86_465));
        assert_eq!(read("1970-01-02T00:01"), Some(86_460));
        assert_eq!(read("tomorrow"), None);
        let shown = utc
            .datetime(86_465)
            .unwrap()
            .strftime(LOCAL_FORMAT)
            .to_string();
        assert_eq!(shown, "1970-01-02T00:01:05");
    }
}
