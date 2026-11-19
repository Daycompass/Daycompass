//! `GET /missions/today` and its writes: the day's tasks, their timer
//! and order, and a timeline of what was tracked.
//!
//! Thin, like every page handler: each write is one call into
//! [`crate::missions::service`], which goes through the sync rules a
//! device's push goes through. Every write answers with the whole
//! `#today` block, plus the layout's timer pill out of band, since
//! starting or stopping a timer changes both.
//!
//! A mission filter (`?mission=<id>`) only narrows what is shown; every
//! write's URL carries it along so the answer keeps it. The Focus page
//! sends the same writes with `?view=focus`, and gets its own block back.
//!
//! The day is the calendar day of the account's time zone.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{format_clock, format_duration, render, render_fragment, Shell, TimerPill, TimerSlot};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::service::{self, Day, Place, SaveOutcome, TaskView, TodayData};
use crate::missions::store::TrackedEntry;
use crate::missions::validate::Mission;
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone::{self, TimeZoneName};

/// The timeline's width in SVG units: one per minute of a 24-hour day.
const TIMELINE_WIDTH: f64 = 1440.0;

#[derive(Template)]
#[template(path = "missions_today.html")]
struct TodayPage {
    shell: Shell,
    heading: String,
    content: TodayContent,
}

#[derive(Template)]
#[template(path = "partials/today.html")]
struct TodayContent {
    /// `?mission=<id>` while filtered, empty otherwise.
    query: String,
    today: String,
    week: String,
    week_secs: i64,
    week_goal: String,
    week_goal_secs: i64,
    left_from_yesterday: usize,
    /// On the review day: the Monday of the week still to review.
    review_due: Option<String>,
    chips: Vec<Chip>,
    choices: Vec<Choice>,
    /// Tasks under a mission, then tasks under none ("Other").
    open: Vec<TaskCard>,
    done: Vec<TaskCard>,
    other_open: Vec<TaskCard>,
    other_done: Vec<TaskCard>,
    timeline: Timeline,
    zone: String,
    /// On an htmx answer: the timer pill, replaced out of band.
    timer_slot: Option<TimerSlot>,
}

/// A filter link.
pub(super) struct Chip {
    pub(super) href: String,
    pub(super) title: String,
    pub(super) colour: Option<i64>,
    pub(super) current: bool,
}

/// A mission the add form offers.
pub(super) struct Choice {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) selected: bool,
}

struct TaskCard {
    id: String,
    title: String,
    mission: Option<String>,
    colour: Option<i64>,
    /// `2h 5m`, or `2:05:09` while it runs, which `daycompass.js` ticks.
    tracked: String,
    tracked_secs: i64,
    running: bool,
    done: bool,
    up: Option<Neighbours>,
    down: Option<Neighbours>,
}

/// The ids a move puts the task between; empty for an end.
pub(super) struct Neighbours {
    pub(super) after: String,
    pub(super) before: String,
}

pub(super) struct Timeline {
    label: String,
    pub(super) total_secs: i64,
    pub(super) blocks: Vec<Block>,
    pub(super) now_x: String,
    /// SVG units per second, which `daycompass.js` grows the running
    /// block and moves the "now" line by.
    pub(super) rate: String,
}

pub(super) struct Block {
    /// The time entry's.
    pub(super) id: String,
    pub(super) x: String,
    pub(super) width: String,
    pub(super) colour: Option<i64>,
    pub(super) title: String,
    pub(super) running: bool,
}

#[derive(Deserialize)]
pub struct Filter {
    mission: Option<String>,
    #[serde(default)]
    view: View,
}

/// The page a write came from, which decides the answer's shape.
#[derive(Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum View {
    #[default]
    Today,
    Focus,
}

pub(super) fn internal(err: &StoreError, what: &'static str) -> ApiError {
    tracing::error!(error = %err, "{what} failed");
    ApiError::of(ErrorKind::InternalError)
}

fn day_of(zone: &TimeZoneName, now: UnixTime) -> Option<(Day, jiff::civil::Date)> {
    let date = zone.date(now.as_secs())?;
    let day = Day {
        date: date.to_string(),
        yesterday: date.yesterday().ok()?.to_string(),
        tomorrow: date.tomorrow().ok()?.to_string(),
        bounds: zone.day_bounds(now.as_secs()),
        week: zone.week_bounds(now.as_secs()),
    };
    Some((day, date))
}

/// The `#today` block, and the page heading, for the caller right now.
async fn content(
    state: &AppState,
    session: &SessionContext,
    filter: Option<String>,
    htmx: bool,
) -> Result<(TodayContent, String), ApiError> {
    let user_id = &session.auth().user.id;
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let now = UnixTime::now();
    let Some((day, date)) = day_of(&zone, now) else {
        tracing::error!("working out today's date failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    let data = service::today_of(&state.pool, user_id, &day, now)
        .await
        .map_err(|err| internal(&err, "reading today's tasks"))?;
    let review_due = service::review_due(&state.pool, user_id, date)
        .await
        .map_err(|err| internal(&err, "reading the review day"))?;
    let heading = date.strftime("%A, %-d %B").to_string();
    let mut content = build(data, &day, &zone, filter, now, htmx);
    content.review_due = review_due;
    Ok((content, heading))
}

fn build(
    data: TodayData,
    day: &Day,
    zone: &TimeZoneName,
    filter: Option<String>,
    now: UnixTime,
    htmx: bool,
) -> TodayContent {
    let TodayData {
        missions,
        tasks,
        running,
        timeline,
        left_from_yesterday,
        hours,
    } = data;
    let running_task = running.as_ref().map(|timer| timer.task_id.clone());
    let query = filter
        .as_deref()
        .map(|id| format!("?mission={id}"))
        .unwrap_or_default();

    let mut chips = vec![Chip {
        href: "/missions/today".to_owned(),
        title: "All".to_owned(),
        colour: None,
        current: filter.is_none(),
    }];
    chips.extend(missions.iter().filter(|m| !m.archived).map(|m| Chip {
        href: format!("/missions/today?mission={}", m.id),
        title: m.title.clone(),
        colour: Some(m.colour),
        current: filter.as_deref() == Some(m.id.as_str()),
    }));
    let choices = missions
        .iter()
        .filter(|m| !m.archived)
        .map(|m| Choice {
            id: m.id.clone(),
            title: m.title.clone(),
            selected: filter.as_deref() == Some(m.id.as_str()),
        })
        .collect();

    // A task whose mission is gone counts as "Other".
    let mission_of = |task: &TaskView| -> Option<&Mission> {
        let id = task.task.mission_id.as_deref()?;
        missions.iter().find(|m| m.id == id)
    };
    let shown = tasks.iter().filter(|task| match filter.as_deref() {
        Some(id) => task.task.mission_id.as_deref() == Some(id),
        None => true,
    });
    let (mut open, mut done, mut other_open, mut other_done) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for task in shown {
        let mission = mission_of(task);
        let running = running_task.as_deref() == Some(task.task.id.as_str());
        let card = TaskCard {
            id: task.task.id.clone(),
            title: task.task.title.clone(),
            mission: mission.map(|m| m.title.clone()),
            colour: mission.map(|m| m.colour),
            tracked: if running {
                format_clock(task.tracked_secs)
            } else {
                format_duration(task.tracked_secs)
            },
            tracked_secs: task.tracked_secs,
            running,
            done: task.task.done_at.is_some(),
            up: None,
            down: None,
        };
        match (mission.is_some(), card.done) {
            (true, false) => open.push(card),
            (true, true) => done.push(card),
            (false, false) => other_open.push(card),
            (false, true) => other_done.push(card),
        }
    }
    with_neighbours(&mut open);
    with_neighbours(&mut other_open);

    TodayContent {
        query,
        today: format_duration(hours.today_secs),
        week: format_duration(hours.week_secs),
        week_secs: hours.week_secs,
        week_goal: format_duration(hours.week_goal_secs),
        week_goal_secs: hours.week_goal_secs,
        left_from_yesterday,
        review_due: None,
        chips,
        choices,
        open,
        done,
        other_open,
        other_done,
        timeline: timeline_of(&timeline, day.bounds, zone, now.as_secs()),
        zone: zone.as_str().to_owned(),
        timer_slot: htmx.then(|| TimerSlot {
            timer: running.map(|timer| TimerPill::new(timer, now.as_secs())),
            oob: true,
        }),
    }
}

/// Gives each card the moves one place up and one place down, within
/// the list it is shown in.
fn with_neighbours(cards: &mut [TaskCard]) {
    let ids: Vec<String> = cards.iter().map(|card| card.id.clone()).collect();
    for (index, card) in cards.iter_mut().enumerate() {
        (card.up, card.down) = up_and_down(&ids, index);
    }
}

/// The moves one place up and one place down for the task at `index`
/// of a list of task ids.
pub(super) fn up_and_down(
    ids: &[String],
    index: usize,
) -> (Option<Neighbours>, Option<Neighbours>) {
    let id_at = |index: Option<usize>| {
        index
            .and_then(|index| ids.get(index))
            .cloned()
            .unwrap_or_default()
    };
    let up = (index > 0).then(|| Neighbours {
        after: id_at(index.checked_sub(2)),
        before: ids[index - 1].clone(),
    });
    let down = (index + 1 < ids.len()).then(|| Neighbours {
        after: ids[index + 1].clone(),
        before: id_at(Some(index + 2)),
    });
    (up, down)
}

/// The entries of `entries` that overlap the day `[start, end)`, laid
/// out on one SVG row.
pub(super) fn timeline_of(
    entries: &[TrackedEntry],
    (start, end): (i64, i64),
    zone: &TimeZoneName,
    now: i64,
) -> Timeline {
    // A day is 23 to 25 hours long; it always spans the full width.
    #[allow(clippy::cast_precision_loss)]
    let scale = TIMELINE_WIDTH / (end - start).max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let x_of = |ts: i64| (ts.clamp(start, end) - start) as f64 * scale;

    let mut total = 0;
    let blocks = entries
        .iter()
        .filter(|entry| entry.start_ts < end && entry.end_ts.unwrap_or(now) > start)
        .map(|entry| {
            let until = entry.end_ts.unwrap_or(now);
            total += until.min(end) - entry.start_ts.max(start);
            let ends = entry
                .end_ts
                .map_or_else(|| "now".to_owned(), |ts| zone.clock(ts));
            Block {
                id: entry.id.clone(),
                x: format!("{:.2}", x_of(entry.start_ts)),
                width: format!("{:.2}", x_of(until) - x_of(entry.start_ts)),
                colour: entry.colour,
                title: format!(
                    "{}, {} to {ends}",
                    entry.task_title,
                    zone.clock(entry.start_ts)
                ),
                running: entry.end_ts.is_none(),
            }
        })
        .collect();
    Timeline {
        label: format!("Tracked today: {}", format_duration(total)),
        total_secs: total,
        blocks,
        now_x: format!("{:.2}", x_of(now)),
        rate: format!("{scale:.6}"),
    }
}

pub async fn page(
    State(state): State<AppState>,
    session: SessionContext,
    Query(filter): Query<Filter>,
) -> Response {
    match content(&state, &session, filter.mission, false).await {
        Ok((content, heading)) => render(&TodayPage {
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
    filter: Filter,
    saved: Result<SaveOutcome, StoreError>,
) -> Response {
    let kind = match saved {
        Ok(SaveOutcome::Saved) => {
            return match filter.view {
                View::Focus => super::focus::fragment(state, session).await,
                View::Today => match content(state, session, filter.mission, true).await {
                    Ok((content, _heading)) => render_fragment(&content),
                    Err(error) => error.into_response(),
                },
            };
        }
        // One answer for "no such task" and "not yours", as on the API.
        Ok(SaveOutcome::NotFound) => ErrorKind::NotFound,
        Ok(SaveOutcome::Invalid(_)) => ErrorKind::TaskInvalid,
        Ok(SaveOutcome::NoRoom) => ErrorKind::TaskOrderConflict,
        // Only the Log writes time entries.
        Ok(SaveOutcome::Running) => ErrorKind::TimeEntryRunning,
        Err(err) => return internal(&err, "saving a task").into_response(),
    };
    ApiError::of(kind).into_response()
}

/// Today's date for a write, from the account's zone.
pub(super) async fn today_for(state: &AppState, user_id: &str) -> Result<Day, ApiError> {
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    day_of(&zone, UnixTime::now())
        .map(|(day, _)| day)
        .ok_or_else(|| ApiError::of(ErrorKind::InternalError))
}

#[derive(Deserialize)]
pub struct AddForm {
    title: String,
    /// A mission id, or empty for none.
    #[serde(default)]
    mission: String,
    /// `top` or `bottom`, from the button that sent the form.
    #[serde(default)]
    at: String,
}

pub async fn add(
    State(state): State<AppState>,
    session: SessionContext,
    Query(filter): Query<Filter>,
    Form(form): Form<AddForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let day = match today_for(&state, user_id).await {
        Ok(day) => day,
        Err(error) => return error.into_response(),
    };
    let place = if form.at == "top" {
        Place::Top
    } else {
        Place::Bottom
    };
    let mission = Some(form.mission).filter(|id| !id.is_empty());
    let saved = service::add_task(
        &state.pool,
        user_id,
        Some(&day.date),
        form.title,
        mission,
        place,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, filter, saved).await
}

pub async fn carry_over(
    State(state): State<AppState>,
    session: SessionContext,
    Query(filter): Query<Filter>,
) -> Response {
    let user_id = &session.auth().user.id;
    let day = match today_for(&state, user_id).await {
        Ok(day) => day,
        Err(error) => return error.into_response(),
    };
    let saved = service::carry_over(
        &state.pool,
        user_id,
        &day.yesterday,
        &day.date,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, filter, saved).await
}

#[derive(Deserialize)]
pub struct MoveForm {
    task: String,
    #[serde(default)]
    after: String,
    #[serde(default)]
    before: String,
}

pub async fn move_task(
    State(state): State<AppState>,
    session: SessionContext,
    Query(filter): Query<Filter>,
    Form(form): Form<MoveForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let neighbour = |id: &str| Some(id.to_owned()).filter(|id| !id.is_empty());
    let saved = service::move_task(
        &state.pool,
        user_id,
        &form.task,
        None,
        neighbour(&form.after).as_deref(),
        neighbour(&form.before).as_deref(),
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, filter, saved).await
}

pub async fn start(
    State(state): State<AppState>,
    session: SessionContext,
    Path(task_id): Path<String>,
    Query(filter): Query<Filter>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::start_timer(&state.pool, user_id, &task_id, UnixTime::now()).await;
    answer(&state, &session, filter, saved).await
}

pub async fn stop(
    State(state): State<AppState>,
    session: SessionContext,
    Path(task_id): Path<String>,
    Query(filter): Query<Filter>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::stop_timer(&state.pool, user_id, &task_id, UnixTime::now()).await;
    answer(&state, &session, filter, saved).await
}

#[derive(Deserialize)]
pub struct DoneForm {
    done: bool,
}

pub async fn done(
    State(state): State<AppState>,
    session: SessionContext,
    Path(task_id): Path<String>,
    Query(filter): Query<Filter>,
    Form(form): Form<DoneForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved = service::set_done(&state.pool, user_id, &task_id, form.done, UnixTime::now()).await;
    answer(&state, &session, filter, saved).await
}

/// Plans the task for tomorrow, at the end.
pub async fn tomorrow(
    State(state): State<AppState>,
    session: SessionContext,
    Path(task_id): Path<String>,
    Query(filter): Query<Filter>,
) -> Response {
    let user_id = &session.auth().user.id;
    let day = match today_for(&state, user_id).await {
        Ok(day) => day,
        Err(error) => return error.into_response(),
    };
    let saved = service::move_to_end_of(
        &state.pool,
        user_id,
        &task_id,
        &day.tomorrow,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, filter, saved).await
}

#[derive(Deserialize)]
pub struct NotesForm {
    #[serde(default)]
    notes: String,
}

pub async fn notes(
    State(state): State<AppState>,
    session: SessionContext,
    Path(task_id): Path<String>,
    Query(filter): Query<Filter>,
    Form(form): Form<NotesForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let saved =
        service::set_notes(&state.pool, user_id, &task_id, &form.notes, UnixTime::now()).await;
    answer(&state, &session, filter, saved).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: &str) -> TaskCard {
        TaskCard {
            id: id.to_owned(),
            title: String::new(),
            mission: None,
            colour: None,
            tracked: String::new(),
            tracked_secs: 0,
            running: false,
            done: false,
            up: None,
            down: None,
        }
    }

    #[test]
    fn up_and_down_name_the_two_tasks_to_land_between() {
        let mut cards: Vec<TaskCard> = ["a", "b", "c"].into_iter().map(card).collect();
        with_neighbours(&mut cards);
        let pair = |n: &Option<Neighbours>| n.as_ref().map(|n| (n.after.clone(), n.before.clone()));
        assert_eq!(pair(&cards[0].up), None);
        assert_eq!(pair(&cards[0].down), Some(("b".into(), "c".into())));
        assert_eq!(pair(&cards[1].up), Some((String::new(), "a".into())));
        assert_eq!(pair(&cards[1].down), Some(("c".into(), String::new())));
        assert_eq!(pair(&cards[2].up), Some(("a".into(), "b".into())));
        assert_eq!(pair(&cards[2].down), None);
    }

    #[test]
    fn the_timeline_clips_entries_to_the_day_and_runs_to_now() {
        let utc = TimeZoneName::utc();
        let day = (86_400, 2 * 86_400);
        let entry = |start, end| TrackedEntry {
            id: String::new(),
            task_id: String::new(),
            mission_id: None,
            start_ts: start,
            end_ts: end,
            task_title: "Exercise 4".to_owned(),
            colour: Some(2),
        };
        let now = 86_400 + 12 * 3600;
        let timeline = timeline_of(
            &[
                entry(86_400 - 3600, Some(86_400 + 3600)),
                entry(86_400 + 11 * 3600, None),
                entry(2 * 86_400, Some(2 * 86_400 + 60)),
            ],
            day,
            &utc,
            now,
        );
        assert_eq!(
            timeline.blocks.len(),
            2,
            "the one after the day is left out"
        );
        assert_eq!(timeline.blocks[0].x, "0.00");
        assert_eq!(timeline.blocks[0].width, "60.00");
        assert_eq!(timeline.blocks[1].x, "660.00");
        assert_eq!(timeline.blocks[1].width, "60.00");
        assert!(timeline.blocks[1].running);
        assert_eq!(timeline.blocks[1].title, "Exercise 4, 11:00 to now");
        assert_eq!(timeline.now_x, "720.00");
        assert_eq!(timeline.label, "Tracked today: 2h 0m");
        assert_eq!(timeline.total_secs, 7200);
    }

    #[test]
    fn the_heading_names_weekday_day_and_month() {
        let date = jiff::civil::date(2026, 11, 5);
        assert_eq!(
            date.strftime("%A, %-d %B").to_string(),
            "Thursday, 5 November"
        );
    }
}
