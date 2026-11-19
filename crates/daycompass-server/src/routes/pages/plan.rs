//! `GET /missions/plan` and its writes: one week of tasks, Monday to
//! Sunday, next to the backlog, to plan and order by drag and drop or
//! by buttons.
//!
//! Thin, like every page handler: each write is one call into
//! [`crate::missions::service`], which goes through the sync rules a
//! device's push goes through. Every write answers with the whole
//! `#plan` block.
//!
//! The query only narrows what is shown: `week` (any `YYYY-MM-DD` of
//! the week; this week without it), `mission` (a filter, as on Today)
//! and `hide_done`. Every write's URL carries it along so the answer
//! keeps it.
//!
//! Weeks are ISO weeks, days calendar days, in the account's time zone.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use jiff::civil::Date;
use jiff::ToSpan;
use serde::Deserialize;

use super::today::{up_and_down, Chip, Choice, Neighbours};
use super::{render, render_fragment, Shell};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::service::{self, Place, PlanData, SaveOutcome};
use crate::missions::validate::{Mission, Task};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::timezone;

#[derive(Template)]
#[template(path = "missions_plan.html")]
struct PlanPage {
    shell: Shell,
    heading: String,
    content: PlanContent,
}

#[derive(Template)]
#[template(path = "partials/plan.html")]
struct PlanContent {
    /// The page's own query, which every write keeps.
    query: String,
    /// The query of the week before, of this week, of the week after,
    /// and of this page with "hide done" flipped.
    previous: String,
    this_week: String,
    next: String,
    hide_done: bool,
    done_toggle: String,
    chips: Vec<Chip>,
    choices: Vec<Choice>,
    /// The backlog, then Monday to Sunday.
    columns: Vec<Column>,
}

struct Column {
    /// `YYYY-MM-DD`, empty for the backlog: what a write sends as `day`.
    day: String,
    /// Unique on the page, for element ids.
    key: String,
    name: String,
    /// `16 Nov`, empty for the backlog.
    date: String,
    today: bool,
    past: bool,
    open: Vec<PlanCard>,
    /// Empty while done tasks are hidden.
    done: Vec<PlanCard>,
}

struct PlanCard {
    id: String,
    title: String,
    mission: Option<String>,
    colour: Option<i64>,
    up: Option<Neighbours>,
    down: Option<Neighbours>,
    /// To the bottom of the column before and after this one. Only the
    /// columns on the page: a drag cannot reach further either.
    earlier: Option<Hop>,
    later: Option<Hop>,
}

/// A move to the bottom of another column.
#[derive(Clone)]
struct Hop {
    day: String,
    /// The last open task shown there; empty if none.
    after: String,
    /// `Tuesday`, `the backlog`: for the button's label.
    to: String,
}

#[derive(Deserialize)]
pub struct View {
    week: Option<String>,
    mission: Option<String>,
    #[serde(default)]
    hide_done: bool,
}

impl View {
    /// `?week=...&mission=...&hide_done=true`, each part only if set.
    fn query(week: Option<Date>, mission: Option<&str>, hide_done: bool) -> String {
        let parts: Vec<String> = [
            week.map(|week| format!("week={week}")),
            mission.map(|id| format!("mission={id}")),
            hide_done.then(|| "hide_done=true".to_owned()),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        }
    }
}

fn internal(err: &StoreError, what: &'static str) -> ApiError {
    tracing::error!(error = %err, "{what} failed");
    ApiError::of(ErrorKind::InternalError)
}

/// The seven days, Monday first, of the week `raw` falls in, or of the
/// week `today` falls in. `None` if `raw` is not a date.
fn week_of(raw: Option<&str>, today: Date) -> Option<Vec<Date>> {
    let date: Date = match raw {
        Some(raw) => raw.parse().ok()?,
        None => today,
    };
    let offset = i64::from(date.weekday().to_monday_zero_offset());
    let monday = date.checked_sub(offset.days()).ok()?;
    (0_i64..7)
        .map(|n| monday.checked_add(n.days()).ok())
        .collect()
}

/// `November 2026`, `November - December 2026`, `December 2026 -
/// January 2027`.
fn month_label(first: Date, last: Date) -> String {
    if (first.year(), first.month()) == (last.year(), last.month()) {
        first.strftime("%B %Y").to_string()
    } else if first.year() == last.year() {
        format!("{} - {}", first.strftime("%B"), last.strftime("%B %Y"))
    } else {
        format!("{} - {}", first.strftime("%B %Y"), last.strftime("%B %Y"))
    }
}

/// The `#plan` block and the page heading, for the caller right now.
async fn content(
    state: &AppState,
    session: &SessionContext,
    view: &View,
) -> Result<(PlanContent, String), ApiError> {
    let user_id = &session.auth().user.id;
    let zone = timezone::get_for_user(&state.pool, user_id)
        .await
        .map_err(|err| internal(&err, "reading the time zone"))?;
    let Some(today) = zone.date(UnixTime::now().as_secs()) else {
        tracing::error!("working out today's date failed");
        return Err(ApiError::of(ErrorKind::InternalError));
    };
    let days = week_of(view.week.as_deref(), today).ok_or(ApiError::of(ErrorKind::BadRequest))?;
    let dates: Vec<String> = days.iter().map(Date::to_string).collect();
    let data = service::plan_of(&state.pool, user_id, &dates)
        .await
        .map_err(|err| internal(&err, "reading the week's tasks"))?;
    let heading = month_label(days[0], days[6]);
    Ok((build(data, &days, today, view), heading))
}

fn build(data: PlanData, days: &[Date], today: Date, view: &View) -> PlanContent {
    let PlanData { missions, columns } = data;
    let filter = view.mission.as_deref();
    let monday = days[0];
    let shift = |weeks: i64| monday.checked_add(weeks.weeks()).ok();

    let mut chips = vec![Chip {
        href: format!(
            "/missions/plan{}",
            View::query(Some(monday), None, view.hide_done)
        ),
        title: "All".to_owned(),
        colour: None,
        current: filter.is_none(),
    }];
    chips.extend(missions.iter().filter(|m| !m.archived).map(|m| Chip {
        href: format!(
            "/missions/plan{}",
            View::query(Some(monday), Some(&m.id), view.hide_done)
        ),
        title: m.title.clone(),
        colour: Some(m.colour),
        current: filter == Some(m.id.as_str()),
    }));
    let choices = missions
        .iter()
        .filter(|m| !m.archived)
        .map(|m| Choice {
            id: m.id.clone(),
            title: m.title.clone(),
            selected: filter == Some(m.id.as_str()),
        })
        .collect();

    let heads = std::iter::once(None).chain(days.iter().copied().map(Some));
    let mut columns: Vec<Column> = heads
        .zip(columns)
        .map(|(date, tasks)| column(date, tasks, &missions, today, view))
        .collect();
    with_hops(&mut columns);

    PlanContent {
        query: View::query(Some(monday), filter, view.hide_done),
        previous: View::query(shift(-1), filter, view.hide_done),
        this_week: View::query(None, filter, view.hide_done),
        next: View::query(shift(1), filter, view.hide_done),
        hide_done: view.hide_done,
        done_toggle: View::query(Some(monday), filter, !view.hide_done),
        chips,
        choices,
        columns,
    }
}

/// One column: the backlog (`date: None`) or a day.
fn column(
    date: Option<Date>,
    tasks: Vec<Task>,
    missions: &[Mission],
    today: Date,
    view: &View,
) -> Column {
    let shown = tasks
        .into_iter()
        .filter(|task| match view.mission.as_deref() {
            Some(id) => task.mission_id.as_deref() == Some(id),
            None => true,
        })
        .filter(|task| !(view.hide_done && task.done_at.is_some()));
    let (mut open, mut done) = (Vec::new(), Vec::new());
    for task in shown {
        // A task whose mission is gone counts as "Other".
        let mission = task
            .mission_id
            .as_deref()
            .and_then(|id| missions.iter().find(|m| m.id == id));
        let card = PlanCard {
            mission: mission.map(|m| m.title.clone()),
            colour: mission.map(|m| m.colour),
            id: task.id,
            title: task.title,
            up: None,
            down: None,
            earlier: None,
            later: None,
        };
        if task.done_at.is_some() {
            done.push(card);
        } else {
            open.push(card);
        }
    }
    let ids: Vec<String> = open.iter().map(|card| card.id.clone()).collect();
    for (index, card) in open.iter_mut().enumerate() {
        (card.up, card.down) = up_and_down(&ids, index);
    }
    match date {
        None => Column {
            day: String::new(),
            key: "backlog".to_owned(),
            name: "Backlog".to_owned(),
            date: String::new(),
            today: false,
            past: false,
            open,
            done,
        },
        Some(date) => Column {
            day: date.to_string(),
            key: date.to_string(),
            name: date.strftime("%A").to_string(),
            date: date.strftime("%-d %b").to_string(),
            today: date == today,
            past: date < today,
            open,
            done,
        },
    }
}

/// Gives each open card the moves to the column before and after its own.
fn with_hops(columns: &mut [Column]) {
    let hops: Vec<Hop> = columns
        .iter()
        .map(|column| Hop {
            day: column.day.clone(),
            after: column
                .open
                .last()
                .map(|card| card.id.clone())
                .unwrap_or_default(),
            to: if column.day.is_empty() {
                "the backlog".to_owned()
            } else {
                column.name.clone()
            },
        })
        .collect();
    let hop = |index: Option<usize>| hops.get(index?).cloned();
    for (index, column) in columns.iter_mut().enumerate() {
        for card in &mut column.open {
            card.earlier = hop(index.checked_sub(1));
            card.later = hop(Some(index + 1));
        }
    }
}

pub async fn page(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
) -> Response {
    match content(&state, &session, &view).await {
        Ok((content, heading)) => render(&PlanPage {
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
            return match content(state, session, view).await {
                Ok((content, _heading)) => render_fragment(&content),
                Err(error) => error.into_response(),
            };
        }
        // One answer for "no such task" and "not yours", as on the API.
        Ok(SaveOutcome::NotFound) => ErrorKind::NotFound,
        Ok(SaveOutcome::Invalid(_)) => ErrorKind::TaskInvalid,
        Ok(SaveOutcome::NoRoom) => ErrorKind::TaskOrderConflict,
        Err(err) => return internal(&err, "saving a task").into_response(),
    };
    ApiError::of(kind).into_response()
}

/// Empty means none: the backlog for a `day`, an end for `after` and
/// `before`. The sync rules check the date.
fn non_empty(raw: &str) -> Option<&str> {
    Some(raw).filter(|day| !day.is_empty())
}

#[derive(Deserialize)]
pub struct AddForm {
    title: String,
    /// A mission id, or empty for none.
    #[serde(default)]
    mission: String,
    day: String,
    /// `top` or `bottom`, from the button that sent the form.
    #[serde(default)]
    at: String,
}

pub async fn add(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
    Form(form): Form<AddForm>,
) -> Response {
    let place = if form.at == "top" {
        Place::Top
    } else {
        Place::Bottom
    };
    let mission = Some(form.mission).filter(|id| !id.is_empty());
    let saved = service::add_task(
        &state.pool,
        &session.auth().user.id,
        non_empty(&form.day),
        form.title,
        mission,
        place,
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, &view, saved).await
}

#[derive(Deserialize)]
pub struct MoveForm {
    task: String,
    day: String,
    #[serde(default)]
    after: String,
    #[serde(default)]
    before: String,
}

pub async fn move_task(
    State(state): State<AppState>,
    session: SessionContext,
    Query(view): Query<View>,
    Form(form): Form<MoveForm>,
) -> Response {
    let saved = service::move_task(
        &state.pool,
        &session.auth().user.id,
        &form.task,
        Some(non_empty(&form.day)),
        non_empty(&form.after),
        non_empty(&form.before),
        UnixTime::now(),
    )
    .await;
    answer(&state, &session, &view, saved).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;

    #[test]
    fn a_week_runs_monday_to_sunday_around_any_of_its_days() {
        let today = date(2026, 11, 19);
        let week = week_of(None, today).unwrap();
        assert_eq!(week.first(), Some(&date(2026, 11, 16)));
        assert_eq!(week.last(), Some(&date(2026, 11, 22)));
        assert_eq!(week_of(Some("2026-11-22"), today), Some(week));
        assert_eq!(
            week_of(Some("2026-12-31"), today).unwrap()[0],
            date(2026, 12, 28)
        );
        assert_eq!(week_of(Some("next week"), today), None);
    }

    #[test]
    fn the_label_names_every_month_the_week_touches() {
        assert_eq!(
            month_label(date(2026, 11, 16), date(2026, 11, 22)),
            "November 2026"
        );
        assert_eq!(
            month_label(date(2026, 11, 30), date(2026, 12, 6)),
            "November - December 2026"
        );
        assert_eq!(
            month_label(date(2026, 12, 28), date(2027, 1, 3)),
            "December 2026 - January 2027"
        );
    }

    #[test]
    fn the_query_keeps_only_what_is_set() {
        assert_eq!(View::query(None, None, false), "");
        assert_eq!(
            View::query(Some(date(2026, 11, 16)), Some("ab"), true),
            "?week=2026-11-16&mission=ab&hide_done=true"
        );
    }
}
