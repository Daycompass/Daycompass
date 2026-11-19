//! `GET /missions/focus`: only the task to work on now, out of today's.
//!
//! That is the open task whose timer runs, or else the first open one in
//! the order the Today page lists them. Completing it brings the next;
//! with none left the page says the day is done. Its writes are the
//! Today page's, sent with `?view=focus`, which answers with `#focus`.

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use super::today::{internal, today_for};
use super::{format_clock, format_duration, render, render_fragment, Shell, TimerPill, TimerSlot};
use crate::auth::time::UnixTime;
use crate::error::ApiError;
use crate::missions::service::{self, TodayData};
use crate::routes::SessionContext;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "missions_focus.html")]
struct FocusPage {
    shell: Shell,
    content: FocusContent,
}

#[derive(Template)]
#[template(path = "partials/focus.html")]
pub(super) struct FocusContent {
    current: Option<Current>,
    /// Today's other open tasks.
    more: usize,
    /// Whether anything at all is planned for today.
    planned: bool,
    today: String,
    /// On an htmx answer: the timer pill, replaced out of band.
    timer_slot: Option<TimerSlot>,
}

struct Current {
    id: String,
    title: String,
    mission: Option<String>,
    colour: Option<i64>,
    notes: String,
    /// As on a Today card: `2h 5m`, or a ticking `2:05:09`.
    tracked: String,
    tracked_secs: i64,
    running: bool,
}

async fn content(
    state: &AppState,
    session: &SessionContext,
    htmx: bool,
) -> Result<FocusContent, ApiError> {
    let user_id = &session.auth().user.id;
    let day = today_for(state, user_id).await?;
    let now = UnixTime::now();
    let data = service::today_of(&state.pool, user_id, &day, now)
        .await
        .map_err(|err| internal(&err, "reading today's tasks"))?;
    Ok(build(data, now, htmx))
}

fn build(data: TodayData, now: UnixTime, htmx: bool) -> FocusContent {
    let TodayData {
        missions,
        tasks,
        running,
        hours,
        ..
    } = data;
    let running_task = running.as_ref().map(|timer| timer.task_id.as_str());
    // A task whose mission is gone counts as "Other", as on Today.
    let mission_of = |id: Option<&str>| missions.iter().find(|m| Some(m.id.as_str()) == id);
    let mut open: Vec<_> = tasks.iter().filter(|t| t.task.done_at.is_none()).collect();
    // Today lists tasks under a mission first, then "Other".
    open.sort_by_key(|t| mission_of(t.task.mission_id.as_deref()).is_none());
    let at = open
        .iter()
        .position(|t| Some(t.task.id.as_str()) == running_task)
        .unwrap_or(0);
    let current = open.get(at).map(|view| {
        let running = Some(view.task.id.as_str()) == running_task;
        let mission = mission_of(view.task.mission_id.as_deref());
        Current {
            id: view.task.id.clone(),
            title: view.task.title.clone(),
            mission: mission.map(|m| m.title.clone()),
            colour: mission.map(|m| m.colour),
            notes: view.task.notes.clone().unwrap_or_default(),
            tracked: if running {
                format_clock(view.tracked_secs)
            } else {
                format_duration(view.tracked_secs)
            },
            tracked_secs: view.tracked_secs,
            running,
        }
    });
    FocusContent {
        current,
        more: open.len().saturating_sub(1),
        planned: !tasks.is_empty(),
        today: format_duration(hours.today_secs),
        timer_slot: htmx.then(|| TimerSlot {
            timer: running.map(|timer| TimerPill::new(timer, now.as_secs())),
            oob: true,
        }),
    }
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    match content(&state, &session, false).await {
        Ok(content) => render(&FocusPage {
            shell: Shell::load(&state.pool, session.auth(), "missions").await,
            content,
        }),
        Err(error) => error.into_response(),
    }
}

/// The answer to a write sent from this page.
pub(super) async fn fragment(state: &AppState, session: &SessionContext) -> Response {
    match content(state, session, true).await {
        Ok(content) => render_fragment(&content),
        Err(error) => error.into_response(),
    }
}
