//! Missions as the dashboard reads and writes them: the account's own
//! missions with their tracked time, the day's tasks and their timer,
//! the North Star.
//!
//! Every write goes through [`sync::apply_own`], so a mission edited in
//! the browser obeys the same rules as one pushed by a device - same
//! validation, last write wins, a new rev that devices then pull.
//! Nothing here knows about forms or HTML.

use sqlx::SqlitePool;

use super::position::key_between;
use super::store::{self, RunningTimer, TrackedEntry};
use super::sync::{self, Changes, Outcome};
use super::validate::{self, Mission, RejectReason, Task, TimeEntry};
use crate::auth::store::{new_id, StoreError};
use crate::auth::time::UnixTime;

/// A live mission with its tracked time.
pub struct MissionView {
    pub mission: Mission,
    pub week_secs: i64,
    pub total_secs: i64,
}

/// The account's live missions, active before archived, each group by
/// title. `week` is `[start, end)` in Unix seconds.
pub async fn list_own(
    pool: &SqlitePool,
    user_id: &str,
    week: (i64, i64),
    now: UnixTime,
) -> Result<Vec<MissionView>, StoreError> {
    let mut conn = pool.acquire().await?;
    let missions = store::missions_after(&mut conn, user_id, 0, -1, true).await?;
    let times = store::mission_times(&mut conn, user_id, week.0, week.1, now.as_secs()).await?;

    let mut views: Vec<MissionView> = missions
        .into_iter()
        .map(|(_rev, mission)| {
            let time = times.iter().find(|time| time.mission_id == mission.id);
            MissionView {
                week_secs: time.map_or(0, |time| time.window_secs),
                total_secs: time.map_or(0, |time| time.total_secs),
                mission,
            }
        })
        .collect();
    views.sort_by_cached_key(|view| (view.mission.archived, view.mission.title.to_lowercase()));
    Ok(views)
}

/// What the account holder fills in for a mission: everything a device
/// can set except the id, `archived` and the timestamps.
pub struct MissionFields {
    pub title: String,
    pub colour: i64,
    pub weekly_goal_secs: i64,
    pub description: Option<String>,
    pub why: Option<String>,
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    Saved,
    /// No live record of this account has that id.
    NotFound,
    Invalid(RejectReason),
    /// No position key fits where the task was to go: its neighbours'
    /// keys are equal, or not of the scheme in [`super::position`].
    NoRoom,
}

/// Creates a mission (`id: None`) or replaces the fields of one of the
/// account's own.
pub async fn save_own(
    pool: &SqlitePool,
    user_id: &str,
    id: Option<&str>,
    fields: MissionFields,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let (id, archived, updated_at) = match id {
        None => (new_id(), false, now.as_secs()),
        Some(id) => {
            let mut conn = pool.acquire().await?;
            let Some(stored) = store::live_mission(&mut conn, user_id, id).await? else {
                return Ok(SaveOutcome::NotFound);
            };
            let updated_at = edit_time(stored.updated_at, now);
            (stored.id, stored.archived, updated_at)
        }
    };
    let mission = Mission {
        id,
        title: fields.title,
        colour: fields.colour,
        weekly_goal_secs: fields.weekly_goal_secs,
        description: fields.description,
        why: fields.why,
        starts_on: fields.starts_on,
        ends_on: fields.ends_on,
        archived,
        deleted: false,
        updated_at,
    };
    write(pool, user_id, missions(mission), now).await
}

pub async fn set_archived_own(
    pool: &SqlitePool,
    user_id: &str,
    id: &str,
    archived: bool,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(stored) = store::live_mission(&mut conn, user_id, id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    drop(conn);
    let mission = Mission {
        archived,
        updated_at: edit_time(stored.updated_at, now),
        ..stored
    };
    write(pool, user_id, missions(mission), now).await
}

/// The `updated_at` of an edit made now. Never older than the stored
/// one: a device clock running ahead (within the allowed skew) must not
/// make an edit made after it lose.
fn edit_time(stored: i64, now: UnixTime) -> i64 {
    now.as_secs().max(stored)
}

fn missions(mission: Mission) -> Changes {
    Changes {
        missions: vec![mission],
        ..Changes::default()
    }
}

fn tasks(tasks: Vec<Task>) -> Changes {
    Changes {
        tasks,
        ..Changes::default()
    }
}

/// Applies `push` through the sync rules. The first refused record, if
/// any, decides the outcome; the records are all built here, so only
/// what the account holder typed can be refused.
async fn write(
    pool: &SqlitePool,
    user_id: &str,
    push: Changes,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let report = sync::apply_own(pool, user_id, &push, now).await?;
    let refused = report
        .missions
        .iter()
        .chain(&report.tasks)
        .chain(&report.time_entries)
        .find_map(|outcome| match outcome {
            Outcome::Rejected(reason) => Some(*reason),
            _ => None,
        });
    // shortcut: `Stale` (a device wrote a newer version between the read
    // and this write) counts as saved; the caller shows the winner.
    // Surface it if that race ever matters in practice.
    Ok(refused.map_or(SaveOutcome::Saved, SaveOutcome::Invalid))
}

/// The day the Today page shows, as the account's time zone sees it.
pub struct Day {
    /// `YYYY-MM-DD`, the value of `tasks.day`.
    pub date: String,
    pub yesterday: String,
    /// `[start, end)` of the day and of its ISO week, Unix seconds.
    pub bounds: (i64, i64),
    pub week: (i64, i64),
}

/// Time on tasks under a live mission, today and this week, against
/// the weekly goals of the active ones.
pub struct MissionHours {
    pub today_secs: i64,
    pub week_secs: i64,
    pub week_goal_secs: i64,
    /// Missions that are not archived.
    pub active: usize,
}

pub async fn mission_hours(
    pool: &SqlitePool,
    user_id: &str,
    day: (i64, i64),
    week: (i64, i64),
    now: UnixTime,
) -> Result<MissionHours, StoreError> {
    let mut conn = pool.acquire().await?;
    let missions = store::missions_after(&mut conn, user_id, 0, -1, true).await?;
    let today = store::mission_times(&mut conn, user_id, day.0, day.1, now.as_secs()).await?;
    let this_week = store::mission_times(&mut conn, user_id, week.0, week.1, now.as_secs()).await?;

    let live = |id: &str| missions.iter().any(|(_, mission)| mission.id == id);
    let sum = |times: &[store::MissionTime]| -> i64 {
        times
            .iter()
            .filter(|time| live(&time.mission_id))
            .map(|time| time.window_secs)
            .sum()
    };
    let active = || missions.iter().filter(|(_, mission)| !mission.archived);
    Ok(MissionHours {
        today_secs: sum(&today),
        week_secs: sum(&this_week),
        week_goal_secs: active().map(|(_, mission)| mission.weekly_goal_secs).sum(),
        active: active().count(),
    })
}

/// A task planned for the day, with all the time tracked on it.
pub struct TaskView {
    pub task: Task,
    pub tracked_secs: i64,
}

pub struct TodayData {
    /// Every live mission, archived ones included: tasks may still
    /// name them.
    pub missions: Vec<Mission>,
    /// In their order, see [`store::tasks_of_day`].
    pub tasks: Vec<TaskView>,
    pub running: Option<RunningTimer>,
    pub timeline: Vec<TrackedEntry>,
    /// Open tasks still planned for yesterday.
    pub left_from_yesterday: usize,
    pub hours: MissionHours,
}

pub async fn today_of(
    pool: &SqlitePool,
    user_id: &str,
    day: &Day,
    now: UnixTime,
) -> Result<TodayData, StoreError> {
    let hours = mission_hours(pool, user_id, day.bounds, day.week, now).await?;
    let mut conn = pool.acquire().await?;
    let mut missions: Vec<Mission> = store::missions_after(&mut conn, user_id, 0, -1, true)
        .await?
        .into_iter()
        .map(|(_rev, mission)| mission)
        .collect();
    missions.sort_by_cached_key(|mission| mission.title.to_lowercase());
    let times = store::task_times(&mut conn, user_id, &day.date, now.as_secs()).await?;
    let tasks = store::tasks_of_day(&mut conn, user_id, &day.date)
        .await?
        .into_iter()
        .map(|task| TaskView {
            tracked_secs: times
                .iter()
                .find(|(id, _)| *id == task.id)
                .map_or(0, |(_, secs)| *secs),
            task,
        })
        .collect();
    let left_from_yesterday = store::tasks_of_day(&mut conn, user_id, &day.yesterday)
        .await?
        .iter()
        .filter(|task| task.done_at.is_none())
        .count();
    Ok(TodayData {
        missions,
        tasks,
        running: store::running_timer(&mut conn, user_id).await?,
        timeline: store::entries_overlapping(
            &mut conn,
            user_id,
            day.bounds.0,
            day.bounds.1,
            now.as_secs(),
        )
        .await?,
        left_from_yesterday,
        hours,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Top,
    Bottom,
}

/// Adds a task to `day`, before or after all of its tasks.
pub async fn add_task(
    pool: &SqlitePool,
    user_id: &str,
    day: &str,
    title: String,
    mission_id: Option<String>,
    place: Place,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let planned = store::tasks_of_day(&mut conn, user_id, day).await?;
    drop(conn);
    let position = match place {
        Place::Top => key_between(None, planned.first().map(|task| task.position.as_str())),
        Place::Bottom => key_between(planned.last().map(|task| task.position.as_str()), None),
    };
    let Some(position) = position else {
        return Ok(SaveOutcome::NoRoom);
    };
    let task = Task {
        id: new_id(),
        mission_id,
        title,
        notes: None,
        day: Some(day.to_owned()),
        position,
        done_at: None,
        deleted: false,
        updated_at: now.as_secs(),
    };
    write(pool, user_id, tasks(vec![task]), now).await
}

/// Starts a timer on one of the account's tasks. The sync rules end
/// whatever timer ran before, on any device: one per account.
pub async fn start_timer(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    let running = store::live_running_entry(&mut conn, user_id).await?;
    drop(conn);
    if running.is_some_and(|entry| entry.task_id == task.id) {
        return Ok(SaveOutcome::Saved);
    }
    let entry = TimeEntry {
        id: new_id(),
        task_id: task.id,
        start_ts: now.as_secs(),
        end_ts: None,
        deleted: false,
        updated_at: now.as_secs(),
    };
    let push = Changes {
        time_entries: vec![entry],
        ..Changes::default()
    };
    write(pool, user_id, push, now).await
}

/// Stops the timer if it runs on this task; otherwise there is nothing
/// to stop, which is not an error.
pub async fn stop_timer(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    let running = store::live_running_entry(&mut conn, user_id).await?;
    drop(conn);
    match running.filter(|entry| entry.task_id == task.id) {
        Some(entry) => {
            let push = Changes {
                time_entries: vec![ended(entry, now)],
                ..Changes::default()
            };
            write(pool, user_id, push, now).await
        }
        None => Ok(SaveOutcome::Saved),
    }
}

/// The entry ended now - at least a second after its start, which the
/// sync rules require of an end.
fn ended(entry: TimeEntry, now: UnixTime) -> TimeEntry {
    TimeEntry {
        end_ts: Some(now.as_secs().max(entry.start_ts + 1)),
        updated_at: edit_time(entry.updated_at, now),
        ..entry
    }
}

/// Marks a task done (stopping its timer, if it runs) or open again.
pub async fn set_done(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    done: bool,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    let running = store::live_running_entry(&mut conn, user_id).await?;
    drop(conn);
    let mut push = tasks(vec![Task {
        done_at: if done {
            task.done_at.or(Some(now.as_secs()))
        } else {
            None
        },
        updated_at: edit_time(task.updated_at, now),
        ..task
    }]);
    if let Some(entry) = running.filter(|entry| done && entry.task_id == task_id) {
        push.time_entries.push(ended(entry, now));
    }
    write(pool, user_id, push, now).await
}

/// Puts a task between two others (`None`: at that end).
pub async fn move_task(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    after: Option<&str>,
    before: Option<&str>,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    let mut positions = [None, None];
    for (slot, id) in positions.iter_mut().zip([after, before]) {
        if let Some(id) = id {
            let Some(neighbour) = store::live_task(&mut conn, user_id, id).await? else {
                return Ok(SaveOutcome::NotFound);
            };
            *slot = Some(neighbour.position);
        }
    }
    drop(conn);
    let [after, before] = positions;
    let Some(position) = key_between(after.as_deref(), before.as_deref()) else {
        return Ok(SaveOutcome::NoRoom);
    };
    let task = Task {
        position,
        updated_at: edit_time(task.updated_at, now),
        ..task
    };
    write(pool, user_id, tasks(vec![task]), now).await
}

/// Moves the open tasks of `from` to the end of `to`, in their order.
pub async fn carry_over(
    pool: &SqlitePool,
    user_id: &str,
    from: &str,
    to: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let left = store::tasks_of_day(&mut conn, user_id, from).await?;
    let planned = store::tasks_of_day(&mut conn, user_id, to).await?;
    drop(conn);
    let mut last = planned.last().map(|task| task.position.clone());
    let mut moved = Vec::new();
    for task in left.into_iter().filter(|task| task.done_at.is_none()) {
        let Some(position) = key_between(last.as_deref(), None) else {
            return Ok(SaveOutcome::NoRoom);
        };
        last = Some(position.clone());
        moved.push(Task {
            day: Some(to.to_owned()),
            position,
            updated_at: edit_time(task.updated_at, now),
            ..task
        });
    }
    if moved.is_empty() {
        return Ok(SaveOutcome::Saved);
    }
    write(pool, user_id, tasks(moved), now).await
}

pub async fn running_timer(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<RunningTimer>, StoreError> {
    let mut conn = pool.acquire().await?;
    store::running_timer(&mut conn, user_id).await
}

pub async fn north_star(pool: &SqlitePool, user_id: &str) -> Result<Option<String>, StoreError> {
    let mut conn = pool.acquire().await?;
    store::north_star(&mut conn, user_id).await
}

/// Sets the North Star; blank clears it.
pub async fn set_north_star(
    pool: &SqlitePool,
    user_id: &str,
    raw: &str,
) -> Result<Result<(), RejectReason>, StoreError> {
    let value = match validate::north_star(raw) {
        Ok(value) => value,
        Err(reason) => return Ok(Err(reason)),
    };
    let mut conn = pool.acquire().await?;
    store::set_north_star(&mut conn, user_id, value.as_deref()).await?;
    Ok(Ok(()))
}
