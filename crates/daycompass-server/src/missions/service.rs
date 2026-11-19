//! Missions as the dashboard reads and writes them: the account's own
//! missions with their tracked time, the day's tasks and their timer,
//! the weekly review, the North Star.
//!
//! Every write goes through [`sync::apply_own`], so a mission edited in
//! the browser obeys the same rules as one pushed by a device - same
//! validation, last write wins, a new rev that devices then pull.
//! Nothing here knows about forms or HTML.

use jiff::civil::Date;
use jiff::ToSpan;
use sqlx::SqlitePool;

use super::position::key_between;
use super::store::{self, Kind, RunningTimer, TrackedEntry};
use super::sync::{self, Changes, Outcome};
use super::validate::{
    self, Mission, RejectReason, Review, ReviewGoal, Task, TimeEntry, MAX_REVIEW_GOALS,
};
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
    /// The time entry still runs: it can only be stopped.
    Running,
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
        .chain(&report.reviews)
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
    pub tomorrow: String,
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
    let missions = missions_by_title(&mut conn, user_id).await?;
    let times = store::task_times(&mut conn, user_id, &day.date, now.as_secs()).await?;
    let tasks = store::tasks_of_day(&mut conn, user_id, Some(&day.date))
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
    let left_from_yesterday = store::tasks_of_day(&mut conn, user_id, Some(&day.yesterday))
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

/// Every live mission, archived ones included (tasks may still name
/// them), by title.
async fn missions_by_title(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
) -> Result<Vec<Mission>, StoreError> {
    let mut missions: Vec<Mission> = store::missions_after(conn, user_id, 0, -1, true)
        .await?
        .into_iter()
        .map(|(_rev, mission)| mission)
        .collect();
    missions.sort_by_cached_key(|mission| mission.title.to_lowercase());
    Ok(missions)
}

pub struct PlanData {
    /// As in [`TodayData::missions`].
    pub missions: Vec<Mission>,
    /// The backlog's tasks, then each day's, each in their order.
    pub columns: Vec<Vec<Task>>,
}

/// The backlog and the tasks planned for each of `days` (`YYYY-MM-DD`).
pub async fn plan_of(
    pool: &SqlitePool,
    user_id: &str,
    days: &[String],
) -> Result<PlanData, StoreError> {
    let mut conn = pool.acquire().await?;
    let missions = missions_by_title(&mut conn, user_id).await?;
    let mut columns = vec![store::tasks_of_day(&mut conn, user_id, None).await?];
    for day in days {
        columns.push(store::tasks_of_day(&mut conn, user_id, Some(day)).await?);
    }
    Ok(PlanData { missions, columns })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Top,
    Bottom,
}

/// Adds a task to `day` (`None`: the backlog), before or after all of
/// its tasks.
pub async fn add_task(
    pool: &SqlitePool,
    user_id: &str,
    day: Option<&str>,
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
        day: day.map(str::to_owned),
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

/// Puts a task between two others (`None`: at that end). `day: Some`
/// also plans it for that day (`Some(None)`: the backlog); `None`
/// leaves it on its own.
pub async fn move_task(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    day: Option<Option<&str>>,
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
        day: day.map_or(task.day, |day| day.map(str::to_owned)),
        position,
        updated_at: edit_time(task.updated_at, now),
        ..task
    };
    write(pool, user_id, tasks(vec![task]), now).await
}

/// Plans a task for `day`, after all of that day's other tasks.
pub async fn move_to_end_of(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    day: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let planned = store::tasks_of_day(&mut conn, user_id, Some(day)).await?;
    drop(conn);
    let last = planned.iter().rev().find(|task| task.id != task_id);
    let after = last.map(|task| task.id.as_str());
    move_task(pool, user_id, task_id, Some(Some(day)), after, None, now).await
}

/// Sets a task's notes; blank clears them.
pub async fn set_notes(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    notes: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    drop(conn);
    // A browser sends a textarea's line breaks as CRLF; the sync rules
    // accept LF only.
    let notes = notes.replace("\r\n", "\n");
    let task = Task {
        notes: Some(notes).filter(|notes| !notes.trim().is_empty()),
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
    let left = store::tasks_of_day(&mut conn, user_id, Some(from)).await?;
    let planned = store::tasks_of_day(&mut conn, user_id, Some(to)).await?;
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

pub struct LogData {
    /// The backlog and the week's days, as in [`plan_of`]: the tasks
    /// time can be put on.
    pub plan: PlanData,
    /// Live entries of live tasks overlapping the week, oldest first.
    pub entries: Vec<TrackedEntry>,
}

/// What the Log shows of the week of `days` (`YYYY-MM-DD`), which spans
/// `week`, `[start, end)` in Unix seconds.
pub async fn log_of(
    pool: &SqlitePool,
    user_id: &str,
    days: &[String],
    week: (i64, i64),
    now: UnixTime,
) -> Result<LogData, StoreError> {
    let plan = plan_of(pool, user_id, days).await?;
    let mut conn = pool.acquire().await?;
    let entries =
        store::entries_overlapping(&mut conn, user_id, week.0, week.1, now.as_secs()).await?;
    Ok(LogData { plan, entries })
}

/// Stricter than the sync rules, which allow a device's clock some
/// skew: time entered here was read off this server's clock.
fn check_span(start: i64, end: i64, now: UnixTime) -> Result<(), RejectReason> {
    if start > now.as_secs() {
        Err(RejectReason::StartInFuture)
    } else if end > now.as_secs() {
        Err(RejectReason::EndInFuture)
    } else if end <= start {
        Err(RejectReason::EndNotAfterStart)
    } else {
        Ok(())
    }
}

fn entries(entry: TimeEntry) -> Changes {
    Changes {
        time_entries: vec![entry],
        ..Changes::default()
    }
}

/// Adds time tracked without a timer, `[start, end)`, to a live task.
pub async fn add_entry(
    pool: &SqlitePool,
    user_id: &str,
    task_id: &str,
    start: i64,
    end: i64,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    if let Err(reason) = check_span(start, end, now) {
        return Ok(SaveOutcome::Invalid(reason));
    }
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    drop(conn);
    let entry = TimeEntry {
        id: new_id(),
        task_id: task.id,
        start_ts: start,
        end_ts: Some(end),
        deleted: false,
        updated_at: now.as_secs(),
    };
    write(pool, user_id, entries(entry), now).await
}

/// One of the account's live entries that is no longer running.
async fn stopped_entry(
    pool: &SqlitePool,
    user_id: &str,
    entry_id: &str,
) -> Result<Result<TimeEntry, SaveOutcome>, StoreError> {
    let mut conn = pool.acquire().await?;
    Ok(
        match store::live_entry(&mut conn, user_id, entry_id).await? {
            None => Err(SaveOutcome::NotFound),
            Some(entry) if entry.end_ts.is_none() => Err(SaveOutcome::Running),
            Some(entry) => Ok(entry),
        },
    )
}

/// Corrects a stopped entry: its start, its end and its task.
pub async fn correct_entry(
    pool: &SqlitePool,
    user_id: &str,
    entry_id: &str,
    task_id: &str,
    start: i64,
    end: i64,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let entry = match stopped_entry(pool, user_id, entry_id).await? {
        Ok(entry) => entry,
        Err(outcome) => return Ok(outcome),
    };
    if let Err(reason) = check_span(start, end, now) {
        return Ok(SaveOutcome::Invalid(reason));
    }
    let mut conn = pool.acquire().await?;
    let Some(task) = store::live_task(&mut conn, user_id, task_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    drop(conn);
    let entry = TimeEntry {
        task_id: task.id,
        start_ts: start,
        end_ts: Some(end),
        updated_at: edit_time(entry.updated_at, now),
        ..entry
    };
    write(pool, user_id, entries(entry), now).await
}

/// Deletes a stopped entry.
pub async fn delete_entry(
    pool: &SqlitePool,
    user_id: &str,
    entry_id: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let entry = match stopped_entry(pool, user_id, entry_id).await? {
        Ok(entry) => entry,
        Err(outcome) => return Ok(outcome),
    };
    let entry = TimeEntry {
        deleted: true,
        updated_at: edit_time(entry.updated_at, now),
        ..entry
    };
    write(pool, user_id, entries(entry), now).await
}

/// Stops an entry if it runs; a stopped one has nothing to stop, which
/// is not an error.
pub async fn stop_entry(
    pool: &SqlitePool,
    user_id: &str,
    entry_id: &str,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let Some(entry) = store::live_entry(&mut conn, user_id, entry_id).await? else {
        return Ok(SaveOutcome::NotFound);
    };
    drop(conn);
    if entry.end_ts.is_some() {
        return Ok(SaveOutcome::Saved);
    }
    write(pool, user_id, entries(ended(entry, now)), now).await
}

/// Seconds of `entry` inside `[start, end)`; a running entry runs to
/// `now`.
pub fn clipped(entry: &TrackedEntry, (start, end): (i64, i64), now: i64) -> i64 {
    (entry.end_ts.unwrap_or(now).min(end) - entry.start_ts.max(start)).max(0)
}

/// One mission's week: tracked time against its goal.
pub struct MissionWeek {
    pub mission: Mission,
    pub actual_secs: i64,
    pub goal_secs: i64,
}

/// Everything the review of one week shows.
pub struct ReviewData {
    /// Mission Hours per day of the week.
    pub day_secs: Vec<i64>,
    pub mission_secs: i64,
    /// All tracked time, on tasks with a mission or without.
    pub tracked_secs: i64,
    /// Live missions with a goal or tracked time this week, by title.
    /// The goal is the review's snapshot, or today's goal before there
    /// is a review.
    pub missions: Vec<MissionWeek>,
    /// Tasks done this week, in the order they were done, each with
    /// its live mission.
    pub done: Vec<(Task, Option<Mission>)>,
    pub review: Option<Review>,
    /// Missions that are not archived, by title: the goals the next
    /// week starts with.
    pub active: Vec<Mission>,
    /// Weeks with a review, newest first.
    pub history: Vec<String>,
}

/// The review of the week starting `week_start`. `days` are the
/// week's seven `[start, end)` bounds, Unix seconds.
pub async fn review_of(
    pool: &SqlitePool,
    user_id: &str,
    week_start: &str,
    days: &[(i64, i64)],
    now: UnixTime,
) -> Result<ReviewData, StoreError> {
    let week = (days[0].0, days[days.len() - 1].1);
    let mut conn = pool.acquire().await?;
    let missions = missions_by_title(&mut conn, user_id).await?;
    let entries =
        store::entries_overlapping(&mut conn, user_id, week.0, week.1, now.as_secs()).await?;
    let done = store::tasks_done_between(&mut conn, user_id, week.0, week.1).await?;
    let review = store::live_review(&mut conn, user_id, week_start).await?;
    let history = store::reviewed_weeks(&mut conn, user_id).await?;
    drop(conn);

    let now = now.as_secs();
    let on_missions = || entries.iter().filter(|entry| entry.mission_id.is_some());
    let day_secs = days
        .iter()
        .map(|&day| on_missions().map(|entry| clipped(entry, day, now)).sum())
        .collect();
    let goals = review
        .as_ref()
        .map_or_else(|| goals_of(&missions), |review| review.goals.clone());
    let weeks = missions
        .iter()
        .map(|mission| MissionWeek {
            actual_secs: on_missions()
                .filter(|entry| entry.mission_id.as_deref() == Some(&mission.id))
                .map(|entry| clipped(entry, week, now))
                .sum(),
            goal_secs: goals
                .iter()
                .find(|goal| goal.mission_id == mission.id)
                .map_or(0, |goal| goal.weekly_goal_secs),
            mission: mission.clone(),
        })
        .filter(|week| week.actual_secs > 0 || week.goal_secs > 0)
        .collect();

    Ok(ReviewData {
        mission_secs: on_missions().map(|entry| clipped(entry, week, now)).sum(),
        tracked_secs: entries.iter().map(|entry| clipped(entry, week, now)).sum(),
        day_secs,
        missions: weeks,
        done: done
            .into_iter()
            .map(|task| {
                let mission = missions
                    .iter()
                    .find(|mission| task.mission_id.as_deref() == Some(&mission.id))
                    .cloned();
                (task, mission)
            })
            .collect(),
        review,
        active: missions
            .into_iter()
            .filter(|mission| !mission.archived)
            .collect(),
        history,
    })
}

/// Today's goals, as a review keeps them: the active missions that
/// have one. A mission left out had no goal.
fn goals_of(missions: &[Mission]) -> Vec<ReviewGoal> {
    missions
        .iter()
        .filter(|mission| !mission.archived && mission.weekly_goal_secs > 0)
        .take(MAX_REVIEW_GOALS)
        .map(|mission| ReviewGoal {
            mission_id: mission.id.clone(),
            weekly_goal_secs: mission.weekly_goal_secs,
        })
        .collect()
}

/// A review's three answers, as typed. Blank clears one.
pub struct Answers {
    pub went_well: String,
    pub went_badly: String,
    pub change_next: String,
}

/// The review of `week_start` as it is about to be written, and whether
/// it is stored already: the live one, or a new one that takes today's
/// goals as its snapshot. A `week_start` that is not a Monday is left
/// to the sync rules to refuse.
async fn review_to_write(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    week_start: &str,
    now: UnixTime,
) -> Result<(Review, bool), StoreError> {
    // A tombstone's `updated_at` counts too: a review written after a
    // delete must not lose to it.
    let stored_at = store::updated_at_of(conn, Kind::Review, user_id, week_start).await?;
    let updated_at = edit_time(stored_at.unwrap_or(0), now);
    Ok(match store::live_review(conn, user_id, week_start).await? {
        Some(review) => (
            Review {
                updated_at,
                ..review
            },
            true,
        ),
        None => (
            Review {
                week_start: week_start.to_owned(),
                went_well: None,
                went_badly: None,
                change_next: None,
                goals: goals_of(&missions_by_title(conn, user_id).await?),
                deleted: false,
                updated_at,
            },
            false,
        ),
    })
}

/// Writes the answers of the review of `week_start`. The first write
/// takes today's goals as the week's snapshot; later ones keep it.
pub async fn save_review(
    pool: &SqlitePool,
    user_id: &str,
    week_start: &str,
    answers: Answers,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let (review, _) = review_to_write(&mut conn, user_id, week_start, now).await?;
    drop(conn);
    // A browser sends a textarea's line breaks as CRLF; the sync rules
    // accept LF only.
    let text = |raw: String| Some(raw.replace("\r\n", "\n")).filter(|text| !text.trim().is_empty());
    let review = Review {
        went_well: text(answers.went_well),
        went_badly: text(answers.went_badly),
        change_next: text(answers.change_next),
        ..review
    };
    let push = Changes {
        reviews: vec![review],
        ..Changes::default()
    };
    write(pool, user_id, push, now).await
}

/// Sets the weekly goals of the account's missions, from the review of
/// `week_start`. That review is written first if there is none yet, so
/// its snapshot holds the goals the week had, not the new ones.
pub async fn set_goals(
    pool: &SqlitePool,
    user_id: &str,
    week_start: &str,
    goals: &[(String, i64)],
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let mut conn = pool.acquire().await?;
    let (review, stored) = review_to_write(&mut conn, user_id, week_start, now).await?;
    let mut missions = Vec::with_capacity(goals.len());
    for (id, weekly_goal_secs) in goals {
        let Some(stored) = store::live_mission(&mut conn, user_id, id).await? else {
            return Ok(SaveOutcome::NotFound);
        };
        if stored.weekly_goal_secs != *weekly_goal_secs {
            missions.push(Mission {
                weekly_goal_secs: *weekly_goal_secs,
                updated_at: edit_time(stored.updated_at, now),
                ..stored
            });
        }
    }
    drop(conn);
    let push = Changes {
        missions,
        reviews: if stored { Vec::new() } else { vec![review] },
        ..Changes::default()
    };
    if push.is_empty() {
        return Ok(SaveOutcome::Saved);
    }
    write(pool, user_id, push, now).await
}

/// The weekday the dashboard asks for a review on, 1 (Monday) to 7.
pub async fn review_day(pool: &SqlitePool, user_id: &str) -> Result<i8, StoreError> {
    let mut conn = pool.acquire().await?;
    store::review_day(&mut conn, user_id).await
}

/// Sets the review day; `false` if `day` is not 1 to 7.
pub async fn set_review_day(pool: &SqlitePool, user_id: &str, day: i8) -> Result<bool, StoreError> {
    if !(1..=7).contains(&day) {
        return Ok(false);
    }
    let mut conn = pool.acquire().await?;
    store::set_review_day(&mut conn, user_id, day).await?;
    Ok(true)
}

/// The Monday of the week to review on `today`, if `today` is the
/// review day. On a Monday the week has only just begun, so it is the
/// week before.
pub fn week_to_review(today: Date, review_day: i8) -> Option<Date> {
    let weekday = today.weekday().to_monday_one_offset();
    if weekday != review_day {
        return None;
    }
    let monday = today.checked_sub(i64::from(weekday - 1).days()).ok()?;
    if weekday == 1 {
        monday.checked_sub(1.week()).ok()
    } else {
        Some(monday)
    }
}

/// The week Today asks to review: on the review day, until that week
/// has a review.
pub async fn review_due(
    pool: &SqlitePool,
    user_id: &str,
    today: Date,
) -> Result<Option<String>, StoreError> {
    let mut conn = pool.acquire().await?;
    let day = store::review_day(&mut conn, user_id).await?;
    let Some(week) = week_to_review(today, day) else {
        return Ok(None);
    };
    let week = week.to_string();
    let reviewed = store::live_review(&mut conn, user_id, &week)
        .await?
        .is_some();
    Ok((!reviewed).then_some(week))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_week_to_review_is_this_one_except_on_a_monday() {
        let date = |raw: &str| raw.parse::<Date>().unwrap();
        // 2026-11-22 is a Sunday, the default review day.
        assert_eq!(
            week_to_review(date("2026-11-22"), 7),
            Some(date("2026-11-16"))
        );
        assert_eq!(week_to_review(date("2026-11-21"), 7), None);
        assert_eq!(
            week_to_review(date("2026-11-20"), 5),
            Some(date("2026-11-16"))
        );
        assert_eq!(
            week_to_review(date("2026-11-23"), 1),
            Some(date("2026-11-16"))
        );
    }

    #[test]
    fn an_entry_counts_only_inside_the_window_and_runs_to_now() {
        let entry = |start_ts, end_ts| TrackedEntry {
            id: String::new(),
            task_id: String::new(),
            mission_id: None,
            start_ts,
            end_ts,
            task_title: String::new(),
            colour: None,
        };
        assert_eq!(clipped(&entry(50, Some(150)), (100, 200), 1_000), 50);
        assert_eq!(clipped(&entry(150, None), (100, 200), 170), 20);
        assert_eq!(clipped(&entry(150, None), (100, 200), 1_000), 50);
        assert_eq!(clipped(&entry(10, Some(20)), (100, 200), 1_000), 0);
    }

    #[test]
    fn a_span_entered_by_hand_ends_after_it_starts_and_not_after_now() {
        let now = UnixTime::from_secs(1_000);
        assert_eq!(check_span(900, 1_000, now), Ok(()));
        assert_eq!(
            check_span(1_001, 1_002, now),
            Err(RejectReason::StartInFuture)
        );
        assert_eq!(check_span(900, 1_001, now), Err(RejectReason::EndInFuture));
        assert_eq!(
            check_span(900, 900, now),
            Err(RejectReason::EndNotAfterStart)
        );
        assert_eq!(
            check_span(900, 899, now),
            Err(RejectReason::EndNotAfterStart)
        );
    }
}
