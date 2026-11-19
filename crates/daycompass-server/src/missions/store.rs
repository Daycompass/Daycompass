//! Every SQL statement that names `missions`, `tasks` or
//! `time_entries`.
//!
//! Every function takes the caller's `user_id` and filters on it; there
//! is no statement here that could reach another account's rows. They
//! take a connection rather than the pool, so [`super::sync`] can run a
//! whole sync in one `BEGIN IMMEDIATE` transaction.

use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};

use super::validate::{Mission, Task, TimeEntry};
use crate::auth::store::StoreError;

/// Which of the three tables a statement is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Mission,
    Task,
    TimeEntry,
}

/// One statement per table, built at compile time: sqlx refuses SQL
/// assembled at runtime, and a table name cannot be a bound parameter.
macro_rules! per_table {
    ($kind:expr, $before:literal, $after:literal) => {
        match $kind {
            Kind::Mission => concat!($before, "missions", $after),
            Kind::Task => concat!($before, "tasks", $after),
            Kind::TimeEntry => concat!($before, "time_entries", $after),
        }
    };
}

/// The account's sync counter, or `None` if the account is gone.
pub async fn current_rev(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Option<i64>, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT missions_rev FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(conn)
            .await?,
    )
}

pub async fn set_rev(
    conn: &mut SqliteConnection,
    user_id: &str,
    rev: i64,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE users SET missions_rev = ?2 WHERE id = ?1")
        .bind(user_id)
        .bind(rev)
        .execute(conn)
        .await?;
    Ok(())
}

/// The stored `updated_at` of one record, tombstones included.
pub async fn updated_at_of(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    id: &str,
) -> Result<Option<i64>, StoreError> {
    let sql = per_table!(
        kind,
        "SELECT updated_at FROM ",
        " WHERE user_id = ?1 AND id = ?2"
    );
    Ok(sqlx::query_scalar(sql)
        .bind(user_id)
        .bind(id)
        .fetch_optional(conn)
        .await?)
}

/// Gives a record a new rev without changing it, so the next pull
/// returns it.
pub async fn bump_rev(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    id: &str,
    rev: i64,
) -> Result<(), StoreError> {
    let sql = per_table!(
        kind,
        "UPDATE ",
        " SET rev = ?3 WHERE user_id = ?1 AND id = ?2"
    );
    sqlx::query(sql)
        .bind(user_id)
        .bind(id)
        .bind(rev)
        .execute(conn)
        .await?;
    Ok(())
}

/// Turns an existing record into a tombstone. References and numbers
/// stay, so foreign keys still hold; text goes.
pub async fn tombstone(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    id: &str,
    updated_at: i64,
    rev: i64,
) -> Result<(), StoreError> {
    // Every free-text field goes with the flag.
    let sql = match kind {
        Kind::Mission => {
            "UPDATE missions SET deleted = 1, title = '', description = NULL, why = NULL,
                 updated_at = ?3, rev = ?4
             WHERE user_id = ?1 AND id = ?2"
        }
        Kind::Task => {
            "UPDATE tasks SET deleted = 1, title = '', notes = NULL, updated_at = ?3, rev = ?4
             WHERE user_id = ?1 AND id = ?2"
        }
        Kind::TimeEntry => {
            "UPDATE time_entries SET deleted = 1, updated_at = ?3, rev = ?4
             WHERE user_id = ?1 AND id = ?2"
        }
    };
    sqlx::query(sql)
        .bind(user_id)
        .bind(id)
        .bind(updated_at)
        .bind(rev)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn upsert_mission(
    conn: &mut SqliteConnection,
    user_id: &str,
    mission: &Mission,
    rev: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO missions
             (user_id, id, title, colour, weekly_goal_secs, description, why, starts_on,
              ends_on, archived, deleted, updated_at, rev)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12)
         ON CONFLICT (user_id, id) DO UPDATE SET
             title = excluded.title, colour = excluded.colour,
             weekly_goal_secs = excluded.weekly_goal_secs,
             description = excluded.description, why = excluded.why,
             starts_on = excluded.starts_on, ends_on = excluded.ends_on,
             archived = excluded.archived, deleted = 0,
             updated_at = excluded.updated_at, rev = excluded.rev",
    )
    .bind(user_id)
    .bind(&mission.id)
    .bind(&mission.title)
    .bind(mission.colour)
    .bind(mission.weekly_goal_secs)
    .bind(mission.description.as_deref())
    .bind(mission.why.as_deref())
    .bind(mission.starts_on.as_deref())
    .bind(mission.ends_on.as_deref())
    .bind(mission.archived)
    .bind(mission.updated_at)
    .bind(rev)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn upsert_task(
    conn: &mut SqliteConnection,
    user_id: &str,
    task: &Task,
    rev: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO tasks
             (user_id, id, mission_id, title, notes, day, position, done_at, deleted,
              updated_at, rev)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)
         ON CONFLICT (user_id, id) DO UPDATE SET
             mission_id = excluded.mission_id, title = excluded.title,
             notes = excluded.notes, day = excluded.day, position = excluded.position,
             done_at = excluded.done_at, deleted = 0,
             updated_at = excluded.updated_at, rev = excluded.rev",
    )
    .bind(user_id)
    .bind(&task.id)
    .bind(task.mission_id.as_deref())
    .bind(&task.title)
    .bind(task.notes.as_deref())
    .bind(task.day.as_deref())
    .bind(&task.position)
    .bind(task.done_at)
    .bind(task.updated_at)
    .bind(rev)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn upsert_time_entry(
    conn: &mut SqliteConnection,
    user_id: &str,
    entry: &TimeEntry,
    rev: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO time_entries
             (user_id, id, task_id, start_ts, end_ts, deleted, updated_at, rev)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)
         ON CONFLICT (user_id, id) DO UPDATE SET
             task_id = excluded.task_id, start_ts = excluded.start_ts,
             end_ts = excluded.end_ts, deleted = 0,
             updated_at = excluded.updated_at, rev = excluded.rev",
    )
    .bind(user_id)
    .bind(&entry.id)
    .bind(&entry.task_id)
    .bind(entry.start_ts)
    .bind(entry.end_ts)
    .bind(entry.updated_at)
    .bind(rev)
    .execute(conn)
    .await?;
    Ok(())
}

/// The account's running timer, other than `except_id`.
pub struct Running {
    pub id: String,
    pub start_ts: i64,
    pub updated_at: i64,
}

pub async fn running_entry(
    conn: &mut SqliteConnection,
    user_id: &str,
    except_id: &str,
) -> Result<Option<Running>, StoreError> {
    let row = sqlx::query(
        "SELECT id, start_ts, updated_at FROM time_entries
         WHERE user_id = ?1 AND end_ts IS NULL AND deleted = 0 AND id != ?2",
    )
    .bind(user_id)
    .bind(except_id)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(Running {
            id: row.try_get("id")?,
            start_ts: row.try_get("start_ts")?,
            updated_at: row.try_get("updated_at")?,
        })
    })
    .transpose()
}

pub async fn end_entry(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
    end_ts: i64,
    updated_at: i64,
    rev: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE time_entries SET end_ts = ?3, updated_at = ?4, rev = ?5
         WHERE user_id = ?1 AND id = ?2",
    )
    .bind(user_id)
    .bind(id)
    .bind(end_ts)
    .bind(updated_at)
    .bind(rev)
    .execute(conn)
    .await?;
    Ok(())
}

/// Records with `rev > after`, oldest rev first, at most `limit` (-1
/// for all). `live_only` leaves tombstones out, for the export.
pub async fn missions_after(
    conn: &mut SqliteConnection,
    user_id: &str,
    after: i64,
    limit: i64,
    live_only: bool,
) -> Result<Vec<(i64, Mission)>, StoreError> {
    let rows = select_after(conn, Kind::Mission, user_id, after, limit, live_only).await?;
    rows.iter()
        .map(|row| Ok((row.try_get("rev")?, mission_from_row(row)?)))
        .collect()
}

fn mission_from_row(row: &SqliteRow) -> Result<Mission, StoreError> {
    Ok(Mission {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        colour: row.try_get("colour")?,
        weekly_goal_secs: row.try_get("weekly_goal_secs")?,
        description: row.try_get("description")?,
        why: row.try_get("why")?,
        starts_on: row.try_get("starts_on")?,
        ends_on: row.try_get("ends_on")?,
        archived: row.try_get("archived")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// One live mission, or `None` if this account has none by that id.
pub async fn live_mission(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<Option<Mission>, StoreError> {
    let row = sqlx::query("SELECT * FROM missions WHERE user_id = ?1 AND id = ?2 AND deleted = 0")
        .bind(user_id)
        .bind(id)
        .fetch_optional(conn)
        .await?;
    row.as_ref().map(mission_from_row).transpose()
}

/// Tracked time per mission: inside `[start, end)` (a day or a week)
/// and in all. A running entry counts up to `now`. Entries of deleted
/// tasks, and of tasks under no mission, count nowhere.
pub struct MissionTime {
    pub mission_id: String,
    pub window_secs: i64,
    pub total_secs: i64,
}

pub async fn mission_times(
    conn: &mut SqliteConnection,
    user_id: &str,
    start: i64,
    end: i64,
    now: i64,
) -> Result<Vec<MissionTime>, StoreError> {
    let rows = sqlx::query(
        "SELECT t.mission_id AS mission_id,
             SUM(MAX(0, MIN(COALESCE(e.end_ts, ?4), ?3) - MAX(e.start_ts, ?2))) AS window_secs,
             SUM(MAX(0, COALESCE(e.end_ts, ?4) - e.start_ts)) AS total_secs
         FROM time_entries e
         JOIN tasks t ON t.user_id = e.user_id AND t.id = e.task_id
         WHERE e.user_id = ?1 AND e.deleted = 0 AND t.deleted = 0
             AND t.mission_id IS NOT NULL
         GROUP BY t.mission_id",
    )
    .bind(user_id)
    .bind(start)
    .bind(end)
    .bind(now)
    .fetch_all(conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(MissionTime {
                mission_id: row.try_get("mission_id")?,
                window_secs: row.try_get("window_secs")?,
                total_secs: row.try_get("total_secs")?,
            })
        })
        .collect()
}

/// The account's running timer, with what the app layout shows of it.
pub struct RunningTimer {
    pub task_id: String,
    pub start_ts: i64,
    pub task_title: String,
    /// `None`: the task is under no mission, or its mission is gone.
    pub colour: Option<i64>,
}

pub async fn running_timer(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Option<RunningTimer>, StoreError> {
    let row = sqlx::query(
        "SELECT e.task_id AS task_id, e.start_ts AS start_ts, t.title AS title,
             m.colour AS colour
         FROM time_entries e
         JOIN tasks t ON t.user_id = e.user_id AND t.id = e.task_id AND t.deleted = 0
         LEFT JOIN missions m
             ON m.user_id = t.user_id AND m.id = t.mission_id AND m.deleted = 0
         WHERE e.user_id = ?1 AND e.end_ts IS NULL AND e.deleted = 0",
    )
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(RunningTimer {
            task_id: row.try_get("task_id")?,
            start_ts: row.try_get("start_ts")?,
            task_title: row.try_get("title")?,
            colour: row.try_get("colour")?,
        })
    })
    .transpose()
}

pub async fn live_task(
    conn: &mut SqliteConnection,
    user_id: &str,
    id: &str,
) -> Result<Option<Task>, StoreError> {
    let row = sqlx::query("SELECT * FROM tasks WHERE user_id = ?1 AND id = ?2 AND deleted = 0")
        .bind(user_id)
        .bind(id)
        .fetch_optional(conn)
        .await?;
    row.as_ref().map(task_from_row).transpose()
}

/// The live tasks planned for `day`, in their order: by position, ties
/// (two devices that picked the same key offline) by id.
pub async fn tasks_of_day(
    conn: &mut SqliteConnection,
    user_id: &str,
    day: &str,
) -> Result<Vec<Task>, StoreError> {
    let rows = sqlx::query(
        "SELECT * FROM tasks WHERE user_id = ?1 AND day = ?2 AND deleted = 0
         ORDER BY position, id",
    )
    .bind(user_id)
    .bind(day)
    .fetch_all(conn)
    .await?;
    rows.iter().map(task_from_row).collect()
}

/// All tracked time per task planned for `day`, whenever it was
/// tracked. A running entry counts up to `now`.
pub async fn task_times(
    conn: &mut SqliteConnection,
    user_id: &str,
    day: &str,
    now: i64,
) -> Result<Vec<(String, i64)>, StoreError> {
    let rows = sqlx::query(
        "SELECT e.task_id AS task_id, SUM(MAX(0, COALESCE(e.end_ts, ?3) - e.start_ts)) AS secs
         FROM time_entries e
         JOIN tasks t ON t.user_id = e.user_id AND t.id = e.task_id
         WHERE e.user_id = ?1 AND e.deleted = 0 AND t.deleted = 0 AND t.day = ?2
         GROUP BY e.task_id",
    )
    .bind(user_id)
    .bind(day)
    .bind(now)
    .fetch_all(conn)
    .await?;
    rows.iter()
        .map(|row| Ok((row.try_get("task_id")?, row.try_get("secs")?)))
        .collect()
}

/// The account's running time entry, whole.
pub async fn live_running_entry(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Option<TimeEntry>, StoreError> {
    let row = sqlx::query(
        "SELECT * FROM time_entries WHERE user_id = ?1 AND end_ts IS NULL AND deleted = 0",
    )
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    row.as_ref().map(entry_from_row).transpose()
}

/// A time entry with what a timeline shows of it.
pub struct TrackedEntry {
    pub start_ts: i64,
    /// `None` while it runs.
    pub end_ts: Option<i64>,
    pub task_title: String,
    pub colour: Option<i64>,
}

/// Live entries of live tasks that overlap `[start, end)`, oldest first.
/// A running entry reaches up to `now`.
pub async fn entries_overlapping(
    conn: &mut SqliteConnection,
    user_id: &str,
    start: i64,
    end: i64,
    now: i64,
) -> Result<Vec<TrackedEntry>, StoreError> {
    let rows = sqlx::query(
        "SELECT e.start_ts AS start_ts, e.end_ts AS end_ts, t.title AS title,
             m.colour AS colour
         FROM time_entries e
         JOIN tasks t ON t.user_id = e.user_id AND t.id = e.task_id AND t.deleted = 0
         LEFT JOIN missions m
             ON m.user_id = t.user_id AND m.id = t.mission_id AND m.deleted = 0
         WHERE e.user_id = ?1 AND e.deleted = 0
             AND e.start_ts < ?3 AND COALESCE(e.end_ts, ?4) > ?2
         ORDER BY e.start_ts",
    )
    .bind(user_id)
    .bind(start)
    .bind(end)
    .bind(now)
    .fetch_all(conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(TrackedEntry {
                start_ts: row.try_get("start_ts")?,
                end_ts: row.try_get("end_ts")?,
                task_title: row.try_get("title")?,
                colour: row.try_get("colour")?,
            })
        })
        .collect()
}

pub async fn north_star(
    conn: &mut SqliteConnection,
    user_id: &str,
) -> Result<Option<String>, StoreError> {
    let stored: Option<Option<String>> =
        sqlx::query_scalar("SELECT north_star FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(conn)
            .await?;
    Ok(stored.flatten())
}

pub async fn set_north_star(
    conn: &mut SqliteConnection,
    user_id: &str,
    north_star: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE users SET north_star = ?2 WHERE id = ?1")
        .bind(user_id)
        .bind(north_star)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn tasks_after(
    conn: &mut SqliteConnection,
    user_id: &str,
    after: i64,
    limit: i64,
    live_only: bool,
) -> Result<Vec<(i64, Task)>, StoreError> {
    let rows = select_after(conn, Kind::Task, user_id, after, limit, live_only).await?;
    rows.iter()
        .map(|row| Ok((row.try_get("rev")?, task_from_row(row)?)))
        .collect()
}

fn task_from_row(row: &SqliteRow) -> Result<Task, StoreError> {
    Ok(Task {
        id: row.try_get("id")?,
        mission_id: row.try_get("mission_id")?,
        title: row.try_get("title")?,
        notes: row.try_get("notes")?,
        day: row.try_get("day")?,
        position: row.try_get("position")?,
        done_at: row.try_get("done_at")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub async fn time_entries_after(
    conn: &mut SqliteConnection,
    user_id: &str,
    after: i64,
    limit: i64,
    live_only: bool,
) -> Result<Vec<(i64, TimeEntry)>, StoreError> {
    let rows = select_after(conn, Kind::TimeEntry, user_id, after, limit, live_only).await?;
    rows.iter()
        .map(|row| Ok((row.try_get("rev")?, entry_from_row(row)?)))
        .collect()
}

fn entry_from_row(row: &SqliteRow) -> Result<TimeEntry, StoreError> {
    Ok(TimeEntry {
        id: row.try_get("id")?,
        task_id: row.try_get("task_id")?,
        start_ts: row.try_get("start_ts")?,
        end_ts: row.try_get("end_ts")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn select_after(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    after: i64,
    limit: i64,
    live_only: bool,
) -> Result<Vec<SqliteRow>, StoreError> {
    let sql = per_table!(
        kind,
        "SELECT * FROM ",
        " WHERE user_id = ?1 AND rev > ?2 AND (?4 = 0 OR deleted = 0) ORDER BY rev LIMIT ?3"
    );
    Ok(sqlx::query(sql)
        .bind(user_id)
        .bind(after)
        .bind(limit)
        .bind(live_only)
        .fetch_all(conn)
        .await?)
}
