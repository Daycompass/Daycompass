//! Missions as the dashboard reads and writes them: the account's own
//! missions with their tracked time, the North Star and the running
//! timer.
//!
//! Every write goes through [`sync::apply_own`], so a mission edited in
//! the browser obeys the same rules as one pushed by a device - same
//! validation, last write wins, a new rev that devices then pull.
//! Nothing here knows about forms or HTML.

use sqlx::SqlitePool;

use super::store::{self, RunningTimer};
use super::sync::{self, Changes, Outcome};
use super::validate::{self, Mission, RejectReason};
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
                week_secs: time.map_or(0, |time| time.week_secs),
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
    /// No live mission of this account has that id.
    NotFound,
    Invalid(RejectReason),
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
            let updated_at = edit_time(&stored, now);
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
    write(pool, user_id, mission, now).await
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
    let updated_at = edit_time(&stored, now);
    let mission = Mission {
        archived,
        updated_at,
        ..stored
    };
    write(pool, user_id, mission, now).await
}

/// The `updated_at` of an edit made now. Never older than the stored
/// one: a device clock running ahead (within the allowed skew) must not
/// make an edit made after it lose.
fn edit_time(stored: &Mission, now: UnixTime) -> i64 {
    now.as_secs().max(stored.updated_at)
}

async fn write(
    pool: &SqlitePool,
    user_id: &str,
    mission: Mission,
    now: UnixTime,
) -> Result<SaveOutcome, StoreError> {
    let push = Changes {
        missions: vec![mission],
        ..Changes::default()
    };
    let report = sync::apply_own(pool, user_id, &push, now).await?;
    Ok(match report.missions.first() {
        Some(Outcome::Rejected(reason)) => SaveOutcome::Invalid(*reason),
        // shortcut: `Stale` (a device wrote a newer version between the
        // read above and this write) counts as saved; the caller shows
        // the winner. Surface it if that race ever matters in practice.
        _ => SaveOutcome::Saved,
    })
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
