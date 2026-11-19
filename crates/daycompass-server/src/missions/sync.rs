//! One sync round trip: apply what a device pushes, then hand back
//! everything after its cursor.
//!
//! Both halves run in one `BEGIN IMMEDIATE` transaction. That is what
//! makes the cursor safe: revs are assigned under the write lock and
//! committed together, so a pull can never see rev 12 without rev 11
//! and skip it for good.
//!
//! # Last write wins
//!
//! Per record, on the client's `updated_at`. A push whose `updated_at`
//! is older than the stored one is `stale`: nothing changes, but the
//! stored record gets a new rev, so the same response carries the
//! winning version back to the device that lost. Equal `updated_at`
//! goes to the push, since it reached the server last - which is also
//! what makes two edits within one second on one device come out
//! right.
//!
//! # Tombstones
//!
//! A tombstone for a record the server never had stores nothing: no
//! other device can know that record either. Otherwise it is an
//! ordinary write under the rule above, so a later edit elsewhere can
//! bring a deleted record back.
//!
//! # One running timer
//!
//! Whenever a running entry is written and another one is running, the
//! one that started earlier is ended at the other's start - whichever
//! of the two arrived first. "Timer started on B stops the one on A"
//! falls out of this, and so does the reverse order, where A's older
//! start reaches the server after B's.

use sqlx::{SqliteConnection, SqlitePool};

use super::store::{self, Kind};
use super::validate::{self, Mission, RejectReason, Task, TimeEntry};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;

/// The most records one push may carry, all three kinds together.
pub const MAX_BATCH_RECORDS: usize = 500;

/// The largest a sync body may be. Attached to the route from its
/// inventory entry; here because it bounds a request together with
/// [`MAX_BATCH_RECORDS`].
pub const MAX_BODY_BYTES: usize = 512 * 1024;

/// The most records one pull returns.
pub const PAGE_RECORDS: usize = 500;

/// Records of all three kinds, pushed or pulled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub missions: Vec<Mission>,
    pub tasks: Vec<Task>,
    pub time_entries: Vec<TimeEntry>,
}

impl Changes {
    pub fn len(&self) -> usize {
        self.missions.len() + self.tasks.len() + self.time_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What happened to one pushed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// The server holds a newer version, returned in the same response.
    Stale,
    Rejected(RejectReason),
}

impl Outcome {
    /// The wire value of the status field.
    pub const fn status(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Stale => "stale",
            Self::Rejected(_) => "rejected",
        }
    }

    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Applied | Self::Stale => None,
            Self::Rejected(reason) => Some(reason.code()),
        }
    }
}

/// One outcome per pushed record, positionally, per kind.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub missions: Vec<Outcome>,
    pub tasks: Vec<Outcome>,
    pub time_entries: Vec<Outcome>,
}

#[derive(Debug)]
pub struct Synced {
    pub report: Report,
    pub changes: Changes,
    /// What the device sends as its cursor next time.
    pub cursor: i64,
    /// More changes wait after `cursor`; pull again.
    pub has_more: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Negative, or ahead of anything this account has issued - most
    /// likely a server restored from an older backup. The device must
    /// start over from 0.
    #[error("the sync cursor was not issued by this account")]
    CursorInvalid,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for SyncError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// Applies `push` for `user_id`, then returns one page of everything
/// after `cursor`.
///
/// Takes the caller's own id and nothing else: there is no parameter
/// that could name another account.
pub async fn sync(
    pool: &SqlitePool,
    user_id: &str,
    cursor: i64,
    push: &Changes,
    now: UnixTime,
) -> Result<Synced, SyncError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    // The device layer resolved this account a moment ago; gone now
    // means it was deleted in between.
    let mut rev = store::current_rev(&mut tx, user_id)
        .await?
        .ok_or(StoreError::CorruptRow)?;
    if !(0..=rev).contains(&cursor) {
        return Err(SyncError::CursorInvalid);
    }

    let report = apply_changes(&mut tx, user_id, &mut rev, push, now).await?;
    store::set_rev(&mut tx, user_id, rev).await?;
    let (changes, cursor, has_more) = changes_since(&mut tx, user_id, cursor, rev).await?;
    tx.commit().await?;

    // Counts only: titles and notes are what a person wrote.
    let all = report
        .missions
        .iter()
        .chain(&report.tasks)
        .chain(&report.time_entries);
    let (mut applied, mut stale, mut rejected) = (0, 0, 0);
    for outcome in all {
        match outcome {
            Outcome::Applied => applied += 1,
            Outcome::Stale => stale += 1,
            Outcome::Rejected(_) => rejected += 1,
        }
    }
    tracing::info!(
        user_id = %user_id,
        applied,
        stale,
        rejected,
        pulled = changes.len(),
        "missions synced"
    );

    Ok(Synced {
        report,
        changes,
        cursor,
        has_more,
    })
}

fn next(rev: &mut i64) -> i64 {
    *rev += 1;
    *rev
}

/// Missions first, then tasks, then time entries, so a record may
/// reference one pushed earlier in the same request.
async fn apply_changes(
    conn: &mut SqliteConnection,
    user_id: &str,
    rev: &mut i64,
    push: &Changes,
    now: UnixTime,
) -> Result<Report, StoreError> {
    let mut report = Report::default();

    for raw in &push.missions {
        let outcome = match validate::mission(raw, now) {
            Err(reason) => Outcome::Rejected(reason),
            Ok(mission) => {
                match settle(
                    conn,
                    Kind::Mission,
                    user_id,
                    &mission.id,
                    mission.updated_at,
                    mission.deleted,
                    rev,
                )
                .await?
                {
                    Some(outcome) => outcome,
                    None => {
                        store::upsert_mission(conn, user_id, &mission, next(rev)).await?;
                        Outcome::Applied
                    }
                }
            }
        };
        report.missions.push(outcome);
    }

    for raw in &push.tasks {
        let outcome = match validate::task(raw, now) {
            Err(reason) => Outcome::Rejected(reason),
            Ok(task) => {
                match settle(
                    conn,
                    Kind::Task,
                    user_id,
                    &task.id,
                    task.updated_at,
                    task.deleted,
                    rev,
                )
                .await?
                {
                    Some(outcome) => outcome,
                    None if !references(
                        conn,
                        Kind::Mission,
                        user_id,
                        task.mission_id.as_deref(),
                    )
                    .await? =>
                    {
                        Outcome::Rejected(RejectReason::MissionUnknown)
                    }
                    None => {
                        store::upsert_task(conn, user_id, &task, next(rev)).await?;
                        Outcome::Applied
                    }
                }
            }
        };
        report.tasks.push(outcome);
    }

    for raw in &push.time_entries {
        let outcome = match validate::time_entry(raw, now) {
            Err(reason) => Outcome::Rejected(reason),
            Ok(entry) => {
                match settle(
                    conn,
                    Kind::TimeEntry,
                    user_id,
                    &entry.id,
                    entry.updated_at,
                    entry.deleted,
                    rev,
                )
                .await?
                {
                    Some(outcome) => outcome,
                    None if !references(conn, Kind::Task, user_id, Some(&entry.task_id))
                        .await? =>
                    {
                        Outcome::Rejected(RejectReason::TaskUnknown)
                    }
                    None => {
                        write_entry(conn, user_id, rev, entry).await?;
                        Outcome::Applied
                    }
                }
            }
        };
        report.time_entries.push(outcome);
    }

    Ok(report)
}

/// Last write wins and tombstones, the same for every kind. Returns
/// the outcome if the record is settled, or `None` if the caller should
/// write it as a live record.
async fn settle(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    id: &str,
    updated_at: i64,
    deleted: bool,
    rev: &mut i64,
) -> Result<Option<Outcome>, StoreError> {
    match store::updated_at_of(conn, kind, user_id, id).await? {
        Some(stored) if stored > updated_at => {
            store::bump_rev(conn, kind, user_id, id, next(rev)).await?;
            Ok(Some(Outcome::Stale))
        }
        Some(_) if deleted => {
            store::tombstone(conn, kind, user_id, id, updated_at, next(rev)).await?;
            Ok(Some(Outcome::Applied))
        }
        None if deleted => Ok(Some(Outcome::Applied)),
        _ => Ok(None),
    }
}

/// Whether a reference points at a record of this account. No
/// reference at all is fine. A tombstone counts: deleting a mission
/// does not orphan the tasks a device wrote against it offline.
async fn references(
    conn: &mut SqliteConnection,
    kind: Kind,
    user_id: &str,
    id: Option<&str>,
) -> Result<bool, StoreError> {
    match id {
        None => Ok(true),
        Some(id) => Ok(store::updated_at_of(conn, kind, user_id, id)
            .await?
            .is_some()),
    }
}

/// Writes a live time entry, ending whichever of two running timers
/// started earlier.
async fn write_entry(
    conn: &mut SqliteConnection,
    user_id: &str,
    rev: &mut i64,
    mut entry: TimeEntry,
) -> Result<(), StoreError> {
    if entry.end_ts.is_none() {
        if let Some(other) = store::running_entry(conn, user_id, &entry.id).await? {
            if other.start_ts <= entry.start_ts {
                // The other one's updated_at moves forward too, so a
                // stale push of it cannot restart it.
                let updated_at = other.updated_at.max(entry.updated_at);
                store::end_entry(
                    conn,
                    user_id,
                    &other.id,
                    entry.start_ts,
                    updated_at,
                    next(rev),
                )
                .await?;
            } else {
                entry.end_ts = Some(other.start_ts);
            }
        }
    }
    store::upsert_time_entry(conn, user_id, &entry, next(rev)).await
}

/// One page of records with `rev > cursor`, oldest first, the next
/// cursor, and whether more follow. `current` is the account's rev
/// after this sync's writes, which is the cursor once nothing follows.
async fn changes_since(
    conn: &mut SqliteConnection,
    user_id: &str,
    cursor: i64,
    current: i64,
) -> Result<(Changes, i64, bool), StoreError> {
    // One more than a page from each table: the page's records are
    // the smallest revs overall, and each table's share of them is at
    // most a page, so this always covers it.
    let limit = PAGE_RECORDS as i64 + 1;
    let missions = store::missions_after(conn, user_id, cursor, limit, false).await?;
    let tasks = store::tasks_after(conn, user_id, cursor, limit, false).await?;
    let entries = store::time_entries_after(conn, user_id, cursor, limit, false).await?;

    let mut revs: Vec<i64> = missions
        .iter()
        .map(|(rev, _)| *rev)
        .chain(tasks.iter().map(|(rev, _)| *rev))
        .chain(entries.iter().map(|(rev, _)| *rev))
        .collect();
    let (last, next_cursor, has_more) = if revs.len() > PAGE_RECORDS {
        revs.sort_unstable();
        let last = revs[PAGE_RECORDS - 1];
        (last, last, true)
    } else {
        (i64::MAX, current, false)
    };

    let changes = Changes {
        missions: up_to(missions, last),
        tasks: up_to(tasks, last),
        time_entries: up_to(entries, last),
    };
    Ok((changes, next_cursor, has_more))
}

fn up_to<T>(rows: Vec<(i64, T)>, last: i64) -> Vec<T> {
    rows.into_iter()
        .filter(|(rev, _)| *rev <= last)
        .map(|(_, record)| record)
        .collect()
}
