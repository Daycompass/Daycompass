//! Every SQL statement that touches the `events` table.
//!
//! **This file is the only place in the codebase allowed to name the
//! `events` table**, and `tests/no_event_reads.rs` fails the build if
//! that stops being true.
//!
//! Two statements live here: the insert ingest uses, and the one read
//! M3 adds - an owner's own events, joined against `devices` to prove
//! ownership in the `WHERE` clause rather than trusting a caller-
//! supplied id. There is still no statement here for anyone else: an
//! admin manages accounts and devices and must never reach event data,
//! full stop. Category rules are a later piece of M3, built on top of
//! this read rather than inside it.
//!
//! # Why `ON CONFLICT ... DO NOTHING` and not `INSERT OR IGNORE`
//!
//! The two look interchangeable and are not. `INSERT OR IGNORE` skips
//! a row that violates *any* constraint, NOT NULL and CHECK included,
//! so a bug in the validator - or a validator and a schema that have
//! drifted apart - would silently drop events and this code would
//! report them to the client as duplicates. The conflict target below
//! suppresses exactly the duplicate and nothing else; every other
//! constraint still raises, fails the transaction, and is logged.
//!
//! "Accepted" and "duplicate" are then told apart by how many rows the
//! statement affected: one, or none.

use sqlx::{Row, SqlitePool};

use super::validate::ValidEvent;
use crate::auth::store::{new_id, StoreError};
use crate::auth::time::UnixTime;

/// What happened to one event that reached the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// Newly written.
    Accepted,
    /// This device had already reported this event id. A resent batch
    /// is made entirely of these.
    Duplicate,
}

/// Writes a batch of already-validated events for one device.
///
/// All of them in one transaction, so a batch either lands or does
/// not. Returns one [`Stored`] per input event, in the same order, so
/// the caller can report per event without matching anything up by id.
///
/// Overlapping events are **not** merged or deduplicated here, by
/// design: two devices observing the same span is expected, and
/// resolving that is a query-time concern for M3. Ingest records what
/// was reported.
pub async fn insert_batch(
    pool: &SqlitePool,
    device_id: &str,
    events: &[ValidEvent],
    received_at: UnixTime,
) -> Result<Vec<Stored>, StoreError> {
    let mut outcomes = Vec::with_capacity(events.len());
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    for event in events {
        let result = sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, label, domain,
                  received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (device_id, event_id) DO NOTHING",
        )
        .bind(new_id())
        .bind(device_id)
        .bind(&event.event_id)
        .bind(event.start_ts)
        .bind(event.duration_secs)
        .bind(&event.app_id)
        .bind(event.label.as_deref())
        .bind(event.domain.as_deref())
        .bind(received_at.as_secs())
        .execute(&mut *tx)
        .await?;

        outcomes.push(if result.rows_affected() == 0 {
            Stored::Duplicate
        } else {
            Stored::Accepted
        });
    }

    tx.commit().await?;
    Ok(outcomes)
}

/// One event as read back, with the device that reported it.
///
/// Deliberately not [`ValidEvent`]: that type is what ingest wrote,
/// this is what a read hands back, and `device_id` is only meaningful
/// on the way out - a client never sends it, since the device layer
/// already knows which device is calling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedEvent {
    pub device_id: String,
    /// Canonical: 32 lowercase hex characters, as stored.
    pub event_id: String,
    pub start_ts: i64,
    pub duration_secs: i64,
    pub app_id: String,
    pub label: Option<String>,
    pub domain: Option<String>,
}

fn queried_event_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<QueriedEvent, StoreError> {
    Ok(QueriedEvent {
        device_id: row.try_get("device_id")?,
        event_id: row.try_get("event_id")?,
        start_ts: row.try_get("start_ts")?,
        duration_secs: row.try_get("duration_secs")?,
        app_id: row.try_get("app_id")?,
        label: row.try_get("label")?,
        domain: row.try_get("domain")?,
    })
}

/// An account's own events whose `start_ts` falls in `[start_ts,
/// end_ts)`, across every device it owns - live or revoked, since
/// revoking a device does not erase what it already reported.
///
/// `limit` is always `events::query::MAX_ROWS + 1`: the caller asks
/// for one more row than it will ever show, purely to tell "there were
/// exactly this many" apart from "there were more" without a second
/// `COUNT` query.
///
/// The `JOIN` against `devices` is what makes this ownership check a
/// property of the query rather than of the caller remembering to
/// filter: there is no code path here that can return a row for a
/// device this account does not own, because the row would not match
/// the `WHERE` clause in the first place.
pub async fn select_own_in_range(
    pool: &SqlitePool,
    user_id: &str,
    start_ts: i64,
    end_ts: i64,
    limit: i64,
) -> Result<Vec<QueriedEvent>, StoreError> {
    let rows = sqlx::query(
        "SELECT e.device_id, e.event_id, e.start_ts, e.duration_secs, e.app_id, e.label,
                e.domain
         FROM events e
         JOIN devices d ON d.id = e.device_id
         WHERE d.user_id = ?1 AND e.start_ts >= ?2 AND e.start_ts < ?3
         ORDER BY e.start_ts ASC, e.device_id ASC, e.event_id ASC
         LIMIT ?4",
    )
    .bind(user_id)
    .bind(start_ts)
    .bind(end_ts)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.iter().map(queried_event_from_row).collect()
}

/// One (UTC calendar day, `app_id`, `domain`) group's summed
/// `duration_secs`, for an owner's own stats aggregation - M3's
/// second read, on the same `JOIN` as [`select_own_in_range`].
///
/// Grouping by `(app_id, domain)` here, in SQL, rather than handing
/// back every row, is what keeps a wide window cheap: a year of one
/// account's history collapses to one row per day per distinct app or
/// site it used, not one row per event. [`crate::categories::resolve`]
/// is what turns each group into a category, once this has already
/// done the summing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyGroupTotal {
    /// The Unix timestamp of this group's day's UTC midnight -
    /// `(start_ts / 86_400) * 86_400`.
    pub day_start_ts: i64,
    pub app_id: String,
    pub domain: Option<String>,
    pub total_duration_secs: i64,
}

fn daily_group_total_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<DailyGroupTotal, StoreError> {
    Ok(DailyGroupTotal {
        day_start_ts: row.try_get("day_start_ts")?,
        app_id: row.try_get("app_id")?,
        domain: row.try_get("domain")?,
        total_duration_secs: row.try_get("total_duration_secs")?,
    })
}

/// Sums `duration_secs` for the caller's own events inside
/// `[start_ts, end_ts)`, grouped by UTC calendar day, `app_id` and
/// `domain`.
///
/// Overlapping events are summed exactly as reported - two devices
/// covering the same span, or one device reporting an app and a
/// domain for the same span, are not merged or deduplicated here
/// either, for the same reason [`select_own_in_range`] hands its rows
/// back unmerged: deciding what an overlap means is a query-time
/// choice this server has not made, not an oversight in this one
/// query.
pub async fn select_own_daily_group_totals(
    pool: &SqlitePool,
    user_id: &str,
    start_ts: i64,
    end_ts: i64,
) -> Result<Vec<DailyGroupTotal>, StoreError> {
    let rows = sqlx::query(
        "SELECT (e.start_ts / 86400) * 86400 AS day_start_ts, e.app_id AS app_id,
                e.domain AS domain, SUM(e.duration_secs) AS total_duration_secs
         FROM events e
         JOIN devices d ON d.id = e.device_id
         WHERE d.user_id = ?1 AND e.start_ts >= ?2 AND e.start_ts < ?3
         GROUP BY e.start_ts / 86400, e.app_id, e.domain
         ORDER BY day_start_ts ASC",
    )
    .bind(user_id)
    .bind(start_ts)
    .bind(end_ts)
    .fetch_all(pool)
    .await?;

    rows.iter().map(daily_group_total_from_row).collect()
}
