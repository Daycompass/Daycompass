//! Every SQL statement that touches the `events` table.
//!
//! **This file is the only place in the codebase allowed to name the
//! `events` table**, and `tests/no_event_reads.rs` fails the build if
//! that stops being true.
//!
//! The insert ingest uses, the owner's own reads - M3's windowed read
//! and daily totals, and M4's export pages - and M4's retention delete.
//! Every read is joined against `devices` to prove ownership in the
//! `WHERE` clause rather than trusting a caller-supplied id. There is
//! still no statement here for anyone else: an admin manages accounts
//! and devices and must never reach event data, full stop.
//!
//! The retention delete is the one statement that is not scoped to an
//! account, because it is not on anybody's behalf: it removes rows by
//! age, across the instance, returns nothing but a count, and is only
//! ever run by the background sweep - never from a request.
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

/// Where the previous export page ended: the sort key of its last row.
///
/// The three columns together are unique - `(device_id, event_id)`
/// already is - so a page that starts strictly after this key neither
/// repeats nor skips a row, however many events share one `start_ts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageKey {
    pub start_ts: i64,
    pub device_id: String,
    pub event_id: String,
}

impl PageKey {
    /// The key of `event`, for resuming after it.
    pub fn after(event: &QueriedEvent) -> Self {
        Self {
            start_ts: event.start_ts,
            device_id: event.device_id.clone(),
            event_id: event.event_id.clone(),
        }
    }
}

/// One page of an account's own events, in `(start_ts, device_id,
/// event_id)` order, starting strictly after `after` - or at the very
/// first event when `after` is `None`.
///
/// M4's export read: every event the account has, a page at a time, on
/// the same ownership `JOIN` as [`select_own_in_range`]. Keyset rather
/// than `OFFSET`, so a late page costs the same as the first one
/// instead of re-scanning every row before it, and so each page is its
/// own short query: the caller holds no connection between pages.
pub async fn select_own_page_after(
    pool: &SqlitePool,
    user_id: &str,
    after: Option<&PageKey>,
    limit: i64,
) -> Result<Vec<QueriedEvent>, StoreError> {
    let rows =
        match after {
            None => sqlx::query(
                "SELECT e.device_id, e.event_id, e.start_ts, e.duration_secs, e.app_id, e.label,
                        e.domain
                 FROM events e
                 JOIN devices d ON d.id = e.device_id
                 WHERE d.user_id = ?1
                 ORDER BY e.start_ts ASC, e.device_id ASC, e.event_id ASC
                 LIMIT ?2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(pool)
            .await?,
            Some(key) => sqlx::query(
                "SELECT e.device_id, e.event_id, e.start_ts, e.duration_secs, e.app_id, e.label,
                        e.domain
                 FROM events e
                 JOIN devices d ON d.id = e.device_id
                 WHERE d.user_id = ?1
                   AND (e.start_ts, e.device_id, e.event_id) > (?2, ?3, ?4)
                 ORDER BY e.start_ts ASC, e.device_id ASC, e.event_id ASC
                 LIMIT ?5",
            )
            .bind(user_id)
            .bind(key.start_ts)
            .bind(&key.device_id)
            .bind(&key.event_id)
            .bind(limit)
            .fetch_all(pool)
            .await?,
        };

    rows.iter().map(queried_event_from_row).collect()
}

/// Deletes at most `limit` events whose `start_ts` is before `cutoff`,
/// across every account, and returns how many it deleted.
///
/// Bounded so that one call holds SQLite's write lock only briefly; the
/// caller loops until a call deletes fewer than `limit`. Which rows go
/// first within one call does not matter - every one of them is past
/// the cutoff - so the inner `SELECT` has no `ORDER BY` and walks
/// `events_start_ts_idx` (migration `0006`) from the oldest.
pub async fn delete_started_before(
    pool: &SqlitePool,
    cutoff: i64,
    limit: i64,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM events
         WHERE id IN (SELECT id FROM events WHERE start_ts < ?1 LIMIT ?2)",
    )
    .bind(cutoff)
    .bind(limit)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// One (time bucket, `app_id`, `domain`) group's summed
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
    /// The Unix timestamp of this group's bucket start -
    /// `(start_ts / bucket_secs) * bucket_secs`.
    pub bucket_start_ts: i64,
    pub app_id: String,
    pub domain: Option<String>,
    pub total_duration_secs: i64,
}

fn daily_group_total_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<DailyGroupTotal, StoreError> {
    Ok(DailyGroupTotal {
        bucket_start_ts: row.try_get("bucket_start_ts")?,
        app_id: row.try_get("app_id")?,
        domain: row.try_get("domain")?,
        total_duration_secs: row.try_get("total_duration_secs")?,
    })
}

/// Sums `duration_secs` for the caller's own events inside
/// `[start_ts, end_ts)`, grouped by `bucket_secs`-wide bucket of
/// `start_ts` (aligned to the Unix epoch), `app_id` and `domain`.
/// `86_400` gives UTC calendar days; a narrower bucket lets the caller
/// fold into days of a time zone, see `crate::stats::aggregate`.
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
    bucket_secs: i64,
) -> Result<Vec<DailyGroupTotal>, StoreError> {
    let rows = sqlx::query(
        "SELECT (e.start_ts / ?4) * ?4 AS bucket_start_ts, e.app_id AS app_id,
                e.domain AS domain, SUM(e.duration_secs) AS total_duration_secs
         FROM events e
         JOIN devices d ON d.id = e.device_id
         WHERE d.user_id = ?1 AND e.start_ts >= ?2 AND e.start_ts < ?3
         GROUP BY e.start_ts / ?4, e.app_id, e.domain
         ORDER BY bucket_start_ts ASC",
    )
    .bind(user_id)
    .bind(start_ts)
    .bind(end_ts)
    .bind(bucket_secs)
    .fetch_all(pool)
    .await?;

    rows.iter().map(daily_group_total_from_row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, DbTarget};

    /// Two accounts, two devices for the first and one for the second,
    /// so both the ownership filter and the tie-break across devices
    /// have something to get wrong.
    async fn pool_with_devices() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");
        for (user, name) in [("u1", "alice"), ("u2", "bob")] {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at)
                 VALUES (?1, ?2, 'placeholder-not-a-hash', 'user', 0)",
            )
            .bind(user)
            .bind(name)
            .execute(&pool)
            .await
            .expect("inserting a user must succeed");
        }
        for (device, user, hash) in [("d1", "u1", 1u8), ("d2", "u1", 2), ("d3", "u2", 3)] {
            sqlx::query(
                "INSERT INTO devices
                     (id, user_id, name, platform, token_hash, created_at, last_seen_at)
                 VALUES (?1, ?2, 'laptop', 'linux', ?3, 0, 0)",
            )
            .bind(device)
            .bind(user)
            .bind(vec![hash])
            .execute(&pool)
            .await
            .expect("inserting a device must succeed");
        }
        pool
    }

    fn event(n: u32, start_ts: i64) -> ValidEvent {
        ValidEvent {
            event_id: format!("{n:032x}"),
            start_ts,
            duration_secs: 60,
            app_id: "org.example.app".to_owned(),
            label: None,
            domain: None,
        }
    }

    async fn all_pages(pool: &SqlitePool, user_id: &str, limit: i64) -> Vec<QueriedEvent> {
        let mut out = Vec::new();
        let mut after: Option<PageKey> = None;
        loop {
            let page = select_own_page_after(pool, user_id, after.as_ref(), limit)
                .await
                .expect("a page must read");
            let Some(last) = page.last() else {
                return out;
            };
            after = Some(PageKey::after(last));
            out.extend(page);
        }
    }

    /// Many events on one `start_ts`, split across two devices, read
    /// back with a page size that lands mid-tie: every row exactly
    /// once, in sort order, and none of the other account's.
    #[tokio::test]
    async fn pages_cover_every_own_event_once_across_ties() {
        let pool = pool_with_devices().await;
        let at = UnixTime::from_secs(0);
        let d1: Vec<ValidEvent> = (0..7).map(|n| event(n, 1_000 + i64::from(n % 2))).collect();
        let d2: Vec<ValidEvent> = (0..7).map(|n| event(n, 1_000)).collect();
        let d3: Vec<ValidEvent> = (0..7).map(|n| event(n, 1_000)).collect();
        insert_batch(&pool, "d1", &d1, at).await.unwrap();
        insert_batch(&pool, "d2", &d2, at).await.unwrap();
        insert_batch(&pool, "d3", &d3, at).await.unwrap();

        for limit in [1, 3, 5, 14, 100] {
            let events = all_pages(&pool, "u1", limit).await;
            assert_eq!(events.len(), 14, "page size {limit}");
            assert!(events.iter().all(|e| e.device_id != "d3"));
            let keys: Vec<(i64, String, String)> = events
                .iter()
                .map(|e| (e.start_ts, e.device_id.clone(), e.event_id.clone()))
                .collect();
            let mut sorted = keys.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(keys, sorted, "page size {limit}: out of order or repeated");
        }
    }

    #[tokio::test]
    async fn an_account_with_no_events_has_an_empty_first_page() {
        let pool = pool_with_devices().await;
        let page = select_own_page_after(&pool, "u1", None, 10).await.unwrap();
        assert!(page.is_empty());
    }
}
