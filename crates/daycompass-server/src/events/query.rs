//! Reading an account's own events back, bounded by a time window.
//!
//! M3's first read path, and the only one: there is no admin variant
//! and no way to name another account's id. The owner's id comes from
//! the session the access layer resolved, the same way every other
//! owner-scoped route in this codebase works - see
//! [`crate::routes::devices`].
//!
//! # Why a bounded window and a truncation flag, not a cursor
//!
//! The account's own history has no upper bound unless the operator
//! configures retention (M4, off by default), so a window with no cap
//! at all would let one request ask for an unbounded amount of work. [`MAX_RANGE_SECS`] bounds how wide a
//! single request's time span may be; [`MAX_ROWS`] bounds how many
//! rows one response carries regardless of how many exist inside that
//! span, which matters because a wide span across many devices can
//! still hold more rows than is reasonable to return at once.
//!
//! A cursor would let a client walk an arbitrarily large result set a
//! page at a time, which is more than this first cut needs: a client
//! that hits `truncated: true` narrows its own window and asks again,
//! exactly as a client that oversends to `POST /api/v1/events` splits
//! its batch. Pagination infrastructure can be added later if a real
//! use ever needs it.
//!
//! No category is assigned here or anywhere in this module. Events
//! carry no category; that is a separate piece of M3 built on top of
//! this read, not inside it.

use sqlx::SqlitePool;

use super::store::{self, QueriedEvent};
use crate::auth::store::StoreError;

/// The widest span one request's `[start_ts, end_ts)` may cover.
///
/// 31 days: wide enough for a dashboard's "this month" view, narrow
/// enough that even a account with many devices cannot ask one query
/// to scan an unbounded slice of its history.
pub const MAX_RANGE_SECS: i64 = 31 * 24 * 60 * 60;

/// The most events one response carries, however many exist in range.
///
/// Not a page size - there is no cursor to resume with. It exists so
/// that a window which turns out to hold far more rows than expected
/// costs a bounded amount of work instead of however much the account
/// happens to have stored.
pub const MAX_ROWS: usize = 5_000;

/// Why a requested range was refused before any query ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `end_ts` was not strictly after `start_ts`.
    Inverted,
    /// The span was wider than [`MAX_RANGE_SECS`].
    TooWide,
}

/// What [`list_own`] failed with.
#[derive(Debug)]
pub enum EventsQueryError {
    Range(RangeError),
    Store(StoreError),
}

/// A page of an account's own events.
///
/// `truncated` is `true` when more rows matched the range than
/// [`MAX_ROWS`] - the caller narrowed nothing, the server did, and the
/// response says so rather than silently under-reporting.
#[derive(Debug, Clone)]
pub struct EventPage {
    pub events: Vec<QueriedEvent>,
    pub truncated: bool,
}

/// Validates `[start_ts, end_ts)` and, if it is in bounds, returns the
/// account's own events inside it.
pub async fn list_own(
    pool: &SqlitePool,
    user_id: &str,
    start_ts: i64,
    end_ts: i64,
) -> Result<EventPage, EventsQueryError> {
    if end_ts <= start_ts {
        return Err(EventsQueryError::Range(RangeError::Inverted));
    }
    // `end_ts - start_ts` cannot overflow once the above holds: both
    // are validated event timestamps' neighbourhood, nowhere near
    // i64's edges, and the subtraction only runs after `end_ts` is
    // known to be the larger of the two.
    if end_ts - start_ts > MAX_RANGE_SECS {
        return Err(EventsQueryError::Range(RangeError::TooWide));
    }

    // One more than the cap, purely to tell "there were exactly
    // MAX_ROWS" apart from "there were more" - see `store::select_own_in_range`.
    let limit = i64::try_from(MAX_ROWS + 1).unwrap_or(i64::MAX);
    let mut events = store::select_own_in_range(pool, user_id, start_ts, end_ts, limit)
        .await
        .map_err(EventsQueryError::Store)?;

    let truncated = events.len() > MAX_ROWS;
    if truncated {
        events.truncate(MAX_ROWS);
    }

    Ok(EventPage { events, truncated })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::time::UnixTime;
    use crate::db::{self, DbTarget};
    use crate::events::validate::ValidEvent;

    const NOW: i64 = 1_800_000_000;

    /// A fresh in-memory database with two accounts, each owning one
    /// device - `alice`/`d-alice` and `bob`/`d-bob`.
    async fn pool_with_two_owners() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");
        for (user_id, device_id, username) in
            [("alice", "d-alice", "alice"), ("bob", "d-bob", "bob")]
        {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at)
                 VALUES (?1, ?2, 'placeholder-not-a-hash', 'user', 0)",
            )
            .bind(user_id)
            .bind(username)
            .execute(&pool)
            .await
            .expect("inserting a user must succeed");
            sqlx::query(
                "INSERT INTO devices
                     (id, user_id, name, platform, token_hash, created_at, last_seen_at)
                 VALUES (?1, ?2, 'device', 'linux', ?3, 0, 0)",
            )
            .bind(device_id)
            .bind(user_id)
            .bind(device_id.as_bytes())
            .execute(&pool)
            .await
            .expect("inserting a device must succeed");
        }
        pool
    }

    /// A valid event starting at `start_ts`, with a unique id derived
    /// from `n`.
    fn event_at(n: u32, start_ts: i64) -> ValidEvent {
        ValidEvent {
            event_id: format!("{n:032x}"),
            start_ts,
            duration_secs: 60,
            app_id: "org.example.app".to_owned(),
            label: None,
            domain: None,
        }
    }

    async fn insert_for(pool: &SqlitePool, device_id: &str, events: &[ValidEvent]) {
        store::insert_batch(pool, device_id, events, UnixTime::from_secs(NOW))
            .await
            .expect("inserting must succeed");
    }

    #[tokio::test]
    async fn an_owner_sees_only_their_own_events() {
        let pool = pool_with_two_owners().await;
        insert_for(&pool, "d-alice", &[event_at(1, NOW)]).await;
        insert_for(&pool, "d-bob", &[event_at(2, NOW)]).await;

        let alice_page = list_own(&pool, "alice", NOW - 10, NOW + 10)
            .await
            .expect("a valid range must succeed");
        assert_eq!(alice_page.events.len(), 1);
        assert_eq!(alice_page.events[0].device_id, "d-alice");

        let bob_page = list_own(&pool, "bob", NOW - 10, NOW + 10)
            .await
            .expect("a valid range must succeed");
        assert_eq!(bob_page.events.len(), 1);
        assert_eq!(bob_page.events[0].device_id, "d-bob");
    }

    /// An account with no devices and no events at all gets an empty
    /// page, not an error - this is the shape a brand-new account's
    /// first call looks like.
    #[tokio::test]
    async fn an_account_with_nothing_stored_gets_an_empty_page() {
        let pool = pool_with_two_owners().await;

        let page = list_own(&pool, "alice", NOW - 10, NOW + 10)
            .await
            .expect("a valid range must succeed");
        assert!(page.events.is_empty());
        assert!(!page.truncated);
    }

    #[tokio::test]
    async fn the_window_is_half_open() {
        let pool = pool_with_two_owners().await;
        insert_for(
            &pool,
            "d-alice",
            &[event_at(1, NOW), event_at(2, NOW + 100)],
        )
        .await;

        // [NOW, NOW + 100): the first event's start is in range, the
        // second's is exactly the exclusive end and must not appear.
        let page = list_own(&pool, "alice", NOW, NOW + 100)
            .await
            .expect("a valid range must succeed");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event_id, format!("{:032x}", 1));
    }

    #[tokio::test]
    async fn events_come_back_ordered_by_start_ts() {
        let pool = pool_with_two_owners().await;
        insert_for(&pool, "d-alice", &[event_at(1, NOW + 50), event_at(2, NOW)]).await;

        let page = list_own(&pool, "alice", NOW - 10, NOW + 100)
            .await
            .expect("a valid range must succeed");
        let starts: Vec<i64> = page.events.iter().map(|event| event.start_ts).collect();
        assert_eq!(starts, vec![NOW, NOW + 50]);
    }

    #[tokio::test]
    async fn an_inverted_range_is_refused_before_any_query_runs() {
        let pool = pool_with_two_owners().await;

        for (start, end) in [(NOW, NOW), (NOW, NOW - 1)] {
            let err = list_own(&pool, "alice", start, end)
                .await
                .expect_err("start >= end must be refused");
            assert!(matches!(err, EventsQueryError::Range(RangeError::Inverted)));
        }
    }

    #[tokio::test]
    async fn a_range_wider_than_the_cap_is_refused() {
        let pool = pool_with_two_owners().await;

        let err = list_own(&pool, "alice", NOW, NOW + MAX_RANGE_SECS + 1)
            .await
            .expect_err("a too-wide range must be refused");
        assert!(matches!(err, EventsQueryError::Range(RangeError::TooWide)));

        // The boundary itself must still be accepted.
        list_own(&pool, "alice", NOW, NOW + MAX_RANGE_SECS)
            .await
            .expect("exactly the cap must be accepted");
    }

    #[tokio::test]
    async fn a_page_wider_than_max_rows_is_truncated_and_says_so() {
        let pool = pool_with_two_owners().await;
        let events: Vec<ValidEvent> = (0..MAX_ROWS + 5)
            .map(|n| event_at(n as u32, NOW + n as i64))
            .collect();
        insert_for(&pool, "d-alice", &events).await;

        let page = list_own(&pool, "alice", NOW - 10, NOW + MAX_ROWS as i64 + 20)
            .await
            .expect("a valid range must succeed");
        assert_eq!(page.events.len(), MAX_ROWS);
        assert!(page.truncated);
    }

    #[tokio::test]
    async fn exactly_max_rows_is_not_truncated() {
        let pool = pool_with_two_owners().await;
        let events: Vec<ValidEvent> = (0..MAX_ROWS)
            .map(|n| event_at(n as u32, NOW + n as i64))
            .collect();
        insert_for(&pool, "d-alice", &events).await;

        let page = list_own(&pool, "alice", NOW - 10, NOW + MAX_ROWS as i64 + 20)
            .await
            .expect("a valid range must succeed");
        assert_eq!(page.events.len(), MAX_ROWS);
        assert!(!page.truncated);
    }
}
