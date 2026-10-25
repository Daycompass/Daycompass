//! Deleting events older than the instance's configured retention.
//!
//! Off unless an operator sets `DAYCOMPASS_RETENTION_DAYS`
//! ([`crate::config`]); env-only, like every other operational limit,
//! never editable through the API. An event's age is its own
//! `start_ts`, not when it was received - retention is about how long a
//! record of what somebody did is kept, and a backfilled event is just
//! as old as the moment it describes.
//!
//! Only events. Accounts, devices, category rules and the account log
//! are not usage data and are kept; they go when the account does.
//!
//! The configuration refuses a retention shorter than the ingest window
//! (`DAYCOMPASS_EVENT_MAX_AGE_SECS`), so a device can never upload an
//! event the next sweep would delete straight away.

use std::time::Duration;

use sqlx::SqlitePool;

use super::store;
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;

/// Events deleted per statement. Small enough that one statement holds
/// the write lock for milliseconds, so ingest and logins never wait on
/// a sweep for long.
const BATCH_ROWS: i64 = 5_000;

/// How long events are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_age: Duration,
}

impl RetentionPolicy {
    /// The `start_ts` before which an event is past retention at `now`.
    pub fn cutoff(self, now: UnixTime) -> i64 {
        let max_age = i64::try_from(self.max_age.as_secs()).unwrap_or(i64::MAX);
        now.as_secs().saturating_sub(max_age)
    }
}

/// Deletes every event past `policy` at `now`, in batches, and returns
/// how many were deleted.
///
/// A failure stops this sweep and is returned; whatever earlier batches
/// deleted stays deleted, and the next sweep picks up where this one
/// stopped.
pub async fn sweep(
    pool: &SqlitePool,
    policy: RetentionPolicy,
    now: UnixTime,
) -> Result<u64, StoreError> {
    sweep_in_batches(pool, policy.cutoff(now), BATCH_ROWS).await
}

async fn sweep_in_batches(pool: &SqlitePool, cutoff: i64, batch: i64) -> Result<u64, StoreError> {
    let mut total = 0;
    loop {
        let deleted = store::delete_started_before(pool, cutoff, batch).await?;
        total += deleted;
        if deleted < batch.unsigned_abs() {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, DbTarget};
    use crate::events::validate::ValidEvent;

    const DAY: i64 = 86_400;

    async fn pool_with_device() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'placeholder-not-a-hash', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");
        sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES ('d1', 'u1', 'laptop', 'linux', x'00', 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a device must succeed");
        pool
    }

    async fn insert(pool: &SqlitePool, starts: &[i64]) {
        let events: Vec<ValidEvent> = starts
            .iter()
            .enumerate()
            .map(|(n, start_ts)| ValidEvent {
                event_id: format!("{n:032x}"),
                start_ts: *start_ts,
                duration_secs: 60,
                app_id: "org.example.app".to_owned(),
                label: None,
                domain: None,
            })
            .collect();
        store::insert_batch(pool, "d1", &events, UnixTime::from_secs(0))
            .await
            .expect("insert");
    }

    async fn remaining(pool: &SqlitePool) -> Vec<i64> {
        sqlx::query_scalar("SELECT start_ts FROM events ORDER BY start_ts")
            .fetch_all(pool)
            .await
            .expect("reading back")
    }

    #[test]
    fn the_cutoff_is_now_minus_the_max_age_and_never_overflows() {
        let policy = RetentionPolicy {
            max_age: Duration::from_secs(30 * 86_400),
        };
        let now = UnixTime::from_secs(1_800_000_000);
        assert_eq!(policy.cutoff(now), 1_800_000_000 - 30 * DAY);

        let forever = RetentionPolicy {
            max_age: Duration::from_secs(u64::MAX),
        };
        assert!(forever.cutoff(now) < 0);
    }

    /// Strictly older than the cutoff goes; an event exactly on it stays.
    #[tokio::test]
    async fn only_events_before_the_cutoff_are_deleted() {
        let pool = pool_with_device().await;
        let now = 100 * DAY;
        let policy = RetentionPolicy {
            max_age: Duration::from_secs(30 * 86_400),
        };
        let cutoff = now - 30 * DAY;
        insert(&pool, &[cutoff - DAY, cutoff - 1, cutoff, cutoff + 1, now]).await;

        let deleted = sweep(&pool, policy, UnixTime::from_secs(now))
            .await
            .expect("sweep");

        assert_eq!(deleted, 2);
        assert_eq!(remaining(&pool).await, vec![cutoff, cutoff + 1, now]);
    }

    /// More rows than one batch, and an exact multiple of it: every
    /// batch loop ends, and nothing old survives.
    #[tokio::test]
    async fn sweeping_in_batches_deletes_everything_past_the_cutoff() {
        for (old, batch) in [(7, 3), (6, 3), (2, 3), (0, 3)] {
            let pool = pool_with_device().await;
            let mut starts: Vec<i64> = (0..old).collect();
            starts.push(1_000);
            insert(&pool, &starts).await;

            let deleted = sweep_in_batches(&pool, 500, batch).await.expect("sweep");

            assert_eq!(deleted, old.unsigned_abs(), "{old} old rows, batch {batch}");
            assert_eq!(remaining(&pool).await, vec![1_000]);
        }
    }
}
