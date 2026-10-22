//! Every SQL statement that touches the `events` table.
//!
//! There is exactly one, and it is an insert. **This file is the only
//! place in the codebase allowed to name the `events` table**, and
//! `tests/no_event_reads.rs` fails the build if that stops being true.
//!
//! M2 deliberately has no way to read an event back: no endpoint, no
//! service function, no join. Statistics and category rules are M3,
//! and an admin never gets event data at all.
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

use sqlx::SqlitePool;

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
