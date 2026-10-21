//! Taking a batch of reported events and storing the ones that are
//! valid.
//!
//! # Why one bad event does not fail the batch
//!
//! A client that cannot get rid of a single malformed event would
//! retry the same batch forever, and the one thing worse than losing
//! an event is a client stuck in a loop reporting nothing. So the
//! request succeeds and every event gets its own verdict: accepted,
//! duplicate, or rejected with a machine-readable reason.
//!
//! Only four things fail a whole request, and all of them are
//! properties of the request rather than of any event in it: malformed
//! JSON, the wrong content type, a body over the size limit, and a
//! batch with more events than the cap. Those are handled at the HTTP
//! edge, not here.
//!
//! # Idempotency
//!
//! Per event, on `UNIQUE (device_id, event_id)`. A resent batch
//! produces a list of `Duplicate` and writes nothing; a batch that
//! partly overlaps an earlier one writes exactly the part that is new.
//! The client therefore never has to track what it has already sent -
//! resending is always safe.

use sqlx::SqlitePool;

use super::store::{self, Stored};
use super::validate::{self, EventWindow, RawEvent, RejectReason, ValidEvent};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;

/// The most events one request may carry.
pub const MAX_BATCH_EVENTS: usize = 500;

/// The largest an ingest body may be.
///
/// Attached to the route from its inventory entry, not read here; the
/// constant lives next to the batch cap because the two together are
/// what bound the work one request can ask for.
pub const MAX_BODY_BYTES: usize = 512 * 1024;

/// What happened to one event in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOutcome {
    Accepted,
    Duplicate,
    Rejected(RejectReason),
}

impl EventOutcome {
    /// The wire value of the status field.
    pub const fn status(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Rejected(_) => "rejected",
        }
    }

    /// The reason code, for a rejection.
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Accepted | Self::Duplicate => None,
            Self::Rejected(reason) => Some(reason.code()),
        }
    }
}

/// What a whole batch did.
#[derive(Debug, Clone)]
pub struct IngestReport {
    /// One outcome per submitted event, in the order they arrived.
    pub outcomes: Vec<EventOutcome>,
}

impl IngestReport {
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut accepted = 0;
        let mut duplicate = 0;
        let mut rejected = 0;
        for outcome in &self.outcomes {
            match outcome {
                EventOutcome::Accepted => accepted += 1,
                EventOutcome::Duplicate => duplicate += 1,
                EventOutcome::Rejected(_) => rejected += 1,
            }
        }
        (accepted, duplicate, rejected)
    }
}

/// Validates a batch and stores what passed.
///
/// The valid events are collected first and written in one
/// transaction, with the rejections slotted back into their original
/// positions afterwards - so the returned list lines up index for
/// index with what the client sent, however many events were refused.
pub async fn ingest(
    pool: &SqlitePool,
    device_id: &str,
    raw_events: &[RawEvent],
    window: EventWindow,
    now: UnixTime,
) -> Result<IngestReport, StoreError> {
    // Validate everything first, remembering where each valid event
    // came from so its outcome can go back in the right slot.
    let mut outcomes: Vec<Option<EventOutcome>> = vec![None; raw_events.len()];
    let mut valid: Vec<ValidEvent> = Vec::with_capacity(raw_events.len());
    let mut positions: Vec<usize> = Vec::with_capacity(raw_events.len());

    for (index, raw) in raw_events.iter().enumerate() {
        match validate::validate(raw, window, now) {
            Ok(event) => {
                valid.push(event);
                positions.push(index);
            }
            Err(reason) => outcomes[index] = Some(EventOutcome::Rejected(reason)),
        }
    }

    if !valid.is_empty() {
        let stored = store::insert_batch(pool, device_id, &valid, now).await?;
        for (position, outcome) in positions.into_iter().zip(stored) {
            outcomes[position] = Some(match outcome {
                Stored::Accepted => EventOutcome::Accepted,
                Stored::Duplicate => EventOutcome::Duplicate,
            });
        }
    }

    let outcomes: Vec<EventOutcome> = outcomes
        .into_iter()
        .map(|slot| slot.expect("every position is filled by one of the two passes above"))
        .collect();

    let report = IngestReport { outcomes };
    let (accepted, duplicate, rejected) = report.counts();
    // Counts only. No event id, app id, label or domain reaches the
    // log - an event is a record of what a person was doing.
    tracing::info!(
        device_id = %device_id,
        accepted,
        duplicate,
        rejected,
        "events ingested"
    );

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::db::{self, DbTarget};

    const NOW: i64 = 1_800_000_000;

    fn now() -> UnixTime {
        UnixTime::from_secs(NOW)
    }

    fn window() -> EventWindow {
        EventWindow {
            max_age: Duration::from_secs(90 * 24 * 60 * 60),
        }
    }

    /// An event id built from a counter, so a test can say "the same
    /// event again" without writing a literal that looks like a
    /// credential.
    fn event_id(n: u32) -> String {
        format!("{n:032x}")
    }

    fn event(n: u32) -> RawEvent {
        RawEvent {
            event_id: event_id(n),
            start_ts: NOW - 3_600 + i64::from(n),
            duration_secs: 60,
            app_id: "org.example.app".to_owned(),
            label: None,
            domain: None,
        }
    }

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

    async fn stored_count(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(pool)
            .await
            .expect("counting must succeed")
    }

    #[tokio::test]
    async fn a_fresh_batch_is_accepted_in_full() {
        let pool = pool_with_device().await;
        let batch: Vec<RawEvent> = (0..5).map(event).collect();

        let report = ingest(&pool, "d1", &batch, window(), now())
            .await
            .expect("ingest must succeed");

        assert_eq!(report.outcomes, vec![EventOutcome::Accepted; 5]);
        assert_eq!(stored_count(&pool).await, 5);
    }

    /// The property the whole design rests on: a client may always
    /// resend.
    #[tokio::test]
    async fn resending_an_identical_batch_writes_nothing_new() {
        let pool = pool_with_device().await;
        let batch: Vec<RawEvent> = (0..5).map(event).collect();

        ingest(&pool, "d1", &batch, window(), now()).await.unwrap();
        let again = ingest(&pool, "d1", &batch, window(), now())
            .await
            .expect("a resend must succeed");

        assert_eq!(again.outcomes, vec![EventOutcome::Duplicate; 5]);
        assert_eq!(stored_count(&pool).await, 5, "nothing may be written twice");
    }

    /// A client that resends a window of recent events plus some new
    /// ones - the ordinary sync pattern - must get exactly the new
    /// ones written.
    #[tokio::test]
    async fn a_partly_overlapping_batch_writes_only_the_new_part() {
        let pool = pool_with_device().await;

        let first: Vec<RawEvent> = (0..5).map(event).collect();
        ingest(&pool, "d1", &first, window(), now()).await.unwrap();

        let overlapping: Vec<RawEvent> = (3..8).map(event).collect();
        let report = ingest(&pool, "d1", &overlapping, window(), now())
            .await
            .expect("an overlapping batch must succeed");

        assert_eq!(
            report.outcomes,
            vec![
                EventOutcome::Duplicate,
                EventOutcome::Duplicate,
                EventOutcome::Accepted,
                EventOutcome::Accepted,
                EventOutcome::Accepted,
            ]
        );
        assert_eq!(stored_count(&pool).await, 8);
    }

    /// One bad event must not cost the batch. This is the reason
    /// ingest answers 200 with a list rather than 400.
    #[tokio::test]
    async fn one_rejected_event_does_not_block_the_rest() {
        let pool = pool_with_device().await;

        let batch = vec![
            event(1),
            RawEvent {
                duration_secs: 0,
                ..event(2)
            },
            event(3),
            RawEvent {
                event_id: "not-an-id".to_owned(),
                ..event(4)
            },
            event(5),
        ];

        let report = ingest(&pool, "d1", &batch, window(), now())
            .await
            .expect("a batch with bad events must still succeed");

        assert_eq!(
            report.outcomes,
            vec![
                EventOutcome::Accepted,
                EventOutcome::Rejected(RejectReason::DurationOutOfRange),
                EventOutcome::Accepted,
                EventOutcome::Rejected(RejectReason::EventIdMalformed),
                EventOutcome::Accepted,
            ],
            "each verdict must line up with the event that earned it"
        );
        assert_eq!(stored_count(&pool).await, 3);
        assert_eq!(report.counts(), (3, 0, 2));
    }

    /// The outcome list is positional, so a batch that is entirely
    /// rejected must still return one entry per submitted event.
    #[tokio::test]
    async fn an_entirely_rejected_batch_still_answers_per_event() {
        let pool = pool_with_device().await;
        let batch: Vec<RawEvent> = (0..3)
            .map(|n| RawEvent {
                duration_secs: -1,
                ..event(n)
            })
            .collect();

        let report = ingest(&pool, "d1", &batch, window(), now())
            .await
            .expect("ingest must succeed");

        assert_eq!(report.outcomes.len(), 3);
        assert!(report
            .outcomes
            .iter()
            .all(|outcome| matches!(outcome, EventOutcome::Rejected(_))));
        assert_eq!(stored_count(&pool).await, 0);
    }

    #[tokio::test]
    async fn an_empty_batch_is_a_no_op() {
        let pool = pool_with_device().await;
        let report = ingest(&pool, "d1", &[], window(), now())
            .await
            .expect("an empty batch must succeed");

        assert!(report.outcomes.is_empty());
        assert_eq!(stored_count(&pool).await, 0);
    }

    /// Overlapping spans are expected - two devices, or one device
    /// reporting a foreground app and a browser domain - and ingest
    /// must record them rather than resolving them. That is a
    /// query-time concern.
    #[tokio::test]
    async fn overlapping_events_are_both_recorded() {
        let pool = pool_with_device().await;

        let batch = vec![
            RawEvent {
                start_ts: NOW - 1_000,
                duration_secs: 600,
                ..event(1)
            },
            RawEvent {
                start_ts: NOW - 900,
                duration_secs: 600,
                app_id: "org.example.other".to_owned(),
                ..event(2)
            },
        ];

        let report = ingest(&pool, "d1", &batch, window(), now()).await.unwrap();
        assert_eq!(report.outcomes, vec![EventOutcome::Accepted; 2]);
        assert_eq!(
            stored_count(&pool).await,
            2,
            "ingest must not merge overlapping spans"
        );
    }

    /// The same event id from a different device is a different
    /// event, not a duplicate.
    #[tokio::test]
    async fn event_ids_are_scoped_to_their_device() {
        let pool = pool_with_device().await;
        sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES ('d2', 'u1', 'phone', 'android', x'01', 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("a second device must be insertable");

        let batch = vec![event(1)];
        assert_eq!(
            ingest(&pool, "d1", &batch, window(), now())
                .await
                .unwrap()
                .outcomes,
            vec![EventOutcome::Accepted]
        );
        assert_eq!(
            ingest(&pool, "d2", &batch, window(), now())
                .await
                .unwrap()
                .outcomes,
            vec![EventOutcome::Accepted],
            "another device reporting the same id is not a duplicate"
        );
        assert_eq!(stored_count(&pool).await, 2);
    }

    /// The two spellings of one id must collide, which is what makes
    /// idempotency survive a client changing its formatting.
    #[tokio::test]
    async fn the_two_event_id_spellings_deduplicate_against_each_other() {
        let pool = pool_with_device().await;

        let bare = "0123456789abcdef0123456789abcdef";
        let dashed = "01234567-89ab-cdef-0123-456789abcdef";

        let first = ingest(
            &pool,
            "d1",
            &[RawEvent {
                event_id: bare.to_owned(),
                ..event(1)
            }],
            window(),
            now(),
        )
        .await
        .unwrap();
        assert_eq!(first.outcomes, vec![EventOutcome::Accepted]);

        let second = ingest(
            &pool,
            "d1",
            &[RawEvent {
                event_id: dashed.to_owned(),
                ..event(1)
            }],
            window(),
            now(),
        )
        .await
        .unwrap();
        assert_eq!(
            second.outcomes,
            vec![EventOutcome::Duplicate],
            "the dashed spelling of the same id must not create a second row"
        );
        assert_eq!(stored_count(&pool).await, 1);
    }

    /// A duplicate inside one batch is still a duplicate: the first
    /// occurrence inserts, the second sees the row the first just
    /// wrote, because both run in the same transaction.
    #[tokio::test]
    async fn a_batch_that_repeats_itself_writes_one_row() {
        let pool = pool_with_device().await;
        let batch = vec![event(1), event(1)];

        let report = ingest(&pool, "d1", &batch, window(), now()).await.unwrap();
        assert_eq!(
            report.outcomes,
            vec![EventOutcome::Accepted, EventOutcome::Duplicate]
        );
        assert_eq!(stored_count(&pool).await, 1);
    }

    #[tokio::test]
    async fn the_stored_row_is_what_was_validated() {
        let pool = pool_with_device().await;
        let batch = vec![RawEvent {
            label: Some("Example Browser".to_owned()),
            domain: Some("EXAMPLE.COM".to_owned()),
            ..event(1)
        }];

        ingest(&pool, "d1", &batch, window(), now()).await.unwrap();

        let (event_id, app_id, label, domain, received_at): (
            String,
            String,
            Option<String>,
            Option<String>,
            i64,
        ) = sqlx::query_as(
            "SELECT event_id, app_id, label, domain, received_at FROM events",
        )
        .fetch_one(&pool)
        .await
        .expect("the event must be stored");

        assert_eq!(event_id, event_id_of(1));
        assert_eq!(app_id, "org.example.app");
        assert_eq!(label.as_deref(), Some("Example Browser"));
        assert_eq!(
            domain.as_deref(),
            Some("example.com"),
            "a hostname is stored lowercased"
        );
        assert_eq!(received_at, NOW, "received_at is the server's clock");
    }

    fn event_id_of(n: u32) -> String {
        event_id(n)
    }
}
