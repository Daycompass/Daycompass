//! Range validation and the day/category folding behind `GET
//! /api/v1/stats`.
//!
//! [`daily_totals`] does three things, in order: validates the
//! requested range, asks [`crate::events::store`] to sum `duration_secs`
//! by day/`app_id`/`domain` in SQL, then resolves each of those groups
//! to a category with a single [`crate::categories::resolve::Resolver`]
//! built from the caller's own rules - so the per-group matching cost
//! is paid once per distinct (day, app, domain) combination in the
//! window, not once per event.
//!
//! # Nothing here resolves overlaps
//!
//! Two devices covering the same span, or one device reporting an app
//! and a domain for the same span, are summed exactly as reported.
//! See `crate::events`'s module doc for why that is a deliberate
//! choice and not an oversight repeated in a second place.

use std::cmp::Ordering;
use std::collections::HashMap;

use sqlx::SqlitePool;

use crate::auth::store::StoreError;
use crate::categories::resolve::Resolver;
use crate::categories::service as categories;
use crate::events::store;
use crate::timezone::{TimeZoneName, OFFSET_GRANULARITY_SECS};

const UTC_DAY_SECS: i64 = 24 * 60 * 60;

/// The widest span one request's `[start_ts, end_ts)` may cover.
///
/// Wider than `events::query::MAX_RANGE_SECS` on purpose: that cap
/// exists because `GET /api/v1/events` hands back one row per event,
/// up to `events::query::MAX_ROWS` of them. This endpoint hands back
/// one row per (day, category) combination instead, so a year-wide
/// "last 12 months" dashboard view costs a bounded, small response
/// even though the window is twelve times wider.
pub const MAX_RANGE_SECS: i64 = 366 * 24 * 60 * 60;

/// Why a requested range was refused before any query ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `end_ts` was not strictly after `start_ts`.
    Inverted,
    /// The span was wider than [`MAX_RANGE_SECS`].
    TooWide,
}

/// What [`daily_totals`] failed with.
#[derive(Debug)]
pub enum AggregateError {
    Range(RangeError),
    Store(StoreError),
}

/// One day's total for one category, summed across every matching
/// event in the caller's own history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyCategoryTotal {
    /// The Unix timestamp of this day's midnight in the zone the totals
    /// were asked for in.
    pub day_start_ts: i64,
    /// `None` for the total of events no rule matched - a real
    /// bucket, not an error.
    pub category: Option<String>,
    pub total_duration_secs: i64,
}

/// Validates `[start_ts, end_ts)` and, if it is in bounds, sums the
/// caller's own screen time per calendar day of `zone`, and category.
///
/// With `zone` UTC the days are UTC days and the SQL does the whole
/// grouping. Any other zone makes SQL group by 15-minute bucket
/// instead, and each bucket is placed in its local day here, because
/// SQLite has no time zone rules and a local day is not a fixed
/// 86,400 seconds long.
///
/// Sparse, like the rule set it is built from: a (day, category)
/// combination with nothing in it has no row at all, rather than one
/// with `total_duration_secs: 0`. Ordered `day_start_ts` ascending,
/// then `category` ascending with the no-category total last within
/// its day.
pub async fn daily_totals(
    pool: &SqlitePool,
    user_id: &str,
    start_ts: i64,
    end_ts: i64,
    zone: &TimeZoneName,
) -> Result<Vec<DailyCategoryTotal>, AggregateError> {
    if end_ts <= start_ts {
        return Err(AggregateError::Range(RangeError::Inverted));
    }
    // `end_ts - start_ts` cannot overflow once the above holds, same
    // reasoning as `events::query::list_own`.
    if end_ts - start_ts > MAX_RANGE_SECS {
        return Err(AggregateError::Range(RangeError::TooWide));
    }

    let rules = categories::list_own_rules(pool, user_id)
        .await
        .map_err(AggregateError::Store)?;
    let resolver = Resolver::build(&rules);

    let bucket_secs = if zone.is_utc() {
        UTC_DAY_SECS
    } else {
        OFFSET_GRANULARITY_SECS
    };
    let groups = store::select_own_daily_group_totals(pool, user_id, start_ts, end_ts, bucket_secs)
        .await
        .map_err(AggregateError::Store)?;

    let mut totals: HashMap<(i64, Option<String>), i64> = HashMap::new();
    for group in &groups {
        let category = resolver
            .category_for(&group.app_id, group.domain.as_deref())
            .map(str::to_owned);
        let day_start_ts = if zone.is_utc() {
            group.bucket_start_ts
        } else {
            zone.day_start(group.bucket_start_ts)
        };
        *totals.entry((day_start_ts, category)).or_insert(0) += group.total_duration_secs;
    }

    let mut totals: Vec<DailyCategoryTotal> = totals
        .into_iter()
        .map(
            |((day_start_ts, category), total_duration_secs)| DailyCategoryTotal {
                day_start_ts,
                category,
                total_duration_secs,
            },
        )
        .collect();
    totals.sort_unstable_by(|a, b| {
        a.day_start_ts
            .cmp(&b.day_start_ts)
            .then_with(|| compare_categories(&a.category, &b.category))
    });

    Ok(totals)
}

/// Orders `Some` categories alphabetically, with `None` sorted last
/// rather than `Option`'s derived order, which would put it first.
fn compare_categories(a: &Option<String>, b: &Option<String>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::time::UnixTime;
    use crate::db::{self, DbTarget};
    use crate::events::validate::ValidEvent;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    /// A fresh in-memory database with one account, `alice`, owning
    /// two devices.
    async fn pool_with_one_owner() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('alice', 'alice', 'placeholder-not-a-hash', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");
        for device_id in ["d-one", "d-two"] {
            sqlx::query(
                "INSERT INTO devices
                     (id, user_id, name, platform, token_hash, created_at, last_seen_at)
                 VALUES (?1, 'alice', 'device', 'linux', ?2, 0, 0)",
            )
            .bind(device_id)
            .bind(device_id.as_bytes())
            .execute(&pool)
            .await
            .expect("inserting a device must succeed");
        }
        pool
    }

    fn event(
        id: u32,
        start_ts: i64,
        duration_secs: i64,
        app_id: &str,
        domain: Option<&str>,
    ) -> ValidEvent {
        ValidEvent {
            event_id: format!("{id:032x}"),
            start_ts,
            duration_secs,
            app_id: app_id.to_owned(),
            label: None,
            domain: domain.map(str::to_owned),
        }
    }

    async fn insert_for(pool: &SqlitePool, device_id: &str, events: &[ValidEvent]) {
        crate::events::store::insert_batch(pool, device_id, events, UnixTime::from_secs(NOW))
            .await
            .expect("inserting must succeed");
    }

    async fn add_rule(pool: &SqlitePool, kind: &str, pattern: &str, category: &str) {
        crate::categories::service::create_rule(
            pool,
            "alice",
            kind,
            pattern,
            category,
            UnixTime::from_secs(NOW),
        )
        .await
        .expect("creating the rule must succeed");
    }

    #[tokio::test]
    async fn events_on_the_same_day_and_category_are_summed() {
        let pool = pool_with_one_owner().await;
        add_rule(&pool, "app_id", "org.example.study", "Study").await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[
                event(1, day_start + 100, 600, "org.example.study", None),
                event(2, day_start + 900, 300, "org.example.study", None),
            ],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        assert_eq!(
            totals,
            vec![DailyCategoryTotal {
                day_start_ts: day_start,
                category: Some("Study".to_owned()),
                total_duration_secs: 900,
            }]
        );
    }

    /// Two devices reporting overlapping spans are summed exactly as
    /// reported - this endpoint does not deduplicate or merge
    /// overlaps, by design.
    #[tokio::test]
    async fn overlapping_events_from_two_devices_are_both_counted() {
        let pool = pool_with_one_owner().await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[event(1, day_start + 100, 600, "org.example.app", None)],
        )
        .await;
        insert_for(
            &pool,
            "d-two",
            &[event(2, day_start + 100, 600, "org.example.app", None)],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        assert_eq!(totals.len(), 1);
        assert_eq!(
            totals[0].total_duration_secs, 1200,
            "both reports must count"
        );
    }

    /// An event with no matching rule still gets a total, under
    /// `category: None`, not dropped and not under a sentinel string.
    #[tokio::test]
    async fn events_matching_no_rule_total_under_no_category() {
        let pool = pool_with_one_owner().await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[event(1, day_start + 100, 300, "org.example.unknown", None)],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        assert_eq!(
            totals,
            vec![DailyCategoryTotal {
                day_start_ts: day_start,
                category: None,
                total_duration_secs: 300,
            }]
        );
    }

    /// An `app_id` rule wins over a `domain` rule, and the win is
    /// still visible after folding into daily totals - re-proving
    /// `categories::resolve`'s own rule at this layer, since a bug in
    /// how groups are folded could still produce the wrong total even
    /// if the resolver itself is correct.
    #[tokio::test]
    async fn app_id_still_wins_over_domain_once_folded_into_a_day() {
        let pool = pool_with_one_owner().await;
        add_rule(&pool, "domain", "example.com", "Browsing").await;
        add_rule(&pool, "app_id", "org.example.browser", "Study").await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[event(
                1,
                day_start + 100,
                300,
                "org.example.browser",
                Some("example.com"),
            )],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        assert_eq!(
            totals,
            vec![DailyCategoryTotal {
                day_start_ts: day_start,
                category: Some("Study".to_owned()),
                total_duration_secs: 300,
            }]
        );
    }

    /// An event is attributed whole to the day its own `start_ts`
    /// falls in, even when `start_ts + duration_secs` crosses into the
    /// next one - the chosen simplicity tradeoff, not a bug.
    #[tokio::test]
    async fn an_event_crossing_midnight_is_attributed_to_its_start_day() {
        let pool = pool_with_one_owner().await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[event(1, day_start + DAY - 60, 300, "org.example.app", None)],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].day_start_ts, day_start);
    }

    #[tokio::test]
    async fn results_are_ordered_by_day_then_category_with_none_last() {
        let pool = pool_with_one_owner().await;
        add_rule(&pool, "app_id", "org.example.study", "Study").await;
        add_rule(&pool, "app_id", "org.example.social", "Social").await;
        let day_start = (NOW / DAY) * DAY;
        insert_for(
            &pool,
            "d-one",
            &[
                event(1, day_start + 100, 60, "org.example.social", None),
                event(2, day_start + 200, 60, "org.example.unknown", None),
                event(3, day_start + 300, 60, "org.example.study", None),
            ],
        )
        .await;

        let totals = daily_totals(
            &pool,
            "alice",
            day_start,
            day_start + DAY,
            &TimeZoneName::utc(),
        )
        .await
        .expect("a valid range must succeed");
        let categories: Vec<Option<String>> = totals.into_iter().map(|t| t.category).collect();
        assert_eq!(
            categories,
            vec![Some("Social".to_owned()), Some("Study".to_owned()), None,]
        );
    }

    #[tokio::test]
    async fn an_account_with_nothing_stored_gets_an_empty_result() {
        let pool = pool_with_one_owner().await;

        let totals = daily_totals(&pool, "alice", NOW - 10, NOW + 10, &TimeZoneName::utc())
            .await
            .expect("a valid range must succeed");
        assert!(totals.is_empty());
    }

    #[tokio::test]
    async fn an_inverted_range_is_refused_before_any_query_runs() {
        let pool = pool_with_one_owner().await;

        for (start, end) in [(NOW, NOW), (NOW, NOW - 1)] {
            let err = daily_totals(&pool, "alice", start, end, &TimeZoneName::utc())
                .await
                .expect_err("start >= end must be refused");
            assert!(matches!(err, AggregateError::Range(RangeError::Inverted)));
        }
    }

    #[tokio::test]
    async fn a_range_wider_than_the_cap_is_refused() {
        let pool = pool_with_one_owner().await;

        let err = daily_totals(
            &pool,
            "alice",
            NOW,
            NOW + MAX_RANGE_SECS + 1,
            &TimeZoneName::utc(),
        )
        .await
        .expect_err("a too-wide range must be refused");
        assert!(matches!(err, AggregateError::Range(RangeError::TooWide)));

        // The boundary itself must still be accepted.
        daily_totals(
            &pool,
            "alice",
            NOW,
            NOW + MAX_RANGE_SECS,
            &TimeZoneName::utc(),
        )
        .await
        .expect("exactly the cap must be accepted");
    }

    /// 23:30 and 00:30 Berlin time on either side of midnight are the
    /// same UTC day but two Berlin days.
    #[tokio::test]
    async fn a_zone_moves_the_day_boundary() {
        let pool = pool_with_one_owner().await;
        // 2026-01-10 22:30 UTC = 23:30 CET, and 23:30 UTC = 00:30 CET
        // the next day.
        let utc_day = 1_768_003_200;
        assert_eq!(utc_day % DAY, 0);
        insert_for(
            &pool,
            "d-one",
            &[
                event(1, utc_day + 22 * 3600 + 1800, 60, "org.example.a", None),
                event(2, utc_day + 23 * 3600 + 1800, 120, "org.example.a", None),
            ],
        )
        .await;
        let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();

        let in_utc = daily_totals(&pool, "alice", utc_day, utc_day + DAY, &TimeZoneName::utc())
            .await
            .unwrap();
        assert_eq!(in_utc.len(), 1);
        assert_eq!(in_utc[0].total_duration_secs, 180);

        let local = daily_totals(&pool, "alice", utc_day, utc_day + DAY, &berlin)
            .await
            .unwrap();
        // Berlin midnight is 23:00 UTC the day before.
        let first = utc_day - 3600;
        assert_eq!(
            local
                .iter()
                .map(|t| (t.day_start_ts, t.total_duration_secs))
                .collect::<Vec<_>>(),
            vec![(first, 60), (first + DAY, 120)]
        );
    }
}
