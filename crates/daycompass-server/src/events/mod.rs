//! Screen time events: validating what a device reports, storing it,
//! and reading an account's own events back, raw or summed by day.
//!
//! The service layer for M2's ingest half and M3's two reads. As
//! everywhere else, nothing here knows about axum.
//!
//! | Topic | Module |
//! | --- | --- |
//! | Every per-event rule, and the closed set of refusal reasons | [`validate`] |
//! | Batching, idempotency, why one bad event never fails a batch | [`ingest`] |
//! | The account's own events, bounded by a time window | [`query`] |
//! | Deleting events past the configured age | [`retention`] |
//! | Every SQL statement that may name `events`, insert and select alike | [`store`] |
//!
//! [`crate::stats`] is a third consumer of this module: it calls
//! [`store::select_own_daily_group_totals`] rather than duplicating a
//! second statement that names `events`, since `tests/no_event_reads.rs`
//! allows exactly one file to do that.
//!
//! # What is still true from M2
//!
//! An admin manages accounts and devices and must never see what a
//! person was doing. Neither [`query::list_own`] nor
//! [`crate::stats::aggregate::daily_totals`] can be pointed at another
//! account - both take the caller's own id, resolved from the session
//! the access layer already authenticated, and there is no admin
//! variant of either route. `tests/no_event_reads.rs` checks this
//! against the sources rather than trusting it to be remembered, and
//! was itself extended, on purpose, to allow exactly these two reads.
//!
//! **Nothing here resolves overlaps.** Two devices reporting the same
//! span, or one device reporting a foreground application and a
//! browser domain at once, are both expected and both stored as sent.
//! Deciding what an overlap means is a query-time question, and
//! neither read answers it: [`query`] hands back what was stored,
//! unmerged, and [`crate::stats`]'s sums are just as raw - category
//! rules assign a label to each group, they do not deduplicate or
//! merge the spans underneath it. If that ever needs to change, it is
//! still nobody's job today.

pub mod ingest;
pub mod query;
pub mod retention;
pub mod store;
pub mod validate;
