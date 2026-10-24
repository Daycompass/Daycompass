//! Screen time events: validating what a device reports, storing it,
//! and reading an account's own events back.
//!
//! The service layer for M2's ingest half and M3's first read. As
//! everywhere else, nothing here knows about axum.
//!
//! | Topic | Module |
//! | --- | --- |
//! | Every per-event rule, and the closed set of refusal reasons | [`validate`] |
//! | Batching, idempotency, why one bad event never fails a batch | [`ingest`] |
//! | The account's own events, bounded by a time window | [`query`] |
//! | Every SQL statement that may name `events`, insert and select alike | [`store`] |
//!
//! # What is still true from M2
//!
//! An admin manages accounts and devices and must never see what a
//! person was doing. [`query::list_own`] cannot be pointed at another
//! account - it takes the caller's own id, resolved from the session
//! the access layer already authenticated, and there is no admin
//! variant of the route that calls it. `tests/no_event_reads.rs`
//! checks this against the sources rather than trusting it to be
//! remembered, and was itself extended, on purpose, to allow exactly
//! this one read.
//!
//! **Ingest does not resolve overlaps.** Two devices reporting the
//! same span, or one device reporting a foreground application and a
//! browser domain at once, are both expected and both stored as sent.
//! Deciding what an overlap means is a query-time question, and
//! [`query`] does not answer it either - it hands back what was
//! stored. Category rules, which are what *would* answer it, are a
//! later piece of M3.

pub mod ingest;
pub mod query;
pub mod store;
pub mod validate;
