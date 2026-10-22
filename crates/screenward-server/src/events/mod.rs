//! Screen time events: validating what a device reports, and storing
//! it.
//!
//! The service layer for M2's ingest half. As everywhere else, nothing
//! here knows about axum.
//!
//! | Topic | Module |
//! | --- | --- |
//! | Every per-event rule, and the closed set of refusal reasons | [`validate`] |
//! | Batching, idempotency, why one bad event never fails a batch | [`ingest`] |
//! | The one `INSERT`, and why it is not `INSERT OR IGNORE` | [`store`] |
//!
//! # What this module does not do
//!
//! **There is no read path.** M2 has no endpoint, no service function
//! and no query that returns an event to anybody - not to the device
//! that reported it, not to its owner, and above all not to an admin,
//! who manages accounts and devices and must never see what a person
//! was doing. Statistics and category rules arrive in M3 and will add
//! that path deliberately, under review.
//!
//! `tests/no_event_reads.rs` enforces this against the sources, so the
//! rule is checked rather than remembered. When M3 adds the first read
//! query it will have to extend that test on purpose - which is the
//! point. The same applies to M4's retention deletes.
//!
//! **Ingest does not resolve overlaps.** Two devices reporting the
//! same span, or one device reporting a foreground application and a
//! browser domain at once, are both expected and both stored as sent.
//! Deciding what an overlap means is a query-time question.

pub mod ingest;
pub mod store;
pub mod validate;
