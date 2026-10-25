//! Aggregating an account's own events into daily category totals.
//!
//! M3's second read, built on top of the first
//! ([`crate::events::store::select_own_daily_group_totals`]) and on
//! [`crate::categories::resolve`]'s matching. Session-scoped only, no
//! admin variant, same reasoning as `GET /api/v1/events` - see
//! `tests/no_event_reads.rs`, which was deliberately extended to allow
//! this second read rather than having its scan widened.
//!
//! | Topic | Module |
//! | --- | --- |
//! | Range validation and the day/category folding | [`aggregate`] |

pub mod aggregate;
