//! Category rules: an account's own mapping from an event's `app_id`
//! or `domain` to a category, applied at query time.
//!
//! Events carry no category column (migration `0003`) - this is the
//! piece that was deferred when `GET /api/v1/events` shipped without
//! one. Nothing here writes to `events` or reads it; this module only
//! manages the rules themselves and resolves a category for a value
//! the caller already has in hand. The join between the two lives in
//! [`crate::routes::events::list_own`], which calls [`resolve`] once
//! per request and maps it over the events [`crate::events::query`]
//! already fetched.
//!
//! # Ownership
//!
//! A rule belongs to one account, the same as a device. No admin
//! variant, no id parameter that could name another account - an
//! admin manages accounts and devices but must never read or shape
//! another account's categorization, same reasoning as the one read
//! path into `events`.
//!
//! # How a rule matches
//!
//! A rule is one of two kinds, [`kind::RuleKind::AppId`] or
//! [`kind::RuleKind::Domain`], and matches on exactly that field:
//!
//! - `app_id`: an exact, case-sensitive match - the same identifier
//!   semantics as `events.app_id` itself, never folded or trimmed.
//! - `domain`: case-insensitive, and **suffix-inclusive of
//!   subdomains** - a rule on `google.com` also matches
//!   `mail.google.com`, but not `notgoogle.com`. The boundary is a
//!   literal `.`, not a bare string suffix; see [`resolve`].
//!
//! When both an `app_id` rule and one or more `domain` rules match the
//! same event, the `app_id` rule wins - it names the exact thing that
//! produced the event, where a domain is one signal among several a
//! browser might report. Among domain rules, the longest (most
//! specific) matching pattern wins, so a rule on `mail.google.com`
//! takes a match away from one on `google.com`. No match leaves the
//! category absent, not a sentinel string.
//!
//! | Topic | Module |
//! | --- | --- |
//! | The rule kind, and pattern normalization per kind | [`kind`] |
//! | The category label policy | [`label`] |
//! | Every SQL statement, and the per-account cap | [`store`] |
//! | Validation-then-store wrappers | [`service`] |
//! | The matching logic itself | [`resolve`] |

pub mod kind;
pub mod label;
pub mod resolve;
pub mod service;
pub mod store;
