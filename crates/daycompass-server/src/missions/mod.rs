//! Missions: an account's own goals, the tasks under them, the time
//! tracked on those tasks and the weekly reviews of it, synced between
//! the account's devices.
//!
//! The service layer behind `POST /api/v1/missions/sync` and the
//! dashboard's missions pages. As everywhere else, nothing here knows
//! about axum.
//!
//! | Topic | Module |
//! | --- | --- |
//! | The four record types, every per-record rule, the closed set of refusal reasons | [`validate`] |
//! | Every SQL statement that names `missions`, `tasks`, `time_entries` or `reviews` | [`store`] |
//! | Last write wins, tombstones, the running timer, the cursor | [`sync`] |
//! | Keys that put a task between two others | [`position`] |
//! | The dashboard's reads and writes, the North Star, the weekly review | [`service`] |
//!
//! # The sync model
//!
//! Devices create records offline, with ids they generate, and push
//! them whenever they can. Per record, the write with the newest
//! client-side `updated_at` wins; on a tie the one that reached the
//! server last wins. The server is authoritative: a write that loses is
//! answered `stale`, and the winning version is sent back in the same
//! response, so every device converges on what the server holds.
//!
//! Every write takes the next value of the account's `missions_rev`, a
//! counter shared by all four tables. A device pulls "everything after
//! the rev I last saw", in pages, and keeps the returned cursor.
//!
//! A delete is a tombstone, so other devices learn of it. A tombstone
//! keeps no text - deleting a mission deletes its words.
//!
//! # Whose data this is
//!
//! An account's own, like its events: the sync route is device-only,
//! keyed to the device's owner, and has no id parameter that could name
//! another account. No admin route reads these tables.

pub mod position;
pub mod service;
pub mod store;
pub mod sync;
pub mod validate;
