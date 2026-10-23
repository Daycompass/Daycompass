//! Devices and the pairing flow that creates them.
//!
//! This is the service layer for M2's device half. As with
//! [`crate::auth`], nothing here knows about axum: the JSON handlers in
//! [`crate::routes`] and the later dashboard drive exactly these
//! functions.
//!
//! # Where each decision is written down
//!
//! | Topic | Module |
//! | --- | --- |
//! | Pairing code alphabet, why 50 bits is enough, input folding | [`code`] |
//! | The device name policy, and why it trims when `app_id` does not | [`name`] |
//! | The closed platform set, mirrored by a CHECK constraint | [`platform`] |
//! | Every SQL statement, and which ones take the write lock | [`store`] |
//! | Pairing, redemption, revocation, the device cap | [`service`] |
//!
//! Device *authentication* - turning an `Authorization: Bearer` header
//! into a device - lives in [`crate::auth::device`] instead, with the
//! rest of the authentication story, and is indexed from
//! [`crate::auth`]. The SQL it runs is still here, in [`store`].
//!
//! # The one rule this module exists to keep
//!
//! No function in this module may read the `events` table, and none
//! returns anything derived from it. An admin manages devices and can
//! never see what any of them reported; a device's owner cannot read
//! their events back either, because M2 has no endpoint for it at all.
//! `tests/no_event_reads.rs` enforces this against the sources rather
//! than trusting the rule to be remembered.

pub mod code;
pub mod name;
pub mod platform;
pub mod service;
pub mod store;
