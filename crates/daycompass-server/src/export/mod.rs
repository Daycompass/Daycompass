//! An account's own data, as one downloadable JSON document.
//!
//! M4's first piece, and the third read into `events` after M3's two.
//! Session-scoped only, no admin variant and no id parameter, same
//! reasoning as `GET /api/v1/events` - `tests/no_event_reads.rs` was
//! deliberately extended to allow this read rather than having its scan
//! widened.
//!
//! # Why the document is streamed, a page at a time
//!
//! Unless the operator configures retention (off by default), an
//! account's history has no upper bound, so
//! building the whole document before sending it would put an unbounded
//! amount of it in memory at once - on a server whose whole point is to
//! run in very little. Reading it in one query would instead hold one
//! of the pool's few connections for as long as the slowest client
//! takes to download it.
//!
//! So the small sections (account, devices, rules, log) are read up
//! front, and events follow in keyset pages of [`service::PAGE_ROWS`].
//! Each page is one short query; the next one runs only once the
//! client has taken the previous page, so a slow download holds no
//! connection while it waits.
//!
//! # Not a snapshot
//!
//! Pages are separate queries, not one transaction. An event ingested
//! while an export runs may or may not appear in it, depending on where
//! it sorts relative to the page being read. Keyset order is what keeps
//! this harmless: no event that existed when the export started is ever
//! repeated or skipped.
//!
//! # The `complete` marker
//!
//! The status code goes out before the first event is read, so a
//! database failure halfway through cannot turn into a 500. It is
//! logged and the body is aborted instead, and `"complete": true` -
//! always the document's last field - is never written. A client
//! accepts an export only if it parses and carries that field.
//!
//! | Topic | Module |
//! | --- | --- |
//! | The document's sections, as serialized | [`format`] |
//! | Reading the account and building the stream | [`service`] |

pub mod format;
pub mod service;
