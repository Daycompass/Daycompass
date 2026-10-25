//! Building one account's export: the small sections read up front,
//! then a stream of event pages.
//!
//! Lives outside `routes` so the M5 dashboard's download link can reuse
//! it unchanged; the JSON handler only adds headers.

use futures_util::stream::{self, Stream, StreamExt};
use sqlx::SqlitePool;

use super::format::{self, Account, AccountLogEntry, CategoryRule, Device, Event, Head};
use crate::auth::account_log;
use crate::auth::store::{StoreError, UserRecord};
use crate::auth::time::UnixTime;
use crate::categories::service as categories;
use crate::devices::service as devices;
use crate::events::store::{self as events, PageKey};

/// Events read per query.
///
/// Small enough that one page is a short query and a modest buffer -
/// a few hundred KiB serialized - and large enough that a year of one
/// account's history is a few hundred queries, not a few hundred
/// thousand.
pub const PAGE_ROWS: i64 = 1_000;

/// What closes the document. Always the last bytes written, and only
/// ever written after the last page was read successfully - see the
/// module doc of [`super`].
const TAIL: &[u8] = b"],\"complete\":true}";

/// The error a body chunk fails with, after the real cause has been
/// logged.
///
/// Deliberately carries nothing: it reaches no client - the status is
/// already sent, so hyper can only abort the connection - and the
/// cause is already in the log, tagged with the account's id.
#[derive(Debug, thiserror::Error)]
#[error("the export was aborted")]
pub struct Aborted;

/// Reads `user`'s account, devices, rules and log, and returns the
/// whole document as a stream of byte chunks.
///
/// Fails before anything is sent if one of the up-front reads fails,
/// so that case is still an ordinary 500. Every later failure ends the
/// stream with [`Aborted`] instead, and the closing `complete` marker
/// is never written.
///
/// Takes the caller's own record and nothing else: there is no
/// parameter that could name another account.
pub async fn export_own(
    pool: &SqlitePool,
    user: &UserRecord,
    now: UnixTime,
) -> Result<impl Stream<Item = Result<Vec<u8>, Aborted>> + Send + 'static, StoreError> {
    let devices = devices::list_own_devices(pool, &user.id).await?;
    let rules = categories::list_own_rules(pool, &user.id).await?;
    let log = account_log::list_all_for_user(pool, &user.id).await?;

    let head = Head {
        format: format::FORMAT_NAME,
        format_version: format::FORMAT_VERSION,
        exported_at: now.as_secs(),
        account: Account::from(user),
        devices: devices.iter().map(Device::from).collect(),
        category_rules: rules.iter().map(CategoryRule::from).collect(),
        account_log: log.iter().map(AccountLogEntry::from).collect(),
    };

    let head = open_events_array(&head);
    let pages = Pages {
        pool: pool.clone(),
        user_id: user.id.clone(),
        after: None,
        done: false,
    };

    Ok(stream::once(async move { Ok(head) }).chain(stream::unfold(pages, Pages::next)))
}

/// `head` serialized, with its closing brace swapped for the opening of
/// the `events` array.
///
/// Serializing [`Head`] in one call and cutting its final `}` keeps
/// every field before `events` escaped by serde rather than by hand;
/// `serde_json` writes a struct compactly, so that brace is always the
/// last byte.
fn open_events_array(head: &Head) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(head).expect("the export head is always serializable");
    let closing = bytes.pop();
    debug_assert_eq!(closing, Some(b'}'));
    bytes.extend_from_slice(b",\"events\":[");
    bytes
}

/// Where the event pages have got to.
///
/// Owned, not borrowed, so the stream outlives the request handler that
/// built it - axum polls the body long after the handler returned.
struct Pages {
    pool: SqlitePool,
    user_id: String,
    /// The last row written, `None` before the first page.
    after: Option<PageKey>,
    /// Set once the tail is written, or once a read failed.
    done: bool,
}

impl Pages {
    /// The next chunk: one page of events, the tail with them if that
    /// page was the last, or the stream's end.
    async fn next(mut self) -> Option<(Result<Vec<u8>, Aborted>, Self)> {
        if self.done {
            return None;
        }

        let page = match events::select_own_page_after(
            &self.pool,
            &self.user_id,
            self.after.as_ref(),
            PAGE_ROWS,
        )
        .await
        {
            Ok(page) => page,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    user_id = %self.user_id,
                    "reading a page of the account export failed"
                );
                self.done = true;
                return Some((Err(Aborted), self));
            }
        };

        let mut chunk = Vec::new();
        for event in &page {
            if self.after.is_some() || !chunk.is_empty() {
                chunk.push(b',');
            }
            serde_json::to_writer(&mut chunk, &Event::from(event))
                .expect("an export event is always serializable");
        }

        // A short page is the last one, so the tail goes out with it
        // rather than costing one more query to learn the next page is
        // empty.
        if page.len() < PAGE_ROWS as usize {
            chunk.extend_from_slice(TAIL);
            self.done = true;
        }
        if let Some(last) = page.last() {
            self.after = Some(PageKey::after(last));
        }

        Some((Ok(chunk), self))
    }
}
