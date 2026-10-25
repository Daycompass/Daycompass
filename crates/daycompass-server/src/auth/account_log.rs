//! The account log.
//!
//! An admin can reset any account's password, and after doing so can
//! log in as that account - see `docs/design-decisions.md` for why that
//! power cannot be removed. This log is what keeps it from being
//! silent: every reset writes an entry here, naming the acting admin
//! and when, and only the account itself may read its own entries (see
//! `routes/account.rs`).
//!
//! There is deliberately **no update and no delete function anywhere in
//! this module**. An entry, once written, is a historical fact; nothing
//! here ever has reason to change one after the write that created it.
//! `tests/account_log.rs` scans the sources to pin that, in the style
//! of `tests/no_event_reads.rs`.

use sqlx::{Row, SqlitePool};

use super::store::{new_id, StoreError};
use super::time::UnixTime;

/// What happened. The exact three values the `kind` CHECK constraint in
/// migration `0004` allows - adding a fourth is another migration,
/// since the kind list is a CHECK constraint and not just this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// An invite was redeemed and the account became active.
    InviteRedeemed,
    /// An admin reset the account to pending, handing out a fresh
    /// invite in place of the password it had.
    PasswordResetByAdmin,
    /// The account changed its own password.
    PasswordChanged,
}

impl LogKind {
    /// The value stored in `account_log.kind`, which is also the value
    /// every read of the log puts on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InviteRedeemed => "invite_redeemed",
            Self::PasswordResetByAdmin => "password_reset_by_admin",
            Self::PasswordChanged => "password_changed",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "invite_redeemed" => Some(Self::InviteRedeemed),
            "password_reset_by_admin" => Some(Self::PasswordResetByAdmin),
            "password_changed" => Some(Self::PasswordChanged),
            _ => None,
        }
    }
}

/// One entry in an account's log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub id: String,
    pub kind: LogKind,
    /// The acting admin, for [`LogKind::PasswordResetByAdmin`]. `None`
    /// for the other two kinds, which are the account acting on
    /// itself.
    pub actor_id: Option<String>,
    /// UTC Unix seconds.
    pub at: UnixTime,
}

fn entry_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<LogEntry, StoreError> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let actor_id: Option<String> = row.try_get("actor_id")?;
    let at: i64 = row.try_get("at")?;

    Ok(LogEntry {
        id,
        kind: LogKind::parse(&kind).ok_or(StoreError::CorruptRow)?,
        actor_id,
        at: UnixTime::from_secs(at),
    })
}

/// Records one entry, inside a transaction the caller already holds
/// the write lock for.
///
/// Takes a connection rather than the pool, like
/// [`crate::devices::store::revoke_all_for_user`], so the SQL for this
/// table stays in the module that owns it while still running inside
/// the caller's own transaction. Every entry this module ever writes is
/// part of some other write - a reset, a redemption, a password change
/// - and must never become visible without it.
pub async fn record(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    kind: LogKind,
    actor_id: Option<&str>,
    at: UnixTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO account_log (id, user_id, kind, actor_id, at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(kind.as_str())
    .bind(actor_id)
    .bind(at.as_secs())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The newest 200 entries of one account's log, newest first.
///
/// There is no scope parameter and no "whose log" ambiguity to get
/// wrong: the caller passes exactly the id of the account reading its
/// own log, which is the only thing this function is ever for - see
/// `routes/account.rs`.
pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<LogEntry>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, kind, actor_id, at FROM account_log
         WHERE user_id = ?1 ORDER BY at DESC, id DESC LIMIT 200",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(entry_from_row).collect()
}

/// Every entry of one account's log, oldest first, for the account's
/// own export.
///
/// No `LIMIT`, unlike [`list_for_user`]: an export that silently
/// dropped the oldest entries would not be one. The log only grows on
/// invite redemptions and password events, so it stays small without a
/// cap. Same "the caller's own id, nothing else" contract as
/// [`list_for_user`] - see `crate::export`.
pub async fn list_all_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<LogEntry>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, kind, actor_id, at FROM account_log
         WHERE user_id = ?1 ORDER BY at ASC, id ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(entry_from_row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, DbTarget};

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    async fn pool_with_user() -> (SqlitePool, String) {
        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");

        let user_id = new_id();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES (?1, 'alice', 'placeholder', 'user', 0)",
        )
        .bind(&user_id)
        .execute(&pool)
        .await
        .expect("inserting the account must succeed");
        (pool, user_id)
    }

    #[tokio::test]
    async fn an_entry_is_recorded_and_read_back() {
        let (pool, user_id) = pool_with_user().await;
        let mut conn = pool.acquire().await.expect("a connection");

        record(&mut conn, &user_id, LogKind::PasswordChanged, None, now())
            .await
            .expect("recording must succeed");
        // The in-memory pool allows exactly one connection; `list_for_user`
        // needs to acquire its own.
        drop(conn);

        let entries = list_for_user(&pool, &user_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, LogKind::PasswordChanged);
        assert_eq!(entries[0].actor_id, None);
        assert_eq!(entries[0].at, now());
    }

    #[tokio::test]
    async fn entries_are_newest_first_and_carry_the_actor() {
        let (pool, user_id) = pool_with_user().await;
        let admin_id = new_id();
        let mut conn = pool.acquire().await.expect("a connection");

        record(&mut conn, &user_id, LogKind::InviteRedeemed, None, now())
            .await
            .unwrap();
        record(
            &mut conn,
            &user_id,
            LogKind::PasswordResetByAdmin,
            Some(&admin_id),
            now().saturating_add(std::time::Duration::from_secs(1)),
        )
        .await
        .unwrap();
        drop(conn);

        let entries = list_for_user(&pool, &user_id).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, LogKind::PasswordResetByAdmin);
        assert_eq!(entries[0].actor_id.as_deref(), Some(admin_id.as_str()));
        assert_eq!(entries[1].kind, LogKind::InviteRedeemed);
    }

    #[tokio::test]
    async fn a_user_sees_only_their_own_log() {
        let (pool, user_id) = pool_with_user().await;
        let other_id = new_id();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES (?1, 'bob', 'placeholder', 'user', 0)",
        )
        .bind(&other_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut conn = pool.acquire().await.expect("a connection");

        record(&mut conn, &user_id, LogKind::PasswordChanged, None, now())
            .await
            .unwrap();
        record(&mut conn, &other_id, LogKind::PasswordChanged, None, now())
            .await
            .unwrap();
        drop(conn);

        assert_eq!(list_for_user(&pool, &user_id).await.unwrap().len(), 1);
        assert_eq!(list_for_user(&pool, &other_id).await.unwrap().len(), 1);
    }

    /// The export's read: past the 200 the endpoint shows, oldest
    /// first, and still only the caller's own.
    #[tokio::test]
    async fn the_full_log_is_uncapped_oldest_first_and_own_only() {
        let (pool, user_id) = pool_with_user().await;
        let other_id = new_id();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES (?1, 'bob', 'placeholder', 'user', 0)",
        )
        .bind(&other_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut conn = pool.acquire().await.expect("a connection");

        for n in 0..250u64 {
            record(
                &mut conn,
                &user_id,
                LogKind::PasswordChanged,
                None,
                now().saturating_add(std::time::Duration::from_secs(n)),
            )
            .await
            .unwrap();
        }
        record(&mut conn, &other_id, LogKind::PasswordChanged, None, now())
            .await
            .unwrap();
        drop(conn);

        let entries = list_all_for_user(&pool, &user_id).await.unwrap();
        assert_eq!(entries.len(), 250);
        assert_eq!(entries[0].at, now());
        assert!(entries.windows(2).all(|pair| pair[0].at <= pair[1].at));
        assert_eq!(list_all_for_user(&pool, &other_id).await.unwrap().len(), 1);
    }
}
