//! Every SQL statement the auth service layer runs.
//!
//! Keeping the queries here means the service modules stay readable and
//! there is one place to audit what touches the auth tables. All
//! statements use bound parameters; no value is ever formatted into SQL.
//!
//! Rows are validated on the way out. A `role` that is not one of the
//! two known values, or a token hash of the wrong length, is reported as
//! [`StoreError::CorruptRow`] rather than papered over - a malformed row
//! is a bug or tampering, and guessing at what it meant is how a
//! privilege check gets bypassed.

use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use super::role::Role;
use super::time::UnixTime;
use super::token::TokenHash;
use super::username::Username;

/// A row from `users`.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: Username,
    /// Argon2id PHC string.
    pub password_hash: String,
    pub role: Role,
    pub created_at: UnixTime,
}

/// Something went wrong talking to the database, or a row did not look
/// the way the schema promises. Messages name neither values nor SQL, so
/// they are safe to log directly.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("a database operation failed")]
    Database(#[source] sqlx::Error),

    #[error("a stored row does not match the expected schema")]
    CorruptRow,
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// A fresh UUID v7, which is time-ordered and therefore indexes well.
pub fn new_id() -> String {
    Uuid::now_v7().to_string()
}

// sqlx 0.9 only accepts literal SQL strings, so the column list is
// spelled out at each call site rather than shared through a constant.
fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserRecord, StoreError> {
    let id: String = row.try_get("id")?;
    let username: String = row.try_get("username")?;
    let password_hash: String = row.try_get("password_hash")?;
    let role: String = row.try_get("role")?;
    let created_at: i64 = row.try_get("created_at")?;

    Ok(UserRecord {
        id,
        // Stored usernames are already normalized, so re-parsing must
        // succeed; if it does not, the row was written by something that
        // bypassed the policy.
        username: Username::parse(&username).map_err(|_| StoreError::CorruptRow)?,
        password_hash,
        role: Role::parse(&role).ok_or(StoreError::CorruptRow)?,
        created_at: UnixTime::from_secs(created_at),
    })
}

/// Looks up an account by its already-normalized username.
pub async fn find_user_by_username(
    pool: &SqlitePool,
    username: &Username,
) -> Result<Option<UserRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?1",
    )
    .bind(username.as_str())
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(user_from_row).transpose()
}

/// Looks up an account by id.
pub async fn find_user_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<UserRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(user_from_row).transpose()
}

/// Replaces an account's password hash, for an in-place upgrade after a
/// successful login against weaker parameters.
pub async fn update_password_hash(
    pool: &SqlitePool,
    user_id: &str,
    password_hash: &str,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE users SET password_hash = ?2 WHERE id = ?1")
        .bind(user_id)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Whether any admin account exists.
///
/// This is advisory outside a transaction: it can be true by the time
/// the caller acts on a false. The authoritative check is the one inside
/// [`insert_first_admin`]'s transaction.
pub async fn admin_exists(pool: &SqlitePool) -> Result<bool, StoreError> {
    let (exists,): (i64,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')")
            .fetch_one(pool)
            .await?;
    Ok(exists != 0)
}

/// Outcome of trying to create the first admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstAdminOutcome {
    Created,
    /// An admin already existed, or the token had been redeemed, by the
    /// time the write lock was held.
    AlreadyCompleted,
    /// The token did not match an unused, unexpired row.
    TokenRejected,
}

/// Redeems a setup token and creates the first admin, atomically.
///
/// Runs in a `BEGIN IMMEDIATE` transaction, which takes SQLite's write
/// lock up front rather than on the first write. With a deferred
/// transaction two concurrent callers could both read "no admin exists"
/// and only collide at COMMIT; taking the lock first serializes them, so
/// the second one sees the first one's admin and backs out.
///
/// The token is marked used in the same transaction as the insert, so it
/// cannot be redeemed twice even if two requests arrive together.
pub async fn insert_first_admin(
    pool: &SqlitePool,
    token_hash: &TokenHash,
    username: &Username,
    password_hash: &str,
    now: UnixTime,
) -> Result<FirstAdminOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let (admin_exists,): (i64,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')")
            .fetch_one(&mut *tx)
            .await?;
    if admin_exists != 0 {
        // Nothing was written, so rolling back is just tidiness.
        tx.rollback().await?;
        return Ok(FirstAdminOutcome::AlreadyCompleted);
    }

    let token_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM setup_tokens
         WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
    )
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_optional(&mut *tx)
    .await?;

    let Some(token_id) = token_id else {
        tx.rollback().await?;
        return Ok(FirstAdminOutcome::TokenRejected);
    };

    sqlx::query("UPDATE setup_tokens SET used_at = ?2 WHERE id = ?1")
        .bind(&token_id)
        .bind(now.as_secs())
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at)
         VALUES (?1, ?2, ?3, 'admin', ?4)",
    )
    .bind(new_id())
    .bind(username.as_str())
    .bind(password_hash)
    .bind(now.as_secs())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(FirstAdminOutcome::Created)
}

/// Discards every existing setup token and stores the hash of a new one.
///
/// Called at startup while no admin exists. Replacing rather than adding
/// means a token printed by an earlier run stops working the moment the
/// process restarts, so only the most recently printed line is live.
pub async fn replace_setup_token(
    pool: &SqlitePool,
    token_hash: &TokenHash,
    now: UnixTime,
    expires_at: UnixTime,
) -> Result<(), StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    sqlx::query("DELETE FROM setup_tokens")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO setup_tokens (id, token_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(new_id())
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .bind(expires_at.as_secs())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Whether a setup token is currently redeemable.
///
/// Advisory: used to reject a bad token before spending Argon2 work on
/// the password. [`insert_first_admin`] re-checks under the write lock.
pub async fn setup_token_is_live(
    pool: &SqlitePool,
    token_hash: &TokenHash,
    now: UnixTime,
) -> Result<bool, StoreError> {
    let (live,): (i64,) = sqlx::query_as(
        "SELECT EXISTS (
             SELECT 1 FROM setup_tokens
             WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2
         )",
    )
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_one(pool)
    .await?;
    Ok(live != 0)
}

/// Removes setup tokens that are expired or already redeemed.
pub async fn delete_stale_setup_tokens(
    pool: &SqlitePool,
    now: UnixTime,
) -> Result<u64, StoreError> {
    let result =
        sqlx::query("DELETE FROM setup_tokens WHERE expires_at <= ?1 OR used_at IS NOT NULL")
            .bind(now.as_secs())
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// A row from `sessions`.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    pub created_at: UnixTime,
    /// When the session was last seen on a request. Drives the idle
    /// timeout.
    pub last_used_at: UnixTime,
    /// Hard end of life, set when the session was created. Drives the
    /// absolute timeout.
    pub expires_at: UnixTime,
}

/// Stores a new session row.
pub async fn insert_session(
    pool: &SqlitePool,
    session: &SessionRecord,
    token_hash: &TokenHash,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, last_used_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&session.id)
    .bind(&session.user_id)
    .bind(token_hash.as_bytes())
    .bind(session.created_at.as_secs())
    .bind(session.last_used_at.as_secs())
    .bind(session.expires_at.as_secs())
    .execute(pool)
    .await?;
    Ok(())
}

/// Looks up a session and its account in one statement.
///
/// One query rather than two so the session and the user are read from a
/// single consistent view: between two separate reads the account could
/// be deleted, leaving a handler holding a session that points nowhere.
pub async fn find_session_with_user(
    pool: &SqlitePool,
    token_hash: &TokenHash,
) -> Result<Option<(SessionRecord, UserRecord)>, StoreError> {
    let row = sqlx::query(
        "SELECT s.id            AS session_id,
                s.user_id       AS session_user_id,
                s.created_at    AS session_created_at,
                s.last_used_at  AS session_last_used_at,
                s.expires_at    AS session_expires_at,
                u.id            AS id,
                u.username      AS username,
                u.password_hash AS password_hash,
                u.role          AS role,
                u.created_at    AS created_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1",
    )
    .bind(token_hash.as_bytes())
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let session = SessionRecord {
        id: row.try_get("session_id")?,
        user_id: row.try_get("session_user_id")?,
        created_at: UnixTime::from_secs(row.try_get("session_created_at")?),
        last_used_at: UnixTime::from_secs(row.try_get("session_last_used_at")?),
        expires_at: UnixTime::from_secs(row.try_get("session_expires_at")?),
    };
    let user = user_from_row(&row)?;
    Ok(Some((session, user)))
}

/// Records that a session was just used.
pub async fn touch_session(
    pool: &SqlitePool,
    session_id: &str,
    now: UnixTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE sessions SET last_used_at = ?2 WHERE id = ?1")
        .bind(session_id)
        .bind(now.as_secs())
        .execute(pool)
        .await?;
    Ok(())
}

/// Deletes one session. Used by logout and when a session is found to
/// have expired.
pub async fn delete_session(pool: &SqlitePool, session_id: &str) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM sessions WHERE id = ?1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Removes every session past its absolute lifetime or its idle window.
///
/// Two statements rather than one `OR`, because each of these can use an
/// index while the disjunction could use neither.
pub async fn delete_expired_sessions(
    pool: &SqlitePool,
    now: UnixTime,
    idle_cutoff: UnixTime,
) -> Result<u64, StoreError> {
    let absolute = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1")
        .bind(now.as_secs())
        .execute(pool)
        .await?;
    let idle = sqlx::query("DELETE FROM sessions WHERE last_used_at <= ?1")
        .bind(idle_cutoff.as_secs())
        .execute(pool)
        .await?;
    Ok(absolute.rows_affected() + idle.rows_affected())
}

/// How many sessions an account currently has. For tests and later
/// session management.
pub async fn count_sessions_for_user(pool: &SqlitePool, user_id: &str) -> Result<i64, StoreError> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = ?1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}
