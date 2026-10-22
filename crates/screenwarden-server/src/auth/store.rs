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

use sqlx::error::DatabaseError;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use super::role::Role;
use super::time::UnixTime;
use super::token::TokenHash;
use super::username::Username;

/// Whether an account has a password it can log in with.
///
/// A pending account exists - an admin has created it and handed over
/// an invite - but has chosen no password yet. Stored as the `status`
/// column; see migration `0004` for why `password_hash` could not
/// simply become nullable instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Pending,
}

impl AccountStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
        }
    }

    /// Parses a value read back from the database. `None` for anything
    /// else, so an unexpected row is reported as corrupt rather than
    /// silently treated as one of the known statuses.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "pending" => Some(Self::Pending),
            _ => None,
        }
    }
}

/// An account's credential: a password, or nothing yet.
///
/// This is the point of having the type at all: with `password_hash` as
/// a bare `String`, every reader - login, a password change, anywhere
/// else - could read straight past a pending account's empty string and
/// into whatever happens to do with it. With this enum there is no
/// hash field to read past; the compiler forces each reader to say what
/// a pending account does.
#[derive(Debug, Clone)]
pub enum Credential {
    /// An Argon2id PHC string.
    Password(String),
    /// No password has been chosen yet. Login must take the same path
    /// as an unknown account - see [`crate::auth::login`].
    Pending,
}

/// A row from `users`.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: Username,
    pub credential: Credential,
    pub role: Role,
    pub status: AccountStatus,
    pub created_at: UnixTime,
}

/// A row from `users` without its password hash.
///
/// Separate from [`UserRecord`] rather than an option on it: the
/// account-management queries select no `password_hash` column at all,
/// so there is no field for one to leak out of. Authentication still
/// needs the hash and keeps using [`UserRecord`].
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub id: String,
    pub username: Username,
    pub role: Role,
    pub status: AccountStatus,
    pub created_at: UnixTime,
}

impl From<&UserRecord> for UserSummary {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.clone(),
            role: user.role,
            status: user.status,
            created_at: user.created_at,
        }
    }
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
    let status: String = row.try_get("status")?;
    let created_at: i64 = row.try_get("created_at")?;

    let status = AccountStatus::parse(&status).ok_or(StoreError::CorruptRow)?;
    let credential = match status {
        AccountStatus::Active => Credential::Password(password_hash),
        AccountStatus::Pending => Credential::Pending,
    };

    Ok(UserRecord {
        id,
        // Stored usernames are already normalized, so re-parsing must
        // succeed; if it does not, the row was written by something that
        // bypassed the policy.
        username: Username::parse(&username).map_err(|_| StoreError::CorruptRow)?,
        credential,
        role: Role::parse(&role).ok_or(StoreError::CorruptRow)?,
        status,
        created_at: UnixTime::from_secs(created_at),
    })
}

fn summary_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<UserSummary, StoreError> {
    let id: String = row.try_get("id")?;
    let username: String = row.try_get("username")?;
    let role: String = row.try_get("role")?;
    let status: String = row.try_get("status")?;
    let created_at: i64 = row.try_get("created_at")?;

    Ok(UserSummary {
        id,
        username: Username::parse(&username).map_err(|_| StoreError::CorruptRow)?,
        role: Role::parse(&role).ok_or(StoreError::CorruptRow)?,
        status: AccountStatus::parse(&status).ok_or(StoreError::CorruptRow)?,
        created_at: UnixTime::from_secs(created_at),
    })
}

/// Looks up an account by its already-normalized username.
pub async fn find_user_by_username(
    pool: &SqlitePool,
    username: &Username,
) -> Result<Option<UserRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, username, password_hash, role, status, created_at
         FROM users WHERE username = ?1",
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
        "SELECT id, username, password_hash, role, status, created_at
         FROM users WHERE id = ?1",
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

/// How many accounts currently have the admin role **and** are active.
///
/// Takes a connection rather than the pool so it can run *inside* a
/// write transaction, which is the only place its answer is
/// authoritative. Outside one it is a number that can change before the
/// caller acts on it.
///
/// A pending admin does not count: it cannot log in, so it is not an
/// administrator anyone can currently rely on, and the last-admin
/// guards that call this must let a pending admin be demoted or deleted
/// freely rather than treating it as the one admin standing between the
/// instance and lockout.
async fn active_admin_count(conn: &mut sqlx::SqliteConnection) -> Result<i64, StoreError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_one(&mut *conn)
            .await?;
    Ok(count)
}

/// Every account, oldest first, without password hashes.
pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserSummary>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, username, role, status, created_at FROM users ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(summary_from_row).collect()
}

/// Outcome of creating an account.
#[derive(Debug, Clone)]
pub enum InsertUserOutcome {
    Created(UserSummary),
    /// The username is already taken. Reported from the UNIQUE
    /// constraint rather than from a prior SELECT, because a check
    /// followed by an insert is a race: two requests for the same name
    /// would both see it free.
    UsernameTaken,
}

/// Creates an **active** account with an already-validated username and
/// an already-computed hash.
///
/// `RETURNING` so the caller sees exactly the stored row rather than a
/// synthesized copy of what was sent. `status` is left to its `DEFAULT
/// 'active'`, since this function always creates an account with a real
/// password; a pending one is [`insert_pending_user_with_invite`].
pub async fn insert_user(
    pool: &SqlitePool,
    username: &Username,
    password_hash: &str,
    role: Role,
    now: UnixTime,
) -> Result<InsertUserOutcome, StoreError> {
    let result = sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         RETURNING id, username, role, status, created_at",
    )
    .bind(new_id())
    .bind(username.as_str())
    .bind(password_hash)
    .bind(role.as_str())
    .bind(now.as_secs())
    .fetch_one(pool)
    .await;

    match result {
        Ok(row) => Ok(InsertUserOutcome::Created(summary_from_row(&row)?)),
        Err(err) => {
            if err
                .as_database_error()
                .is_some_and(DatabaseError::is_unique_violation)
            {
                return Ok(InsertUserOutcome::UsernameTaken);
            }
            Err(err.into())
        }
    }
}

/// Creates a **pending** account together with the one invite that can
/// activate it.
///
/// One `BEGIN IMMEDIATE` transaction so a username that turns out to be
/// taken never leaves an orphaned invite row behind, and so a database
/// error between the two inserts never leaves an account with no way
/// in. `password_hash` is the empty-string sentinel; see migration
/// `0004` for why.
pub async fn insert_pending_user_with_invite(
    pool: &SqlitePool,
    username: &Username,
    role: Role,
    token_hash: &TokenHash,
    now: UnixTime,
    expires_at: UnixTime,
) -> Result<InsertUserOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let result = sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, status, created_at)
         VALUES (?1, ?2, '', ?3, 'pending', ?4)
         RETURNING id, username, role, status, created_at",
    )
    .bind(new_id())
    .bind(username.as_str())
    .bind(role.as_str())
    .bind(now.as_secs())
    .fetch_one(&mut *tx)
    .await;

    let user = match result {
        Ok(row) => summary_from_row(&row)?,
        Err(err) => {
            if err
                .as_database_error()
                .is_some_and(DatabaseError::is_unique_violation)
            {
                tx.rollback().await?;
                return Ok(InsertUserOutcome::UsernameTaken);
            }
            return Err(err.into());
        }
    };

    sqlx::query(
        "INSERT INTO invite_tokens (id, user_id, token_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(new_id())
    .bind(&user.id)
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .bind(expires_at.as_secs())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(InsertUserOutcome::Created(user))
}

/// Outcome of changing an account's role.
#[derive(Debug, Clone)]
pub enum RoleChangeOutcome {
    Changed(UserSummary),
    NotFound,
    /// The target is the only admin left, so demoting it would leave the
    /// instance with nobody who can manage accounts.
    LastAdmin,
}

/// Changes an account's role, refusing to demote the last admin.
///
/// The count and the write are one `BEGIN IMMEDIATE` transaction. That
/// is the whole point of this function: with two separate statements,
/// two admins demoting each other at the same time would both read "two
/// admins exist" and both succeed, leaving zero. Taking SQLite's write
/// lock up front serializes them, so the second one sees one admin left
/// and is refused.
pub async fn set_role_guarded(
    pool: &SqlitePool,
    user_id: &str,
    role: Role,
) -> Result<RoleChangeOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let current: Option<(String, String)> =
        sqlx::query_as("SELECT role, status FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current_role, current_status)) = current else {
        tx.rollback().await?;
        return Ok(RoleChangeOutcome::NotFound);
    };
    let current_role = Role::parse(&current_role).ok_or(StoreError::CorruptRow)?;
    let current_status = AccountStatus::parse(&current_status).ok_or(StoreError::CorruptRow)?;

    // A pending admin is not one anyone can currently rely on - it
    // cannot log in - so it never blocks a demotion, however many
    // active admins remain.
    if current_role.is_admin()
        && current_status == AccountStatus::Active
        && !role.is_admin()
        && active_admin_count(&mut tx).await? <= 1
    {
        tx.rollback().await?;
        return Ok(RoleChangeOutcome::LastAdmin);
    }

    let row = sqlx::query(
        "UPDATE users SET role = ?2 WHERE id = ?1
         RETURNING id, username, role, status, created_at",
    )
    .bind(user_id)
    .bind(role.as_str())
    .fetch_one(&mut *tx)
    .await?;
    let summary = summary_from_row(&row)?;

    tx.commit().await?;
    Ok(RoleChangeOutcome::Changed(summary))
}

/// Outcome of deleting an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteUserOutcome {
    Deleted,
    NotFound,
    /// The target is the only admin left.
    LastAdmin,
}

/// Hard-deletes an account, refusing to delete the last admin.
///
/// Same `BEGIN IMMEDIATE` reasoning as [`set_role_guarded`]. The
/// account's sessions go with it through `ON DELETE CASCADE`, which is
/// why foreign key enforcement is switched on for every connection in
/// [`crate::db::connect`] - without that pragma SQLite would leave the
/// rows behind and the deleted account's cookies would keep working.
pub async fn delete_user_guarded(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<DeleteUserOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let current: Option<(String, String)> =
        sqlx::query_as("SELECT role, status FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current_role, current_status)) = current else {
        tx.rollback().await?;
        return Ok(DeleteUserOutcome::NotFound);
    };
    let current_role = Role::parse(&current_role).ok_or(StoreError::CorruptRow)?;
    let current_status = AccountStatus::parse(&current_status).ok_or(StoreError::CorruptRow)?;

    // Same reasoning as `set_role_guarded`: a pending admin never blocks
    // a deletion.
    if current_role.is_admin()
        && current_status == AccountStatus::Active
        && active_admin_count(&mut tx).await? <= 1
    {
        tx.rollback().await?;
        return Ok(DeleteUserOutcome::LastAdmin);
    }

    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(DeleteUserOutcome::Deleted)
}

/// Outcome of resetting an account to pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetToPendingOutcome {
    Reset {
        /// How many of the account's sessions were ended. All of them:
        /// unlike a self-service password change, there is no session
        /// making this request to spare.
        sessions_ended: u64,
        /// How many of the account's devices were revoked.
        devices_revoked: u64,
    },
    NotFound,
    /// The target is the last remaining **active** admin. A pending
    /// admin never trips this - see [`active_admin_count`].
    LastAdmin,
}

/// Resets an account to pending, handing out a fresh invite in place of
/// whatever password it had.
///
/// One `BEGIN IMMEDIATE` transaction, for the same reason as
/// [`set_role_guarded`] - the last-admin check and the write must not
/// be two separate round trips - plus a reset's extra property: the
/// password, every earlier invite, every session and every device
/// token are replaced or revoked together, so there is no window in
/// which the account is reachable by anything but the invite just
/// issued.
pub async fn reset_to_pending(
    pool: &SqlitePool,
    target_id: &str,
    actor_id: &str,
    token_hash: &TokenHash,
    now: UnixTime,
    expires_at: UnixTime,
) -> Result<ResetToPendingOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let current: Option<(String, String)> =
        sqlx::query_as("SELECT role, status FROM users WHERE id = ?1")
            .bind(target_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current_role, current_status)) = current else {
        tx.rollback().await?;
        return Ok(ResetToPendingOutcome::NotFound);
    };
    let current_role = Role::parse(&current_role).ok_or(StoreError::CorruptRow)?;
    let current_status = AccountStatus::parse(&current_status).ok_or(StoreError::CorruptRow)?;

    if current_role.is_admin()
        && current_status == AccountStatus::Active
        && active_admin_count(&mut tx).await? <= 1
    {
        tx.rollback().await?;
        return Ok(ResetToPendingOutcome::LastAdmin);
    }

    sqlx::query("UPDATE users SET password_hash = '', status = 'pending' WHERE id = ?1")
        .bind(target_id)
        .execute(&mut *tx)
        .await?;

    // Every earlier invite for this account stops working - there is
    // only ever one live invite per account.
    sqlx::query("DELETE FROM invite_tokens WHERE user_id = ?1")
        .bind(target_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO invite_tokens (id, user_id, token_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(new_id())
    .bind(target_id)
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .bind(expires_at.as_secs())
    .execute(&mut *tx)
    .await?;

    let sessions_ended = sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
        .bind(target_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let devices_revoked =
        crate::devices::store::revoke_all_for_user(&mut tx, target_id, now).await?;

    super::account_log::record(
        &mut tx,
        target_id,
        super::account_log::LogKind::PasswordResetByAdmin,
        Some(actor_id),
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(ResetToPendingOutcome::Reset {
        sessions_ended,
        devices_revoked,
    })
}

/// Outcome of redeeming an invite token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemInviteOutcome {
    Redeemed {
        user_id: String,
    },
    /// Unknown, expired, already used, or the account was not pending
    /// by the time the write lock was held. One variant for all of
    /// them: the caller is unauthenticated, and distinguishing these
    /// would say whether a token or an account ever existed.
    Rejected,
}

/// Redeems an invite token, setting the new password and activating the
/// account, atomically.
///
/// The single-use property rests on the `UPDATE ... WHERE used_at IS
/// NULL` below, not on a preceding `SELECT` - the same lesson as
/// `devices::store::redeem_code_and_create_device` - so two concurrent
/// redemptions of the same token can only ever have one of them affect
/// a row.
pub async fn redeem_invite(
    pool: &SqlitePool,
    token_hash: &TokenHash,
    new_password_hash: &str,
    now: UnixTime,
) -> Result<RedeemInviteOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let invite: Option<(String, String)> = sqlx::query_as(
        "UPDATE invite_tokens SET used_at = ?2
         WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2
         RETURNING id, user_id",
    )
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_optional(&mut *tx)
    .await?;

    let Some((invite_id, user_id)) = invite else {
        tx.rollback().await?;
        return Ok(RedeemInviteOutcome::Rejected);
    };

    let updated = sqlx::query(
        "UPDATE users SET password_hash = ?2, status = 'active'
         WHERE id = ?1 AND status = 'pending'",
    )
    .bind(&user_id)
    .bind(new_password_hash)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        // The token was good, but the account was not pending any more
        // (reset again, or somehow already active). Commit, not
        // rollback: the only write so far is the invite's own
        // `used_at`, above, and that one must stick - it named an
        // account state that no longer exists, and nothing issues a
        // second invite from the same row. A rollback here would undo
        // that write too and hand the token back live, which defeats
        // the single-use property this function exists to hold. Add
        // nothing after this point that would need to survive a retry.
        tx.commit().await?;
        return Ok(RedeemInviteOutcome::Rejected);
    }

    sqlx::query("DELETE FROM invite_tokens WHERE user_id = ?1 AND id <> ?2")
        .bind(&user_id)
        .bind(&invite_id)
        .execute(&mut *tx)
        .await?;

    super::account_log::record(
        &mut tx,
        &user_id,
        super::account_log::LogKind::InviteRedeemed,
        None,
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(RedeemInviteOutcome::Redeemed { user_id })
}

/// Whether an invite token is currently redeemable.
///
/// Advisory, like [`setup_token_is_live`]: used to reject a bad token
/// before spending Argon2 work on the new password. [`redeem_invite`]
/// re-checks under the write lock.
pub async fn invite_token_is_live(
    pool: &SqlitePool,
    token_hash: &TokenHash,
    now: UnixTime,
) -> Result<bool, StoreError> {
    let (live,): (i64,) = sqlx::query_as(
        "SELECT EXISTS (
             SELECT 1 FROM invite_tokens
             WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2
         )",
    )
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_one(pool)
    .await?;
    Ok(live != 0)
}

/// Outcome of a password change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordChangeOutcome {
    Changed {
        /// How many of the account's other sessions were ended.
        other_sessions_ended: u64,
    },
    /// The stored hash is no longer the one the caller verified against,
    /// or the account is gone. Either way the change must not be
    /// applied: a second concurrent change has already won, and writing
    /// now would silently undo it.
    Stale,
}

/// Replaces an account's password hash and ends its other sessions.
///
/// Two properties, both from doing this in one `BEGIN IMMEDIATE`
/// transaction:
///
///   * The `UPDATE` is conditional on the hash still being
///     `expected_hash`, so of two parallel changes exactly one is
///     applied and the other is told its view was stale. Without the
///     condition both would succeed and the password would end up being
///     whichever write landed last, while both clients were told their
///     own new password was in effect.
///   * The sessions are deleted in the same transaction, so there is no
///     window in which the new password is live but the old sessions
///     still are.
///
/// `keep_session_id` is the session making the request; it survives, so
/// changing a password does not log out the browser doing it.
pub async fn replace_password_hash_if_unchanged(
    pool: &SqlitePool,
    user_id: &str,
    expected_hash: &str,
    new_hash: &str,
    keep_session_id: &str,
    now: UnixTime,
) -> Result<PasswordChangeOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let updated =
        sqlx::query("UPDATE users SET password_hash = ?2 WHERE id = ?1 AND password_hash = ?3")
            .bind(user_id)
            .bind(new_hash)
            .bind(expected_hash)
            .execute(&mut *tx)
            .await?;

    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(PasswordChangeOutcome::Stale);
    }

    let ended = sqlx::query("DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2")
        .bind(user_id)
        .bind(keep_session_id)
        .execute(&mut *tx)
        .await?;

    super::account_log::record(
        &mut tx,
        user_id,
        super::account_log::LogKind::PasswordChanged,
        None,
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(PasswordChangeOutcome::Changed {
        other_sessions_ended: ended.rows_affected(),
    })
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

/// Removes invite tokens that are expired or already redeemed.
pub async fn delete_stale_invite_tokens(
    pool: &SqlitePool,
    now: UnixTime,
) -> Result<u64, StoreError> {
    let result =
        sqlx::query("DELETE FROM invite_tokens WHERE expires_at <= ?1 OR used_at IS NOT NULL")
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
                u.status        AS status,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::{Token, TokenKind};
    use crate::db::{self, DbTarget};

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    /// Nothing here is a credential: these stand in for PHC strings in
    /// tests that never hash or verify anything. The real hashes come
    /// from Argon2 at the service layer, which has its own tests.
    fn opaque_hash(tag: &str) -> String {
        format!("placeholder-not-a-hash-{tag}")
    }

    fn username(raw: &str) -> Username {
        Username::parse(raw).expect("a valid username")
    }

    async fn memory_pool() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");
        pool
    }

    /// A file-backed database in a fresh temporary directory. The
    /// in-memory pool is capped at one connection, so concurrent callers
    /// would queue on the pool instead of contending for SQLite's write
    /// lock - which is exactly what the race tests need to exercise.
    struct TempDb {
        pool: SqlitePool,
        dir: std::path::PathBuf,
    }

    impl TempDb {
        async fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "screenwarden-store-test-{}-{unique}",
                std::process::id()
            ));
            let pool = db::connect(&DbTarget::File {
                data_dir: dir.clone(),
            })
            .await
            .expect("file pool must connect");
            db::migrate(&pool).await.expect("migrations must apply");
            Self { pool, dir }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    async fn add(pool: &SqlitePool, name: &str, role: Role) -> UserSummary {
        match insert_user(pool, &username(name), &opaque_hash(name), role, now())
            .await
            .expect("inserting must succeed")
        {
            InsertUserOutcome::Created(summary) => summary,
            InsertUserOutcome::UsernameTaken => panic!("{name} must still be free"),
        }
    }

    async fn role_of(pool: &SqlitePool, user_id: &str) -> Option<Role> {
        let stored: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .expect("reading the role must succeed");
        stored.map(|raw| Role::parse(&raw).expect("a known role"))
    }

    async fn admins(pool: &SqlitePool) -> i64 {
        let mut conn = pool.acquire().await.expect("a connection");
        active_admin_count(&mut conn)
            .await
            .expect("counting must succeed")
    }

    #[tokio::test]
    async fn an_inserted_account_is_read_back_as_stored() {
        let pool = memory_pool().await;
        let created = add(&pool, "alice", Role::Admin).await;

        assert_eq!(created.username, username("alice"));
        assert_eq!(created.role, Role::Admin);
        assert_eq!(created.created_at, now());
        assert!(!created.id.is_empty());

        let found = find_user_by_id(&pool, &created.id)
            .await
            .expect("the lookup must succeed")
            .expect("the account must exist");
        assert!(matches!(
            found.credential,
            Credential::Password(hash) if hash == opaque_hash("alice")
        ));
        assert_eq!(found.status, AccountStatus::Active);
    }

    #[tokio::test]
    async fn a_duplicate_username_is_reported_not_inserted() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;

        let outcome = insert_user(
            &pool,
            &username("alice"),
            &opaque_hash("second"),
            Role::User,
            now(),
        )
        .await
        .expect("the insert must not error");

        assert!(matches!(outcome, InsertUserOutcome::UsernameTaken));
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "the second insert must not have landed");
    }

    #[tokio::test]
    async fn the_list_is_oldest_first_and_carries_no_hash() {
        let pool = memory_pool().await;
        let first = add(&pool, "alice", Role::Admin).await;
        let second = insert_user(
            &pool,
            &username("bob"),
            &opaque_hash("bob"),
            Role::User,
            now().saturating_add(std::time::Duration::from_secs(1)),
        )
        .await
        .expect("inserting must succeed");
        let InsertUserOutcome::Created(second) = second else {
            panic!("bob must be free");
        };

        let listed = list_users(&pool).await.expect("listing must succeed");
        let ids: Vec<&str> = listed.iter().map(|user| user.id.as_str()).collect();
        assert_eq!(ids, vec![first.id.as_str(), second.id.as_str()]);

        // The type has no hash field at all; this is the behavioural
        // half, in case the query ever grows one.
        let rendered = format!("{listed:?}");
        assert!(!rendered.contains("placeholder-not-a-hash"));
    }

    #[tokio::test]
    async fn a_role_change_is_applied_and_read_back() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;
        let bob = add(&pool, "bob", Role::User).await;

        let outcome = set_role_guarded(&pool, &bob.id, Role::Admin)
            .await
            .expect("the change must succeed");
        let RoleChangeOutcome::Changed(changed) = outcome else {
            panic!("the change must be applied");
        };
        assert_eq!(changed.role, Role::Admin);
        assert_eq!(role_of(&pool, &bob.id).await, Some(Role::Admin));
    }

    #[tokio::test]
    async fn the_last_admin_can_be_neither_demoted_nor_deleted() {
        let pool = memory_pool().await;
        let alice = add(&pool, "alice", Role::Admin).await;
        add(&pool, "bob", Role::User).await;

        assert!(matches!(
            set_role_guarded(&pool, &alice.id, Role::User)
                .await
                .unwrap(),
            RoleChangeOutcome::LastAdmin
        ));
        assert_eq!(role_of(&pool, &alice.id).await, Some(Role::Admin));

        assert_eq!(
            delete_user_guarded(&pool, &alice.id).await.unwrap(),
            DeleteUserOutcome::LastAdmin
        );
        assert_eq!(role_of(&pool, &alice.id).await, Some(Role::Admin));
    }

    #[tokio::test]
    async fn an_admin_may_be_demoted_while_another_admin_remains() {
        let pool = memory_pool().await;
        let alice = add(&pool, "alice", Role::Admin).await;
        add(&pool, "bob", Role::Admin).await;

        assert!(matches!(
            set_role_guarded(&pool, &alice.id, Role::User)
                .await
                .unwrap(),
            RoleChangeOutcome::Changed(_)
        ));
        assert_eq!(role_of(&pool, &alice.id).await, Some(Role::User));
        assert_eq!(admins(&pool).await, 1);
    }

    #[tokio::test]
    async fn an_unknown_id_is_reported_as_not_found() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;
        let missing = new_id();

        assert!(matches!(
            set_role_guarded(&pool, &missing, Role::Admin)
                .await
                .unwrap(),
            RoleChangeOutcome::NotFound
        ));
        assert_eq!(
            delete_user_guarded(&pool, &missing).await.unwrap(),
            DeleteUserOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn deleting_an_account_takes_its_sessions_with_it() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;
        let bob = add(&pool, "bob", Role::User).await;

        let token = Token::generate(TokenKind::Session).expect("the CSPRNG must be available");
        let session = SessionRecord {
            id: new_id(),
            user_id: bob.id.clone(),
            created_at: now(),
            last_used_at: now(),
            expires_at: now().saturating_add(std::time::Duration::from_secs(3_600)),
        };
        insert_session(&pool, &session, &token.hash())
            .await
            .expect("inserting the session must succeed");
        assert_eq!(count_sessions_for_user(&pool, &bob.id).await.unwrap(), 1);

        assert_eq!(
            delete_user_guarded(&pool, &bob.id).await.unwrap(),
            DeleteUserOutcome::Deleted
        );
        assert_eq!(count_sessions_for_user(&pool, &bob.id).await.unwrap(), 0);
        assert!(
            find_session_with_user(&pool, &token.hash())
                .await
                .unwrap()
                .is_none(),
            "the deleted account's session token must resolve to nothing"
        );
    }

    /// Sets up one account with two sessions and returns both session
    /// ids, the second being the one a request would be made with.
    async fn user_with_two_sessions(pool: &SqlitePool) -> (UserSummary, String, String) {
        let user = add(pool, "bob", Role::User).await;
        let mut ids = Vec::new();
        for _ in 0..2 {
            let token = Token::generate(TokenKind::Session).expect("the CSPRNG must be available");
            let session = SessionRecord {
                id: new_id(),
                user_id: user.id.clone(),
                created_at: now(),
                last_used_at: now(),
                expires_at: now().saturating_add(std::time::Duration::from_secs(3_600)),
            };
            insert_session(pool, &session, &token.hash())
                .await
                .expect("inserting the session must succeed");
            ids.push(session.id);
        }
        (user, ids[0].clone(), ids[1].clone())
    }

    #[tokio::test]
    async fn a_password_change_keeps_the_current_session_and_ends_the_others() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;
        let (user, other, current) = user_with_two_sessions(&pool).await;

        let outcome = replace_password_hash_if_unchanged(
            &pool,
            &user.id,
            &opaque_hash("bob"),
            &opaque_hash("bob-next"),
            &current,
            now(),
        )
        .await
        .expect("the change must succeed");

        assert_eq!(
            outcome,
            PasswordChangeOutcome::Changed {
                other_sessions_ended: 1
            }
        );
        let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?1")
            .bind(&user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, opaque_hash("bob-next"));

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM sessions WHERE user_id = ?1")
                .bind(&user.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, vec![current]);
        assert!(!remaining.contains(&other));
    }

    #[tokio::test]
    async fn a_password_change_against_a_stale_hash_changes_nothing() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::Admin).await;
        let (user, _other, current) = user_with_two_sessions(&pool).await;

        let outcome = replace_password_hash_if_unchanged(
            &pool,
            &user.id,
            &opaque_hash("not-what-is-stored"),
            &opaque_hash("bob-next"),
            &current,
            now(),
        )
        .await
        .expect("the attempt must not error");

        assert_eq!(outcome, PasswordChangeOutcome::Stale);
        let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?1")
            .bind(&user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, opaque_hash("bob"), "the hash must be untouched");
        assert_eq!(
            count_sessions_for_user(&pool, &user.id).await.unwrap(),
            2,
            "a refused change must not end any session"
        );
    }

    /// Two parallel changes, both verified against the same stored hash:
    /// exactly one may be applied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_parallel_password_changes_cannot_both_win() {
        let db = TempDb::new().await;
        add(&db.pool, "alice", Role::Admin).await;
        let (user, first_session, second_session) = user_with_two_sessions(&db.pool).await;
        let stored_hash = opaque_hash("bob");
        let left_hash = opaque_hash("bob-left");
        let right_hash = opaque_hash("bob-right");

        let (left, right) = tokio::join!(
            replace_password_hash_if_unchanged(
                &db.pool,
                &user.id,
                &stored_hash,
                &left_hash,
                &first_session,
                now(),
            ),
            replace_password_hash_if_unchanged(
                &db.pool,
                &user.id,
                &stored_hash,
                &right_hash,
                &second_session,
                now(),
            )
        );

        let outcomes = [left.expect("no error"), right.expect("no error")];
        let applied = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PasswordChangeOutcome::Changed { .. }))
            .count();
        assert_eq!(
            applied, 1,
            "exactly one change may be applied: {outcomes:?}"
        );

        let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?1")
            .bind(&user.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert!(
            stored == opaque_hash("bob-left") || stored == opaque_hash("bob-right"),
            "the stored hash must be one of the two new ones"
        );
    }

    /// The property the `BEGIN IMMEDIATE` transactions exist for: two
    /// admins acting at the same time cannot leave the instance with
    /// none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_admins_cannot_demote_each_other_at_the_same_time() {
        let db = TempDb::new().await;
        let alice = add(&db.pool, "alice", Role::Admin).await;
        let bob = add(&db.pool, "bob", Role::Admin).await;

        let (left, right) = tokio::join!(
            set_role_guarded(&db.pool, &bob.id, Role::User),
            set_role_guarded(&db.pool, &alice.id, Role::User)
        );

        let outcomes = [left.expect("no error"), right.expect("no error")];
        let demoted = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RoleChangeOutcome::Changed(_)))
            .count();
        assert!(
            demoted <= 1,
            "at most one demotion may be applied: {outcomes:?}"
        );
        assert_eq!(admins(&db.pool).await, 1, "one admin must remain");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_admins_cannot_delete_each_other_at_the_same_time() {
        let db = TempDb::new().await;
        let alice = add(&db.pool, "alice", Role::Admin).await;
        let bob = add(&db.pool, "bob", Role::Admin).await;

        let (left, right) = tokio::join!(
            delete_user_guarded(&db.pool, &bob.id),
            delete_user_guarded(&db.pool, &alice.id)
        );

        let outcomes = [left.expect("no error"), right.expect("no error")];
        let deleted = outcomes
            .iter()
            .filter(|outcome| **outcome == DeleteUserOutcome::Deleted)
            .count();
        assert!(deleted <= 1, "at most one deletion may land: {outcomes:?}");
        assert_eq!(admins(&db.pool).await, 1, "one admin must remain");
    }

    // --- invites and account resets -----------------------------------

    fn invite_token() -> Token {
        Token::generate(TokenKind::Invite).expect("the OS CSPRNG must be available")
    }

    fn one_hour_from(at: UnixTime) -> UnixTime {
        at.saturating_add(std::time::Duration::from_secs(3_600))
    }

    #[tokio::test]
    async fn a_pending_account_is_created_with_its_invite() {
        let pool = memory_pool().await;
        let token = invite_token();

        let outcome = insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::Admin,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .expect("inserting must succeed");
        let InsertUserOutcome::Created(user) = outcome else {
            panic!("alice must be free");
        };
        assert_eq!(user.status, AccountStatus::Pending);

        let found = find_user_by_id(&pool, &user.id).await.unwrap().unwrap();
        assert!(matches!(found.credential, Credential::Pending));

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM invite_tokens WHERE user_id = ?1")
                .bind(&user.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn a_pending_account_with_a_taken_username_leaves_no_invite_behind() {
        let pool = memory_pool().await;
        add(&pool, "alice", Role::User).await;
        let token = invite_token();

        let outcome = insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .expect("must not error");
        assert!(matches!(outcome, InsertUserOutcome::UsernameTaken));

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "no orphaned invite may exist");
    }

    #[tokio::test]
    async fn resetting_an_account_ends_its_sessions_and_revokes_its_devices() {
        let pool = memory_pool().await;
        add(&pool, "admin", Role::Admin).await;
        let bob = add(&pool, "bob", Role::User).await;

        let session_token = Token::generate(TokenKind::Session).unwrap();
        insert_session(
            &pool,
            &SessionRecord {
                id: new_id(),
                user_id: bob.id.clone(),
                created_at: now(),
                last_used_at: now(),
                expires_at: one_hour_from(now()),
            },
            &session_token.hash(),
        )
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO devices (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES (?1, ?2, 'phone', 'android', ?3, ?4, ?4)",
        )
        .bind(new_id())
        .bind(&bob.id)
        .bind(Token::generate(TokenKind::Device).unwrap().hash().as_bytes())
        .bind(now().as_secs())
        .execute(&pool)
        .await
        .unwrap();

        let token = invite_token();
        let outcome = reset_to_pending(
            &pool,
            &bob.id,
            "admin-id",
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .expect("reset must succeed");

        assert_eq!(
            outcome,
            ResetToPendingOutcome::Reset {
                sessions_ended: 1,
                devices_revoked: 1,
            }
        );

        let found = find_user_by_id(&pool, &bob.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Pending);
        assert!(matches!(found.credential, Credential::Pending));
        assert_eq!(count_sessions_for_user(&pool, &bob.id).await.unwrap(), 0);

        let (revoked,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND revoked_at IS NOT NULL",
        )
        .bind(&bob.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(revoked, 1);

        let logs = crate::auth::account_log::list_for_user(&pool, &bob.id)
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].kind,
            crate::auth::account_log::LogKind::PasswordResetByAdmin
        );
        assert_eq!(logs[0].actor_id.as_deref(), Some("admin-id"));
    }

    #[tokio::test]
    async fn resetting_the_last_active_admin_is_refused() {
        let pool = memory_pool().await;
        let alice = add(&pool, "alice", Role::Admin).await;
        let token = invite_token();

        let outcome = reset_to_pending(
            &pool,
            &alice.id,
            "someone",
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ResetToPendingOutcome::LastAdmin);
        assert_eq!(role_of(&pool, &alice.id).await, Some(Role::Admin));
    }

    /// A pending admin is not an administrator anyone can currently rely
    /// on - it cannot log in - so resetting it must never be blocked by
    /// the last-admin guard, however many active admins remain (here,
    /// zero).
    #[tokio::test]
    async fn resetting_a_pending_admin_never_trips_the_last_admin_guard() {
        let pool = memory_pool().await;
        let token = invite_token();
        let outcome = insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::Admin,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        let InsertUserOutcome::Created(alice) = outcome else {
            panic!("alice must be free");
        };

        let reset_token = invite_token();
        let outcome = reset_to_pending(
            &pool,
            &alice.id,
            "someone",
            &reset_token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ResetToPendingOutcome::Reset { .. }));
    }

    #[tokio::test]
    async fn resetting_an_unknown_account_is_not_found() {
        let pool = memory_pool().await;
        let token = invite_token();
        let outcome = reset_to_pending(
            &pool,
            &new_id(),
            "someone",
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ResetToPendingOutcome::NotFound);
    }

    #[tokio::test]
    async fn redeeming_an_invite_activates_the_account() {
        let pool = memory_pool().await;
        let token = invite_token();
        let outcome = insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        let InsertUserOutcome::Created(alice) = outcome else {
            panic!("alice must be free");
        };

        let outcome = redeem_invite(&pool, &token.hash(), &opaque_hash("new"), now())
            .await
            .expect("redeeming must succeed");
        assert_eq!(
            outcome,
            RedeemInviteOutcome::Redeemed {
                user_id: alice.id.clone()
            }
        );

        let found = find_user_by_id(&pool, &alice.id).await.unwrap().unwrap();
        assert_eq!(found.status, AccountStatus::Active);
        assert!(matches!(
            found.credential,
            Credential::Password(hash) if hash == opaque_hash("new")
        ));

        // The spent invite row itself stays (its `used_at` now set, so
        // it can never redeem again) - only every *other* invite for
        // the account would have been cleared here.
        let (remaining,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM invite_tokens WHERE used_at IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 1, "the spent invite stays, marked used");

        let logs = crate::auth::account_log::list_for_user(&pool, &alice.id)
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].kind,
            crate::auth::account_log::LogKind::InviteRedeemed
        );
        assert_eq!(logs[0].actor_id, None);
    }

    #[tokio::test]
    async fn redeeming_twice_only_succeeds_once() {
        let pool = memory_pool().await;
        let token = invite_token();
        insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();

        let first = redeem_invite(&pool, &token.hash(), &opaque_hash("one"), now())
            .await
            .unwrap();
        let second = redeem_invite(&pool, &token.hash(), &opaque_hash("two"), now())
            .await
            .unwrap();

        assert!(matches!(first, RedeemInviteOutcome::Redeemed { .. }));
        assert_eq!(second, RedeemInviteOutcome::Rejected);
    }

    #[tokio::test]
    async fn an_expired_invite_is_rejected() {
        let pool = memory_pool().await;
        let token = invite_token();
        insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            now().saturating_add(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

        let after_expiry = now().saturating_add(std::time::Duration::from_secs(61));
        let outcome = redeem_invite(&pool, &token.hash(), &opaque_hash("new"), after_expiry)
            .await
            .unwrap();
        assert_eq!(outcome, RedeemInviteOutcome::Rejected);
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected() {
        let pool = memory_pool().await;
        let token = invite_token();
        let outcome = redeem_invite(&pool, &token.hash(), &opaque_hash("new"), now())
            .await
            .unwrap();
        assert_eq!(outcome, RedeemInviteOutcome::Rejected);
    }

    /// A live, unexpired invite whose account is no longer `pending` by
    /// the time the write lock is held must leave its token spent
    /// forever, not merely refuse once. Pins the fix for a bug where
    /// `tx.rollback()` in this branch undid the token's own `used_at`
    /// write, handing it back live.
    ///
    /// There is no production path that reaches this state today - a
    /// reset always clears the account's invite rows first - so it is
    /// manufactured directly, the same way `redeeming_an_invite_...`
    /// above reaches into the row to check `used_at` rather than going
    /// through a second API.
    #[tokio::test]
    async fn redeeming_against_an_account_no_longer_pending_leaves_the_token_spent() {
        let pool = memory_pool().await;
        let token = invite_token();
        let outcome = insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();
        let InsertUserOutcome::Created(alice) = outcome else {
            panic!("alice must be free");
        };

        sqlx::query("UPDATE users SET status = 'active' WHERE id = ?1")
            .bind(&alice.id)
            .execute(&pool)
            .await
            .unwrap();

        let outcome = redeem_invite(&pool, &token.hash(), &opaque_hash("new"), now())
            .await
            .unwrap();
        assert_eq!(outcome, RedeemInviteOutcome::Rejected);

        // Even if the account becomes pending again, the same token
        // must never redeem: `used_at` has to have survived, which is
        // exactly what a rollback here would have undone.
        sqlx::query("UPDATE users SET status = 'pending', password_hash = '' WHERE id = ?1")
            .bind(&alice.id)
            .execute(&pool)
            .await
            .unwrap();
        let second = redeem_invite(&pool, &token.hash(), &opaque_hash("new-2"), now())
            .await
            .unwrap();
        assert_eq!(
            second,
            RedeemInviteOutcome::Rejected,
            "a rejected redemption must leave the token spent, never live again"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_concurrent_redemptions_of_one_token_yield_exactly_one_winner() {
        let db = TempDb::new().await;
        let token = invite_token();
        insert_pending_user_with_invite(
            &db.pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            one_hour_from(now()),
        )
        .await
        .unwrap();

        let left_hash = opaque_hash("left");
        let right_hash = opaque_hash("right");
        let token_hash = token.hash();
        let (left, right) = tokio::join!(
            redeem_invite(&db.pool, &token_hash, &left_hash, now()),
            redeem_invite(&db.pool, &token_hash, &right_hash, now())
        );

        let outcomes = [left.unwrap(), right.unwrap()];
        let redeemed = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RedeemInviteOutcome::Redeemed { .. }))
            .count();
        assert_eq!(redeemed, 1, "exactly one redemption may land: {outcomes:?}");
    }

    #[tokio::test]
    async fn invite_liveness_follows_expiry_and_use() {
        let pool = memory_pool().await;
        let token = invite_token();
        insert_pending_user_with_invite(
            &pool,
            &username("alice"),
            Role::User,
            &token.hash(),
            now(),
            now().saturating_add(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

        assert!(invite_token_is_live(&pool, &token.hash(), now())
            .await
            .unwrap());
        assert!(!invite_token_is_live(
            &pool,
            &token.hash(),
            now().saturating_add(std::time::Duration::from_secs(61))
        )
        .await
        .unwrap());

        redeem_invite(&pool, &token.hash(), &opaque_hash("new"), now())
            .await
            .unwrap();
        assert!(!invite_token_is_live(&pool, &token.hash(), now())
            .await
            .unwrap());
    }
}
