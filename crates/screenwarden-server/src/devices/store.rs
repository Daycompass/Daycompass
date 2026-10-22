//! Every SQL statement the device service layer runs.
//!
//! Same arrangement as [`crate::auth::store`]: the queries live here so
//! the service modules stay readable and there is one file to audit.
//! All statements use bound parameters; no value is ever formatted into
//! SQL. Rows are validated on the way out - a platform or a name that
//! does not satisfy today's policy is [`StoreError::CorruptRow`] rather
//! than something guessed at.
//!
//! **No statement in this file may mention the `events` table.** An
//! admin manages devices and must never reach event data, and M2 has no
//! event read path for anyone. `tests/no_event_reads.rs` checks the
//! sources for that rather than trusting it to be remembered.
//!
//! Three operations take `BEGIN IMMEDIATE`, and each one is a
//! check-then-write that would be a race without it:
//!
//!   * [`insert_pairing_code_guarded`] - count live codes, then insert.
//!   * [`redeem_code_and_create_device`] - find the code, count the
//!     owner's devices, mark it used, create the device.
//!   * [`revoke_device`] - find the device, then revoke it.

use sqlx::{Row, SqlitePool};

use super::code::PairingCodeHash;
use super::name::DeviceName;
use super::platform::Platform;
use crate::auth::store::{new_id, StoreError};
use crate::auth::time::UnixTime;
use crate::auth::token::TokenHash;

/// A row from `devices`.
///
/// Deliberately carries no token and no event data: the token exists
/// only as a hash in the database, and events are not this module's
/// business at all.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: String,
    pub user_id: String,
    pub name: DeviceName,
    pub platform: Platform,
    pub created_at: UnixTime,
    pub last_seen_at: UnixTime,
    /// `None` while the device is live.
    pub revoked_at: Option<UnixTime>,
}

impl DeviceRecord {
    /// Whether this device may still authenticate.
    ///
    /// Read from the row resolved for the current request, never
    /// cached, so a revocation takes effect on the device's very next
    /// call rather than when something expires.
    pub fn is_live(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// A device plus who owns it, for the admin listing.
///
/// A separate type from [`DeviceRecord`] rather than an option on it,
/// for the same reason [`crate::auth::store::UserSummary`] is separate
/// from `UserRecord`: the owner's name is something only the admin
/// listing selects, so no other query has a field for it to leak out
/// of.
#[derive(Debug, Clone)]
pub struct DeviceWithOwner {
    pub device: DeviceRecord,
    pub owner_username: String,
}

fn device_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<DeviceRecord, StoreError> {
    let id: String = row.try_get("id")?;
    let user_id: String = row.try_get("user_id")?;
    let name: String = row.try_get("name")?;
    let platform: String = row.try_get("platform")?;
    let created_at: i64 = row.try_get("created_at")?;
    let last_seen_at: i64 = row.try_get("last_seen_at")?;
    let revoked_at: Option<i64> = row.try_get("revoked_at")?;

    Ok(DeviceRecord {
        id,
        user_id,
        // Stored names have already been through the policy, so this
        // must succeed; if it does not, the row was written by
        // something that bypassed it.
        name: DeviceName::parse(&name).map_err(|_| StoreError::CorruptRow)?,
        platform: Platform::parse(&platform).ok_or(StoreError::CorruptRow)?,
        created_at: UnixTime::from_secs(created_at),
        last_seen_at: UnixTime::from_secs(last_seen_at),
        revoked_at: revoked_at.map(UnixTime::from_secs),
    })
}

// --- pairing codes ----------------------------------------------------

/// Outcome of creating a pairing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewCodeOutcome {
    Created,
    /// The owner already has the maximum number of live codes.
    TooManyActive,
}

/// Stores a new pairing code for `user_id`, capped at `max_active` live
/// codes.
///
/// The count and the insert are one transaction, or two parallel
/// requests would both see room and both insert.
///
/// The owner's spent and expired codes are deleted in the same
/// transaction. The cap bounds how many codes are *live* at once, but
/// on its own it would let somebody create a code, wait ten minutes,
/// and repeat - growing the table without ever exceeding the cap. The
/// hourly sweep would eventually collect those; deleting them here
/// bounds one owner's rows to the cap plus whatever expired since they
/// last asked, without waiting for it.
pub async fn insert_pairing_code_guarded(
    pool: &SqlitePool,
    user_id: &str,
    code_hash: &PairingCodeHash,
    now: UnixTime,
    expires_at: UnixTime,
    max_active: usize,
) -> Result<NewCodeOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    sqlx::query(
        "DELETE FROM pairing_codes
         WHERE user_id = ?1 AND (expires_at <= ?2 OR used_at IS NOT NULL)",
    )
    .bind(user_id)
    .bind(now.as_secs())
    .execute(&mut *tx)
    .await?;

    let (active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pairing_codes
         WHERE user_id = ?1 AND used_at IS NULL AND expires_at > ?2",
    )
    .bind(user_id)
    .bind(now.as_secs())
    .fetch_one(&mut *tx)
    .await?;

    if active >= i64::try_from(max_active).unwrap_or(i64::MAX) {
        tx.rollback().await?;
        return Ok(NewCodeOutcome::TooManyActive);
    }

    sqlx::query(
        "INSERT INTO pairing_codes (id, user_id, code_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(code_hash.as_bytes())
    .bind(now.as_secs())
    .bind(expires_at.as_secs())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(NewCodeOutcome::Created)
}

/// Removes pairing codes that are expired or already redeemed.
///
/// The instance-wide counterpart to the per-owner delete inside
/// [`insert_pairing_code_guarded`], run by the background sweep so that
/// codes belonging to someone who never comes back are collected too.
pub async fn delete_stale_pairing_codes(
    pool: &SqlitePool,
    now: UnixTime,
) -> Result<u64, StoreError> {
    let result =
        sqlx::query("DELETE FROM pairing_codes WHERE expires_at <= ?1 OR used_at IS NOT NULL")
            .bind(now.as_secs())
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

// --- pairing ----------------------------------------------------------

/// Outcome of redeeming a pairing code.
#[derive(Debug, Clone)]
pub enum RedeemOutcome {
    Paired(DeviceRecord),
    /// The code was unknown, expired, or already redeemed. One variant
    /// for all three: the caller is unauthenticated, and telling them
    /// which it was would say whether a code ever existed.
    CodeRejected,
    /// The code was good, but its owner is already at the device cap.
    /// Distinguishable from the above on purpose - it is only reachable
    /// with a valid code, so it is not an oracle, and the person
    /// pairing needs to know why it failed.
    DeviceLimitReached,
}

/// Redeems a code and creates the device it pairs, atomically.
///
/// `BEGIN IMMEDIATE` takes SQLite's write lock up front, so two clients
/// racing with the same code are serialized: the second one finds
/// `used_at` already set and is refused. Exactly one device results.
///
/// The order inside the transaction matters. The device cap is checked
/// *before* the code is marked used, and hitting it rolls the whole
/// transaction back - so a refused pairing leaves the code unspent and
/// the person can revoke an old device and try the same code again.
///
/// Only live devices count towards the cap. Counting revoked ones would
/// let somebody who had cycled through twenty devices lock themselves
/// out permanently, with no way back that does not involve an admin.
pub async fn redeem_code_and_create_device(
    pool: &SqlitePool,
    code_hash: &PairingCodeHash,
    name: &DeviceName,
    platform: Platform,
    token_hash: &TokenHash,
    now: UnixTime,
    max_devices: usize,
) -> Result<RedeemOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let found: Option<(String, String)> = sqlx::query_as(
        "SELECT id, user_id FROM pairing_codes
         WHERE code_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
    )
    .bind(code_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_optional(&mut *tx)
    .await?;

    let Some((code_id, user_id)) = found else {
        tx.rollback().await?;
        return Ok(RedeemOutcome::CodeRejected);
    };

    let (live_devices,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND revoked_at IS NULL")
            .bind(&user_id)
            .fetch_one(&mut *tx)
            .await?;

    if live_devices >= i64::try_from(max_devices).unwrap_or(i64::MAX) {
        // Nothing has been written yet, so the code survives this.
        tx.rollback().await?;
        return Ok(RedeemOutcome::DeviceLimitReached);
    }

    // `AND used_at IS NULL` repeats what the SELECT above already
    // established. That is the point: the SELECT's guarantee holds
    // only because `BEGIN IMMEDIATE` has the write lock, so without
    // this condition the whole single-use property would rest on the
    // transaction mode and nothing else. With it, a deferred
    // transaction - or any future change to how this is opened -
    // fails loudly here instead of redeeming a code twice.
    let marked =
        sqlx::query("UPDATE pairing_codes SET used_at = ?2 WHERE id = ?1 AND used_at IS NULL")
            .bind(&code_id)
            .bind(now.as_secs())
            .execute(&mut *tx)
            .await?;

    if marked.rows_affected() != 1 {
        // Somebody else spent it between the SELECT and here, which
        // the write lock should make impossible. Treated as the
        // ordinary refusal rather than an error: the caller's code is
        // in fact no longer redeemable, and that is all they may
        // learn.
        tracing::warn!(
            "a pairing code was spent between its lookup and its update; \
             the redemption transaction is not holding the write lock"
        );
        tx.rollback().await?;
        return Ok(RedeemOutcome::CodeRejected);
    }

    let row = sqlx::query(
        "INSERT INTO devices
             (id, user_id, name, platform, token_hash, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         RETURNING id, user_id, name, platform, created_at, last_seen_at, revoked_at",
    )
    .bind(new_id())
    .bind(&user_id)
    .bind(name.as_str())
    .bind(platform.as_str())
    .bind(token_hash.as_bytes())
    .bind(now.as_secs())
    .fetch_one(&mut *tx)
    .await?;
    let device = device_from_row(&row)?;

    tx.commit().await?;
    Ok(RedeemOutcome::Paired(device))
}

// --- device authentication -------------------------------------------

/// Looks a **live** device up by the hash of its token.
///
/// A revoked device is not returned, and the name says so: this is
/// the query device authentication runs, and the one place where
/// getting revocation wrong would mean a revoked token still works.
///
/// `revoked_at IS NULL` is in the `WHERE` rather than left to the
/// caller. An earlier version returned revoked rows and relied on
/// [`crate::auth::device::resolve`] to filter them, which was correct
/// but fragile: a second caller that forgot the check would
/// authenticate a revoked device, and nothing would have failed. The
/// Rust check stays as a second line - see `resolve` - so the two
/// have to agree for a revoked device to get through.
pub async fn find_live_device_by_token_hash(
    pool: &SqlitePool,
    token_hash: &TokenHash,
) -> Result<Option<DeviceRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT id, user_id, name, platform, created_at, last_seen_at, revoked_at
         FROM devices WHERE token_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(token_hash.as_bytes())
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(device_from_row).transpose()
}

/// Records that a device was just seen.
pub async fn touch_device(
    pool: &SqlitePool,
    device_id: &str,
    now: UnixTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE devices SET last_seen_at = ?2 WHERE id = ?1")
        .bind(device_id)
        .bind(now.as_secs())
        .execute(pool)
        .await?;
    Ok(())
}

/// Revokes every live device belonging to `user_id`, inside a
/// transaction the caller already holds the write lock for. Returns how
/// many were revoked.
///
/// Takes a connection rather than the pool, like the private
/// `active_admin_count` helper in `crate::auth::store`, so the SQL for
/// this table stays here while still running inside the caller's own
/// transaction. Used by an admin password reset, which must end a
/// target's device tokens in the same transaction as the account
/// reset, because otherwise a device could still authenticate in the
/// window between the two writes.
pub async fn revoke_all_for_user(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    now: UnixTime,
) -> Result<u64, StoreError> {
    let result =
        sqlx::query("UPDATE devices SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL")
            .bind(user_id)
            .bind(now.as_secs())
            .execute(&mut *conn)
            .await?;
    Ok(result.rows_affected())
}

// --- device management ------------------------------------------------

/// One owner's devices, oldest first. Revoked ones are included, so the
/// owner can see what they revoked.
pub async fn list_devices_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<DeviceRecord>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, user_id, name, platform, created_at, last_seen_at, revoked_at
         FROM devices WHERE user_id = ?1 ORDER BY created_at, id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(device_from_row).collect()
}

/// Every device on the instance, with its owner's username, for an
/// admin.
///
/// Metadata only. The join is to `users`, and there is deliberately no
/// second join anywhere in this function - an admin may see that a
/// device exists and who owns it, never what it reported.
pub async fn list_all_devices(pool: &SqlitePool) -> Result<Vec<DeviceWithOwner>, StoreError> {
    let rows = sqlx::query(
        "SELECT d.id           AS id,
                d.user_id      AS user_id,
                d.name         AS name,
                d.platform     AS platform,
                d.created_at   AS created_at,
                d.last_seen_at AS last_seen_at,
                d.revoked_at   AS revoked_at,
                u.username     AS owner_username
         FROM devices d
         JOIN users u ON u.id = d.user_id
         ORDER BY d.created_at, d.id",
    )
    .fetch_all(pool)
    .await?;

    rows.iter()
        .map(|row| {
            Ok(DeviceWithOwner {
                device: device_from_row(row)?,
                owner_username: row.try_get("owner_username")?,
            })
        })
        .collect()
}

/// Which devices an operation is allowed to touch.
///
/// Passed explicitly rather than inferred, so a handler cannot reach
/// another owner's device by forgetting an argument: the owner-scoped
/// variant carries the id the request was authenticated as.
#[derive(Debug, Clone, Copy)]
pub enum Scope<'a> {
    /// Only devices belonging to this account.
    Owner(&'a str),
    /// Any device. Only ever constructed from an admin route.
    AnyDevice,
}

/// Renames a device, returning the updated row.
///
/// `None` covers both "no such device" and "that device is somebody
/// else's" when the scope is an owner. Distinguishing them would turn
/// this endpoint into an oracle for which device ids exist on the
/// instance.
pub async fn rename_device(
    pool: &SqlitePool,
    scope: Scope<'_>,
    device_id: &str,
    name: &DeviceName,
) -> Result<Option<DeviceRecord>, StoreError> {
    let row = match scope {
        Scope::Owner(user_id) => {
            sqlx::query(
                "UPDATE devices SET name = ?3 WHERE id = ?1 AND user_id = ?2
                 RETURNING id, user_id, name, platform, created_at, last_seen_at, revoked_at",
            )
            .bind(device_id)
            .bind(user_id)
            .bind(name.as_str())
            .fetch_optional(pool)
            .await?
        }
        Scope::AnyDevice => {
            sqlx::query(
                "UPDATE devices SET name = ?2 WHERE id = ?1
                 RETURNING id, user_id, name, platform, created_at, last_seen_at, revoked_at",
            )
            .bind(device_id)
            .bind(name.as_str())
            .fetch_optional(pool)
            .await?
        }
    };

    row.as_ref().map(device_from_row).transpose()
}

/// Outcome of revoking a device.
#[derive(Debug, Clone)]
pub enum RevokeOutcome {
    Revoked(DeviceRecord),
    /// Already revoked. Reported separately so the caller can answer
    /// idempotently rather than pretending it just happened.
    AlreadyRevoked(DeviceRecord),
    /// No such device, or not one this scope may touch.
    NotFound,
}

/// Revokes a device, keeping the row and every event it reported.
///
/// One `BEGIN IMMEDIATE` transaction: without it, two parallel
/// revocations would both read "live" and the second would overwrite
/// the first one's timestamp, so the recorded moment of revocation
/// would be the later of two races rather than the first one that
/// actually took effect.
///
/// There is deliberately no `DELETE` counterpart. Revocation must not
/// destroy data: the events stay, and so does the row that says which
/// device reported them.
pub async fn revoke_device(
    pool: &SqlitePool,
    scope: Scope<'_>,
    device_id: &str,
    now: UnixTime,
) -> Result<RevokeOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let existing = match scope {
        Scope::Owner(user_id) => {
            sqlx::query(
                "SELECT id, user_id, name, platform, created_at, last_seen_at, revoked_at
                 FROM devices WHERE id = ?1 AND user_id = ?2",
            )
            .bind(device_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        }
        Scope::AnyDevice => {
            sqlx::query(
                "SELECT id, user_id, name, platform, created_at, last_seen_at, revoked_at
                 FROM devices WHERE id = ?1",
            )
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?
        }
    };

    let Some(existing) = existing else {
        tx.rollback().await?;
        return Ok(RevokeOutcome::NotFound);
    };
    let existing = device_from_row(&existing)?;

    if !existing.is_live() {
        tx.rollback().await?;
        return Ok(RevokeOutcome::AlreadyRevoked(existing));
    }

    let row = sqlx::query(
        "UPDATE devices SET revoked_at = ?2 WHERE id = ?1
         RETURNING id, user_id, name, platform, created_at, last_seen_at, revoked_at",
    )
    .bind(device_id)
    .bind(now.as_secs())
    .fetch_one(&mut *tx)
    .await?;
    let device = device_from_row(&row)?;

    tx.commit().await?;
    Ok(RevokeOutcome::Revoked(device))
}
