//! Pairing a device, and managing the ones that exist.
//!
//! The service layer: handlers call these, and so will the dashboard.
//! Nothing here knows about axum.
//!
//! # The order of work in a pairing
//!
//! 1. The device name and platform are validated. This happens
//!    **before** the code is looked at, for two reasons: a malformed
//!    request costs no database query, and the answer leaks nothing,
//!    because whether a name is well formed is independent of whether
//!    a code exists.
//! 2. The presented code is normalized and hashed. A code that cannot
//!    be one at all is refused here, so arbitrary client input never
//!    becomes a lookup - the same rule tokens follow.
//! 3. A device token is generated. It is minted before the transaction
//!    because the CSPRNG must not be called while holding SQLite's
//!    write lock, and a token that is never committed is simply
//!    discarded.
//! 4. [`store::redeem_code_and_create_device`] does the rest in one
//!    `BEGIN IMMEDIATE` transaction.
//!
//! # What the caller is told
//!
//! An unknown, expired and already-redeemed code produce one identical
//! error. The device cap produces a different one, which is safe
//! because reaching it requires a valid code in the first place.
//!
//! The token is returned exactly once, in the response that completes
//! the pairing. The server keeps only its hash and cannot show it
//! again.

use std::time::Duration;

use sqlx::SqlitePool;

use super::code::PairingCode;
use super::name::{DeviceName, DeviceNameError};
use super::platform::Platform;
use super::store::{self, DeviceRecord, DeviceWithOwner, NewCodeOutcome, RedeemOutcome, Scope};
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;
use crate::auth::token::{RngUnavailable, Token, TokenKind};

/// How long a pairing code stays redeemable.
///
/// Ten minutes. This is not a convenience setting: the code is only
/// ~50 bits, and its short life is what makes a leaked hash not worth
/// cracking. See [`super::code`] before changing it.
pub const CODE_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// How many unredeemed, unexpired codes one account may hold.
pub const MAX_ACTIVE_CODES: usize = 5;

/// The limits a pairing is subject to.
///
/// `max_devices_per_user` comes from configuration; the other two are
/// compiled in, because neither is a thing an operator has a reason to
/// tune and both are load-bearing for the code's security argument.
#[derive(Debug, Clone, Copy)]
pub struct DevicePolicy {
    pub max_devices_per_user: usize,
}

/// A pairing code that was just created.
pub struct NewPairingCode {
    pub code: PairingCode,
    pub expires_at: UnixTime,
}

/// Why a pairing code could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreateCodeError {
    #[error("this account already has the maximum number of active pairing codes")]
    TooManyActive,

    #[error(transparent)]
    Rng(#[from] RngUnavailable),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Creates a pairing code for `user_id`.
///
/// The caller is an authenticated owner, so there is no secrecy to
/// preserve about the cap: being told the limit is reached is what
/// lets them go and use one of the codes they already have.
pub async fn create_pairing_code(
    pool: &SqlitePool,
    user_id: &str,
    now: UnixTime,
) -> Result<NewPairingCode, CreateCodeError> {
    let code = PairingCode::generate()?;
    let expires_at = now.saturating_add(CODE_LIFETIME);

    match store::insert_pairing_code_guarded(
        pool,
        user_id,
        &code.hash(),
        now,
        expires_at,
        MAX_ACTIVE_CODES,
    )
    .await?
    {
        NewCodeOutcome::Created => {
            // The user id, never the code or any part of it.
            tracing::info!(user_id = %user_id, "pairing code created");
            Ok(NewPairingCode { code, expires_at })
        }
        NewCodeOutcome::TooManyActive => Err(CreateCodeError::TooManyActive),
    }
}

/// A device that was just paired, with the one copy of its token.
pub struct PairedDevice {
    pub device: DeviceRecord,
    /// Shown to the client once and never recoverable afterwards.
    pub token: Token,
}

/// Why a pairing failed.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    /// Unknown, expired, or already redeemed. One variant for all
    /// three, so the response cannot say which.
    #[error("the pairing code is not valid")]
    CodeRejected,

    /// A valid code whose owner is at the device cap.
    #[error("this account has reached its device limit")]
    DeviceLimitReached,

    #[error(transparent)]
    InvalidName(#[from] DeviceNameError),

    #[error("the platform is not one this server knows")]
    UnknownPlatform,

    #[error(transparent)]
    Rng(#[from] RngUnavailable),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Redeems a pairing code and creates the device it pairs.
pub async fn pair_device(
    pool: &SqlitePool,
    presented_code: &str,
    raw_name: &str,
    raw_platform: &str,
    policy: DevicePolicy,
    now: UnixTime,
) -> Result<PairedDevice, PairError> {
    // Input first: cheap, and it says nothing about any code.
    let name = DeviceName::parse(raw_name)?;
    let platform = Platform::parse(raw_platform).ok_or(PairError::UnknownPlatform)?;

    // A code that cannot be one never becomes a database lookup.
    let Some(code_hash) = PairingCode::hash_presented(presented_code) else {
        return Err(PairError::CodeRejected);
    };

    let token = Token::generate(TokenKind::Device)?;

    match store::redeem_code_and_create_device(
        pool,
        &code_hash,
        &name,
        platform,
        &token.hash(),
        now,
        policy.max_devices_per_user,
    )
    .await?
    {
        RedeemOutcome::Paired(device) => {
            // Ids and the platform only. The device name is something
            // a person wrote and can identify them, so it is treated
            // the way usernames are and stays out of the log.
            tracing::info!(
                user_id = %device.user_id,
                device_id = %device.id,
                platform = %device.platform,
                "device paired"
            );
            Ok(PairedDevice { device, token })
        }
        RedeemOutcome::CodeRejected => Err(PairError::CodeRejected),
        RedeemOutcome::DeviceLimitReached => Err(PairError::DeviceLimitReached),
    }
}

/// Deletes every pairing code that is spent or expired.
///
/// Run by the background sweep. [`store::insert_pairing_code_guarded`]
/// already collects the *minting* account's dead codes, which bounds
/// what one person can accumulate while they are active; this is what
/// collects the codes of somebody who minted one and never came back.
///
/// Deliberately a separate entry point from
/// [`crate::auth::session::sweep_expired`] rather than a line added to
/// it: that function sweeps the auth tables, this one sweeps a device
/// table, and the cleanup task calls both. Reaching across the module
/// boundary to save one call would make `auth` responsible for rows it
/// knows nothing about.
pub async fn sweep_expired_codes(pool: &SqlitePool, now: UnixTime) -> Result<u64, StoreError> {
    store::delete_stale_pairing_codes(pool, now).await
}

// --- management -------------------------------------------------------

/// One owner's devices, revoked ones included.
pub async fn list_own_devices(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<DeviceRecord>, StoreError> {
    store::list_devices_for_user(pool, user_id).await
}

/// Every device on the instance, with its owner. Admin only, metadata
/// only - see the rule at the top of [`super`].
pub async fn list_all_devices(pool: &SqlitePool) -> Result<Vec<DeviceWithOwner>, StoreError> {
    store::list_all_devices(pool).await
}

/// Why a device could not be renamed or revoked.
#[derive(Debug, thiserror::Error)]
pub enum DeviceActionError {
    /// No such device, or not one the caller may touch. Deliberately
    /// one variant: an owner must not be able to learn that a device
    /// id exists on somebody else's account.
    #[error("no such device")]
    NotFound,

    #[error(transparent)]
    InvalidName(#[from] DeviceNameError),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Renames a device within `scope`.
pub async fn rename_device(
    pool: &SqlitePool,
    scope: Scope<'_>,
    device_id: &str,
    raw_name: &str,
) -> Result<DeviceRecord, DeviceActionError> {
    let name = DeviceName::parse(raw_name)?;

    match store::rename_device(pool, scope, device_id, &name).await? {
        Some(device) => {
            tracing::info!(device_id = %device.id, "device renamed");
            Ok(device)
        }
        None => Err(DeviceActionError::NotFound),
    }
}

/// What a revocation did.
#[derive(Debug, Clone)]
pub struct RevokeReport {
    pub device: DeviceRecord,
    /// False when the device was already revoked, so the caller can
    /// answer idempotently without claiming it just happened.
    pub newly_revoked: bool,
}

/// Revokes a device within `scope`, keeping its events.
///
/// Takes effect on the device's next request: authentication reads
/// `revoked_at` from the row every time, with nothing cached in
/// between.
pub async fn revoke_device(
    pool: &SqlitePool,
    scope: Scope<'_>,
    device_id: &str,
    now: UnixTime,
) -> Result<RevokeReport, DeviceActionError> {
    match store::revoke_device(pool, scope, device_id, now).await? {
        store::RevokeOutcome::Revoked(device) => {
            tracing::info!(
                user_id = %device.user_id,
                device_id = %device.id,
                "device revoked"
            );
            Ok(RevokeReport {
                device,
                newly_revoked: true,
            })
        }
        store::RevokeOutcome::AlreadyRevoked(device) => Ok(RevokeReport {
            device,
            newly_revoked: false,
        }),
        store::RevokeOutcome::NotFound => Err(DeviceActionError::NotFound),
    }
}
