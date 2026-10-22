//! Invite-based onboarding.
//!
//! An admin creates a pending account and hands over a one-time invite
//! token; the person redeems it and chooses their own password. An
//! admin can also reset an existing account to pending, handing out a
//! fresh invite in place of whatever password it had - see
//! `docs/design-decisions.md` for why that power exists and what keeps
//! it from being silent.
//!
//! No step here ever sees or stores a password chosen by anyone but the
//! account holder: creating or resetting an account costs no Argon2
//! work at all, because there is no password yet to hash.

use std::time::Duration;

use sqlx::SqlitePool;

use super::password::{HashError, Hasher, Password, PasswordPolicyError};
use super::role::Role;
use super::secret::SecretString;
use super::store::{
    self, InsertUserOutcome, RedeemInviteOutcome, ResetToPendingOutcome, StoreError, UserSummary,
};
use super::time::UnixTime;
use super::token::{RngUnavailable, Token, TokenHash, TokenKind};
use super::username::{Username, UsernameError};

/// How long a freshly issued invite token remains redeemable.
#[derive(Debug, Clone, Copy)]
pub struct InvitePolicy {
    pub ttl: Duration,
}

/// An account together with the invite token that activates it.
///
/// The token is plaintext and exists here, in the response that hands
/// it to the admin, and nowhere else on the server: there is no
/// `Debug` derive, so it cannot leak into a log by accident the way a
/// field on a logged struct could.
pub struct IssuedInvite {
    pub user: UserSummary,
    pub token: Token,
    pub expires_at: UnixTime,
}

/// Why a pending account could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreatePendingAccountError {
    #[error(transparent)]
    InvalidUsername(#[from] UsernameError),

    #[error("that username is already taken")]
    UsernameTaken,

    #[error(transparent)]
    Rng(#[from] RngUnavailable),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Creates a pending account and its invite.
///
/// No password parameter: there is nothing to hash, so this is a cheap
/// endpoint, unlike every other write in this module's neighbourhood
/// that touches Argon2.
pub async fn create_pending_account(
    pool: &SqlitePool,
    raw_username: &str,
    role: Role,
    policy: InvitePolicy,
    now: UnixTime,
) -> Result<IssuedInvite, CreatePendingAccountError> {
    let username = Username::parse(raw_username)?;
    let token = Token::generate(TokenKind::Invite)?;
    let expires_at = now.saturating_add(policy.ttl);

    match store::insert_pending_user_with_invite(
        pool,
        &username,
        role,
        &token.hash(),
        now,
        expires_at,
    )
    .await?
    {
        InsertUserOutcome::Created(user) => {
            tracing::info!(user_id = %user.id, role = %user.role, "pending account created");
            Ok(IssuedInvite {
                user,
                token,
                expires_at,
            })
        }
        InsertUserOutcome::UsernameTaken => Err(CreatePendingAccountError::UsernameTaken),
    }
}

/// Why an account could not be reset to pending.
#[derive(Debug, thiserror::Error)]
pub enum ResetPasswordError {
    #[error("no such account")]
    NotFound,

    #[error("the last remaining admin may not be reset")]
    LastAdmin,

    #[error(transparent)]
    Rng(#[from] RngUnavailable),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// What a successful reset did, beyond issuing the new invite.
pub struct ResetReport {
    pub invite: IssuedInvite,
    /// How many sessions were ended. Every one the account had: unlike
    /// a self-service password change, there is no session making this
    /// request to spare.
    pub sessions_ended: u64,
    pub devices_revoked: u64,
}

/// Resets an account to pending: its password stops working, every
/// session ends, every device is revoked, and a fresh invite takes its
/// place.
///
/// `actor_id` is the acting admin's id, written to the account's log so
/// the reset is visible to the account holder - see
/// `crate::auth::account_log` and `docs/design-decisions.md`.
pub async fn reset_password(
    pool: &SqlitePool,
    target_id: &str,
    actor_id: &str,
    policy: InvitePolicy,
    now: UnixTime,
) -> Result<ResetReport, ResetPasswordError> {
    let token = Token::generate(TokenKind::Invite)?;
    let expires_at = now.saturating_add(policy.ttl);

    match store::reset_to_pending(pool, target_id, actor_id, &token.hash(), now, expires_at).await?
    {
        ResetToPendingOutcome::Reset {
            sessions_ended,
            devices_revoked,
        } => {
            tracing::info!(
                user_id = %target_id,
                actor_id = %actor_id,
                sessions_ended,
                devices_revoked,
                "account reset to pending by an admin"
            );
            let user = store::find_user_by_id(pool, target_id)
                .await?
                .map(|record| UserSummary::from(&record))
                .ok_or(ResetPasswordError::NotFound)?;
            Ok(ResetReport {
                invite: IssuedInvite {
                    user,
                    token,
                    expires_at,
                },
                sessions_ended,
                devices_revoked,
            })
        }
        ResetToPendingOutcome::NotFound => Err(ResetPasswordError::NotFound),
        ResetToPendingOutcome::LastAdmin => Err(ResetPasswordError::LastAdmin),
    }
}

/// Why an invite could not be redeemed.
#[derive(Debug, thiserror::Error)]
pub enum RedeemError {
    /// Unknown, expired, malformed, or already used. One variant for
    /// all of them: the caller is unauthenticated, and distinguishing
    /// these would say whether a token ever existed.
    #[error("the invite token is not valid")]
    Rejected,

    #[error(transparent)]
    InvalidPassword(#[from] PasswordPolicyError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Redeems an invite token, setting the account's first password.
///
/// The order mirrors [`super::setup::complete_setup`]:
///
/// 1. The new password goes through the full policy, including the
///    minimum length - this is a password being *chosen*.
/// 2. The token's shape is checked in memory before any query.
/// 3. A cheap advisory liveness read, so a bad token costs no Argon2
///    work.
/// 4. Only then is the password hashed, outside any transaction: it
///    takes tens of milliseconds, and holding SQLite's write lock for
///    that long would stall every other writer.
/// 5. The authoritative write happens in [`store::redeem_invite`]'s own
///    `BEGIN IMMEDIATE` transaction, which re-checks the token and the
///    account's status under the write lock.
///
/// No session is created here: the person logs in normally afterwards,
/// through [`super::login::log_in`].
pub async fn redeem(
    pool: &SqlitePool,
    hasher: &Hasher,
    presented_token: &SecretString,
    new_password: SecretString,
    now: UnixTime,
) -> Result<(), RedeemError> {
    let password = Password::parse(new_password)?;

    let token_hash = TokenHash::of_presented(TokenKind::Invite, presented_token.expose())
        .ok_or(RedeemError::Rejected)?;

    if !store::invite_token_is_live(pool, &token_hash, now).await? {
        return Err(RedeemError::Rejected);
    }

    let password_hash = hasher.hash(&password).await?;

    match store::redeem_invite(pool, &token_hash, &password_hash, now).await? {
        RedeemInviteOutcome::Redeemed { user_id } => {
            tracing::info!(user_id = %user_id, "an invite was redeemed");
            Ok(())
        }
        RedeemInviteOutcome::Rejected => Err(RedeemError::Rejected),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use super::*;
    use crate::auth::password::HashingParams;
    use crate::auth::store::{AccountStatus, Credential};
    use crate::db::{self, DbTarget};

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    fn policy() -> InvitePolicy {
        InvitePolicy {
            ttl: StdDuration::from_secs(259_200),
        }
    }

    fn hasher() -> Hasher {
        Hasher::new(
            HashingParams::owasp_minimum(),
            4,
            StdDuration::from_secs(30),
        )
    }

    fn random_password() -> SecretString {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        SecretString::new(URL_SAFE_NO_PAD.encode(bytes))
    }

    async fn pool() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");
        pool
    }

    #[tokio::test]
    async fn creating_a_pending_account_issues_a_redeemable_invite() {
        let pool = pool().await;

        let issued = create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .expect("creating must succeed");
        assert!(issued.token.expose().starts_with("swi_"));
        assert_eq!(
            issued.expires_at,
            now().saturating_add(StdDuration::from_secs(259_200))
        );

        let found = store::find_user_by_id(&pool, &issued.user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(found.credential, Credential::Pending));
        assert_eq!(found.status, AccountStatus::Pending);
    }

    #[tokio::test]
    async fn a_duplicate_username_is_reported_and_issues_no_invite() {
        let pool = pool().await;
        create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .unwrap();

        let outcome = create_pending_account(&pool, "Alice", Role::User, policy(), now()).await;
        assert!(matches!(
            outcome,
            Err(CreatePendingAccountError::UsernameTaken)
        ));
    }

    #[tokio::test]
    async fn a_redeemed_invite_lets_the_account_log_in() {
        let pool = pool().await;
        let hasher = hasher();
        let issued = create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .unwrap();
        let password = random_password();
        let password_copy = SecretString::new(password.expose().to_owned());

        redeem(
            &pool,
            &hasher,
            &SecretString::new(issued.token.expose().to_owned()),
            password,
            now(),
        )
        .await
        .expect("redeeming must succeed");

        let found = store::find_user_by_id(&pool, &issued.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, AccountStatus::Active);
        let Credential::Password(stored_hash) = found.credential else {
            panic!("the account must have a password after redemption");
        };
        assert!(matches!(
            hasher
                .verify(
                    &Password::parse_for_verification(password_copy).unwrap(),
                    &stored_hash
                )
                .await
                .unwrap(),
            crate::auth::password::Verification::Match { .. }
        ));
    }

    #[tokio::test]
    async fn redeeming_twice_fails_the_second_time() {
        let pool = pool().await;
        let hasher = hasher();
        let issued = create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .unwrap();
        let token = SecretString::new(issued.token.expose().to_owned());

        redeem(&pool, &hasher, &token, random_password(), now())
            .await
            .unwrap();
        let second = redeem(&pool, &hasher, &token, random_password(), now()).await;
        assert!(matches!(second, Err(RedeemError::Rejected)));
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected_without_hashing() {
        let pool = pool().await;
        let fake = Token::generate(TokenKind::Invite).unwrap();
        let outcome = redeem(
            &pool,
            &hasher(),
            &SecretString::new(fake.expose().to_owned()),
            random_password(),
            now(),
        )
        .await;
        assert!(matches!(outcome, Err(RedeemError::Rejected)));
    }

    #[tokio::test]
    async fn the_password_policy_applies_at_redemption() {
        let pool = pool().await;
        let issued = create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .unwrap();
        let token = SecretString::new(issued.token.expose().to_owned());
        let short = SecretString::new("short".to_owned());

        let outcome = redeem(&pool, &hasher(), &token, short, now()).await;
        assert!(matches!(
            outcome,
            Err(RedeemError::InvalidPassword(PasswordPolicyError::Length))
        ));

        // The invite must still be live: a rejected password must not
        // consume it.
        let found = store::find_user_by_id(&pool, &issued.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status, AccountStatus::Pending);
    }

    #[tokio::test]
    async fn resetting_an_account_issues_a_fresh_invite_and_revokes_the_old_one() {
        let pool = pool().await;
        let issued = create_pending_account(&pool, "alice", Role::User, policy(), now())
            .await
            .unwrap();
        let first_token = SecretString::new(issued.token.expose().to_owned());

        let reset = reset_password(&pool, &issued.user.id, "admin-1", policy(), now())
            .await
            .expect("reset must succeed");
        assert_eq!(reset.sessions_ended, 0);
        assert_eq!(reset.devices_revoked, 0);

        // The original invite no longer works.
        let first_attempt = redeem(&pool, &hasher(), &first_token, random_password(), now()).await;
        assert!(matches!(first_attempt, Err(RedeemError::Rejected)));

        // The new one does.
        let new_token = SecretString::new(reset.invite.token.expose().to_owned());
        redeem(&pool, &hasher(), &new_token, random_password(), now())
            .await
            .expect("the fresh invite must redeem");
    }

    #[tokio::test]
    async fn resetting_the_last_admin_is_refused() {
        let pool = pool().await;
        let hasher = hasher();
        let issued = create_pending_account(&pool, "alice", Role::Admin, policy(), now())
            .await
            .unwrap();
        redeem(
            &pool,
            &hasher,
            &SecretString::new(issued.token.expose().to_owned()),
            random_password(),
            now(),
        )
        .await
        .unwrap();

        let outcome = reset_password(&pool, &issued.user.id, "someone", policy(), now()).await;
        assert!(matches!(outcome, Err(ResetPasswordError::LastAdmin)));
    }

    #[tokio::test]
    async fn resetting_an_unknown_account_is_not_found() {
        let pool = pool().await;
        let outcome = reset_password(&pool, "not-an-id", "someone", policy(), now()).await;
        assert!(matches!(outcome, Err(ResetPasswordError::NotFound)));
    }
}
