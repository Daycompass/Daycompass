//! Account management, and a user changing their own password.
//!
//! This is the service layer for M1c: an admin creates, lists, re-roles
//! and deletes accounts, and any logged-in account can change its own
//! password. Nothing here knows about axum, so the later dashboard will
//! drive exactly these functions.
//!
//! Three rules are worth stating in one place, because they are the
//! reason this module exists rather than the handlers calling
//! [`crate::auth::store`] directly:
//!
//! * **Every authorization decision is made against the role that was
//!   just read from the database.** Nothing here takes a role as an
//!   argument to decide *whether* a caller may act; the admin check
//!   happens at the edge, on a record resolved for this one request. A
//!   role cached in a session or a token would keep a demoted admin
//!   administrative for as long as that cache lived.
//! * **The last admin is protected inside the write transaction**, in
//!   [`store::set_role_guarded`] and [`store::delete_user_guarded`].
//!   This module must not pre-check the admin count and then write: two
//!   concurrent requests would both pass such a check.
//! * **Argon2 work always goes through the shared hasher**, so the
//!   semaphore that bounds concurrent hashing covers account creation
//!   and password changes just as it covers login. A path that hashed
//!   directly would be a way around that bound.
//!
//! Log lines here carry user ids and never a username, a password or a
//! hash - see the note in [`crate::auth::login`] for why the id is the
//! only safe identifier to record.

use sqlx::SqlitePool;

use super::invite::{self, CreatePendingAccountError, InvitePolicy, IssuedInvite};
use super::password::{HashError, Hasher, Password, PasswordPolicyError, Verification};
use super::role::Role;
use super::secret::SecretString;
use super::store::{
    self, Credential, DeleteUserOutcome, PasswordChangeOutcome, RoleChangeOutcome, StoreError,
    UserSummary,
};
use super::time::UnixTime;

/// Creates a pending account and its invite.
///
/// A thin delegate to [`invite::create_pending_account`]: account
/// creation is no longer "an admin chooses a password" (see M1d's
/// `docs/design-decisions.md`), so there is nothing here for this
/// module to add on top. Kept as its own function so the call sites in
/// `routes/users.rs` read as account management rather than reaching
/// into the invite module directly.
pub async fn create_user(
    pool: &SqlitePool,
    raw_username: &str,
    role: Role,
    invite_policy: InvitePolicy,
    now: UnixTime,
) -> Result<IssuedInvite, CreatePendingAccountError> {
    invite::create_pending_account(pool, raw_username, role, invite_policy, now).await
}

/// Every account, oldest first, without password hashes.
pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserSummary>, StoreError> {
    store::list_users(pool).await
}

/// Why a role could not be changed.
#[derive(Debug, thiserror::Error)]
pub enum RoleChangeError {
    #[error("no such account")]
    NotFound,

    #[error("the last remaining admin may not be demoted")]
    LastAdmin,

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Changes an account's role.
///
/// Demoting the last admin is refused by the store, inside the write
/// transaction. An admin demoting *themselves* while another admin
/// remains is allowed: the role is re-read on every request, so their
/// own session loses administrative access immediately afterwards.
pub async fn change_role(
    pool: &SqlitePool,
    target_id: &str,
    role: Role,
) -> Result<UserSummary, RoleChangeError> {
    match store::set_role_guarded(pool, target_id, role).await? {
        RoleChangeOutcome::Changed(user) => {
            tracing::info!(user_id = %user.id, role = %user.role, "account role changed");
            Ok(user)
        }
        RoleChangeOutcome::NotFound => Err(RoleChangeError::NotFound),
        RoleChangeOutcome::LastAdmin => Err(RoleChangeError::LastAdmin),
    }
}

/// Why an account could not be deleted.
#[derive(Debug, thiserror::Error)]
pub enum DeleteUserError {
    #[error("no such account")]
    NotFound,

    #[error("the last remaining admin may not be deleted")]
    LastAdmin,

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Hard-deletes an account. Its sessions go with it, so every cookie it
/// handed out stops working on the next request.
pub async fn delete_user(pool: &SqlitePool, target_id: &str) -> Result<(), DeleteUserError> {
    match store::delete_user_guarded(pool, target_id).await? {
        DeleteUserOutcome::Deleted => {
            tracing::info!(user_id = %target_id, "account deleted");
            Ok(())
        }
        DeleteUserOutcome::NotFound => Err(DeleteUserError::NotFound),
        DeleteUserOutcome::LastAdmin => Err(DeleteUserError::LastAdmin),
    }
}

/// Why a password change did not happen.
#[derive(Debug, thiserror::Error)]
pub enum PasswordChangeError {
    /// The current password did not match. Also covers a current
    /// password that could not possibly match because it fails the
    /// bounds every presented password is checked against.
    #[error("the current password is incorrect")]
    CurrentPasswordInvalid,

    #[error(transparent)]
    InvalidNewPassword(PasswordPolicyError),

    /// Another change landed first. Retrying is the right answer.
    #[error("the password was changed by another request")]
    Conflict,

    /// The account disappeared between the session being resolved and
    /// the change being applied.
    #[error("the account no longer exists")]
    AccountGone,

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// What a successful password change did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordChangeReport {
    /// Sessions of this account that were ended. The one making the
    /// request is not among them.
    pub other_sessions_ended: u64,
}

/// Changes an account's own password.
///
/// `current_session_id` is the session the request arrived on; it
/// survives, and every other session of the account is ended in the
/// same transaction as the new hash. A password change is the action
/// someone takes when they believe a session is not theirs any more, so
/// it has to be the thing that revokes the others - and it must not log
/// out the browser doing it, or the change looks like a failure.
///
/// The order of work:
///
/// 1. The presented current password is bounds-checked and the new one
///    is checked against the full policy. Both are decided from the
///    caller's own input, so neither says anything about the account.
/// 2. The stored hash is read.
/// 3. The current password is verified against it, through the shared
///    hasher.
/// 4. The new password is hashed, also through the shared hasher.
/// 5. The write applies only if the stored hash is still the one step 3
///    verified against, so two parallel changes cannot both succeed.
///
/// Rate limiting happens before any of this, per session, at the route
/// itself: see [`crate::routes::INVENTORY`]. It has to be in front of
/// the Argon2 semaphore rather than behind it, or a flood of password
/// changes would occupy the hashing permits that logins also need. Per
/// session rather than per account so that a stolen session cannot
/// spend the budget the owner needs in order to lock it out; the
/// trade-off is set out in [`crate::ratelimit::SessionKey`].
pub async fn change_own_password(
    pool: &SqlitePool,
    hasher: &Hasher,
    user_id: &str,
    current_session_id: &str,
    current_password: SecretString,
    new_password: SecretString,
    now: UnixTime,
) -> Result<PasswordChangeReport, PasswordChangeError> {
    // A current password outside the bounds every presented password is
    // checked against cannot match a stored hash, so it is the same
    // answer as a wrong one rather than a policy complaint about a
    // field the caller is not choosing.
    let current = Password::parse_for_verification(current_password)
        .map_err(|_| PasswordChangeError::CurrentPasswordInvalid)?;
    let new = Password::parse(new_password).map_err(PasswordChangeError::InvalidNewPassword)?;

    let Some(user) = store::find_user_by_id(pool, user_id).await? else {
        return Err(PasswordChangeError::AccountGone);
    };

    // Unreachable in practice - a pending account cannot hold a session
    // to call this with - but it is the arm the compiler now demands,
    // and answering the same as a wrong password is the right refusal
    // if it were ever reached.
    let Credential::Password(stored_hash) = &user.credential else {
        return Err(PasswordChangeError::CurrentPasswordInvalid);
    };

    match hasher.verify(&current, stored_hash).await? {
        Verification::Mismatch => return Err(PasswordChangeError::CurrentPasswordInvalid),
        // Any rehash the old hash might have needed is moot: it is being
        // replaced with one at the current parameters right now.
        Verification::Match { .. } => {}
    }

    let new_hash = hasher.hash(&new).await?;

    match store::replace_password_hash_if_unchanged(
        pool,
        user_id,
        stored_hash,
        &new_hash,
        current_session_id,
        now,
    )
    .await?
    {
        PasswordChangeOutcome::Changed {
            other_sessions_ended,
        } => {
            tracing::info!(
                user_id = %user_id,
                other_sessions_ended,
                "password changed; other sessions ended"
            );
            Ok(PasswordChangeReport {
                other_sessions_ended,
            })
        }
        PasswordChangeOutcome::Stale => Err(PasswordChangeError::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use super::*;
    use crate::auth::password::HashingParams;
    use crate::auth::session::{self, SessionPolicy};
    use crate::auth::store::AccountStatus;
    use crate::auth::username::UsernameError;
    use crate::db::{self, DbTarget};

    /// Every password in these tests is generated at runtime.
    fn random_password() -> SecretString {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        SecretString::new(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn hasher() -> Hasher {
        Hasher::new(HashingParams::owasp_minimum(), 4, Duration::from_secs(30))
    }

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    fn policy() -> SessionPolicy {
        SessionPolicy {
            idle_timeout: Duration::from_secs(600),
            absolute_timeout: Duration::from_secs(3_600),
        }
    }

    fn invite_policy() -> InvitePolicy {
        InvitePolicy {
            ttl: Duration::from_secs(259_200),
        }
    }

    async fn pool() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");
        pool
    }

    /// Creates a pending account and immediately redeems its invite with
    /// `password`, so the result is an ordinary active account. Several
    /// tests below are about sessions and password changes, which need
    /// a real password to start from rather than a pending one.
    async fn create_active_user(
        pool: &SqlitePool,
        username: &str,
        password: SecretString,
        role: Role,
    ) -> UserSummary {
        let issued = create_user(pool, username, role, invite_policy(), now())
            .await
            .expect("creating must succeed");
        invite::redeem(
            pool,
            &hasher(),
            &SecretString::new(issued.token.expose().to_owned()),
            password,
            now(),
        )
        .await
        .expect("redeeming must succeed");
        issued.user
    }

    /// An instance with one admin, so the last-admin guard is not what
    /// a test trips over by accident.
    async fn pool_with_admin() -> SqlitePool {
        let pool = pool().await;
        create_active_user(&pool, "alice", random_password(), Role::Admin).await;
        pool
    }

    #[tokio::test]
    async fn creating_an_account_issues_a_pending_invite() {
        let pool = pool().await;

        let issued = create_user(&pool, "alice", Role::Admin, invite_policy(), now())
            .await
            .expect("creating must succeed");
        assert_eq!(issued.user.username.as_str(), "alice");
        assert_eq!(issued.user.role, Role::Admin);
        assert_eq!(issued.user.status, AccountStatus::Pending);
        assert!(issued.token.expose().starts_with("swi_"));

        let found = store::find_user_by_id(&pool, &issued.user.id)
            .await
            .unwrap()
            .expect("the account must exist");
        assert!(matches!(found.credential, Credential::Pending));
    }

    /// The username is normalized exactly as the setup flow normalizes
    /// it, so a differently cased spelling is the same account.
    #[tokio::test]
    async fn a_differently_cased_username_is_already_taken() {
        let pool = pool_with_admin().await;

        let outcome = create_user(&pool, "Alice", Role::User, invite_policy(), now()).await;

        assert!(matches!(
            outcome,
            Err(CreatePendingAccountError::UsernameTaken)
        ));
        assert_eq!(
            list_users(&pool).await.unwrap().len(),
            1,
            "no second account may exist"
        );
    }

    #[tokio::test]
    async fn surrounding_whitespace_is_trimmed_from_a_new_username() {
        let pool = pool().await;
        let issued = create_user(&pool, "  bob  ", Role::User, invite_policy(), now())
            .await
            .expect("creating must succeed");
        assert_eq!(issued.user.username.as_str(), "bob");
    }

    #[tokio::test]
    async fn the_username_policy_applies_to_a_new_account() {
        let pool = pool().await;

        assert!(matches!(
            create_user(&pool, "no", Role::User, invite_policy(), now()).await,
            Err(CreatePendingAccountError::InvalidUsername(
                UsernameError::Length
            ))
        ));
        assert!(matches!(
            create_user(&pool, "Not Allowed", Role::User, invite_policy(), now()).await,
            Err(CreatePendingAccountError::InvalidUsername(
                UsernameError::Charset
            ))
        ));
        assert!(
            list_users(&pool).await.unwrap().is_empty(),
            "no rejected account may have been created"
        );
    }

    #[tokio::test]
    async fn the_last_admin_is_protected_from_demotion_and_deletion() {
        let pool = pool_with_admin().await;
        let admin = list_users(&pool).await.unwrap().remove(0);

        assert!(matches!(
            change_role(&pool, &admin.id, Role::User).await,
            Err(RoleChangeError::LastAdmin)
        ));
        assert!(matches!(
            delete_user(&pool, &admin.id).await,
            Err(DeleteUserError::LastAdmin)
        ));
        assert!(matches!(
            change_role(&pool, &store::new_id(), Role::User).await,
            Err(RoleChangeError::NotFound)
        ));
        assert!(matches!(
            delete_user(&pool, &store::new_id()).await,
            Err(DeleteUserError::NotFound)
        ));
    }

    async fn stored_hash_of(pool: &SqlitePool, user_id: &str) -> String {
        let user = store::find_user_by_id(pool, user_id)
            .await
            .unwrap()
            .expect("the account must exist");
        let Credential::Password(hash) = user.credential else {
            panic!("the account must have a password");
        };
        hash
    }

    /// One account, three sessions: the request's own and two others.
    async fn account_with_sessions(
        pool: &SqlitePool,
        password: SecretString,
    ) -> (String, String, Vec<String>) {
        let user = create_active_user(pool, "bob", password, Role::User).await;

        let mut sessions = Vec::new();
        for _ in 0..3 {
            let created = session::create(pool, &user.id, policy(), now())
                .await
                .expect("creating a session must succeed");
            sessions.push(created.record.id);
        }
        let current = sessions.remove(0);
        (user.id, current, sessions)
    }

    #[tokio::test]
    async fn a_password_change_replaces_the_hash_and_ends_the_other_sessions() {
        let pool = pool_with_admin().await;
        let hasher = hasher();
        let password = random_password();
        let old = SecretString::new(password.expose().to_owned());
        let (user_id, current, others) = account_with_sessions(&pool, password).await;
        let new = random_password();
        let new_copy = SecretString::new(new.expose().to_owned());

        let report = change_own_password(&pool, &hasher, &user_id, &current, old, new, now())
            .await
            .expect("the change must succeed");
        assert_eq!(
            report,
            PasswordChangeReport {
                other_sessions_ended: others.len() as u64
            }
        );

        let stored = store::find_user_by_id(&pool, &user_id)
            .await
            .unwrap()
            .expect("the account must exist");
        let Credential::Password(stored_hash) = &stored.credential else {
            panic!("the account must still have a password");
        };
        assert!(matches!(
            hasher
                .verify(
                    &Password::parse_for_verification(new_copy).unwrap(),
                    stored_hash
                )
                .await
                .unwrap(),
            Verification::Match { .. }
        ));

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM sessions WHERE user_id = ?1")
                .bind(&user_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, vec![current]);

        // Two entries: the invite redemption `create_active_user`
        // performed, and this password change, newest first.
        let logs = crate::auth::account_log::list_for_user(&pool, &user_id)
            .await
            .unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(
            logs[0].kind,
            crate::auth::account_log::LogKind::PasswordChanged
        );
        assert_eq!(logs[0].actor_id, None);
    }

    #[tokio::test]
    async fn a_wrong_current_password_changes_nothing() {
        let pool = pool_with_admin().await;
        let hasher = hasher();
        let password = random_password();
        let (user_id, current, others) = account_with_sessions(&pool, password).await;
        let before = stored_hash_of(&pool, &user_id).await;

        let outcome = change_own_password(
            &pool,
            &hasher,
            &user_id,
            &current,
            random_password(),
            random_password(),
            now(),
        )
        .await;

        assert!(matches!(
            outcome,
            Err(PasswordChangeError::CurrentPasswordInvalid)
        ));
        let after = stored_hash_of(&pool, &user_id).await;
        assert_eq!(before, after, "the stored hash must be untouched");
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            others.len() as i64 + 1,
            "a refused change must not end any session"
        );
    }

    /// A blank or over-long current password is answered the same way as
    /// a wrong one, not with a policy error about a field the caller is
    /// not choosing.
    #[tokio::test]
    async fn an_unusable_current_password_is_answered_as_simply_wrong() {
        let pool = pool_with_admin().await;
        let password = random_password();
        let (user_id, current, _others) = account_with_sessions(&pool, password).await;

        for unusable in [
            SecretString::new("   ".to_owned()),
            SecretString::new("x".repeat(crate::auth::password::MAX_CHARS + 1)),
        ] {
            let outcome = change_own_password(
                &pool,
                &hasher(),
                &user_id,
                &current,
                unusable,
                random_password(),
                now(),
            )
            .await;
            assert!(matches!(
                outcome,
                Err(PasswordChangeError::CurrentPasswordInvalid)
            ));
        }
    }

    #[tokio::test]
    async fn a_new_password_below_the_policy_is_refused() {
        let pool = pool_with_admin().await;
        let password = random_password();
        let old = SecretString::new(password.expose().to_owned());
        let (user_id, current, _others) = account_with_sessions(&pool, password).await;
        let short = SecretString::new(random_password().expose()[..11].to_owned());

        let outcome =
            change_own_password(&pool, &hasher(), &user_id, &current, old, short, now()).await;

        assert!(matches!(
            outcome,
            Err(PasswordChangeError::InvalidNewPassword(
                PasswordPolicyError::Length
            ))
        ));
    }
}
