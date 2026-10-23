//! Logging in.
//!
//! The one property this module exists to protect is that an attacker
//! learns nothing about which accounts exist. A wrong password and an
//! unknown username take the same path, cost the same Argon2 work, and
//! produce the same error, so neither the response nor its timing
//! separates them.
//!
//! That is why an unknown username is verified against a decoy hash
//! built at startup with the current parameters. Skipping the hash for
//! an unknown account would make "no such user" answer in a millisecond
//! while a real account takes fifty, which is a reliable account
//! oracle - and a much easier one to exploit than most timing attacks,
//! because the difference is enormous rather than marginal.
//!
//! # The order of work in a login
//!
//! Each step exists to keep the next one from being reachable cheaply,
//! so the order is the protection:
//!
//! 1. The **`Origin` check**, as a layer attached from the route's entry
//!    in [`crate::routes::INVENTORY`]. A present, foreign origin is
//!    refused before anything else happens.
//! 2. The **per-address rate limit**, also a layer from that entry. It
//!    caps how many distinct usernames one client can even introduce,
//!    which is what keeps step 3's map bounded.
//! 3. The **per-username rate limit**, in the handler, because its key
//!    is in the request body. It protects one account against a
//!    guessing attack spread across many addresses.
//! 4. **Input bounds**: a blank or over-long password, and a username
//!    that could not name an account, are decided from the caller's own
//!    input and so leak nothing.
//! 5. The **account lookup**, then exactly one **Argon2 verification** -
//!    against the stored hash, or against the decoy if there is no such
//!    account. This is the only expensive step, and it is behind all of
//!    the above plus the hasher's own semaphore and wait timeout.
//! 6. On success, a **new session**; never a reused or refreshed one.
//!
//! Only then is a stored hash upgraded, if it was made with weaker
//! parameters - the one moment the plaintext is available.

use sqlx::SqlitePool;

use super::password::{HashError, Hasher, Password, Verification};
use super::secret::SecretString;
use super::session::{self, NewSession, SessionError, SessionPolicy};
use super::store::{self, Credential, StoreError, UserRecord};
use super::time::UnixTime;
use super::username::Username;

/// A successful login.
pub struct LoginOutcome {
    pub user: UserRecord,
    pub session: NewSession,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// Wrong password, unknown account, or input that could not name an
    /// account at all. One variant on purpose: the three must be
    /// indistinguishable to the caller.
    #[error("the username or password is incorrect")]
    InvalidCredentials,

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Session(#[from] SessionError),
}

/// Verifies credentials and opens a new session.
///
/// `decoy_hash` is a PHC string built once at startup by
/// [`Hasher::decoy_hash`], whose plaintext was discarded.
pub async fn log_in(
    pool: &SqlitePool,
    hasher: &Hasher,
    decoy_hash: &str,
    policy: SessionPolicy,
    raw_username: &str,
    raw_password: SecretString,
    now: UnixTime,
) -> Result<LoginOutcome, LoginError> {
    // Rejecting over-long or blank input before hashing is safe: the
    // outcome depends only on what the caller sent, never on whether an
    // account exists.
    let Ok(password) = Password::parse_for_verification(raw_password) else {
        return Err(LoginError::InvalidCredentials);
    };

    // A username that cannot pass the policy cannot name an account, so
    // there is nothing to look up. It still goes through a verification
    // against the decoy, so the work done is the same as for a
    // well-formed unknown username.
    let candidate = match Username::parse(raw_username) {
        Ok(username) => store::find_user_by_username(pool, &username).await?,
        Err(_) => None,
    };

    let Some(user) = candidate else {
        // Deliberately ignores the result: it can only be a mismatch,
        // since the decoy's plaintext no longer exists anywhere.
        hasher.verify(&password, decoy_hash).await?;
        return Err(LoginError::InvalidCredentials);
    };

    // A pending account has no password to verify against - it exists,
    // but nobody has chosen one yet - so it takes exactly the path an
    // unknown account takes: the same decoy, the same work, the same
    // error. Anything else would make "this username exists but is
    // pending" observable from login's timing or response alone.
    let Credential::Password(password_hash) = &user.credential else {
        hasher.verify(&password, decoy_hash).await?;
        return Err(LoginError::InvalidCredentials);
    };

    match hasher.verify(&password, password_hash).await? {
        Verification::Mismatch => return Err(LoginError::InvalidCredentials),
        Verification::Match { needs_rehash } => {
            if needs_rehash {
                // This is the only moment the plaintext is available, so
                // it is the only chance to upgrade the stored hash. A
                // failure here must not fail the login: the credentials
                // were correct, and the old hash still works.
                match hasher.hash(&password).await {
                    Ok(upgraded) => {
                        if let Err(err) =
                            store::update_password_hash(pool, &user.id, &upgraded).await
                        {
                            tracing::warn!(
                                user_id = %user.id,
                                error = %err,
                                "could not store the upgraded password hash"
                            );
                        } else {
                            tracing::info!(
                                user_id = %user.id,
                                "upgraded a password hash to the current parameters"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(
                        user_id = %user.id,
                        error = %err,
                        "could not compute an upgraded password hash"
                    ),
                }
            }
        }
    }

    let session = session::create(pool, &user.id, policy, now).await?;
    // The user id, never the username: an id is meaningless to anyone
    // reading the logs without database access, a username is not.
    tracing::info!(user_id = %user.id, "login succeeded");

    Ok(LoginOutcome { user, session })
}

/// Logs the fact that a login failed.
///
/// Separate from [`log_in`] so the call site is explicit about what is
/// recorded: no username, no password, no token. Which account someone
/// *tried* is exactly the thing a log reader should not be handed, both
/// because a mistyped password often lands in the username field and
/// because the log would otherwise become a list of account names.
pub fn log_failure() {
    tracing::info!("login failed");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use super::*;
    use argon2::Params;

    use crate::auth::password::HashingParams;
    use crate::auth::session;
    use crate::db::{self, DbTarget};

    /// Every password here is generated at runtime.
    fn random_password() -> String {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn hasher() -> Hasher {
        Hasher::new(HashingParams::owasp_minimum(), 4, Duration::from_secs(30))
    }

    fn policy() -> SessionPolicy {
        SessionPolicy {
            idle_timeout: Duration::from_secs(600),
            absolute_timeout: Duration::from_secs(3_600),
        }
    }

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    /// A pool holding one account, plus its plaintext password and the
    /// decoy hash the unknown-account path uses.
    struct Fixture {
        pool: SqlitePool,
        hasher: Hasher,
        decoy: String,
        user_id: String,
        password: String,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::with_stored_hash(None).await
        }

        /// `stored_hash` overrides how the password is hashed, so a hash
        /// written by an older, weaker configuration can be simulated.
        async fn with_stored_hash(stored_hash: Option<&dyn Fn(&str) -> String>) -> Self {
            let pool = db::connect(&DbTarget::Memory).await.expect("connect");
            db::migrate(&pool).await.expect("migrate");

            let hasher = hasher();
            let password = random_password();
            let hash = match stored_hash {
                Some(build) => build(&password),
                None => hasher
                    .hash(
                        &Password::parse(SecretString::new(password.clone()))
                            .expect("a generated password must satisfy the policy"),
                    )
                    .await
                    .expect("hashing must succeed"),
            };

            let user_id = store::new_id();
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at)
                 VALUES (?1, 'alice', ?2, 'user', 0)",
            )
            .bind(&user_id)
            .bind(&hash)
            .execute(&pool)
            .await
            .expect("inserting the account must succeed");

            let decoy = hasher.decoy_hash().await.expect("decoy must build");
            Self {
                pool,
                hasher,
                decoy,
                user_id,
                password,
            }
        }

        async fn attempt(
            &self,
            username: &str,
            password: &str,
        ) -> Result<LoginOutcome, LoginError> {
            log_in(
                &self.pool,
                &self.hasher,
                &self.decoy,
                policy(),
                username,
                SecretString::new(password.to_owned()),
                now(),
            )
            .await
        }
    }

    #[tokio::test]
    async fn a_correct_password_logs_in_and_opens_a_session() {
        let fixture = Fixture::new().await;
        let outcome = fixture
            .attempt("alice", &fixture.password)
            .await
            .expect("the correct password must be accepted");

        assert_eq!(outcome.user.id, fixture.user_id);
        assert!(outcome.session.token.expose().starts_with("dcs_"));
        assert_eq!(outcome.session.csrf_token.len(), 43);
        assert!(session::resolve(
            &fixture.pool,
            outcome.session.token.expose(),
            policy(),
            now()
        )
        .await
        .unwrap()
        .is_some());
    }

    #[tokio::test]
    async fn the_username_is_matched_case_insensitively() {
        let fixture = Fixture::new().await;
        for spelling in ["alice", "ALICE", "Alice", "  alice  "] {
            assert!(
                fixture.attempt(spelling, &fixture.password).await.is_ok(),
                "{spelling:?} must reach the same account"
            );
        }
    }

    /// The property this module exists for: nothing distinguishes a
    /// wrong password from an account that does not exist.
    #[tokio::test]
    async fn wrong_password_and_unknown_account_fail_identically() {
        let fixture = Fixture::new().await;

        let wrong_password = fixture.attempt("alice", &random_password()).await;
        let unknown_account = fixture.attempt("bob", &random_password()).await;
        let malformed_username = fixture.attempt("x", &random_password()).await;
        let impossible_username = fixture.attempt("not a username!", &random_password()).await;

        for (label, result) in [
            ("wrong password", wrong_password),
            ("unknown account", unknown_account),
            ("username too short", malformed_username),
            ("username outside the charset", impossible_username),
        ] {
            assert!(
                matches!(result, Err(LoginError::InvalidCredentials)),
                "{label} must be InvalidCredentials"
            );
        }

        // And no session was opened by any of them.
        assert_eq!(
            store::count_sessions_for_user(&fixture.pool, &fixture.user_id)
                .await
                .unwrap(),
            0
        );
    }

    /// An over-long password is refused without hashing. That is safe
    /// because the outcome depends only on the caller's own input, and
    /// it is still the same error as every other failure.
    #[tokio::test]
    async fn an_over_long_password_is_rejected_as_invalid_credentials() {
        let fixture = Fixture::new().await;
        let too_long: String = std::iter::repeat_n('x', 129).collect();
        assert!(matches!(
            fixture.attempt("alice", &too_long).await,
            Err(LoginError::InvalidCredentials)
        ));
        assert!(matches!(
            fixture.attempt("alice", "   ").await,
            Err(LoginError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn every_login_opens_a_new_session_rather_than_reusing_one() {
        let fixture = Fixture::new().await;
        let first = fixture.attempt("alice", &fixture.password).await.unwrap();
        let second = fixture.attempt("alice", &fixture.password).await.unwrap();

        assert_ne!(
            first.session.token.expose(),
            second.session.token.expose(),
            "a login must never hand back an existing token"
        );
        assert_ne!(first.session.record.id, second.session.record.id);
        assert_eq!(
            store::count_sessions_for_user(&fixture.pool, &fixture.user_id)
                .await
                .unwrap(),
            2,
            "the earlier session must survive: logging in elsewhere does not log you out"
        );
    }

    /// A successful login is the only moment the plaintext exists, so it
    /// is the only chance to upgrade a hash written under weaker
    /// parameters.
    #[tokio::test]
    async fn a_weak_stored_hash_is_upgraded_on_a_successful_login() {
        use argon2::{Algorithm, Argon2, PasswordHasher, Version};

        let weak = |password: &str| {
            let params = Params::new(Params::MIN_M_COST, 1, 1, None).expect("valid");
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password(password.as_bytes())
                .expect("hashing must succeed")
                .to_string()
        };
        let fixture = Fixture::with_stored_hash(Some(&weak)).await;

        let stored_before: String = sqlx::query_scalar("SELECT password_hash FROM users")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert!(stored_before.contains(&format!("m={}", Params::MIN_M_COST)));

        fixture
            .attempt("alice", &fixture.password)
            .await
            .expect("a weak hash must still verify, or no upgrade could ever happen");

        let stored_after: String = sqlx::query_scalar("SELECT password_hash FROM users")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_ne!(stored_after, stored_before, "the hash must be replaced");
        assert!(stored_after.contains("m=19456"), "at the current cost");

        // The upgraded hash still accepts the same password, and still
        // rejects a different one.
        assert!(fixture.attempt("alice", &fixture.password).await.is_ok());
        assert!(matches!(
            fixture.attempt("alice", &random_password()).await,
            Err(LoginError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn a_wrong_password_against_a_weak_hash_does_not_upgrade_anything() {
        use argon2::{Algorithm, Argon2, PasswordHasher, Version};

        let weak = |password: &str| {
            let params = Params::new(Params::MIN_M_COST, 1, 1, None).expect("valid");
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password(password.as_bytes())
                .expect("hashing must succeed")
                .to_string()
        };
        let fixture = Fixture::with_stored_hash(Some(&weak)).await;

        let before: String = sqlx::query_scalar("SELECT password_hash FROM users")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert!(matches!(
            fixture.attempt("alice", &random_password()).await,
            Err(LoginError::InvalidCredentials)
        ));
        let after: String = sqlx::query_scalar("SELECT password_hash FROM users")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(before, after);
    }

    /// A correct password must not be accepted against the decoy, which
    /// is the hash the unknown-account path verifies against.
    #[tokio::test]
    async fn the_decoy_hash_accepts_nothing() {
        let fixture = Fixture::new().await;
        let password = Password::parse(SecretString::new(fixture.password.clone())).unwrap();
        assert_eq!(
            fixture
                .hasher
                .verify(&password, &fixture.decoy)
                .await
                .unwrap(),
            crate::auth::password::Verification::Mismatch
        );
    }

    /// A pending account - one with no password chosen yet - must fail
    /// a login exactly like an unknown account: same error, same
    /// decoy-verified work, no session.
    #[tokio::test]
    async fn a_pending_account_fails_like_an_unknown_one() {
        let fixture = Fixture::new().await;
        sqlx::query("UPDATE users SET status = 'pending', password_hash = '' WHERE id = ?1")
            .bind(&fixture.user_id)
            .execute(&fixture.pool)
            .await
            .unwrap();

        let result = fixture.attempt("alice", &fixture.password).await;
        assert!(matches!(result, Err(LoginError::InvalidCredentials)));
        assert_eq!(
            store::count_sessions_for_user(&fixture.pool, &fixture.user_id)
                .await
                .unwrap(),
            0
        );
    }
}
