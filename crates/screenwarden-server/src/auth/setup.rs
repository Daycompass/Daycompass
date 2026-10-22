//! The one-time flow that creates the first admin account.
//!
//! An empty instance has no way to authenticate anybody, so it prints a
//! bootstrap token once at startup and accepts exactly one request that
//! redeems it. The moment an admin exists this whole flow is dead code:
//! the endpoint reports 404 and never looks at a token again.
//!
//! 404 rather than 403 is deliberate. A 403 would confirm that the
//! endpoint exists and that setup has been completed, which tells an
//! unauthenticated scanner something about the instance. 404 makes a
//! provisioned instance indistinguishable from one that never had the
//! route.

use std::time::Duration;

use sqlx::SqlitePool;

use super::password::{HashError, Hasher, Password, PasswordPolicyError};
use super::secret::SecretString;
use super::store::{self, FirstAdminOutcome, StoreError, UserRecord};
use super::time::UnixTime;
use super::token::{RngUnavailable, Token, TokenHash, TokenKind};
use super::username::{Username, UsernameError};

/// How long a printed setup token stays redeemable.
///
/// Not configurable: it is a bootstrap value with no operational reason
/// to differ between deployments, and a longer window is strictly worse
/// because the token sits in the container logs.
pub const SETUP_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

/// Why setup did not complete.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// An admin already exists. The endpoint turns this into a 404.
    #[error("setup has already been completed")]
    AlreadyCompleted,

    /// The token was malformed, unknown, expired, or already redeemed.
    /// One variant for all of those on purpose: distinguishing them
    /// would tell a caller whether a token ever existed.
    #[error("the setup token is not valid")]
    InvalidToken,

    #[error(transparent)]
    InvalidUsername(#[from] UsernameError),

    #[error(transparent)]
    InvalidPassword(#[from] PasswordPolicyError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Rng(#[from] RngUnavailable),
}

/// Issues a fresh setup token if the instance still has no admin.
///
/// Returns `Ok(None)` once an admin exists, which is the steady state
/// for every restart after the first.
///
/// Any token from an earlier run is deleted, so a line printed by a
/// previous start - still sitting in the logs - stops working. Only the
/// most recent printed token is live.
pub async fn issue_token_if_unprovisioned(
    pool: &SqlitePool,
    now: UnixTime,
) -> Result<Option<Token>, SetupError> {
    if store::admin_exists(pool).await? {
        // Housekeeping: drop anything left over from before setup
        // completed, so the table does not keep a redeemed hash forever.
        store::delete_stale_setup_tokens(pool, now).await?;
        return Ok(None);
    }

    let token = Token::generate(TokenKind::Setup)?;
    store::replace_setup_token(
        pool,
        &token.hash(),
        now,
        now.saturating_add(SETUP_TOKEN_TTL),
    )
    .await?;
    Ok(Some(token))
}

/// The line printed to stdout when a setup token is issued.
///
/// Written to stdout directly rather than through `tracing`, so it
/// cannot be swallowed by a log level or reshaped into JSON that an
/// operator then has to dig the value out of. It is the one thing a
/// first-time operator needs to see.
pub fn setup_instructions(token: &Token, public_url: &str) -> String {
    format!(
        "Screenwarden first-time setup: no admin account exists yet.\n\
         Create one within {minutes} minutes by sending this token, a username \
         and a password to POST {public_url}/api/v1/setup\n\
         Setup token: {token}\n\
         This token is single use. It appears in this process's output, so treat \
         these logs as sensitive until setup is complete.",
        minutes = SETUP_TOKEN_TTL.as_secs() / 60,
        token = token.expose(),
    )
}

/// Redeems `presented_token` and creates the first admin.
///
/// The order of work matters:
///
/// 1. The admin check comes **first**, before anything looks at the
///    input at all. Once an admin exists every call must answer
///    `AlreadyCompleted` - which the endpoint turns into a 404 - no
///    matter what was sent. Validating the token or the policies first
///    would make a provisioned instance answer 401 or 400 for
///    malformed input while a genuinely absent route answers 404, which
///    is exactly the leak the 404 is there to prevent.
/// 2. Then the username and password policies, because they are free.
/// 3. Then the token, as a cheap read, so a bad one is rejected before
///    any Argon2 work is spent on it.
/// 4. Only then is the password hashed.
/// 5. The authoritative write happens in a `BEGIN IMMEDIATE`
///    transaction that re-checks the admin and the token, so two
///    requests racing through the earlier steps still produce exactly
///    one admin.
///
/// Hashing deliberately happens outside the transaction: it takes tens
/// of milliseconds, and holding SQLite's write lock for that long would
/// stall every other writer.
pub async fn complete_setup(
    pool: &SqlitePool,
    hasher: &Hasher,
    presented_token: &SecretString,
    raw_username: &str,
    raw_password: SecretString,
    now: UnixTime,
) -> Result<UserRecord, SetupError> {
    // Before anything else, so a provisioned instance is uniformly a
    // 404 and this function's remaining logic really is dead code.
    if store::admin_exists(pool).await? {
        return Err(SetupError::AlreadyCompleted);
    }

    let username = Username::parse(raw_username)?;
    let password = Password::parse(raw_password)?;

    let token_hash = TokenHash::of_presented(TokenKind::Setup, presented_token.expose())
        .ok_or(SetupError::InvalidToken)?;

    if !store::setup_token_is_live(pool, &token_hash, now).await? {
        return Err(SetupError::InvalidToken);
    }

    let password_hash = hasher.hash(&password).await?;

    match store::insert_first_admin(pool, &token_hash, &username, &password_hash, now).await? {
        FirstAdminOutcome::Created => {}
        FirstAdminOutcome::AlreadyCompleted => return Err(SetupError::AlreadyCompleted),
        FirstAdminOutcome::TokenRejected => return Err(SetupError::InvalidToken),
    }

    // Read back rather than synthesizing the record, so the caller sees
    // exactly what was stored.
    store::find_user_by_username(pool, &username)
        .await?
        .ok_or(SetupError::Store(StoreError::CorruptRow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::password::HashingParams;
    use crate::auth::store::Credential;
    use crate::db::{self, DbTarget};

    /// Every credential in these tests is generated at runtime.
    fn random_secret() -> SecretString {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        SecretString::new(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ))
    }

    fn test_hasher() -> Hasher {
        Hasher::new(HashingParams::owasp_minimum(), 4, Duration::from_secs(30))
    }

    async fn memory_pool() -> SqlitePool {
        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");
        pool
    }

    /// A file-backed database in a fresh temporary directory, cleaned up
    /// on drop. Needed where real concurrency matters: the in-memory
    /// pool is capped at one connection, so concurrent callers would
    /// queue on the pool instead of contending for SQLite's write lock.
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
                "screenwarden-setup-test-{}-{unique}",
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

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    async fn complete(
        pool: &SqlitePool,
        token: &Token,
        username: &str,
        at: UnixTime,
    ) -> Result<UserRecord, SetupError> {
        complete_setup(
            pool,
            &test_hasher(),
            &SecretString::new(token.expose().to_owned()),
            username,
            random_secret(),
            at,
        )
        .await
    }

    #[tokio::test]
    async fn a_fresh_instance_issues_a_setup_token() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .expect("issuing must succeed")
            .expect("an unprovisioned instance must issue a token");

        assert_eq!(token.kind(), TokenKind::Setup);
        assert!(token.expose().starts_with("swb_"));
        assert!(store::setup_token_is_live(&pool, &token.hash(), now())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn only_the_hash_of_the_setup_token_is_stored() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();
        let plaintext = token.expose().to_owned();

        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM setup_tokens WHERE CAST(token_hash AS TEXT) LIKE '%swb_%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "no stored value may contain the token");

        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.len(), 32, "the column holds a SHA-256 digest");
        assert_ne!(stored, plaintext.as_bytes(), "not the token itself");
    }

    #[tokio::test]
    async fn restarting_invalidates_the_previously_printed_token() {
        let pool = memory_pool().await;
        let first = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();
        let second = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        assert_ne!(first.expose(), second.expose());
        assert!(
            !store::setup_token_is_live(&pool, &first.hash(), now())
                .await
                .unwrap(),
            "a token printed by an earlier run must stop working"
        );
        assert!(store::setup_token_is_live(&pool, &second.hash(), now())
            .await
            .unwrap());

        // And the stale one is really gone, not merely shadowed.
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn setup_creates_an_admin_and_then_reports_already_completed() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        let admin = complete(&pool, &token, "alice", now())
            .await
            .expect("setup must succeed");
        assert_eq!(admin.username.as_str(), "alice");
        assert!(admin.role.is_admin());
        assert!(matches!(
            &admin.credential,
            Credential::Password(hash) if hash.starts_with("$argon2id$")
        ));

        // A second attempt, even with a fresh token, is refused.
        let second = complete(&pool, &token, "bob", now()).await;
        assert!(
            matches!(second, Err(SetupError::AlreadyCompleted)),
            "got {second:?}"
        );

        // And no further token is ever issued.
        assert!(issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn the_username_is_normalized_before_it_is_stored() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        let admin = complete(&pool, &token, "  ALICE  ", now())
            .await
            .expect("setup must succeed");
        assert_eq!(admin.username.as_str(), "alice");

        let stored: String = sqlx::query_scalar("SELECT username FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, "alice");
    }

    #[tokio::test]
    async fn an_expired_setup_token_is_rejected() {
        let pool = memory_pool().await;
        let issued_at = now();
        let token = issue_token_if_unprovisioned(&pool, issued_at)
            .await
            .unwrap()
            .unwrap();

        // One second past the window.
        let too_late = issued_at.saturating_add(SETUP_TOKEN_TTL + Duration::from_secs(1));
        let result = complete(&pool, &token, "alice", too_late).await;
        assert!(
            matches!(result, Err(SetupError::InvalidToken)),
            "got {result:?}"
        );

        // Still valid at the last moment inside the window.
        let just_in_time = issued_at.saturating_add(SETUP_TOKEN_TTL - Duration::from_secs(1));
        assert!(complete(&pool, &token, "alice", just_in_time).await.is_ok());
    }

    #[tokio::test]
    async fn a_setup_token_cannot_be_reused_after_a_failed_attempt_succeeds() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        assert!(complete(&pool, &token, "alice", now()).await.is_ok());

        // The row is marked used, independently of the admin check.
        let used_at: Option<i64> = sqlx::query_scalar("SELECT used_at FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(used_at, Some(now().as_secs()));
        assert!(!store::setup_token_is_live(&pool, &token.hash(), now())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_wrong_or_malformed_token_is_rejected_identically() {
        let pool = memory_pool().await;
        issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        // A well-formed token that was never issued.
        let other = Token::generate(TokenKind::Setup).unwrap();
        // A session-prefixed token, which must not be accepted here.
        let wrong_kind = Token::generate(TokenKind::Session).unwrap();

        for candidate in [
            other.expose().to_owned(),
            wrong_kind.expose().to_owned(),
            String::new(),
            "swb_".to_owned(),
            "not-a-token".to_owned(),
        ] {
            let result = complete_setup(
                &pool,
                &test_hasher(),
                &SecretString::new(candidate.clone()),
                "alice",
                random_secret(),
                now(),
            )
            .await;
            assert!(
                matches!(result, Err(SetupError::InvalidToken)),
                "{candidate:?} must be InvalidToken, got {result:?}"
            );
        }

        let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 0, "no account may be created by a bad token");
    }

    #[tokio::test]
    async fn the_policies_are_enforced_before_the_token_is_spent() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();

        // Username too short.
        let result = complete(&pool, &token, "ab", now()).await;
        assert!(matches!(result, Err(SetupError::InvalidUsername(_))));

        // Password too short.
        let result = complete_setup(
            &pool,
            &test_hasher(),
            &SecretString::new(token.expose().to_owned()),
            "alice",
            SecretString::new("short".to_owned()),
            now(),
        )
        .await;
        assert!(matches!(result, Err(SetupError::InvalidPassword(_))));

        // The token survived both rejections and still works.
        assert!(store::setup_token_is_live(&pool, &token.hash(), now())
            .await
            .unwrap());
        assert!(complete(&pool, &token, "alice", now()).await.is_ok());
    }

    /// The whole point of `BEGIN IMMEDIATE`: concurrent callers must not
    /// both get past the "no admin exists" check. Uses a file-backed
    /// database so the requests really contend for the write lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_setup_requests_produce_exactly_one_admin() {
        let db = TempDb::new().await;
        let token = issue_token_if_unprovisioned(&db.pool, now())
            .await
            .unwrap()
            .unwrap();
        let token_value = token.expose().to_owned();

        let hasher = test_hasher();
        let mut tasks = Vec::new();
        for index in 0..6 {
            let pool = db.pool.clone();
            let hasher = hasher.clone();
            let token_value = token_value.clone();
            tasks.push(tokio::spawn(async move {
                complete_setup(
                    &pool,
                    &hasher,
                    &SecretString::new(token_value),
                    &format!("user{index}"),
                    random_secret(),
                    now(),
                )
                .await
            }));
        }

        let mut created = 0;
        let mut refused = 0;
        for task in tasks {
            match task.await.expect("no task may panic") {
                Ok(_) => created += 1,
                // Either the admin check or the token check caught it,
                // depending on which raced ahead; both are correct.
                Err(SetupError::AlreadyCompleted | SetupError::InvalidToken) => refused += 1,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }

        assert_eq!(created, 1, "exactly one request may succeed");
        assert_eq!(refused, 5);

        let (admins,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(admins, 1);
        let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(users, 1, "no second account may exist either");
    }

    /// Once an admin exists, every input must give the same answer.
    /// Reporting a malformed token or a bad username instead would tell
    /// an unauthenticated caller that this endpoint exists at all.
    #[tokio::test]
    async fn a_provisioned_instance_answers_already_completed_for_any_input() {
        let pool = memory_pool().await;
        let token = issue_token_if_unprovisioned(&pool, now())
            .await
            .unwrap()
            .unwrap();
        complete(&pool, &token, "alice", now())
            .await
            .expect("setup must succeed once");

        let session_token = Token::generate(TokenKind::Session).unwrap();
        let cases: [(&str, &str); 5] = [
            ("a well-formed but unknown token", "swb_x"),
            ("a session token", session_token.expose()),
            ("junk", "not-a-token"),
            ("nothing", ""),
            ("the token that worked", token.expose()),
        ];

        for (label, candidate) in cases {
            for username in ["bob", "x", "not a username!"] {
                let result = complete_setup(
                    &pool,
                    &test_hasher(),
                    &SecretString::new(candidate.to_owned()),
                    username,
                    random_secret(),
                    now(),
                )
                .await;
                assert!(
                    matches!(result, Err(SetupError::AlreadyCompleted)),
                    "{label} with username {username:?} must be AlreadyCompleted,                      got {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_printed_instructions_carry_the_token_and_the_endpoint() {
        let token = Token::generate(TokenKind::Setup).unwrap();
        let message = setup_instructions(&token, "https://example.org");

        assert!(message.contains(token.expose()));
        assert!(message.contains("https://example.org/api/v1/setup"));
        assert!(message.contains("60 minutes"));
        assert!(message.contains("single use"));
    }
}
