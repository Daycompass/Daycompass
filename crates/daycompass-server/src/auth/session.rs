//! Login sessions: creating them, resolving one from a cookie, ending
//! one, and sweeping the expired ones.
//!
//! Two independent timeouts apply. The *absolute* one is fixed when the
//! session is created and stored as `expires_at`, so a session cannot be
//! kept alive indefinitely by using it. The *idle* one is measured from
//! `last_used_at`, so an unused session dies sooner. A session must
//! satisfy both to be accepted.

use std::time::Duration;

use sqlx::SqlitePool;

use super::csrf;
use super::store::{self, SessionRecord, StoreError, UserRecord};
use super::time::UnixTime;
use super::token::{RngUnavailable, Token, TokenHash, TokenKind};

/// How stale `last_used_at` must be before a request writes it again.
///
/// Updating it on every request would mean a database write per request
/// for no benefit; the idle window is measured in days. The cost is that
/// a session's recorded last use can lag reality by up to this much,
/// which only ever makes the idle timeout fire slightly early.
const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

/// The two timeouts governing a session's life, from configuration.
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
}

/// A session that was just created.
///
/// The two token values exist only here and in the response that carries
/// them to the client; the server keeps a hash of the first and nothing
/// at all of the second.
pub struct NewSession {
    /// Goes into the `__Host-dcs` cookie.
    pub token: Token,
    /// Goes into the response body for the client to echo back in
    /// `X-CSRF-Token`.
    pub csrf_token: String,
    pub record: SessionRecord,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Rng(#[from] RngUnavailable),
}

/// Creates a new session for `user_id`.
///
/// Always a new row with a new token: a login never reuses or refreshes
/// an existing session. That keeps a stolen token from being extended by
/// the victim's own later login, and makes "log in again" a reliable way
/// to get a clean session.
pub async fn create(
    pool: &SqlitePool,
    user_id: &str,
    policy: SessionPolicy,
    now: UnixTime,
) -> Result<NewSession, SessionError> {
    let token = Token::generate(TokenKind::Session)?;
    let csrf_token = csrf::derive(token.expose());

    let record = SessionRecord {
        id: store::new_id(),
        user_id: user_id.to_owned(),
        created_at: now,
        last_used_at: now,
        expires_at: now.saturating_add(policy.absolute_timeout),
    };

    store::insert_session(pool, &record, &token.hash()).await?;

    Ok(NewSession {
        token,
        csrf_token,
        record,
    })
}

/// An authenticated session and the account it belongs to.
#[derive(Debug, Clone)]
pub struct ResolvedSession {
    pub session: SessionRecord,
    pub user: UserRecord,
}

/// Resolves a presented session token.
///
/// Returns `Ok(None)` for every way a token can fail to identify a live
/// session - malformed, unknown, expired, idle too long - because a
/// caller has no legitimate use for the distinction and reporting it
/// would tell an attacker whether a token was ever valid.
///
/// A session found to be expired is deleted on the spot. The background
/// sweep exists so that sessions nobody presents are also cleaned up,
/// not as the only thing that enforces expiry.
pub async fn resolve(
    pool: &SqlitePool,
    presented_token: &str,
    policy: SessionPolicy,
    now: UnixTime,
) -> Result<Option<ResolvedSession>, SessionError> {
    let Some(token_hash) = TokenHash::of_presented(TokenKind::Session, presented_token) else {
        return Ok(None);
    };

    let Some((session, user)) = store::find_session_with_user(pool, &token_hash).await? else {
        return Ok(None);
    };

    if is_expired(&session, policy, now) {
        store::delete_session(pool, &session.id).await?;
        return Ok(None);
    }

    // Only write when the recorded time is actually stale, to keep this
    // from being a database write on every authenticated request.
    let mut session = session;
    if now.saturating_duration_since(session.last_used_at) >= TOUCH_INTERVAL {
        store::touch_session(pool, &session.id, now).await?;
        session.last_used_at = now;
    }

    Ok(Some(ResolvedSession { session, user }))
}

/// True if `session` has passed either timeout.
///
/// A session whose `last_used_at` lies in the future - a clock that
/// jumped backwards - is treated as not idle rather than as expired,
/// because `saturating_duration_since` reports zero for it. Erring
/// towards keeping the session matches what the absolute timeout already
/// guarantees: it still ends at `expires_at`.
fn is_expired(session: &SessionRecord, policy: SessionPolicy, now: UnixTime) -> bool {
    if now >= session.expires_at {
        return true;
    }
    now.saturating_duration_since(session.last_used_at) >= policy.idle_timeout
}

/// Ends one session server side.
pub async fn end(pool: &SqlitePool, session_id: &str) -> Result<(), SessionError> {
    store::delete_session(pool, session_id).await?;
    Ok(())
}

/// Deletes every session that has passed either timeout, plus any setup
/// or invite token that is spent or expired.
///
/// Returns how many rows went away, for the log line.
pub async fn sweep_expired(
    pool: &SqlitePool,
    policy: SessionPolicy,
    now: UnixTime,
) -> Result<u64, SessionError> {
    let idle_cutoff = now.saturating_sub(policy.idle_timeout);
    let sessions = store::delete_expired_sessions(pool, now, idle_cutoff).await?;
    let setup_tokens = store::delete_stale_setup_tokens(pool, now).await?;
    let invite_tokens = store::delete_stale_invite_tokens(pool, now).await?;
    Ok(sessions + setup_tokens + invite_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, DbTarget};

    fn policy() -> SessionPolicy {
        SessionPolicy {
            idle_timeout: Duration::from_secs(600),
            absolute_timeout: Duration::from_secs(3_600),
        }
    }

    fn now() -> UnixTime {
        UnixTime::from_secs(1_800_000_000)
    }

    async fn pool_with_user() -> (SqlitePool, String) {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");

        let id = store::new_id();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES (?1, 'alice', 'placeholder-not-a-hash', 'user', 0)",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");
        (pool, id)
    }

    #[tokio::test]
    async fn creating_a_session_stores_only_the_token_hash() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        assert!(created.token.expose().starts_with("dcs_"));
        assert_eq!(created.record.created_at, now());
        assert_eq!(created.record.last_used_at, now());
        assert_eq!(
            created.record.expires_at,
            now().saturating_add(policy().absolute_timeout)
        );

        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.len(), 32);
        assert_ne!(stored, created.token.expose().as_bytes());

        // The CSRF token is derived, never stored.
        assert_eq!(created.csrf_token, csrf::derive(created.token.expose()));
    }

    #[tokio::test]
    async fn a_valid_token_resolves_to_its_session_and_user() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        let resolved = resolve(&pool, created.token.expose(), policy(), now())
            .await
            .unwrap()
            .expect("a fresh session must resolve");
        assert_eq!(resolved.session.id, created.record.id);
        assert_eq!(resolved.user.id, user_id);
        assert_eq!(resolved.user.username.as_str(), "alice");
    }

    #[tokio::test]
    async fn every_creation_yields_a_distinct_session() {
        let (pool, user_id) = pool_with_user().await;
        let first = create(&pool, &user_id, policy(), now()).await.unwrap();
        let second = create(&pool, &user_id, policy(), now()).await.unwrap();

        assert_ne!(first.token.expose(), second.token.expose());
        assert_ne!(first.record.id, second.record.id);
        assert_ne!(first.csrf_token, second.csrf_token);
        // Both remain valid: creating one session must not end another.
        assert!(resolve(&pool, first.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_some());
        assert!(resolve(&pool, second.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn an_unknown_or_malformed_token_does_not_resolve() {
        let (pool, user_id) = pool_with_user().await;
        create(&pool, &user_id, policy(), now()).await.unwrap();

        let never_issued = Token::generate(TokenKind::Session).unwrap();
        let wrong_kind = Token::generate(TokenKind::Setup).unwrap();

        for candidate in [
            never_issued.expose().to_owned(),
            wrong_kind.expose().to_owned(),
            String::new(),
            "dcs_".to_owned(),
            "garbage".to_owned(),
        ] {
            assert!(
                resolve(&pool, &candidate, policy(), now())
                    .await
                    .unwrap()
                    .is_none(),
                "{candidate:?} must not resolve"
            );
        }
    }

    #[tokio::test]
    async fn a_session_past_its_absolute_lifetime_is_rejected_and_deleted() {
        let (pool, user_id) = pool_with_user().await;
        // Idle window as long as the absolute one, so the absolute
        // bound is what this test actually exercises. With the shorter
        // default idle window the session would be refused for being
        // idle long before reaching expires_at.
        let policy = SessionPolicy {
            idle_timeout: Duration::from_secs(3_600),
            absolute_timeout: Duration::from_secs(3_600),
        };
        let created = create(&pool, &user_id, policy, now()).await.unwrap();

        // Still valid one second before the hard end.
        let just_before = created
            .record
            .expires_at
            .saturating_sub(Duration::from_secs(1));
        assert!(resolve(&pool, created.token.expose(), policy, just_before)
            .await
            .unwrap()
            .is_some());

        // Rejected exactly at the boundary.
        let at_expiry = created.record.expires_at;
        assert!(resolve(&pool, created.token.expose(), policy, at_expiry)
            .await
            .unwrap()
            .is_none());

        // And the row is gone, not merely refused.
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_session_idle_too_long_is_rejected_and_deleted() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        // Idle for exactly the window: rejected, while still inside the
        // absolute lifetime, which proves the two timeouts are separate.
        let idled_out = now().saturating_add(policy().idle_timeout);
        assert!(idled_out < created.record.expires_at);
        assert!(resolve(&pool, created.token.expose(), policy(), idled_out)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            0
        );
    }

    /// Using a session keeps it alive against the idle timeout but not
    /// against the absolute one.
    #[tokio::test]
    async fn using_a_session_defers_only_the_idle_timeout() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        // Use it repeatedly, each time just inside the idle window.
        let mut at = now();
        for _ in 0..5 {
            at = at.saturating_add(policy().idle_timeout - Duration::from_secs(1));
            if at >= created.record.expires_at {
                break;
            }
            assert!(
                resolve(&pool, created.token.expose(), policy(), at)
                    .await
                    .unwrap()
                    .is_some(),
                "an actively used session must stay valid"
            );
        }

        // Past the absolute lifetime it ends regardless of use.
        let past_absolute = created
            .record
            .expires_at
            .saturating_add(Duration::from_secs(1));
        assert!(
            resolve(&pool, created.token.expose(), policy(), past_absolute)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `last_used_at` is only written when it is actually stale, so an
    /// authenticated request is not also a database write.
    #[tokio::test]
    async fn last_used_at_is_written_only_when_stale() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        async fn stored_last_used(pool: &SqlitePool) -> i64 {
            sqlx::query_scalar("SELECT last_used_at FROM sessions")
                .fetch_one(pool)
                .await
                .unwrap()
        }

        // A request one second later leaves the column alone.
        let soon = now().saturating_add(Duration::from_secs(1));
        resolve(&pool, created.token.expose(), policy(), soon)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_last_used(&pool).await, now().as_secs());

        // One past the touch interval writes it.
        let later = now().saturating_add(TOUCH_INTERVAL);
        resolve(&pool, created.token.expose(), policy(), later)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_last_used(&pool).await, later.as_secs());
    }

    #[tokio::test]
    async fn ending_a_session_stops_it_resolving() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        end(&pool, &created.record.id).await.unwrap();

        assert!(resolve(&pool, created.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            0
        );
    }

    /// A session row pointing at a non-active account must not resolve,
    /// enforced in the SQL `find_session_with_user` runs rather than
    /// left to a check afterwards. No known path leaves such a row
    /// behind today - a reset deletes every session in the same
    /// transaction that clears the password - so the state is forced
    /// directly, the way `deleting_the_user_removes_their_sessions`
    /// below forces the account's own disappearance.
    #[tokio::test]
    async fn a_session_for_a_non_active_account_does_not_resolve() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        sqlx::query("UPDATE users SET status = 'pending' WHERE id = ?1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(resolve(&pool, created.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn the_sweep_removes_expired_sessions_but_keeps_live_ones() {
        let (pool, user_id) = pool_with_user().await;
        let live = create(&pool, &user_id, policy(), now()).await.unwrap();

        // A session created long enough ago to be past both timeouts.
        let stale_at = now().saturating_sub(Duration::from_secs(100_000));
        let stale = create(&pool, &user_id, policy(), stale_at).await.unwrap();

        let removed = sweep_expired(&pool, policy(), now()).await.unwrap();
        assert!(removed >= 1);

        assert!(resolve(&pool, live.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_some());
        assert!(resolve(&pool, stale.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store::count_sessions_for_user(&pool, &user_id)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn the_sweep_also_removes_spent_and_expired_setup_tokens() {
        let (pool, _user_id) = pool_with_user().await;
        let token = Token::generate(TokenKind::Setup).unwrap();
        store::replace_setup_token(
            &pool,
            &token.hash(),
            now(),
            now().saturating_add(Duration::from_secs(60)),
        )
        .await
        .unwrap();

        // Before expiry the sweep leaves it alone.
        sweep_expired(&pool, policy(), now()).await.unwrap();
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);

        // After expiry it goes.
        sweep_expired(
            &pool,
            policy(),
            now().saturating_add(Duration::from_secs(120)),
        )
        .await
        .unwrap();
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[tokio::test]
    async fn the_sweep_also_removes_spent_and_expired_invite_tokens() {
        let (pool, user_id) = pool_with_user().await;
        let token = Token::generate(TokenKind::Invite).unwrap();
        sqlx::query(
            "INSERT INTO invite_tokens (id, user_id, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(store::new_id())
        .bind(&user_id)
        .bind(token.hash().as_bytes())
        .bind(now().as_secs())
        .bind(now().saturating_add(Duration::from_secs(60)).as_secs())
        .execute(&pool)
        .await
        .unwrap();

        // Before expiry the sweep leaves it alone.
        sweep_expired(&pool, policy(), now()).await.unwrap();
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);

        // After expiry it goes.
        sweep_expired(
            &pool,
            policy(),
            now().saturating_add(Duration::from_secs(120)),
        )
        .await
        .unwrap();
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invite_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    /// Deleting the account must take its sessions with it, so a
    /// resolved session can never outlive the user it names.
    #[tokio::test]
    async fn deleting_the_user_removes_their_sessions() {
        let (pool, user_id) = pool_with_user().await;
        let created = create(&pool, &user_id, policy(), now()).await.unwrap();

        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(resolve(&pool, created.token.expose(), policy(), now())
            .await
            .unwrap()
            .is_none());
    }
}
