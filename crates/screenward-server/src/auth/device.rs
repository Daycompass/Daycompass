//! Device authentication: turning an `Authorization: Bearer` header
//! into a device.
//!
//! This lives under `src/auth/` rather than with the rest of the device
//! code because it is the authentication story for a second kind of
//! principal, and `CLAUDE.md` points here for those. The SQL it runs is
//! in [`crate::devices::store`].
//!
//! # Bearer only, and cookies are a refusal
//!
//! A device authenticates with a bearer token and nothing else. Two
//! rules make that mutual, and both are attached from the route
//! inventory rather than left to a handler:
//!
//! * A device route **refuses** any request carrying the Screenward
//!   session cookie, even one that also presents a valid token. It is
//!   the *Screenward* cookie specifically, not any cookie: a reverse
//!   proxy or CDN that attaches its own cookies must not break device
//!   authentication.
//! * A session route refuses any request carrying a bearer
//!   credential. That one is the second line - a device token could
//!   not be accepted as a session anyway, because the token prefix is
//!   part of what gets hashed and the two live in different tables -
//!   but a request that is confused about what it is should be
//!   refused rather than quietly reinterpreted.
//!
//! The scheme name is matched case-insensitively, per RFC 7235, which
//! says the auth-scheme token is case-insensitive. Matching only
//! `Bearer` would let `bearer` slip past the session-route refusal
//! above while still being accepted by every HTTP client in existence.
//!
//! # Revocation is not cached
//!
//! [`resolve`] reads the device row on every request and refuses a
//! revoked one. There is no cache, no expiry and nothing carried in
//! the token itself, so a revocation takes effect on the device's very
//! next call.
//!
//! # Why malformed tokens never reach the database
//!
//! `/api/v1/events` is rate limited per device, which means the
//! limiter cannot run until the device is known. An unauthenticated
//! caller is therefore bounded by nothing but the connection itself,
//! so the cheap checks come first: the prefix, the length and the
//! base64url shape are all verified in memory by
//! [`TokenHash::of_presented`], and only a token that could possibly
//! exist costs a query.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use sqlx::SqlitePool;

use super::store::StoreError;
use super::time::UnixTime;
use super::token::{TokenHash, TokenKind};
use crate::devices::store::{self as device_store, DeviceRecord};
use crate::error::{ApiError, ErrorKind};
use crate::state::AppState;

/// How stale `last_seen_at` may be before a request writes it again.
///
/// Same reasoning as the session equivalent: a write on every ingest
/// call would be a write per request for no benefit. The cost is that
/// the recorded time can lag by up to this much, which matters to
/// nothing - `last_seen_at` is shown to a person, never compared
/// against a limit.
pub const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

/// An authenticated device.
pub struct AuthDevice {
    pub device: DeviceRecord,
}

impl fmt::Debug for AuthDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ids and platform only. The name is something a person wrote
        // and can identify them, so it is kept out the way usernames
        // are.
        f.debug_struct("AuthDevice")
            .field("device_id", &self.device.id)
            .field("user_id", &self.device.user_id)
            .field("platform", &self.device.platform)
            .finish()
    }
}

/// Why a request was not accepted as a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRejection {
    /// No usable bearer token, or it named no live device. One variant
    /// for every cause - absent, malformed, unknown, revoked - because
    /// the distinction would tell a caller whether a token was ever
    /// valid, and in particular whether a device had been revoked
    /// rather than never existing.
    Unauthenticated,
    /// The device could not be looked up. Logged where it happens.
    Unavailable,
}

impl IntoResponse for DeviceRejection {
    fn into_response(self) -> Response {
        let kind = match self {
            Self::Unauthenticated => ErrorKind::Unauthenticated,
            Self::Unavailable => ErrorKind::InternalError,
        };
        ApiError::of(kind).into_response()
    }
}

/// The bearer credential on a request, if there is one.
///
/// Returns the token part of exactly one `Authorization` header whose
/// scheme is `Bearer`, compared case-insensitively. More than one such
/// header is treated as none at all - picking one of several would be
/// a way to smuggle a second credential past whatever looked at the
/// first, the same reasoning the duplicate `Origin` and duplicate
/// cookie rules follow.
pub fn presented_bearer(parts: &Parts) -> Option<&str> {
    let mut values = parts.headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }

    let text = first.to_str().ok()?;
    let (scheme, credential) = text.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

/// Whether the request carries any bearer credential at all.
///
/// Used by the access layer to refuse one on a session route. Looser
/// than [`presented_bearer`] on purpose: a duplicate or empty bearer
/// header is not a usable credential, but it is still a request that
/// is confused about how it authenticates, and the refusal should not
/// depend on the credential being well formed.
///
/// A non-bearer scheme - `Basic` from a reverse proxy, say - is not
/// matched, so infrastructure that attaches its own `Authorization`
/// header does not break session routes.
pub fn carries_bearer(parts: &Parts) -> bool {
    parts
        .headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|text| {
            text.split_once(' ')
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        })
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthError {
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Resolves a presented device token.
///
/// Returns `Ok(None)` for every way a token can fail to name a live
/// device - malformed, unknown, revoked - for the same reason
/// [`crate::auth::session::resolve`] does: the caller has no
/// legitimate use for the distinction.
///
/// Updates `last_seen_at` when the stored value is stale, and only
/// then.
pub async fn resolve(
    pool: &SqlitePool,
    presented_token: &str,
    now: UnixTime,
) -> Result<Option<DeviceRecord>, DeviceAuthError> {
    // In memory, before any query: the prefix, the length and a
    // canonical base64url body. An unauthenticated caller cannot spend
    // a query on a string that could not be a token.
    let Some(token_hash) = TokenHash::of_presented(TokenKind::Device, presented_token) else {
        return Ok(None);
    };

    let Some(device) = device_store::find_device_by_token_hash(pool, &token_hash).await? else {
        return Ok(None);
    };

    // Read from the row, every request, nothing cached.
    if !device.is_live() {
        return Ok(None);
    }

    let mut device = device;
    if now.saturating_duration_since(device.last_seen_at) >= TOUCH_INTERVAL {
        device_store::touch_device(pool, &device.id, now).await?;
        device.last_seen_at = now;
    }

    Ok(Some(device))
}

/// The device a route's access layer resolved for this request.
///
/// Holds a private field and is defined in the auth module, the same
/// arrangement that makes [`crate::auth::extract::SessionContext`]
/// unforgeable: no handler can build one, so a route registered
/// without the device layer fails closed with a 500 and a log line
/// rather than calling a handler that believes it is authenticated.
pub struct DeviceContext(Arc<AuthDevice>);

impl DeviceContext {
    pub fn device(&self) -> &DeviceRecord {
        &self.0.device
    }
}

impl FromRequestParts<AppState> for DeviceContext {
    type Rejection = DeviceRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<Arc<AuthDevice>>() {
            Some(auth) => Ok(Self(Arc::clone(auth))),
            None => {
                tracing::error!(
                    "a handler asked for a device on a route with no device layer attached"
                );
                Err(DeviceRejection::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::handler::Handler;
    use axum::http::StatusCode;

    use super::*;
    use crate::auth::token::Token;
    use crate::db::{self, DbTarget};
    use crate::devices::name::DeviceName;
    use crate::devices::platform::Platform;

    fn parts_with(headers: &[(&str, &str)]) -> Parts {
        let mut builder = axum::http::Request::builder().uri("/probe");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(axum::body::Body::empty())
            .expect("the request must be valid")
            .into_parts()
            .0
    }

    /// RFC 7235 makes the scheme token case-insensitive. Matching only
    /// the canonical spelling would let `bearer` past the refusal on
    /// session routes while every HTTP client still accepted it.
    #[test]
    fn the_bearer_scheme_is_matched_case_insensitively() {
        for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let parts = parts_with(&[("authorization", &format!("{scheme} swd_abc"))]);
            assert_eq!(
                presented_bearer(&parts),
                Some("swd_abc"),
                "{scheme} must be recognised"
            );
            assert!(carries_bearer(&parts), "{scheme} must count as a bearer");
        }
    }

    #[test]
    fn a_non_bearer_scheme_is_not_a_bearer_credential() {
        // A reverse proxy attaching Basic auth must not break a
        // session route, so this must not be seen as a bearer.
        for value in ["Basic dXNlcjpwdw==", "Digest realm=x", "Negotiate abc"] {
            let parts = parts_with(&[("authorization", value)]);
            assert_eq!(presented_bearer(&parts), None, "{value}");
            assert!(!carries_bearer(&parts), "{value}");
        }
    }

    #[test]
    fn a_malformed_authorization_header_yields_no_credential() {
        for value in ["", "Bearer", "Bearer ", "Bearer    ", "swd_abc"] {
            let parts = parts_with(&[("authorization", value)]);
            assert_eq!(presented_bearer(&parts), None, "{value:?}");
        }
    }

    /// Two credentials is not something a legitimate client sends, and
    /// choosing one of them would be a way to smuggle the other past
    /// whatever inspected the first.
    #[test]
    fn two_authorization_headers_yield_no_credential() {
        let parts = parts_with(&[
            ("authorization", "Bearer swd_one"),
            ("authorization", "Bearer swd_two"),
        ]);
        assert_eq!(presented_bearer(&parts), None);
        // Still a request that is confused about how it authenticates,
        // so a session route must still refuse it.
        assert!(carries_bearer(&parts));
    }

    #[test]
    fn no_authorization_header_is_no_credential() {
        let parts = parts_with(&[]);
        assert_eq!(presented_bearer(&parts), None);
        assert!(!carries_bearer(&parts));
    }

    async fn pool_with_device() -> (SqlitePool, Token, String) {
        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");

        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'placeholder-not-a-hash', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");

        // Inserted directly rather than through the pairing flow: this
        // module is about what a token resolves to, and going through
        // a code would make these tests fail for reasons that belong
        // to `devices::service`.
        let token = Token::generate(TokenKind::Device).expect("the OS CSPRNG must be available");
        let device_id = "device-1".to_owned();
        sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES (?1, 'u1', 'laptop', 'linux', ?2, 1000, 1000)",
        )
        .bind(&device_id)
        .bind(token.hash().as_bytes())
        .execute(&pool)
        .await
        .expect("inserting a device must succeed");

        (pool, token, device_id)
    }

    #[tokio::test]
    async fn a_live_device_resolves_from_its_token() {
        let (pool, token, device_id) = pool_with_device().await;

        let resolved = resolve(&pool, token.expose(), UnixTime::from_secs(1_000))
            .await
            .expect("the lookup must succeed")
            .expect("a live device must resolve");
        assert_eq!(resolved.id, device_id);
        assert!(resolved.is_live());
    }

    #[tokio::test]
    async fn a_malformed_token_resolves_to_nothing() {
        let (pool, token, _id) = pool_with_device().await;
        let body = &token.expose()[4..];

        for candidate in [
            String::new(),
            "swd_".to_owned(),
            body.to_owned(),
            // The right body under the session prefix: the prefix is
            // part of the hash, so this is a different token.
            format!("sws_{body}"),
            format!("swd_{}", &body[..42]),
            format!("swd_{body}X"),
        ] {
            assert!(
                resolve(&pool, &candidate, UnixTime::from_secs(1_000))
                    .await
                    .expect("the lookup must succeed")
                    .is_none(),
                "{candidate:?} must not resolve"
            );
        }
    }

    #[tokio::test]
    async fn a_revoked_device_stops_resolving_immediately() {
        let (pool, token, device_id) = pool_with_device().await;

        sqlx::query("UPDATE devices SET revoked_at = 1001 WHERE id = ?1")
            .bind(&device_id)
            .execute(&pool)
            .await
            .expect("revoking must succeed");

        assert!(
            resolve(&pool, token.expose(), UnixTime::from_secs(1_002))
                .await
                .expect("the lookup must succeed")
                .is_none(),
            "a revoked device must not resolve"
        );
    }

    /// `last_seen_at` is written at most once per interval, so an
    /// ingest-heavy client does not turn every request into a write.
    #[tokio::test]
    async fn last_seen_at_is_written_at_most_once_per_interval() {
        let (pool, token, device_id) = pool_with_device().await;

        async fn last_seen(pool: &SqlitePool, id: &str) -> i64 {
            sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE id = ?1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("the device must exist")
        }

        assert_eq!(last_seen(&pool, &device_id).await, 1_000);

        // One second later: too soon, nothing written.
        resolve(&pool, token.expose(), UnixTime::from_secs(1_001))
            .await
            .unwrap()
            .expect("still live");
        assert_eq!(last_seen(&pool, &device_id).await, 1_000);

        // One second before the interval ends: still nothing.
        resolve(&pool, token.expose(), UnixTime::from_secs(1_059))
            .await
            .unwrap()
            .expect("still live");
        assert_eq!(last_seen(&pool, &device_id).await, 1_000);

        // Exactly at the interval: written.
        resolve(&pool, token.expose(), UnixTime::from_secs(1_060))
            .await
            .unwrap()
            .expect("still live");
        assert_eq!(last_seen(&pool, &device_id).await, 1_060);
    }

    #[test]
    fn debug_output_names_the_device_but_not_its_name() {
        let device = DeviceRecord {
            id: "device-1".to_owned(),
            user_id: "user-1".to_owned(),
            name: DeviceName::parse("Mika's Laptop").unwrap(),
            platform: Platform::Linux,
            created_at: UnixTime::from_secs(0),
            last_seen_at: UnixTime::from_secs(0),
            revoked_at: None,
        };
        let rendered = format!("{:?}", AuthDevice { device });

        assert!(rendered.contains("device-1"));
        assert!(rendered.contains("user-1"));
        assert!(
            !rendered.contains("Mika"),
            "a device name identifies a person and stays out of logs"
        );
    }

    /// A handler asking for a device on a route whose entry attached no
    /// device layer must fail, not run.
    #[tokio::test]
    async fn a_device_handler_without_its_layer_fails_closed() {
        async fn handler(_device: DeviceContext) -> &'static str {
            "this must never be reached"
        }

        let request = axum::http::Request::builder()
            .uri("/probe")
            .body(axum::body::Body::empty())
            .expect("the request must be valid");

        let pool = db::connect(&DbTarget::Memory).await.expect("connect");
        db::migrate(&pool).await.expect("migrate");
        let state = AppState::new(pool, &crate::config::Config::defaults())
            .await
            .expect("building the state must succeed");

        let response = handler.call(request, state).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
