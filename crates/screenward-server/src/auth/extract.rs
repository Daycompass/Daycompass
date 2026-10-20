//! The authentication extractor.
//!
//! Asking for an [`AuthSession`] in a handler is the only way to reach
//! an authenticated user, and it performs the CSRF check itself. That is
//! deliberate: a handler cannot accidentally accept a cookie-
//! authenticated state-changing request without CSRF protection,
//! because the same thing that gives it the user also enforces it.
//!
//! The `Origin` check is separate, in [`crate::middleware`], because it
//! applies to requests that have no session yet - login above all.

use std::fmt;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use super::store::{SessionRecord, UserRecord};
use super::time::UnixTime;
use super::{cookie, csrf, origin, session};
use crate::error::{ApiError, ErrorKind};
use crate::state::AppState;

/// Header a client echoes its CSRF token back in.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// An authenticated request: a live session and the account it belongs
/// to.
pub struct AuthSession {
    pub session: SessionRecord,
    pub user: UserRecord,
    /// Kept so [`AuthSession::csrf_token`] can re-derive the CSRF token
    /// without a handler ever touching the session token itself.
    session_token: super::secret::SecretString,
}

impl AuthSession {
    /// The CSRF token belonging to this session.
    ///
    /// Derived on demand rather than stored, which is what makes it
    /// identical across reloads and tabs.
    pub fn csrf_token(&self) -> String {
        csrf::derive(self.session_token.expose())
    }

    /// Returns the user if they are an admin, otherwise a rejection that
    /// becomes a 403.
    ///
    /// No endpoint calls this yet - admin-only routes are a later
    /// milestone - so it is covered by its own tests rather than through
    /// a request.
    pub fn require_admin(&self) -> Result<&UserRecord, AuthRejection> {
        if self.user.role.is_admin() {
            Ok(&self.user)
        } else {
            Err(AuthRejection::NotAnAdmin)
        }
    }
}

impl fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The session token must not appear even here; SecretString
        // redacts itself, and this impl is written out so that stays
        // true if a field is added.
        f.debug_struct("AuthSession")
            .field("session_id", &self.session.id)
            .field("user_id", &self.user.id)
            .field("role", &self.user.role)
            .field("session_token", &self.session_token)
            .finish()
    }
}

/// Why a request was not accepted as authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRejection {
    /// No usable cookie, or it named no live session. One variant for
    /// every cause - absent, malformed, unknown, expired, idled out -
    /// because the distinction would tell a caller whether a token was
    /// ever valid.
    Unauthenticated,
    /// A state-changing request arrived without a CSRF token.
    CsrfMissing,
    /// The CSRF token did not match the session.
    CsrfInvalid,
    /// Authenticated, but not an admin.
    NotAnAdmin,
    /// The session could not be looked up. Logged where it happens.
    Unavailable,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let kind = match self {
            Self::Unauthenticated => ErrorKind::Unauthenticated,
            // Naming which half failed is safe: the client knows what it
            // sent, and a hostile page cannot read either response.
            Self::CsrfMissing => ErrorKind::CsrfTokenMissing,
            Self::CsrfInvalid => ErrorKind::CsrfTokenInvalid,
            Self::NotAnAdmin => ErrorKind::NotPermitted,
            Self::Unavailable => ErrorKind::InternalError,
        };
        ApiError::of(kind).into_response()
    }
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok());
        let token = cookie::read(cookies)
            .ok_or(AuthRejection::Unauthenticated)?
            .to_owned();

        // CSRF before the database lookup. The check needs only the two
        // values the client sent, so a forged request is refused without
        // spending a query on it - and the outcome still says nothing
        // about whether the session is real.
        if !origin::is_safe_method(parts.method.as_str()) {
            let presented = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthRejection::CsrfMissing)?;
            if !csrf::verify(&token, presented) {
                return Err(AuthRejection::CsrfInvalid);
            }
        }

        let resolved = session::resolve(&state.pool, &token, state.session_policy, UnixTime::now())
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "could not resolve a session");
                AuthRejection::Unavailable
            })?
            .ok_or(AuthRejection::Unauthenticated)?;

        Ok(Self {
            session: resolved.session,
            user: resolved.user,
            session_token: super::secret::SecretString::new(token),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::auth::role::Role;
    use crate::auth::secret::SecretString;
    use crate::auth::token::{Token, TokenKind};
    use crate::auth::username::Username;

    /// Builds an [`AuthSession`] directly. No admin-only endpoint exists
    /// yet - those are a later milestone - so the role helper is covered
    /// here rather than through a request.
    fn auth_session(role: Role) -> (AuthSession, Token) {
        let token = Token::generate(TokenKind::Session).expect("CSPRNG must be available");
        let session = SessionRecord {
            id: "session-1".to_owned(),
            user_id: "user-1".to_owned(),
            created_at: UnixTime::from_secs(0),
            last_used_at: UnixTime::from_secs(0),
            expires_at: UnixTime::from_secs(i64::MAX),
        };
        let user = UserRecord {
            id: "user-1".to_owned(),
            username: Username::parse("alice").expect("a valid username"),
            password_hash: "placeholder-not-a-hash".to_owned(),
            role,
            created_at: UnixTime::from_secs(0),
        };
        let auth = AuthSession {
            session,
            user,
            session_token: SecretString::new(token.expose().to_owned()),
        };
        (auth, token)
    }

    #[test]
    fn require_admin_accepts_an_admin() {
        let (auth, _token) = auth_session(Role::Admin);
        let user = auth.require_admin().expect("an admin must be accepted");
        assert_eq!(user.id, "user-1");
    }

    #[test]
    fn require_admin_rejects_an_ordinary_user() {
        let (auth, _token) = auth_session(Role::User);
        assert!(matches!(
            auth.require_admin(),
            Err(AuthRejection::NotAnAdmin)
        ));
    }

    /// The rejection must be a 403, not a 404 or a 401: the caller is
    /// authenticated, they simply may not do this.
    #[test]
    fn the_admin_rejection_is_a_forbidden_response() {
        let response = AuthRejection::NotAnAdmin.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn each_rejection_maps_to_its_status() {
        for (rejection, expected) in [
            (AuthRejection::Unauthenticated, StatusCode::UNAUTHORIZED),
            (AuthRejection::CsrfMissing, StatusCode::FORBIDDEN),
            (AuthRejection::CsrfInvalid, StatusCode::FORBIDDEN),
            (AuthRejection::NotAnAdmin, StatusCode::FORBIDDEN),
            (
                AuthRejection::Unavailable,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(
                rejection.into_response().status(),
                expected,
                "{rejection:?}"
            );
        }
    }

    /// The CSRF token a handler sees must be the one derived from the
    /// session cookie, so a reload and a second tab agree.
    #[test]
    fn the_csrf_token_is_derived_from_the_session_token() {
        let (auth, token) = auth_session(Role::User);
        assert_eq!(auth.csrf_token(), csrf::derive(token.expose()));
        assert_eq!(auth.csrf_token(), auth.csrf_token());
    }

    #[test]
    fn debug_output_does_not_leak_the_session_token() {
        let (auth, token) = auth_session(Role::Admin);
        let debug = format!("{auth:?}");
        let body = &token.expose()[4..];

        assert!(!debug.contains(body), "the session token must not appear");
        assert!(debug.contains("[redacted]"));
        // The non-secret identifiers are useful and safe to show.
        assert!(debug.contains("user-1"));
        assert!(debug.contains("session-1"));
    }
}
