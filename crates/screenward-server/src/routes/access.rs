//! The layers that enforce a route's inventory entry, and the
//! extractors a handler reads the result with.
//!
//! Every protection in [`crate::routes::INVENTORY`] is applied here,
//! from the flags on the entry. Nothing in this module decides *which*
//! protection a route gets - that is the table's job - and no handler
//! can grant itself a session, because the only way to get one is to
//! read what the layer put on the request.
//!
//! Why layers rather than extractors alone: an extractor protects a
//! route only if the handler asks for it, and "the handler forgot" is
//! not a failure mode a table can rule out. A layer attached from the
//! entry protects the route whatever the handler does. The extractors
//! are still the second line - [`AdminContext`] re-checks the role it
//! was handed, and [`crate::auth::extract::AuthSession`] still enforces
//! CSRF on an unsafe method by itself - so a route reached by a path
//! that skipped a layer fails closed rather than open.
//!
//! The role is never cached. The layer resolves the session, and with it
//! the account row, on every single request, so an account demoted a
//! moment ago is an ordinary user on its very next request even though
//! its session is untouched.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::extract::{verify_csrf, AuthRejection, AuthSession};
use crate::auth::origin;
use crate::auth::time::UnixTime;
use crate::clientip::ClientAddr;
use crate::error::{ApiError, ErrorKind};
use crate::ratelimit::UserKey;
use crate::routes::{rate_limited, Access, Bucket, LimitKey, RouteSpec};
use crate::state::AppState;

/// What one route's enforcement layers are built with: the application
/// state, plus the entry being enforced.
type RouteState = (AppState, &'static RouteSpec);

/// Rejects a state-changing request whose `Origin` names someone else.
///
/// Attached per route from `origin_checked`. The rule itself lives in
/// [`crate::auth::origin`], which is where it is tested.
pub async fn enforce_origin(
    State((state, _spec)): State<RouteState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().get_all(axum::http::header::ORIGIN);
    let mut values = headers.iter();
    let first = values.next();

    // More than one Origin header is not something a browser does, and
    // picking one of several would be a way to smuggle the wrong answer
    // past this check.
    if values.next().is_some() {
        return reject_origin();
    }

    let origin = match first {
        None => None,
        Some(value) => match value.to_str() {
            Ok(text) => Some(text),
            // Present but not text: refuse rather than fall through to
            // the "absent" case, which is deliberately permissive.
            Err(_) => return reject_origin(),
        },
    };

    if !origin::is_allowed(request.method().as_str(), origin, &state.public_url) {
        return reject_origin();
    }

    next.run(request).await
}

/// The one response an Origin failure produces. The message does not
/// echo the offending value, and does not state the expected one.
fn reject_origin() -> Response {
    ApiError::of(ErrorKind::OriginMismatch).into_response()
}

/// Requires a session - and, where the entry says so, a CSRF token and
/// the admin role - then hands the resolved session to the handler.
///
/// The order is CSRF, then the session lookup, then the role. The CSRF
/// check needs only the two values the client sent, so a forged request
/// is refused without spending a query on it, and the outcome still
/// says nothing about whether the session is real.
pub async fn enforce_access(
    State((state, spec)): State<RouteState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    if spec.csrf {
        if let Err(rejection) = verify_csrf(&parts) {
            return rejection.into_response();
        }
    }

    let auth = match AuthSession::from_request_parts(&mut parts, &state).await {
        Ok(auth) => auth,
        Err(rejection) => return rejection.into_response(),
    };

    // Read from the record this request just resolved, never from
    // anything carried in the session or the cookie.
    if spec.access == Access::Admin && !auth.user.role.is_admin() {
        return AuthRejection::NotAnAdmin.into_response();
    }

    let mut request = Request::from_parts(parts, body);
    request.extensions_mut().insert(Arc::new(auth));
    next.run(request).await
}

/// Applies the layer-enforced limiters named in the entry.
///
/// Attached inside [`enforce_access`], so an account-keyed limit can key
/// on the session that layer resolved - and so a password change is
/// counted *before* it reaches the Argon2 semaphore, which is the point
/// of limiting it at all. Every request that gets this far counts,
/// whether or not it goes on to succeed.
pub async fn enforce_rate_limits(
    State((state, spec)): State<RouteState>,
    request: Request,
    next: Next,
) -> Response {
    let now = UnixTime::now();
    let (mut parts, body) = request.into_parts();

    for limit in spec.rate_limits {
        let decision = match (limit.bucket, limit.key) {
            (bucket, LimitKey::Peer) => {
                let client = match ClientAddr::from_request_parts(&mut parts, &state).await {
                    Ok(client) => client,
                    // No peer address means nothing can be counted;
                    // ClientAddr already logs and fails closed.
                    Err(rejection) => return rejection.into_response(),
                };
                let key = client.rate_limit_key();
                match bucket {
                    Bucket::LoginIp => state.limits.login_ip.check(key, now),
                    Bucket::SetupIp => state.limits.setup_ip.check(key, now),
                    _ => return unenforceable(*limit),
                }
            }
            (Bucket::PasswordUser, LimitKey::Account) => {
                let Some(auth) = parts.extensions.get::<Arc<AuthSession>>() else {
                    // Only reachable if the entry asked for an
                    // account-keyed limit without a session layer, which
                    // RouteSpec::validate refuses at startup.
                    tracing::error!("an account-keyed rate limit ran with no resolved session");
                    return ApiError::of(ErrorKind::InternalError).into_response();
                };
                state
                    .limits
                    .password_user
                    .check(UserKey::new(&auth.user.id), now)
            }
            // The handler owns this one: its key is in the request body.
            (_, LimitKey::Body) => continue,
            _ => return unenforceable(*limit),
        };

        if let Some(error) = rate_limited(decision) {
            return error.into_response();
        }
    }

    next.run(Request::from_parts(parts, body)).await
}

/// A bucket-and-key combination no layer knows how to apply.
///
/// Fails the request closed rather than letting it through unlimited: a
/// table entry claiming a limit that nothing enforces is a wiring bug,
/// and answering 500 is what makes it visible instead of silent.
fn unenforceable(limit: crate::routes::RateLimit) -> Response {
    tracing::error!(
        bucket = ?limit.bucket,
        key = ?limit.key,
        "no layer can enforce this rate limit combination"
    );
    ApiError::of(ErrorKind::InternalError).into_response()
}

/// The session [`enforce_access`] resolved for this request.
///
/// A handler cannot construct one: the only way to get it is to read
/// what the layer stored, and a route with no access layer therefore
/// fails closed with a 500 and a log line rather than running the
/// handler unauthenticated.
pub struct SessionContext(Arc<AuthSession>);

impl SessionContext {
    pub fn auth(&self) -> &AuthSession {
        &self.0
    }
}

impl FromRequestParts<AppState> for SessionContext {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<Arc<AuthSession>>() {
            Some(auth) => Ok(Self(Arc::clone(auth))),
            None => {
                tracing::error!(
                    "a handler asked for a session on a route with no access layer attached"
                );
                Err(AuthRejection::Unavailable)
            }
        }
    }
}

/// Like [`SessionContext`], and the account is an admin.
///
/// The role is re-checked here against the record resolved for this
/// request. [`enforce_access`] has already checked it for an
/// `Access::Admin` route; this is the second line, so a handler that
/// asks for admin rights gets them only if the account really has them
/// now, whatever the route was registered as.
pub struct AdminContext(Arc<AuthSession>);

impl AdminContext {
    pub fn auth(&self) -> &AuthSession {
        &self.0
    }
}

impl FromRequestParts<AppState> for AdminContext {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = SessionContext::from_request_parts(parts, state).await?;
        session.auth().require_admin()?;
        Ok(Self(session.0))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::handler::Handler;
    use axum::http::{Request as HttpRequest, StatusCode};

    use super::*;

    /// A handler asking for a session on a route that has no access
    /// layer must fail, not run. This is the fail-closed half of the
    /// table driving the layers: forgetting the entry's flag cannot
    /// produce an unauthenticated call into a handler that believes it
    /// is authenticated.
    ///
    /// The handlers are called directly rather than through a router,
    /// because registering a route anywhere but in
    /// [`crate::routes::RouteTable::add`] is what the inventory test
    /// forbids.
    #[tokio::test]
    async fn a_session_handler_without_its_layer_fails_closed() {
        async fn handler(_session: SessionContext) -> &'static str {
            "this must never be reached"
        }

        let response = handler.call(probe_request(), test_state().await).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn an_admin_handler_without_its_layer_fails_closed() {
        async fn handler(_admin: AdminContext) -> &'static str {
            "this must never be reached"
        }

        let response = handler.call(probe_request(), test_state().await).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn probe_request() -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/probe")
            .body(Body::empty())
            .expect("the request must be valid")
    }

    async fn test_state() -> AppState {
        use crate::config::Config;
        use crate::db::{self, DbTarget};

        let pool = db::connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        db::migrate(&pool).await.expect("migrations must apply");
        AppState::new(pool, &Config::defaults())
            .await
            .expect("building the state must succeed")
    }
}
