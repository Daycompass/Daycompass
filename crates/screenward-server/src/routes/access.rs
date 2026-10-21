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
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::device::{self, AuthDevice, DeviceRejection};
use crate::auth::extract::{verify_csrf, AuthRejection, AuthSession};
use crate::auth::time::UnixTime;
use crate::auth::{cookie, origin};
use crate::clientip::ClientAddr;
use crate::error::{ApiError, ErrorKind};
use crate::ratelimit::{DeviceKey, GlobalKey, SessionKey};
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
pub async fn enforce_session_access(
    State((state, spec)): State<RouteState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    // A session route authenticates by cookie, so a bearer credential
    // on it is a request that is confused about what it is. Refused
    // rather than ignored.
    //
    // This is the second line, not the first: a device token could not
    // be accepted as a session anyway, because the token prefix is
    // part of what gets hashed and the two kinds live in different
    // tables. The scheme is matched case-insensitively, so `bearer`
    // does not slip past; see `crate::auth::device`.
    //
    // Deliberately only the `Bearer` scheme. A reverse proxy or CDN
    // that attaches `Basic` credentials of its own must not break
    // every session route.
    if device::carries_bearer(&parts) {
        return AuthRejection::Unauthenticated.into_response();
    }

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

/// Requires a paired, unrevoked device, then hands it to the handler.
///
/// Attached from an [`Access::Device`] entry. The two cross-credential
/// rules it enforces are the mirror image of the bearer refusal above,
/// and both are documented in [`crate::auth::device`].
///
/// # The pre-authentication limiter
///
/// This layer also enforces the route's
/// [`LimitKey::PeerBeforeAuth`] limit, which the shared rate-limit
/// layer cannot: the policy is *peek, then charge only on failure*,
/// and `RateLimiter::check` counts and decides in one call.
///
/// The order below is what makes it worth having. The peek happens
/// first, before the cookie check, before the bearer is parsed and
/// before any query - so a caller who is already out of budget costs
/// one hash-map lookup and nothing else. Every path that refuses the
/// request then charges the bucket; the path that succeeds does not,
/// so a working device never spends from it however much it syncs.
///
/// A database *error* does not charge. That is this server failing,
/// not the caller misbehaving, and charging for it would let a
/// database wobble lock out the clients that happened to be syncing.
pub async fn enforce_device_access(
    State((state, _spec)): State<RouteState>,
    request: Request,
    next: Next,
) -> Response {
    let now = UnixTime::now();
    let (mut parts, body) = request.into_parts();

    // Fail closed if the client address cannot be resolved. Without it
    // there is no key to count against, and letting the request
    // through unlimited is exactly the hole this layer exists to
    // close. `ClientAddr` already logs and answers 500; the important
    // part is that the request stops here rather than reaching the
    // lookup uncounted.
    let client = match ClientAddr::from_request_parts(&mut parts, &state).await {
        Ok(client) => client,
        Err(rejection) => return rejection.into_response(),
    };
    let peer = client.rate_limit_key();

    // Read-only, and before everything. An exhausted bucket answers
    // 429 with a Retry-After and never touches the database.
    if let Some(error) = rate_limited(state.limits.device_auth_fail.peek(&peer, now)) {
        return error.into_response();
    }

    // Charges the failure bucket and produces the one refusal every
    // kind of authentication failure shares.
    let refuse = || {
        state.limits.device_auth_fail.check(peer, now);
        DeviceRejection::Unauthenticated.into_response()
    };

    // A device route refuses any request carrying the Screenward
    // session cookie, even one that also presents a valid token. A
    // device is a different principal with a different credential, and
    // a request arriving with both is not something a native client
    // does.
    //
    // It charges the bucket like any other failure: the budget is per
    // address, and a browser that reaches a device route is a client
    // with a bug, spending its own address's budget.
    //
    // `cookie::is_present` rather than `cookie::read(..).is_some()`:
    // `read` returns `None` for a *duplicated* cookie, so two copies
    // of it would otherwise be a way to slip past this refusal.
    //
    // And it is this one cookie, never "any cookie" - a proxy or CDN
    // attaching its own must not break device authentication.
    let cookies = parts
        .headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok());
    if cookie::is_present(cookies) {
        return refuse();
    }

    let Some(presented) = device::presented_bearer(&parts) else {
        return refuse();
    };

    // The shape of the token is checked in memory inside `resolve`
    // before any query, so a malformed token costs no lookup even
    // while it does spend from the failure budget.
    let resolved = match device::resolve(&state.pool, presented, now).await {
        Ok(resolved) => resolved,
        Err(err) => {
            // Not charged: see the note above.
            tracing::error!(error = %err, "could not resolve a device");
            return DeviceRejection::Unavailable.into_response();
        }
    };
    let Some(record) = resolved else {
        return refuse();
    };

    let mut request = Request::from_parts(parts, body);
    request
        .extensions_mut()
        .insert(Arc::new(AuthDevice { device: record }));
    next.run(request).await
}

/// Applies the layer-enforced limiters named in the entry.
///
/// Attached inside `enforce_access`, so a session-keyed limit can key
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
                    Bucket::PairIp => state.limits.pair_ip.check(key, now),
                    _ => return unenforceable(*limit),
                }
            }
            // One shared bucket for the whole endpoint, so there is no
            // key to resolve and nothing about the caller to read.
            (Bucket::PairGlobal, LimitKey::Global) => {
                state.limits.pair_global.check(GlobalKey, now)
            }
            (Bucket::IngestDevice, LimitKey::Device) => {
                let Some(auth) = parts.extensions.get::<Arc<AuthDevice>>() else {
                    // Only reachable if the entry asked for a
                    // device-keyed limit without a device layer, which
                    // RouteSpec::validate refuses at startup.
                    tracing::error!("a device-keyed rate limit ran with no resolved device");
                    return ApiError::of(ErrorKind::InternalError).into_response();
                };
                state
                    .limits
                    .ingest_device
                    .check(DeviceKey::new(&auth.device.id), now)
            }
            (Bucket::PwChange, LimitKey::Session) => {
                let Some(auth) = parts.extensions.get::<Arc<AuthSession>>() else {
                    // Only reachable if the entry asked for a
                    // session-keyed limit without a session layer, which
                    // RouteSpec::validate refuses at startup.
                    tracing::error!("a session-keyed rate limit ran with no resolved session");
                    return ApiError::of(ErrorKind::InternalError).into_response();
                };
                // The session id, not the account id: another session of
                // the same account has its own budget.
                state
                    .limits
                    .pw_change
                    .check(SessionKey::new(&auth.session.id), now)
            }
            // The handler owns this one: its key is in the request body.
            (_, LimitKey::Body) => continue,
            // `enforce_device_access` owns this one. It runs before
            // this layer and before any query, peeks rather than
            // charges, and charges only when authentication fails -
            // none of which this loop can express.
            (_, LimitKey::PeerBeforeAuth) => continue,
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

// The types a handler reads the resolved session with -
// [`crate::auth::extract::SessionContext`] and `AdminContext` - are
// deliberately defined in the auth module rather than here. Both wrap a
// private field, so only the module defining them can construct one,
// and that module is the one that owns authentication. This layer's
// side of the arrangement is the `Arc<AuthSession>` it inserts above;
// it cannot mint a context either.
