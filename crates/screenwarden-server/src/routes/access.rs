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

use crate::auth::device::{self, AuthDevice, DeviceRejection};
use crate::auth::extract::{verify_csrf, AuthRejection, AuthSession};
use crate::auth::time::UnixTime;
use crate::auth::{cookie, origin};
use crate::clientip::ClientAddr;
use crate::devices::store::DeviceRecord;
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
/// The peek happens first, before anything [`try_authenticate_device`]
/// does - so a caller who is already out of budget costs one hash-map
/// lookup and nothing else.
///
/// The charge is the other half, and it happens in exactly one place:
/// here, once, after [`try_authenticate_device`] returns. That function
/// has no opinion on rate limiting at all; it only classifies what went
/// wrong, through [`DeviceRejection::charges_budget`], which is what
/// decides whether this wrapper spends the bucket. A database *error*
/// is classified `false` there: that is this server failing, not the
/// caller misbehaving, and charging for it would let a database wobble
/// lock out the clients that happened to be syncing.
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
    // 429 with a Retry-After and never touches the database. This
    // peek never charges: see `RateLimiter::peek`.
    if let Some(error) = rate_limited(state.limits.device_auth_fail.peek(&peer, now)) {
        return error.into_response();
    }

    match try_authenticate_device(&mut parts, &state, now).await {
        Ok(record) => {
            let mut request = Request::from_parts(parts, body);
            request
                .extensions_mut()
                .insert(Arc::new(AuthDevice { device: record }));
            next.run(request).await
        }
        Err(rejection) => {
            // The one charge point. Every caller-attributable
            // rejection spends the bucket; `Unavailable` - this
            // server's own failure to look a device up - does not.
            if rejection.charges_budget() {
                state.limits.device_auth_fail.check(peer, now);
            }
            rejection.into_response()
        }
    }
}

/// The device-authentication logic itself, with no opinion on rate
/// limiting: it returns a typed rejection and nothing else, and
/// [`enforce_device_access`] is the one place that turns a rejection
/// into a charge.
async fn try_authenticate_device(
    parts: &mut Parts,
    state: &AppState,
    now: UnixTime,
) -> Result<DeviceRecord, DeviceRejection> {
    // A device route refuses any request carrying the Screenwarden
    // session cookie, even one that also presents a valid token. A
    // device is a different principal with a different credential, and
    // a request arriving with both is not something a native client
    // does.
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
        return Err(DeviceRejection::Unauthenticated);
    }

    let Some(presented) = device::presented_bearer(parts) else {
        return Err(DeviceRejection::Unauthenticated);
    };

    // The shape of the token is checked in memory inside `resolve`
    // before any query, so a malformed token costs no lookup even
    // while it does still spend from the failure budget, through the
    // classification above.
    match device::resolve(&state.pool, presented, now).await {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(DeviceRejection::Unauthenticated),
        Err(err) => {
            tracing::error!(error = %err, "could not resolve a device");
            Err(DeviceRejection::Unavailable)
        }
    }
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
        // Matched on the key first, then - where more than one bucket
        // could in principle carry that key - on the bucket. Both
        // levels are exhaustive with no wildcard arm: a combination
        // nothing enforces still reaches `unenforceable`, but naming
        // every remaining variant rather than catching them with `_`
        // means a new `Bucket` or `LimitKey` fails the build here
        // instead of becoming a silent runtime 500.
        let decision = match limit.key {
            LimitKey::Peer => {
                let client = match ClientAddr::from_request_parts(&mut parts, &state).await {
                    Ok(client) => client,
                    // No peer address means nothing can be counted;
                    // ClientAddr already logs and fails closed.
                    Err(rejection) => return rejection.into_response(),
                };
                let key = client.rate_limit_key();
                match limit.bucket {
                    Bucket::LoginIp => state.limits.login_ip.check(key, now),
                    Bucket::SetupIp => state.limits.setup_ip.check(key, now),
                    Bucket::PairIp => state.limits.pair_ip.check(key, now),
                    Bucket::InviteIp => state.limits.invite_ip.check(key, now),
                    Bucket::LoginUsername
                    | Bucket::PwChange
                    | Bucket::PairGlobal
                    | Bucket::IngestDevice
                    | Bucket::DeviceAuthFail
                    | Bucket::InviteGlobal => return unenforceable(*limit),
                }
            }
            // One shared bucket for the whole endpoint, so there is no
            // key to resolve and nothing about the caller to read.
            LimitKey::Global => match limit.bucket {
                Bucket::PairGlobal => state.limits.pair_global.check(GlobalKey, now),
                Bucket::InviteGlobal => state.limits.invite_global.check(GlobalKey, now),
                Bucket::LoginIp
                | Bucket::LoginUsername
                | Bucket::SetupIp
                | Bucket::PwChange
                | Bucket::PairIp
                | Bucket::IngestDevice
                | Bucket::DeviceAuthFail
                | Bucket::InviteIp => return unenforceable(*limit),
            },
            LimitKey::Device => {
                let Some(auth) = parts.extensions.get::<Arc<AuthDevice>>() else {
                    // Only reachable if the entry asked for a
                    // device-keyed limit without a device layer, which
                    // RouteSpec::validate refuses at startup.
                    tracing::error!("a device-keyed rate limit ran with no resolved device");
                    return ApiError::of(ErrorKind::InternalError).into_response();
                };
                match limit.bucket {
                    Bucket::IngestDevice => state
                        .limits
                        .ingest_device
                        .check(DeviceKey::new(&auth.device.id), now),
                    Bucket::LoginIp
                    | Bucket::LoginUsername
                    | Bucket::SetupIp
                    | Bucket::PwChange
                    | Bucket::PairIp
                    | Bucket::PairGlobal
                    | Bucket::DeviceAuthFail
                    | Bucket::InviteIp
                    | Bucket::InviteGlobal => return unenforceable(*limit),
                }
            }
            LimitKey::Session => {
                let Some(auth) = parts.extensions.get::<Arc<AuthSession>>() else {
                    // Only reachable if the entry asked for a
                    // session-keyed limit without a session layer, which
                    // RouteSpec::validate refuses at startup.
                    tracing::error!("a session-keyed rate limit ran with no resolved session");
                    return ApiError::of(ErrorKind::InternalError).into_response();
                };
                match limit.bucket {
                    // The session id, not the account id: another
                    // session of the same account has its own budget.
                    Bucket::PwChange => state
                        .limits
                        .pw_change
                        .check(SessionKey::new(&auth.session.id), now),
                    Bucket::LoginIp
                    | Bucket::LoginUsername
                    | Bucket::SetupIp
                    | Bucket::PairIp
                    | Bucket::PairGlobal
                    | Bucket::IngestDevice
                    | Bucket::DeviceAuthFail
                    | Bucket::InviteIp
                    | Bucket::InviteGlobal => return unenforceable(*limit),
                }
            }
            // The handler owns this one: its key is in the request body.
            LimitKey::Body => continue,
            // `enforce_device_access` owns this one. It runs before
            // this layer and before any query, peeks rather than
            // charges, and charges only when authentication fails -
            // none of which this loop can express.
            LimitKey::PeerBeforeAuth => continue,
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
