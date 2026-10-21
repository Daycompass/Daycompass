//! Route definitions and the HTTP-facing views of domain types.
//!
//! Handlers here parse input, call the service layer in
//! [`crate::auth`], and map results onto status codes. No rules live in
//! this module: per `CLAUDE.md`, the JSON handlers and the later HTML
//! handlers must share one service layer.
//!
//! ## The route inventory
//!
//! [`INVENTORY`] lists every route this server answers, together with
//! what protects it. It is not documentation: [`router`] registers each
//! route *through* its entry, and the entry's flags are what attach the
//! layers. A route whose entry says `Access::Admin` is admin-only
//! because the table says so, and one with `origin_checked` is checked
//! because the table says so.
//!
//! Two directions are therefore impossible rather than merely tested:
//!
//!   * A route that is not in the table cannot be registered -
//!     `RouteTable::add` panics at startup for an unknown
//!     method-and-path.
//!   * A table entry that is never registered cannot be left behind -
//!     `RouteTable::finish` panics for it.
//!
//! `tests/route_inventory.rs` walks the table over HTTP (anonymous,
//! ordinary user, admin, plus missing-CSRF and wrong-Origin probes) and
//! also fails if `.route(` appears anywhere outside the one call in
//! `RouteTable::add`, which is what keeps the registration path
//! single.

mod access;
mod auth;
mod devices;
mod events;
mod health;
mod pairing;
mod setup;
mod users;

use axum::handler::Handler;
use axum::routing::{on, MethodFilter, MethodRouter};
use axum::Router;
use serde::Serialize;

use crate::auth::store::{UserRecord, UserSummary};
use crate::devices::store::{DeviceRecord, DeviceWithOwner};
use crate::error::{not_found, ApiError, ErrorKind};
use crate::ratelimit::Decision;
use crate::state::AppState;

// Re-exported for the handlers' import paths only. The types are
// defined in the auth module and hold private fields, so re-exporting
// them here does not make them constructible outside it.
pub use crate::auth::device::DeviceContext;
pub use crate::auth::extract::{AdminContext, SessionContext};

/// What a route requires of its caller.
///
/// This is also the statement of *how* a route authenticates, which is
/// what [`OriginRule`] below is validated against. The distinction
/// between [`Access::Public`] and [`Access::BodySecret`] exists for
/// exactly that reason and for no other: both are reachable without a
/// session, but only one of them presents an unguessable secret that
/// a browser could not supply on a victim's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No credential at all. Anyone who can reach the port may call
    /// it.
    ///
    /// Login lives here, not in [`Access::BodySecret`]: a password is
    /// a credential, but it is one a person can be tricked into
    /// submitting, and a successful login *mints* ambient authority.
    /// Both halves are why login is `Origin`-checked.
    Public,
    /// No session, but the request carries an unguessable capability
    /// in its body - a setup token, a pairing code - and the response
    /// establishes no ambient credential.
    ///
    /// That combination is what makes the `Origin` exemption safe: a
    /// hostile page cannot read such a secret, so it cannot forge the
    /// request, and nothing the response hands back lands in a cookie
    /// the browser would attach to anything later.
    BodySecret,
    /// Any live session.
    Session,
    /// A live session whose account is an admin *right now*, read from
    /// the database on this request.
    Admin,
    /// A paired device, authenticated by `Authorization: Bearer` and
    /// nothing else. A session cookie on such a route is a refusal,
    /// not something to ignore. See [`crate::auth::device`].
    Device,
}

impl Access {
    /// Whether a live session is required. False for [`Self::Device`]:
    /// a device is a principal, but not a session one.
    pub const fn needs_session(self) -> bool {
        matches!(self, Self::Session | Self::Admin)
    }

    pub const fn needs_device(self) -> bool {
        matches!(self, Self::Device)
    }

    /// Whether the caller presents any credential at all. Used only by
    /// the inventory walk, to decide what "refused" should mean.
    pub const fn is_anonymous(self) -> bool {
        matches!(self, Self::Public | Self::BodySecret)
    }
}

/// Whether a route's `Origin` header is checked, and - where it is not
/// - the named reason it may be skipped.
///
/// This is deliberately not a `bool`. An `origin_checked: false` on an
/// entry is an ad-hoc exemption that reads as an oversight; a named
/// variant states the security property the exemption rests on, and
/// [`RouteSpec::validate`] refuses to let it be attached to a route
/// that does not have that property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRule {
    /// State-changing requests must carry a matching `Origin`. The
    /// default, and the only thing a cookie-authenticated route may
    /// be.
    Checked,
    /// Exempt, because the route has **no ambient cookie authority**
    /// in either direction: it does not authenticate by cookie, and
    /// it does not hand one out.
    ///
    /// Native clients send no `Origin` at all, so checking it would
    /// mean the API only worked from a browser. That is affordable
    /// only here, where a browser has nothing to contribute to the
    /// request that the attacker does not already have to know.
    ///
    /// Two independent conditions are enforced before an entry may
    /// claim this, and login fails both: the access kind must be
    /// [`Access::BodySecret`] or [`Access::Device`], and the route
    /// must set no session cookie.
    NoAmbientAuthority,
}

/// One of the rate limiters in [`crate::state::Limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    LoginIp,
    LoginUsername,
    SetupIp,
    PwChange,
    PairIp,
    PairGlobal,
    /// Requests from one authenticated device. Shared by
    /// `POST /api/v1/events` and `GET /api/v1/device/me`: the name
    /// says ingest because that is what it was introduced for and
    /// what its environment variable is called, but both device
    /// routes count against it.
    IngestDevice,
    /// *Failed* device authentications from one client address.
    DeviceAuthFail,
}

/// What a limiter counts a request against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKey {
    /// The client address, resolved by [`crate::clientip`].
    Peer,
    /// The session the request arrived on. Only possible where a session
    /// is required, since the key comes from the resolved session.
    Session,
    /// The device the request arrived on. Only possible where a device
    /// is required, for the same reason.
    Device,
    /// Nothing - one shared bucket for the whole endpoint. A ceiling
    /// on total work rather than a per-caller limit, and therefore
    /// also a denial-of-service lever; see [`crate::ratelimit::GlobalKey`].
    Global,
    /// A field of the request body. Checked by the handler rather than
    /// by a layer, because a layer cannot see the body without
    /// buffering it - the handler is the first place the key exists.
    Body,
    /// The client address, checked *before* the caller is
    /// authenticated and charged only when authentication fails.
    ///
    /// Enforced by [`crate::routes::access::enforce_device_access`]
    /// rather than by the shared rate-limit layer, which cannot
    /// express it: that layer's loop calls `check`, which counts and
    /// decides in one step, while this policy needs a read-only peek
    /// up front and a charge on three separate failure paths.
    ///
    /// Moving the shared layer outside the access layer would not
    /// help - it would still be one `check` per limit, and it would
    /// change the ordering of [`LimitKey::Device`], which must stay
    /// inside because it keys on the device that layer resolves.
    PeerBeforeAuth,
}

/// A limiter a route is counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub bucket: Bucket,
    pub key: LimitKey,
}

impl RateLimit {
    const fn new(bucket: Bucket, key: LimitKey) -> Self {
        Self { bucket, key }
    }

    /// Whether the shared rate-limit layer enforces this one.
    ///
    /// Not "whether a layer does": an access layer is a layer too, and
    /// once a second enforcer exists the old name is a lie. A limit
    /// this returns `false` for is enforced somewhere else that the
    /// [`LimitKey`] variant names - the handler, or the access layer -
    /// and is skipped by the shared layer's loop rather than being
    /// unenforced.
    pub const fn enforced_by_shared_layer(self) -> bool {
        !matches!(self.key, LimitKey::Body | LimitKey::PeerBeforeAuth)
    }
}

/// One route, and everything that guards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// Uppercase HTTP method. Also what the registered method filter is
    /// built from, so the table and the router cannot disagree about
    /// which method a handler answers.
    pub method: &'static str,
    pub path: &'static str,
    pub access: Access,
    /// Whether a mismatched `Origin` is rejected, and if not, why it
    /// is safe not to.
    pub origin: OriginRule,
    /// Whether an `X-CSRF-Token` matching the session is required.
    pub csrf: bool,
    /// Whether a successful response carries a `Set-Cookie` for the
    /// session cookie. Clearing it on logout counts: the field is
    /// about whether the route touches ambient authority at all.
    ///
    /// Half of what [`OriginRule::NoAmbientAuthority`] is validated
    /// against, and pinned independently by a test that sends every
    /// route and checks which ones answer with a `Set-Cookie`.
    pub sets_session_cookie: bool,
    /// A body size limit for this route alone, overriding the global
    /// one in [`crate::middleware`]. `None` means the global limit.
    pub max_body_bytes: Option<usize>,
    pub rate_limits: &'static [RateLimit],
}

impl RouteSpec {
    /// Whether a mismatched `Origin` is rejected on this route.
    pub const fn origin_checked(&self) -> bool {
        matches!(self.origin, OriginRule::Checked)
    }
}

impl RouteSpec {
    /// Rejects a table entry that could not be enforced as written.
    ///
    /// Called while the router is being built, so a contradictory entry
    /// stops the process at startup instead of quietly producing a route
    /// with less protection than the table claims.
    fn validate(&self) {
        assert!(
            self.method
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '-'),
            "{} {}: the method must be uppercase",
            self.method,
            self.path
        );

        // Requiring a CSRF token implies requiring a session: the token
        // is checked against one, so there has to be one. This also
        // refuses it on a device route, which has no session to check
        // against and authenticates by bearer alone.
        assert!(
            !self.csrf || self.access.needs_session(),
            "{} {}: a route without a session cannot require a CSRF token",
            self.method,
            self.path
        );

        // The `Origin` exemption, guarded in two independent ways.
        //
        // This is the check that has to be a *whitelist* rather than a
        // list of forbidden combinations. Written as "not when a
        // session is needed, and not when CSRF is set", login would
        // have slipped straight through - it is public, needs no
        // session and sets no CSRF token - and login is precisely the
        // route where the check matters most, because a hostile page
        // can make a browser submit one and the resulting cookie
        // sticks.
        if matches!(self.origin, OriginRule::NoAmbientAuthority) {
            assert!(
                matches!(self.access, Access::BodySecret | Access::Device),
                "{} {}: only a body-secret or device route may skip the Origin check",
                self.method,
                self.path
            );
            // The second lock, independent of the first: whatever the
            // access kind claims, a route that hands out a session
            // cookie is creating ambient authority and must be
            // checked.
            assert!(
                !self.sets_session_cookie,
                "{} {}: a route that sets the session cookie may not skip the Origin check",
                self.method, self.path
            );
        }

        // The converse for devices. A native client sends no `Origin`
        // at all, so a device route that demanded one would be
        // unreachable by the only callers it has - and the entry
        // would be claiming a protection that silently refuses every
        // legitimate request instead of providing one.
        assert!(
            !self.access.needs_device() || matches!(self.origin, OriginRule::NoAmbientAuthority),
            "{} {}: a device route must be marked NoAmbientAuthority",
            self.method,
            self.path
        );

        // The converse is the dangerous direction: a cookie-
        // authenticated, state-changing route with no CSRF token is
        // exactly the hole the extractor and the access layer exist to
        // close. Being state-changing and session-backed implies CSRF.
        let state_changing_session_route =
            self.access.needs_session() && !crate::auth::origin::is_safe_method(self.method);
        assert!(
            !state_changing_session_route || self.csrf,
            "{} {}: a state-changing session route must require a CSRF token",
            self.method,
            self.path
        );

        // A session- or device-keyed limit implies that principal,
        // since the key is whatever the access layer resolved. The
        // session case also refuses `LimitKey::Session` on a device
        // route, which has no session to key on.
        for limit in self.rate_limits {
            assert!(
                limit.key != LimitKey::Session || self.access.needs_session(),
                "{} {}: a session-keyed limit needs a session to key on",
                self.method,
                self.path
            );
            assert!(
                limit.key != LimitKey::Device || self.access.needs_device(),
                "{} {}: a device-keyed limit needs a device to key on",
                self.method,
                self.path
            );
            // Only the device access layer enforces this one, so an
            // entry claiming it anywhere else would be claiming a
            // protection nothing applies.
            assert!(
                limit.key != LimitKey::PeerBeforeAuth || self.access.needs_device(),
                "{} {}: a pre-auth peer limit is only enforced on a device route",
                self.method,
                self.path
            );
        }

        // And the converse, which is the half that actually protects
        // anything: every device route must declare it. The layer
        // enforces it unconditionally, so an entry without it would
        // leave the table describing less than the server does - and
        // the next person to add a device route would get the limit
        // by accident rather than by decision.
        assert!(
            !self.access.needs_device()
                || self
                    .rate_limits
                    .iter()
                    .any(|limit| limit.key == LimitKey::PeerBeforeAuth),
            "{} {}: a device route must declare a PeerBeforeAuth limit",
            self.method,
            self.path
        );
    }
}

/// Every route this server answers.
///
/// Read the `Access` column as "what the caller must be", and the rest
/// as what is attached on top. The `Body`-keyed limits are the only ones
/// a handler enforces; everything else here is a layer.
pub const INVENTORY: &[RouteSpec] = &[
    // Liveness. Marked `Checked` even though it is a GET, which the
    // Origin rule allows from anywhere regardless: an exemption it
    // does not need would be one more entry to read past when
    // auditing which routes really are exempt.
    RouteSpec {
        method: "GET",
        path: "/healthz",
        access: Access::Public,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // Authenticates by the unguessable setup token in its body and
    // hands back no cookie, which is what earns the exemption. 404
    // once an admin exists.
    RouteSpec {
        method: "POST",
        path: "/api/v1/setup",
        access: Access::BodySecret,
        origin: OriginRule::NoAmbientAuthority,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[RateLimit::new(Bucket::SetupIp, LimitKey::Peer)],
    },
    // Two buckets: the address first, which caps how many distinct
    // usernames one client can even introduce, then the username, whose
    // key is in the body and is therefore the handler's to check.
    //
    // `Public`, not `BodySecret`, and that is load-bearing. A password
    // is a credential a person can be tricked into submitting, and a
    // successful login mints a session cookie - so this route is
    // exactly the one that must stay Origin-checked, and the access
    // kind plus `sets_session_cookie` are what stop the exemption from
    // ever being attached here.
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/login",
        access: Access::Public,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: true,
        max_body_bytes: None,
        rate_limits: &[
            RateLimit::new(Bucket::LoginIp, LimitKey::Peer),
            RateLimit::new(Bucket::LoginUsername, LimitKey::Body),
        ],
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/logout",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: true,
        // Clearing the cookie is still a Set-Cookie on the wire.
        sets_session_cookie: true,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/auth/me",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // The one endpoint an ordinary account can spend Argon2 work on, so
    // it is limited per session - in front of the hashing semaphore,
    // because the layer runs before the handler. Per session rather
    // than per account so a stolen session cannot spend the budget the
    // owner needs to lock it out; see `ratelimit::SessionKey`.
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/password",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[RateLimit::new(Bucket::PwChange, LimitKey::Session)],
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/users",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/users",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "PATCH",
        path: "/api/v1/users/{id}",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "DELETE",
        path: "/api/v1/users/{id}",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // --- devices and pairing ------------------------------------------
    //
    // An owner mints a pairing code from the dashboard, so this is an
    // ordinary cookie route with every cookie protection on it.
    RouteSpec {
        method: "POST",
        path: "/api/v1/pairing-codes",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // Redeeming one is the opposite: a native client with no cookie
    // and no Origin, authenticating by the code in its body and
    // receiving a bearer token that never touches a cookie jar.
    //
    // Two buckets. The per-address one shapes ordinary abuse; the
    // global one is a ceiling so a flood from many addresses cannot
    // turn pairing into unbounded database work. Both count every
    // attempt, successes included - pairing is rare enough that this
    // costs nobody anything, and counting only failures would let the
    // limit be sidestepped by interleaving valid calls.
    RouteSpec {
        method: "POST",
        path: "/api/v1/pair",
        access: Access::BodySecret,
        origin: OriginRule::NoAmbientAuthority,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[
            RateLimit::new(Bucket::PairIp, LimitKey::Peer),
            RateLimit::new(Bucket::PairGlobal, LimitKey::Global),
        ],
    },
    // The only write path into `events`, and the only route with a
    // body limit of its own. The limit is attached from this entry
    // rather than by the handler, and it sits *inside* the device
    // layer - an unauthenticated caller is refused before anything
    // reads its body.
    RouteSpec {
        method: "POST",
        path: "/api/v1/events",
        access: Access::Device,
        origin: OriginRule::NoAmbientAuthority,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: Some(crate::events::ingest::MAX_BODY_BYTES),
        rate_limits: &[
            RateLimit::new(Bucket::DeviceAuthFail, LimitKey::PeerBeforeAuth),
            RateLimit::new(Bucket::IngestDevice, LimitKey::Device),
        ],
    },
    // Lets a client detect clock skew, which is what makes the
    // validator's future-dating rules diagnosable from the outside.
    RouteSpec {
        method: "GET",
        path: "/api/v1/device/me",
        access: Access::Device,
        origin: OriginRule::NoAmbientAuthority,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[
            RateLimit::new(Bucket::DeviceAuthFail, LimitKey::PeerBeforeAuth),
            // The same bucket as ingest, deliberately: a client that
            // polls this route is spending the same kind of budget as
            // one that syncs, and two buckets would just be two
            // numbers to keep in step.
            RateLimit::new(Bucket::IngestDevice, LimitKey::Device),
        ],
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/devices",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "PATCH",
        path: "/api/v1/devices/{id}",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // A POST rather than a DELETE, because revoking is not deleting:
    // the row stays and so does every event the device reported.
    RouteSpec {
        method: "POST",
        path: "/api/v1/devices/{id}/revoke",
        access: Access::Session,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    // Admin device management. Metadata only, in both routes: an
    // admin may see that a device exists and who owns it, never what
    // it reported.
    RouteSpec {
        method: "GET",
        path: "/api/v1/admin/devices",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: false,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/admin/devices/{id}/revoke",
        access: Access::Admin,
        origin: OriginRule::Checked,
        csrf: true,
        sets_session_cookie: false,
        max_body_bytes: None,
        rate_limits: &[],
    },
];

/// The entry for one method and path, if the inventory has one.
pub fn spec_for(method: &str, path: &str) -> Option<&'static RouteSpec> {
    INVENTORY
        .iter()
        .find(|spec| spec.method == method && spec.path == path)
}

/// Builds the route table.
///
/// Every route goes through `RouteTable::add`, which looks its entry
/// up in [`INVENTORY`] and attaches what the entry calls for.
pub fn router(state: AppState) -> Router {
    let mut table = RouteTable::new(state);

    table.add("GET", "/healthz", health::healthz);
    table.add("POST", "/api/v1/setup", setup::create_first_admin);
    table.add("POST", "/api/v1/auth/login", auth::log_in);
    table.add("POST", "/api/v1/auth/logout", auth::log_out);
    table.add("GET", "/api/v1/auth/me", auth::me);
    table.add("POST", "/api/v1/auth/password", auth::change_password);
    table.add("POST", "/api/v1/users", users::create_user);
    table.add("GET", "/api/v1/users", users::list_users);
    table.add("PATCH", "/api/v1/users/{id}", users::change_role);
    table.add("DELETE", "/api/v1/users/{id}", users::delete_user);
    table.add("POST", "/api/v1/pairing-codes", pairing::create_code);
    table.add("POST", "/api/v1/pair", pairing::pair_device);
    table.add("POST", "/api/v1/events", events::ingest);
    table.add("GET", "/api/v1/device/me", events::device_me);
    table.add("GET", "/api/v1/devices", devices::list_own);
    table.add("PATCH", "/api/v1/devices/{id}", devices::rename_own);
    table.add("POST", "/api/v1/devices/{id}/revoke", devices::revoke_own);
    table.add("GET", "/api/v1/admin/devices", devices::list_all);
    table.add(
        "POST",
        "/api/v1/admin/devices/{id}/revoke",
        devices::revoke_any,
    );

    table.finish()
}

/// Assembles the router from the inventory.
struct RouteTable {
    router: Router<AppState>,
    state: AppState,
    registered: Vec<&'static RouteSpec>,
}

impl RouteTable {
    fn new(state: AppState) -> Self {
        Self {
            router: Router::new(),
            state,
            registered: Vec::new(),
        }
    }

    /// Registers `handler` for the inventory entry at `method` `path`,
    /// wrapped in the layers that entry calls for.
    ///
    /// The method filter is derived from the entry rather than from the
    /// call site, so the table's `method` really is the method the
    /// handler answers.
    ///
    /// Layers are applied innermost first, so a request passes through
    /// them in this order: `Origin`, then access (session, CSRF, admin,
    /// or device), then the layer-enforced rate limits, then the body
    /// limit, then the handler. The rate limits sit *inside* the
    /// access layer because a session- or device-keyed limit needs the
    /// resolved principal to key on.
    ///
    /// That order is also what keeps an unauthenticated caller from
    /// spending anything on the ingest route. Neither the access layer
    /// nor the rate-limit layer reads the request body - both split it
    /// off and pass it through untouched - and the body is first
    /// consumed by the handler's `Json` extractor. So authentication
    /// happens before a single byte of a 512 KiB body is buffered, and
    /// `tests/events_ingest.rs` sends exactly that to prove it.
    fn add<H, T>(&mut self, method: &'static str, path: &'static str, handler: H)
    where
        H: Handler<T, AppState>,
        T: 'static,
    {
        let spec = spec_for(method, path)
            .unwrap_or_else(|| panic!("{method} {path} is not in the route inventory"));
        spec.validate();
        assert!(
            !self.registered.contains(&spec),
            "{method} {path} is registered twice"
        );

        let mut route: MethodRouter<AppState> = on(method_filter(spec.method), handler);

        // Innermost, so it overrides the global limit rather than the
        // other way round.
        if let Some(max_bytes) = spec.max_body_bytes {
            route = route.layer(axum::extract::DefaultBodyLimit::max(max_bytes));
        }

        if spec
            .rate_limits
            .iter()
            .any(|limit| limit.enforced_by_shared_layer())
        {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_rate_limits,
            ));
        }

        if spec.access.needs_session() {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_session_access,
            ));
        } else if spec.access.needs_device() {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_device_access,
            ));
        }

        if spec.origin_checked() {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_origin,
            ));
        }

        // The one place a route is registered. `tests/route_inventory.rs`
        // fails if `.route(` appears anywhere else in the sources.
        self.router = std::mem::take(&mut self.router).route(path, route);
        self.registered.push(spec);
    }

    /// Finishes the router, having checked that the table was followed
    /// exactly.
    fn finish(self) -> Router {
        for spec in INVENTORY {
            assert!(
                self.registered.contains(&spec),
                "{} {} is in the inventory but was never registered",
                spec.method,
                spec.path
            );
        }

        self.router.fallback(not_found).with_state(self.state)
    }
}

/// The method filter for an inventory entry's method.
///
/// Deliberately exhaustive over the methods the table uses rather than
/// parsing: an entry naming a method this server does not serve is a
/// mistake, and a startup panic is a better answer than a route nobody
/// can reach.
fn method_filter(method: &str) -> MethodFilter {
    match method {
        "GET" => MethodFilter::GET,
        "POST" => MethodFilter::POST,
        "PATCH" => MethodFilter::PATCH,
        "DELETE" => MethodFilter::DELETE,
        other => panic!("the route inventory names an unsupported method: {other}"),
    }
}

/// What a client is told about an account.
///
/// Deliberately not the full [`UserRecord`]: the password hash has no
/// business leaving the server, and `created_at` is not something the
/// session endpoints need.
#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub role: &'static str,
}

impl From<&UserRecord> for UserView {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.as_str().to_owned(),
            role: user.role.as_str(),
        }
    }
}

/// What account management returns about an account.
///
/// Built from [`UserSummary`], which has no password hash to leave out
/// in the first place. `created_at` is the Unix second the row stores.
#[derive(Serialize)]
pub struct UserDetailView {
    pub id: String,
    pub username: String,
    pub role: &'static str,
    pub created_at: i64,
}

impl From<&UserSummary> for UserDetailView {
    fn from(user: &UserSummary) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.as_str().to_owned(),
            role: user.role.as_str(),
            created_at: user.created_at.as_secs(),
        }
    }
}

/// What an owner is told about one of their devices.
///
/// No token and no token hash: the plaintext leaves the server exactly
/// once, in the pairing response, and the hash has no business leaving
/// it at all. `revoked_at` is present so an owner can see what they
/// revoked and when.
#[derive(Serialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub platform: &'static str,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
}

impl From<&DeviceRecord> for DeviceView {
    fn from(device: &DeviceRecord) -> Self {
        Self {
            id: device.id.clone(),
            name: device.name.as_str().to_owned(),
            platform: device.platform.as_str(),
            created_at: device.created_at.as_secs(),
            last_seen_at: device.last_seen_at.as_secs(),
            revoked_at: device.revoked_at.map(|at| at.as_secs()),
        }
    }
}

/// What an admin is told about a device anywhere on the instance.
///
/// [`DeviceView`] plus the owner. Deliberately **not** a superset
/// that grows over time: the field list is pinned by a test, because
/// this is the one view where a careless addition could put event
/// data in front of somebody who must never see it.
#[derive(Serialize)]
pub struct AdminDeviceView {
    pub id: String,
    pub owner_id: String,
    pub owner_username: String,
    pub name: String,
    pub platform: &'static str,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
}

impl From<&DeviceWithOwner> for AdminDeviceView {
    fn from(row: &DeviceWithOwner) -> Self {
        Self {
            id: row.device.id.clone(),
            owner_id: row.device.user_id.clone(),
            owner_username: row.owner_username.clone(),
            name: row.device.name.as_str().to_owned(),
            platform: row.device.platform.as_str(),
            created_at: row.device.created_at.as_secs(),
            last_seen_at: row.device.last_seen_at.as_secs(),
            revoked_at: row.device.revoked_at.map(|at| at.as_secs()),
        }
    }
}

/// Turns a limiter decision into the one response every rate limit
/// produces.
///
/// Identical whichever bucket refused, and it never says which. "This
/// account is rate limited" would be an account oracle, and a far
/// cheaper one than timing a password check.
fn rate_limited(decision: Decision) -> Option<ApiError> {
    match decision {
        Decision::Allowed => None,
        Decision::Limited { retry_after } => {
            Some(ApiError::of(ErrorKind::RateLimited).retry_after(retry_after))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry has to be enforceable as written; the router build
    /// asserts this, and this test says so without starting a server.
    #[test]
    fn every_inventory_entry_is_internally_consistent() {
        for spec in INVENTORY {
            spec.validate();
        }
    }

    #[test]
    fn the_inventory_has_no_duplicate_routes() {
        for (index, spec) in INVENTORY.iter().enumerate() {
            assert!(
                spec_for(spec.method, spec.path).is_some(),
                "{} {} cannot be looked up",
                spec.method,
                spec.path
            );
            for other in &INVENTORY[index + 1..] {
                assert!(
                    !(spec.method == other.method && spec.path == other.path),
                    "{} {} appears twice",
                    spec.method,
                    spec.path
                );
            }
        }
    }

    /// Every method named in the table must map to a filter, or the
    /// route would be registered for nothing.
    #[test]
    fn every_inventory_method_has_a_filter() {
        for spec in INVENTORY {
            let _ = method_filter(spec.method);
        }
    }

    /// A green build does not prove the consistency check works, so
    /// here is each contradiction it has to refuse. Every one of these
    /// would otherwise be a route with less protection than the table
    /// claims.
    fn spec_with(access: Access, csrf: bool, limits: &'static [RateLimit]) -> RouteSpec {
        RouteSpec {
            method: "POST",
            path: "/probe",
            access,
            origin: OriginRule::Checked,
            csrf,
            sets_session_cookie: false,
            max_body_bytes: None,
            rate_limits: limits,
        }
    }

    /// Like [`spec_with`], but exempt from the `Origin` check, for the
    /// cases about who may claim that exemption.
    fn exempt_spec(access: Access, sets_session_cookie: bool) -> RouteSpec {
        RouteSpec {
            method: "POST",
            path: "/probe",
            access,
            origin: OriginRule::NoAmbientAuthority,
            csrf: false,
            sets_session_cookie,
            max_body_bytes: None,
            rate_limits: &[],
        }
    }

    #[test]
    #[should_panic(expected = "a route without a session cannot require a CSRF token")]
    fn a_public_route_may_not_demand_a_csrf_token() {
        spec_with(Access::Public, true, &[]).validate();
    }

    /// A device route has no session for a CSRF token to be checked
    /// against, so demanding one would be a protection that cannot be
    /// applied.
    #[test]
    #[should_panic(expected = "a route without a session cannot require a CSRF token")]
    fn a_device_route_may_not_demand_a_csrf_token() {
        let mut spec = spec_with(Access::Device, true, PRE_AUTH);
        spec.origin = OriginRule::NoAmbientAuthority;
        spec.validate();
    }

    /// The limit every device route has to declare, for the probes
    /// above that are about some *other* contradiction.
    const PRE_AUTH: &[RateLimit] = &[RateLimit::new(
        Bucket::DeviceAuthFail,
        LimitKey::PeerBeforeAuth,
    )];

    #[test]
    #[should_panic(expected = "must require a CSRF token")]
    fn a_state_changing_session_route_may_not_skip_csrf() {
        spec_with(Access::Session, false, &[]).validate();
    }

    #[test]
    #[should_panic(expected = "needs a session to key on")]
    fn a_session_keyed_limit_needs_a_session() {
        const LIMITS: &[RateLimit] = &[RateLimit::new(Bucket::PwChange, LimitKey::Session)];
        spec_with(Access::Public, false, LIMITS).validate();
    }

    /// The same rule read from the device side: a device route has no
    /// session, so a session-keyed limit on it would key on nothing.
    #[test]
    #[should_panic(expected = "needs a session to key on")]
    fn a_device_route_may_not_use_a_session_keyed_limit() {
        const LIMITS: &[RateLimit] = &[
            RateLimit::new(Bucket::DeviceAuthFail, LimitKey::PeerBeforeAuth),
            RateLimit::new(Bucket::PwChange, LimitKey::Session),
        ];
        let mut spec = spec_with(Access::Device, false, LIMITS);
        spec.origin = OriginRule::NoAmbientAuthority;
        spec.validate();
    }

    /// The pre-auth peer limit is enforced only by the device access
    /// layer, so claiming it anywhere else claims a protection
    /// nothing applies.
    #[test]
    #[should_panic(expected = "a pre-auth peer limit is only enforced on a device route")]
    fn a_pre_auth_peer_limit_is_only_for_device_routes() {
        const LIMITS: &[RateLimit] = &[RateLimit::new(
            Bucket::DeviceAuthFail,
            LimitKey::PeerBeforeAuth,
        )];
        spec_with(Access::Public, false, LIMITS).validate();
    }

    /// And the direction that actually protects something: the layer
    /// enforces the limit on every device route unconditionally, so an
    /// entry that does not declare it would leave the table describing
    /// less than the server does.
    #[test]
    #[should_panic(expected = "a device route must declare a PeerBeforeAuth limit")]
    fn a_device_route_must_declare_the_pre_auth_peer_limit() {
        let mut spec = spec_with(Access::Device, false, &[]);
        spec.origin = OriginRule::NoAmbientAuthority;
        spec.validate();
    }

    #[test]
    #[should_panic(expected = "needs a device to key on")]
    fn a_device_keyed_limit_needs_a_device() {
        const LIMITS: &[RateLimit] = &[RateLimit::new(Bucket::IngestDevice, LimitKey::Device)];
        spec_with(Access::Session, true, LIMITS).validate();
    }

    /// The hole this whitelist exists to close. Login is public, needs
    /// no session and sets no CSRF token, so a rule phrased as "refuse
    /// the exemption when a session is needed or CSRF is set" would
    /// have let it through - and login is the route where the `Origin`
    /// check matters most, because a hostile page can make a browser
    /// submit one and the session cookie it mints then sticks.
    #[test]
    #[should_panic(expected = "only a body-secret or device route may skip the Origin check")]
    fn a_public_route_may_not_skip_the_origin_check() {
        exempt_spec(Access::Public, false).validate();
    }

    #[test]
    #[should_panic(expected = "only a body-secret or device route may skip the Origin check")]
    fn a_session_route_may_not_skip_the_origin_check() {
        exempt_spec(Access::Session, false).validate();
    }

    #[test]
    #[should_panic(expected = "only a body-secret or device route may skip the Origin check")]
    fn an_admin_route_may_not_skip_the_origin_check() {
        exempt_spec(Access::Admin, false).validate();
    }

    /// The second, independent lock. Even if a route were reclassified
    /// as authenticating by a body secret, handing out a session
    /// cookie creates ambient authority and must be checked.
    #[test]
    #[should_panic(expected = "a route that sets the session cookie may not skip the Origin check")]
    fn a_route_that_sets_the_cookie_may_not_skip_the_origin_check() {
        exempt_spec(Access::BodySecret, true).validate();
    }

    /// The converse: a native client sends no `Origin`, so a device
    /// route demanding one would refuse every legitimate caller while
    /// claiming to be protected.
    #[test]
    #[should_panic(expected = "a device route must be marked NoAmbientAuthority")]
    fn a_device_route_must_skip_the_origin_check() {
        spec_with(Access::Device, false, PRE_AUTH).validate();
    }

    /// And the shapes that are fine must stay fine, or the check would
    /// be refusing the table it is supposed to allow.
    #[test]
    fn the_shapes_the_table_actually_uses_are_accepted() {
        const BODY: &[RateLimit] = &[RateLimit::new(Bucket::LoginUsername, LimitKey::Body)];
        spec_with(Access::Public, false, BODY).validate();
        spec_with(Access::Session, true, &[]).validate();
        spec_with(Access::Admin, true, &[]).validate();

        // The two kinds that may skip the Origin check.
        exempt_spec(Access::BodySecret, false).validate();
        // A device route also has to carry the pre-auth limit, so the
        // exempt probe needs it to be a shape the table could use.
        let mut exempt_device = exempt_spec(Access::Device, false);
        exempt_device.rate_limits = PRE_AUTH;
        exempt_device.validate();

        // A device route, with both limits its entry must carry.
        const INGEST: &[RateLimit] = &[
            RateLimit::new(Bucket::DeviceAuthFail, LimitKey::PeerBeforeAuth),
            RateLimit::new(Bucket::IngestDevice, LimitKey::Device),
        ];
        let mut device = spec_with(Access::Device, false, INGEST);
        device.origin = OriginRule::NoAmbientAuthority;
        device.max_body_bytes = Some(512 * 1024);
        device.validate();

        // A global limit needs nothing to key on, so it is valid
        // wherever it is written.
        const GLOBAL: &[RateLimit] = &[RateLimit::new(Bucket::PairGlobal, LimitKey::Global)];
        exempt_spec(Access::BodySecret, false).validate();
        spec_with(Access::Public, false, GLOBAL).validate();

        // A safe method needs no CSRF token, whatever the access.
        RouteSpec {
            method: "GET",
            path: "/probe",
            access: Access::Admin,
            origin: OriginRule::Checked,
            csrf: false,
            sets_session_cookie: false,
            max_body_bytes: None,
            rate_limits: &[],
        }
        .validate();
    }

    /// The exemption is pinned to an exact set, so adding a fifth
    /// route to it is a deliberate edit to this test rather than a
    /// line in a table nobody re-reads.
    #[test]
    fn exactly_four_routes_skip_the_origin_check() {
        let mut exempt: Vec<String> = INVENTORY
            .iter()
            .filter(|spec| matches!(spec.origin, OriginRule::NoAmbientAuthority))
            .map(|spec| format!("{} {}", spec.method, spec.path))
            .collect();
        exempt.sort();

        assert_eq!(
            exempt,
            [
                "GET /api/v1/device/me",
                "POST /api/v1/events",
                "POST /api/v1/pair",
                "POST /api/v1/setup",
            ],
            "the set of Origin-exempt routes changed; every addition needs \
             its own review of why no browser can forge the request"
        );
    }

    /// Login must stay checked. Spelled out as its own test rather
    /// than left to the set above, because this is the single entry
    /// whose misclassification would be a real vulnerability.
    #[test]
    fn login_is_origin_checked_and_declares_its_cookie() {
        let login = spec_for("POST", "/api/v1/auth/login").expect("login must be in the table");
        assert!(login.origin_checked(), "login CSRF depends on this");
        assert!(
            login.sets_session_cookie,
            "login mints ambient authority and must say so"
        );
        assert_eq!(
            login.access,
            Access::Public,
            "a password is not an unguessable capability"
        );
    }

    /// Only the ingest route overrides the global body limit, and it
    /// overrides it to the documented value.
    #[test]
    fn only_ingest_raises_the_body_limit() {
        let raised: Vec<(&str, &str, usize)> = INVENTORY
            .iter()
            .filter_map(|spec| spec.max_body_bytes.map(|max| (spec.method, spec.path, max)))
            .collect();

        assert_eq!(
            raised,
            vec![(
                "POST",
                "/api/v1/events",
                crate::events::ingest::MAX_BODY_BYTES
            )]
        );
    }

    /// The privacy rule from `CLAUDE.md`, as a property of the type: an
    /// account view has exactly these fields and no hash among them.
    #[test]
    fn the_account_views_carry_no_hash() {
        use crate::auth::role::Role;
        use crate::auth::time::UnixTime;
        use crate::auth::username::Username;

        let summary = UserSummary {
            id: "user-1".to_owned(),
            username: Username::parse("alice").unwrap(),
            role: Role::Admin,
            created_at: UnixTime::from_secs(7),
        };
        let json = serde_json::to_value(UserDetailView::from(&summary)).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["created_at", "id", "role", "username"]);
    }
}
