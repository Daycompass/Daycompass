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
//!     [`RouteTable::add`] panics at startup for an unknown
//!     method-and-path.
//!   * A table entry that is never registered cannot be left behind -
//!     [`RouteTable::finish`] panics for it.
//!
//! `tests/route_inventory.rs` walks the table over HTTP (anonymous,
//! ordinary user, admin, plus missing-CSRF and wrong-Origin probes) and
//! also fails if `.route(` appears anywhere outside the one call in
//! [`RouteTable::add`], which is what keeps the registration path
//! single.

mod access;
mod auth;
mod health;
mod setup;
mod users;

use axum::handler::Handler;
use axum::routing::{on, MethodFilter, MethodRouter};
use axum::Router;
use serde::Serialize;

use crate::auth::store::{UserRecord, UserSummary};
use crate::error::{not_found, ApiError, ErrorKind};
use crate::ratelimit::Decision;
use crate::state::AppState;

pub use access::{AdminContext, SessionContext};

/// What a route requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No session. Anyone who can reach the port may call it.
    Public,
    /// Any live session.
    Session,
    /// A live session whose account is an admin *right now*, read from
    /// the database on this request.
    Admin,
}

impl Access {
    pub const fn needs_session(self) -> bool {
        !matches!(self, Self::Public)
    }
}

/// One of the rate limiters in [`crate::state::Limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    LoginIp,
    LoginUsername,
    SetupIp,
    PasswordUser,
}

/// What a limiter counts a request against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKey {
    /// The client address, resolved by [`crate::clientip`].
    Peer,
    /// The authenticated account. Only possible where a session is
    /// required, since the key comes from the resolved session.
    Account,
    /// A field of the request body. Checked by the handler rather than
    /// by a layer, because a layer cannot see the body without
    /// buffering it - the handler is the first place the key exists.
    Body,
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

    /// Whether a layer enforces this one, as opposed to the handler.
    pub const fn enforced_by_layer(self) -> bool {
        !matches!(self.key, LimitKey::Body)
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
    /// Whether a mismatched `Origin` is rejected.
    pub origin_checked: bool,
    /// Whether an `X-CSRF-Token` matching the session is required.
    pub csrf: bool,
    pub rate_limits: &'static [RateLimit],
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

        // A CSRF token is checked against a session, so there has to be
        // one.
        assert!(
            !(self.csrf && !self.access.needs_session()),
            "{} {}: a public route cannot require a CSRF token",
            self.method,
            self.path
        );

        // The converse is the dangerous direction: a cookie-
        // authenticated, state-changing route with no CSRF token is
        // exactly the hole the extractor and this layer exist to close.
        assert!(
            !(self.access.needs_session()
                && !crate::auth::origin::is_safe_method(self.method)
                && !self.csrf),
            "{} {}: a state-changing session route must require a CSRF token",
            self.method,
            self.path
        );

        for limit in self.rate_limits {
            assert!(
                !(limit.key == LimitKey::Account && !self.access.needs_session()),
                "{} {}: an account-keyed limit needs a session to key on",
                self.method,
                self.path
            );
        }
    }
}

/// Every route this server answers.
///
/// Read the `Access` column as "what the caller must be", and the rest
/// as what is attached on top. The `Body`-keyed limits are the only ones
/// a handler enforces; everything else here is a layer.
pub const INVENTORY: &[RouteSpec] = &[
    // Liveness. No session, no Origin check: it is a GET, which the
    // Origin rule allows from anywhere anyway.
    RouteSpec {
        method: "GET",
        path: "/healthz",
        access: Access::Public,
        origin_checked: false,
        csrf: false,
        rate_limits: &[],
    },
    // Exempt from the Origin check on purpose: it carries no cookie, so
    // there is no ambient credential for a hostile page to ride on, and
    // its protection is the unguessable setup token. 404 once an admin
    // exists.
    RouteSpec {
        method: "POST",
        path: "/api/v1/setup",
        access: Access::Public,
        origin_checked: false,
        csrf: false,
        rate_limits: &[RateLimit::new(Bucket::SetupIp, LimitKey::Peer)],
    },
    // Two buckets: the address first, which caps how many distinct
    // usernames one client can even introduce, then the username, whose
    // key is in the body and is therefore the handler's to check.
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/login",
        access: Access::Public,
        origin_checked: true,
        csrf: false,
        rate_limits: &[
            RateLimit::new(Bucket::LoginIp, LimitKey::Peer),
            RateLimit::new(Bucket::LoginUsername, LimitKey::Body),
        ],
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/logout",
        access: Access::Session,
        origin_checked: true,
        csrf: true,
        rate_limits: &[],
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/auth/me",
        access: Access::Session,
        origin_checked: true,
        csrf: false,
        rate_limits: &[],
    },
    // The one endpoint an ordinary account can spend Argon2 work on, so
    // it is limited per account - in front of the hashing semaphore,
    // because the layer runs before the handler.
    RouteSpec {
        method: "POST",
        path: "/api/v1/auth/password",
        access: Access::Session,
        origin_checked: true,
        csrf: true,
        rate_limits: &[RateLimit::new(Bucket::PasswordUser, LimitKey::Account)],
    },
    RouteSpec {
        method: "POST",
        path: "/api/v1/users",
        access: Access::Admin,
        origin_checked: true,
        csrf: true,
        rate_limits: &[],
    },
    RouteSpec {
        method: "GET",
        path: "/api/v1/users",
        access: Access::Admin,
        origin_checked: true,
        csrf: false,
        rate_limits: &[],
    },
    RouteSpec {
        method: "PATCH",
        path: "/api/v1/users/{id}",
        access: Access::Admin,
        origin_checked: true,
        csrf: true,
        rate_limits: &[],
    },
    RouteSpec {
        method: "DELETE",
        path: "/api/v1/users/{id}",
        access: Access::Admin,
        origin_checked: true,
        csrf: true,
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
/// Every route goes through [`RouteTable::add`], which looks its entry
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
    /// them in this order: `Origin`, then access (session, CSRF, admin),
    /// then the layer-enforced rate limits, then the handler. The rate
    /// limits sit *inside* the access layer because an account-keyed
    /// limit needs the resolved session to key on.
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

        if spec
            .rate_limits
            .iter()
            .any(|limit| limit.enforced_by_layer())
        {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_rate_limits,
            ));
        }

        if spec.access.needs_session() {
            route = route.layer(axum::middleware::from_fn_with_state(
                (self.state.clone(), spec),
                access::enforce_access,
            ));
        }

        if spec.origin_checked {
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
