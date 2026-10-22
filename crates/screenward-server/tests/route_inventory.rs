//! Walks the route inventory over HTTP.
//!
//! `screenward_server::routes::INVENTORY` is what the router is built
//! from: each entry's flags attach the layers that protect that route.
//! This file is the other half of that arrangement - it takes the table
//! as a specification and checks the running server against it, so an
//! entry that claims a protection the server does not apply fails here.
//!
//! Four things are checked for every entry:
//!
//!   * anonymous, ordinary-user and admin callers get the outcome the
//!     `access` column calls for;
//!   * a route marked `csrf` refuses a missing and a wrong token;
//!   * a route whose `OriginRule` is `Checked` refuses a foreign
//!     `Origin`, and a `NoAmbientAuthority` one does not;
//!   * a device token is refused on every session route, and a
//!     session cookie on every device route;
//!   * a route with a layer-enforced rate limit really does refuse once
//!     the limit is reached.
//!
//! Plus the one structural check that keeps the table authoritative: no
//! source file outside the single registration helper may call
//! `.route(`.

mod common;

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use common::{
    Credentials, Device, Session, TestApp, TestRequest, TestResponse, BAD_ORIGIN, GOOD_ORIGIN,
};
use screenward_server::routes::{Access, RouteSpec, INVENTORY};

/// Error codes that mean "not allowed", as opposed to any other refusal
/// a route might answer with.
const UNAUTHENTICATED: &str = "unauthenticated";
const NOT_PERMITTED: &str = "forbidden";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
    Anonymous,
    User,
    Admin,
    /// A paired device, authenticating by bearer token. Added in M2:
    /// without it, nothing would check that a device token is refused
    /// on a session route, or a session cookie on a device route.
    Device,
}

/// Every kind of caller the walk tries on every route.
const EVERY_CALLER: [Caller; 4] = [
    Caller::Anonymous,
    Caller::User,
    Caller::Admin,
    Caller::Device,
];

/// One app with an admin, an ordinary user and a paired device.
struct Fixture {
    app: TestApp,
    admin: Session,
    admin_credentials: Credentials,
    user: Session,
    user_credentials: Credentials,
    device: Device,
}

impl Fixture {
    async fn new() -> Self {
        let app = TestApp::new().await;
        let (admin_credentials, admin) = app.provisioned_admin().await;
        let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
        let user = app.log_in(&user_credentials).await;
        let device = app.pair_device(&user, "walk-probe", "linux").await;
        Self {
            app,
            admin,
            admin_credentials,
            user,
            user_credentials,
            device,
        }
    }

    fn session(&self, caller: Caller) -> Option<&Session> {
        match caller {
            Caller::Anonymous | Caller::Device => None,
            Caller::User => Some(&self.user),
            Caller::Admin => Some(&self.admin),
        }
    }

    fn password_of(&self, caller: Caller) -> String {
        match caller {
            Caller::Anonymous | Caller::Device => common::random_secret(),
            Caller::User => self.user_credentials.password.clone(),
            Caller::Admin => self.admin_credentials.password.clone(),
        }
    }

    /// A device id belonging to `caller`, for the `{id}` device
    /// routes.
    ///
    /// Whose device it is matters: `/api/v1/devices/{id}` is
    /// owner-scoped, so aiming it at somebody else's device is a
    /// legitimate 404 and the walk would read that as the route being
    /// missing. An anonymous caller has no account to own one, so it
    /// gets the ordinary user's - it will be refused before the id is
    /// ever looked at.
    async fn disposable_device(&self, caller: Caller) -> String {
        let owner = match caller {
            Caller::Admin => &self.admin,
            Caller::Anonymous | Caller::User | Caller::Device => &self.user,
        };
        self.app
            .pair_device(owner, "disposable", "android")
            .await
            .id
    }

    /// An account to aim an `{id}` route at, so a route that exists is
    /// never answered with a 404 for want of a real target.
    ///
    /// The name is generated, because several of these exist at once
    /// and a repeat would be refused as taken.
    async fn disposable_account(&self) -> String {
        let name = format!("t-{}", common::random_secret()[..8].to_ascii_lowercase());
        let (id, _credentials) = self.app.create_account(&self.admin, &name, "user").await;
        id
    }

    /// Sends `spec`'s request as `caller`, with a matching `Origin` and,
    /// where there is a session, its CSRF token.
    async fn call(&self, spec: &RouteSpec, caller: Caller, target_id: &str) -> TestResponse {
        let path = spec.path.replace("{id}", target_id);
        let mut request = TestRequest::new(method_of(spec), &path).origin(GOOD_ORIGIN);

        if let Some(session) = self.session(caller) {
            request = request.authenticated(session);
        }
        if caller == Caller::Device {
            request = request.authenticated_as_device(&self.device);
        }
        if let Some(body) = self.body_for(spec, caller, target_id).await {
            request = request.json(body);
        }

        self.app.send(request).await
    }

    /// A body that is valid for the route, so the answer is about
    /// authorization rather than about a malformed request.
    async fn body_for(&self, spec: &RouteSpec, caller: Caller, target_id: &str) -> Option<Value> {
        match (spec.method, spec.path) {
            ("POST", "/api/v1/setup") => Some(json!({
                // Syntactically valid, and worthless: setup is complete,
                // so this route answers 404 whatever it is sent.
                "setup_token": self.app.issue_setup_token_after_provisioning().await,
                "username": "carol",
                "password": common::random_secret(),
            })),
            ("POST", "/api/v1/auth/login") => Some(json!({
                "username": self.admin_credentials.username,
                "password": self.admin_credentials.password,
            })),
            ("POST", "/api/v1/auth/password") => Some(json!({
                "current_password": self.password_of(caller),
                "new_password": common::random_secret(),
            })),
            ("POST", "/api/v1/users") => Some(json!({
                "username": format!("probe-{}", &target_id[..8]),
                "password": common::random_secret(),
                "role": "user",
            })),
            ("POST", "/api/v1/pair") => Some(json!({
                // Syntactically valid and worthless: a code that was
                // never issued, so this route answers the same
                // `invalid_pairing_code` whoever calls it.
                "pairing_code": "0123456789",
                "device_name": "probe",
                "platform": "linux",
            })),
            ("POST", "/api/v1/events") => Some(json!({ "events": [] })),
            ("PATCH", "/api/v1/devices/{id}") => Some(json!({ "name": "renamed" })),
            ("PATCH", _) => Some(json!({ "role": "user" })),
            _ => None,
        }
    }

    /// The right kind of `{id}` for this route: a device id for the
    /// device routes, an account id for the rest. Without this a
    /// device route would answer 404 for want of a real target and the
    /// walk could not tell that apart from a refusal.
    async fn target_for(&self, spec: &RouteSpec, caller: Caller) -> String {
        if spec.path.contains("/devices/{id}") {
            self.disposable_device(caller).await
        } else {
            self.disposable_account().await
        }
    }
}

fn method_of(spec: &RouteSpec) -> Method {
    Method::from_bytes(spec.method.as_bytes()).expect("the inventory names a real method")
}

/// The walk: every route, every kind of caller.
#[tokio::test]
async fn every_route_answers_each_caller_the_way_the_inventory_says() {
    for spec in INVENTORY {
        let fixture = Fixture::new().await;

        // Every target is created up front, before any call is made.
        // One target per caller, because a call may consume it -
        // DELETE does - but all of them before the loop, because a
        // call may also destroy the admin session the creation needs:
        // `POST /api/v1/auth/logout` as the admin does exactly that,
        // and any target created after it would fail to be created at
        // all. Hoisting them removes the dependency on which caller
        // happens to run last.
        let mut targets = Vec::with_capacity(EVERY_CALLER.len());
        for caller in EVERY_CALLER {
            targets.push(fixture.target_for(spec, caller).await);
        }

        for (caller, target) in EVERY_CALLER.into_iter().zip(targets) {
            let response = fixture.call(spec, caller, &target).await;
            let code = response.error_code().unwrap_or_default().to_owned();
            let label = format!("{} {} as {caller:?}", spec.method, spec.path);

            match (spec.access, caller) {
                // An anonymous route may refuse for its own reasons -
                // a bad pairing code, a spent setup token - but never
                // because of who is calling.
                //
                // The device caller is the exception worth naming: it
                // sends a bearer token, and `/api/v1/pair` is a
                // `BodySecret` route that neither reads nor refuses
                // one, so it still answers about the code.
                (Access::Public | Access::BodySecret, _) => {
                    assert!(
                        code != UNAUTHENTICATED && code != NOT_PERMITTED,
                        "{label}: an anonymous route must not refuse the caller ({code}, {:?})",
                        response.body
                    );
                }

                // A device token is not a session, and must be
                // refused on a session route exactly as anonymity is.
                (Access::Session | Access::Admin, Caller::Anonymous | Caller::Device) => {
                    assert_eq!(
                        response.status,
                        StatusCode::UNAUTHORIZED,
                        "{label}: {:?}",
                        response.body
                    );
                    assert_eq!(code, UNAUTHENTICATED, "{label}");
                }

                (Access::Admin, Caller::User) => {
                    assert_eq!(
                        response.status,
                        StatusCode::FORBIDDEN,
                        "{label}: {:?}",
                        response.body
                    );
                    assert_eq!(code, NOT_PERMITTED, "{label}");
                }

                // And a session is not a device. The cookie is
                // refused on a device route whether or not the
                // account behind it is real.
                (Access::Device, Caller::Anonymous | Caller::User | Caller::Admin) => {
                    assert_eq!(
                        response.status,
                        StatusCode::UNAUTHORIZED,
                        "{label}: {:?}",
                        response.body
                    );
                    assert_eq!(code, UNAUTHENTICATED, "{label}");
                }

                (Access::Session, Caller::User | Caller::Admin)
                | (Access::Admin, Caller::Admin)
                | (Access::Device, Caller::Device) => {
                    assert!(
                        code != UNAUTHENTICATED && code != NOT_PERMITTED,
                        "{label}: an authorized caller was refused ({code}, {:?})",
                        response.body
                    );
                    // The route exists and answers. `/api/v1/setup` is
                    // the one deliberate 404: it is indistinguishable
                    // from an absent route once an admin exists.
                    if spec.path != "/api/v1/setup" {
                        assert_ne!(
                            response.status,
                            StatusCode::NOT_FOUND,
                            "{label} is in the inventory but answers 404"
                        );
                    }
                }
            }
        }
    }
}

/// The two cross-authentication rules, stated as their own test
/// rather than left implicit in the walk above.
///
/// The walk covers them with one spelling of the scheme. These are
/// the cases a walk cannot express: that the scheme is matched
/// case-insensitively, that a duplicated cookie does not slip past,
/// and that a device route refuses a cookie even when a perfectly
/// good token comes with it.
#[tokio::test]
async fn a_device_route_refuses_the_session_cookie_however_it_arrives() {
    let fixture = Fixture::new().await;

    for spec in INVENTORY
        .iter()
        .filter(|spec| spec.access == Access::Device)
    {
        let label = format!("{} {}", spec.method, spec.path);
        let body = fixture
            .body_for(spec, Caller::Device, "")
            .await
            .unwrap_or(json!({}));

        // A valid device token is present in every one of these, so
        // the refusal can only be about the cookie.
        let with_cookie = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), spec.path)
                    .authenticated_as_device(&fixture.device)
                    .cookie(&fixture.user.cookie)
                    .json(body.clone()),
            )
            .await;
        assert_eq!(
            with_cookie.status,
            StatusCode::UNAUTHORIZED,
            "{label}: a session cookie must be refused even alongside a valid token: {:?}",
            with_cookie.body
        );

        // Two copies of the cookie. `cookie::read` deliberately
        // returns None for a duplicate, so a presence check written
        // as `read(..).is_some()` would have let this through.
        let duplicated = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), spec.path)
                    .authenticated_as_device(&fixture.device)
                    .cookie(&format!("{}; {}", fixture.user.cookie, fixture.user.cookie))
                    .json(body.clone()),
            )
            .await;
        assert_eq!(
            duplicated.status,
            StatusCode::UNAUTHORIZED,
            "{label}: a duplicated cookie must not slip past the refusal: {:?}",
            duplicated.body
        );

        // A cookie belonging to nothing at all is still a refusal,
        // so the rule is about the cookie's presence rather than
        // about it naming a live session.
        let bogus = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), spec.path)
                    .authenticated_as_device(&fixture.device)
                    .cookie("__Host-sws=not-a-real-token")
                    .json(body.clone()),
            )
            .await;
        assert_eq!(bogus.status, StatusCode::UNAUTHORIZED, "{label}");

        // Someone else's cookies must not break it, though.
        let other_cookies = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), spec.path)
                    .authenticated_as_device(&fixture.device)
                    .cookie("cf_bm=abc; _ga=1")
                    .json(body),
            )
            .await;
        assert_ne!(
            other_cookies.status,
            StatusCode::UNAUTHORIZED,
            "{label}: an unrelated cookie must not break device auth: {:?}",
            other_cookies.body
        );
    }
}

/// The scheme is case-insensitive per RFC 7235, in both directions:
/// a device route must accept `bearer`, and a session route must
/// refuse it.
#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive_on_both_kinds_of_route() {
    let fixture = Fixture::new().await;

    // The control: the same session, with no Authorization header at
    // all, must work. Without this, a 401 inside the loop below could
    // just as easily mean the session or CSRF setup is broken, rather
    // than proving the bearer header is what gets refused.
    let control = fixture
        .app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&fixture.user),
        )
        .await;
    assert_eq!(
        control.status,
        StatusCode::OK,
        "the session alone must work, with nothing to compare the bearer cases against: {:?}",
        control.body
    );

    for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
        let accepted = fixture
            .app
            .send(
                TestRequest::get("/api/v1/device/me")
                    .bearer_with_scheme(scheme, &fixture.device.token),
            )
            .await;
        assert_eq!(
            accepted.status,
            StatusCode::OK,
            "{scheme} must authenticate a device: {:?}",
            accepted.body
        );

        // And the same spelling must not slip past the refusal on a
        // session route, which is the direction that would otherwise
        // be bypassable by lowercasing.
        let refused = fixture
            .app
            .send(
                TestRequest::get("/api/v1/auth/me")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&fixture.user)
                    .bearer_with_scheme(scheme, &fixture.device.token),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "{scheme} must be refused on a session route: {:?}",
            refused.body
        );
    }

    // A non-bearer scheme is infrastructure's business, not ours, and
    // must leave a session route working.
    let unaffected = fixture
        .app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&fixture.user)
                .authorization("Basic dXNlcjpwdw=="),
        )
        .await;
    assert_eq!(
        unaffected.status,
        StatusCode::OK,
        "a proxy's Basic credentials must not break a session route: {:?}",
        unaffected.body
    );
}

/// `sets_session_cookie` has to mean something, or it is just a
/// comment that the `Origin` whitelist happens to read.
#[tokio::test]
async fn exactly_the_routes_that_declare_a_cookie_send_one() {
    for spec in INVENTORY {
        let fixture = Fixture::new().await;
        let label = format!("{} {}", spec.method, spec.path);

        // Called as a caller it will accept, so a refusal is not what
        // is being measured.
        let caller = match spec.access {
            Access::Public | Access::BodySecret => Caller::Anonymous,
            Access::Session => Caller::User,
            Access::Admin => Caller::Admin,
            Access::Device => Caller::Device,
        };
        let target = fixture.target_for(spec, caller).await;
        let response = fixture.call(spec, caller, &target).await;

        assert_eq!(
            response.set_cookie().is_some(),
            spec.sets_session_cookie,
            "{label} declares sets_session_cookie = {} but answered {:?} with Set-Cookie = {:?}",
            spec.sets_session_cookie,
            response.status,
            response.set_cookie()
        );
    }
}

/// A route the table marks `csrf` must refuse both a missing and a
/// mismatched token - before it even looks the session up, so the
/// answer is the same for a live session and a dead one.
#[tokio::test]
async fn every_csrf_route_refuses_a_missing_or_wrong_token() {
    for spec in INVENTORY.iter().filter(|spec| spec.csrf) {
        let fixture = Fixture::new().await;
        // The probes below send the admin's cookie, so the target is
        // the admin's too.
        let target = fixture.target_for(spec, Caller::Admin).await;
        let path = spec.path.replace("{id}", &target);
        let label = format!("{} {}", spec.method, spec.path);

        let without = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), &path)
                    .origin(GOOD_ORIGIN)
                    .cookie(&fixture.admin.cookie)
                    .json(json!({})),
            )
            .await;
        assert_eq!(without.status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(without.error_code(), Some("csrf_token_missing"), "{label}");

        let wrong = fixture
            .app
            .send(
                TestRequest::new(method_of(spec), &path)
                    .origin(GOOD_ORIGIN)
                    .cookie(&fixture.admin.cookie)
                    .csrf(&common::random_secret())
                    .json(json!({})),
            )
            .await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(wrong.error_code(), Some("csrf_token_invalid"), "{label}");
    }
}

/// The `Origin` rule has to mean something in both directions: a
/// `Checked` route refuses a foreign origin, and a
/// `NoAmbientAuthority` one does not.
#[tokio::test]
async fn the_origin_check_follows_the_inventory() {
    for spec in INVENTORY {
        let fixture = Fixture::new().await;
        let caller = if spec.access == Access::Device {
            Caller::Device
        } else {
            Caller::Admin
        };
        let target = fixture.target_for(spec, caller).await;
        let path = spec.path.replace("{id}", &target);
        let label = format!("{} {}", spec.method, spec.path);

        let mut request = TestRequest::new(method_of(spec), &path).origin(BAD_ORIGIN);
        // Authenticated as whatever the route accepts, so the answer
        // is about the origin rather than about the credential.
        match spec.access {
            Access::Public | Access::BodySecret => {}
            Access::Session | Access::Admin => request = request.authenticated(&fixture.admin),
            Access::Device => request = request.authenticated_as_device(&fixture.device),
        }
        if let Some(body) = fixture.body_for(spec, caller, &target).await {
            request = request.json(body);
        }
        let response = fixture.app.send(request).await;

        if spec.origin_checked() && !is_safe(spec.method) {
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(response.error_code(), Some("origin_mismatch"), "{label}");
        } else {
            assert_ne!(
                response.error_code(),
                Some("origin_mismatch"),
                "{label} is not Origin-checked for this method: {:?}",
                response.body
            );
        }
    }
}

/// A GET is allowed from any origin by the rule in `auth::origin`, so an
/// `origin_checked` GET still answers a foreign origin.
fn is_safe(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// Every limit the table says a *layer* enforces must actually refuse
/// once it is reached, counting every attempt rather than only the ones
/// that fail for other reasons.
#[tokio::test]
async fn every_layer_enforced_rate_limit_refuses_when_reached() {
    let tight = &[
        ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "2/300"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_SETUP_IP", "2/3600"),
        ("SCREENWARD_RATE_LIMIT_PW_CHANGE", "2/900"),
        ("SCREENWARD_RATE_LIMIT_PAIR_IP", "2/300"),
        // Left wide here so the per-address bucket is what refuses;
        // the ceiling gets its own test below, where nothing else
        // could be the cause.
        ("SCREENWARD_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
        ("SCREENWARD_RATE_LIMIT_INGEST_DEVICE", "2/60"),
    ];

    for spec in INVENTORY.iter().filter(|spec| {
        spec.rate_limits
            .iter()
            .any(|limit| limit.enforced_by_shared_layer())
    }) {
        let app = TestApp::with_vars(tight).await;
        let (credentials, admin) = app.provisioned_admin().await;
        let label = format!("{} {}", spec.method, spec.path);

        // Paired before the loop, so pairing's own budget is not what
        // the ingest route's limit is measured against.
        let device = if spec.access == Access::Device {
            Some(app.pair_device(&admin, "limit-probe", "linux").await)
        } else {
            None
        };

        let mut statuses = Vec::new();
        let mut limited = None;
        for _ in 0..4 {
            let mut request = TestRequest::new(method_of(spec), spec.path).origin(GOOD_ORIGIN);
            match spec.access {
                Access::Public | Access::BodySecret => {}
                Access::Session | Access::Admin => request = request.authenticated(&admin),
                Access::Device => {
                    request =
                        request.authenticated_as_device(device.as_ref().expect("paired above"));
                }
            }
            request = match (spec.method, spec.path) {
                ("POST", "/api/v1/setup") => request.json(json!({
                    "setup_token": app.issue_setup_token_after_provisioning().await,
                    "username": "carol",
                    "password": common::random_secret(),
                })),
                ("POST", "/api/v1/auth/login") => request.json(json!({
                    "username": credentials.username,
                    "password": credentials.password,
                })),
                // Deliberately wrong every time: a refused attempt must
                // count too, or a wrong-password flood would be free.
                ("POST", "/api/v1/auth/password") => request.json(json!({
                    "current_password": common::random_secret(),
                    "new_password": common::random_secret(),
                })),
                // Also deliberately wrong every time, for the same
                // reason: the limit must count attempts, not failures.
                ("POST", "/api/v1/pair") => request.json(json!({
                    "pairing_code": "0123456789",
                    "device_name": "probe",
                    "platform": "linux",
                })),
                // An empty batch is a successful request, which is
                // the point here: a *succeeding* ingest call must
                // count too, or a client could sync without limit.
                ("POST", "/api/v1/events") => request.json(json!({ "events": [] })),
                _ => request,
            };

            let response = app.send(request).await;
            statuses.push(response.status);
            if response.status == StatusCode::TOO_MANY_REQUESTS && limited.is_none() {
                limited = Some(response);
            }
        }

        // The first attempt must get through - a limit that refuses
        // everyone from the start would pass the check below without
        // being a limit at all. The setup route is the one place where
        // an earlier request (provisioning the admin) has already
        // spent part of the budget, which is why the refusal is looked
        // for anywhere in the run rather than at a fixed position.
        assert_ne!(
            statuses[0],
            StatusCode::TOO_MANY_REQUESTS,
            "{label} refused its first attempt, saw {statuses:?}"
        );
        let limited =
            limited.unwrap_or_else(|| panic!("{label} was never limited, saw {statuses:?}"));
        assert_eq!(limited.error_code(), Some("rate_limited"), "{label}");
        assert!(
            limited.retry_after().is_some_and(|after| after >= 1),
            "{label} must say when to come back"
        );
        assert_eq!(
            statuses[statuses.len() - 1],
            StatusCode::TOO_MANY_REQUESTS,
            "{label} must stay limited once it is, saw {statuses:?}"
        );
    }
}

/// A path that is in no entry answers 404, and a method that is in no
/// entry for a listed path answers 405 - neither reaches a handler.
#[tokio::test]
async fn nothing_outside_the_inventory_is_served() {
    let fixture = Fixture::new().await;

    for path in ["/api/v1/users/", "/api/v1/user", "/api/v2/users", "/admin"] {
        let response = fixture
            .app
            .send(
                TestRequest::get(path)
                    .origin(GOOD_ORIGIN)
                    .authenticated(&fixture.admin),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "{path} must not be served"
        );
    }

    // DELETE is in no entry for this path, though POST and GET are.
    let response = fixture
        .app
        .send(
            TestRequest::delete("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&fixture.admin),
        )
        .await;
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
}

/// Calls that attach request-handling surface which no inventory entry
/// would describe. None of them may appear anywhere in the sources.
///
/// `.route(` is not in this list because it is how the one helper
/// registers a listed route; it is checked separately below. The rest
/// have no legitimate use in this server: `.merge(` and `.nest(` graft
/// in whole routers, and the `_service` variants do the same with a
/// bare tower service, which would not pass through the helper and so
/// would carry none of the layers an entry attaches.
const FORBIDDEN_ANYWHERE: &[&str] = &[
    ".merge(",
    ".nest(",
    ".nest_service(",
    ".route_service(",
    ".fallback_service(",
];

/// Calls allowed only in `routes/mod.rs`, with how many times.
///
/// `.route(` is the single registration in the helper. `.fallback(` is
/// the 404 catch-all, which is not a route at all - but it is route
/// table surface, so it belongs in the same file under the same eyes.
const CONFINED_TO_THE_ROUTE_TABLE: &[(&str, usize)] = &[(".route(", 1), (".fallback(", 1)];

/// The structural guard: request-handling surface may only be attached
/// in the one helper that looks its entry up in the inventory first.
///
/// Without this, someone could add a perfectly working route that no
/// entry describes and nothing above would notice, because every test
/// here starts from the table.
///
/// It is a textual check, so be clear about its limits: it skips
/// comment lines, and it cannot see a call assembled in a macro or out
/// of a string. It catches the ordinary mistake - someone reaching for
/// `.merge(` or `.nest(` because it is the obvious way to add a route -
/// not a determined author.
#[test]
fn no_source_file_attaches_routes_outside_the_inventory_helper() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&src);
    assert!(!sources.is_empty(), "the scan must read something");

    for needle in FORBIDDEN_ANYWHERE {
        let found = occurrences(&sources, needle);
        assert!(
            found.is_empty(),
            "{needle} attaches routing surface the inventory cannot describe, found {found:?}"
        );
    }

    for (needle, allowed) in CONFINED_TO_THE_ROUTE_TABLE {
        let found = occurrences(&sources, needle);
        assert_eq!(
            found.len(),
            1,
            "{needle} must appear in exactly one file, found {found:?}"
        );
        let (path, count) = &found[0];
        assert!(
            path.ends_with("routes/mod.rs"),
            "{needle} must only appear in routes/mod.rs, found it in {path:?}"
        );
        assert_eq!(
            count, allowed,
            "{needle} must appear {allowed} time(s) in routes/mod.rs, found {count}"
        );
    }
}

/// Which files contain `needle`, and how often, ignoring comment lines:
/// prose about route registration - including the comments explaining
/// this very rule - is not a registration.
fn occurrences(sources: &[std::path::PathBuf], needle: &str) -> Vec<(std::path::PathBuf, usize)> {
    let mut found = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(path).expect("a source file must be readable");
        let count = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(needle))
            .count();
        if count > 0 {
            found.push((path.clone(), count));
        }
    }
    found
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).expect("the source directory must be readable");

    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            files.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}
