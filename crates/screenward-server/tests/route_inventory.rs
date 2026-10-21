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
//!   * a route marked `origin_checked` refuses a foreign `Origin`, and
//!     one not marked does not;
//!   * a route with a layer-enforced rate limit really does refuse once
//!     the limit is reached.
//!
//! Plus the one structural check that keeps the table authoritative: no
//! source file outside the single registration helper may call
//! `.route(`.

mod common;

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use common::{Credentials, Session, TestApp, TestRequest, TestResponse, BAD_ORIGIN, GOOD_ORIGIN};
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
}

/// One app with an admin and an ordinary user, both logged in.
struct Fixture {
    app: TestApp,
    admin: Session,
    admin_credentials: Credentials,
    user: Session,
    user_credentials: Credentials,
}

impl Fixture {
    async fn new() -> Self {
        let app = TestApp::new().await;
        let (admin_credentials, admin) = app.provisioned_admin().await;
        let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
        let user = app.log_in(&user_credentials).await;
        Self {
            app,
            admin,
            admin_credentials,
            user,
            user_credentials,
        }
    }

    fn session(&self, caller: Caller) -> Option<&Session> {
        match caller {
            Caller::Anonymous => None,
            Caller::User => Some(&self.user),
            Caller::Admin => Some(&self.admin),
        }
    }

    fn password_of(&self, caller: Caller) -> String {
        match caller {
            Caller::Anonymous => common::random_secret(),
            Caller::User => self.user_credentials.password.clone(),
            Caller::Admin => self.admin_credentials.password.clone(),
        }
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
            ("PATCH", _) => Some(json!({ "role": "user" })),
            _ => None,
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

        for caller in [Caller::Anonymous, Caller::User, Caller::Admin] {
            let target = fixture.disposable_account().await;
            let response = fixture.call(spec, caller, &target).await;
            let code = response.error_code().unwrap_or_default().to_owned();
            let label = format!("{} {} as {caller:?}", spec.method, spec.path);

            match (spec.access, caller) {
                // A public route may refuse for its own reasons, but
                // never because of who is calling.
                (Access::Public, _) => {
                    assert!(
                        code != UNAUTHENTICATED && code != NOT_PERMITTED,
                        "{label}: a public route must not refuse the caller ({code}, {:?})",
                        response.body
                    );
                }

                (Access::Session | Access::Admin, Caller::Anonymous) => {
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

                (Access::Session, Caller::User | Caller::Admin)
                | (Access::Admin, Caller::Admin) => {
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

/// A route the table marks `csrf` must refuse both a missing and a
/// mismatched token - before it even looks the session up, so the
/// answer is the same for a live session and a dead one.
#[tokio::test]
async fn every_csrf_route_refuses_a_missing_or_wrong_token() {
    for spec in INVENTORY.iter().filter(|spec| spec.csrf) {
        let fixture = Fixture::new().await;
        let target = fixture.disposable_account().await;
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

/// `origin_checked` has to mean something in both directions: a checked
/// route refuses a foreign origin, and an exempt one does not.
#[tokio::test]
async fn the_origin_check_follows_the_inventory() {
    for spec in INVENTORY {
        let fixture = Fixture::new().await;
        let target = fixture.disposable_account().await;
        let path = spec.path.replace("{id}", &target);
        let label = format!("{} {}", spec.method, spec.path);

        let mut request = TestRequest::new(method_of(spec), &path).origin(BAD_ORIGIN);
        if spec.access != Access::Public {
            request = request.authenticated(&fixture.admin);
        }
        if let Some(body) = fixture.body_for(spec, Caller::Admin, &target).await {
            request = request.json(body);
        }
        let response = fixture.app.send(request).await;

        if spec.origin_checked && !is_safe(spec.method) {
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
        ("SCREENWARD_RATE_LIMIT_PASSWORD_USER", "2/900"),
    ];

    for spec in INVENTORY.iter().filter(|spec| {
        spec.rate_limits
            .iter()
            .any(|limit| limit.enforced_by_layer())
    }) {
        let app = TestApp::with_vars(tight).await;
        let (credentials, admin) = app.provisioned_admin().await;
        let label = format!("{} {}", spec.method, spec.path);

        let mut statuses = Vec::new();
        let mut limited = None;
        for _ in 0..4 {
            let mut request = TestRequest::new(method_of(spec), spec.path).origin(GOOD_ORIGIN);
            if spec.access != Access::Public {
                request = request.authenticated(&admin);
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

/// The structural guard: a route may only be registered in the one
/// helper that looks its entry up in the inventory first.
///
/// Without this, someone could add a perfectly working route that no
/// entry describes and nothing above would notice, because every test
/// here starts from the table.
#[test]
fn no_source_file_registers_a_route_outside_the_inventory_helper() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();

    for path in rust_sources(&src) {
        let text = std::fs::read_to_string(&path).expect("a source file must be readable");
        // Comment lines are skipped: prose about route registration -
        // including the comments explaining this very rule - is not a
        // registration.
        let count = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(".route("))
            .count();
        if count > 0 {
            found.push((path, count));
        }
    }

    assert_eq!(
        found.len(),
        1,
        ".route( must appear in exactly one file, found {found:?}"
    );
    let (path, count) = &found[0];
    assert!(
        path.ends_with("routes/mod.rs"),
        ".route( must only appear in routes/mod.rs, found it in {path:?}"
    );
    assert_eq!(
        *count, 1,
        "routes/mod.rs must register routes in exactly one place"
    );
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
