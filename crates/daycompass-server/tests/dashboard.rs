//! The M5 dashboard, over HTTP: login and logout, the overview, error
//! rendering, the static assets, and the headers every response carries.
//!
//! The route-by-route protections (access, CSRF, `Origin`, rate limits)
//! are walked for the dashboard routes by `tests/route_inventory.rs`,
//! like for every other route. This file is about what that walk cannot
//! see: what a browser is actually shown, and the properties specific
//! to pages - that the login form shares the API login's budget, that a
//! page is never cached, that nothing from a request reaches the HTML.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};
use daycompass_server::middleware::CONTENT_SECURITY_POLICY;

/// The cookie name, as `auth::cookie` sets it.
const COOKIE_PREFIX: &str = "__Host-dcs=";

#[tokio::test]
async fn the_login_page_renders_a_form_and_sets_no_cookie() {
    let app = TestApp::new().await;
    let response = app.send(TestRequest::get("/login")).await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(response
        .header("content-type")
        .is_some_and(|value| value.starts_with("text/html")));
    assert!(response.text.contains(r#"action="/login""#));
    assert!(response.set_cookie().is_none());
}

#[tokio::test]
async fn a_plain_form_login_sets_the_cookie_and_redirects() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let response = app
        .send(TestRequest::post("/login").origin(GOOD_ORIGIN).form(&[
            ("username", &credentials.username),
            ("password", &credentials.password),
        ]))
        .await;

    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.text);
    assert_eq!(response.location(), Some("/"));
    let cookie = response.session_cookie().expect("a session cookie");
    assert!(cookie.starts_with(COOKIE_PREFIX));

    // And the cookie it handed out is a real session.
    let me = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&cookie))
        .await;
    assert_eq!(me.status, StatusCode::OK);
}

#[tokio::test]
async fn an_htmx_login_is_redirected_by_header() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let response = app
        .send(
            TestRequest::post("/login")
                .origin(GOOD_ORIGIN)
                .htmx()
                .form(&[
                    ("username", &credentials.username),
                    ("password", &credentials.password),
                ]),
        )
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("hx-redirect"), Some("/"));
    assert!(response.session_cookie().is_some());
}

/// A failed login is the API's failure, rendered: same status, same
/// code, and nothing typed into the form shows up in the page.
#[tokio::test]
async fn a_failed_login_renders_the_api_error_without_echoing_input() {
    let app = TestApp::new().await;
    app.provision_admin().await;
    let typed = "<script>probe</script>";

    for htmx in [false, true] {
        let mut request = TestRequest::post("/login")
            .origin(GOOD_ORIGIN)
            .form(&[("username", typed), ("password", typed)]);
        if htmx {
            request = request.htmx();
        }
        let response = app.send(request).await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "htmx={htmx}");
        assert_eq!(response.error_code(), Some("invalid_credentials"));
        assert!(response.set_cookie().is_none());
        assert!(
            !response.text.contains("probe"),
            "input reached the page: {}",
            response.text
        );
        if htmx {
            assert_eq!(response.header("hx-retarget"), Some("#dc-flash"));
        } else {
            assert!(response.text.starts_with("<!doctype html>"));
        }
    }
}

/// The login form and the JSON login spend the *same* per-username
/// bucket. Two buckets would double what a guessing attack gets.
#[tokio::test]
async fn the_form_and_the_api_share_the_username_budget() {
    let app = TestApp::with_vars(&[("DAYCOMPASS_RATE_LIMIT_LOGIN_USERNAME", "2/300")]).await;
    let credentials = app.provision_admin().await;
    let wrong = common::random_secret();

    let api = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({ "username": credentials.username, "password": wrong })),
        )
        .await;
    assert_eq!(api.status, StatusCode::UNAUTHORIZED);

    let form = app
        .send(
            TestRequest::post("/login")
                .origin(GOOD_ORIGIN)
                .form(&[("username", &credentials.username), ("password", &wrong)]),
        )
        .await;
    assert_eq!(form.status, StatusCode::UNAUTHORIZED);

    // The budget is spent, so even the right password is refused - on
    // either route.
    let right = [
        ("username", credentials.username.as_str()),
        ("password", credentials.password.as_str()),
    ];
    let limited = app
        .send(TestRequest::post("/login").origin(GOOD_ORIGIN).form(&right))
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), Some("rate_limited"));
    assert!(limited.retry_after().is_some_and(|after| after >= 1));

    let limited_api = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(
                    json!({ "username": credentials.username, "password": credentials.password }),
                ),
        )
        .await;
    assert_eq!(limited_api.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_overview_needs_a_session() {
    let app = TestApp::new().await;

    let page = app.send(TestRequest::get("/")).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_eq!(page.location(), Some("/login"));

    // htmx cannot follow a 303 into a full page, so it is told by
    // header instead - and the status still says what happened.
    let htmx = app.send(TestRequest::get("/").htmx()).await;
    assert_eq!(htmx.status, StatusCode::UNAUTHORIZED);
    assert_eq!(htmx.header("hx-redirect"), Some("/login"));

    // A cookie that names no session is no better than none.
    let bogus = app
        .send(TestRequest::get("/").cookie("__Host-dcs=not-a-real-token"))
        .await;
    assert_eq!(bogus.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_overview_carries_the_csrf_token_for_htmx_and_is_not_cached() {
    let app = TestApp::new().await;
    let (credentials, admin) = app.provisioned_admin().await;

    let response = app.send(TestRequest::get("/").cookie(&admin.cookie)).await;

    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let expected = format!(r#"hx-headers='{{"X-CSRF-Token": "{}"}}'"#, admin.csrf_token);
    assert!(response.text.contains(&expected), "{}", response.text);
    assert!(response.text.contains(&credentials.username));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    // Nothing tracked yet.
    assert!(response.text.contains("Nothing tracked yet"));
}

/// The overview is the caller's own, by construction: an admin's
/// categories never appear on another account's page, or the other way
/// round.
#[tokio::test]
async fn the_overview_shows_only_the_callers_own_screen_time() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    // The admin's history: one categorized event, with a category name
    // that would break the page if it were not escaped.
    let rule = app
        .send(
            TestRequest::post("/api/v1/category-rules")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "kind": "app_id",
                    "pattern": "org.example.game",
                    "category": "<b>Games</b>",
                })),
        )
        .await;
    assert_eq!(rule.status, StatusCode::CREATED, "{:?}", rule.body);

    let device = app.pair_device(&admin, "laptop", "linux").await;
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let ingested = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(json!({
                    "events": [{
                        "event_id": "0123456789abcdef0123456789abcdef",
                        "start_ts": now - 5000,
                        "duration_secs": 3600 + 14 * 60,
                        "app_id": "org.example.game",
                        "label": "A Very Private Thing",
                    }],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 1, "{:?}", ingested.body);

    let own = app.send(TestRequest::get("/").cookie(&admin.cookie)).await;
    assert_eq!(own.status, StatusCode::OK);
    assert!(
        own.text.contains("&#60;b&#62;Games&#60;/b&#62;"),
        "{}",
        own.text
    );
    assert!(
        !own.text.contains("<b>Games</b>"),
        "the category was not escaped"
    );
    assert!(own.text.contains("1h 14m"), "{}", own.text);
    // Totals per category only: never the app id or the label.
    assert!(!own.text.contains("org.example.game"));
    assert!(!own.text.contains("A Very Private Thing"));

    let bobs = app.send(TestRequest::get("/").cookie(&bob.cookie)).await;
    assert_eq!(bobs.status, StatusCode::OK);
    assert!(
        !bobs.text.contains("Games"),
        "another account's category leaked"
    );
    assert!(bobs.text.contains("Nothing tracked yet"));
}

#[tokio::test]
async fn logging_out_ends_the_session_and_clears_the_cookie() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let response = app
        .send(
            TestRequest::post("/logout")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .htmx(),
        )
        .await;

    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.header("hx-redirect"), Some("/login"));
    let cleared = response.set_cookie().expect("the cookie is cleared");
    assert!(cleared.starts_with(COOKIE_PREFIX) && cleared.contains("Max-Age=0"));

    let after = app.send(TestRequest::get("/").cookie(&admin.cookie)).await;
    assert_eq!(
        after.status,
        StatusCode::SEE_OTHER,
        "the session must be gone"
    );
}

/// A logout without the token is refused like any other write - and the
/// refusal is a page, not JSON.
#[tokio::test]
async fn logging_out_without_the_csrf_token_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let response = app
        .send(
            TestRequest::post("/logout")
                .origin(GOOD_ORIGIN)
                .cookie(&admin.cookie),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error_code(), Some("csrf_token_missing"));
    assert!(response.text.starts_with("<!doctype html>"));

    let still = app.send(TestRequest::get("/").cookie(&admin.cookie)).await;
    assert_eq!(still.status, StatusCode::OK, "the session must survive");
}

/// One CSP everywhere: pages, the API, and the assets.
#[tokio::test]
async fn every_response_carries_the_content_security_policy() {
    let app = TestApp::new().await;
    for path in [
        "/login",
        "/",
        "/healthz",
        "/api/v1/auth/me",
        "/static/daycompass.css",
        "/static/favicon.svg",
        "/static/missing.css",
        "/no-such-page",
    ] {
        let response = app.send(TestRequest::get(path)).await;
        assert_eq!(
            response.header("content-security-policy"),
            Some(CONTENT_SECURITY_POLICY),
            "{path}"
        );
    }
    assert!(CONTENT_SECURITY_POLICY.contains("default-src 'none'"));
    assert!(!CONTENT_SECURITY_POLICY.contains("unsafe"));
}

#[tokio::test]
async fn assets_are_served_with_their_type_and_revalidated_by_etag() {
    let app = TestApp::new().await;

    for (name, content_type) in [
        ("daycompass.css", "text/css; charset=utf-8"),
        ("htmx-2.0.11.min.js", "text/javascript; charset=utf-8"),
        ("Fredoka-Variable.woff2", "font/woff2"),
        ("Nunito-Variable.woff2", "font/woff2"),
        ("Fredoka-OFL.txt", "text/plain; charset=utf-8"),
        ("favicon.svg", "image/svg+xml"),
    ] {
        let path = format!("/static/{name}");
        let response = app.send(TestRequest::get(&path)).await;
        assert_eq!(response.status, StatusCode::OK, "{name}");
        assert_eq!(
            response.header("content-type"),
            Some(content_type),
            "{name}"
        );
        assert_eq!(response.header("cache-control"), Some("no-cache"), "{name}");
        let etag = response.header("etag").expect("an etag").to_owned();

        let again = app
            .send(TestRequest::get(&path).header("if-none-match", &etag))
            .await;
        assert_eq!(again.status, StatusCode::NOT_MODIFIED, "{name}");
        assert!(again.text.is_empty());
    }
}

/// The name is looked up in a table and never used as a path.
#[tokio::test]
async fn an_unknown_or_traversing_asset_name_is_a_404_page() {
    let app = TestApp::new().await;
    for path in [
        "/static/missing.css",
        "/static/..%2F..%2FCargo.toml",
        "/static/%2e%2e",
        "/static/daycompass.CSS",
    ] {
        let response = app.send(TestRequest::get(path)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response.error_code(), Some("not_found"), "{path}");
        assert!(!response.text.contains("[package]"), "{path}");
    }
}

/// The API's own error shape is untouched by the dashboard: still JSON,
/// still `no-store`.
#[tokio::test]
async fn api_errors_stay_json() {
    let app = TestApp::new().await;
    let response = app.send(TestRequest::get("/api/v1/auth/me")).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.body["error"]["code"], "unauthenticated");
    assert_eq!(response.header("cache-control"), Some("no-store"));
}
