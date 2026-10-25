//! The M5 dashboard's own-account pages, over HTTP: devices and pairing,
//! category rules, and the account page.
//!
//! The protections every route has (session, CSRF, `Origin`, rate
//! limits) are walked by `tests/route_inventory.rs`. This file checks
//! what those routes *do*: that every write is scoped to the caller,
//! answers with the re-rendered list, and agrees with the JSON route it
//! shares a service function with.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

/// A dashboard write: htmx, matching `Origin`, cookie and CSRF token.
fn write(path: &str, session: &Session) -> TestRequest {
    TestRequest::post(path)
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .htmx()
}

async fn page(app: &TestApp, path: &str, session: &Session) -> TestResponse {
    let response = app
        .send(TestRequest::get(path).cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.text);
    response
}

#[tokio::test]
async fn the_devices_page_lists_only_the_callers_own_devices() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    app.pair_device(&admin, "admin-laptop", "linux").await;
    app.pair_device(&bob, "bob-phone", "android").await;

    let bobs = page(&app, "/devices", &bob).await;
    assert!(bobs.text.contains("bob-phone"));
    assert!(
        !bobs.text.contains("admin-laptop"),
        "another account's device"
    );
    assert!(bobs.text.contains(r#"aria-current="page">"#));
}

#[tokio::test]
async fn renaming_a_device_answers_with_the_new_list() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    let path = format!("/devices/{}/rename", device.id);
    let response = app
        .send(write(&path, &admin).form(&[("name", "desk")]))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(response.text.contains(r#"id="devices""#));
    assert!(response.text.contains("desk"));
    assert!(
        !response.text.contains("<!doctype html>"),
        "a fragment, not a page"
    );

    // The name rules are the API's.
    let blank = app.send(write(&path, &admin).form(&[("name", "")])).await;
    assert_eq!(blank.status, StatusCode::BAD_REQUEST);
    assert_eq!(blank.header("hx-retarget"), Some("#dc-flash"));
}

/// "No such device" and "not yours" are one answer here too.
#[tokio::test]
async fn another_accounts_device_is_not_found() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let admins = app.pair_device(&admin, "laptop", "linux").await;

    for path in [
        format!("/devices/{}/rename", admins.id),
        format!("/devices/{}/revoke", admins.id),
        "/devices/no-such-device/revoke".to_owned(),
    ] {
        let response = app
            .send(write(&path, &bob).form(&[("name", "mine-now")]))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response.error_code(), Some("not_found"), "{path}");
    }

    let still = page(&app, "/devices", &admin).await;
    assert!(still.text.contains("laptop") && !still.text.contains("Revoked"));
}

#[tokio::test]
async fn revoking_a_device_stops_its_token() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    let response = app
        .send(write(&format!("/devices/{}/revoke", device.id), &admin))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(response.text.contains("Revoked"));

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_pairing_code_from_the_page_pairs_a_device() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let response = app.send(write("/devices/pairing-code", &admin)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let start = response
        .text
        .find(r#"<span class="dc-code">"#)
        .expect("the code")
        + 22;
    let end = start + response.text[start..].find('<').unwrap();
    let code = response.text[start..end].to_owned();

    let device = app.redeem_pairing_code(&code, "tablet", "android").await;
    assert!(!device.token.is_empty());
    assert!(page(&app, "/devices", &admin).await.text.contains("tablet"));
}

#[tokio::test]
async fn category_rules_are_added_and_deleted_from_the_page() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let added = app
        .send(write("/category-rules", &admin).form(&[
            ("kind", "domain"),
            ("pattern", "docs.example.com"),
            ("category", "Study"),
        ]))
        .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    assert!(added.text.contains(r#"id="rules""#));
    assert!(added.text.contains("docs.example.com") && added.text.contains("Study"));

    // The same rule twice is the API's conflict.
    let again = app
        .send(write("/category-rules", &admin).form(&[
            ("kind", "domain"),
            ("pattern", "docs.example.com"),
            ("category", "Other"),
        ]))
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.error_code(), Some("category_rule_duplicate"));

    // And it is the same rule the API sees.
    let listed = app
        .send(
            TestRequest::get("/api/v1/category-rules")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    let id = listed.body["rules"][0]["id"].as_str().unwrap().to_owned();

    let deleted = app
        .send(write(&format!("/category-rules/{id}/delete"), &admin))
        .await;
    assert_eq!(deleted.status, StatusCode::OK);
    assert!(!deleted.text.contains("docs.example.com"));
}

#[tokio::test]
async fn another_accounts_rule_cannot_be_deleted() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    let created = app
        .send(
            TestRequest::post("/api/v1/category-rules")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(
                    json!({ "kind": "app_id", "pattern": "org.example.game", "category": "Games" }),
                ),
        )
        .await;
    let id = created.body["rule"]["id"].as_str().unwrap().to_owned();

    let response = app
        .send(write(&format!("/category-rules/{id}/delete"), &bob))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(!page(&app, "/category-rules", &bob)
        .await
        .text
        .contains("Games"));
    assert!(page(&app, "/category-rules", &admin)
        .await
        .text
        .contains("Games"));
}

#[tokio::test]
async fn changing_the_password_ends_other_sessions_and_logs_it() {
    let app = TestApp::new().await;
    let (credentials, admin) = app.provisioned_admin().await;
    let other = app.log_in(&credentials).await;
    let new_password = common::random_secret();

    let wrong = app
        .send(write("/account/password", &admin).form(&[
            ("current_password", &common::random_secret()),
            ("new_password", &new_password),
        ]))
        .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert_eq!(wrong.error_code(), Some("invalid_current_password"));

    let changed = app
        .send(write("/account/password", &admin).form(&[
            ("current_password", &credentials.password),
            ("new_password", &new_password),
        ]))
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert!(changed.text.contains("1 other session was logged out"));
    assert!(
        !changed.text.contains(&new_password),
        "a password came back"
    );
    assert!(!changed.text.contains(&credentials.password));

    // This session survives, the other one does not.
    let account = page(&app, "/account", &admin).await;
    assert!(account.text.contains("Password changed"));
    assert!(account.text.contains(r#"href="/api/v1/export""#));
    let gone = app.send(TestRequest::get("/").cookie(&other.cookie)).await;
    assert_eq!(gone.status, StatusCode::SEE_OTHER);
}

/// The form and `POST /api/v1/auth/password` spend one per-session
/// bucket, counted before any Argon2 work.
#[tokio::test]
async fn the_form_and_the_api_share_the_password_change_budget() {
    let app = TestApp::with_vars(&[("DAYCOMPASS_RATE_LIMIT_PW_CHANGE", "2/900")]).await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let api = app
        .send(
            TestRequest::post("/api/v1/auth/password")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "current_password": common::random_secret(),
                    "new_password": common::random_secret(),
                })),
        )
        .await;
    assert_eq!(api.status, StatusCode::FORBIDDEN);

    let wrong = common::random_secret();
    let fields = [
        ("current_password", wrong.as_str()),
        ("new_password", wrong.as_str()),
    ];
    let form = app
        .send(write("/account/password", &admin).form(&fields))
        .await;
    assert_eq!(form.status, StatusCode::FORBIDDEN);

    let limited = app
        .send(write("/account/password", &admin).form(&fields))
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), Some("rate_limited"));
}

/// Every dashboard page renders for a signed-in account and carries no
/// inline script or style, which the CSP would refuse.
#[tokio::test]
async fn every_page_renders_without_inline_script_or_style() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    app.pair_device(&admin, "laptop", "linux").await;

    for path in ["/", "/devices", "/category-rules", "/account"] {
        let text = page(&app, path, &admin).await.text;
        assert!(!text.contains(" style="), "{path} has an inline style");
        assert!(!text.contains("<style"), "{path} has a <style>");
        let scripts: Vec<_> = text.match_indices("<script").collect();
        assert_eq!(scripts.len(), 1, "{path}: exactly the htmx script");
        assert!(text.contains(r#"<script src="/static/htmx-2.0.11.min.js" defer>"#));
        assert!(
            !text.contains(" onclick=") && !text.contains(" onload="),
            "{path}"
        );
    }
}
