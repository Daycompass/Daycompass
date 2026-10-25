//! The M5 dashboard's onboarding and admin pages, over HTTP: first-start
//! setup, invite redemption, account management and the instance-wide
//! device list.
//!
//! Route protections are walked by `tests/route_inventory.rs`; that an
//! admin page shows no event data is swept by `tests/no_event_reads.rs`.
//! This file checks the flows themselves and that they agree with the
//! JSON routes they share their functions with.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Credentials, Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

fn write(path: &str, session: &Session) -> TestRequest {
    TestRequest::post(path)
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .htmx()
}

/// The text of the first `<span class="dc-code">` - a pairing or invite
/// code shown once.
fn shown_code(response: &TestResponse) -> String {
    let marker = r#"<span class="dc-code">"#;
    let start = response.text.find(marker).expect("a code") + marker.len();
    let end = start + response.text[start..].find('<').unwrap();
    response.text[start..end].trim().to_owned()
}

#[tokio::test]
async fn setup_from_the_page_creates_the_first_admin_and_then_disappears() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;

    let page = app.send(TestRequest::get("/setup")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text.contains(r#"action="/setup""#));

    let credentials = Credentials::generate("alice");
    let created = app
        .send(TestRequest::post("/setup").origin(GOOD_ORIGIN).form(&[
            ("setup_token", &token),
            ("username", &credentials.username),
            ("password", &credentials.password),
        ]))
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.text);
    assert_eq!(created.location(), Some("/login"));
    assert!(created.set_cookie().is_none(), "setup mints no session");
    app.log_in(&credentials).await;

    // Indistinguishable from a route that never existed, on both
    // methods and both surfaces.
    let gone = app.send(TestRequest::get("/setup")).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    let again = app
        .send(TestRequest::post("/setup").origin(GOOD_ORIGIN).form(&[
            ("setup_token", &token),
            ("username", "mallory"),
            ("password", &common::random_secret()),
        ]))
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.error_code(), Some("not_found"));
}

#[tokio::test]
async fn a_wrong_setup_token_is_the_apis_refusal() {
    let app = TestApp::new().await;
    app.issue_setup_token().await;

    let response = app
        .send(TestRequest::post("/setup").origin(GOOD_ORIGIN).form(&[
            ("setup_token", "not-the-token"),
            ("username", "alice"),
            ("password", &common::random_secret()),
        ]))
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), Some("invalid_setup_token"));
    assert_eq!(
        app.send(TestRequest::get("/setup")).await.status,
        StatusCode::OK
    );
}

/// The whole onboarding loop through the dashboard alone: an admin
/// invites, the new account holder redeems the code and logs in.
#[tokio::test]
async fn an_invite_from_the_admin_page_activates_an_account() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let created = app
        .send(write("/admin/users", &admin).form(&[("username", "bob"), ("role", "user")]))
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert!(created.text.contains("Invite for bob"));
    assert!(created.text.contains("invite not redeemed yet"));
    let code = shown_code(&created);

    // Shown once: the list rendered afterwards does not carry it.
    let later = app
        .send(TestRequest::get("/admin/users").cookie(&admin.cookie))
        .await;
    assert!(!later.text.contains(&code));

    let password = common::random_secret();
    let redeemed = app
        .send(
            TestRequest::post("/invite")
                .origin(GOOD_ORIGIN)
                .form(&[("invite_token", &code), ("new_password", &password)]),
        )
        .await;
    assert_eq!(redeemed.status, StatusCode::SEE_OTHER, "{}", redeemed.text);
    assert_eq!(redeemed.location(), Some("/login"));

    app.log_in(&Credentials {
        username: "bob".to_owned(),
        password,
    })
    .await;

    // Spent.
    let twice = app
        .send(TestRequest::post("/invite").origin(GOOD_ORIGIN).form(&[
            ("invite_token", &code),
            ("new_password", &common::random_secret()),
        ]))
        .await;
    assert_eq!(twice.status, StatusCode::UNAUTHORIZED);
    assert_eq!(twice.error_code(), Some("invalid_invite_token"));
}

#[tokio::test]
async fn an_ordinary_account_is_refused_every_admin_page() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    for path in ["/admin/users", "/admin/devices"] {
        let response = app.send(TestRequest::get(path).cookie(&bob.cookie)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response.error_code(), Some("forbidden"), "{path}");
    }
    let create = app
        .send(write("/admin/users", &bob).form(&[("username", "eve"), ("role", "admin")]))
        .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN);

    // And an ordinary account is never shown the admin links.
    let overview = app.send(TestRequest::get("/").cookie(&bob.cookie)).await;
    assert!(!overview.text.contains("/admin/"));
    let own = app.send(TestRequest::get("/").cookie(&admin.cookie)).await;
    assert!(own.text.contains(r#"href="/admin/users""#));
}

#[tokio::test]
async fn the_last_admin_cannot_be_demoted_from_the_page() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let me = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    let own_id = me.body["user"]["id"].as_str().unwrap().to_owned();

    let response = app
        .send(write(&format!("/admin/users/{own_id}/role"), &admin).form(&[("role", "user")]))
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.error_code(), Some("last_admin_protected"));

    // The own row offers no delete or reset at all.
    let page = app
        .send(TestRequest::get("/admin/users").cookie(&admin.cookie))
        .await;
    assert!(!page.text.contains(&format!("/admin/users/{own_id}/delete")));
    assert!(!page
        .text
        .contains(&format!("/admin/users/{own_id}/password-reset")));
}

/// A reset from the page is the API's reset: every session ended, every
/// device revoked, a fresh invite, and the entry in the account's own
/// log.
#[tokio::test]
async fn a_reset_from_the_page_does_what_the_api_reset_does() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let device = app.pair_device(&bob, "phone", "android").await;

    let response = app
        .send(write(
            &format!("/admin/users/{bob_id}/password-reset"),
            &admin,
        ))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(response
        .text
        .contains("1 session(s) ended, 1 device(s) revoked"));
    let code = shown_code(&response);

    let dead = app.send(TestRequest::get("/").cookie(&bob.cookie)).await;
    assert_eq!(dead.status, StatusCode::SEE_OTHER);
    let revoked = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);

    let password = common::random_secret();
    app.send(
        TestRequest::post("/invite")
            .origin(GOOD_ORIGIN)
            .form(&[("invite_token", &code), ("new_password", &password)]),
    )
    .await;
    let back = app
        .log_in(&Credentials {
            username: "bob".to_owned(),
            password,
        })
        .await;
    let account = app
        .send(TestRequest::get("/account").cookie(&back.cookie))
        .await;
    assert!(account.text.contains("Password reset by an admin"));
}

#[tokio::test]
async fn deleting_from_the_page_removes_the_account() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, _bob) = app.create_account(&admin, "bob", "user").await;

    let response = app
        .send(write(&format!("/admin/users/{bob_id}/delete"), &admin))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.text.contains(">bob<") && !response.text.contains("bob "));

    let listed = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(listed.body["users"].as_array().unwrap().len(), 1);
}

/// The admin device page names devices and owners - and nothing a
/// device reported.
#[tokio::test]
async fn the_admin_device_page_is_metadata_only_and_can_revoke() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let device = app.pair_device(&bob, "bob-phone", "android").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    app.send(
        TestRequest::post("/api/v1/events")
            .authenticated_as_device(&device)
            .json(json!({
                "events": [{
                    "event_id": "0123456789abcdef0123456789abcdef",
                    "start_ts": now - 900,
                    "duration_secs": 600,
                    "app_id": "org.example.secretgame",
                    "label": "A Very Private Thing",
                    "domain": "private.example",
                }],
            })),
    )
    .await;

    let page = app
        .send(TestRequest::get("/admin/devices").cookie(&admin.cookie))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text.contains("bob-phone") && page.text.contains("bob"));
    for needle in [
        "org.example.secretgame",
        "A Very Private Thing",
        "private.example",
    ] {
        assert!(
            !page.text.contains(needle),
            "event data on the admin page: {needle}"
        );
    }

    let revoked = app
        .send(write(
            &format!("/admin/devices/{}/revoke", device.id),
            &admin,
        ))
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert!(revoked.text.contains("Revoked"));
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}
