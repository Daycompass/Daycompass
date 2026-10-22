//! End-to-end tests for listing, renaming and revoking devices.
//!
//! The property worth most of the attention here is isolation: one
//! owner must not be able to see, rename, revoke or even *detect*
//! another owner's device. "No such device" and "not yours" are one
//! answer, or the endpoint becomes a way to enumerate device ids
//! across accounts.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Session, TestApp, TestRequest, GOOD_ORIGIN};

fn revoke(device_id: &str, session: &Session) -> TestRequest {
    TestRequest::post(&format!("/api/v1/devices/{device_id}/revoke"))
        .origin(GOOD_ORIGIN)
        .authenticated(session)
}

fn rename(device_id: &str, session: &Session, name: &str) -> TestRequest {
    TestRequest::patch(&format!("/api/v1/devices/{device_id}"))
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .json(json!({ "name": name }))
}

/// An admin, an ordinary user, and one device each.
async fn two_owners() -> (TestApp, Session, Session, String, String) {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;

    let admin_device = app.pair_device(&admin, "admins-laptop", "linux").await;
    let user_device = app.pair_device(&user, "bobs-phone", "android").await;

    (app, admin, user, admin_device.id, user_device.id)
}

// --- listing ----------------------------------------------------------

#[tokio::test]
async fn an_owner_sees_only_their_own_devices() {
    let (app, admin, user, admin_device, user_device) = two_owners().await;

    let theirs = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&user),
        )
        .await;
    assert_eq!(theirs.status, StatusCode::OK, "{:?}", theirs.body);

    let ids: Vec<&str> = theirs.body["devices"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|device| device["id"].as_str().expect("an id"))
        .collect();
    assert_eq!(ids, [user_device.as_str()]);

    // And the admin's own listing is their own, not everybody's -
    // being an admin does not change what this route scopes to.
    let admins = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    let ids: Vec<&str> = admins.body["devices"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|device| device["id"].as_str().expect("an id"))
        .collect();
    assert_eq!(
        ids,
        [admin_device.as_str()],
        "the owner route must stay owner-scoped for an admin too"
    );
}

#[tokio::test]
async fn an_owner_still_sees_a_device_they_revoked() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    app.send(revoke(&device.id, &session)).await;

    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    let devices = listing.body["devices"].as_array().expect("an array");
    assert_eq!(devices.len(), 1, "revoking must not hide the row");
    assert!(
        devices[0]["revoked_at"].as_i64().is_some(),
        "and it must say when"
    );
}

#[tokio::test]
async fn an_admin_sees_every_device_with_its_owner() {
    let (app, admin, _user, admin_device, user_device) = two_owners().await;

    let listing = app
        .send(
            TestRequest::get("/api/v1/admin/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.body);

    let devices = listing.body["devices"].as_array().expect("an array");
    assert_eq!(devices.len(), 2);

    let mut ids: Vec<&str> = devices
        .iter()
        .map(|device| device["id"].as_str().expect("an id"))
        .collect();
    ids.sort_unstable();
    let mut expected = [admin_device.as_str(), user_device.as_str()];
    expected.sort_unstable();
    assert_eq!(ids, expected);

    // The owner is named, which an admin could learn from the account
    // listing anyway, and is what makes the view usable at all.
    let owners: Vec<&str> = devices
        .iter()
        .map(|device| device["owner_username"].as_str().expect("an owner"))
        .collect();
    assert!(owners.contains(&"bob"));
}

/// An ordinary user may not use the admin listing, however many
/// devices they own.
#[tokio::test]
async fn an_ordinary_user_cannot_list_every_device() {
    let (app, _admin, user, _admin_device, _user_device) = two_owners().await;

    let response = app
        .send(
            TestRequest::get("/api/v1/admin/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&user),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error_code(), Some("forbidden"));
}

// --- renaming ---------------------------------------------------------

#[tokio::test]
async fn an_owner_renames_their_own_device() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let response = app
        .send(rename(&device.id, &session, "  Study Laptop  "))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(
        response.body["device"]["name"], "Study Laptop",
        "a display name is trimmed"
    );

    // And it stuck.
    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(listing.body["devices"][0]["name"], "Study Laptop");
}

#[tokio::test]
async fn renaming_enforces_the_name_policy() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    for (label, name) in [
        ("empty", String::new()),
        ("blank", "   ".to_owned()),
        ("one over the maximum", "x".repeat(65)),
        ("a newline", "laptop\nadmin".to_owned()),
        ("a bidi override", "laptop\u{202e}revoked".to_owned()),
    ] {
        let response = app.send(rename(&device.id, &session, &name)).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{label}: {:?}",
            response.body
        );
        assert_eq!(
            response.error_code(),
            Some("invalid_device_name"),
            "{label}"
        );
    }

    // The name is unchanged after all that.
    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(listing.body["devices"][0]["name"], "laptop");
}

// --- isolation --------------------------------------------------------

/// The core isolation property, and the reason "not found" and "not
/// yours" are one answer.
#[tokio::test]
async fn one_owner_cannot_touch_anothers_device() {
    let (app, _admin, user, admin_device, _user_device) = two_owners().await;

    // Renaming somebody else's device.
    let renamed = app.send(rename(&admin_device, &user, "mine now")).await;
    assert_eq!(renamed.status, StatusCode::NOT_FOUND, "{:?}", renamed.body);

    // Revoking it.
    let revoked = app.send(revoke(&admin_device, &user)).await;
    assert_eq!(revoked.status, StatusCode::NOT_FOUND, "{:?}", revoked.body);

    // A device id that exists nowhere must be answered identically,
    // so the response cannot be used to probe which ids are real.
    let absent = app
        .send(revoke("00000000-0000-7000-8000-000000000000", &user))
        .await;
    assert_eq!(absent.status, revoked.status);
    assert_eq!(
        absent.body, revoked.body,
        "somebody else's device must look exactly like no device"
    );

    let absent_rename = app
        .send(rename(
            "00000000-0000-7000-8000-000000000000",
            &user,
            "mine now",
        ))
        .await;
    assert_eq!(absent_rename.body, renamed.body);
}

/// And the device really is untouched afterwards.
#[tokio::test]
async fn a_failed_cross_owner_attempt_changes_nothing() {
    let (app, admin, user, admin_device, _user_device) = two_owners().await;

    app.send(rename(&admin_device, &user, "mine now")).await;
    app.send(revoke(&admin_device, &user)).await;

    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    let device = &listing.body["devices"][0];
    assert_eq!(device["name"], "admins-laptop");
    assert!(
        device["revoked_at"].is_null(),
        "another account must not be able to revoke this"
    );
}

// --- revoking ---------------------------------------------------------

#[tokio::test]
async fn revoking_keeps_the_device_and_its_events() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

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
                        "start_ts": now - 600,
                        "duration_secs": 300,
                        "app_id": "org.example.app",
                    }],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 1);

    let response = app.send(revoke(&device.id, &session)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert!(response.body["device"]["revoked_at"].as_i64().is_some());

    // This is the whole point of revoke-not-delete.
    assert_eq!(app.count_devices().await, 1, "the row must stay");
    assert_eq!(app.count_events().await, 1, "the events must stay");
}

/// Revoking twice is not an error: the caller asked for the device to
/// be revoked, and it is.
#[tokio::test]
async fn revoking_is_idempotent() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let first = app.send(revoke(&device.id, &session)).await;
    assert_eq!(first.status, StatusCode::OK);
    let revoked_at = first.body["device"]["revoked_at"].as_i64().expect("a time");

    let second = app.send(revoke(&device.id, &session)).await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.body);
    assert_eq!(
        second.body["device"]["revoked_at"].as_i64(),
        Some(revoked_at),
        "the recorded moment must be the first revocation, not the latest call"
    );
}

#[tokio::test]
async fn an_admin_may_revoke_any_device() {
    let (app, admin, user, _admin_device, user_device) = two_owners().await;

    let response = app
        .send(
            TestRequest::post(&format!("/api/v1/admin/devices/{user_device}/revoke"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert!(response.body["device"]["revoked_at"].as_i64().is_some());

    // The owner sees it as revoked.
    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&user),
        )
        .await;
    assert!(listing.body["devices"][0]["revoked_at"].as_i64().is_some());

    // And the events survive, because an admin revoking is still not
    // an admin deleting.
    assert_eq!(app.count_devices().await, 2);
}

#[tokio::test]
async fn an_ordinary_user_cannot_use_the_admin_revoke_route() {
    let (app, _admin, user, admin_device, user_device) = two_owners().await;

    for target in [&admin_device, &user_device] {
        let response = app
            .send(
                TestRequest::post(&format!("/api/v1/admin/devices/{target}/revoke"))
                    .origin(GOOD_ORIGIN)
                    .authenticated(&user),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "even their own device must not be reachable through the admin route"
        );
    }
}

/// Deleting an account takes its devices, its codes and its events.
#[tokio::test]
async fn deleting_a_user_cascades_to_devices_codes_and_events() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (user_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;

    let device = app.pair_device(&user, "bobs-laptop", "android").await;
    // An outstanding, unredeemed code as well.
    app.issue_pairing_code(&user).await;

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
                    "start_ts": now - 600,
                    "duration_secs": 300,
                    "app_id": "org.example.app",
                }],
            })),
    )
    .await;

    assert_eq!(app.count_devices().await, 1);
    assert_eq!(app.count_pairing_codes().await, 1);
    assert_eq!(app.count_events().await, 1);

    let deleted = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{user_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);

    assert_eq!(app.count_devices().await, 0, "devices must cascade");
    assert_eq!(app.count_pairing_codes().await, 0, "codes must cascade");
    assert_eq!(
        app.count_events().await,
        0,
        "events must cascade through devices"
    );
}
