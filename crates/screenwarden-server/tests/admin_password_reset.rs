//! End-to-end tests for `POST /api/v1/users/{id}/password-reset`.
//!
//! The properties worth stating up front:
//!
//!   * a reset ends every session and revokes every device the account
//!     had, in the same transaction as the reset itself;
//!   * every earlier invite for the account stops working, and the
//!     fresh one redeems;
//!   * the reset is visible afterwards in the account's own log, with
//!     the acting admin's id;
//!   * the last-admin protection only ever looks at **active** admins,
//!     so a pending admin never blocks anything.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

fn reset_request(user_id: &str) -> TestRequest {
    TestRequest::post(&format!("/api/v1/users/{user_id}/password-reset")).origin(GOOD_ORIGIN)
}

#[tokio::test]
async fn a_reset_ends_sessions_and_revokes_devices_and_issues_a_working_invite() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let device = app.pair_device(&bob, "laptop", "linux").await;

    // The session and the device both work before the reset.
    let before = app
        .send(TestRequest::get("/api/v1/auth/me").authenticated(&bob))
        .await;
    assert_eq!(before.status, StatusCode::OK);
    let device_before = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(device_before.status, StatusCode::OK);

    let response = app.send(reset_request(&bob_id).authenticated(&admin)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(response.body["sessions_ended"], 1);
    assert_eq!(response.body["devices_revoked"], 1);
    let token = response.body["invite"]["token"]
        .as_str()
        .expect("an invite token")
        .to_owned();
    assert!(token.starts_with("swi_"));

    // The session and the device both stop working immediately.
    let after_session = app
        .send(TestRequest::get("/api/v1/auth/me").authenticated(&bob))
        .await;
    assert_eq!(after_session.status, StatusCode::UNAUTHORIZED);
    let after_device = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(after_device.status, StatusCode::UNAUTHORIZED);

    // The account can no longer log in with its old password...
    let old_login = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "username": "bob",
                    "password": bob_credentials.password,
                })),
        )
        .await;
    assert_eq!(old_login.status, StatusCode::UNAUTHORIZED);

    // ...but the fresh invite redeems and lets it back in.
    let new_password = common::random_secret();
    let redeemed = app
        .send(
            TestRequest::post("/api/v1/invites/redeem")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "invite_token": token,
                    "new_password": new_password,
                })),
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        redeemed.body
    );

    let new_session = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({ "username": "bob", "password": new_password })),
        )
        .await;
    assert_eq!(new_session.status, StatusCode::OK, "{:?}", new_session.body);
}

#[tokio::test]
async fn earlier_invites_stop_working_after_a_reset() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (id, first_token, _expires_at) = app.create_pending_account(&admin, "carol", "user").await;

    let response = app.send(reset_request(&id).authenticated(&admin)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);

    let stale = app
        .send(
            TestRequest::post("/api/v1/invites/redeem")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "invite_token": first_token,
                    "new_password": common::random_secret(),
                })),
        )
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stale.error_code(), Some("invalid_invite_token"));
}

/// An outstanding, unredeemed pairing code is as much a way back into
/// the account as a session or a device token - it can mint a brand
/// new device, independent of either. `docs/design-decisions.md`
/// states there is no window after a reset other than the invite just
/// issued; an unspent code left alive would be exactly such a window.
#[tokio::test]
async fn an_outstanding_pairing_code_does_not_survive_a_reset() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let code = app.issue_pairing_code(&bob).await;

    let response = app.send(reset_request(&bob_id).authenticated(&admin)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);

    let pair = app
        .send(TestRequest::post("/api/v1/pair").json(json!({
            "pairing_code": code,
            "device_name": "laptop",
            "platform": "linux",
        })))
        .await;
    assert_eq!(pair.status, StatusCode::UNAUTHORIZED, "{:?}", pair.body);
    assert_eq!(pair.error_code(), Some("invalid_pairing_code"));
    assert_eq!(
        app.count_devices().await,
        0,
        "the reset account must not have gained a device"
    );
}

/// The reset is visible to the account itself afterwards, naming the
/// acting admin and the kind - that visibility is the whole reason a
/// reset is a different thing from the admin silently knowing the
/// account's password.
#[tokio::test]
async fn the_account_sees_the_reset_in_its_own_log() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let admin_id = app
        .send(TestRequest::get("/api/v1/auth/me").authenticated(&admin))
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (bob_id, _bob_credentials) = app.create_account(&admin, "bob", "user").await;

    let reset = app.send(reset_request(&bob_id).authenticated(&admin)).await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    let token = reset.body["invite"]["token"].as_str().unwrap().to_owned();

    let new_password = common::random_secret();
    app.send(
        TestRequest::post("/api/v1/invites/redeem")
            .origin(GOOD_ORIGIN)
            .json(json!({
                "invite_token": token,
                "new_password": new_password,
            })),
    )
    .await;

    let session = app
        .log_in(&common::Credentials {
            username: "bob".to_owned(),
            password: new_password,
        })
        .await;

    let log = app
        .send(
            TestRequest::get("/api/v1/account/log")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(log.status, StatusCode::OK, "{:?}", log.body);
    let entries = log.body["entries"].as_array().expect("a list");
    // Newest first: the redemption, then the reset.
    assert_eq!(entries[0]["kind"], "invite_redeemed");
    assert_eq!(entries[0]["actor_id"], serde_json::Value::Null);
    assert_eq!(entries[1]["kind"], "password_reset_by_admin");
    assert_eq!(entries[1]["actor_id"], admin_id);
}

/// A reset is refused on the last *active* admin, exactly like a
/// demotion or a deletion.
#[tokio::test]
async fn resetting_the_last_active_admin_is_refused() {
    let app = TestApp::new().await;
    let (admin_credentials, admin) = app.provisioned_admin().await;
    let own_id = app
        .send(TestRequest::get("/api/v1/auth/me").authenticated(&admin))
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let response = app.send(reset_request(&own_id).authenticated(&admin)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{:?}", response.body);
    assert_eq!(response.error_code(), Some("last_admin_protected"));

    // Still able to log in with the original password.
    app.log_in(&admin_credentials).await;
}

/// The last-admin guard only ever counts **active** admins: a pending
/// admin may be demoted or deleted freely even while it is the only
/// other admin on the instance, and resetting it is unaffected by the
/// active admin's own protection.
#[tokio::test]
async fn a_pending_admin_never_blocks_the_last_admin_guard() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (pending_id, _token, _expires_at) = app
        .create_pending_account(&admin, "pending-admin", "admin")
        .await;

    // Resetting the pending admin succeeds: the last-admin guard
    // protects the last *active* admin, and this account was never
    // one.
    let reset = app
        .send(reset_request(&pending_id).authenticated(&admin))
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);

    // Demoting the pending admin to a user also succeeds, even though
    // it was (nominally) the instance's second admin.
    let demote = app
        .send(
            TestRequest::patch(&format!("/api/v1/users/{pending_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({ "role": "user" })),
        )
        .await;
    assert_eq!(demote.status, StatusCode::OK, "{:?}", demote.body);
}
