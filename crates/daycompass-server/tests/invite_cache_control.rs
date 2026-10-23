//! `Cache-Control: no-store` on the two responses that carry an invite
//! token in the clear: creating a pending account and resetting one to
//! pending.
//!
//! The header is applied globally, in `middleware::apply`, to every
//! response regardless of route - so this is not exercising anything
//! route-specific in the production code. It pins the guarantee at the
//! two routes that actually matter, rather than relying on an
//! unrelated route's test (`tests/healthz.rs`) to stand in for it.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

#[tokio::test]
async fn creating_a_pending_account_carries_no_store() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let response = app
        .send(
            TestRequest::post("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({ "username": "bob", "role": "user" })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.body);
    assert_eq!(
        response
            .headers
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store"),
        "a response carrying an invite token must never be cached"
    );
}

#[tokio::test]
async fn resetting_an_account_carries_no_store() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, _bob_credentials) = app.create_account(&admin, "bob", "user").await;

    let response = app
        .send(
            TestRequest::post(&format!("/api/v1/users/{bob_id}/password-reset"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(
        response
            .headers
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store"),
        "a response carrying a fresh invite token must never be cached"
    );
}
