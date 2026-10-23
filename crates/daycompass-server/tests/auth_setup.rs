//! End-to-end tests for `POST /api/v1/setup`.

mod common;

use axum::http::StatusCode;
use common::{TestApp, TestRequest, BAD_ORIGIN, GOOD_ORIGIN};
use serde_json::json;

#[tokio::test]
async fn setup_creates_the_first_admin() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;
    let password = common::random_secret();

    let response = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "alice",
            "password": password,
        })))
        .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.body["user"]["username"], "alice");
    assert_eq!(response.body["user"]["role"], "admin");
    assert!(
        response.body["user"]["id"].is_string(),
        "the account id must be returned"
    );
    // No credential material comes back.
    assert!(response.body["user"]["password_hash"].is_null());
    assert!(response.set_cookie().is_none(), "setup does not log you in");
}

/// Once an admin exists the route must be indistinguishable from one
/// that was never there - same status and same body as an unknown path.
#[tokio::test]
async fn setup_is_a_plain_404_once_an_admin_exists() {
    let app = TestApp::new().await;
    app.provision_admin().await;

    let second = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": app.issue_setup_token_after_provisioning().await,
            "username": "bob",
            "password": common::random_secret(),
        })))
        .await;

    let unknown_route = app
        .send(TestRequest::post("/api/v1/does-not-exist").json(json!({})))
        .await;

    assert_eq!(second.status, StatusCode::NOT_FOUND);
    assert_eq!(
        second.status, unknown_route.status,
        "a provisioned instance must look like a missing route"
    );
    assert_eq!(
        second.body, unknown_route.body,
        "and must answer with the identical body"
    );
    assert_ne!(
        second.status,
        StatusCode::FORBIDDEN,
        "403 would confirm that setup had been completed"
    );
}

#[tokio::test]
async fn an_expired_setup_token_is_rejected() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;

    // Move the stored expiry into the past; the handler reads the real
    // clock, so the row is what has to change.
    sqlx::query("UPDATE setup_tokens SET expires_at = 1")
        .execute(&app.pool)
        .await
        .expect("ageing the token must succeed");

    let response = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "alice",
            "password": common::random_secret(),
        })))
        .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), Some("invalid_setup_token"));
    assert_no_users(&app).await;
}

#[tokio::test]
async fn a_reused_setup_token_is_rejected() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;
    let body = json!({
        "setup_token": token,
        "username": "alice",
        "password": common::random_secret(),
    });

    let first = app
        .send(TestRequest::post("/api/v1/setup").json(body.clone()))
        .await;
    assert_eq!(first.status, StatusCode::CREATED);

    // The same token again. The admin check fires first, so this is the
    // 404 - which is also what hides that the token was ever valid.
    let second = app
        .send(TestRequest::post("/api/v1/setup").json(body))
        .await;
    assert_eq!(second.status, StatusCode::NOT_FOUND);

    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

/// An unknown token, a wrong-kind token and junk must all look the same.
#[tokio::test]
async fn every_bad_token_gives_the_same_answer() {
    let app = TestApp::new().await;
    app.issue_setup_token().await;

    // Both of these are assembled at runtime rather than written out.
    // A token-shaped literal in the source would be a finding for the
    // gitleaks rule in .gitleaks.toml - correctly, which is how this
    // was caught in the first place.
    let unknown = format!("dcb_{}", "A".repeat(43));
    let wrong_kind = format!("dcs_{}", "A".repeat(43));
    let candidates = [
        unknown.as_str(),
        wrong_kind.as_str(),
        "dcb_",
        "",
        "not-a-token",
    ];

    let mut seen = Vec::new();
    for candidate in candidates {
        let response = app
            .send(TestRequest::post("/api/v1/setup").json(json!({
                "setup_token": candidate,
                "username": "alice",
                "password": common::random_secret(),
            })))
            .await;
        seen.push((response.status, response.body.clone()));
    }

    let first = &seen[0];
    for (status, body) in &seen {
        assert_eq!(status, &first.0, "every bad token must share a status");
        assert_eq!(body, &first.1, "and an identical body");
    }
    assert_eq!(first.0, StatusCode::UNAUTHORIZED);
    assert_no_users(&app).await;
}

#[tokio::test]
async fn the_policies_are_reported_without_echoing_the_input() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;

    let bad_username = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "a",
            "password": common::random_secret(),
        })))
        .await;
    assert_eq!(bad_username.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_username.error_code(), Some("invalid_username"));
    assert!(
        !bad_username.body.to_string().contains("\"a\""),
        "the message must not echo the input"
    );

    let bad_password = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "alice",
            "password": "short",
        })))
        .await;
    assert_eq!(bad_password.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_password.error_code(), Some("invalid_password"));
    assert!(
        !bad_password.body.to_string().contains("short"),
        "the message must not echo the password"
    );

    assert_no_users(&app).await;
}

/// Setup is exempt from the Origin check: it carries no cookie, so there
/// is no ambient credential for a hostile page to ride on, and a sync
/// client has no origin to send.
#[tokio::test]
async fn setup_is_exempt_from_the_origin_check() {
    for origin in [None, Some(GOOD_ORIGIN), Some(BAD_ORIGIN)] {
        let app = TestApp::new().await;
        let token = app.issue_setup_token().await;

        let mut request = TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "alice",
            "password": common::random_secret(),
        }));
        if let Some(origin) = origin {
            request = request.origin(origin);
        }

        let response = app.send(request).await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "setup must work with origin {origin:?}"
        );
    }
}

#[tokio::test]
async fn a_malformed_body_is_rejected_without_quoting_it() {
    let app = TestApp::new().await;
    app.issue_setup_token().await;

    // A password of the wrong JSON type. serde's own message would
    // quote the offending value; the error middleware must replace the
    // whole body.
    let response = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": "dcb_x",
            "username": "alice",
            "password": 1234567890123_i64,
        })))
        .await;

    assert!(response.status.is_client_error());
    assert!(
        !response.body.to_string().contains("1234567890123"),
        "the response must not quote the request body: {:?}",
        response.body
    );
    assert!(
        response.error_code().is_some(),
        "it must still be the uniform error shape"
    );
}

/// Whatever is sent, a provisioned instance must look exactly like a
/// route that was never there - otherwise the 404 above is only skin
/// deep.
#[tokio::test]
async fn a_provisioned_instance_answers_404_even_for_malformed_input() {
    let app = TestApp::new().await;
    app.provision_admin().await;

    let unknown_route = app
        .send(TestRequest::post("/api/v1/does-not-exist").json(json!({})))
        .await;

    let bodies = [
        json!({ "setup_token": "not-a-token", "username": "a", "password": "short" }),
        json!({ "setup_token": "", "username": "", "password": "" }),
        json!({
            "setup_token": app.issue_setup_token_after_provisioning().await,
            "username": "not a username!",
            "password": common::random_secret(),
        }),
    ];

    for body in bodies {
        let response = app
            .send(TestRequest::post("/api/v1/setup").json(body.clone()))
            .await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "input {body} must give a plain 404"
        );
        assert_eq!(response.body, unknown_route.body);
    }
}

async fn assert_no_users(app: &TestApp) {
    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(users, 0, "no account may have been created");
}
