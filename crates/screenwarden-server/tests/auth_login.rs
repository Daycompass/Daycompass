//! End-to-end tests for `POST /api/v1/auth/login`.

mod common;

use std::time::Instant;

use axum::http::StatusCode;
use common::{TestApp, TestRequest, GOOD_ORIGIN};
use serde_json::json;

fn login_body(username: &str, password: &str) -> serde_json::Value {
    json!({ "username": username, "password": password })
}

#[tokio::test]
async fn a_correct_password_logs_in() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let response = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body(&credentials.username, &credentials.password)),
        )
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["user"]["username"], "alice");
    assert_eq!(response.body["user"]["role"], "admin");
    let csrf = response.body["csrf_token"]
        .as_str()
        .expect("a CSRF token must be returned");
    assert_eq!(csrf.len(), 43);

    // The session token itself must not be in the body: it belongs in
    // the cookie, where page scripts cannot read it.
    let body = response.body.to_string();
    assert!(
        !body.contains("sws_"),
        "the session token must not be in the body"
    );
    assert!(!body.contains(&credentials.password));
}

/// The cookie attributes are specified exactly, so they are asserted
/// exactly.
#[tokio::test]
async fn the_session_cookie_has_exactly_the_specified_attributes() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let response = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body(&credentials.username, &credentials.password)),
        )
        .await;

    let cookie = response.set_cookie().expect("a Set-Cookie header");
    let (pair, attributes) = cookie.split_once("; ").expect("attributes must follow");

    assert!(
        pair.starts_with("__Host-sws=sws_"),
        "unexpected cookie name or token prefix: {pair}"
    );
    assert_eq!(
        attributes, "Path=/; HttpOnly; Secure; SameSite=Strict",
        "the attribute string must match the specification exactly"
    );
    // Spelled out so a failure names the missing attribute.
    assert!(cookie.contains("; HttpOnly"), "HttpOnly is required");
    assert!(cookie.contains("; Secure"), "Secure is required");
    assert!(
        cookie.contains("; SameSite=Strict"),
        "SameSite=Strict is required"
    );
    assert!(cookie.contains("; Path=/"), "Path=/ is required");
    assert!(
        !cookie.to_ascii_lowercase().contains("domain"),
        "a Domain attribute would break the __Host- prefix"
    );
    assert!(
        !cookie.to_ascii_lowercase().contains("max-age"),
        "the server decides the lifetime, not the client"
    );
    assert!(!cookie.to_ascii_lowercase().contains("expires"));
}

/// The central no-enumeration property, checked at the HTTP boundary:
/// status, headers and body shape must be identical.
#[tokio::test]
async fn wrong_password_and_unknown_account_are_indistinguishable() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let wrong_password = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body(&credentials.username, &common::random_secret())),
        )
        .await;

    let unknown_account = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body("bob", &common::random_secret())),
        )
        .await;

    let malformed_username = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body("x", &common::random_secret())),
        )
        .await;

    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    for other in [&unknown_account, &malformed_username] {
        assert_eq!(other.status, wrong_password.status, "the status must match");
        assert_eq!(other.body, wrong_password.body, "the body must match");
        assert_eq!(
            other.shape(),
            wrong_password.shape(),
            "the shape must match"
        );
        assert!(
            other.set_cookie().is_none(),
            "a failed login must set no cookie"
        );
    }
    assert_eq!(wrong_password.error_code(), Some("invalid_credentials"));
}

/// A pending account - created but its invite not yet redeemed - has
/// to fail exactly the way an unknown account does: the same status,
/// the same body, the same shape. Anything else would let a login
/// attempt tell a caller "this username exists but is pending", which
/// is exactly the enumeration this endpoint exists to prevent.
#[tokio::test]
async fn a_pending_account_fails_like_an_unknown_one() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (_id, _token, _expires_at) = app.create_pending_account(&admin, "bob", "user").await;

    let pending = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body("bob", &common::random_secret())),
        )
        .await;
    let unknown_account = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body("carol", &common::random_secret())),
        )
        .await;

    assert_eq!(pending.status, StatusCode::UNAUTHORIZED);
    assert_eq!(pending.status, unknown_account.status);
    assert_eq!(pending.body, unknown_account.body);
    assert_eq!(pending.shape(), unknown_account.shape());
    assert!(pending.set_cookie().is_none());
    assert_eq!(pending.error_code(), Some("invalid_credentials"));
}

#[tokio::test]
async fn the_username_is_matched_case_insensitively() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    for spelling in ["alice", "ALICE", "Alice", "  alice  "] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(GOOD_ORIGIN)
                    .json(login_body(spelling, &credentials.password)),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{spelling:?} must work");
    }
}

#[tokio::test]
async fn every_login_issues_a_fresh_session() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let first = app.log_in(&credentials).await;
    let second = app.log_in(&credentials).await;

    assert_ne!(first.cookie, second.cookie, "a new token every time");
    assert_ne!(first.csrf_token, second.csrf_token);

    // The earlier session still works: logging in elsewhere must not
    // log you out here.
    for session in [&first, &second] {
        let response = app
            .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
            .await;
        assert_eq!(response.status, StatusCode::OK);
    }

    let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 2);
}

/// Login is not exempt from the Origin check, even though it has no
/// cookie yet.
#[tokio::test]
async fn login_rejects_a_mismatched_origin_but_allows_an_absent_one() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    let mismatched = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(common::BAD_ORIGIN)
                .json(login_body(&credentials.username, &credentials.password)),
        )
        .await;
    assert_eq!(mismatched.status, StatusCode::FORBIDDEN);
    assert_eq!(mismatched.error_code(), Some("origin_mismatch"));
    assert!(mismatched.set_cookie().is_none());

    // No Origin at all: allowed, because a sync client or a script
    // sends none and refusing would make the API browser-only.
    let absent = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .json(login_body(&credentials.username, &credentials.password)),
        )
        .await;
    assert_eq!(absent.status, StatusCode::OK);
}

/// A smoke check, not a proof.
///
/// It exists to catch the obvious regression - someone skipping the
/// decoy hash so an unknown account answers an order of magnitude
/// faster - and nothing finer. Timing on a shared CI runner is noisy, so
/// the tolerance is deliberately enormous: a real leak here would be a
/// factor of ten or more, while this only fails past a factor of four.
/// It is NOT evidence that the endpoint is free of timing side channels.
#[tokio::test]
async fn unknown_accounts_and_wrong_passwords_take_comparable_time() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    async fn median_millis(app: &TestApp, username: &str) -> u128 {
        let mut samples = Vec::new();
        for _ in 0..5 {
            let password = common::random_secret();
            let started = Instant::now();
            let response = app
                .send(
                    TestRequest::post("/api/v1/auth/login")
                        .origin(GOOD_ORIGIN)
                        .json(login_body(username, &password)),
                )
                .await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
            samples.push(started.elapsed().as_millis());
        }
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    let known = median_millis(&app, &credentials.username).await;
    let unknown = median_millis(&app, "bob").await;

    // Both must actually have done the hashing work. Argon2 at the
    // configured cost cannot finish in under a millisecond.
    assert!(
        known > 0 && unknown > 0,
        "neither path may short-circuit (known {known}ms, unknown {unknown}ms)"
    );

    let (smaller, larger) = if known <= unknown {
        (known, unknown)
    } else {
        (unknown, known)
    };
    let ratio = larger as f64 / smaller.max(1) as f64;
    assert!(
        ratio < 4.0,
        "the two paths differ by {ratio:.1}x (known {known}ms, unknown {unknown}ms); \
         a large gap suggests the unknown-account path skips the decoy hash"
    );
}

#[tokio::test]
async fn a_blank_or_over_long_password_fails_like_any_other_wrong_one() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let baseline = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(login_body(&credentials.username, &common::random_secret())),
        )
        .await;

    let over_long: String = std::iter::repeat_n('x', 129).collect();
    for password in ["", "    ", over_long.as_str()] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(GOOD_ORIGIN)
                    .json(login_body(&credentials.username, password)),
            )
            .await;
        assert_eq!(response.status, baseline.status);
        assert_eq!(response.body, baseline.body);
    }
}

/// Deleting the account must immediately invalidate its sessions.
#[tokio::test]
async fn a_session_dies_with_its_account() {
    let app = TestApp::new().await;
    let admin = app.provision_admin().await;
    let session = app.log_in(&admin).await;

    sqlx::query("DELETE FROM users")
        .execute(&app.pool)
        .await
        .expect("deleting the account must succeed");

    let response = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}
