//! End-to-end tests for session handling, CSRF and the Origin check on
//! `GET /api/v1/auth/me` and `POST /api/v1/auth/logout`.

mod common;

use axum::http::StatusCode;
use common::{TestApp, TestRequest, BAD_ORIGIN, GOOD_ORIGIN};

#[tokio::test]
async fn me_reports_the_authenticated_account() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let response = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["user"]["username"], "alice");
    assert_eq!(response.body["user"]["role"], "admin");
}

/// The reason the CSRF token is derived rather than stored: a reload or
/// a second tab can recover it with a plain GET, and gets the same
/// value.
#[tokio::test]
async fn me_returns_the_same_csrf_token_across_reloads_and_tabs() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let first_tab = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    let after_reload = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    let second_tab = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;

    let from_login = session.csrf_token.as_str();
    for response in [&first_tab, &after_reload, &second_tab] {
        assert_eq!(
            response.body["csrf_token"].as_str(),
            Some(from_login),
            "every read must derive the identical token"
        );
    }

    // And it is usable: a state-changing request with it succeeds.
    let logout = app
        .send(
            TestRequest::post("/api/v1/auth/logout")
                .origin(GOOD_ORIGIN)
                .cookie(&session.cookie)
                .csrf(first_tab.body["csrf_token"].as_str().unwrap()),
        )
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
}

/// A different session must derive a different token, or one session's
/// CSRF token would work against another.
#[tokio::test]
async fn a_csrf_token_is_not_valid_for_another_session() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let first = app.log_in(&credentials).await;
    let second = app.log_in(&credentials).await;

    assert_ne!(first.csrf_token, second.csrf_token);

    let response = app
        .send(
            TestRequest::post("/api/v1/auth/logout")
                .origin(GOOD_ORIGIN)
                .cookie(&first.cookie)
                .csrf(&second.csrf_token),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error_code(), Some("csrf_token_invalid"));
}

#[tokio::test]
async fn a_state_changing_request_without_a_csrf_token_is_rejected() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let response = app
        .send(
            TestRequest::post("/api/v1/auth/logout")
                .origin(GOOD_ORIGIN)
                .cookie(&session.cookie),
        )
        .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.error_code(), Some("csrf_token_missing"));

    // And the session is untouched, so a forged request cannot be used
    // to log someone out.
    let still_live = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(still_live.status, StatusCode::OK);
}

#[tokio::test]
async fn a_wrong_csrf_token_is_rejected() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let mut tampered = session.csrf_token.clone();
    let replacement = if tampered.starts_with('A') { 'B' } else { 'A' };
    tampered.replace_range(0..1, &replacement.to_string());

    for candidate in [
        tampered.as_str(),
        "",
        "not-a-token",
        &session.csrf_token[..42],
    ] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/logout")
                    .origin(GOOD_ORIGIN)
                    .cookie(&session.cookie)
                    .csrf(candidate),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{candidate:?} must be rejected"
        );
    }
}

#[tokio::test]
async fn a_state_changing_request_from_a_wrong_origin_is_rejected() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    for origin in [BAD_ORIGIN, "null", "http://127.0.0.1:9999", ""] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/logout")
                    .origin(origin)
                    .authenticated(&session),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "origin {origin:?} must be rejected"
        );
        assert_eq!(response.error_code(), Some("origin_mismatch"));
    }

    // The session survived every one of them.
    let response = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

/// A GET changes nothing, so it is not subject to the Origin check.
#[tokio::test]
async fn a_get_is_allowed_from_any_origin_and_needs_no_csrf_token() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    for origin in [GOOD_ORIGIN, BAD_ORIGIN, "null"] {
        let response = app
            .send(
                TestRequest::get("/api/v1/auth/me")
                    .origin(origin)
                    .cookie(&session.cookie),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "origin {origin:?}");
    }
}

#[tokio::test]
async fn logout_ends_the_session_server_side_and_clears_the_cookie() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let logout = app
        .send(
            TestRequest::post("/api/v1/auth/logout")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    let cleared = logout.set_cookie().expect("the cookie must be cleared");
    assert!(cleared.starts_with("__Host-sws=;"));
    assert!(cleared.contains("Max-Age=0"));
    assert!(cleared.contains("Secure"));
    assert!(cleared.contains("HttpOnly"));

    // The row is gone, so the token is dead even if a client keeps it.
    let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        sessions, 0,
        "logout must delete the row, not just the cookie"
    );

    let replayed = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_expired_session_is_rejected_and_cleaned_up() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    // Past its absolute lifetime. The handler reads the real clock, so
    // the stored row is what moves.
    sqlx::query("UPDATE sessions SET expires_at = 1")
        .execute(&app.pool)
        .await
        .expect("ageing the session must succeed");

    let response = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0, "an expired session must be deleted when seen");
}

/// The idle timeout is independent of the absolute one: a session well
/// inside its lifetime still dies if it goes unused.
#[tokio::test]
async fn an_idle_session_is_rejected_even_before_its_absolute_expiry() {
    let app = TestApp::with_vars(&[
        ("SCREENWARD_SESSION_IDLE_SECS", "60"),
        ("SCREENWARD_SESSION_ABSOLUTE_SECS", "2592000"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    // Unused for longer than the idle window, while expires_at is still
    // thirty days away.
    sqlx::query("UPDATE sessions SET last_used_at = last_used_at - 600")
        .execute(&app.pool)
        .await
        .expect("ageing the session must succeed");

    let response = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_missing_malformed_or_unknown_cookie_is_unauthenticated() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let unknown = format!("__Host-sws=sws_{}", "A".repeat(43));
    let candidates = [
        None,
        Some("__Host-sws="),
        Some("__Host-sws=garbage"),
        Some(unknown.as_str()),
        Some("sws=whatever"),
        // Two copies leave no single right answer, so the request is
        // treated as unauthenticated rather than resolved by guessing.
        Some(&*format!("{}; {}", session.cookie, session.cookie)),
    ];

    for candidate in candidates {
        let mut request = TestRequest::get("/api/v1/auth/me");
        if let Some(cookie) = candidate {
            request = request.cookie(cookie);
        }
        let response = app.send(request).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "cookie {candidate:?} must not authenticate"
        );
        assert_eq!(response.error_code(), Some("unauthenticated"));
    }
}

/// A session token must not be usable where a setup token is expected,
/// nor the reverse. The prefix is part of what gets hashed.
#[tokio::test]
async fn a_session_token_is_not_accepted_as_a_setup_token() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let token = session
        .cookie
        .split_once('=')
        .map(|(_, value)| value.to_owned())
        .expect("the cookie must have a value");

    let response = app
        .send(TestRequest::post("/api/v1/setup").json(serde_json::json!({
            "setup_token": token,
            "username": "bob",
            "password": common::random_secret(),
        })))
        .await;
    // Setup is already complete here, so this is the 404 - and the
    // token never gets a chance to be mistaken for a setup token.
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}
