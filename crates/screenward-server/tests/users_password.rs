//! End-to-end tests for `POST /api/v1/auth/password`.
//!
//! The endpoint takes no account parameter at all, so there is nothing
//! to aim at somebody else: it can only ever change the caller's own
//! password. What is tested here is what that costs and what it
//! revokes.
//!
//! Every password is generated at runtime.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Credentials, Session, TestApp, TestRequest, GOOD_ORIGIN};

/// A change request for `session`, with the given passwords.
fn change(session: &Session, current: &str, new: &str) -> TestRequest {
    TestRequest::post("/api/v1/auth/password")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .json(json!({
            "current_password": current,
            "new_password": new,
        }))
}

#[tokio::test]
async fn a_change_keeps_this_session_and_ends_every_other_one() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;

    // Three sessions, as three browsers would be.
    let current = app.log_in(&credentials).await;
    let other = app.log_in(&credentials).await;
    let third = app.log_in(&credentials).await;
    let new_password = common::random_secret();

    let response = app
        .send(change(&current, &credentials.password, &new_password))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(response.body["other_sessions_ended"], 2);
    assert!(!response.body.to_string().contains(&new_password));

    // The session that made the change still works...
    let still = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&current),
        )
        .await;
    assert_eq!(still.status, StatusCode::OK, "{:?}", still.body);

    // ...and the others do not, on their very next request.
    for dead in [&other, &third] {
        let response = app
            .send(
                TestRequest::get("/api/v1/auth/me")
                    .origin(GOOD_ORIGIN)
                    .authenticated(dead),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{:?}",
            response.body
        );
        assert_eq!(response.error_code(), Some("unauthenticated"));
    }

    // The new password works and the old one does not.
    let renewed = Credentials {
        username: credentials.username.clone(),
        password: new_password,
    };
    app.log_in(&renewed).await;

    let old = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "username": credentials.username,
                    "password": credentials.password,
                })),
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    assert_eq!(old.error_code(), Some("invalid_credentials"));
}

/// An ordinary account can change its own password; nothing about this
/// endpoint needs an admin.
#[tokio::test]
async fn an_ordinary_account_can_change_its_own_password() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let new_password = common::random_secret();

    let response = app
        .send(change(&bob, &bob_credentials.password, &new_password))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(response.body["other_sessions_ended"], 0);

    app.log_in(&Credentials {
        username: bob_credentials.username,
        password: new_password,
    })
    .await;
}

#[tokio::test]
async fn a_wrong_current_password_changes_nothing() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let current = app.log_in(&credentials).await;
    let other = app.log_in(&credentials).await;

    let response = app
        .send(change(
            &current,
            &common::random_secret(),
            &common::random_secret(),
        ))
        .await;

    // 403, not 401: the session is perfectly valid, so a client must not
    // conclude it has been logged out.
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        response.body
    );
    assert_eq!(response.error_code(), Some("invalid_current_password"));

    // No session was ended, and the old password still works.
    let untouched = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&other),
        )
        .await;
    assert_eq!(untouched.status, StatusCode::OK);
    app.log_in(&credentials).await;
}

/// A new password is a password being *chosen*, so the full policy
/// applies to it - including the minimum length, which login
/// deliberately does not enforce.
#[tokio::test]
async fn a_new_password_below_the_policy_is_refused() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;
    let generated = common::random_secret();

    for (new, code) in [
        (&generated[..11], "invalid_password"),
        ("   ", "invalid_password"),
    ] {
        let response = app.send(change(&session, &credentials.password, new)).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{new:?}: {:?}",
            response.body
        );
        assert_eq!(response.error_code(), Some(code), "{new:?}");
        assert_eq!(response.shape(), vec!["error.code", "error.message"]);
    }

    // The old password is still the one that works.
    app.log_in(&credentials).await;
}

/// Two parallel changes, over a file-backed database so they really
/// overlap. The final write is conditional on the stored hash still
/// being the one that was verified, so exactly one may be applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_parallel_changes_cannot_both_succeed() {
    let app = TestApp::with_file_db().await;
    let credentials = app.provision_admin().await;
    let first = app.log_in(&credentials).await;
    let second = app.log_in(&credentials).await;
    let left_password = common::random_secret();
    let right_password = common::random_secret();

    let (left, right) = tokio::join!(
        app.send(change(&first, &credentials.password, &left_password)),
        app.send(change(&second, &credentials.password, &right_password))
    );

    let statuses = [left.status, right.status];
    let applied = statuses
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    assert_eq!(
        applied, 1,
        "exactly one change may be applied, saw {statuses:?}"
    );

    // The loser is told either that its view was stale or that the
    // current password it verified against is no longer current.
    // Which one depends on whether the winner committed before or
    // after the loser's verification; both are refusals.
    let loser = if left.status == StatusCode::OK {
        right
    } else {
        left
    };
    assert!(
        matches!(
            loser.error_code(),
            Some("password_change_conflict") | Some("invalid_current_password")
        ),
        "the loser must be refused, got {:?}",
        loser.body
    );

    // Exactly one of the two new passwords is in effect - not both,
    // which is what a non-conditional write would have produced.
    let mut working = 0;
    for password in [&left_password, &right_password] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(GOOD_ORIGIN)
                    .json(json!({
                        "username": credentials.username,
                        "password": password,
                    })),
            )
            .await;
        if response.status == StatusCode::OK {
            working += 1;
        }
    }
    assert_eq!(working, 1, "exactly one new password may be in effect");
}

/// The per-account limit counts every attempt, not only the ones that
/// fail: a flood of *correct* changes is just as expensive in Argon2
/// work as a flood of wrong ones.
#[tokio::test]
async fn the_per_account_limit_counts_successful_changes_too() {
    let app = TestApp::with_vars(&[
        ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_SETUP_IP", "1000/3600"),
        ("SCREENWARD_RATE_LIMIT_PASSWORD_USER", "2/900"),
    ])
    .await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;

    let second = common::random_secret();
    let third = common::random_secret();
    let fourth = common::random_secret();

    let first = app
        .send(change(&session, &credentials.password, &second))
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);

    let again = app.send(change(&session, &second, &third)).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);

    let limited = app.send(change(&session, &third, &fourth)).await;
    assert_eq!(
        limited.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        limited.body
    );
    assert_eq!(limited.error_code(), Some("rate_limited"));
    assert!(limited.retry_after().is_some_and(|after| after >= 1));

    // The refused attempt really did not happen.
    app.log_in(&Credentials {
        username: credentials.username,
        password: third,
    })
    .await;
}

/// The limit is per account, so one account hitting it does not refuse
/// another's change.
#[tokio::test]
async fn the_limit_is_per_account() {
    let app = TestApp::with_vars(&[
        ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_SETUP_IP", "1000/3600"),
        ("SCREENWARD_RATE_LIMIT_PASSWORD_USER", "1/900"),
    ])
    .await;
    let (admin_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    let spent = app
        .send(change(
            &admin,
            &admin_credentials.password,
            &common::random_secret(),
        ))
        .await;
    assert_eq!(spent.status, StatusCode::OK, "{:?}", spent.body);

    let refused = app
        .send(change(
            &admin,
            &common::random_secret(),
            &common::random_secret(),
        ))
        .await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);

    // Same address, different account: unaffected.
    let other = app
        .send(change(
            &bob,
            &bob_credentials.password,
            &common::random_secret(),
        ))
        .await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.body);
}

#[tokio::test]
async fn bad_input_is_the_uniform_error_and_never_echoed() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    let session = app.log_in(&credentials).await;
    let marker = format!("marker-{}", common::random_secret());

    for body in [
        // An unknown field, which must be refused rather than ignored.
        json!({
            "current_password": credentials.password,
            "new_password": common::random_secret(),
            "user_id": marker,
        }),
        // A missing field, a wrong type, and a body that is not an
        // object at all.
        json!({ "current_password": credentials.password }),
        json!({ "current_password": 7, "new_password": 8 }),
        json!(marker),
    ] {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/password")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&session)
                    .json(body),
            )
            .await;
        assert!(response.status.is_client_error(), "{:?}", response.body);
        assert_eq!(response.shape(), vec!["error.code", "error.message"]);
        let rendered = response.body.to_string();
        assert!(!rendered.contains(&marker), "the input was echoed back");
        assert!(!rendered.contains(&credentials.password));
    }

    // Nothing above changed the password.
    app.log_in(&credentials).await;
}
