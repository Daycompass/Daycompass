//! End-to-end tests for rate limiting and proxy handling.

mod common;

use axum::http::StatusCode;
use common::{TestApp, TestRequest, GOOD_ORIGIN};
use serde_json::json;

/// Limits low enough to reach quickly, and generous Argon2 settings are
/// irrelevant here because every attempt fails before a session exists.
async fn app_with_limits(login_ip: &str, login_username: &str) -> TestApp {
    TestApp::with_vars(&[
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_IP", login_ip),
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_USERNAME", login_username),
        ("DAYCOMPASS_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await
}

fn login(username: &str) -> TestRequest {
    TestRequest::post("/api/v1/auth/login")
        .origin(GOOD_ORIGIN)
        .json(json!({ "username": username, "password": common::random_secret() }))
}

#[tokio::test]
async fn the_per_address_limit_triggers_with_a_retry_after() {
    let app = app_with_limits("3/300", "1000/300").await;
    app.provision_admin().await;

    for attempt in 1..=3 {
        let response = app.send(login("alice")).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} must still be processed"
        );
    }

    let limited = app.send(login("alice")).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), Some("rate_limited"));
    let retry_after = limited.retry_after().expect("a 429 must carry Retry-After");
    assert!(
        retry_after > 0 && retry_after <= 300,
        "Retry-After must be within the window, got {retry_after}"
    );
}

/// The per-username bucket is what protects one account from a guessing
/// attack spread across addresses.
#[tokio::test]
async fn the_per_username_limit_follows_the_account_across_addresses() {
    let app = app_with_limits("1000/300", "3/300").await;
    app.provision_admin().await;

    for attempt in 1..=3 {
        let response = app
            .send(login("alice").peer(&format!("192.0.2.{attempt}:1111")))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    // A fourth address, same account: still refused.
    let limited = app.send(login("alice").peer("192.0.2.200:1111")).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    // A different account from the same new address is unaffected.
    let other = app.send(login("bob").peer("192.0.2.200:1111")).await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
}

/// Case and whitespace must not open a second budget for one account.
#[tokio::test]
async fn username_spellings_share_one_bucket() {
    let app = app_with_limits("1000/300", "2/300").await;
    app.provision_admin().await;

    assert_eq!(
        app.send(login("alice")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.send(login("ALICE")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.send(login("  Alice  ")).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a different spelling must not get a fresh budget"
    );
}

/// Both buckets must give the same answer, or the response becomes an
/// oracle for which one refused - and so for whether the account exists.
#[tokio::test]
async fn both_buckets_produce_an_identical_response() {
    let by_address = {
        let app = app_with_limits("1/300", "1000/300").await;
        app.provision_admin().await;
        app.send(login("alice")).await;
        app.send(login("alice")).await
    };
    let by_username = {
        let app = app_with_limits("1000/300", "1/300").await;
        app.provision_admin().await;
        app.send(login("alice")).await;
        app.send(login("alice")).await
    };

    assert_eq!(by_address.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(by_username.status, by_address.status);
    assert_eq!(by_username.body, by_address.body);
    assert!(
        !by_username.body.to_string().contains("alice"),
        "the message must not name the account"
    );
}

#[tokio::test]
async fn different_addresses_have_separate_budgets() {
    let app = app_with_limits("2/300", "1000/300").await;
    app.provision_admin().await;

    for _ in 0..2 {
        app.send(login("alice").peer("192.0.2.1:1111")).await;
    }
    assert_eq!(
        app.send(login("alice").peer("192.0.2.1:1111")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.send(login("alice").peer("192.0.2.2:1111")).await.status,
        StatusCode::UNAUTHORIZED,
        "another address must have its own budget"
    );
}

/// With no trusted proxy configured the header must be ignored, or any
/// client could hand itself a fresh budget per request.
#[tokio::test]
async fn x_forwarded_for_is_ignored_from_an_untrusted_peer() {
    let app = app_with_limits("2/300", "1000/300").await;
    app.provision_admin().await;

    for _ in 0..2 {
        app.send(
            login("alice")
                .peer("192.0.2.1:1111")
                .forwarded_for(&common::random_secret()),
        )
        .await;
    }

    // A different claimed address each time must not help.
    let limited = app
        .send(
            login("alice")
                .peer("192.0.2.1:1111")
                .forwarded_for("198.51.100.77"),
        )
        .await;
    assert_eq!(
        limited.status,
        StatusCode::TOO_MANY_REQUESTS,
        "an untrusted peer must not be able to rewrite its own address"
    );
}

#[tokio::test]
async fn x_forwarded_for_is_honored_from_a_trusted_peer() {
    let app = TestApp::with_vars(&[
        ("DAYCOMPASS_TRUSTED_PROXIES", "192.0.2.1/32"),
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_IP", "2/300"),
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("DAYCOMPASS_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await;
    app.provision_admin().await;

    // Two attempts attributed to one client behind the proxy.
    for _ in 0..2 {
        let response = app
            .send(
                login("alice")
                    .peer("192.0.2.1:1111")
                    .forwarded_for("198.51.100.5"),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    // That client is now limited.
    let limited = app
        .send(
            login("alice")
                .peer("192.0.2.1:1111")
                .forwarded_for("198.51.100.5"),
        )
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    // A different client behind the same proxy still has its budget,
    // which is the whole point of honoring the header.
    let other = app
        .send(
            login("alice")
                .peer("192.0.2.1:1111")
                .forwarded_for("198.51.100.6"),
        )
        .await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
}

/// The spoofing case: a client behind a trusted proxy prepends entries
/// of its own. Only the right-most untrusted entry counts, so this must
/// change nothing.
#[tokio::test]
async fn a_spoofed_left_most_entry_does_not_grant_a_fresh_budget() {
    let app = TestApp::with_vars(&[
        ("DAYCOMPASS_TRUSTED_PROXIES", "192.0.2.1/32"),
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_IP", "2/300"),
        ("DAYCOMPASS_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("DAYCOMPASS_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await;
    app.provision_admin().await;

    for _ in 0..2 {
        app.send(
            login("alice")
                .peer("192.0.2.1:1111")
                .forwarded_for("198.51.100.5"),
        )
        .await;
    }

    // Each of these prepends a different address the client made up.
    // The real entry, appended by our proxy, is still right-most.
    for spoof in ["203.0.113.1", "10.0.0.1", "198.51.100.99"] {
        let response = app
            .send(
                login("alice")
                    .peer("192.0.2.1:1111")
                    .forwarded_for(&format!("{spoof}, 198.51.100.5")),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::TOO_MANY_REQUESTS,
            "prepending {spoof} must not reset the budget"
        );
    }
}

#[tokio::test]
async fn the_setup_endpoint_is_rate_limited_per_address() {
    let app = TestApp::with_vars(&[("DAYCOMPASS_RATE_LIMIT_SETUP_IP", "2/3600")]).await;
    let token = app.issue_setup_token().await;

    let attempt = || {
        TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": "dcb_wrong",
            "username": "alice",
            "password": common::random_secret(),
        }))
    };

    for _ in 0..2 {
        let response = app.send(attempt()).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    let limited = app.send(attempt()).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.retry_after().is_some());

    // The real token is refused too while the window holds: the limit
    // is on the address, not on the attempt's outcome.
    let with_real_token = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": token,
            "username": "alice",
            "password": common::random_secret(),
        })))
        .await;
    assert_eq!(with_real_token.status, StatusCode::TOO_MANY_REQUESTS);
}

/// Reaching a limit must never be permanent: there is no state here
/// that an administrator has to clear, so nobody can lock out an
/// account for good.
#[tokio::test]
async fn a_rate_limited_account_can_still_log_in_from_elsewhere() {
    let app = app_with_limits("1/300", "1000/300").await;
    let credentials = app.provision_admin().await;

    // Burn the budget for one address.
    app.send(login(&credentials.username).peer("192.0.2.1:1111"))
        .await;
    assert_eq!(
        app.send(login(&credentials.username).peer("192.0.2.1:1111"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );

    // The account itself is not locked: the correct password still
    // works from an address with budget left.
    let response = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .peer("192.0.2.9:1111")
                .json(json!({
                    "username": credentials.username,
                    "password": credentials.password,
                })),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "an address limit must not lock the account"
    );
}

/// A token that is syntactically valid and was never issued, for
/// exercising a failed redemption without consuming a real invite.
fn unissued_invite_token() -> String {
    use daycompass_server::auth::token::{Token, TokenKind};
    Token::generate(TokenKind::Invite)
        .expect("the OS CSPRNG must be available")
        .expose()
        .to_owned()
}

/// The default `InviteIp` budget must absorb a classroom-scale burst
/// of *successful* redemptions from one shared address (a school's
/// NAT, say) without being exhausted by them, while still refusing
/// bad tokens from that same address on their own terms rather than
/// with a 429. Exercises the real default from `Config`, not an
/// override, since the default itself is what is under test.
#[tokio::test]
async fn invite_redemption_absorbs_a_classroom_burst_from_one_address() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let peer = "192.0.2.50:1111";

    for i in 0..25 {
        let (_id, token, _expires_at) = app
            .create_pending_account(&admin, &format!("student{i}"), "user")
            .await;
        let response = app
            .send(
                TestRequest::post("/api/v1/invites/redeem")
                    .origin(GOOD_ORIGIN)
                    .peer(peer)
                    .json(json!({
                        "invite_token": token,
                        "new_password": common::random_secret(),
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::NO_CONTENT,
            "successful redemption {i} from a shared address must not be rate limited: {:?}",
            response.body
        );
    }

    for i in 0..5 {
        let response = app
            .send(
                TestRequest::post("/api/v1/invites/redeem")
                    .origin(GOOD_ORIGIN)
                    .peer(peer)
                    .json(json!({
                        "invite_token": unissued_invite_token(),
                        "new_password": common::random_secret(),
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "failed attempt {i} must be refused on its own terms, not by the rate limiter"
        );
    }
}

/// The Origin check runs before the rate limiter, so a cross-origin
/// attempt cannot be used to burn someone else's budget.
#[tokio::test]
async fn a_rejected_origin_does_not_consume_the_budget() {
    let app = app_with_limits("2/300", "1000/300").await;
    let credentials = app.provision_admin().await;

    for _ in 0..5 {
        let response = app
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(common::BAD_ORIGIN)
                    .json(json!({ "username": "alice", "password": common::random_secret() })),
            )
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    let response = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "username": credentials.username,
                    "password": credentials.password,
                })),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "cross-origin noise must not spend a real client's budget"
    );
}
