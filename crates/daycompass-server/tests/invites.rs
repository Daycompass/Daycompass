//! End-to-end tests for `POST /api/v1/invites/redeem`.
//!
//! The properties worth stating up front:
//!
//!   * redeeming activates a pending account and sets no cookie - the
//!     person logs in normally afterwards;
//!   * an unknown, an expired, an already-used and a malformed token
//!     are indistinguishable in the response;
//!   * the new password goes through the full policy, since it is a
//!     password being chosen.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

/// A token that is syntactically valid and was never issued.
///
/// Built from the OS CSPRNG through the real `Token` type rather than
/// written as a literal, so the test sources contain nothing
/// credential-shaped - the same reason `tests/pairing.rs` builds its
/// unissued pairing code instead of writing one out.
fn unissued_invite_token() -> String {
    use daycompass_server::auth::token::{Token, TokenKind};
    Token::generate(TokenKind::Invite)
        .expect("the OS CSPRNG must be available")
        .expose()
        .to_owned()
}

fn redeem_request(token: &str, new_password: &str) -> TestRequest {
    TestRequest::post("/api/v1/invites/redeem")
        .origin(GOOD_ORIGIN)
        .json(json!({
            "invite_token": token,
            "new_password": new_password,
        }))
}

#[tokio::test]
async fn redeeming_an_invite_activates_the_account_and_sets_no_cookie() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (id, token, _expires_at) = app.create_pending_account(&admin, "bob", "user").await;
    let new_password = common::random_secret();

    let response = app.send(redeem_request(&token, &new_password)).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        response.body
    );
    assert!(
        response.set_cookie().is_none(),
        "redeeming must set no session cookie"
    );

    let login = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({ "username": "bob", "password": new_password })),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    assert_eq!(login.body["user"]["id"], id);
}

/// An unknown, an expired, an already-used and a malformed token must
/// all answer identically - status, code, body and headers - so none
/// of them tells an unauthenticated caller which it was.
#[tokio::test]
async fn unknown_expired_used_and_malformed_tokens_are_indistinguishable() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let (_id, expired_token, _expires_at) =
        app.create_pending_account(&admin, "carol", "user").await;
    sqlx::query("UPDATE invite_tokens SET expires_at = 1")
        .execute(&app.pool)
        .await
        .expect("expiring the invite must succeed");

    let (_id, used_token, _expires_at) = app.create_pending_account(&admin, "dave", "user").await;
    let first = app
        .send(redeem_request(&used_token, &common::random_secret()))
        .await;
    assert_eq!(first.status, StatusCode::NO_CONTENT, "{:?}", first.body);

    let unknown = app
        .send(redeem_request(
            &unissued_invite_token(),
            &common::random_secret(),
        ))
        .await;
    let expired = app
        .send(redeem_request(&expired_token, &common::random_secret()))
        .await;
    let used = app
        .send(redeem_request(&used_token, &common::random_secret()))
        .await;
    let malformed = app
        .send(redeem_request(
            "not-a-token-at-all",
            &common::random_secret(),
        ))
        .await;

    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    for (label, other) in [
        ("expired", &expired),
        ("used", &used),
        ("malformed", &malformed),
    ] {
        assert_eq!(other.status, unknown.status, "{label}");
        assert_eq!(other.body, unknown.body, "{label}");
        assert_eq!(other.shape(), unknown.shape(), "{label}");
        // Not the full header map: `x-request-id` differs on every
        // request by design. What must agree is that none of them set
        // a cookie or a Retry-After, same as the one this is compared
        // against.
        assert_eq!(other.set_cookie(), unknown.set_cookie(), "{label}");
        assert_eq!(other.retry_after(), unknown.retry_after(), "{label}");
    }
    assert_eq!(unknown.error_code(), Some("invalid_invite_token"));
}

/// A new password is a password being *chosen*, so the full policy
/// applies - including the minimum length, which login deliberately
/// does not enforce.
#[tokio::test]
async fn the_password_policy_applies_at_redemption() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, token, _expires_at) = app.create_pending_account(&admin, "erin", "user").await;
    let generated = common::random_secret();

    for (new, code) in [
        (&generated[..11], "invalid_password"),
        ("   ", "invalid_password"),
    ] {
        let response = app.send(redeem_request(&token, new)).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{new:?}: {:?}",
            response.body
        );
        assert_eq!(response.error_code(), Some(code), "{new:?}");
    }

    // The invite must still be live: a rejected password must not
    // consume it.
    let response = app.send(redeem_request(&token, &generated)).await;
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        response.body
    );
}

/// An unknown field is refused rather than ignored, and nothing sent is
/// ever echoed back.
#[tokio::test]
async fn bad_input_is_the_uniform_error_and_never_echoed() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, token, _expires_at) = app.create_pending_account(&admin, "frank", "user").await;
    let marker = format!("marker-{}", common::random_secret());

    for body in [
        json!({
            "invite_token": token,
            "new_password": common::random_secret(),
            "username": marker,
        }),
        json!({ "invite_token": token }),
        json!({ "invite_token": 7, "new_password": 8 }),
        json!(marker),
    ] {
        let response = app
            .send(
                TestRequest::post("/api/v1/invites/redeem")
                    .origin(GOOD_ORIGIN)
                    .json(body),
            )
            .await;
        assert!(response.status.is_client_error(), "{:?}", response.body);
        assert_eq!(response.shape(), vec!["error.code", "error.message"]);
        let rendered = response.body.to_string();
        assert!(!rendered.contains(&marker), "the input was echoed back");
    }
}
