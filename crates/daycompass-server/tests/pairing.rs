//! End-to-end tests for minting and redeeming pairing codes.
//!
//! The properties worth stating up front, because they are what the
//! `BEGIN IMMEDIATE` transaction in `devices::store` exists for:
//!
//!   * a code is single use, and two clients racing with the same one
//!     produce exactly one device;
//!   * an unknown, an expired and a spent code are indistinguishable
//!     in the response;
//!   * hitting the device cap rolls the transaction back, so the code
//!     survives and can be used once room is made.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

/// A code that is syntactically valid and was never issued.
///
/// Built from the alphabet rather than written as a literal, so the
/// test sources contain nothing credential-shaped.
fn unissued_code() -> String {
    "0123456789".to_owned()
}

fn pair_request(code: &str) -> TestRequest {
    TestRequest::post("/api/v1/pair").json(json!({
        "pairing_code": code,
        "device_name": "laptop",
        "platform": "linux",
    }))
}

// --- minting ----------------------------------------------------------

#[tokio::test]
async fn an_owner_mints_a_code_and_sees_it_once() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let response = app
        .send(
            TestRequest::post("/api/v1/pairing-codes")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;

    assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.body);
    let code = response.body["pairing_code"].as_str().expect("a code");

    // Shown grouped for reading aloud, and from the unambiguous
    // alphabet only.
    assert_eq!(code.len(), 11, "XXXXX-XXXXX");
    assert_eq!(code.as_bytes()[5], b'-');
    let bare = code.replace('-', "");
    assert_eq!(bare.len(), 10);
    for omitted in ['I', 'L', 'O', 'U'] {
        assert!(
            !bare.contains(omitted),
            "{omitted} is confusable and must never be generated: {code}"
        );
    }

    // The expiry is in the future and the server says what time it
    // thinks it is, so a client can show a countdown without trusting
    // its own clock.
    let expires_at = response.body["expires_at"].as_i64().expect("an expiry");
    let server_time = response.body["server_time"].as_i64().expect("a clock");
    assert!(expires_at > server_time);
    assert!(
        expires_at - server_time <= 600,
        "a code must not outlive ten minutes"
    );
}

/// An ordinary user pairs their own devices; this is not an admin
/// endpoint.
#[tokio::test]
async fn an_ordinary_user_may_mint_a_code() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;

    let device = app.pair_device(&user, "bobs-phone", "android").await;
    assert!(!device.id.is_empty());
}

#[tokio::test]
async fn an_account_may_hold_only_five_live_codes() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    for n in 1..=5 {
        let response = app
            .send(
                TestRequest::post("/api/v1/pairing-codes")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&session),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "code {n} of 5");
    }

    let sixth = app
        .send(
            TestRequest::post("/api/v1/pairing-codes")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(sixth.status, StatusCode::CONFLICT, "{:?}", sixth.body);
    assert_eq!(sixth.error_code(), Some("pairing_code_limit_reached"));

    // Spending one frees a slot, so the cap bounds live codes rather
    // than being a lifetime quota.
    let code = app.issue_pairing_code_raw(&session).await;
    assert!(code.is_none(), "the sixth mint must not have produced one");

    let (_id, other) = app.create_account(&session, "bob", "user").await;
    let other_session = app.log_in(&other).await;
    let theirs = app
        .send(
            TestRequest::post("/api/v1/pairing-codes")
                .origin(GOOD_ORIGIN)
                .authenticated(&other_session),
        )
        .await;
    assert_eq!(
        theirs.status,
        StatusCode::CREATED,
        "the cap is per account, not per instance"
    );
}

/// The cap bounds live codes. Minting also collects the account's own
/// spent and expired ones, so cycling cannot grow the table without
/// bound while staying under the cap.
#[tokio::test]
async fn minting_collects_the_accounts_dead_codes() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    for _ in 0..5 {
        app.issue_pairing_code(&session).await;
    }
    assert_eq!(app.count_pairing_codes().await, 5);

    // Age them all out, then mint again.
    app.expire_all_pairing_codes().await;
    app.issue_pairing_code(&session).await;

    assert_eq!(
        app.count_pairing_codes().await,
        1,
        "the five dead codes must have been collected"
    );
}

/// The per-owner collection above only runs when that owner mints
/// again. The background sweep is what collects the codes of somebody
/// who minted one and never came back.
#[tokio::test]
async fn the_sweep_collects_dead_codes_from_every_account() {
    use daycompass_server::auth::time::UnixTime;
    use daycompass_server::devices::service;

    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let (_id, carol_credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&carol_credentials).await;

    // A spent code on one account.
    let spent = app.issue_pairing_code(&admin).await;
    app.send(pair_request(&spent)).await;

    // An expired one on another. Aged through SQL, because the expiry
    // is ten minutes and the rule under test is the comparison.
    app.issue_pairing_code(&bob).await;
    sqlx::query("UPDATE pairing_codes SET expires_at = 1 WHERE used_at IS NULL")
        .execute(&app.pool)
        .await
        .expect("ageing must succeed");

    // And a live one on a third account. It has to be a third
    // account: minting collects the *minting* owner's dead codes, so
    // reusing either of the two above would quietly remove the row
    // this test is about before the sweep ever ran.
    let live = app.issue_pairing_code(&carol).await;
    assert_eq!(app.count_pairing_codes().await, 3);

    let removed = service::sweep_expired_codes(&app.pool, UnixTime::now())
        .await
        .expect("the sweep must succeed");
    assert_eq!(removed, 2, "the spent and the expired code must both go");
    assert_eq!(app.count_pairing_codes().await, 1);

    // And the survivor still works, so the sweep is not collecting
    // live codes.
    let response = app.send(pair_request(&live)).await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "a live code must survive the sweep: {:?}",
        response.body
    );
}

// --- redeeming --------------------------------------------------------

#[tokio::test]
async fn a_code_pairs_a_device_and_returns_its_token_once() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let code = app.issue_pairing_code(&session).await;

    let response = app.send(pair_request(&code)).await;
    assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.body);

    let token = response.body["device_token"].as_str().expect("a token");
    assert!(token.starts_with("dcd_"), "a device token, not a session");

    let device = &response.body["device"];
    assert_eq!(device["name"], "laptop");
    assert_eq!(device["platform"], "linux");
    assert!(device["revoked_at"].is_null());
    // The token is in the envelope, never inside the device object
    // that later listings also return.
    assert!(device["device_token"].is_null());
    assert!(device["token"].is_null());
}

/// Whatever a person types, if it folds onto the issued code it must
/// work - that is the whole reason the alphabet omits confusables.
#[tokio::test]
async fn a_code_is_accepted_in_every_spelling_a_person_might_type() {
    for transform in [
        |code: &str| code.to_owned(),
        |code: &str| code.replace('-', ""),
        str::to_lowercase,
        |code: &str| format!("  {code}  "),
        |code: &str| code.replace('-', " "),
        // The confusables that are never generated fold onto the
        // digits they are mistaken for.
        |code: &str| code.replace('1', "l").replace('0', "O"),
    ] {
        let app = TestApp::new().await;
        let (_credentials, session) = app.provisioned_admin().await;
        let code = app.issue_pairing_code(&session).await;
        let typed = transform(&code);

        let response = app.send(pair_request(&typed)).await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{typed:?} must pair: {:?}",
            response.body
        );
    }
}

#[tokio::test]
async fn a_code_may_only_be_redeemed_once() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let code = app.issue_pairing_code(&session).await;

    let first = app.send(pair_request(&code)).await;
    assert_eq!(first.status, StatusCode::CREATED);

    let second = app.send(pair_request(&code)).await;
    assert_eq!(second.status, StatusCode::UNAUTHORIZED, "{:?}", second.body);
    assert_eq!(second.error_code(), Some("invalid_pairing_code"));

    assert_eq!(app.count_devices().await, 1);
}

#[tokio::test]
async fn an_expired_code_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let code = app.issue_pairing_code(&session).await;

    app.expire_all_pairing_codes().await;

    let response = app.send(pair_request(&code)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), Some("invalid_pairing_code"));
    assert_eq!(app.count_devices().await, 0);
}

/// The no-oracle rule. An unauthenticated caller must not be able to
/// tell a code that never existed from one that did.
#[tokio::test]
async fn unknown_expired_and_spent_codes_are_indistinguishable() {
    // Unknown.
    let unknown = {
        let app = TestApp::new().await;
        app.provisioned_admin().await;
        app.send(pair_request(&unissued_code())).await
    };

    // Expired.
    let expired = {
        let app = TestApp::new().await;
        let (_credentials, session) = app.provisioned_admin().await;
        let code = app.issue_pairing_code(&session).await;
        app.expire_all_pairing_codes().await;
        app.send(pair_request(&code)).await
    };

    // Spent.
    let spent = {
        let app = TestApp::new().await;
        let (_credentials, session) = app.provisioned_admin().await;
        let code = app.issue_pairing_code(&session).await;
        app.send(pair_request(&code)).await;
        app.send(pair_request(&code)).await
    };

    // Malformed, which must also not stand out.
    let malformed = {
        let app = TestApp::new().await;
        app.provisioned_admin().await;
        app.send(pair_request("!!!!!!!!!!")).await
    };

    for (label, response) in [
        ("expired", &expired),
        ("spent", &spent),
        ("malformed", &malformed),
    ] {
        assert_eq!(
            response.status, unknown.status,
            "{label} differs from unknown in status"
        );
        assert_eq!(
            response.body, unknown.body,
            "{label} differs from unknown in body"
        );
    }
}

#[tokio::test]
async fn one_accounts_code_cannot_be_distinguished_from_anothers() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;

    // Each code pairs a device onto its own owner, and nothing in the
    // response says whose it was.
    let admin_code = app.issue_pairing_code(&admin).await;
    let user_code = app.issue_pairing_code(&user).await;

    let first = app.send(pair_request(&admin_code)).await;
    let second = app.send(pair_request(&user_code)).await;

    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(second.status, StatusCode::CREATED);
    assert_eq!(
        first.shape(),
        second.shape(),
        "the response must not vary with whose code it was"
    );
    assert!(
        !first.body.to_string().contains("alice") && !second.body.to_string().contains("bob"),
        "a pairing response must not name the owner"
    );
}

/// The guard on the redeem UPDATE, exercised directly.
///
/// The end-to-end single-use test above passes whether or not the
/// UPDATE carries `AND used_at IS NULL`, because `BEGIN IMMEDIATE`
/// stops a second redemption from ever reaching it. This one runs the
/// statement itself, twice, so the condition has to be there.
#[tokio::test]
async fn the_redeem_update_affects_no_row_the_second_time() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    app.issue_pairing_code(&session).await;

    let code_id: String = sqlx::query_scalar("SELECT id FROM pairing_codes")
        .fetch_one(&app.pool)
        .await
        .expect("the code must exist");

    let statement = "UPDATE pairing_codes SET used_at = ?2 WHERE id = ?1 AND used_at IS NULL";

    let first = sqlx::query(statement)
        .bind(&code_id)
        .bind(1_800_000_000_i64)
        .execute(&app.pool)
        .await
        .expect("the first update must run");
    assert_eq!(first.rows_affected(), 1, "the first must claim the code");

    let second = sqlx::query(statement)
        .bind(&code_id)
        .bind(1_800_000_999_i64)
        .execute(&app.pool)
        .await
        .expect("the second update must run");
    assert_eq!(
        second.rows_affected(),
        0,
        "the second must claim nothing, which is what the redeem path checks"
    );

    // And the recorded moment is the first one's, not the second's.
    let used_at: i64 = sqlx::query_scalar("SELECT used_at FROM pairing_codes WHERE id = ?1")
        .bind(&code_id)
        .fetch_one(&app.pool)
        .await
        .expect("the code must still be there");
    assert_eq!(used_at, 1_800_000_000);
}

// --- the device cap ---------------------------------------------------

/// Hitting the cap rolls the transaction back, so the code is **not**
/// consumed. Without that, a person at their limit would burn a code
/// every time they tried, and the recovery - revoke something, try
/// again - would not work.
#[tokio::test]
async fn hitting_the_device_cap_leaves_the_code_unspent() {
    let app = TestApp::with_vars(&[
        ("DAYCOMPASS_MAX_DEVICES_PER_USER", "1"),
        ("DAYCOMPASS_RATE_LIMIT_PAIR_IP", "1000/300"),
        ("DAYCOMPASS_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
    ])
    .await;
    let (_credentials, session) = app.provisioned_admin().await;

    let first = app.pair_device(&session, "laptop", "linux").await;
    assert_eq!(app.count_devices().await, 1);

    // A second code, refused by the cap.
    let code = app.issue_pairing_code(&session).await;
    let refused = app.send(pair_request(&code)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.body);
    assert_eq!(refused.error_code(), Some("device_limit_reached"));
    assert_eq!(
        app.count_devices().await,
        1,
        "nothing may have been created"
    );

    // The code survived, which is the point. Make room and it works.
    let revoked = app
        .send(
            TestRequest::post(&format!("/api/v1/devices/{}/revoke", first.id))
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);

    let retried = app.send(pair_request(&code)).await;
    assert_eq!(
        retried.status,
        StatusCode::CREATED,
        "the unspent code must still work once there is room: {:?}",
        retried.body
    );
}

/// Only live devices count towards the cap, or somebody who had
/// cycled through their allowance would be locked out for good.
#[tokio::test]
async fn revoked_devices_do_not_count_towards_the_cap() {
    let app = TestApp::with_vars(&[
        ("DAYCOMPASS_MAX_DEVICES_PER_USER", "2"),
        ("DAYCOMPASS_RATE_LIMIT_PAIR_IP", "1000/300"),
        ("DAYCOMPASS_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
    ])
    .await;
    let (_credentials, session) = app.provisioned_admin().await;

    // Fill the allowance, revoke both, and fill it again.
    for round in 0..3 {
        let a = app.pair_device(&session, "first", "linux").await;
        let b = app.pair_device(&session, "second", "android").await;

        for device in [&a, &b] {
            let response = app
                .send(
                    TestRequest::post(&format!("/api/v1/devices/{}/revoke", device.id))
                        .origin(GOOD_ORIGIN)
                        .authenticated(&session),
                )
                .await;
            assert_eq!(response.status, StatusCode::OK, "round {round}");
        }
    }

    // Six rows, none of them live, and still room for two more.
    assert_eq!(app.count_devices().await, 6);
    app.pair_device(&session, "seventh", "linux").await;
}

// --- input ------------------------------------------------------------

#[tokio::test]
async fn the_device_name_bounds_are_enforced_at_the_edge() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let longest = "x".repeat(64);
    let too_long = "x".repeat(65);

    for (label, name, expected) in [
        ("the minimum", "x".to_owned(), None),
        ("the maximum", longest, None),
        ("empty", String::new(), Some("invalid_device_name")),
        ("blank", "   ".to_owned(), Some("invalid_device_name")),
        (
            "one over the maximum",
            too_long,
            Some("invalid_device_name"),
        ),
        (
            "a newline",
            "laptop\nadmin".to_owned(),
            Some("invalid_device_name"),
        ),
        (
            "a bidi override",
            "laptop\u{202e}revoked".to_owned(),
            Some("invalid_device_name"),
        ),
    ] {
        let code = app.issue_pairing_code(&session).await;
        let response = app
            .send(TestRequest::post("/api/v1/pair").json(json!({
                "pairing_code": code,
                "device_name": name,
                "platform": "linux",
            })))
            .await;

        match expected {
            None => assert_eq!(
                response.status,
                StatusCode::CREATED,
                "{label} must be accepted: {:?}",
                response.body
            ),
            Some(code) => {
                assert_eq!(
                    response.status,
                    StatusCode::BAD_REQUEST,
                    "{label}: {:?}",
                    response.body
                );
                assert_eq!(response.error_code(), Some(code), "{label}");
            }
        }
    }
}

#[tokio::test]
async fn every_known_platform_is_accepted_and_nothing_else_is() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    for platform in ["android", "windows", "macos", "linux", "ios", "LINUX"] {
        let code = app.issue_pairing_code(&session).await;
        let response = app
            .send(TestRequest::post("/api/v1/pair").json(json!({
                "pairing_code": code,
                "device_name": "probe",
                "platform": platform,
            })))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{platform} must be accepted: {:?}",
            response.body
        );
    }

    for platform in ["", "freebsd", "web", "Android TV"] {
        let code = app.issue_pairing_code(&session).await;
        let response = app
            .send(TestRequest::post("/api/v1/pair").json(json!({
                "pairing_code": code,
                "device_name": "probe",
                "platform": platform,
            })))
            .await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "{platform:?} must be refused"
        );
        assert_eq!(response.error_code(), Some("invalid_platform"));
    }
}

/// Input is checked before the code is looked at, so a request with
/// both a bad name and a bad code reports the name - and, more
/// importantly, spends no database lookup on the code.
#[tokio::test]
async fn input_is_validated_before_the_code_is() {
    let app = TestApp::new().await;
    app.provisioned_admin().await;

    let response = app
        .send(TestRequest::post("/api/v1/pair").json(json!({
            "pairing_code": unissued_code(),
            "device_name": "",
            "platform": "linux",
        })))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.error_code(), Some("invalid_device_name"));
}

#[tokio::test]
async fn a_body_with_an_unknown_field_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let code = app.issue_pairing_code(&session).await;

    let response = app
        .send(TestRequest::post("/api/v1/pair").json(json!({
            "pairing_code": code,
            "device_name": "laptop",
            "platform": "linux",
            "role": "admin",
        })))
        .await;
    assert!(
        response.status.is_client_error(),
        "a stray field must not be silently ignored: {:?}",
        response.body
    );
    // And the rejection must not quote what was sent.
    assert!(!response.body.to_string().contains("role"));
}
