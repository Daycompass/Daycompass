//! Two concurrent redemptions of one invite token, over a file-backed
//! database so the requests really overlap.
//!
//! The single-use property rests on the `UPDATE ... WHERE used_at IS
//! NULL` inside `store::redeem_invite`, not on a preceding `SELECT` -
//! see that function's doc comment - so exactly one of two concurrent
//! redemptions may land.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_redemption_of_one_invite_yields_exactly_one_password() {
    // Repeated, because a race that only sometimes interleaves would
    // otherwise pass by luck.
    for attempt in 1..=5 {
        let app = TestApp::with_file_db().await;
        let (_credentials, admin) = app.provisioned_admin().await;
        let (user_id, token, _expires_at) = app.create_pending_account(&admin, "bob", "user").await;

        let request = |password: &str| {
            TestRequest::post("/api/v1/invites/redeem")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "invite_token": token,
                    "new_password": password,
                }))
        };
        let left_password = common::random_secret();
        let right_password = common::random_secret();

        let (left, right) = tokio::join!(
            app.send(request(&left_password)),
            app.send(request(&right_password))
        );

        let statuses = [left.status, right.status];
        let redeemed = statuses
            .iter()
            .filter(|status| **status == StatusCode::NO_CONTENT)
            .count();
        let rejected = statuses
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count();

        assert_eq!(
            redeemed, 1,
            "attempt {attempt}: exactly one redemption may land, saw {statuses:?}"
        );
        assert_eq!(
            rejected, 1,
            "attempt {attempt}: the loser must be refused, saw {statuses:?}"
        );

        // Exactly one of the two passwords is in effect.
        let mut working = 0;
        for password in [&left_password, &right_password] {
            let response = app
                .send(
                    TestRequest::post("/api/v1/auth/login")
                        .origin(GOOD_ORIGIN)
                        .json(json!({ "username": "bob", "password": password })),
                )
                .await;
            if response.status == StatusCode::OK {
                working += 1;
            }
        }
        assert_eq!(
            working, 1,
            "attempt {attempt}: exactly one new password may be in effect"
        );

        // And exactly one `invite_redeemed` entry exists - the loser's
        // attempt never wrote one.
        let session = app
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(GOOD_ORIGIN)
                    .json(json!({
                        "username": "bob",
                        "password": if left.status == StatusCode::NO_CONTENT {
                            &left_password
                        } else {
                            &right_password
                        },
                    })),
            )
            .await;
        let cookie = session.session_cookie().expect("a session cookie");
        let log = app
            .send(TestRequest::get("/api/v1/account/log").cookie(&cookie))
            .await;
        let entries = log.body["entries"].as_array().expect("a list");
        assert_eq!(
            entries.len(),
            1,
            "attempt {attempt}: exactly one log entry may exist: {entries:?}"
        );
        assert_eq!(entries[0]["kind"], "invite_redeemed");

        let (invite_rows,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM invite_tokens WHERE user_id = ?1")
                .bind(&user_id)
                .fetch_one(&app.pool)
                .await
                .expect("counting must succeed");
        assert_eq!(
            invite_rows, 1,
            "attempt {attempt}: the one spent invite row stays, marked used"
        );
    }
}
