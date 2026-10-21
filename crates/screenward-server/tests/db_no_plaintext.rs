//! Scans the whole database for anything that should only ever exist as
//! a hash.
//!
//! Deliberately table-agnostic: it reads the table list from
//! `sqlite_master` and dumps every value, so a table added by a later
//! migration is covered without anyone remembering to extend this test.

mod common;

use axum::http::StatusCode;
use common::{TestApp, TestRequest, GOOD_ORIGIN};
use serde_json::json;

/// Drives the full flow, then asserts that none of the secrets involved
/// can be found anywhere in storage.
#[tokio::test]
async fn no_plaintext_secret_is_ever_stored() {
    let app = TestApp::new().await;

    // A setup token, which must be stored only as a hash.
    let setup_token = app.issue_setup_token().await;
    let password = common::random_secret();

    let created = app
        .send(TestRequest::post("/api/v1/setup").json(json!({
            "setup_token": setup_token,
            "username": "alice",
            "password": password,
        })))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);

    // A session token and its derived CSRF token.
    let login = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({ "username": "alice", "password": password })),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK);

    let session_cookie = login.session_cookie().expect("a session cookie");
    let session_token = session_cookie
        .split_once('=')
        .map(|(_, value)| value.to_owned())
        .expect("the cookie must have a value");
    let csrf_token = login.body["csrf_token"]
        .as_str()
        .expect("a CSRF token")
        .to_owned();

    // Use the session, so last_used_at is written too.
    let me = app
        .send(TestRequest::get("/api/v1/auth/me").cookie(&session_cookie))
        .await;
    assert_eq!(me.status, StatusCode::OK);

    // An account created by an admin, and a password changed by its
    // owner: both write a password hash through a different path than
    // setup does, so both belong in this scan.
    let session = common::Session {
        cookie: session_cookie.clone(),
        csrf_token: csrf_token.clone(),
    };
    let (_id, created_credentials) = app.create_account(&session, "bob", "user").await;
    let changed_password = common::random_secret();
    let change = app
        .send(
            TestRequest::post("/api/v1/auth/password")
                .origin(GOOD_ORIGIN)
                .authenticated(&session)
                .json(json!({
                    "current_password": password,
                    "new_password": changed_password,
                })),
        )
        .await;
    assert_eq!(change.status, StatusCode::OK, "{:?}", change.body);

    let dump = app.dump_all_values().await;
    assert!(!dump.is_empty(), "the scan must actually read something");

    let secrets = [
        ("the password", password.as_str()),
        ("the created account's password", created_credentials.password.as_str()),
        ("the changed password", changed_password.as_str()),
        ("the setup token", setup_token.as_str()),
        ("the session token", session_token.as_str()),
        // Derived, never stored: if this appears, something started
        // persisting it.
        ("the CSRF token", csrf_token.as_str()),
    ];

    for (label, secret) in secrets {
        for value in &dump {
            assert!(
                !value.contains(secret),
                "{label} appears in the database: {value}"
            );
        }
    }

    // The random bodies of the tokens, without their prefixes, in case
    // something stored a token stripped of its prefix.
    for (label, secret) in secrets {
        if secret.len() > 4 {
            let body = &secret[4..];
            for value in &dump {
                assert!(
                    !value.contains(body),
                    "the body of {label} appears in the database: {value}"
                );
            }
        }
    }
}

/// What *is* stored must be the right shape: a PHC string for the
/// password, and 32 raw bytes for each token hash.
#[tokio::test]
async fn what_is_stored_is_a_hash_of_the_expected_form() {
    let app = TestApp::new().await;
    let credentials = app.provision_admin().await;
    app.log_in(&credentials).await;

    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users")
        .fetch_one(&app.pool)
        .await
        .expect("the account must exist");
    assert!(
        password_hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "unexpected stored hash form: {password_hash}"
    );

    let session_hash: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_one(&app.pool)
        .await
        .expect("the session must exist");
    assert_eq!(session_hash.len(), 32, "a SHA-256 digest");

    let setup_hash: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM setup_tokens")
        .fetch_one(&app.pool)
        .await
        .expect("the redeemed setup token row must still be there");
    assert_eq!(setup_hash.len(), 32);
}

/// There must be no column anywhere whose name suggests it holds a
/// secret in the clear. This is a guard against a future migration, not
/// a check on today's schema.
#[tokio::test]
async fn no_column_is_named_like_a_plaintext_secret() {
    let app = TestApp::new().await;

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT t.name || '.' || c.name
         FROM sqlite_master AS t
         JOIN pragma_table_info(t.name) AS c
         WHERE t.type = 'table' AND t.name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&app.pool)
    .await
    .expect("listing columns must succeed");

    assert!(!columns.is_empty());
    for column in &columns {
        let lower = column.to_ascii_lowercase();
        let name = lower.split('.').next_back().unwrap_or(&lower);
        let suspicious = ["password", "token", "secret", "csrf"]
            .iter()
            .any(|needle| name.contains(needle));
        if suspicious {
            assert!(
                name.ends_with("_hash"),
                "{column} looks like it holds a secret but is not a _hash column"
            );
        }
    }
}
