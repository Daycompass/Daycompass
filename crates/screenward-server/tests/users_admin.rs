//! End-to-end tests for the admin-only account endpoints.
//!
//! The route-level protections (anonymous, non-admin, CSRF, `Origin`)
//! are walked for every route in `tests/route_inventory.rs`, from the
//! inventory itself. What is tested here is what the endpoints *do*:
//! the account rules, the last-admin protection, and the fact that a
//! role is re-read on every request rather than cached in a session.
//!
//! Every credential is generated at runtime.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Credentials, TestApp, TestRequest, GOOD_ORIGIN};
use screenward_server::routes::{Access, INVENTORY};

/// Nothing a client is ever shown may contain a stored hash, whatever
/// else a test is about.
fn assert_no_hash(body: &serde_json::Value, password: &str) {
    let rendered = body.to_string();
    for needle in ["password_hash", "$argon2", password] {
        assert!(
            !rendered.contains(needle),
            "a response contained {needle:?}: {rendered}"
        );
    }
}

#[tokio::test]
async fn creating_an_account_returns_it_without_a_hash() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let credentials = Credentials::generate("bob");

    let response = app
        .send(
            TestRequest::post("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "username": credentials.username,
                    "password": credentials.password,
                    "role": "user",
                })),
        )
        .await;

    assert_eq!(response.status, StatusCode::CREATED, "{:?}", response.body);
    assert_eq!(
        response.shape(),
        vec!["user.created_at", "user.id", "user.role", "user.username"]
    );
    assert_eq!(response.body["user"]["username"], "bob");
    assert_eq!(response.body["user"]["role"], "user");
    assert_no_hash(&response.body, &credentials.password);

    // And the account really works.
    let session = app.log_in(&credentials).await;
    let me = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["role"], "user");
}

/// The username is normalized the same way everywhere, so a differently
/// cased spelling is the same account - and is refused as taken.
#[tokio::test]
async fn a_duplicate_username_is_a_conflict_however_it_is_spelled() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    app.create_account(&admin, "bob", "user").await;

    for spelling in ["bob", "BOB", "Bob", "  bob  "] {
        let response = app
            .send(
                TestRequest::post("/api/v1/users")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin)
                    .json(json!({
                        "username": spelling,
                        "password": common::random_secret(),
                        "role": "user",
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::CONFLICT,
            "{spelling:?}: {:?}",
            response.body
        );
        assert_eq!(
            response.error_code(),
            Some("username_taken"),
            "{spelling:?}"
        );
    }

    let listed = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(
        listed.body["users"].as_array().expect("a list").len(),
        2,
        "only the admin and bob may exist"
    );
}

#[tokio::test]
async fn the_list_shows_every_account_and_no_hashes() {
    let app = TestApp::new().await;
    let (admin_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob) = app.create_account(&admin, "bob", "user").await;

    let response = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;

    assert_eq!(response.status, StatusCode::OK);
    let users = response.body["users"].as_array().expect("a list").clone();
    assert_eq!(users.len(), 2);
    for user in &users {
        let mut keys: Vec<&str> = user
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["created_at", "id", "role", "username"]);
        assert!(user["created_at"].as_i64().is_some_and(|at| at > 0));
    }
    assert_no_hash(&response.body, &admin_credentials.password);
    assert_no_hash(&response.body, &bob.password);
}

/// The role is read from the database on every request, never cached in
/// the session: an account demoted a moment ago is an ordinary user on
/// its very next request, with its session untouched.
#[tokio::test]
async fn a_demoted_admins_existing_session_loses_admin_rights_at_once() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (second_id, second) = app.second_admin(&admin, "bob").await;

    // The second admin can manage accounts.
    let before = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&second),
        )
        .await;
    assert_eq!(before.status, StatusCode::OK);

    let demoted = app
        .send(
            TestRequest::patch(&format!("/api/v1/users/{second_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({ "role": "user" })),
        )
        .await;
    assert_eq!(demoted.status, StatusCode::OK, "{:?}", demoted.body);
    assert_eq!(demoted.body["user"]["role"], "user");

    // Same cookie, same CSRF token, no new login: the next admin
    // request is refused.
    let after = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&second),
        )
        .await;
    assert_eq!(after.status, StatusCode::FORBIDDEN, "{:?}", after.body);
    assert_eq!(after.error_code(), Some("forbidden"));

    // The session itself is still alive, and reports the new role.
    let me = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&second),
        )
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["role"], "user");
}

/// An admin may step down while another admin remains - and loses the
/// rights immediately, on the session they stepped down with.
#[tokio::test]
async fn an_admin_may_demote_itself_and_loses_its_rights_at_once() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (_second_id, _second) = app.second_admin(&admin, "bob").await;

    let own_id = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let demoted = app
        .send(
            TestRequest::patch(&format!("/api/v1/users/{own_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({ "role": "user" })),
        )
        .await;
    assert_eq!(demoted.status, StatusCode::OK, "{:?}", demoted.body);

    let after = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(after.status, StatusCode::FORBIDDEN, "{:?}", after.body);
}

/// Deleting your own account is allowed while another admin remains,
/// and the session dies with the account.
#[tokio::test]
async fn an_admin_may_delete_itself_and_its_session_dies() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    app.second_admin(&admin, "bob").await;

    let own_id = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let deleted = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{own_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let after = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "{:?}", after.body);
    assert_eq!(after.error_code(), Some("unauthenticated"));
}

#[tokio::test]
async fn the_last_admin_can_be_neither_demoted_nor_deleted() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    // An ordinary account exists, so the instance is not empty - it
    // simply has one admin.
    app.create_account(&admin, "bob", "user").await;

    let own_id = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let demote = app
        .send(
            TestRequest::patch(&format!("/api/v1/users/{own_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({ "role": "user" })),
        )
        .await;
    assert_eq!(demote.status, StatusCode::CONFLICT, "{:?}", demote.body);
    assert_eq!(demote.error_code(), Some("last_admin_protected"));

    let delete = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{own_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(delete.status, StatusCode::CONFLICT, "{:?}", delete.body);
    assert_eq!(delete.error_code(), Some("last_admin_protected"));

    // Still an admin, and still able to work.
    let still = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(still.status, StatusCode::OK);
}

/// Two admins, each deleting the other at the same moment, over a
/// file-backed database so the requests really overlap. The last-admin
/// rule lives inside a `BEGIN IMMEDIATE` transaction, so one of them
/// has to lose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_admins_cannot_delete_each_other_at_the_same_time() {
    let app = TestApp::with_file_db().await;
    let (_first_credentials, first) = app.provisioned_admin().await;
    let (second_id, second) = app.second_admin(&first, "bob").await;
    let first_id = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&first),
        )
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let (left, right) = tokio::join!(
        app.send(
            TestRequest::delete(&format!("/api/v1/users/{second_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&first),
        ),
        app.send(
            TestRequest::delete(&format!("/api/v1/users/{first_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&second),
        )
    );

    let statuses = [left.status, right.status];
    let deleted = statuses
        .iter()
        .filter(|status| **status == StatusCode::NO_CONTENT)
        .count();
    assert!(
        deleted <= 1,
        "at most one deletion may land, saw {statuses:?}"
    );

    // Whatever the interleaving, an admin is left.
    let (admins,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&app.pool)
        .await
        .expect("counting must succeed");
    assert_eq!(admins, 1, "exactly one admin must remain");
}

/// The same race through `PATCH`: two admins demoting each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_admins_cannot_demote_each_other_at_the_same_time() {
    let app = TestApp::with_file_db().await;
    let (_first_credentials, first) = app.provisioned_admin().await;
    let (second_id, second) = app.second_admin(&first, "bob").await;
    let first_id = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&first),
        )
        .await
        .body["user"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let (left, right) = tokio::join!(
        app.send(
            TestRequest::patch(&format!("/api/v1/users/{second_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&first)
                .json(json!({ "role": "user" })),
        ),
        app.send(
            TestRequest::patch(&format!("/api/v1/users/{first_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&second)
                .json(json!({ "role": "user" })),
        )
    );

    let statuses = [left.status, right.status];
    let demoted = statuses
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    assert!(
        demoted <= 1,
        "at most one demotion may land, saw {statuses:?}"
    );

    let (admins,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&app.pool)
        .await
        .expect("counting must succeed");
    assert_eq!(admins, 1, "exactly one admin must remain");
}

#[tokio::test]
async fn a_deleted_accounts_session_stops_working_immediately() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    let before = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&bob),
        )
        .await;
    assert_eq!(before.status, StatusCode::OK);

    let deleted = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{bob_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let after = app
        .send(
            TestRequest::get("/api/v1/auth/me")
                .origin(GOOD_ORIGIN)
                .authenticated(&bob),
        )
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "{:?}", after.body);
    assert_eq!(after.error_code(), Some("unauthenticated"));

    // And logging in again is not possible either.
    let login = app
        .send(
            TestRequest::post("/api/v1/auth/login")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "username": bob_credentials.username,
                    "password": bob_credentials.password,
                })),
        )
        .await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);
    assert_eq!(login.error_code(), Some("invalid_credentials"));
}

#[tokio::test]
async fn an_unknown_account_id_is_a_not_found() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    // A well-formed id that names nothing, and one that is not an id at
    // all: both answer the same way.
    for id in ["00000000-0000-7000-8000-000000000000", "not-an-id"] {
        let patch = app
            .send(
                TestRequest::patch(&format!("/api/v1/users/{id}"))
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin)
                    .json(json!({ "role": "user" })),
            )
            .await;
        assert_eq!(
            patch.status,
            StatusCode::NOT_FOUND,
            "{id}: {:?}",
            patch.body
        );
        assert_eq!(patch.error_code(), Some("not_found"), "{id}");

        let delete = app
            .send(
                TestRequest::delete(&format!("/api/v1/users/{id}"))
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin),
            )
            .await;
        assert_eq!(delete.status, StatusCode::NOT_FOUND, "{id}");
        assert_eq!(delete.error_code(), Some("not_found"), "{id}");
    }
}

/// Bad input is answered from the closed error set, in the uniform
/// shape, and never by quoting what was sent.
#[tokio::test]
async fn bad_input_is_the_uniform_error_and_never_echoed() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let password = common::random_secret();
    let (bob_id, _bob) = app.create_account(&admin, "bob", "user").await;

    // An unknown role, on both endpoints that take one.
    for role in ["root", "ADMIN", "Admin", "superuser", ""] {
        let created = app
            .send(
                TestRequest::post("/api/v1/users")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin)
                    .json(json!({
                        "username": "carol",
                        "password": password,
                        "role": role,
                    })),
            )
            .await;
        assert_eq!(
            created.status,
            StatusCode::BAD_REQUEST,
            "{role:?}: {:?}",
            created.body
        );
        assert_eq!(created.error_code(), Some("invalid_role"), "{role:?}");

        let patched = app
            .send(
                TestRequest::patch(&format!("/api/v1/users/{bob_id}"))
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin)
                    .json(json!({ "role": role })),
            )
            .await;
        assert_eq!(patched.error_code(), Some("invalid_role"), "{role:?}");
    }

    // An unknown field is refused rather than ignored, so "I sent
    // role=admin" cannot quietly have meant "I sent nothing".
    let stray = app
        .send(
            TestRequest::post("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "username": "carol",
                    "password": password,
                    "role": "user",
                    "is_admin": true,
                })),
        )
        .await;
    assert!(stray.status.is_client_error(), "{:?}", stray.body);
    assert_eq!(stray.shape(), vec!["error.code", "error.message"]);
    assert!(!stray.body.to_string().contains("is_admin"));

    // A wrong type, a missing field, and a body that is not JSON.
    for body in [
        json!({ "username": 7, "password": password, "role": "user" }),
        json!({ "username": "carol" }),
        json!("not an object"),
    ] {
        let response = app
            .send(
                TestRequest::post("/api/v1/users")
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin)
                    .json(body),
            )
            .await;
        assert!(response.status.is_client_error(), "{:?}", response.body);
        assert_eq!(response.shape(), vec!["error.code", "error.message"]);
    }

    // The policies, which are public rules and are named as such.
    let short = app
        .send(
            TestRequest::post("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "username": "carol",
                    "password": &password[..11],
                    "role": "user",
                })),
        )
        .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.error_code(), Some("invalid_password"));

    let bad_name = app
        .send(
            TestRequest::post("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin)
                .json(json!({
                    "username": "Not Allowed",
                    "password": password,
                    "role": "user",
                })),
        )
        .await;
    assert_eq!(bad_name.error_code(), Some("invalid_username"));
    assert!(!bad_name.body.to_string().contains("Not Allowed"));
}

/// The same ground the inventory walk covers, stated directly: no admin
/// route answers an anonymous or an ordinary caller.
#[tokio::test]
async fn no_admin_route_answers_an_anonymous_or_ordinary_caller() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (target_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    for spec in INVENTORY.iter().filter(|spec| spec.access == Access::Admin) {
        let path = spec.path.replace("{id}", &target_id);
        let method = axum::http::Method::from_bytes(spec.method.as_bytes()).expect("a method");

        let anonymous = app
            .send(
                TestRequest::new(method.clone(), &path)
                    .origin(GOOD_ORIGIN)
                    .json(json!({ "role": "user" })),
            )
            .await;
        assert_eq!(
            anonymous.status,
            StatusCode::UNAUTHORIZED,
            "{} {}: {:?}",
            spec.method,
            spec.path,
            anonymous.body
        );

        let ordinary = app
            .send(
                TestRequest::new(method, &path)
                    .origin(GOOD_ORIGIN)
                    .authenticated(&bob)
                    .json(json!({ "role": "user" })),
            )
            .await;
        assert_eq!(
            ordinary.status,
            StatusCode::FORBIDDEN,
            "{} {}: {:?}",
            spec.method,
            spec.path,
            ordinary.body
        );
        assert_eq!(ordinary.error_code(), Some("forbidden"));
    }

    // Nothing above changed anything.
    let listed = app
        .send(
            TestRequest::get("/api/v1/users")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(listed.body["users"].as_array().expect("a list").len(), 2);
}
