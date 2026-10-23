//! End-to-end tests for `GET /api/v1/account/log`, and the structural
//! guarantee that nothing in the sources may update or delete an entry
//! once written.
//!
//! The behavioural half: all three kinds appear, with UTC Unix
//! timestamps, and an account sees only its own log - there is no id
//! parameter and no admin variant. The structural half is a source
//! scan in the style of `tests/no_event_reads.rs`.

mod common;

use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use serde_json::json;

use common::{Credentials, TestApp, TestRequest, GOOD_ORIGIN};
use daycompass_server::routes::INVENTORY;

/// The only route this server has for reading the account log, and it
/// is a `GET`.
const THE_ONLY_ACCOUNT_LOG_ROUTE: (&str, &str) = ("GET", "/api/v1/account/log");

/// Files permitted to write to `account_log` in SQL. Extend
/// deliberately, with a reviewer, if a later milestone adds a
/// legitimate new writer.
const FILES_ALLOWED_TO_WRITE_ACCOUNT_LOG: &[&str] = &["auth/account_log.rs"];

/// SQL shapes that would change or erase an existing entry.
///
/// `insert into account_log` is deliberately absent: that is the one
/// write this table is for, and it is checked for separately below.
const FORBIDDEN_VERBS: &[&str] = &["update account_log", "delete from account_log"];

#[test]
fn the_inventory_has_exactly_one_account_log_route_and_it_is_a_read() {
    let touching: Vec<(&str, &str)> = INVENTORY
        .iter()
        .filter(|spec| spec.path.contains("account"))
        .map(|spec| (spec.method, spec.path))
        .collect();

    assert_eq!(touching, vec![THE_ONLY_ACCOUNT_LOG_ROUTE]);
}

/// No source file anywhere may update or delete an `account_log` row.
/// An entry, once written, is a historical fact.
#[test]
fn no_source_statement_updates_or_deletes_an_account_log_entry() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&src);
    assert!(!sources.is_empty(), "the scan must read something");

    let mut offenders: Vec<String> = Vec::new();
    for path in &sources {
        let relative = relative_to(&src, path);
        let text = std::fs::read_to_string(path).expect("a source file must be readable");
        let normalized = normalize(production_part(&text, &relative));

        for verb in FORBIDDEN_VERBS {
            if normalized.contains(verb) {
                offenders.push(format!("{relative}: {verb}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these files would update or delete an account_log entry: {offenders:?}"
    );
}

/// And only the one module permitted to may insert into the table, so
/// the allowed-list above is not vacuous.
#[test]
fn only_account_log_rs_inserts_into_account_log() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&src);

    let mut writers: Vec<String> = Vec::new();
    for path in &sources {
        let relative = relative_to(&src, path);
        let text = std::fs::read_to_string(path).expect("a source file must be readable");
        let normalized = normalize(production_part(&text, &relative));
        if normalized.contains("into account_log") {
            writers.push(relative);
        }
    }

    for writer in &writers {
        assert!(
            FILES_ALLOWED_TO_WRITE_ACCOUNT_LOG
                .iter()
                .any(|allowed| writer.ends_with(allowed)),
            "{writer} inserts into account_log but is not in the allowed list"
        );
    }
    assert!(
        !writers.is_empty(),
        "the scan found no writer at all; its needle is probably wrong"
    );
}

fn production_part<'a>(text: &'a str, relative: &str) -> &'a str {
    let occurrences = text.matches("#[cfg(test)]").count();
    assert!(
        occurrences <= 1,
        "{relative} has {occurrences} #[cfg(test)] attributes"
    );
    match text.find("#[cfg(test)]") {
        Some(index) => &text[..index],
        None => text,
    }
}

fn normalize(text: &str) -> String {
    let without_comments: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    without_comments
        .join(" ")
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).expect("the source directory must be readable");
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            files.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

// --- behaviour ----------------------------------------------------------

#[tokio::test]
async fn all_three_kinds_appear_with_unix_timestamps() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let admin_id = app
        .send(TestRequest::get("/api/v1/auth/me").authenticated(&admin))
        .await
        .body["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // invite_redeemed, via the normal create-then-redeem flow.
    let (bob_id, token, _expires_at) = app.create_pending_account(&admin, "bob", "user").await;
    let password = common::random_secret();
    app.send(
        TestRequest::post("/api/v1/invites/redeem")
            .origin(GOOD_ORIGIN)
            .json(json!({ "invite_token": token, "new_password": password })),
    )
    .await;
    let session = app
        .log_in(&Credentials {
            username: "bob".to_owned(),
            password: password.clone(),
        })
        .await;

    // password_changed, self-service.
    let new_password = common::random_secret();
    let changed = app
        .send(
            TestRequest::post("/api/v1/auth/password")
                .origin(GOOD_ORIGIN)
                .authenticated(&session)
                .json(json!({
                    "current_password": password,
                    "new_password": new_password,
                })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);

    // password_reset_by_admin.
    let reset = app
        .send(
            TestRequest::post(&format!("/api/v1/users/{bob_id}/password-reset"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    let reset_token = reset.body["invite"]["token"].as_str().unwrap().to_owned();

    // Redeem the fresh invite so there is a session to read the log
    // with - the reset itself ended the previous one.
    let final_password = common::random_secret();
    app.send(
        TestRequest::post("/api/v1/invites/redeem")
            .origin(GOOD_ORIGIN)
            .json(json!({ "invite_token": reset_token, "new_password": final_password })),
    )
    .await;
    let final_session = app
        .log_in(&Credentials {
            username: "bob".to_owned(),
            password: final_password,
        })
        .await;

    let log = app
        .send(
            TestRequest::get("/api/v1/account/log")
                .origin(GOOD_ORIGIN)
                .authenticated(&final_session),
        )
        .await;
    assert_eq!(log.status, StatusCode::OK, "{:?}", log.body);
    let entries = log.body["entries"].as_array().expect("a list");
    // Four, not three: the account redeemed an invite twice - once at
    // creation, once after the reset - so `invite_redeemed` appears
    // twice among the four entries.
    assert_eq!(entries.len(), 4, "{entries:?}");

    let kinds: Vec<&str> = entries
        .iter()
        .map(|entry| entry["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"invite_redeemed"));
    assert!(kinds.contains(&"password_changed"));
    assert!(kinds.contains(&"password_reset_by_admin"));

    let reset_entry = entries
        .iter()
        .find(|entry| entry["kind"] == "password_reset_by_admin")
        .expect("the reset entry");
    assert_eq!(reset_entry["actor_id"], admin_id);

    // Every timestamp is a plausible Unix second, not a string and not
    // zero.
    for entry in entries {
        let at = entry["at"].as_i64().expect("an integer timestamp");
        assert!(at > 1_700_000_000, "timestamp looks wrong: {at}");
    }
}

#[tokio::test]
async fn an_account_sees_only_its_own_log() {
    let app = TestApp::new().await;
    let (admin_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    // The admin changes its own password, writing an entry to its own
    // log only.
    let new_password = common::random_secret();
    app.send(
        TestRequest::post("/api/v1/auth/password")
            .origin(GOOD_ORIGIN)
            .authenticated(&admin)
            .json(json!({
                "current_password": admin_credentials.password,
                "new_password": new_password,
            })),
    )
    .await;

    let bob_log = app
        .send(
            TestRequest::get("/api/v1/account/log")
                .origin(GOOD_ORIGIN)
                .authenticated(&bob),
        )
        .await;
    assert_eq!(bob_log.status, StatusCode::OK);
    // One, not zero: `create_account` redeems bob's own invite as part
    // of setting him up, which is itself an `invite_redeemed` entry.
    // The admin's password change must not have added a second one.
    assert_eq!(bob_log.body["entries"].as_array().unwrap().len(), 1);

    let admin_session = app
        .log_in(&Credentials {
            username: admin_credentials.username,
            password: new_password,
        })
        .await;
    let admin_log = app
        .send(
            TestRequest::get("/api/v1/account/log")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin_session),
        )
        .await;
    assert_eq!(admin_log.body["entries"].as_array().unwrap().len(), 1);
}

/// A session row pointing at a pending account - not reachable through
/// any HTTP flow today, since a pending account has no password to log
/// in with, so it is created directly against the pool - must be
/// refused at the route, not merely fail to resolve in isolation.
#[tokio::test]
async fn a_session_for_a_pending_account_is_refused_at_the_route() {
    use std::time::Duration;

    use daycompass_server::auth::cookie;
    use daycompass_server::auth::session::{self, SessionPolicy};
    use daycompass_server::auth::time::UnixTime;

    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (pending_id, _token, _expires_at) =
        app.create_pending_account(&admin, "carol", "user").await;

    let policy = SessionPolicy {
        idle_timeout: Duration::from_secs(86_400),
        absolute_timeout: Duration::from_secs(86_400),
    };
    let session = session::create(&app.pool, &pending_id, policy, UnixTime::now())
        .await
        .expect("creating a session directly must succeed");

    let response = app
        .send(
            TestRequest::get("/api/v1/account/log")
                .origin(GOOD_ORIGIN)
                .cookie(&format!(
                    "{}={}",
                    cookie::COOKIE_NAME,
                    session.token.expose()
                )),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        response.body
    );
}

#[tokio::test]
async fn no_admin_route_may_read_another_accounts_log() {
    // There is no such route in the inventory at all; this states that
    // fact as a behavioural guarantee rather than leaving it implicit.
    assert!(
        !INVENTORY
            .iter()
            .any(|spec| spec.path.contains("account") && spec.path.contains("{id}")),
        "an id-parameterized account route appeared; it must not be able \
         to read someone else's log"
    );
}
