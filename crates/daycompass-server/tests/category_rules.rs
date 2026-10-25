//! End-to-end tests for an account's own category rules, and for the
//! category `GET /api/v1/events` resolves from them.
//!
//! The property worth the most attention, same as
//! `tests/devices_manage.rs`: one account must not be able to see or
//! delete another account's rule. "No such rule" and "not yours" are
//! one answer, or the endpoint becomes a way to enumerate rule ids
//! across accounts.

mod common;

use std::collections::HashMap;

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Session, TestApp, TestRequest, GOOD_ORIGIN};

fn create_rule(session: &Session, kind: &str, pattern: &str, category: &str) -> TestRequest {
    TestRequest::post("/api/v1/category-rules")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .json(json!({ "kind": kind, "pattern": pattern, "category": category }))
}

fn list_rules(session: &Session) -> TestRequest {
    TestRequest::get("/api/v1/category-rules")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
}

fn delete_rule(rule_id: &str, session: &Session) -> TestRequest {
    TestRequest::delete(&format!("/api/v1/category-rules/{rule_id}"))
        .origin(GOOD_ORIGIN)
        .authenticated(session)
}

fn event_id(n: u32) -> String {
    format!("{n:032x}")
}

// --- create / list / delete -------------------------------------------

#[tokio::test]
async fn creating_listing_and_deleting_a_rule_round_trips() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let created = app
        .send(create_rule(&session, "app_id", "org.example.app", "Study"))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["rule"]["kind"], "app_id");
    assert_eq!(created.body["rule"]["pattern"], "org.example.app");
    assert_eq!(created.body["rule"]["category"], "Study");
    assert!(created.body["rule"]["created_at"].as_i64().is_some());
    let rule_id = created.body["rule"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let listed = app.send(list_rules(&session)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let rules = listed.body["rules"].as_array().expect("an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], rule_id);

    let deleted = app.send(delete_rule(&rule_id, &session)).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);

    let listed_after = app.send(list_rules(&session)).await;
    assert!(
        listed_after.body["rules"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "the deleted rule must be gone"
    );
}

#[tokio::test]
async fn a_rule_with_an_unknown_kind_or_a_blank_category_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let bad_kind = app
        .send(create_rule(&session, "url", "example.com", "Browsing"))
        .await;
    assert_eq!(
        bad_kind.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        bad_kind.body
    );
    assert_eq!(bad_kind.error_code(), Some("invalid_category_rule_kind"));

    let blank_category = app
        .send(create_rule(&session, "app_id", "org.example.app", "   "))
        .await;
    assert_eq!(
        blank_category.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        blank_category.body
    );
    assert_eq!(blank_category.error_code(), Some("invalid_category_label"));

    let malformed_domain = app
        .send(create_rule(
            &session,
            "domain",
            "https://example.com",
            "Browsing",
        ))
        .await;
    assert_eq!(
        malformed_domain.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        malformed_domain.body
    );
    assert_eq!(
        malformed_domain.error_code(),
        Some("invalid_category_pattern")
    );

    let listed = app.send(list_rules(&session)).await;
    assert!(
        listed.body["rules"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "nothing refused must have been stored"
    );
}

// --- duplicates ---------------------------------------------------------

#[tokio::test]
async fn a_duplicate_kind_and_pattern_is_refused_even_under_a_different_category() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let first = app
        .send(create_rule(&session, "domain", "example.com", "Browsing"))
        .await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);

    // Same kind and pattern, a different category - still a
    // duplicate: (kind, pattern) is the whole key, not the category
    // it happens to name.
    let second = app
        .send(create_rule(&session, "domain", "example.com", "Other"))
        .await;
    assert_eq!(second.status, StatusCode::CONFLICT, "{:?}", second.body);
    assert_eq!(second.error_code(), Some("category_rule_duplicate"));

    let listed = app.send(list_rules(&session)).await;
    assert_eq!(
        listed.body["rules"].as_array().expect("an array").len(),
        1,
        "the duplicate must not have been stored"
    );
}

/// The same pattern text under the *other* kind is a different rule,
/// not a duplicate - `(user_id, kind, pattern)` is the key.
#[tokio::test]
async fn the_same_pattern_text_under_a_different_kind_is_not_a_duplicate() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let as_domain = app
        .send(create_rule(&session, "domain", "example.com", "Browsing"))
        .await;
    assert_eq!(
        as_domain.status,
        StatusCode::CREATED,
        "{:?}",
        as_domain.body
    );

    let as_app_id = app
        .send(create_rule(&session, "app_id", "example.com", "Other"))
        .await;
    assert_eq!(
        as_app_id.status,
        StatusCode::CREATED,
        "{:?}",
        as_app_id.body
    );

    let listed = app.send(list_rules(&session)).await;
    assert_eq!(listed.body["rules"].as_array().expect("an array").len(), 2);
}

// --- the per-account cap -------------------------------------------------

#[tokio::test]
async fn an_account_cannot_exceed_the_rule_cap() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let cap = daycompass_server::categories::store::MAX_RULES_PER_USER;
    for n in 0..cap {
        let response = app
            .send(create_rule(
                &session,
                "app_id",
                &format!("org.example.rule-{n}"),
                "Study",
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "rule {n}: {:?}",
            response.body
        );
    }

    let over_the_cap = app
        .send(create_rule(
            &session,
            "app_id",
            "org.example.one-too-many",
            "Study",
        ))
        .await;
    assert_eq!(
        over_the_cap.status,
        StatusCode::CONFLICT,
        "{:?}",
        over_the_cap.body
    );
    assert_eq!(
        over_the_cap.error_code(),
        Some("category_rule_limit_reached")
    );

    let listed = app.send(list_rules(&session)).await;
    assert_eq!(
        listed.body["rules"].as_array().expect("an array").len(),
        cap,
        "the rejected rule must not have been stored"
    );
}

// --- isolation ------------------------------------------------------------

/// The core isolation property, and the reason "not found" and "not
/// yours" are one answer.
#[tokio::test]
async fn one_account_cannot_see_or_delete_anothers_rule() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;

    let created = app
        .send(create_rule(&admin, "app_id", "org.example.app", "Study"))
        .await;
    let rule_id = created.body["rule"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let listed_as_user = app.send(list_rules(&user)).await;
    assert!(
        listed_as_user.body["rules"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "another account's rules must not be visible"
    );

    let deleted = app.send(delete_rule(&rule_id, &user)).await;
    assert_eq!(deleted.status, StatusCode::NOT_FOUND, "{:?}", deleted.body);

    // Untouched for the real owner.
    let listed_as_admin = app.send(list_rules(&admin)).await;
    assert_eq!(
        listed_as_admin.body["rules"]
            .as_array()
            .expect("an array")
            .len(),
        1,
        "a failed cross-account delete must not have removed it"
    );

    // A rule id that exists nowhere must be answered identically, so
    // the response cannot be used to probe which ids are real.
    let absent = app
        .send(delete_rule("00000000-0000-7000-8000-000000000000", &user))
        .await;
    assert_eq!(absent.status, deleted.status);
    assert_eq!(
        absent.body, deleted.body,
        "somebody else's rule must look exactly like no rule"
    );
}

// --- category resolution on GET /api/v1/events ---------------------------

/// `app_id` beats `domain`, and among domain rules the longest
/// (most specific) matching pattern wins - exercised end to end
/// through the real read path, not just the resolver's own unit
/// tests.
#[tokio::test]
async fn category_is_resolved_from_the_callers_own_rules_when_reading_events_back() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();

    let ingested = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(json!({
                    "events": [
                        {
                            "event_id": event_id(1),
                            "start_ts": now - 400,
                            "duration_secs": 60,
                            "app_id": "org.example.app",
                            "domain": "example.com",
                        },
                        {
                            "event_id": event_id(2),
                            "start_ts": now - 300,
                            "duration_secs": 60,
                            "app_id": "org.example.browser",
                            "domain": "mail.google.com",
                        },
                        {
                            "event_id": event_id(3),
                            "start_ts": now - 200,
                            "duration_secs": 60,
                            "app_id": "org.example.browser",
                            "domain": "docs.google.com",
                        },
                        {
                            "event_id": event_id(4),
                            "start_ts": now - 100,
                            "duration_secs": 60,
                            "app_id": "org.example.unmatched",
                        },
                    ],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 4, "{:?}", ingested.body);

    // Event 1 matches both an app_id rule and a domain rule - the
    // app_id rule must win.
    app.send(create_rule(&session, "app_id", "org.example.app", "Study"))
        .await;
    app.send(create_rule(&session, "domain", "example.com", "Browsing"))
        .await;
    // Events 2 and 3 both sit under google.com, but event 2's more
    // specific mail.google.com rule must win for event 2, while event
    // 3 falls back to the wider rule.
    app.send(create_rule(&session, "domain", "google.com", "Search"))
        .await;
    app.send(create_rule(&session, "domain", "mail.google.com", "Email"))
        .await;

    let path = format!("/api/v1/events?start_ts={}&end_ts={}", now - 3600, now + 10);
    let response = app
        .send(
            TestRequest::get(&path)
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);

    let by_id: HashMap<&str, &Value> = response.body["events"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|event| (event["event_id"].as_str().expect("an event_id"), event))
        .collect();

    assert_eq!(
        by_id[event_id(1).as_str()]["category"],
        "Study",
        "an app_id match must beat a domain match"
    );
    assert_eq!(
        by_id[event_id(2).as_str()]["category"],
        "Email",
        "the more specific domain rule must win"
    );
    assert_eq!(
        by_id[event_id(3).as_str()]["category"],
        "Search",
        "a sibling subdomain falls back to the wider rule"
    );
    assert!(
        by_id[event_id(4).as_str()]["category"].is_null(),
        "an event matching no rule must have category absent, not a sentinel string"
    );
}

/// An account with no category rules at all still reads its events
/// back - `category` is simply absent on every one of them, same as
/// before this feature existed.
#[tokio::test]
async fn events_are_still_readable_with_no_category_rules_at_all() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    app.send(
        TestRequest::post("/api/v1/events")
            .authenticated_as_device(&device)
            .json(json!({
                "events": [{
                    "event_id": event_id(1),
                    "start_ts": now - 60,
                    "duration_secs": 60,
                    "app_id": "org.example.app",
                }],
            })),
    )
    .await;

    let path = format!("/api/v1/events?start_ts={}&end_ts={}", now - 3600, now + 10);
    let response = app
        .send(
            TestRequest::get(&path)
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    let events = response.body["events"].as_array().expect("an array");
    assert_eq!(events.len(), 1);
    assert!(events[0]["category"].is_null());
}
