//! End-to-end tests for `GET /api/v1/stats`: an account's own screen
//! time, summed per UTC calendar day and category, over the real HTTP
//! path rather than `stats::aggregate`'s own unit tests.
//!
//! The property worth the most attention is the same one every other
//! owner-scoped route in this codebase is tested for: one account's
//! events must never show up in another account's totals.

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Session, TestApp, TestRequest, GOOD_ORIGIN};

fn create_rule(session: &Session, kind: &str, pattern: &str, category: &str) -> TestRequest {
    TestRequest::post("/api/v1/category-rules")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .json(json!({ "kind": kind, "pattern": pattern, "category": category }))
}

fn get_stats(session: &Session, start_ts: i64, end_ts: i64) -> TestRequest {
    TestRequest::get(&format!(
        "/api/v1/stats?start_ts={start_ts}&end_ts={end_ts}"
    ))
    .origin(GOOD_ORIGIN)
    .authenticated(session)
}

fn event_id(n: u32) -> String {
    format!("{n:032x}")
}

/// Finds the one entry for `day_start_ts`/`category` in a `days`
/// array, or `None` if there isn't one - callers check sparseness by
/// asserting this directly rather than indexing.
fn find<'a>(days: &'a [Value], day_start_ts: i64, category: Option<&str>) -> Option<&'a Value> {
    days.iter().find(|day| {
        day["day_start_ts"].as_i64() == Some(day_start_ts) && day["category"].as_str() == category
    })
}

#[tokio::test]
async fn totals_are_grouped_by_day_and_category_and_app_id_beats_domain() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let day_start = (now / 86_400) * 86_400;

    app.send(create_rule(
        &session,
        "app_id",
        "org.example.study",
        "Study",
    ))
    .await;
    app.send(create_rule(&session, "domain", "example.com", "Browsing"))
        .await;

    let ingested = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(json!({
                    "events": [
                        {
                            "event_id": event_id(1),
                            "start_ts": day_start + 100,
                            "duration_secs": 300,
                            "app_id": "org.example.study",
                        },
                        {
                            "event_id": event_id(2),
                            "start_ts": day_start + 500,
                            "duration_secs": 60,
                            "app_id": "org.example.study",
                        },
                        // Matches both the app_id rule above and a
                        // domain rule - the app_id rule must win.
                        {
                            "event_id": event_id(3),
                            "start_ts": day_start + 900,
                            "duration_secs": 120,
                            "app_id": "org.example.study",
                            "domain": "example.com",
                        },
                        // No matching rule at all.
                        {
                            "event_id": event_id(4),
                            "start_ts": day_start + 1200,
                            "duration_secs": 45,
                            "app_id": "org.example.unknown",
                        },
                    ],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 4, "{:?}", ingested.body);

    let response = app
        .send(get_stats(&session, day_start, day_start + 86_400))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    let days = response.body["days"].as_array().expect("an array");
    assert_eq!(days.len(), 2, "one row for Study, one for no category");

    let study = find(days, day_start, Some("Study")).expect("a Study total");
    assert_eq!(study["total_duration_secs"], 300 + 60 + 120);

    let uncategorized = find(days, day_start, None).expect("a total for the unmatched event");
    assert_eq!(uncategorized["total_duration_secs"], 45);
    assert!(
        !uncategorized.as_object().unwrap().contains_key("category"),
        "the no-category entry must omit the field, not null it in"
    );
}

/// Two devices reporting the same span are both counted - this
/// endpoint sums overlaps exactly as reported, it does not
/// deduplicate or merge them.
#[tokio::test]
async fn overlapping_reports_from_two_devices_are_both_counted() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device_one = app.pair_device(&session, "laptop", "linux").await;
    let device_two = app.pair_device(&session, "phone", "android").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device_one))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let day_start = (now / 86_400) * 86_400;

    for device in [&device_one, &device_two] {
        let ingested = app
            .send(
                TestRequest::post("/api/v1/events")
                    .authenticated_as_device(device)
                    .json(json!({
                        "events": [{
                            "event_id": event_id(1),
                            "start_ts": day_start + 100,
                            "duration_secs": 600,
                            "app_id": "org.example.app",
                        }],
                    })),
            )
            .await;
        assert_eq!(ingested.body["accepted"], 1, "{:?}", ingested.body);
    }

    let response = app
        .send(get_stats(&session, day_start, day_start + 86_400))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    let days = response.body["days"].as_array().expect("an array");
    assert_eq!(days.len(), 1);
    assert_eq!(
        days[0]["total_duration_secs"], 1200,
        "both devices' reports must be summed, not deduplicated"
    );
}

#[tokio::test]
async fn an_account_with_no_events_gets_an_empty_result() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let response = app.send(get_stats(&session, 0, 86_400)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert!(response.body["days"]
        .as_array()
        .expect("an array")
        .is_empty());
}

#[tokio::test]
async fn an_inverted_or_too_wide_range_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let inverted = app.send(get_stats(&session, 1000, 1000)).await;
    assert_eq!(
        inverted.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        inverted.body
    );
    assert_eq!(inverted.error_code(), Some("invalid_stats_range"));

    let max_range_secs = daycompass_server::stats::aggregate::MAX_RANGE_SECS;
    let too_wide = app.send(get_stats(&session, 0, max_range_secs + 1)).await;
    assert_eq!(
        too_wide.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        too_wide.body
    );
    assert_eq!(too_wide.error_code(), Some("invalid_stats_range"));

    let exactly_the_cap = app.send(get_stats(&session, 0, max_range_secs)).await;
    assert_eq!(
        exactly_the_cap.status,
        StatusCode::OK,
        "exactly the cap must be accepted: {:?}",
        exactly_the_cap.body
    );
}

/// The core isolation property: an admin manages `bob`'s account and
/// devices, but their own session's stats must stay their own - never
/// `bob`'s screen time, and `bob` never sees the admin's either.
#[tokio::test]
async fn one_account_cannot_see_anothers_stats() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let bobs_device = app.pair_device(&bob, "bobs-laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&bobs_device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let day_start = (now / 86_400) * 86_400;

    app.send(
        TestRequest::post("/api/v1/events")
            .authenticated_as_device(&bobs_device)
            .json(json!({
                "events": [{
                    "event_id": event_id(1),
                    "start_ts": day_start + 100,
                    "duration_secs": 600,
                    "app_id": "org.example.app",
                }],
            })),
    )
    .await;

    let admins_view = app
        .send(get_stats(&admin, day_start, day_start + 86_400))
        .await;
    assert_eq!(admins_view.status, StatusCode::OK, "{:?}", admins_view.body);
    assert!(
        admins_view.body["days"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "an admin must not see another account's screen time through its own session"
    );

    let bobs_view = app
        .send(get_stats(&bob, day_start, day_start + 86_400))
        .await;
    assert_eq!(bobs_view.status, StatusCode::OK, "{:?}", bobs_view.body);
    assert_eq!(
        bobs_view.body["days"].as_array().expect("an array").len(),
        1,
        "bob must still see his own screen time through his own session"
    );
}
