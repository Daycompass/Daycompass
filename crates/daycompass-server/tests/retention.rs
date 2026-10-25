//! End-to-end tests for event retention: events ingested over HTTP,
//! the sweep run against the same database, and the account's own
//! reads checked afterwards.
//!
//! The sweep itself is driven directly rather than by waiting for the
//! hourly background task - what is under test is what it deletes, not
//! the timer.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;

use common::{TestApp, TestRequest, GOOD_ORIGIN};
use daycompass_server::auth::time::UnixTime;
use daycompass_server::events::retention::{self, RetentionPolicy};

const DAY: i64 = 86_400;

/// Old events go, recent ones stay, for every account alike - and
/// nothing that is not an event is touched.
#[tokio::test]
async fn the_sweep_deletes_old_events_and_nothing_else() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let admin_device = app.pair_device(&admin, "laptop", "linux").await;
    let bobs_device = app.pair_device(&bob, "phone", "android").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&admin_device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();

    for device in [&admin_device, &bobs_device] {
        let ingested = app
            .send(
                TestRequest::post("/api/v1/events")
                    .authenticated_as_device(device)
                    .json(json!({
                        "events": [
                            {
                                "event_id": format!("{:032x}", 1),
                                "start_ts": now - 40 * DAY,
                                "duration_secs": 60,
                                "app_id": "org.example.old",
                            },
                            {
                                "event_id": format!("{:032x}", 2),
                                "start_ts": now - DAY,
                                "duration_secs": 60,
                                "app_id": "org.example.recent",
                            },
                        ],
                    })),
            )
            .await;
        assert_eq!(ingested.body["accepted"], 2, "{:?}", ingested.body);
    }
    app.send(
        TestRequest::post("/api/v1/category-rules")
            .origin(GOOD_ORIGIN)
            .authenticated(&bob)
            .json(json!({ "kind": "app_id", "pattern": "org.example.old", "category": "Games" })),
    )
    .await;

    let policy = RetentionPolicy {
        max_age: Duration::from_secs(30 * 86_400),
    };
    let deleted = retention::sweep(&app.pool, policy, UnixTime::from_secs(now))
        .await
        .expect("the sweep must succeed");
    assert_eq!(deleted, 2, "one old event per account");
    assert_eq!(app.count_events().await, 2);
    assert_eq!(app.count_devices().await, 2, "devices are not usage data");

    let export = app
        .send(
            TestRequest::get("/api/v1/export")
                .origin(GOOD_ORIGIN)
                .authenticated(&bob),
        )
        .await;
    assert_eq!(export.status, StatusCode::OK);
    let events = export.body["events"].as_array().expect("an array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["app_id"], "org.example.recent");
    assert_eq!(export.body["category_rules"].as_array().unwrap().len(), 1);
    assert_eq!(export.body["account_log"].as_array().unwrap().len(), 1);

    // A second sweep finds nothing left to do.
    let again = retention::sweep(&app.pool, policy, UnixTime::from_secs(now))
        .await
        .expect("the sweep must succeed");
    assert_eq!(again, 0);
}
