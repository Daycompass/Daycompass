//! End-to-end tests for `GET /api/v1/export`: an account's whole data
//! as one streamed JSON document, over the real HTTP path.
//!
//! The property worth the most attention is the one every owner-scoped
//! route here is tested for - one account's data never appears in
//! another account's export, an admin's included. The second is the
//! paging: an export spanning several pages must carry every event
//! exactly once and end in the `complete` marker.

mod common;

use std::collections::HashSet;

use axum::http::{header, StatusCode};
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, GENEROUS_LIMITS, GOOD_ORIGIN};
use daycompass_server::export::service::PAGE_ROWS;

fn get_export(session: &Session) -> TestRequest {
    TestRequest::get("/api/v1/export")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
}

fn event_id(n: u32) -> String {
    format!("{n:032x}")
}

/// The server's clock, read through the device route, so events land
/// inside the accepted window without the test guessing at it.
async fn server_time(app: &TestApp, device: &Device) -> i64 {
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(device))
        .await;
    me.body["server_time"].as_i64().expect("a server time")
}

/// Ingests `count` events numbered from `first`, in batches the ingest
/// cap accepts, each a second apart and ending well before `now`.
async fn ingest(app: &TestApp, device: &Device, first: u32, count: u32, now: i64, app_id: &str) {
    let ids: Vec<u32> = (first..first + count).collect();
    for batch in ids.chunks(500) {
        let events: Vec<Value> = batch
            .iter()
            .map(|n| {
                json!({
                    "event_id": event_id(*n),
                    "start_ts": now - 86_400 + i64::from(*n),
                    "duration_secs": 30,
                    "app_id": app_id,
                })
            })
            .collect();
        let response = app
            .send(
                TestRequest::post("/api/v1/events")
                    .authenticated_as_device(device)
                    .json(json!({ "events": events })),
            )
            .await;
        assert_eq!(
            response.body["accepted"].as_u64(),
            Some(batch.len() as u64),
            "{:?}",
            response.body
        );
    }
}

#[tokio::test]
async fn an_export_carries_the_accounts_own_data_and_nobody_elses() {
    let app = TestApp::new().await;
    let (_admin_credentials, admin) = app.provisioned_admin().await;
    let (carol_id, carol_credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&carol_credentials).await;
    let (_dave_id, dave_credentials) = app.create_account(&admin, "dave", "user").await;
    let dave = app.log_in(&dave_credentials).await;

    let carol_device = app.pair_device(&carol, "laptop", "linux").await;
    let dave_device = app.pair_device(&dave, "phone", "android").await;
    let now = server_time(&app, &carol_device).await;
    ingest(&app, &carol_device, 0, 3, now, "org.example.carol").await;
    ingest(&app, &dave_device, 0, 4, now, "org.example.dave").await;

    let rule = app
        .send(
            TestRequest::post("/api/v1/category-rules")
                .origin(GOOD_ORIGIN)
                .authenticated(&carol)
                .json(json!({ "kind": "app_id", "pattern": "org.example.carol", "category": "Study" })),
        )
        .await;
    assert_eq!(rule.status, StatusCode::CREATED, "{:?}", rule.body);

    let response = app.send(get_export(&carol)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    let doc = &response.body;

    assert_eq!(doc["format"], "daycompass-export");
    assert_eq!(doc["format_version"], 1);
    assert_eq!(doc["complete"], true);
    assert_eq!(doc["account"]["id"], carol_id.as_str());
    assert_eq!(doc["account"]["username"], "carol");
    assert_eq!(doc["account"]["role"], "user");

    let devices = doc["devices"].as_array().expect("a devices array");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["id"], carol_device.id.as_str());

    let rules = doc["category_rules"].as_array().expect("a rules array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["category"], "Study");

    let log = doc["account_log"].as_array().expect("a log array");
    assert_eq!(log.len(), 1, "carol redeemed one invite: {log:?}");
    assert_eq!(log[0]["kind"], "invite_redeemed");

    let events = doc["events"].as_array().expect("an events array");
    assert_eq!(events.len(), 3);
    for event in events {
        assert_eq!(event["device_id"], carol_device.id.as_str());
        assert_eq!(event["app_id"], "org.example.carol");
        assert!(
            event.get("category").is_none(),
            "events are exported raw, without a category: {event:?}"
        );
    }
}

/// An admin's export is the admin's own, like every other owner read:
/// no other account's events or devices, however many it manages.
#[tokio::test]
async fn an_admins_export_holds_only_the_admins_own_data() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_carol_id, carol_credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&carol_credentials).await;
    let carol_device = app.pair_device(&carol, "laptop", "linux").await;
    let now = server_time(&app, &carol_device).await;
    ingest(&app, &carol_device, 0, 5, now, "org.example.carol").await;

    let response = app.send(get_export(&admin)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(response.body["account"]["role"], "admin");
    assert_eq!(response.body["devices"], json!([]));
    assert_eq!(response.body["events"], json!([]));
    assert_eq!(response.body["complete"], true);
    assert!(
        !response.body.to_string().contains(&carol_device.id),
        "another account's device leaked into the admin's export"
    );
}

/// More events than one page holds, several of them sharing a
/// `start_ts` across two devices: each comes back once, in order.
#[tokio::test]
async fn an_export_spanning_several_pages_has_every_event_once() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let laptop = app.pair_device(&session, "laptop", "linux").await;
    let phone = app.pair_device(&session, "phone", "android").await;
    let now = server_time(&app, &laptop).await;

    let per_device = u32::try_from(PAGE_ROWS).unwrap() + 250;
    ingest(&app, &laptop, 0, per_device, now, "org.example.app").await;
    ingest(&app, &phone, 0, per_device, now, "org.example.app").await;

    let response = app.send(get_export(&session)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["complete"], true);

    let events = response.body["events"].as_array().expect("an events array");
    assert_eq!(events.len(), 2 * per_device as usize);

    let keys: Vec<(i64, String, String)> = events
        .iter()
        .map(|event| {
            (
                event["start_ts"].as_i64().unwrap(),
                event["device_id"].as_str().unwrap().to_owned(),
                event["event_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let unique: HashSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "an event was exported twice");
    assert!(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "out of order"
    );
}

/// An exact multiple of the page size ends in an empty page, which is
/// the one case where the tail goes out on its own.
#[tokio::test]
async fn an_export_of_exactly_one_full_page_is_still_complete() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    let now = server_time(&app, &device).await;
    ingest(
        &app,
        &device,
        0,
        u32::try_from(PAGE_ROWS).unwrap(),
        now,
        "org.example.app",
    )
    .await;

    let response = app.send(get_export(&session)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["complete"], true);
    assert_eq!(
        response.body["events"].as_array().unwrap().len(),
        PAGE_ROWS as usize
    );
}

#[tokio::test]
async fn an_export_is_a_download_and_never_cached() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let response = app.send(get_export(&session)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(
        response.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"daycompass-export.json\""
    );
    assert_eq!(response.headers[header::CACHE_CONTROL], "no-store");
}

/// Nothing secret, at any depth: the document is scanned as text, keys
/// and values alike, so a hash added to any section later fails here.
#[tokio::test]
async fn an_export_carries_no_secret_material() {
    let app = TestApp::new().await;
    let (credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    let now = server_time(&app, &device).await;
    ingest(&app, &device, 0, 2, now, "org.example.app").await;

    let response = app.send(get_export(&session)).await;
    let text = response.body.to_string();
    for marker in ["hash", "token", "password", "secret", "cookie", "csrf"] {
        assert!(
            !text.contains(marker),
            "the export mentions {marker:?}: {text}"
        );
    }
    assert!(!text.contains(&credentials.password));
    assert!(!text.contains(&device.token));
    assert!(!text.contains(&session.csrf_token));
}

#[tokio::test]
async fn an_export_needs_a_session() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let anonymous = app
        .send(TestRequest::get("/api/v1/export").origin(GOOD_ORIGIN))
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let as_device = app
        .send(
            TestRequest::get("/api/v1/export")
                .origin(GOOD_ORIGIN)
                .authenticated_as_device(&device),
        )
        .await;
    assert_eq!(as_device.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn exports_are_rate_limited_per_session() {
    let mut vars: Vec<(&str, &str)> = GENEROUS_LIMITS
        .iter()
        .copied()
        .filter(|(name, _)| *name != "DAYCOMPASS_RATE_LIMIT_EXPORT")
        .collect();
    vars.push(("DAYCOMPASS_RATE_LIMIT_EXPORT", "3/3600"));
    let app = TestApp::with_vars(&vars).await;
    let (credentials, first) = app.provisioned_admin().await;

    for _ in 0..3 {
        let response = app.send(get_export(&first)).await;
        assert_eq!(response.status, StatusCode::OK);
    }
    let refused = app.send(get_export(&first)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.error_code(), Some("rate_limited"));
    assert!(
        refused.retry_after().is_some(),
        "a 429 must say when to retry"
    );

    // Per session, not per account: a fresh login has its own budget.
    let second = app.log_in(&credentials).await;
    let response = app.send(get_export(&second)).await;
    assert_eq!(response.status, StatusCode::OK);
}

/// No parameter can point the export anywhere: an unknown one is
/// refused rather than ignored, so a client trying `user_id` finds out.
#[tokio::test]
async fn an_export_refuses_query_parameters() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let response = app
        .send(
            TestRequest::get("/api/v1/export?user_id=0190a0b2-0000-7000-8000-000000000001")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.error_code(), Some("bad_request"));
}
