//! End-to-end tests for `POST /api/v1/missions/sync` over the real
//! HTTP path: last write wins, tombstones, the one running timer, the
//! cursor, and that one account never sees another's records.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, TestResponse, GENEROUS_LIMITS, GOOD_ORIGIN};

fn id(n: u32) -> String {
    format!("{n:032x}")
}

fn mission(n: u32, title: &str, updated_at: i64) -> Value {
    json!({
        "id": id(n), "title": title, "colour": 2, "weekly_goal_secs": 3600,
        "archived": false, "deleted": false, "updated_at": updated_at,
    })
}

fn task(n: u32, mission: Option<u32>, updated_at: i64) -> Value {
    json!({
        "id": id(n), "mission_id": mission.map(id), "title": format!("task {n}"),
        "position": "a0", "deleted": false, "updated_at": updated_at,
    })
}

fn entry(n: u32, task: u32, start_ts: i64, end_ts: Option<i64>, updated_at: i64) -> Value {
    json!({
        "id": id(n), "task_id": id(task), "start_ts": start_ts, "end_ts": end_ts,
        "deleted": false, "updated_at": updated_at,
    })
}

fn review(week_start: &str, went_well: &str, goals: Value, updated_at: i64) -> Value {
    json!({
        "week_start": week_start, "went_well": went_well, "goals": goals,
        "deleted": false, "updated_at": updated_at,
    })
}

/// The review of `week_start` in this response's changes.
fn changed_review<'a>(body: &'a Value, week_start: &str) -> &'a Value {
    body["changes"]["reviews"]
        .as_array()
        .expect("changes")
        .iter()
        .find(|r| r["week_start"] == week_start)
        .unwrap_or_else(|| panic!("{week_start} not in review changes: {body:?}"))
}

/// One sync, which must succeed.
async fn sync(app: &TestApp, device: &Device, body: Value) -> Value {
    let response = send_sync(app, device, body).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body
}

async fn send_sync(app: &TestApp, device: &Device, body: Value) -> TestResponse {
    app.send(
        TestRequest::post("/api/v1/missions/sync")
            .authenticated_as_device(device)
            .json(body),
    )
    .await
}

fn statuses(body: &Value, kind: &str) -> Vec<String> {
    body["results"][kind]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| match r["reason"].as_str() {
            Some(reason) => format!("rejected:{reason}"),
            None => r["status"].as_str().unwrap().to_owned(),
        })
        .collect()
}

/// The record with `id` in this response's changes.
fn changed<'a>(body: &'a Value, kind: &str, record: &str) -> &'a Value {
    body["changes"][kind]
        .as_array()
        .expect("changes")
        .iter()
        .find(|r| r["id"] == record)
        .unwrap_or_else(|| panic!("{record} not in {kind} changes: {body:?}"))
}

async fn server_time(app: &TestApp, device: &Device) -> i64 {
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(device))
        .await;
    me.body["server_time"].as_i64().expect("a server time")
}

/// An account with two paired devices, and the admin who made it.
async fn two_devices(app: &TestApp) -> (Session, String, Device, Device) {
    let (_, admin) = app.provisioned_admin().await;
    let (carol_id, credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&credentials).await;
    let laptop = app.pair_device(&carol, "laptop", "linux").await;
    let phone = app.pair_device(&carol, "phone", "android").await;
    (admin, carol_id, laptop, phone)
}

#[tokio::test]
async fn the_newer_edit_wins_whichever_arrives_first() {
    let app = TestApp::new().await;
    let (_, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    let body = sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [mission(1, "laptop", now - 100)] }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);
    let laptop_cursor = body["cursor"].as_i64().unwrap();

    // The phone edited offline, earlier, and only now reaches the
    // server. It loses, and is handed the winner in the same response.
    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0, "missions": [mission(1, "phone", now - 200)] }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["stale"]);
    assert_eq!(changed(&body, "missions", &id(1))["title"], "laptop");

    // The stale push changed nothing, so the laptop's next pull has no
    // other title to tell it about.
    let body = sync(&app, &laptop, json!({ "cursor": laptop_cursor })).await;
    for m in body["changes"]["missions"].as_array().unwrap() {
        assert_eq!(m["title"], "laptop");
    }
}

#[tokio::test]
async fn on_equal_updated_at_the_later_push_wins() {
    let app = TestApp::new().await;
    let (_, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [mission(1, "first", now)] }),
    )
    .await;
    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0, "missions": [mission(1, "second", now)] }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);

    let body = sync(&app, &laptop, json!({ "cursor": 0 })).await;
    assert_eq!(changed(&body, "missions", &id(1))["title"], "second");
}

/// A second device that was offline creates a mission, a task under it
/// and time on that task, all in one push; the first device pulls all
/// three in order.
#[tokio::test]
async fn offline_work_on_a_second_device_arrives_whole() {
    let app = TestApp::new().await;
    let (_, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    let first = sync(&app, &laptop, json!({ "cursor": 0 })).await;
    let cursor = first["cursor"].as_i64().unwrap();

    let body = sync(
        &app,
        &phone,
        json!({
            "cursor": 0,
            // Listed child first: the server applies missions, then
            // tasks, then entries, whatever order the arrays arrive in.
            "time_entries": [entry(3, 2, now - 3_600, Some(now - 1_800), now - 1_800)],
            "tasks": [task(2, Some(1), now - 3_600)],
            "missions": [mission(1, "Maths", now - 3_700)],
        }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);
    assert_eq!(statuses(&body, "tasks"), ["applied"]);
    assert_eq!(statuses(&body, "time_entries"), ["applied"]);

    let body = sync(&app, &laptop, json!({ "cursor": cursor })).await;
    assert_eq!(changed(&body, "missions", &id(1))["title"], "Maths");
    assert_eq!(changed(&body, "tasks", &id(2))["mission_id"], id(1));
    assert_eq!(
        changed(&body, "time_entries", &id(3))["end_ts"],
        now - 1_800
    );
    assert_eq!(body["has_more"], false);
}

#[tokio::test]
async fn a_bad_record_is_refused_alone() {
    let app = TestApp::new().await;
    let (_, _, laptop, _) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    let body = sync(
        &app,
        &laptop,
        json!({
            "cursor": 0,
            "missions": [mission(1, "ok", now), mission(2, " ", now)],
            "tasks": [task(3, Some(99), now), task(4, None, now)],
            "time_entries": [entry(5, 98, now - 60, Some(now), now), entry(6, 4, now - 60, Some(now - 60), now)],
        }),
    )
    .await;
    assert_eq!(
        statuses(&body, "missions"),
        ["applied", "rejected:title_length"]
    );
    assert_eq!(
        statuses(&body, "tasks"),
        ["rejected:mission_unknown", "applied"]
    );
    assert_eq!(
        statuses(&body, "time_entries"),
        ["rejected:task_unknown", "rejected:end_ts_not_after_start"]
    );
}

#[tokio::test]
async fn a_tombstone_reaches_other_devices_and_keeps_no_text() {
    let app = TestApp::new().await;
    let (_, carol_id, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    let mut m = mission(1, "Private title", now - 100);
    m["why"] = json!("a private reason");
    sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [m.clone()] }),
    )
    .await;
    let cursor = sync(&app, &phone, json!({ "cursor": 0 })).await["cursor"]
        .as_i64()
        .unwrap();

    m["deleted"] = json!(true);
    m["updated_at"] = json!(now - 50);
    let body = sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [m.clone()] }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);

    let body = sync(&app, &phone, json!({ "cursor": cursor })).await;
    let tombstone = changed(&body, "missions", &id(1));
    assert_eq!(tombstone["deleted"], true);
    assert_eq!(tombstone["title"], "");
    assert_eq!(tombstone["why"], Value::Null);

    let (title, why): (String, Option<String>) =
        sqlx::query_as("SELECT title, why FROM missions WHERE user_id = ?1")
            .bind(&carol_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!((title.as_str(), why), ("", None), "the words are gone");

    // An older edit made before the delete does not bring it back.
    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0, "missions": [mission(1, "revived", now - 75)] }),
    )
    .await;
    assert_eq!(statuses(&body, "missions"), ["stale"]);

    // The tombstone, sent back exactly as received, is accepted.
    let echo = changed(&body, "missions", &id(1)).clone();
    let body = sync(&app, &phone, json!({ "cursor": 0, "missions": [echo] })).await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);

    // A tombstone for something the server never had stores nothing.
    let mut never = mission(7, "x", now);
    never["deleted"] = json!(true);
    let body = sync(&app, &phone, json!({ "cursor": 0, "missions": [never] })).await;
    assert_eq!(statuses(&body, "missions"), ["applied"]);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM missions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

async fn running_count(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM time_entries WHERE end_ts IS NULL AND deleted = 0")
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_timer_started_on_the_phone_stops_the_one_on_the_laptop() {
    let app = TestApp::new().await;
    let (_, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "tasks": [task(1, None, now - 900)],
        "time_entries": [entry(10, 1, now - 600, None, now - 600)] }),
    )
    .await;
    let cursor = sync(&app, &laptop, json!({ "cursor": 0 })).await["cursor"]
        .as_i64()
        .unwrap();

    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0,
        "time_entries": [entry(11, 1, now - 60, None, now - 60)] }),
    )
    .await;
    assert_eq!(statuses(&body, "time_entries"), ["applied"]);
    assert_eq!(changed(&body, "time_entries", &id(10))["end_ts"], now - 60);
    assert_eq!(running_count(&app).await, 1);

    // The laptop learns its timer was stopped.
    let body = sync(&app, &laptop, json!({ "cursor": cursor })).await;
    assert_eq!(changed(&body, "time_entries", &id(10))["end_ts"], now - 60);
    assert_eq!(
        changed(&body, "time_entries", &id(11))["end_ts"],
        Value::Null
    );

    // An older start that reaches the server late is ended at the
    // newer one's start rather than ending it.
    let body = sync(
        &app,
        &laptop,
        json!({ "cursor": 0,
        "time_entries": [entry(12, 1, now - 300, None, now - 300)] }),
    )
    .await;
    assert_eq!(statuses(&body, "time_entries"), ["applied"]);
    assert_eq!(changed(&body, "time_entries", &id(12))["end_ts"], now - 60);
    assert_eq!(
        changed(&body, "time_entries", &id(11))["end_ts"],
        Value::Null
    );
    assert_eq!(running_count(&app).await, 1);
}

#[tokio::test]
async fn one_account_never_sees_or_references_anothers_records() {
    let app = TestApp::new().await;
    let (admin, _, carol_device, _) = two_devices(&app).await;
    let (_, credentials) = app.create_account(&admin, "dave", "user").await;
    let dave = app.log_in(&credentials).await;
    let dave_device = app.pair_device(&dave, "tablet", "android").await;
    let now = server_time(&app, &carol_device).await;

    sync(
        &app,
        &carol_device,
        json!({ "cursor": 0, "missions": [mission(1, "carol's", now)] }),
    )
    .await;

    // Dave cannot hang a task off Carol's mission...
    let body = sync(
        &app,
        &dave_device,
        json!({ "cursor": 0, "tasks": [task(2, Some(1), now)] }),
    )
    .await;
    assert_eq!(statuses(&body, "tasks"), ["rejected:mission_unknown"]);
    assert_eq!(
        body["changes"]["missions"],
        json!([]),
        "and sees none of hers"
    );

    // ...and his own record with the same id is a different record.
    sync(
        &app,
        &dave_device,
        json!({ "cursor": 0, "missions": [mission(1, "dave's", now)] }),
    )
    .await;
    let body = sync(&app, &carol_device, json!({ "cursor": 0 })).await;
    assert_eq!(changed(&body, "missions", &id(1))["title"], "carol's");
}

#[tokio::test]
async fn a_large_history_comes_in_pages_and_the_cursor_is_checked() {
    let app = TestApp::new().await;
    let (_, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;

    let missions: Vec<Value> = (0..400).map(|n| mission(n, "m", now)).collect();
    sync(&app, &laptop, json!({ "cursor": 0, "missions": missions })).await;
    let tasks: Vec<Value> = (1_000..1_200)
        .map(|n| task(n, Some(n - 1_000), now))
        .collect();
    sync(&app, &laptop, json!({ "cursor": 0, "tasks": tasks })).await;

    let mut seen = HashSet::new();
    let mut cursor = 0;
    let mut pages = 0;
    loop {
        let body = sync(&app, &phone, json!({ "cursor": cursor })).await;
        for kind in ["missions", "tasks", "time_entries"] {
            for record in body["changes"][kind].as_array().unwrap() {
                assert!(
                    seen.insert(record["id"].as_str().unwrap().to_owned()),
                    "a repeat"
                );
            }
        }
        cursor = body["cursor"].as_i64().unwrap();
        pages += 1;
        if body["has_more"] == false {
            break;
        }
    }
    assert_eq!((seen.len(), pages), (600, 2));

    // Up to date: nothing more, same cursor.
    let body = sync(&app, &phone, json!({ "cursor": cursor })).await;
    assert_eq!(body["cursor"], cursor);
    assert_eq!(body["changes"]["missions"], json!([]));

    for bad in [-1, cursor + 1] {
        let response = send_sync(&app, &phone, json!({ "cursor": bad })).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.error_code(), Some("invalid_sync_cursor"));
    }

    let too_many: Vec<Value> = (0..501).map(|n| mission(n, "m", now)).collect();
    let response = send_sync(&app, &phone, json!({ "cursor": 0, "missions": too_many })).await;
    assert_eq!(response.error_code(), Some("batch_too_large"));
}

/// Its own bucket: a client that hits the sync limit can still report
/// screen time.
#[tokio::test]
async fn the_sync_limit_is_its_own_bucket() {
    let mut vars = GENEROUS_LIMITS.to_vec();
    vars.push(("DAYCOMPASS_RATE_LIMIT_MISSIONS_SYNC_DEVICE", "2/60"));
    let app = TestApp::with_vars(&vars).await;
    let (_, _, laptop, _) = two_devices(&app).await;

    for _ in 0..2 {
        sync(&app, &laptop, json!({ "cursor": 0 })).await;
    }
    let refused = send_sync(&app, &laptop, json!({ "cursor": 0 })).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.retry_after().is_some());

    let ingest = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&laptop)
                .json(json!({ "events": [] })),
        )
        .await;
    assert_eq!(ingest.status, StatusCode::OK);
}

#[tokio::test]
async fn deleting_the_account_deletes_its_missions_and_export_carries_them() {
    let app = TestApp::new().await;
    let (_, admin) = app.provisioned_admin().await;
    let (carol_id, credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&credentials).await;
    let laptop = app.pair_device(&carol, "laptop", "linux").await;
    let now = server_time(&app, &laptop).await;

    let mut gone = mission(2, "deleted", now);
    sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [mission(1, "Maths", now), gone.clone()],
        "tasks": [task(3, Some(1), now)],
        "time_entries": [entry(4, 3, now - 60, None, now)],
        "reviews": [review("2026-11-16", "Exercises", json!([]), now)] }),
    )
    .await;
    gone["deleted"] = json!(true);
    sync(&app, &laptop, json!({ "cursor": 0, "missions": [gone] })).await;

    let export = app
        .send(
            TestRequest::get("/api/v1/export")
                .origin(GOOD_ORIGIN)
                .authenticated(&carol),
        )
        .await;
    assert_eq!(export.status, StatusCode::OK);
    let missions = export.body["missions"].as_array().unwrap();
    assert_eq!(missions.len(), 1, "no tombstones in an export");
    assert_eq!(missions[0]["title"], "Maths");
    assert_eq!(export.body["tasks"][0]["mission_id"], id(1));
    assert_eq!(export.body["time_entries"][0]["end_ts"], Value::Null);
    assert_eq!(export.body["reviews"][0]["week_start"], "2026-11-16");
    assert_eq!(export.body["reviews"][0]["went_well"], "Exercises");

    let deleted = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{carol_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    for sql in [
        "SELECT COUNT(*) FROM missions",
        "SELECT COUNT(*) FROM tasks",
        "SELECT COUNT(*) FROM time_entries",
        "SELECT COUNT(*) FROM reviews",
    ] {
        let count: i64 = sqlx::query_scalar(sql).fetch_one(&app.pool).await.unwrap();
        assert_eq!(count, 0, "{sql}");
    }
}

/// A review is keyed by its week: two devices reviewing the same week
/// write one record, the newer edit wins, a delete takes the text, and
/// its goals may name only the account's own missions.
#[tokio::test]
async fn a_week_has_one_review_whichever_device_writes_it() {
    let app = TestApp::new().await;
    let (admin, _, laptop, phone) = two_devices(&app).await;
    let now = server_time(&app, &laptop).await;
    let goals = json!([{ "mission_id": id(1), "weekly_goal_secs": 36000 }]);

    let body = sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "missions": [mission(1, "Maths", now)],
                "reviews": [review("2026-11-16", "laptop", goals.clone(), now - 10)] }),
    )
    .await;
    assert_eq!(statuses(&body, "reviews"), ["applied"]);

    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0, "reviews": [review("2026-11-16", "phone", json!([]), now - 20)] }),
    )
    .await;
    assert_eq!(statuses(&body, "reviews"), ["stale"]);
    let winner = changed_review(&body, "2026-11-16");
    assert_eq!(winner["went_well"], "laptop");
    assert_eq!(winner["goals"], goals);

    let body = sync(
        &app,
        &phone,
        json!({ "cursor": 0, "reviews": [review("2026-11-16", "phone", goals.clone(), now)] }),
    )
    .await;
    assert_eq!(statuses(&body, "reviews"), ["applied"]);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "one week, one review");

    let mut gone = review("2026-11-16", "phone", goals, now);
    gone["deleted"] = json!(true);
    sync(&app, &phone, json!({ "cursor": 0, "reviews": [gone] })).await;
    let body = sync(&app, &laptop, json!({ "cursor": 0 })).await;
    let tombstone = changed_review(&body, "2026-11-16");
    assert_eq!(tombstone["deleted"], true);
    assert_eq!(
        tombstone["went_well"],
        Value::Null,
        "a tombstone keeps no text"
    );

    let body = sync(
        &app,
        &laptop,
        json!({ "cursor": 0, "reviews": [
            review("2026-11-17", "", json!([]), now),
            review("2026-11-23", "", json!([{ "mission_id": id(9), "weekly_goal_secs": 0 }]), now),
            review("2026-11-30", "", json!([
                { "mission_id": id(1), "weekly_goal_secs": 0 },
                { "mission_id": id(1), "weekly_goal_secs": 60 },
            ]), now),
        ] }),
    )
    .await;
    assert_eq!(
        statuses(&body, "reviews"),
        [
            "rejected:week_start_not_monday",
            "rejected:mission_unknown",
            "rejected:goals_malformed",
        ]
    );

    // Another account's mission is no mission of this one.
    let (_, credentials) = app.create_account(&admin, "dave", "user").await;
    let dave = app.log_in(&credentials).await;
    let dave_device = app.pair_device(&dave, "tablet", "android").await;
    let body = sync(
        &app,
        &dave_device,
        json!({ "cursor": 0, "reviews": [review("2026-11-16", "dave",
            json!([{ "mission_id": id(1), "weekly_goal_secs": 0 }]), now)] }),
    )
    .await;
    assert_eq!(statuses(&body, "reviews"), ["rejected:mission_unknown"]);
    assert_eq!(
        body["changes"]["reviews"],
        json!([]),
        "and sees none of carol's"
    );
}
