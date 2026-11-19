//! Screen time on the Missions pages: the distraction during a time
//! entry (Log), in a week (Review), the category track on Today, and
//! the settings that turn it on and off.
//!
//! Accounts are on UTC, the default. The week used is the one two
//! weeks before this one, worked out at run time: old enough to be in
//! the past, young enough for the ingest window.

mod common;

use axum::http::StatusCode;
use jiff::civil::Date;
use jiff::ToSpan;
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

/// Instagram has a built-in category, `Social`.
const SOCIAL_APP: &str = "com.instagram.android";

fn write(path: &str, session: &Session) -> TestRequest {
    TestRequest::post(path)
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .htmx()
}

async fn page(app: &TestApp, path: &str, session: &Session) -> TestResponse {
    let response = app
        .send(TestRequest::get(path).cookie(&session.cookie))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.text);
    response
}

async fn ok(app: &TestApp, request: TestRequest) -> TestResponse {
    let response = app.send(request).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response
}

fn id(n: u32) -> String {
    format!("{n:032x}")
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// The Monday two weeks before this week's, UTC.
fn monday() -> Date {
    let today = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date();
    let offset = i64::from(today.weekday().to_monday_zero_offset());
    today.checked_sub((offset + 14).days()).unwrap()
}

/// Unix seconds of `hour:minute` UTC on the Wednesday of [`monday`]'s week.
fn wednesday(hour: i8, minute: i8) -> i64 {
    monday()
        .checked_add(2.days())
        .unwrap()
        .at(hour, minute, 0, 0)
        .to_zoned(jiff::tz::TimeZone::UTC)
        .unwrap()
        .timestamp()
        .as_second()
}

async fn ingest(app: &TestApp, device: &Device, events: &[(u32, i64, i64, &str)]) {
    let events: Vec<Value> = events
        .iter()
        .map(|(n, start_ts, duration_secs, app_id)| {
            json!({ "event_id": id(*n), "start_ts": start_ts, "duration_secs": duration_secs, "app_id": app_id })
        })
        .collect();
    let response = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(device)
                .json(json!({ "events": events })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(
        response.body["accepted"].as_u64(),
        Some(events.len() as u64),
        "{:?}",
        response.body
    );
}

/// A mission, a task under it, and an hour on it, 09:00 to 10:00 on
/// Wednesday: time entry 3.
async fn tracked_hour(app: &TestApp, device: &Device) {
    let at = wednesday(12, 0);
    let response = app
        .send(
            TestRequest::post("/api/v1/missions/sync")
                .authenticated_as_device(device)
                .json(json!({ "cursor": 0,
                    "missions": [{ "id": id(1), "title": "Maths", "colour": 3,
                        "weekly_goal_secs": 0, "archived": false, "deleted": false,
                        "updated_at": at }],
                    "tasks": [{ "id": id(2), "mission_id": id(1), "title": "Exercise 4",
                        "position": "a0", "deleted": false, "updated_at": at }],
                    "time_entries": [{ "id": id(3), "task_id": id(2),
                        "start_ts": wednesday(9, 0), "end_ts": wednesday(10, 0),
                        "deleted": false, "updated_at": at }] })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
}

fn log_path() -> String {
    format!("/missions/log?week={}&entry={}", monday(), id(3))
}

fn review_path() -> String {
    format!("/missions/review?week={}", monday())
}

async fn settings(app: &TestApp, session: &Session, fields: &[(&str, &str)]) -> TestResponse {
    ok(app, write("/account/screen-time", session).form(fields)).await
}

#[tokio::test]
async fn distraction_shows_once_a_category_is_marked() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let phone = app.pair_device(&session, "phone", "android").await;
    tracked_hour(&app, &phone).await;
    ingest(
        &app,
        &phone,
        &[
            // 10 minutes inside the entry, 5 outside it but in the week.
            (10, wednesday(9, 10), 600, SOCIAL_APP),
            (11, wednesday(11, 0), 300, SOCIAL_APP),
            // Uncategorized, inside the entry.
            (12, wednesday(9, 30), 600, "org.example.notes"),
            // Starts before the entry, reaches 5 minutes into it.
            (13, wednesday(8, 55), 600, SOCIAL_APP),
        ],
    )
    .await;

    let text = page(&app, &log_path(), &session).await.text;
    assert!(text.contains("Exercise 4: 1h 0m"), "{text}");
    assert!(!text.contains("distraction"), "nothing marked yet: {text}");
    let text = page(&app, &review_path(), &session).await.text;
    assert!(!text.contains("Distraction"), "nothing marked yet: {text}");

    let saved = settings(
        &app,
        &session,
        &[("enabled", "true"), ("distraction", "Social")],
    )
    .await;
    assert!(
        saved.text.contains("Screen time settings saved."),
        "{}",
        saved.text
    );
    assert!(
        saved.text.contains(r#"value="Social" checked"#),
        "{}",
        saved.text
    );

    let text = page(&app, &log_path(), &session).await.text;
    assert!(
        text.contains("Exercise 4: 1h 0m · 15m distraction"),
        "10 minutes inside, and the 5 of the earlier event that reach in: {text}"
    );
    let text = page(&app, &review_path(), &session).await.text;
    assert!(text.contains("Distraction"), "{text}");
    assert!(
        text.contains("25m"),
        "all of the week's Social time, 10 + 5 + 10: {text}"
    );

    let file = page(
        &app,
        &format!("/missions/review/markdown?week={}", monday()),
        &session,
    )
    .await;
    assert!(file.text.contains("Distraction: 25m"), "{}", file.text);
}

#[tokio::test]
async fn turned_off_the_missions_pages_show_no_screen_time() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let phone = app.pair_device(&session, "phone", "android").await;
    tracked_hour(&app, &phone).await;
    ingest(&app, &phone, &[(10, wednesday(9, 10), 600, SOCIAL_APP)]).await;
    settings(
        &app,
        &session,
        &[("enabled", "true"), ("distraction", "Social")],
    )
    .await;
    let text = page(&app, "/missions/today", &session).await.text;
    assert!(
        text.contains("dc-timeline--thin"),
        "the track is on: {text}"
    );

    // An unticked box sends nothing.
    let saved = settings(&app, &session, &[("distraction", "Social")]).await;
    assert!(
        !saved
            .text
            .contains(r#"name="enabled" value="true" checked"#),
        "{}",
        saved.text
    );
    let text = page(&app, "/missions/today", &session).await.text;
    assert!(!text.contains("dc-timeline--thin"), "{text}");
    let text = page(&app, &log_path(), &session).await.text;
    assert!(!text.contains("distraction"), "{text}");
    let text = page(&app, &review_path(), &session).await.text;
    assert!(!text.contains("Distraction"), "{text}");
}

#[tokio::test]
async fn todays_track_draws_screen_time_by_category() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let phone = app.pair_device(&session, "phone", "android").await;
    let now = now();
    // Inside today even a minute after midnight.
    let start = (now - 120).max(now - now % 86_400);
    ingest(&app, &phone, &[(10, start, 60, SOCIAL_APP)]).await;
    settings(
        &app,
        &session,
        &[("enabled", "true"), ("distraction", "Social")],
    )
    .await;

    let text = page(&app, "/missions/today", &session).await.text;
    assert!(text.contains("<title>Social (distraction), "), "{text}");
}

#[tokio::test]
async fn only_the_accounts_own_screen_time_counts() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let laptop = app.pair_device(&admin, "laptop", "linux").await;
    tracked_hour(&app, &laptop).await;

    let (_id, credentials) = app.create_account(&admin, "carol", "user").await;
    let carol = app.log_in(&credentials).await;
    let carol_phone = app.pair_device(&carol, "phone", "android").await;
    ingest(
        &app,
        &carol_phone,
        &[(10, wednesday(9, 10), 600, SOCIAL_APP)],
    )
    .await;

    // A category nothing offers is dropped, not stored.
    settings(
        &app,
        &admin,
        &[
            ("enabled", "true"),
            ("distraction", "Social"),
            ("distraction", "Nonsense"),
        ],
    )
    .await;
    let marked: Vec<String> = sqlx::query_scalar("SELECT category FROM distraction_categories")
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(marked, ["Social"]);

    let text = page(&app, &log_path(), &admin).await.text;
    assert!(
        text.contains("Exercise 4: 1h 0m · 0m distraction"),
        "carol's screen time is not the admin's: {text}"
    );
}
