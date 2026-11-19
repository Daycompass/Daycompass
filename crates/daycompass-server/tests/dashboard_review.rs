//! The Review page of the Missions tab: a week's numbers, the review's
//! answers and goal snapshot, next week's goals, the Markdown file, the
//! review day and Today's reminder.
//!
//! Accounts are on UTC, the default. Most tests work in the week of
//! Monday 2026-11-02, which is in the past; records with past times are
//! pushed by a device, since the dashboard only writes the present.

mod common;

use axum::http::{header, StatusCode};
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

const WEEK: &str = "?week=2026-11-04";

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

/// Unix seconds of a UTC wall-clock time.
fn ts(local: &str) -> i64 {
    let local: jiff::civil::DateTime = local.parse().unwrap();
    local
        .to_zoned(jiff::tz::TimeZone::UTC)
        .unwrap()
        .timestamp()
        .as_second()
}

async fn sync(app: &TestApp, device: &Device, body: Value) -> Value {
    let response = app
        .send(
            TestRequest::post("/api/v1/missions/sync")
                .authenticated_as_device(device)
                .json(body),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body
}

/// Mission 1, "Maths", with a 10-hour goal.
async fn maths(app: &TestApp, device: &Device) {
    let at = ts("2026-11-01T12:00:00");
    sync(
        app,
        device,
        json!({ "cursor": 0, "missions": [{
            "id": id(1), "title": "Maths", "colour": 3, "weekly_goal_secs": 36000,
            "archived": false, "deleted": false, "updated_at": at,
        }] }),
    )
    .await;
}

/// `(goals, went_well)` of the review of `week_start`.
async fn stored_review(app: &TestApp, week_start: &str) -> (String, Option<String>) {
    sqlx::query_as("SELECT goals, went_well FROM reviews WHERE week_start = ?1")
        .bind(week_start)
        .fetch_one(&app.pool)
        .await
        .expect("the review")
}

async fn goal_of(app: &TestApp, mission: &str) -> i64 {
    sqlx::query_scalar("SELECT weekly_goal_secs FROM missions WHERE id = ?1")
        .bind(mission)
        .fetch_one(&app.pool)
        .await
        .expect("the mission")
}

#[tokio::test]
async fn a_week_reads_back_its_hours_goals_and_done_tasks() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    maths(&app, &device).await;
    let at = ts("2026-11-06T12:00:00");
    sync(
        &app,
        &device,
        json!({ "cursor": 0,
            "tasks": [
                { "id": id(2), "mission_id": id(1), "title": "Exercise 4", "position": "a0",
                  "day": "2026-11-04", "done_at": ts("2026-11-04T11:00:00"),
                  "deleted": false, "updated_at": at },
                { "id": id(3), "title": "Laundry", "position": "a1",
                  "day": "2026-11-05", "deleted": false, "updated_at": at },
            ],
            "time_entries": [
                { "id": id(4), "task_id": id(2), "start_ts": ts("2026-11-04T09:00:00"),
                  "end_ts": ts("2026-11-04T11:00:00"), "deleted": false, "updated_at": at },
                { "id": id(5), "task_id": id(3), "start_ts": ts("2026-11-05T09:00:00"),
                  "end_ts": ts("2026-11-05T11:00:00"), "deleted": false, "updated_at": at },
                // Half of it in the week before: only that half is gone.
                { "id": id(6), "task_id": id(2), "start_ts": ts("2026-11-01T23:00:00"),
                  "end_ts": ts("2026-11-02T01:00:00"), "deleted": false, "updated_at": at },
            ] }),
    )
    .await;

    let text = page(&app, &format!("/missions/review{WEEK}"), &session)
        .await
        .text;
    assert!(text.contains("Week of 2 November 2026"), "{text}");
    assert!(text.contains("Wednesday 4 Nov"), "{text}");
    assert!(
        text.contains("Maths: 3h 0m of 10h 0m"),
        "actual vs goal: {text}"
    );
    assert!(
        text.contains("60%"),
        "3 of 5 tracked hours are mission hours: {text}"
    );
    assert!(text.contains("5h 0m tracked in all"), "{text}");
    assert!(text.contains("Exercise 4"), "the done list: {text}");
    assert!(text.contains("Wed 4 Nov"), "the day it was done: {text}");
    assert!(
        !text.contains("Laundry"),
        "an open task is not done: {text}"
    );
    assert!(text.contains("Today's goals"), "no review yet: {text}");
}

#[tokio::test]
async fn a_review_keeps_the_goals_it_was_measured_against() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    maths(&app, &device).await;

    let saved = ok(
        &app,
        write(&format!("/missions/review{WEEK}"), &session).form(&[
            ("went_well", "Exercises\r\nevery day"),
            ("went_badly", ""),
            ("change_next", "Start earlier"),
        ]),
    )
    .await;
    assert!(saved.text.contains("Review saved."), "{}", saved.text);
    let (goals, went_well) = stored_review(&app, "2026-11-02").await;
    assert_eq!(went_well.as_deref(), Some("Exercises\nevery day"));
    let goals: Value = serde_json::from_str(&goals).unwrap();
    assert_eq!(
        goals,
        json!([{ "mission_id": id(1), "weekly_goal_secs": 36000 }])
    );

    // Next week's goal changes the mission, not the reviewed week.
    let field = format!("goal_{}", id(1));
    ok(
        &app,
        write(&format!("/missions/review/goals{WEEK}"), &session).form(&[(field.as_str(), "5")]),
    )
    .await;
    assert_eq!(goal_of(&app, &id(1)).await, 18_000);
    let (goals, _) = stored_review(&app, "2026-11-02").await;
    assert!(goals.contains("36000"), "{goals}");
    let text = page(&app, &format!("/missions/review{WEEK}"), &session)
        .await
        .text;
    assert!(
        text.contains("of 10h 0m"),
        "the snapshot, not today's goal: {text}"
    );
    assert!(text.contains("when this week was first reviewed"), "{text}");

    // A later save of the answers keeps the snapshot too.
    ok(
        &app,
        write(&format!("/missions/review{WEEK}"), &session).form(&[("went_well", "Again")]),
    )
    .await;
    let (goals, went_well) = stored_review(&app, "2026-11-02").await;
    assert!(goals.contains("36000"), "{goals}");
    assert_eq!(went_well.as_deref(), Some("Again"));

    // A device pulls the review like any other record.
    let body = sync(&app, &device, json!({ "cursor": 0 })).await;
    assert_eq!(body["changes"]["reviews"][0]["week_start"], "2026-11-02");
    assert_eq!(body["changes"]["reviews"][0]["change_next"], Value::Null);

    let refused = app
        .send(
            write(&format!("/missions/review{WEEK}"), &session)
                .form(&[("went_well", &"x".repeat(2_001))]),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.text.contains("invalid_review"), "{}", refused.text);
}

/// Setting goals before writing any answer still takes the week's
/// snapshot first, so the week keeps the goals it had.
#[tokio::test]
async fn goals_set_before_the_answers_do_not_rewrite_the_week() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    maths(&app, &device).await;

    let field = format!("goal_{}", id(1));
    ok(
        &app,
        write(&format!("/missions/review/goals{WEEK}"), &session).form(&[(field.as_str(), "4")]),
    )
    .await;
    assert_eq!(goal_of(&app, &id(1)).await, 14_400);
    let (goals, went_well) = stored_review(&app, "2026-11-02").await;
    assert!(goals.contains("36000"), "{goals}");
    assert_eq!(went_well, None);

    let refused = app
        .send(
            write(&format!("/missions/review/goals{WEEK}"), &session)
                .form(&[(field.as_str(), "a lot")]),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_goal_for_another_accounts_mission_is_not_found() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;
    maths(&app, &device).await;
    let (_id, credentials) = app.create_account(&admin, "dave", "user").await;
    let dave = app.log_in(&credentials).await;

    let field = format!("goal_{}", id(1));
    let refused = app
        .send(write(&format!("/missions/review/goals{WEEK}"), &dave).form(&[(field.as_str(), "1")]))
        .await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND, "{}", refused.text);
    assert_eq!(goal_of(&app, &id(1)).await, 36_000);
    let reviews: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(reviews, 0);
}

#[tokio::test]
async fn the_week_downloads_as_markdown() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    maths(&app, &device).await;
    ok(
        &app,
        write(&format!("/missions/review{WEEK}"), &session)
            .form(&[("went_badly", "Too little sleep")]),
    )
    .await;

    let file = page(&app, &format!("/missions/review/markdown{WEEK}"), &session).await;
    assert_eq!(
        file.headers[header::CONTENT_TYPE],
        "text/markdown; charset=utf-8"
    );
    assert_eq!(
        file.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"daycompass-review-2026-11-02.md\""
    );
    assert!(
        file.text.starts_with("# Week of 2 November 2026\n"),
        "{}",
        file.text
    );
    assert!(file.text.contains("- Maths: 0m of 10h 0m"), "{}", file.text);
    assert!(
        file.text
            .contains("## What went badly, and why\n\nToo little sleep"),
        "{}",
        file.text
    );
}

#[tokio::test]
async fn today_asks_for_a_review_on_the_review_day_until_there_is_one() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let today = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date();
    let weekday = today.weekday().to_monday_one_offset();
    let monday = today
        .checked_sub(jiff::Span::new().days(i64::from(weekday - 1)))
        .unwrap();
    // On a Monday the week has only begun: the reminder is for the one before.
    let week = if weekday == 1 {
        monday.checked_sub(jiff::Span::new().weeks(1)).unwrap()
    } else {
        monday
    };

    let other_day = (weekday % 7 + 1).to_string();
    ok(
        &app,
        write("/account/review-day", &session).form(&[("day", other_day.as_str())]),
    )
    .await;
    let text = page(&app, "/missions/today", &session).await.text;
    assert!(!text.contains("review day"), "not the review day: {text}");

    let saved = ok(
        &app,
        write("/account/review-day", &session).form(&[("day", weekday.to_string().as_str())]),
    )
    .await;
    assert!(saved.text.contains("Review day saved."), "{}", saved.text);
    let text = page(&app, "/missions/today", &session).await.text;
    assert!(text.contains("review day"), "{text}");
    assert!(
        text.contains(&format!("/missions/review?week={week}")),
        "{text}"
    );

    ok(
        &app,
        write(&format!("/missions/review?week={week}"), &session).form(&[("went_well", "Yes")]),
    )
    .await;
    let text = page(&app, "/missions/today", &session).await.text;
    assert!(!text.contains("review day"), "the week is reviewed: {text}");

    let refused = app
        .send(write("/account/review-day", &session).form(&[("day", "8")]))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}
