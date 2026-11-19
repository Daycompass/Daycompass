//! The Log page of the Missions tab: a week of tracked time, adding
//! time by hand, correcting, deleting and stopping an entry, and what
//! the page refuses.
//!
//! Writes go through the sync service, like Today's, so a device pulls
//! them. Accounts are on UTC, the default; most tests work in the week
//! of Wednesday 2026-11-04, which is in the past.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

const WEEK: &str = "/missions/log?week=2026-11-04";

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

/// Unix seconds of a UTC wall-clock time.
fn ts(local: &str) -> i64 {
    let local: jiff::civil::DateTime = local.parse().unwrap();
    local
        .to_zoned(jiff::tz::TimeZone::UTC)
        .unwrap()
        .timestamp()
        .as_second()
}

/// A form value `secs` from now, UTC.
fn from_now(secs: i64) -> String {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() + secs)
        .unwrap()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

/// Adds a task for today and returns its id.
async fn task(app: &TestApp, session: &Session, title: &str) -> String {
    ok(
        app,
        write("/missions/today/tasks", session).form(&[("title", title)]),
    )
    .await;
    sqlx::query_scalar("SELECT id FROM tasks WHERE title = ?1")
        .bind(title)
        .fetch_one(&app.pool)
        .await
        .expect("the task")
}

async fn add_time(
    app: &TestApp,
    session: &Session,
    task: &str,
    start: &str,
    end: &str,
) -> TestResponse {
    app.send(
        write("/missions/log/entries?week=2026-11-02", session).form(&[
            ("task", task),
            ("start", start),
            ("end", end),
        ]),
    )
    .await
}

/// The one entry's id.
async fn entry_id(app: &TestApp) -> String {
    sqlx::query_scalar("SELECT id FROM time_entries")
        .fetch_one(&app.pool)
        .await
        .expect("one entry")
}

/// `(task_id, start_ts, end_ts, deleted)` of an entry.
async fn entry(app: &TestApp, id: &str) -> (String, i64, Option<i64>, bool) {
    sqlx::query_as("SELECT task_id, start_ts, end_ts, deleted FROM time_entries WHERE id = ?1")
        .bind(id)
        .fetch_one(&app.pool)
        .await
        .expect("the entry")
}

#[tokio::test]
async fn time_added_by_hand_shows_on_its_day_and_a_device_pulls_it() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;
    let reading = task(&app, &admin, "Reading").await;

    let added = add_time(
        &app,
        &admin,
        &reading,
        "2026-11-04T09:00:00",
        "2026-11-04T10:30",
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    assert!(added.text.contains(r#"<div id="log""#));
    assert!(added.text.contains(r#"id="dc-timer" hx-swap-oob="true""#));
    let id = entry_id(&app).await;
    assert_eq!(
        entry(&app, &id).await,
        (
            reading.clone(),
            ts("2026-11-04T09:00:00"),
            Some(ts("2026-11-04T10:30:00")),
            false
        )
    );

    let text = page(&app, WEEK, &admin).await.text;
    assert!(text.contains(r#"href="/missions/log" aria-current="page">Log"#));
    assert!(text.contains("November 2026"));
    assert!(text.contains("Tracked this week: 1h 30m"));
    assert!(text.contains(r#"aria-label="Wednesday 4 Nov: 1h 30m""#));
    assert!(text.contains(r#"aria-label="Thursday 5 Nov: 0m""#));
    // 09:00 is minute 540 of the day.
    assert!(text.contains(&format!(
        r#"<a href="/missions/log?week=2026-11-02&amp;entry={id}#log-editor" aria-label="Reading, 09:00 to 10:30, 1h 30m"><rect class="dc-fill--neutral" x="540.00""#
    )));
    assert!(
        !text.contains("log-editor\" class"),
        "no editor until one is picked"
    );

    let pulled = app
        .send(
            TestRequest::post("/api/v1/missions/sync")
                .authenticated_as_device(&device)
                .json(json!({ "cursor": 0 })),
        )
        .await
        .body;
    assert_eq!(pulled["changes"]["time_entries"][0]["id"], json!(id));
    assert_eq!(
        pulled["changes"]["time_entries"][0]["end_ts"],
        json!(ts("2026-11-04T10:30:00"))
    );
}

#[tokio::test]
async fn an_entry_can_be_corrected_onto_other_times_and_another_task() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let reading = task(&app, &admin, "Reading").await;
    let writing = task(&app, &admin, "Writing").await;
    add_time(
        &app,
        &admin,
        &reading,
        "2026-11-04T09:00:00",
        "2026-11-04T10:00:00",
    )
    .await;
    let id = entry_id(&app).await;

    let editor = page(&app, &format!("{WEEK}&entry={id}"), &admin).await.text;
    assert!(editor.contains(r#"id="log-editor""#));
    assert!(editor.contains(r#"value="2026-11-04T09:00:00""#));
    assert!(editor.contains(r#"value="2026-11-04T10:00:00""#));
    assert!(editor.contains(&format!(
        r#"<option value="{reading}" selected>Reading</option>"#
    )));
    assert!(editor.contains("dc-timeline__picked"));

    // Across midnight, onto the other task.
    let saved = ok(
        &app,
        write(
            &format!("/missions/log/entries/{id}?week=2026-11-04"),
            &admin,
        )
        .form(&[
            ("task", writing.as_str()),
            ("start", "2026-11-04T23:30:00"),
            ("end", "2026-11-05T00:15:00"),
        ]),
    )
    .await;
    assert!(
        !saved.text.contains(r#"id="log-editor""#),
        "the editor closes"
    );
    assert!(saved.text.contains(r#"aria-label="Wednesday 4 Nov: 30m""#));
    assert!(saved.text.contains(r#"aria-label="Thursday 5 Nov: 15m""#));
    assert_eq!(
        entry(&app, &id).await,
        (
            writing,
            ts("2026-11-04T23:30:00"),
            Some(ts("2026-11-05T00:15:00")),
            false
        )
    );
}

#[tokio::test]
async fn time_in_the_future_or_out_of_order_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let reading = task(&app, &admin, "Reading").await;

    let past = from_now(-3600);
    let future = from_now(3600);
    for (start, end) in [
        ("2026-11-04T10:00:00", "2026-11-04T10:00:00"),
        ("2026-11-04T10:00:00", "2026-11-04T09:00:00"),
        (past.as_str(), future.as_str()),
        (future.as_str(), future.as_str()),
        ("yesterday", "2026-11-04T09:00:00"),
        ("2026-11-04T10:00:00", ""),
    ] {
        let response = add_time(&app, &admin, &reading, start, end).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{start} {end}");
        assert!(response.text.contains("invalid_time_entry"));
    }
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM time_entries")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    // A correction obeys the same rules.
    add_time(
        &app,
        &admin,
        &reading,
        "2026-11-04T09:00:00",
        "2026-11-04T10:00:00",
    )
    .await;
    let id = entry_id(&app).await;
    let response = app
        .send(
            write(&format!("/missions/log/entries/{id}"), &admin).form(&[
                ("task", reading.as_str()),
                ("start", "2026-11-04T09:00:00"),
                ("end", future.as_str()),
            ]),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(entry(&app, &id).await.2, Some(ts("2026-11-04T10:00:00")));
}

#[tokio::test]
async fn a_running_entry_can_only_be_stopped() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let reading = task(&app, &admin, "Reading").await;
    ok(
        &app,
        write(&format!("/missions/tasks/{reading}/start"), &admin),
    )
    .await;
    let id = entry_id(&app).await;

    let text = page(&app, &format!("/missions/log?entry={id}"), &admin)
        .await
        .text;
    assert!(text.contains("This time is still being tracked."));
    assert!(text.contains(&format!(r#"hx-post="/missions/log/entries/{id}/stop"#)));
    assert!(
        text.contains("dc-timeline__now"),
        "this week has today's row"
    );

    let past = from_now(-3600);
    for request in [
        write(&format!("/missions/log/entries/{id}"), &admin).form(&[
            ("task", reading.as_str()),
            ("start", past.as_str()),
            ("end", past.as_str()),
        ]),
        write(&format!("/missions/log/entries/{id}/delete"), &admin),
    ] {
        let response = app.send(request).await;
        assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text);
        assert!(response.text.contains("time_entry_running"));
    }
    assert_eq!(entry(&app, &id).await.2, None);

    let stopped = ok(
        &app,
        write(&format!("/missions/log/entries/{id}/stop"), &admin),
    )
    .await;
    assert!(entry(&app, &id).await.2.is_some());
    assert!(stopped
        .text
        .contains(r#"<div id="dc-timer" hx-swap-oob="true"></div>"#));
    // Stopping a stopped entry changes nothing and is no error.
    ok(
        &app,
        write(&format!("/missions/log/entries/{id}/stop"), &admin),
    )
    .await;
}

#[tokio::test]
async fn a_deleted_entry_leaves_the_week() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let reading = task(&app, &admin, "Reading").await;
    add_time(
        &app,
        &admin,
        &reading,
        "2026-11-04T09:00:00",
        "2026-11-04T10:00:00",
    )
    .await;
    let id = entry_id(&app).await;

    let answer = ok(
        &app,
        write(
            &format!("/missions/log/entries/{id}/delete?week=2026-11-04"),
            &admin,
        ),
    )
    .await;
    assert!(answer.text.contains("Tracked this week: 0m"));
    assert!(entry(&app, &id).await.3);
    let text = page(&app, &format!("{WEEK}&entry={id}"), &admin).await.text;
    assert!(!text.contains(r#"id="log-editor""#));
}

#[tokio::test]
async fn another_accounts_time_cannot_be_touched() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    let reading = task(&app, &admin, "Reading").await;
    add_time(
        &app,
        &admin,
        &reading,
        "2026-11-04T09:00:00",
        "2026-11-04T10:00:00",
    )
    .await;
    let id = entry_id(&app).await;

    let text = page(&app, &format!("{WEEK}&entry={id}"), &bob).await.text;
    assert!(!text.contains("Reading"));
    assert!(!text.contains(r#"id="log-editor""#));

    let fields = [
        ("task", reading.as_str()),
        ("start", "2026-11-04T11:00:00"),
        ("end", "2026-11-04T12:00:00"),
    ];
    for request in [
        write("/missions/log/entries", &bob).form(&fields),
        write(&format!("/missions/log/entries/{id}"), &bob).form(&fields),
        write(&format!("/missions/log/entries/{id}/delete"), &bob),
        write(&format!("/missions/log/entries/{id}/stop"), &bob),
    ] {
        let response = app.send(request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{}", response.text);
    }
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM time_entries")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(entries, 1);
    assert_eq!(
        entry(&app, &id).await,
        (
            reading,
            ts("2026-11-04T09:00:00"),
            Some(ts("2026-11-04T10:00:00")),
            false
        )
    );
}
