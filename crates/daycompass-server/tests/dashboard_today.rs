//! The Today page of the Missions tab: adding and ordering the day's
//! tasks, the one timer, done tasks, yesterday's leftovers, the mission
//! filter, the timeline, and the mission hours card on the overview.
//!
//! Writes go through the sync service, so a device sees them, and the
//! page shows what a device pushed. Accounts are on UTC, the default.

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

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

async fn add(app: &TestApp, session: &Session, fields: &[(&str, &str)]) -> TestResponse {
    ok(app, write("/missions/today/tasks", session).form(fields)).await
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// Today and yesterday in UTC, as `tasks.day` holds them.
fn days() -> (String, String) {
    let today = jiff::Timestamp::now()
        .to_zoned_datetime(jiff::tz::TimeZone::UTC)
        .date();
    (today.to_string(), today.yesterday().unwrap().to_string())
}

fn id(n: u32) -> String {
    format!("{n:032x}")
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

async fn task_id(app: &TestApp, title: &str) -> String {
    sqlx::query_scalar("SELECT id FROM tasks WHERE title = ?1")
        .bind(title)
        .fetch_one(&app.pool)
        .await
        .expect("the task")
}

async fn running_task(app: &TestApp) -> Option<String> {
    sqlx::query_scalar("SELECT task_id FROM time_entries WHERE end_ts IS NULL AND deleted = 0")
        .fetch_optional(&app.pool)
        .await
        .unwrap()
}

/// Where each title first appears; panics if one is missing.
fn order(text: &str, titles: &[&str]) -> Vec<usize> {
    titles
        .iter()
        .map(|title| {
            text.find(&format!(r#"<span class="dc-task__title">{title}</span>"#))
                .unwrap_or_else(|| panic!("{title} is not on the page"))
        })
        .collect()
}

fn ascending(positions: &[usize]) -> bool {
    positions.windows(2).all(|pair| pair[0] < pair[1])
}

#[tokio::test]
async fn tasks_go_to_the_top_or_the_bottom_and_a_device_pulls_them() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    add(&app, &admin, &[("title", "Bravo"), ("at", "bottom")]).await;
    add(&app, &admin, &[("title", "Charlie")]).await;
    let last = add(&app, &admin, &[("title", "Alpha"), ("at", "top")]).await;
    assert!(ascending(&order(
        &last.text,
        &["Alpha", "Bravo", "Charlie"]
    )));

    let pulled = sync(&app, &device, json!({ "cursor": 0 })).await;
    let mut tasks: Vec<(String, String, String)> = pulled["changes"]["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|task| {
            (
                task["position"].as_str().unwrap().to_owned(),
                task["title"].as_str().unwrap().to_owned(),
                task["day"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    tasks.sort();
    let (today, _) = days();
    let expected: Vec<(String, String, String)> =
        [("Zz", "Alpha"), ("a0", "Bravo"), ("a1", "Charlie")]
            .iter()
            .map(|(position, title)| ((*position).to_owned(), (*title).to_owned(), today.clone()))
            .collect();
    assert_eq!(tasks, expected);
}

#[tokio::test]
async fn one_timer_runs_at_a_time_and_the_pill_follows_it() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    add(&app, &admin, &[("title", "Alpha")]).await;
    add(&app, &admin, &[("title", "Bravo")]).await;
    let (alpha, bravo) = (task_id(&app, "Alpha").await, task_id(&app, "Bravo").await);

    let started = ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/start"), &admin),
    )
    .await;
    assert_eq!(running_task(&app).await.as_deref(), Some(alpha.as_str()));
    // The pill comes along out of band, and the timeline grows a block.
    assert!(started
        .text
        .contains(r#"<div id="dc-timer" hx-swap-oob="true"><a class="dc-timer""#));
    assert!(started.text.contains("data-dc-widen="));
    assert!(started.text.contains("Pause Alpha"));

    // Starting again on the same task changes nothing.
    ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/start"), &admin),
    )
    .await;
    // A timer on another task ends the first.
    ok(
        &app,
        write(&format!("/missions/tasks/{bravo}/start"), &admin),
    )
    .await;
    assert_eq!(running_task(&app).await.as_deref(), Some(bravo.as_str()));
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM time_entries")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(entries, 2);

    // Stopping Alpha, which no longer runs, is not an error and stops
    // nothing; stopping Bravo does.
    ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/stop"), &admin),
    )
    .await;
    assert_eq!(running_task(&app).await.as_deref(), Some(bravo.as_str()));
    let stopped = ok(
        &app,
        write(&format!("/missions/tasks/{bravo}/stop"), &admin),
    )
    .await;
    assert_eq!(running_task(&app).await, None);
    assert!(stopped
        .text
        .contains(r#"<div id="dc-timer" hx-swap-oob="true"></div>"#));
}

#[tokio::test]
async fn a_done_task_goes_to_the_bottom_and_its_timer_stops() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    add(&app, &admin, &[("title", "Alpha")]).await;
    add(&app, &admin, &[("title", "Bravo")]).await;
    let alpha = task_id(&app, "Alpha").await;
    ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/start"), &admin),
    )
    .await;

    let done = ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/done"), &admin).form(&[("done", "true")]),
    )
    .await;
    assert_eq!(running_task(&app).await, None);
    assert!(ascending(&order(&done.text, &["Bravo", "Alpha"])));
    assert!(done.text.contains("Mark Alpha not done"));

    let undone = ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/done"), &admin).form(&[("done", "false")]),
    )
    .await;
    assert!(ascending(&order(&undone.text, &["Alpha", "Bravo"])));
    assert!(undone.text.contains("Mark Alpha done"));
}

#[tokio::test]
async fn a_move_puts_a_task_between_the_two_it_names() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    for title in ["Alpha", "Bravo", "Charlie"] {
        add(&app, &admin, &[("title", title)]).await;
    }
    let (alpha, charlie) = (task_id(&app, "Alpha").await, task_id(&app, "Charlie").await);

    let to_top = ok(
        &app,
        write("/missions/tasks/move", &admin).form(&[
            ("task", charlie.as_str()),
            ("after", ""),
            ("before", alpha.as_str()),
        ]),
    )
    .await;
    assert!(ascending(&order(
        &to_top.text,
        &["Charlie", "Alpha", "Bravo"]
    )));
    // Up and down offer the same move: Alpha's "up" lands it before Charlie.
    assert!(to_top.text.contains(&format!(
        r#"hx-vals='{{"task": "{alpha}", "after": "", "before": "{charlie}"}}'"#
    )));
}

#[tokio::test]
async fn a_move_between_two_tasks_with_the_same_key_is_a_conflict() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;
    let (today, _) = days();
    // Two devices that added a task offline at the same place.
    let task = |n: u32, title: &str| {
        json!({
            "id": id(n), "title": title, "day": today, "position": "a1",
            "deleted": false, "updated_at": now(),
        })
    };
    sync(
        &app,
        &device,
        json!({ "cursor": 0, "tasks": [task(1, "Twin one"), task(2, "Twin two")] }),
    )
    .await;
    add(&app, &admin, &[("title", "Mover"), ("at", "top")]).await;
    let mover = task_id(&app, "Mover").await;

    let response = app
        .send(write("/missions/tasks/move", &admin).form(&[
            ("task", mover.as_str()),
            ("after", id(1).as_str()),
            ("before", id(2).as_str()),
        ]))
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert!(response.text.contains("task_order_conflict"));
}

#[tokio::test]
async fn yesterdays_open_tasks_move_only_when_asked() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;
    let (_, yesterday) = days();
    let task = |n: u32, title: &str, done_at: Option<i64>| {
        json!({
            "id": id(n), "title": title, "day": yesterday, "position": "a0",
            "done_at": done_at, "deleted": false, "updated_at": now(),
        })
    };
    sync(
        &app,
        &device,
        json!({ "cursor": 0, "tasks": [task(1, "Left over", None), task(2, "Finished", Some(now() - 60))] }),
    )
    .await;
    add(&app, &admin, &[("title", "Planned")]).await;

    let before = page(&app, "/missions/today", &admin).await.text;
    assert!(before.contains("1 task left from yesterday"));
    assert!(!before.contains("Left over"));

    let moved = ok(&app, write("/missions/today/carry-over", &admin)).await;
    assert!(!moved.text.contains("left from yesterday"));
    assert!(ascending(&order(&moved.text, &["Planned", "Left over"])));
    assert!(!moved.text.contains("Finished"));
}

#[tokio::test]
async fn another_accounts_task_cannot_be_touched() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    add(&app, &admin, &[("title", "Admin task")]).await;
    let task = task_id(&app, "Admin task").await;

    assert!(!page(&app, "/missions/today", &bob)
        .await
        .text
        .contains("Admin task"));
    for request in [
        write(&format!("/missions/tasks/{task}/start"), &bob),
        write(&format!("/missions/tasks/{task}/stop"), &bob),
        write(&format!("/missions/tasks/{task}/done"), &bob).form(&[("done", "true")]),
        write(&format!("/missions/tasks/{task}/tomorrow"), &bob),
        write(&format!("/missions/tasks/{task}/notes"), &bob).form(&[("notes", "x")]),
        write("/missions/tasks/move", &bob).form(&[("task", task.as_str())]),
    ] {
        let response = app.send(request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{}", response.text);
    }
    assert_eq!(running_task(&app).await, None);
}

#[tokio::test]
async fn an_invalid_task_is_refused() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let long = "x".repeat(201);
    for title in ["  ", long.as_str()] {
        let response = app
            .send(write("/missions/today/tasks", &admin).form(&[("title", title)]))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.text.contains("invalid_task"));
    }
}

#[tokio::test]
async fn the_filter_narrows_the_list_and_writes_keep_it() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    for title in ["Maths", "Music"] {
        ok(
            &app,
            write("/missions/manage", &admin).form(&[("title", title), ("colour", "1")]),
        )
        .await;
    }
    let maths: String = sqlx::query_scalar("SELECT id FROM missions WHERE title = 'Maths'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let music: String = sqlx::query_scalar("SELECT id FROM missions WHERE title = 'Music'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    add(
        &app,
        &admin,
        &[("title", "Algebra"), ("mission", maths.as_str())],
    )
    .await;
    add(
        &app,
        &admin,
        &[("title", "Scales"), ("mission", music.as_str())],
    )
    .await;
    let all = add(&app, &admin, &[("title", "Laundry")]).await.text;
    assert!(all.contains(r#"<details id="other-tasks""#));
    order(&all, &["Algebra", "Scales", "Laundry"]);

    let filtered = page(&app, &format!("/missions/today?mission={maths}"), &admin)
        .await
        .text;
    order(&filtered, &["Algebra"]);
    assert!(!filtered.contains("Scales") && !filtered.contains("Laundry"));
    assert!(filtered.contains(&format!(
        r#"hx-post="/missions/today/tasks?mission={maths}""#
    )));
    assert!(filtered.contains(&format!(r#"<option value="{maths}" selected>"#)));

    let added = add_filtered(&app, &admin, &maths).await;
    assert!(added.contains("Geometry") && !added.contains("Scales"));
}

async fn add_filtered(app: &TestApp, admin: &Session, mission: &str) -> String {
    ok(
        app,
        write(&format!("/missions/today/tasks?mission={mission}"), admin)
            .form(&[("title", "Geometry"), ("mission", mission)]),
    )
    .await
    .text
}

#[tokio::test]
async fn todays_time_shows_on_the_timeline_and_as_mission_hours() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    // No active mission, no card.
    assert!(!page(&app, "/", &admin).await.text.contains("Mission hours"));

    let (today, _) = days();
    let start = now() - 60;
    sync(
        &app,
        &device,
        json!({
            "cursor": 0,
            "missions": [{
                "id": id(1), "title": "Physics", "colour": 5, "weekly_goal_secs": 18_000,
                "archived": false, "deleted": false, "updated_at": now(),
            }],
            "tasks": [{
                "id": id(2), "mission_id": id(1), "title": "Exercise 4", "day": today,
                "position": "a0", "deleted": false, "updated_at": now(),
            }],
            "time_entries": [{
                "id": id(3), "task_id": id(2), "start_ts": start, "end_ts": start + 60,
                "deleted": false, "updated_at": now(),
            }],
        }),
    )
    .await;

    let text = page(&app, "/missions/today", &admin).await.text;
    assert!(text.contains(r#"<rect class="dc-fill--c5""#), "{text}");
    assert!(text.contains("<title>Exercise 4, "), "{text}");
    assert!(text.contains("Tracked today: 1m"));
    assert!(text.contains("1m of 5h 0m"));

    let overview = page(&app, "/", &admin).await.text;
    assert!(overview.contains("Mission hours today"));
    assert!(overview.contains("1m of 5h 0m this week"));
    assert!(overview.contains(r#"href="/missions/today">Open Missions"#));
}
