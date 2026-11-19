//! The Missions tab on the dashboard: `/missions/manage` and its writes,
//! the North Star, and the running-timer pill in the layout.
//!
//! Page writes go through the same sync service as a device's push, so
//! these tests check the other side too: a device pulls what the page
//! wrote, and the page shows what a device pushed.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Device, Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

const DAY: i64 = 86_400;

/// A dashboard write: htmx, matching `Origin`, cookie and CSRF token.
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

async fn create(app: &TestApp, session: &Session, fields: &[(&str, &str)]) -> TestResponse {
    app.send(write("/missions/manage", session).form(fields))
        .await
}

fn now() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    i64::try_from(since.as_secs()).unwrap()
}

/// Monday 00:00 UTC of the current week, worked out independently of
/// the server's own `week_bounds`. 1970-01-01 was a Thursday.
fn utc_week_start(ts: i64) -> i64 {
    let days = ts.div_euclid(DAY);
    (days - (days + 3).rem_euclid(7)) * DAY
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

/// A device pushes one mission (`colour` 5, goal 5 h), one task under
/// it and these time entries, all applied.
async fn push_tracked(app: &TestApp, device: &Device, entries: &[(i64, Option<i64>)]) {
    let at = now();
    let entries: Vec<Value> = entries
        .iter()
        .enumerate()
        .map(|(n, (start_ts, end_ts))| {
            json!({
                "id": id(100 + u32::try_from(n).unwrap()), "task_id": id(2),
                "start_ts": start_ts, "end_ts": end_ts, "deleted": false, "updated_at": at,
            })
        })
        .collect();
    let body = sync(
        app,
        device,
        json!({
            "cursor": 0,
            "missions": [{
                "id": id(1), "title": "Physics", "colour": 5, "weekly_goal_secs": 18_000,
                "archived": false, "deleted": false, "updated_at": at,
            }],
            "tasks": [{
                "id": id(2), "mission_id": id(1), "title": "Exercise 4", "position": "a0",
                "deleted": false, "updated_at": at,
            }],
            "time_entries": entries,
        }),
    )
    .await;
    let all = ["missions", "tasks", "time_entries"]
        .iter()
        .flat_map(|kind| body["results"][kind].as_array().unwrap().clone());
    for result in all {
        assert_eq!(result["status"], "applied", "{body:?}");
    }
}

async fn mission_id(app: &TestApp, title: &str) -> String {
    sqlx::query_scalar("SELECT id FROM missions WHERE title = ?1")
        .bind(title)
        .fetch_one(&app.pool)
        .await
        .expect("the mission")
}

fn pulled<'a>(body: &'a Value, mission: &str) -> &'a Value {
    body["changes"]["missions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == mission)
        .unwrap_or_else(|| panic!("{mission} not pulled: {body:?}"))
}

#[tokio::test]
async fn a_mission_made_on_the_page_reaches_a_device_and_so_do_edits() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    let created = create(
        &app,
        &admin,
        &[
            ("title", "Maths <i>A</i>"),
            ("colour", "3"),
            ("weekly_goal_hours", "7.5"),
            ("description", "line one\r\nline two"),
            ("why", ""),
            ("starts_on", "2026-09-01"),
            ("ends_on", ""),
        ],
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert!(!created.text.contains("<i>A</i>"), "the title is escaped");
    assert!(
        created.text.contains("Maths &#60;i&#62;A&#60;/i&#62;"),
        "{}",
        created.text
    );
    assert!(created.text.contains("0m of 7h 30m"));
    let mission = mission_id(&app, "Maths <i>A</i>").await;

    let first = sync(&app, &device, json!({ "cursor": 0 })).await;
    let record = pulled(&first, &mission);
    assert_eq!(record["colour"], 3);
    assert_eq!(record["weekly_goal_secs"], 27_000);
    assert_eq!(record["description"], "line one\nline two");
    assert_eq!(record["why"], Value::Null);
    assert_eq!(record["starts_on"], "2026-09-01");
    assert_eq!(record["ends_on"], Value::Null);
    assert_eq!(record["archived"], false);

    let edited = app
        .send(
            write(&format!("/missions/{mission}/edit"), &admin)
                .form(&[("title", "Maths"), ("colour", "4")]),
        )
        .await;
    assert_eq!(edited.status, StatusCode::OK, "{}", edited.text);
    let archived = app
        .send(write(&format!("/missions/{mission}/archive"), &admin).form(&[("archived", "true")]))
        .await;
    assert_eq!(archived.status, StatusCode::OK, "{}", archived.text);
    assert!(archived.text.contains("Archived") && archived.text.contains("Unarchive"));

    let second = sync(&app, &device, json!({ "cursor": first["cursor"] })).await;
    let record = pulled(&second, &mission);
    assert_eq!(record["title"], "Maths");
    assert_eq!(record["colour"], 4);
    // The edit form replaces every field it has; it left these empty.
    assert_eq!(record["weekly_goal_secs"], 0);
    assert_eq!(record["description"], Value::Null);
    assert_eq!(record["archived"], true);
}

#[tokio::test]
async fn one_account_never_sees_or_changes_anothers_missions() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    create(&app, &admin, &[("title", "Admin plan"), ("colour", "0")]).await;
    let mission = mission_id(&app, "Admin plan").await;

    assert!(!page(&app, "/missions/manage", &bob)
        .await
        .text
        .contains("Admin plan"));
    for (path, fields) in [
        (
            format!("/missions/{mission}/edit"),
            vec![("title", "Taken"), ("colour", "0")],
        ),
        (
            format!("/missions/{mission}/archive"),
            vec![("archived", "true")],
        ),
    ] {
        let response = app.send(write(&path, &bob).form(&fields)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
    }

    let text = page(&app, "/missions/manage", &admin).await.text;
    assert!(text.contains("Admin plan") && !text.contains("Taken") && !text.contains("Unarchive"));
}

#[tokio::test]
async fn an_invalid_mission_is_refused_and_nothing_is_stored() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let long_title = "x".repeat(101);
    for fields in [
        vec![
            ("title", "Inverted"),
            ("colour", "0"),
            ("starts_on", "2026-09-01"),
            ("ends_on", "2026-08-31"),
        ],
        vec![
            ("title", "Goal"),
            ("colour", "0"),
            ("weekly_goal_hours", "abc"),
        ],
        vec![
            ("title", "Week"),
            ("colour", "0"),
            ("weekly_goal_hours", "169"),
        ],
        vec![("title", long_title.as_str()), ("colour", "0")],
        vec![("title", "Colour"), ("colour", "8")],
        vec![("title", "  "), ("colour", "0")],
    ] {
        let response = create(&app, &admin, &fields).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{fields:?}");
        assert_eq!(
            response.headers.get("hx-retarget").unwrap(),
            "#dc-flash",
            "{fields:?}"
        );
        assert!(response.text.contains("invalid_mission"), "{fields:?}");
        let title = fields[0].1;
        if !title.trim().is_empty() {
            assert!(!response.text.contains(title), "{fields:?} is echoed");
        }
    }

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM missions")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

#[tokio::test]
async fn the_page_counts_this_weeks_time_against_the_goal_and_all_time() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    // The account is on UTC. One entry straddles this week's start, so
    // only its last minute counts this week; one is from last week.
    let week = utc_week_start(now());
    push_tracked(
        &app,
        &device,
        &[
            (week - 1800, Some(week + 60)),
            (week - 7 * DAY, Some(week - 7 * DAY + 3600)),
        ],
    )
    .await;

    let text = page(&app, "/missions/manage", &admin).await.text;
    assert!(text.contains("1m of 5h 0m"), "{text}");
    assert!(text.contains("1h 31m in total"), "{text}");
    assert!(text.contains(r#"value="60" max="18000""#), "{text}");
}

#[tokio::test]
async fn more_than_three_active_missions_get_a_hint_until_one_is_archived() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let mut last = None;
    for title in ["One", "Two", "Three", "Four"] {
        last = Some(create(&app, &admin, &[("title", title), ("colour", "0")]).await);
    }
    assert!(last.unwrap().text.contains("4 active missions"));

    let mission = mission_id(&app, "Four").await;
    let archived = app
        .send(write(&format!("/missions/{mission}/archive"), &admin).form(&[("archived", "true")]))
        .await;
    assert!(!archived.text.contains("active missions"));
}

#[tokio::test]
async fn the_north_star_is_saved_shown_and_cleared() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let north_star =
        |value: &str| write("/missions/north-star", &admin).form(&[("north_star", value)]);

    let saved = app.send(north_star("  Finish school well ")).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(saved.text.contains(">Finish school well<"));
    assert!(page(&app, "/missions/manage", &admin)
        .await
        .text
        .contains("Finish school well"));

    let too_long = "x".repeat(201);
    for refused in [too_long.as_str(), "two\nlines"] {
        let response = app.send(north_star(refused)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.text.contains("invalid_north_star"));
    }

    let cleared = app.send(north_star("")).await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(!cleared.text.contains("Finish school well"));
    let stored: Option<String> = sqlx::query_scalar("SELECT north_star FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(stored, None);
}

#[tokio::test]
async fn a_running_timer_shows_on_every_page() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    assert!(!page(&app, "/", &admin)
        .await
        .text
        .contains("data-dc-elapsed"));

    push_tracked(&app, &device, &[(now() - 90, None)]).await;

    for path in [
        "/",
        "/missions/manage",
        "/devices",
        "/category-rules",
        "/account",
        "/admin/users",
        "/admin/devices",
    ] {
        let text = page(&app, path, &admin).await.text;
        assert!(text.contains("Exercise 4"), "{path}");
        assert!(text.contains("dc-swatch dc-swatch--c5"), "{path}");
        let elapsed: i64 = text
            .split(r#"data-dc-elapsed=""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .and_then(|secs| secs.parse().ok())
            .unwrap_or_else(|| panic!("{path} has no timer"));
        assert!((90..600).contains(&elapsed), "{path}: {elapsed}");
    }
}

#[tokio::test]
async fn missions_are_in_the_navigation_and_categories_on_the_account_page() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let overview = page(&app, "/", &admin).await.text;
    assert!(overview.contains(r#"href="/missions/today""#));
    // Not in the navigation; the command menu, rendered after it, may
    // still lead there.
    let navigation = overview.split(r#"<dialog id="dc-command""#).next();
    assert!(!navigation.unwrap().contains(r#"href="/category-rules""#));
    assert!(page(&app, "/account", &admin)
        .await
        .text
        .contains(r#"href="/category-rules""#));

    // The sidebar and the bottom bar lead to Today; the sub-navigation
    // marks the page itself.
    let manage = page(&app, "/missions/manage", &admin).await.text;
    assert_eq!(
        manage
            .matches(r#"href="/missions/today" aria-current="page""#)
            .count(),
        2
    );
    assert_eq!(
        manage
            .matches(r#"href="/missions/manage" aria-current="page""#)
            .count(),
        1
    );
    let today = page(&app, "/missions/today", &admin).await.text;
    assert_eq!(
        today
            .matches(r#"href="/missions/today" aria-current="page""#)
            .count(),
        3
    );
}
