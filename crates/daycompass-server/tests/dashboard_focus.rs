//! The Focus page of the Missions tab: the one task to work on now, the
//! next one once it is done, "Day done", and the two writes it brought
//! along (notes, move to tomorrow), which the Today page uses too.
//!
//! Accounts are on UTC, the default.

mod common;

use axum::http::StatusCode;

use common::{Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

fn write(path: &str, session: &Session) -> TestRequest {
    TestRequest::post(path)
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .htmx()
}

async fn ok(app: &TestApp, request: TestRequest) -> TestResponse {
    let response = app.send(request).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response
}

async fn focus(app: &TestApp, session: &Session) -> String {
    ok(
        app,
        TestRequest::get("/missions/focus").cookie(&session.cookie),
    )
    .await
    .text
}

/// Adds a task for today, and returns its id.
async fn add(app: &TestApp, session: &Session, fields: &[(&str, &str)]) -> String {
    ok(app, write("/missions/today/tasks", session).form(fields)).await;
    sqlx::query_scalar("SELECT id FROM tasks WHERE title = ?1")
        .bind(fields[0].1)
        .fetch_one(&app.pool)
        .await
        .expect("the task")
}

/// The title of the task Focus shows, if any.
fn current(text: &str) -> Option<&str> {
    let start = text.find(r#"id="focus-title">"#)? + r#"id="focus-title">"#.len();
    let end = text[start..].find("</h2>")?;
    Some(&text[start..start + end])
}

#[tokio::test]
async fn focus_shows_the_first_open_task_or_the_one_whose_timer_runs() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    assert!(focus(&app, &admin)
        .await
        .contains("Nothing planned for today yet."));

    add(&app, &admin, &[("title", "Alpha")]).await;
    let bravo = add(&app, &admin, &[("title", "Bravo")]).await;
    add(&app, &admin, &[("title", "Charlie")]).await;
    let text = focus(&app, &admin).await;
    assert_eq!(current(&text), Some("Alpha"));
    assert!(text.contains("2 more today"));
    assert!(text.contains("Start</button>"));

    // A write sent with ?view=focus answers with the Focus block.
    let started = ok(
        &app,
        write(&format!("/missions/tasks/{bravo}/start?view=focus"), &admin),
    )
    .await;
    assert!(started.text.contains(r#"<div id="focus""#));
    assert!(!started.text.contains(r#"<div id="today""#));
    assert_eq!(current(&started.text), Some("Bravo"));
    assert!(started.text.contains("Pause</button>"));
    assert!(started
        .text
        .contains(r#"<div id="dc-timer" hx-swap-oob="true"><a class="dc-timer""#));

    let paused = ok(
        &app,
        write(&format!("/missions/tasks/{bravo}/stop?view=focus"), &admin),
    )
    .await;
    // Back to the first open task, as nothing runs.
    assert_eq!(current(&paused.text), Some("Alpha"));
}

#[tokio::test]
async fn completing_a_task_brings_the_next_and_then_day_done() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let alpha = add(&app, &admin, &[("title", "Alpha")]).await;
    let bravo = add(&app, &admin, &[("title", "Bravo")]).await;

    let done = ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/done?view=focus"), &admin)
            .form(&[("done", "true")]),
    )
    .await;
    assert_eq!(current(&done.text), Some("Bravo"));
    assert!(!done.text.contains("more today"));

    let last = ok(
        &app,
        write(&format!("/missions/tasks/{bravo}/done?view=focus"), &admin)
            .form(&[("done", "true")]),
    )
    .await;
    assert_eq!(current(&last.text), None);
    assert!(last.text.contains("Day done"));
    assert!(last.text.contains("0m on missions today."));
}

#[tokio::test]
async fn a_task_under_a_mission_comes_before_one_under_none() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    ok(
        &app,
        write("/missions/manage", &admin).form(&[("title", "Maths"), ("colour", "1")]),
    )
    .await;
    let maths: String = sqlx::query_scalar("SELECT id FROM missions WHERE title = 'Maths'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    add(&app, &admin, &[("title", "Loose end")]).await;
    add(
        &app,
        &admin,
        &[("title", "Exercise 4"), ("mission", &maths)],
    )
    .await;

    let text = focus(&app, &admin).await;
    assert_eq!(current(&text), Some("Exercise 4"));
    assert!(text.contains("Maths</span>"));
    assert!(text.contains("1 more today"));
}

#[tokio::test]
async fn notes_keep_plain_line_breaks_and_blank_clears_them() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let alpha = add(&app, &admin, &[("title", "Alpha")]).await;
    let notes_of = || async {
        sqlx::query_scalar::<_, Option<String>>("SELECT notes FROM tasks WHERE id = ?1")
            .bind(&alpha)
            .fetch_one(&app.pool)
            .await
            .unwrap()
    };
    let path = format!("/missions/tasks/{alpha}/notes?view=focus");

    ok(
        &app,
        write(&path, &admin).form(&[("notes", "line one\r\nline two")]),
    )
    .await;
    assert_eq!(notes_of().await.as_deref(), Some("line one\nline two"));
    assert!(focus(&app, &admin)
        .await
        .contains(">line one\nline two</textarea>"));

    ok(&app, write(&path, &admin).form(&[("notes", "  \r\n")])).await;
    assert_eq!(notes_of().await, None);

    let long = "x".repeat(4001);
    for notes in [long.as_str(), "\u{202e}"] {
        let response = app
            .send(write(&path, &admin).form(&[("notes", notes)]))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.text.contains("invalid_task"));
    }
    assert_eq!(notes_of().await, None);
}

#[tokio::test]
async fn tomorrow_moves_a_task_to_the_end_of_tomorrow() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let tomorrow = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
        .tomorrow()
        .unwrap()
        .to_string();
    let alpha = add(&app, &admin, &[("title", "Alpha")]).await;
    ok(
        &app,
        write("/missions/plan/tasks", &admin).form(&[("title", "Bravo"), ("day", &tomorrow)]),
    )
    .await;

    // From Today, the answer is the Today block, without the task.
    let moved = ok(
        &app,
        write(&format!("/missions/tasks/{alpha}/tomorrow"), &admin),
    )
    .await;
    assert!(moved.text.contains(r#"<div id="today""#));
    assert!(!moved.text.contains("Alpha</span>"));

    let planned: Vec<(String, String)> =
        sqlx::query_as("SELECT title, day FROM tasks ORDER BY position")
            .fetch_all(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        planned,
        [
            ("Bravo".to_owned(), tomorrow.clone()),
            ("Alpha".to_owned(), tomorrow.clone())
        ]
    );
}

#[tokio::test]
async fn the_layout_carries_the_command_menu_and_the_shortcuts() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    let admin_page = focus(&app, &admin).await;
    for part in [
        r#"<dialog id="dc-command""#,
        r#"<dialog id="dc-keys""#,
        r#"href="/admin/users">Admin: Accounts"#,
    ] {
        assert!(admin_page.contains(part), "{part}");
    }
    // Admin links in the menu only for an admin.
    let bob_page = focus(&app, &bob).await;
    assert!(bob_page.contains(r#"<dialog id="dc-command""#));
    assert!(!bob_page.contains("Admin: Accounts"));

    let account = ok(&app, TestRequest::get("/account").cookie(&bob.cookie))
        .await
        .text;
    assert!(account.contains("data-dc-sound"));
}
