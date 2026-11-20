//! The Plan page of the Missions tab: a week next to the backlog,
//! adding to any column, moving tasks within and across columns, the
//! week navigation, the mission filter and hiding done tasks.
//!
//! Writes go through the sync service, like Today's. Accounts are on
//! UTC, the default.

mod common;

use axum::http::StatusCode;
use jiff::civil::Date;
use jiff::ToSpan;

use common::{Session, TestApp, TestRequest, TestResponse, GOOD_ORIGIN};

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
    ok(app, write("/missions/plan/tasks", session).form(fields)).await
}

async fn move_to(
    app: &TestApp,
    session: &Session,
    task: &str,
    day: &str,
    after: &str,
    before: &str,
) -> TestResponse {
    ok(
        app,
        write("/missions/plan/move", session).form(&[
            ("task", task),
            ("day", day),
            ("after", after),
            ("before", before),
        ]),
    )
    .await
}

/// Today in UTC, and the Monday of its week.
fn today_and_monday() -> (Date, Date) {
    let today = jiff::Timestamp::now()
        .to_zoned_datetime(jiff::tz::TimeZone::UTC)
        .date();
    let offset = i64::from(today.weekday().to_monday_zero_offset());
    (today, today.checked_sub(offset.days()).unwrap())
}

async fn task_id(app: &TestApp, title: &str) -> String {
    sqlx::query_scalar("SELECT id FROM tasks WHERE title = ?1")
        .bind(title)
        .fetch_one(&app.pool)
        .await
        .expect("the task")
}

async fn day_of(app: &TestApp, title: &str) -> Option<String> {
    sqlx::query_scalar("SELECT day FROM tasks WHERE title = ?1")
        .bind(title)
        .fetch_one(&app.pool)
        .await
        .expect("the task")
}

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
async fn a_week_shows_the_backlog_and_seven_days_with_today_marked() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (today, monday) = today_and_monday();

    let text = page(&app, "/missions/plan", &admin).await.text;
    assert!(text.contains(r#"href="/missions/plan" aria-current="page">Plan"#));
    assert!(text.contains(r#"data-dc-day="""#), "the backlog");
    for n in 0..7 {
        let day = monday.checked_add(n.days()).unwrap();
        assert!(text.contains(&format!(r#"data-dc-day="{day}""#)), "{day}");
    }
    assert_eq!(text.matches("dc-plan__day--today").count(), 1);
    assert!(text.contains(&format!(r#"id="day-{today}""#)));
    assert!(text.contains(&today.strftime("%B").to_string()));

    // Any day of a week shows that week; a past one is dimmed throughout.
    let past = monday.checked_sub(13.days()).unwrap();
    let text = page(&app, &format!("/missions/plan?week={past}"), &admin)
        .await
        .text;
    let past_monday = monday.checked_sub(14.days()).unwrap();
    assert!(text.contains(&format!(r#"data-dc-day="{past_monday}""#)));
    assert_eq!(text.matches("dc-plan__day--today").count(), 0);
    assert_eq!(text.matches("dc-plan__day--past").count(), 7);
    let next = past_monday.checked_add(7.days()).unwrap();
    assert!(text.contains(&format!(r#"href="/missions/plan?week={next}""#)));
    assert!(text.contains(r#"href="/missions/plan">Today</a>"#));

    let response = app
        .send(TestRequest::get("/missions/plan?week=someday").cookie(&admin.cookie))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tasks_go_to_the_top_or_bottom_of_a_day_or_the_backlog() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_, monday) = today_and_monday();
    let monday = monday.to_string();

    add(&app, &admin, &[("title", "Bravo"), ("day", "")]).await;
    add(
        &app,
        &admin,
        &[("title", "Alpha"), ("day", ""), ("at", "top")],
    )
    .await;
    add(&app, &admin, &[("title", "Delta"), ("day", &monday)]).await;
    let last = add(
        &app,
        &admin,
        &[("title", "Charlie"), ("day", &monday), ("at", "top")],
    )
    .await;

    assert!(ascending(&order(
        &last.text,
        &["Alpha", "Bravo", "Charlie", "Delta"]
    )));
    assert_eq!(day_of(&app, "Alpha").await, None);
    assert_eq!(
        day_of(&app, "Charlie").await.as_deref(),
        Some(monday.as_str())
    );

    let response = app
        .send(
            write("/missions/plan/tasks", &admin).form(&[("title", "Bad"), ("day", "2026-02-30")]),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.text.contains("invalid_task"));
}

#[tokio::test]
async fn a_move_crosses_days_and_the_buttons_offer_the_neighbouring_columns() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_, monday) = today_and_monday();
    let tuesday = monday.checked_add(1.days()).unwrap().to_string();
    let sunday = monday.checked_add(6.days()).unwrap().to_string();
    let monday = monday.to_string();
    for title in ["Alpha", "Bravo"] {
        add(&app, &admin, &[("title", title), ("day", &monday)]).await;
    }
    add(&app, &admin, &[("title", "Charlie"), ("day", "")]).await;
    add(&app, &admin, &[("title", "Echo"), ("day", &sunday)]).await;
    let [alpha, bravo, charlie] = [
        task_id(&app, "Alpha").await,
        task_id(&app, "Bravo").await,
        task_id(&app, "Charlie").await,
    ];

    // From the backlog to between Alpha and Bravo.
    let moved = move_to(&app, &admin, &charlie, &monday, &alpha, &bravo).await;
    assert_eq!(
        day_of(&app, "Charlie").await.as_deref(),
        Some(monday.as_str())
    );
    assert!(ascending(&order(
        &moved.text,
        &["Alpha", "Charlie", "Bravo"]
    )));

    // To an empty day, then to the backlog.
    move_to(&app, &admin, &alpha, &tuesday, "", "").await;
    assert_eq!(
        day_of(&app, "Alpha").await.as_deref(),
        Some(tuesday.as_str())
    );
    let moved = move_to(&app, &admin, &alpha, "", "", "").await;
    assert_eq!(day_of(&app, "Alpha").await, None);

    // One column earlier or later lands at the bottom there; nothing
    // reaches past the backlog or Sunday.
    let text = &moved.text;
    assert!(text.contains(&format!(
        r##"hx-vals='{{"task": "{bravo}", "day": "", "after": "{alpha}", "before": ""}}' hx-target="#plan" hx-swap="outerHTML" aria-label="Move Bravo to the backlog""##
    )));
    assert!(text.contains(&format!(
        r##"hx-vals='{{"task": "{alpha}", "day": "{monday}", "after": "{bravo}", "before": ""}}' hx-target="#plan" hx-swap="outerHTML" aria-label="Move Alpha to Monday""##
    )));
    assert!(text.contains(r#"aria-label="Move Bravo to Tuesday""#));
    assert!(!text.contains(r#"aria-label="Move Alpha to the backlog""#));
    assert!(text.contains(r#"aria-label="Move Echo to Saturday""#));
    assert!(!text.contains(r#"aria-label="Move Echo to Monday""#));
}

#[tokio::test]
async fn the_filter_and_hiding_done_tasks_narrow_the_week_and_writes_keep_them() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_, monday) = today_and_monday();
    let monday = monday.to_string();
    ok(
        &app,
        write("/missions/manage", &admin).form(&[("title", "Maths"), ("colour", "1")]),
    )
    .await;
    let maths: String = sqlx::query_scalar("SELECT id FROM missions WHERE title = 'Maths'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    add(
        &app,
        &admin,
        &[("title", "Algebra"), ("day", &monday), ("mission", &maths)],
    )
    .await;
    add(&app, &admin, &[("title", "Laundry"), ("day", &monday)]).await;
    add(&app, &admin, &[("title", "Washed"), ("day", &monday)]).await;
    let washed = task_id(&app, "Washed").await;
    ok(
        &app,
        write(&format!("/missions/tasks/{washed}/done"), &admin).form(&[("done", "true")]),
    )
    .await;

    let all = page(&app, "/missions/plan", &admin).await.text;
    order(&all, &["Algebra", "Laundry", "Washed"]);
    assert!(all.contains(r#"<li class="dc-task dc-task--done">"#));

    let filtered = page(&app, &format!("/missions/plan?mission={maths}"), &admin)
        .await
        .text;
    order(&filtered, &["Algebra"]);
    assert!(!filtered.contains("Laundry") && !filtered.contains("Washed"));
    assert!(filtered.contains(&format!(r#"<option value="{maths}" selected>"#)));

    let shown = page(&app, "/missions/plan?hide_done=true", &admin)
        .await
        .text;
    order(&shown, &["Algebra", "Laundry"]);
    assert!(!shown.contains("Washed"));
    assert!(shown.contains("Show done tasks"));

    let query = format!("?week={monday}&mission={maths}&hide_done=true");
    let added = ok(
        &app,
        write(&format!("/missions/plan/tasks{query}"), &admin).form(&[
            ("title", "Geometry"),
            ("day", ""),
            ("mission", &maths),
        ]),
    )
    .await
    .text;
    assert!(added.contains("Geometry") && !added.contains("Laundry"));
    assert!(added.contains(&format!(
        r#"hx-post="/missions/plan/move?week={monday}&#38;mission={maths}&#38;hide_done=true""#
    )));
}

#[tokio::test]
async fn another_accounts_task_cannot_be_moved() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;
    add(&app, &admin, &[("title", "Admin task"), ("day", "")]).await;
    let task = task_id(&app, "Admin task").await;

    assert!(!page(&app, "/missions/plan", &bob)
        .await
        .text
        .contains("Admin task"));
    let response = app
        .send(write("/missions/plan/move", &bob).form(&[("task", task.as_str()), ("day", "")]))
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "{}", response.text);
}
