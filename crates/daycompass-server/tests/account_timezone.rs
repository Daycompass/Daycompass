//! `GET`/`PATCH /api/v1/account/timezone`, and `day_boundary=account`
//! on `GET /api/v1/stats`, over the real HTTP path.

mod common;

use axum::http::StatusCode;
use serde_json::json;

use common::{Session, TestApp, TestRequest, GOOD_ORIGIN};

fn set_timezone(session: &Session, name: &str) -> TestRequest {
    TestRequest::patch("/api/v1/account/timezone")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
        .json(json!({ "timezone": name }))
}

fn get_timezone(session: &Session) -> TestRequest {
    TestRequest::get("/api/v1/account/timezone")
        .origin(GOOD_ORIGIN)
        .authenticated(session)
}

#[tokio::test]
async fn a_new_account_is_in_utc_and_a_set_zone_sticks() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let response = app.send(get_timezone(&session)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["timezone"], "UTC");

    // Stored in the database's own spelling, whatever case was sent.
    let response = app.send(set_timezone(&session, "europe/berlin")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["timezone"], "Europe/Berlin");

    let response = app.send(get_timezone(&session)).await;
    assert_eq!(response.body["timezone"], "Europe/Berlin");
}

#[tokio::test]
async fn an_unknown_zone_is_refused_and_changes_nothing() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    app.send(set_timezone(&session, "Europe/Berlin")).await;

    for bad in ["Mars/Olympus", "", "EST5EDT,M3.2.0,M11.1.0", "+02:00"] {
        let response = app.send(set_timezone(&session, bad)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_eq!(response.error_code(), Some("invalid_timezone"), "{bad:?}");
    }

    let response = app.send(get_timezone(&session)).await;
    assert_eq!(response.body["timezone"], "Europe/Berlin");
}

#[tokio::test]
async fn setting_a_zone_needs_a_session_and_a_csrf_token() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let anonymous = TestRequest::patch("/api/v1/account/timezone")
        .origin(GOOD_ORIGIN)
        .json(json!({ "timezone": "Europe/Berlin" }));
    assert_eq!(app.send(anonymous).await.status, StatusCode::UNAUTHORIZED);

    // A session cookie alone, without the CSRF header.
    let without_csrf = TestRequest::patch("/api/v1/account/timezone")
        .origin(GOOD_ORIGIN)
        .cookie(&session.cookie)
        .json(json!({ "timezone": "Europe/Berlin" }));
    assert_eq!(app.send(without_csrf).await.status, StatusCode::FORBIDDEN);

    let response = app.send(get_timezone(&session)).await;
    assert_eq!(response.body["timezone"], "UTC");
}

#[tokio::test]
async fn accounts_have_their_own_zone() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_, other) = app.second_admin(&admin, "bob").await;

    app.send(set_timezone(&admin, "Asia/Tokyo")).await;

    let response = app.send(get_timezone(&other)).await;
    assert_eq!(response.body["timezone"], "UTC");
}

#[tokio::test]
async fn stats_follow_the_zone_only_when_asked() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;
    app.send(set_timezone(&session, "Asia/Tokyo")).await;

    // Tokyo is UTC+9 all year. 20:00 UTC on a UTC day is 05:00 the next
    // morning in Tokyo, so the same event is two different days.
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let utc_day = (now / 86_400) * 86_400 - 86_400;
    let start = utc_day + 20 * 3600;
    app.send(
        TestRequest::post("/api/v1/events")
            .authenticated_as_device(&device)
            .json(json!({ "events": [{
                "event_id": format!("{:032x}", 1),
                "start_ts": start,
                "duration_secs": 60,
                "app_id": "org.example.app",
            }]})),
    )
    .await;

    let window = format!("start_ts={}&end_ts={}", utc_day, utc_day + 2 * 86_400);
    let utc = app
        .send(
            TestRequest::get(&format!("/api/v1/stats?{window}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(utc.body["days"][0]["day_start_ts"], utc_day);

    let local = app
        .send(
            TestRequest::get(&format!("/api/v1/stats?{window}&day_boundary=account"))
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    // Tokyo midnight of the next day is 15:00 UTC.
    assert_eq!(local.body["days"][0]["day_start_ts"], utc_day + 15 * 3600);

    let bad = app
        .send(
            TestRequest::get(&format!("/api/v1/stats?{window}&day_boundary=nope"))
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}
