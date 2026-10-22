//! End-to-end tests for `POST /api/v1/events` and
//! `GET /api/v1/device/me`.
//!
//! The properties these exist to pin:
//!
//!   * idempotency per event, so a client may always resend;
//!   * one bad event never fails a batch, because a client that could
//!     not get rid of it would retry forever;
//!   * every validation bound bites exactly where it is documented;
//!   * a revoked device stops working on its very next request;
//!   * authentication runs before the body is read, so an
//!     unauthenticated caller cannot make the server buffer 512 KiB.

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

use common::{Device, TestApp, TestRequest, GOOD_ORIGIN};

/// An event id from a counter, so the sources hold no literal that
/// looks like one.
fn event_id(n: u32) -> String {
    format!("{n:032x}")
}

/// One valid event, `n` seconds after `start`.
fn event(n: u32, start: i64) -> Value {
    json!({
        "event_id": event_id(n),
        "start_ts": start + i64::from(n),
        "duration_secs": 60,
        "app_id": "org.example.app",
    })
}

fn ingest(device: &Device, events: Vec<Value>) -> TestRequest {
    TestRequest::post("/api/v1/events")
        .authenticated_as_device(device)
        .json(json!({ "events": events }))
}

/// An app with one paired device, and the server's own clock.
async fn app_with_device() -> (TestApp, Device, i64) {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let server_time = me.body["server_time"].as_i64().expect("a clock");

    (app, device, server_time)
}

/// The statuses of a response's per-event results, in order.
fn statuses(body: &Value) -> Vec<String> {
    body["results"]
        .as_array()
        .expect("a results array")
        .iter()
        .map(|result| result["status"].as_str().unwrap_or("?").to_owned())
        .collect()
}

fn reasons(body: &Value) -> Vec<Option<String>> {
    body["results"]
        .as_array()
        .expect("a results array")
        .iter()
        .map(|result| result["reason"].as_str().map(str::to_owned))
        .collect()
}

// --- the happy path ---------------------------------------------------

#[tokio::test]
async fn a_batch_is_stored_and_reported_per_event() {
    let (app, device, now) = app_with_device().await;
    let batch: Vec<Value> = (0..3).map(|n| event(n, now - 3_600)).collect();

    let response = app.send(ingest(&device, batch)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);

    assert_eq!(response.body["accepted"], 3);
    assert_eq!(response.body["duplicate"], 0);
    assert_eq!(response.body["rejected"], 0);
    assert_eq!(statuses(&response.body), ["accepted"; 3]);

    // The results are positional, so each carries its index and
    // nothing echoed back from the event itself.
    for (index, result) in response.body["results"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(result["index"], index);
        assert!(result["event_id"].is_null(), "input must not be echoed");
        assert!(result["app_id"].is_null());
    }

    assert_eq!(app.count_events().await, 3);
}

/// The property the whole design rests on: resending is always safe.
#[tokio::test]
async fn a_resent_batch_creates_no_duplicates() {
    let (app, device, now) = app_with_device().await;
    let batch: Vec<Value> = (0..5).map(|n| event(n, now - 3_600)).collect();

    let first = app.send(ingest(&device, batch.clone())).await;
    assert_eq!(first.body["accepted"], 5);

    let again = app.send(ingest(&device, batch.clone())).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body["accepted"], 0);
    assert_eq!(again.body["duplicate"], 5);
    assert_eq!(statuses(&again.body), ["duplicate"; 5]);

    // And a third time, to be sure nothing accumulates.
    app.send(ingest(&device, batch)).await;
    assert_eq!(app.count_events().await, 5);
}

/// The ordinary sync pattern: resend a window of recent events plus
/// whatever is new.
#[tokio::test]
async fn a_partly_overlapping_batch_stores_only_the_new_events() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;

    let first: Vec<Value> = (0..5).map(|n| event(n, start)).collect();
    app.send(ingest(&device, first)).await;

    let overlapping: Vec<Value> = (3..8).map(|n| event(n, start)).collect();
    let response = app.send(ingest(&device, overlapping)).await;

    assert_eq!(
        statuses(&response.body),
        ["duplicate", "duplicate", "accepted", "accepted", "accepted"]
    );
    assert_eq!(app.count_events().await, 8);
}

/// Two devices reporting the same span is expected, and ingest must
/// record both rather than resolving the overlap.
#[tokio::test]
async fn overlapping_events_from_two_devices_are_both_kept() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let laptop = app.pair_device(&session, "laptop", "linux").await;
    let phone = app.pair_device(&session, "phone", "android").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&laptop))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();

    // The same id from two devices is two events, not a duplicate.
    let overlapping = vec![json!({
        "event_id": event_id(1),
        "start_ts": now - 600,
        "duration_secs": 300,
        "app_id": "org.example.app",
    })];

    assert_eq!(
        statuses(&app.send(ingest(&laptop, overlapping.clone())).await.body),
        ["accepted"]
    );
    assert_eq!(
        statuses(&app.send(ingest(&phone, overlapping)).await.body),
        ["accepted"],
        "an event id is scoped to its device"
    );
    assert_eq!(app.count_events().await, 2);
}

/// One bad event must not cost the batch - the reason ingest answers
/// 200 with a list instead of 400.
#[tokio::test]
async fn one_rejected_event_does_not_block_the_others() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;

    let batch = vec![
        event(1, start),
        json!({
            "event_id": event_id(2),
            "start_ts": start,
            "duration_secs": 0,
            "app_id": "org.example.app",
        }),
        event(3, start),
    ];

    let response = app.send(ingest(&device, batch)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    assert_eq!(
        statuses(&response.body),
        ["accepted", "rejected", "accepted"]
    );
    assert_eq!(
        reasons(&response.body),
        [None, Some("duration_out_of_range".to_owned()), None]
    );
    assert_eq!(app.count_events().await, 2);
}

// --- validation bounds, each at the edge and one step past ------------

/// Drives one field to a value and returns the reason, if any.
async fn reason_for(app: &TestApp, device: &Device, event: Value) -> Option<String> {
    let response = app.send(ingest(device, vec![event])).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    reasons(&response.body).into_iter().next().flatten()
}

#[tokio::test]
async fn the_duration_bounds_bite_at_the_edge() {
    let (app, device, now) = app_with_device().await;
    let start = now - 90_000;

    for (n, duration, expected) in [
        (1, 0, Some("duration_out_of_range")),
        (2, 1, None),
        (3, 86_400, None),
        (4, 86_401, Some("duration_out_of_range")),
        (5, -1, Some("duration_out_of_range")),
    ] {
        let reason = reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(n),
                "start_ts": start,
                "duration_secs": duration,
                "app_id": "org.example.app",
            }),
        )
        .await;
        assert_eq!(reason.as_deref(), expected, "duration {duration}");
    }
}

#[tokio::test]
async fn the_future_bounds_bite_at_the_skew_allowance() {
    let (app, device, now) = app_with_device().await;

    // A one-second event ending exactly at the allowance.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(1),
                "start_ts": now + 299,
                "duration_secs": 1,
                "app_id": "org.example.app",
            })
        )
        .await,
        None,
        "an end exactly at the allowance must be accepted"
    );

    // One second further, and the end is past it.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(2),
                "start_ts": now + 300,
                "duration_secs": 1,
                "app_id": "org.example.app",
            })
        )
        .await
        .as_deref(),
        Some("end_ts_in_future")
    );

    // A start beyond the allowance is caught before the end is even
    // considered.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(3),
                "start_ts": now + 400,
                "duration_secs": 1,
                "app_id": "org.example.app",
            })
        )
        .await
        .as_deref(),
        Some("start_ts_in_future")
    );

    // A past event whose duration runs into the future: the case the
    // separate end rule exists for.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(4),
                "start_ts": now - 60,
                "duration_secs": 86_400,
                "app_id": "org.example.app",
            })
        )
        .await
        .as_deref(),
        Some("end_ts_in_future")
    );
}

/// The age window is configurable, so the test configures a narrow one
/// rather than trying to land on 90 days exactly.
#[tokio::test]
async fn the_age_bound_follows_the_configured_window() {
    let app = TestApp::with_vars(&[
        ("SCREENWARDEN_EVENT_MAX_AGE_SECS", "3600"),
        ("SCREENWARDEN_RATE_LIMIT_PAIR_IP", "1000/300"),
        ("SCREENWARDEN_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
        ("SCREENWARDEN_RATE_LIMIT_INGEST_DEVICE", "1000/60"),
    ])
    .await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();

    // Just inside the window.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(1),
                "start_ts": now - 3_500,
                "duration_secs": 60,
                "app_id": "org.example.app",
            })
        )
        .await,
        None
    );

    // Comfortably outside it.
    assert_eq!(
        reason_for(
            &app,
            &device,
            json!({
                "event_id": event_id(2),
                "start_ts": now - 7_200,
                "duration_secs": 60,
                "app_id": "org.example.app",
            })
        )
        .await
        .as_deref(),
        Some("start_ts_too_old")
    );
}

#[tokio::test]
async fn the_string_bounds_bite_at_the_edge() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;

    let cases: Vec<(u32, &str, Value, Option<&str>)> = vec![
        (1, "app_id at the minimum", json!({"app_id": "x"}), None),
        (
            2,
            "app_id at the maximum",
            json!({"app_id": "x".repeat(256)}),
            None,
        ),
        (
            3,
            "app_id one over",
            json!({"app_id": "x".repeat(257)}),
            Some("app_id_length"),
        ),
        (
            4,
            "app_id empty",
            json!({"app_id": ""}),
            Some("app_id_length"),
        ),
        (
            5,
            "app_id blank",
            json!({"app_id": "   "}),
            Some("app_id_blank"),
        ),
        (
            6,
            "label at the maximum",
            json!({"app_id": "org.example", "label": "x".repeat(128)}),
            None,
        ),
        (
            7,
            "label one over",
            json!({"app_id": "org.example", "label": "x".repeat(129)}),
            Some("label_length"),
        ),
        (
            8,
            "a newline in the label",
            json!({"app_id": "org.example", "label": "a\nb"}),
            Some("forbidden_character"),
        ),
        (
            9,
            "a bidi override in app_id",
            json!({"app_id": "org.example\u{202e}"}),
            Some("forbidden_character"),
        ),
    ];

    for (n, label, overrides, expected) in cases {
        let mut body = json!({
            "event_id": event_id(n),
            "start_ts": start,
            "duration_secs": 60,
            "app_id": "org.example.app",
        });
        for (key, value) in overrides.as_object().unwrap() {
            body[key] = value.clone();
        }

        assert_eq!(
            reason_for(&app, &device, body).await.as_deref(),
            expected,
            "{label}"
        );
    }
}

#[tokio::test]
async fn a_domain_must_be_a_bare_hostname() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;
    let mut n = 0;

    let mut check = |domain: &str, expected: Option<&'static str>| {
        n += 1;
        let body = json!({
            "event_id": event_id(n),
            "start_ts": start,
            "duration_secs": 60,
            "app_id": "org.example.browser",
            "domain": domain,
        });
        (body, expected, domain.to_owned())
    };

    let cases = vec![
        check("example.com", None),
        check("EXAMPLE.COM", None),
        check("sub.example.com.", None),
        check(&"a".repeat(63), None),
        check(
            &format!("{}.example", "a".repeat(64)),
            Some("domain_malformed"),
        ),
        check("https://example.com", Some("domain_malformed")),
        check("example.com/path?q=secret", Some("domain_malformed")),
        check("example.com:443", Some("domain_malformed")),
        check("user@example.com", Some("domain_malformed")),
        check("-example.com", Some("domain_malformed")),
        check("example..com", Some("domain_malformed")),
        check(&"x".repeat(254), Some("domain_length")),
    ];

    for (body, expected, domain) in cases {
        assert_eq!(
            reason_for(&app, &device, body).await.as_deref(),
            expected,
            "{domain:?}"
        );
    }

    // A hostname is stored lowercased, so two spellings are one host.
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT domain FROM events WHERE domain IS NOT NULL")
            .fetch_all(&app.pool)
            .await
            .expect("reading must succeed");
    assert!(
        stored.iter().all(|host| host == &host.to_lowercase()),
        "every stored hostname must be lowercase: {stored:?}"
    );
    assert!(
        stored.iter().any(|host| host == "example.com"),
        "EXAMPLE.COM must have folded onto example.com: {stored:?}"
    );
}

#[tokio::test]
async fn a_malformed_event_id_is_rejected_per_event() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;

    for candidate in [
        "",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdeg",
        "{01234567-89ab-cdef-0123-456789abcdef}",
        "0123-456789abcdef0123456789abcdef",
    ] {
        let reason = reason_for(
            &app,
            &device,
            json!({
                "event_id": candidate,
                "start_ts": start,
                "duration_secs": 60,
                "app_id": "org.example.app",
            }),
        )
        .await;
        assert_eq!(
            reason.as_deref(),
            Some("event_id_malformed"),
            "{candidate:?}"
        );
    }
}

/// The two accepted spellings of one id must collide, so idempotency
/// survives a client changing how it formats them.
#[tokio::test]
async fn the_dashed_and_bare_event_id_spellings_deduplicate() {
    let (app, device, now) = app_with_device().await;
    let start = now - 3_600;

    let bare = "0123456789abcdef0123456789abcdef";
    let dashed = "01234567-89ab-cdef-0123-456789abcdef";

    let make = |id: &str| {
        json!({
            "event_id": id,
            "start_ts": start,
            "duration_secs": 60,
            "app_id": "org.example.app",
        })
    };

    assert_eq!(
        statuses(&app.send(ingest(&device, vec![make(bare)])).await.body),
        ["accepted"]
    );
    assert_eq!(
        statuses(&app.send(ingest(&device, vec![make(dashed)])).await.body),
        ["duplicate"],
        "the same id in another spelling must not create a second row"
    );
    assert_eq!(app.count_events().await, 1);
}

// --- whole-request refusals -------------------------------------------

#[tokio::test]
async fn a_batch_over_the_cap_is_refused_whole() {
    let (app, device, now) = app_with_device().await;
    let start = now - 90_000;

    let at_the_cap: Vec<Value> = (0..500).map(|n| event(n, start)).collect();
    let accepted = app.send(ingest(&device, at_the_cap)).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    assert_eq!(accepted.body["accepted"], 500);

    let over_the_cap: Vec<Value> = (0..501).map(|n| event(n, start)).collect();
    let refused = app.send(ingest(&device, over_the_cap)).await;
    assert_eq!(
        refused.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{:?}",
        refused.body
    );
    assert_eq!(refused.error_code(), Some("batch_too_large"));
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_parsed() {
    let (app, device, _now) = app_with_device().await;

    // Just over 512 KiB of valid JSON.
    let filler = "x".repeat(512 * 1024);
    let body = json!({ "events": [], "padding": filler }).to_string();
    assert!(body.len() > 512 * 1024);

    let response = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .raw_json(body.into_bytes()),
        )
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// The layer order, stated as a test.
///
/// Device authentication runs before anything reads the body, so an
/// unauthenticated caller cannot make the server buffer half a
/// megabyte. If the body limit or the JSON extractor ran first this
/// would answer 413 or 400 instead.
#[tokio::test]
async fn an_unauthenticated_oversized_body_is_refused_as_unauthenticated() {
    let app = TestApp::new().await;
    app.provisioned_admin().await;

    let filler = "x".repeat(512 * 1024);
    let body = json!({ "events": [], "padding": filler }).to_string();

    let response = app
        .send(TestRequest::post("/api/v1/events").raw_json(body.into_bytes()))
        .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "authentication must run before the body is read: {:?}",
        response.body
    );
    assert_eq!(response.error_code(), Some("unauthenticated"));
}

#[tokio::test]
async fn malformed_json_and_a_missing_content_type_fail_the_request() {
    let (app, device, _now) = app_with_device().await;

    let malformed = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .raw_json(b"{ not json".to_vec()),
        )
        .await;
    assert!(malformed.status.is_client_error(), "{:?}", malformed.status);
    // The rejection must not quote the body back.
    assert!(!malformed.body.to_string().contains("not json"));

    let no_type = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(json!({ "events": [] }))
                .without_content_type(),
        )
        .await;
    assert_eq!(no_type.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn an_event_with_an_unknown_field_fails_the_request() {
    let (app, device, now) = app_with_device().await;

    let response = app
        .send(ingest(
            &device,
            vec![json!({
                "event_id": event_id(1),
                "start_ts": now - 3_600,
                "duration_secs": 60,
                "app_id": "org.example.app",
                "category": "games",
            })],
        ))
        .await;

    // A client sending the wrong schema has a bug to fix, which is
    // different from one sending an event whose values are bad. And
    // `category` in particular must never be accepted: categories are
    // assigned at query time, never stored on an event.
    assert!(response.status.is_client_error(), "{:?}", response.body);
    assert_eq!(app.count_events().await, 0);
}

// --- revocation and identity ------------------------------------------

/// Revocation takes effect on the very next request, with nothing
/// cached in between.
#[tokio::test]
async fn a_revoked_device_is_refused_on_both_device_routes() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    // Working before.
    let before = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(before.status, StatusCode::OK);
    let now = before.body["server_time"].as_i64().unwrap();

    let revoked = app
        .send(
            TestRequest::post(&format!("/api/v1/devices/{}/revoke", device.id))
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);

    // Refused immediately afterwards, on both routes.
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.error_code(), Some("unauthenticated"));

    let events = app.send(ingest(&device, vec![event(1, now - 3_600)])).await;
    assert_eq!(events.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        events.error_code(),
        Some("unauthenticated"),
        "a revoked device must not be distinguishable from an unknown one"
    );
    assert_eq!(app.count_events().await, 0);
}

#[tokio::test]
async fn device_me_reports_identity_and_the_servers_clock() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "Mika's Laptop", "macos").await;

    let response = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["id"], device.id);
    assert_eq!(response.body["name"], "Mika's Laptop");
    assert_eq!(response.body["platform"], "macos");
    assert!(response.body["server_time"].as_i64().is_some_and(|t| t > 0));

    // Identity only: nothing about the owner, and nothing about what
    // the device has reported.
    let mut keys: Vec<&str> = response
        .body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "name", "platform", "server_time"]);
}

/// `last_seen_at` is written at most once a minute, so an
/// ingest-heavy client does not turn every request into a write.
#[tokio::test]
async fn last_seen_at_is_not_written_on_every_request() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let read = || async {
        sqlx::query_scalar::<_, i64>("SELECT last_seen_at FROM devices WHERE id = ?1")
            .bind(&device.id)
            .fetch_one(&app.pool)
            .await
            .expect("the device must exist")
    };

    let at_pairing = read().await;
    for _ in 0..5 {
        app.send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
            .await;
    }
    assert_eq!(
        read().await,
        at_pairing,
        "five requests inside the interval must write once at most"
    );

    // Age the stored time past the interval; the next request writes.
    sqlx::query("UPDATE devices SET last_seen_at = last_seen_at - 120 WHERE id = ?1")
        .bind(&device.id)
        .execute(&app.pool)
        .await
        .expect("ageing must succeed");

    app.send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert!(
        read().await >= at_pairing,
        "a stale last_seen_at must be refreshed"
    );
}

#[tokio::test]
async fn a_device_token_is_refused_once_its_owner_is_deleted() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (user_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;
    let device = app.pair_device(&user, "bobs-laptop", "android").await;

    let deleted = app
        .send(
            TestRequest::delete(&format!("/api/v1/users/{user_id}"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let response = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "the device row went with the account"
    );
    assert_eq!(app.count_devices().await, 0);
}
