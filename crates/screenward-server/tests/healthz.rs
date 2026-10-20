//! Integration tests for the HTTP app, against an in-memory SQLite
//! database. No users, auth, or domain tables exist yet to test.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use sqlx::SqlitePool;
use tower::ServiceExt;

use screenward_server::config::Config;
use screenward_server::db::{connect, migrate, DbTarget};
use screenward_server::state::AppState;

async fn migrated_pool() -> SqlitePool {
    let pool = connect(&DbTarget::Memory)
        .await
        .expect("in-memory pool must connect");
    migrate(&pool).await.expect("migrations must apply");
    pool
}

/// Application state over `pool`, using the default configuration.
fn test_state(pool: SqlitePool) -> AppState {
    AppState::new(pool, &Config::defaults())
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("reading the body must not fail");
    serde_json::from_slice(&bytes).expect("body must be valid JSON")
}

#[tokio::test]
async fn healthz_returns_200_with_db_reachable() {
    let app = screenward_server::build_app(test_state(migrated_pool().await));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn healthz_response_has_no_internal_details() {
    let app = screenward_server::build_app(test_state(migrated_pool().await));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    for forbidden in ["sqlite", "sqlx", ".sqlite3", "/data", "panic", "Error"] {
        assert!(
            !text.contains(forbidden),
            "response leaked an internal detail: {forbidden:?} in {text:?}"
        );
    }
}

#[tokio::test]
async fn healthz_returns_503_with_no_internal_details_when_db_is_unreachable() {
    let pool = migrated_pool().await;
    pool.close().await; // simulate the database becoming unreachable

    let app = screenward_server::build_app(test_state(pool));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "service_unavailable");
    assert_eq!(body["error"]["message"], "service unavailable");
    let body_text = body.to_string();
    for forbidden in ["sqlx", "pool", "closed", ".sqlite3"] {
        assert!(
            !body_text.to_ascii_lowercase().contains(forbidden),
            "503 body leaked an internal detail: {forbidden:?} in {body_text:?}"
        );
    }
}

#[tokio::test]
async fn unknown_route_returns_uniform_json_error() {
    let app = screenward_server::build_app(test_state(migrated_pool().await));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "not_found");
    assert_eq!(body["error"]["message"], "not found");
}

#[tokio::test]
async fn responses_carry_a_request_id_and_security_headers() {
    let app = screenward_server::build_app(test_state(migrated_pool().await));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let headers = response.headers();
    assert!(
        headers.get("x-request-id").is_some(),
        "missing x-request-id"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn error_responses_also_carry_security_headers() {
    let app = screenward_server::build_app(test_state(migrated_pool().await));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let headers = response.headers();
    assert!(
        headers.get("x-request-id").is_some(),
        "missing x-request-id on an error response"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}
