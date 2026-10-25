//! `GET /healthz`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use sqlx::SqlitePool;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
struct HealthzBody {
    status: &'static str,
}

/// Reports whether the database is reachable. The response never
/// contains the underlying error - that is logged separately - so a
/// client only ever learns "ok" or "not ok", nothing more specific.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    operation_id = "healthz",
    summary = "Liveness and database reachability",
    responses(
        (status = 200, description = "The server is up and its database answers.", body = HealthzBody),
        (status = 503, description = "The database is not reachable. Empty body."),
    )
)]
pub async fn healthz(State(pool): State<SqlitePool>) -> Response {
    match crate::db::check_reachable(&pool).await {
        Ok(()) => (StatusCode::OK, Json(HealthzBody { status: "ok" })).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "healthz: database is not reachable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
