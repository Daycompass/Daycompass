//! `GET /api/v1/export` - an account downloads everything it has.
//!
//! Session auth, no CSRF (a `GET`), no admin variant - same shape as
//! `GET /api/v1/events`, for the same reason. Thin on purpose: what the
//! document holds and how it is paged is [`crate::export`]'s business;
//! this only names the download.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::export::service;
use crate::routes::SessionContext;
use crate::state::AppState;

/// Fixed, never derived from the account: a username in a header would
/// be one more place it could end up logged.
const CONTENT_DISPOSITION: &str = "attachment; filename=\"daycompass-export.json\"";

/// The route takes no parameters. Parsed anyway, so a stray one is
/// refused like on every other route here rather than silently
/// ignored - a client sending `?user_id=` has a bug worth surfacing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportParams {}

#[utoipa::path(
    get,
    path = "/api/v1/export",
    tag = "events",
    operation_id = "export",
    summary = "Download everything your account holds, as one JSON document",
    responses(
        (status = 200, description = "Streamed. Accept it only if it parses and ends with `\"complete\": true`.", body = crate::export::format::Document,
            headers(("Content-Disposition" = String, description = "`attachment; filename=\"daycompass-export.json\"`"))),
    )
)]
pub async fn export_own(
    State(state): State<AppState>,
    session: SessionContext,
    Query(_params): Query<ExportParams>,
) -> Response {
    let user = &session.auth().user;

    match service::export_own(&state.pool, user, UnixTime::now()).await {
        Ok(stream) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CONTENT_DISPOSITION, CONTENT_DISPOSITION),
            ],
            Body::from_stream(stream),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, user_id = %user.id, "starting the account export failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
