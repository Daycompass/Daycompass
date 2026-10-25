//! `GET /api/v1/stats` - an account's own screen time, summed per UTC
//! calendar day and category.
//!
//! Session auth, no CSRF (a `GET`), no admin variant - same shape as
//! `GET /api/v1/events`, and for the same reason: see
//! `crate::stats`'s module doc.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::stats::aggregate::{self, AggregateError, DailyCategoryTotal, RangeError};

/// `start_ts` and `end_ts` on `GET /api/v1/stats`, both required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsQueryParams {
    start_ts: i64,
    end_ts: i64,
}

/// One day's total for one category, as handed back to its owner.
#[derive(Serialize)]
struct DailyCategoryTotalView {
    day_start_ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    total_duration_secs: i64,
}

impl From<DailyCategoryTotal> for DailyCategoryTotalView {
    fn from(total: DailyCategoryTotal) -> Self {
        Self {
            day_start_ts: total.day_start_ts,
            category: total.category,
            total_duration_secs: total.total_duration_secs,
        }
    }
}

#[derive(Serialize)]
struct StatsResponse {
    days: Vec<DailyCategoryTotalView>,
}

/// An account's own screen time, inside `[start_ts, end_ts)`, summed
/// per UTC calendar day and category.
///
/// Session-authenticated, scoped to the caller alone - no admin
/// variant and no id parameter that could point it at anyone else,
/// same shape as `GET /api/v1/events`.
pub async fn daily_totals(
    State(state): State<AppState>,
    session: SessionContext,
    Query(params): Query<StatsQueryParams>,
) -> Response {
    let user_id = &session.auth().user.id;

    match aggregate::daily_totals(&state.pool, user_id, params.start_ts, params.end_ts).await {
        Ok(days) => (
            StatusCode::OK,
            Json(StatsResponse {
                days: days.into_iter().map(DailyCategoryTotalView::from).collect(),
            }),
        )
            .into_response(),
        Err(AggregateError::Range(RangeError::Inverted)) => {
            ApiError::of(ErrorKind::StatsRangeInverted).into_response()
        }
        Err(AggregateError::Range(RangeError::TooWide)) => {
            ApiError::of(ErrorKind::StatsRangeTooWide).into_response()
        }
        Err(AggregateError::Store(err)) => {
            tracing::error!(error = %err, user_id = %user_id, "aggregating stats failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
