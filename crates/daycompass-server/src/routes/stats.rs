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
use utoipa::{IntoParams, ToSchema};

use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::stats::aggregate::{self, AggregateError, DailyCategoryTotal, RangeError};
use crate::timezone::{self, TimeZoneName};

/// `start_ts` and `end_ts` on `GET /api/v1/stats`, both required.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct StatsQueryParams {
    /// Inclusive start of the window, Unix seconds.
    start_ts: i64,
    /// Exclusive end of the window, Unix seconds.
    end_ts: i64,
    /// Where a day starts: `utc` (the default) or `account`, the time
    /// zone set with `PATCH /api/v1/account/timezone`.
    #[serde(default)]
    day_boundary: DayBoundary,
}

/// Which midnight separates one day's total from the next.
#[derive(Deserialize, ToSchema, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum DayBoundary {
    #[default]
    Utc,
    Account,
}

/// One day's total for one category, as handed back to its owner.
#[derive(Serialize, ToSchema)]
struct DailyCategoryTotalView {
    day_start_ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
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

#[derive(Serialize, ToSchema)]
struct StatsResponse {
    days: Vec<DailyCategoryTotalView>,
}

/// An account's own screen time, inside `[start_ts, end_ts)`, summed
/// per calendar day (UTC, or the account's zone) and category.
///
/// Session-authenticated, scoped to the caller alone - no admin
/// variant and no id parameter that could point it at anyone else,
/// same shape as `GET /api/v1/events`.
#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "events",
    operation_id = "stats",
    summary = "Your screen time per day and category, at most 366 days",
    params(StatsQueryParams),
    responses(
        (status = 200, description = "Sparse daily totals.", body = StatsResponse),
        (status = 400, description = "`invalid_stats_range`, or `bad_request` for a missing or unknown parameter.", body = crate::error::ErrorBody),
    )
)]
pub async fn daily_totals(
    State(state): State<AppState>,
    session: SessionContext,
    Query(params): Query<StatsQueryParams>,
) -> Response {
    let user_id = &session.auth().user.id;

    let zone = match params.day_boundary {
        DayBoundary::Utc => TimeZoneName::utc(),
        DayBoundary::Account => match timezone::get_for_user(&state.pool, user_id).await {
            Ok(zone) => zone,
            Err(err) => {
                tracing::error!(error = %err, user_id = %user_id, "reading the time zone failed");
                return ApiError::of(ErrorKind::InternalError).into_response();
            }
        },
    };

    match aggregate::daily_totals(&state.pool, user_id, params.start_ts, params.end_ts, &zone).await
    {
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
