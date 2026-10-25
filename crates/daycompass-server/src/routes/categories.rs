//! `POST`, `GET /api/v1/category-rules` and
//! `DELETE /api/v1/category-rules/{id}`: an account's own category
//! rules.
//!
//! Session-scoped only, exactly like `GET /api/v1/events`: an admin
//! manages accounts and devices but must never read or shape another
//! account's categorization. There is no admin variant, no admin list,
//! and no id parameter that could name another account - these three
//! routes take the caller's own id from the session the access layer
//! already resolved, never from the request.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::time::UnixTime;
use crate::categories::kind::PatternError;
use crate::categories::label::CategoryLabelError;
use crate::categories::service::{self, CreateRuleError};
use crate::categories::store::CategoryRuleRecord;
use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRuleRequest {
    kind: String,
    pattern: String,
    category: String,
}

/// One rule as handed back to its owner.
///
/// No `user_id`: the caller already knows which account they are,
/// same reasoning as other owner-scoped views in this server.
#[derive(Serialize, ToSchema)]
struct RuleView {
    id: String,
    kind: &'static str,
    pattern: String,
    category: String,
    created_at: i64,
}

impl From<&CategoryRuleRecord> for RuleView {
    fn from(rule: &CategoryRuleRecord) -> Self {
        Self {
            id: rule.id.clone(),
            kind: rule.kind.as_str(),
            pattern: rule.pattern.clone(),
            category: rule.category.clone(),
            created_at: rule.created_at.as_secs(),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct RuleResponse {
    rule: RuleView,
}

#[derive(Serialize, ToSchema)]
struct RuleListResponse {
    rules: Vec<RuleView>,
}

#[utoipa::path(
    post,
    path = "/api/v1/category-rules",
    tag = "categories",
    operation_id = "create_category_rule",
    summary = "Add a rule mapping an app_id or domain to a category",
    request_body = CreateRuleRequest,
    responses(
        (status = 201, description = "Created.", body = RuleResponse),
        (status = 400, description = "`invalid_category_rule_kind`, `invalid_category_pattern` or `invalid_category_label`.", body = crate::error::ErrorBody),
        (status = 409, description = "`category_rule_duplicate` or `category_rule_limit_reached`.", body = crate::error::ErrorBody),
    )
)]
pub async fn create_own(
    State(state): State<AppState>,
    session: SessionContext,
    Json(request): Json<CreateRuleRequest>,
) -> Response {
    let user_id = &session.auth().user.id;

    let result = service::create_rule(
        &state.pool,
        user_id,
        &request.kind,
        &request.pattern,
        &request.category,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(rule) => (
            StatusCode::CREATED,
            Json(RuleResponse {
                rule: RuleView::from(&rule),
            }),
        )
            .into_response(),
        Err(err) => create_error(err).into_response(),
    }
}

/// Ordered `created_at, id` ascending, same convention as
/// `GET /api/v1/devices`.
#[utoipa::path(
    get,
    path = "/api/v1/category-rules",
    tag = "categories",
    operation_id = "list_category_rules",
    summary = "Your own category rules",
    responses(
        (status = 200, description = "Your rules.", body = RuleListResponse),
    )
)]
pub async fn list_own(State(state): State<AppState>, session: SessionContext) -> Response {
    let user_id = &session.auth().user.id;

    match service::list_own_rules(&state.pool, user_id).await {
        Ok(rules) => (
            StatusCode::OK,
            Json(RuleListResponse {
                rules: rules.iter().map(RuleView::from).collect(),
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "listing category rules failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/category-rules/{id}",
    tag = "categories",
    operation_id = "delete_category_rule",
    summary = "Delete one of your category rules",
    params(("id" = String, Path, description = "The rule id.")),
    responses(
        (status = 204, description = "Deleted."),
        (status = 404, description = "`not_found`: no such rule, or not yours.", body = crate::error::ErrorBody),
    )
)]
pub async fn delete_own(
    State(state): State<AppState>,
    session: SessionContext,
    Path(rule_id): Path<String>,
) -> Response {
    let user_id = session.auth().user.id.clone();

    match service::delete_rule(&state.pool, &user_id, &rule_id).await {
        Ok(Some(_)) => StatusCode::NO_CONTENT.into_response(),
        // One answer for "no such rule" and "not yours" - an owner
        // must not be able to probe which rule ids exist on other
        // accounts, same reasoning as the device routes.
        Ok(None) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "deleting a category rule failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

/// Shared with the dashboard's category page, so both answer alike.
pub(super) fn create_error(err: CreateRuleError) -> ApiError {
    match err {
        CreateRuleError::UnknownKind => ApiError::of(ErrorKind::CategoryRuleKindUnknown),
        CreateRuleError::InvalidPattern(reason) => ApiError::of(match reason {
            PatternError::Blank => ErrorKind::CategoryPatternBlank,
            PatternError::Length => ErrorKind::CategoryPatternLength,
            PatternError::Malformed => ErrorKind::CategoryPatternMalformed,
            PatternError::Charset => ErrorKind::CategoryPatternCharset,
        }),
        CreateRuleError::InvalidLabel(reason) => ApiError::of(match reason {
            CategoryLabelError::Length => ErrorKind::CategoryLabelLength,
            CategoryLabelError::Charset => ErrorKind::CategoryLabelCharset,
        }),
        CreateRuleError::Duplicate => ApiError::of(ErrorKind::CategoryRuleDuplicate),
        CreateRuleError::TooMany => ApiError::of(ErrorKind::CategoryRuleLimitReached),
        CreateRuleError::Store(_) => {
            tracing::error!(error = %err, "creating a category rule failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}
