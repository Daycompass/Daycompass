//! `GET /category-rules` and its writes: the caller's own rules mapping
//! an `app_id` or domain to a category, adding one and deleting one.
//!
//! Same service functions and error mapping as the JSON routes; every
//! write answers with the re-rendered rule list.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{render, render_fragment, Shell};
use crate::auth::time::UnixTime;
use crate::categories::palette;
use crate::categories::service;
use crate::categories::store::CategoryRuleRecord;
use crate::error::{ApiError, ErrorKind};
use crate::routes::{categories, SessionContext};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "categories.html")]
struct CategoriesPage {
    shell: Shell,
    list: RuleList,
}

#[derive(Template)]
#[template(path = "partials/rule_list.html")]
struct RuleList {
    rules: Vec<RuleRow>,
}

struct RuleRow {
    id: String,
    kind: &'static str,
    pattern: String,
    category: String,
    /// The category's colour slot, see `categories::palette`.
    color: u32,
}

impl From<&CategoryRuleRecord> for RuleRow {
    fn from(rule: &CategoryRuleRecord) -> Self {
        Self {
            id: rule.id.clone(),
            kind: match rule.kind.as_str() {
                "domain" => "Domain",
                _ => "App",
            },
            pattern: rule.pattern.clone(),
            category: rule.category.clone(),
            color: palette::slot_for(&rule.category),
        }
    }
}

async fn own_list(state: &AppState, session: &SessionContext) -> Result<RuleList, ApiError> {
    let user_id = &session.auth().user.id;
    match service::list_own_rules(&state.pool, user_id).await {
        Ok(rules) => Ok(RuleList {
            rules: rules.iter().map(RuleRow::from).collect(),
        }),
        Err(err) => {
            tracing::error!(error = %err, "listing category rules failed");
            Err(ApiError::of(ErrorKind::InternalError))
        }
    }
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    match own_list(&state, &session).await {
        Ok(list) => render(&CategoriesPage {
            shell: Shell::for_session(session.auth(), "categories"),
            list,
        }),
        Err(error) => error.into_response(),
    }
}

async fn list_fragment(state: &AppState, session: &SessionContext) -> Response {
    match own_list(state, session).await {
        Ok(list) => render_fragment(&list),
        Err(error) => error.into_response(),
    }
}

/// The add-rule form. Same field names as the JSON body.
#[derive(Deserialize)]
pub struct CreateForm {
    kind: String,
    pattern: String,
    category: String,
}

pub async fn create(
    State(state): State<AppState>,
    session: SessionContext,
    Form(form): Form<CreateForm>,
) -> Response {
    let user_id = &session.auth().user.id;
    let result = service::create_rule(
        &state.pool,
        user_id,
        &form.kind,
        &form.pattern,
        &form.category,
        UnixTime::now(),
    )
    .await;
    match result {
        Ok(_) => list_fragment(&state, &session).await,
        Err(err) => categories::create_error(err).into_response(),
    }
}

pub async fn delete(
    State(state): State<AppState>,
    session: SessionContext,
    Path(rule_id): Path<String>,
) -> Response {
    let user_id = session.auth().user.id.clone();
    match service::delete_rule(&state.pool, &user_id, &rule_id).await {
        Ok(Some(_)) => list_fragment(&state, &session).await,
        // One answer for "no such rule" and "not yours", as on the API.
        Ok(None) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "deleting a category rule failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
