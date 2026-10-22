//! The admin-only account endpoints: `POST` and `GET /api/v1/users`,
//! `PATCH` and `DELETE /api/v1/users/{id}`.
//!
//! Thin adapters. Every rule - the password policy, username
//! normalization, the last-admin protection - lives in
//! [`crate::auth::users`], so the later dashboard drives the same code.
//!
//! What makes these admin-only is the route's entry in
//! [`crate::routes::INVENTORY`], which attaches the access layer. Asking
//! for [`AdminContext`] re-checks the role on top of that, against the
//! account record resolved for this request, so neither half alone is
//! what the authorization rests on.
//!
//! Bodies are `deny_unknown_fields`: a request with a stray or
//! misspelled field is refused rather than silently ignored, which is
//! what keeps "I sent role=admin" from quietly meaning "I sent nothing".
//! Such a rejection becomes the uniform JSON error shape through the
//! normalizing middleware, like any other malformed body, and never
//! echoes what was sent.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::password::{HashError, PasswordPolicyError};
use crate::auth::role::Role;
use crate::auth::secret::SecretString;
use crate::auth::time::UnixTime;
use crate::auth::username::UsernameError;
use crate::auth::users::{self, CreateUserError, DeleteUserError, RoleChangeError};
use crate::error::{ApiError, ErrorKind};
use crate::routes::{AdminContext, UserDetailView};
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    username: String,
    password: SecretString,
    /// Taken as a string and parsed here, so an unknown value is this
    /// server's own `invalid_role` from the closed error set rather than
    /// serde's rejection text.
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRoleRequest {
    role: String,
}

#[derive(Serialize)]
struct UserResponse {
    user: UserDetailView,
}

#[derive(Serialize)]
struct UserListResponse {
    users: Vec<UserDetailView>,
}

pub async fn create_user(
    State(state): State<AppState>,
    admin: AdminContext,
    Json(request): Json<CreateUserRequest>,
) -> Response {
    let Some(role) = Role::parse(&request.role) else {
        return ApiError::of(ErrorKind::RoleUnknown).into_response();
    };

    let result = users::create_user(
        &state.pool,
        &state.hasher,
        &request.username,
        request.password,
        role,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(user) => {
            // Who did it and who was created, by id. The username is
            // deliberately absent: it is the one field of an account
            // that identifies a person to anyone reading the logs.
            tracing::info!(
                actor_id = %admin.auth().user.id,
                user_id = %user.id,
                "admin created an account"
            );
            (
                StatusCode::CREATED,
                Json(UserResponse {
                    user: UserDetailView::from(&user),
                }),
            )
                .into_response()
        }
        Err(err) => create_error(err, &state).into_response(),
    }
}

fn create_error(err: CreateUserError, state: &AppState) -> ApiError {
    match err {
        // The policies are public rules, so naming which one failed is
        // useful rather than leaky, and none of these messages echoes
        // the input.
        CreateUserError::InvalidUsername(reason) => ApiError::of(match reason {
            UsernameError::Length => ErrorKind::UsernameLength,
            UsernameError::Charset => ErrorKind::UsernameCharset,
        }),
        CreateUserError::InvalidPassword(reason) => ApiError::of(match reason {
            PasswordPolicyError::Blank => ErrorKind::PasswordBlank,
            PasswordPolicyError::Length => ErrorKind::PasswordLength,
        }),

        // Only an admin can reach this, and an admin can list the
        // accounts anyway, so saying the name is taken is not an
        // enumeration oracle here.
        CreateUserError::UsernameTaken => ApiError::of(ErrorKind::UsernameTaken),

        // Shed, not refused: the client should come back.
        CreateUserError::Hash(HashError::Busy) => {
            ApiError::of(ErrorKind::ServerBusy).retry_after(state.hasher.wait_timeout())
        }

        CreateUserError::Hash(_) | CreateUserError::Store(_) => {
            tracing::error!(error = %err, "creating an account failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}

pub async fn list_users(State(state): State<AppState>, _admin: AdminContext) -> Response {
    match users::list_users(&state.pool).await {
        Ok(users) => {
            let body = UserListResponse {
                users: users.iter().map(UserDetailView::from).collect(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "listing accounts failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

pub async fn change_role(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
    Json(request): Json<ChangeRoleRequest>,
) -> Response {
    let Some(role) = Role::parse(&request.role) else {
        return ApiError::of(ErrorKind::RoleUnknown).into_response();
    };

    match users::change_role(&state.pool, &user_id, role).await {
        Ok(user) => {
            tracing::info!(
                actor_id = %admin.auth().user.id,
                user_id = %user.id,
                "admin changed an account's role"
            );
            (
                StatusCode::OK,
                Json(UserResponse {
                    user: UserDetailView::from(&user),
                }),
            )
                .into_response()
        }
        // The id came from the caller, so reporting that it names
        // nothing tells an admin only what they could learn from the
        // list endpoint.
        Err(RoleChangeError::NotFound) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(RoleChangeError::LastAdmin) => {
            ApiError::of(ErrorKind::LastAdminProtected).into_response()
        }
        Err(err @ RoleChangeError::Store(_)) => {
            tracing::error!(error = %err, "changing an account's role failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

pub async fn delete_user(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
) -> Response {
    match users::delete_user(&state.pool, &user_id).await {
        Ok(()) => {
            tracing::info!(
                actor_id = %admin.auth().user.id,
                user_id = %user_id,
                "admin deleted an account"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(DeleteUserError::NotFound) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(DeleteUserError::LastAdmin) => {
            ApiError::of(ErrorKind::LastAdminProtected).into_response()
        }
        Err(err @ DeleteUserError::Store(_)) => {
            tracing::error!(error = %err, "deleting an account failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
