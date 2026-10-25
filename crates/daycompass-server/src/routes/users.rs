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
use utoipa::ToSchema;

use crate::auth::invite::{CreatePendingAccountError, IssuedInvite, ResetPasswordError};
use crate::auth::role::Role;
use crate::auth::time::UnixTime;
use crate::auth::username::UsernameError;
use crate::auth::users::{self, DeleteUserError, RoleChangeError};
use crate::error::{ApiError, ErrorKind};
use crate::routes::{AdminContext, UserDetailView};
use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    username: String,
    /// Taken as a string and parsed here, so an unknown value is this
    /// server's own `invalid_role` from the closed error set rather than
    /// serde's rejection text.
    role: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeRoleRequest {
    role: String,
}

#[derive(Serialize, ToSchema)]
struct UserResponse {
    user: UserDetailView,
}

#[derive(Serialize, ToSchema)]
struct UserListResponse {
    users: Vec<UserDetailView>,
}

/// What a created or reset account's invite looks like on the wire.
///
/// The token is a plain `String`, built in exactly one place
/// (`token.expose().to_owned()`, here): `SecretString` has no
/// `Serialize` impl on purpose, and this is the one spot that is
/// allowed to read the plaintext out of a [`crate::auth::token::Token`]
/// and hand it to a client - the only time it ever will.
#[derive(Serialize, ToSchema)]
struct InviteView {
    token: String,
    expires_at: i64,
}

impl From<IssuedInvite> for InviteView {
    fn from(issued: IssuedInvite) -> Self {
        Self {
            token: issued.token.expose().to_owned(),
            expires_at: issued.expires_at.as_secs(),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct CreateUserResponse {
    user: UserDetailView,
    invite: InviteView,
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "accounts",
    operation_id = "create_user",
    summary = "Create a pending account and its invite (admin)",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "Created, pending until the invite is redeemed.", body = CreateUserResponse),
        (status = 400, description = "`invalid_username` or `invalid_role`.", body = crate::error::ErrorBody),
        (status = 409, description = "`username_taken`.", body = crate::error::ErrorBody),
    )
)]
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
        &request.username,
        role,
        state.invite_policy,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(issued) => {
            // Who did it and who was created, by id. The username is
            // deliberately absent: it is the one field of an account
            // that identifies a person to anyone reading the logs.
            tracing::info!(
                actor_id = %admin.auth().user.id,
                user_id = %issued.user.id,
                "admin created a pending account"
            );
            let user = UserDetailView::from(&issued.user);
            (
                StatusCode::CREATED,
                Json(CreateUserResponse {
                    user,
                    invite: InviteView::from(issued),
                }),
            )
                .into_response()
        }
        Err(err) => create_error(err).into_response(),
    }
}

fn create_error(err: CreatePendingAccountError) -> ApiError {
    match err {
        // A public rule, so naming which one failed is useful rather
        // than leaky, and the message never echoes the input.
        CreatePendingAccountError::InvalidUsername(reason) => ApiError::of(match reason {
            UsernameError::Length => ErrorKind::UsernameLength,
            UsernameError::Charset => ErrorKind::UsernameCharset,
        }),

        // Only an admin can reach this, and an admin can list the
        // accounts anyway, so saying the name is taken is not an
        // enumeration oracle here.
        CreatePendingAccountError::UsernameTaken => ApiError::of(ErrorKind::UsernameTaken),

        CreatePendingAccountError::Rng(_) | CreatePendingAccountError::Store(_) => {
            tracing::error!(error = %err, "creating a pending account failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}

/// Resets an account to pending, in place of whatever password it had.
///
/// Every session the account held is ended and every device it paired
/// is revoked, in the same transaction as the reset - see
/// `crate::auth::invite::reset_password`. The response reports how many
/// of each, so the admin performing the reset is not surprised by it.
#[utoipa::path(
    post,
    path = "/api/v1/users/{id}/password-reset",
    tag = "accounts",
    operation_id = "reset_password",
    summary = "Reset an account to pending with a fresh invite (admin)",
    params(("id" = String, Path, description = "The account id.")),
    responses(
        (status = 200, description = "Reset. Every session ended, every device revoked.", body = ResetPasswordResponse),
        (status = 404, description = "`not_found`.", body = crate::error::ErrorBody),
        (status = 409, description = "`last_admin_protected`.", body = crate::error::ErrorBody),
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
) -> Response {
    let result = crate::auth::invite::reset_password(
        &state.pool,
        &user_id,
        &admin.auth().user.id,
        state.invite_policy,
        UnixTime::now(),
    )
    .await;

    match result {
        Ok(report) => {
            tracing::info!(
                actor_id = %admin.auth().user.id,
                user_id = %user_id,
                sessions_ended = report.sessions_ended,
                devices_revoked = report.devices_revoked,
                "admin reset an account to pending"
            );
            (
                StatusCode::OK,
                Json(ResetPasswordResponse {
                    invite: InviteView::from(report.invite),
                    sessions_ended: report.sessions_ended,
                    devices_revoked: report.devices_revoked,
                }),
            )
                .into_response()
        }
        // The id came from the caller, so reporting that it names
        // nothing tells an admin only what they could learn from the
        // list endpoint.
        Err(ResetPasswordError::NotFound) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(ResetPasswordError::LastAdmin) => {
            ApiError::of(ErrorKind::LastAdminProtected).into_response()
        }
        Err(err @ (ResetPasswordError::Rng(_) | ResetPasswordError::Store(_))) => {
            tracing::error!(error = %err, "resetting an account failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

#[derive(Serialize, ToSchema)]
struct ResetPasswordResponse {
    invite: InviteView,
    sessions_ended: u64,
    devices_revoked: u64,
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "accounts",
    operation_id = "list_users",
    summary = "Every account on the instance (admin)",
    responses(
        (status = 200, description = "All accounts.", body = UserListResponse),
    )
)]
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

#[utoipa::path(
    patch,
    path = "/api/v1/users/{id}",
    tag = "accounts",
    operation_id = "change_role",
    summary = "Change an account's role (admin)",
    params(("id" = String, Path, description = "The account id.")),
    request_body = ChangeRoleRequest,
    responses(
        (status = 200, description = "Changed.", body = UserResponse),
        (status = 400, description = "`invalid_role`.", body = crate::error::ErrorBody),
        (status = 404, description = "`not_found`.", body = crate::error::ErrorBody),
        (status = 409, description = "`last_admin_protected`.", body = crate::error::ErrorBody),
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}",
    tag = "accounts",
    operation_id = "delete_user",
    summary = "Delete an account and everything it owns (admin)",
    params(("id" = String, Path, description = "The account id.")),
    responses(
        (status = 204, description = "Deleted."),
        (status = 404, description = "`not_found`.", body = crate::error::ErrorBody),
        (status = 409, description = "`last_admin_protected`.", body = crate::error::ErrorBody),
    )
)]
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
