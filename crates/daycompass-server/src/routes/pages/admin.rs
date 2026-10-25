//! The admin pages: `/admin/users` and `/admin/devices`.
//!
//! Account and device *management*, nothing else. Like their JSON
//! counterparts, these read account rows and device metadata only - an
//! admin sees that a device exists, whose it is and when it last
//! synced, never what it reported. `tests/no_event_reads.rs` sweeps
//! these pages with every other `GET`.
//!
//! Every action goes through the same shared function as the API
//! (`routes::users::*_for_admin`, `routes::devices::revoke_any_for_admin`),
//! so the last-admin rule, the account-log entry a reset writes and the
//! log lines are identical whichever surface was used.
//!
//! # The password reset
//!
//! `CLAUDE.md` names this as a known limit: an admin who resets a
//! password receives the invite and could redeem it themselves, which
//! is an account takeover. A button makes that one click rather than
//! one API call, which changes nothing about who can do it. The
//! confirmation says what the reset does, and the invite is shown once,
//! with an instruction to hand it to the account holder.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{format_utc, render, Shell};
use crate::auth::invite::IssuedInvite;
use crate::auth::store::UserSummary;
use crate::auth::users;
use crate::devices::service;
use crate::devices::store::DeviceWithOwner;
use crate::error::{ApiError, ErrorKind};
use crate::routes::{devices, users as user_routes, AdminContext};
use crate::state::AppState;

// --- accounts --------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_accounts.html")]
struct AccountsPage {
    shell: Shell,
    list: AccountList,
}

/// The account list, as the page's and every action's answer. After a
/// create or a reset it carries the new invite, shown once.
#[derive(Template)]
#[template(path = "partials/account_list.html")]
struct AccountList {
    accounts: Vec<AccountRow>,
    /// The admin looking at the list, so their own row offers no
    /// delete.
    own_id: String,
    invite: Option<InviteNotice>,
}

struct AccountRow {
    id: String,
    username: String,
    is_admin: bool,
    pending: bool,
    created: String,
}

impl From<&UserSummary> for AccountRow {
    fn from(user: &UserSummary) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.as_str().to_owned(),
            is_admin: user.role.is_admin(),
            pending: user.status.as_str() == "pending",
            created: format_utc(user.created_at.as_secs()),
        }
    }
}

/// An invite just issued, for the account it belongs to.
struct InviteNotice {
    username: String,
    token: String,
    expires: String,
    /// Set for a reset: what it ended along the way.
    reset: Option<(u64, u64)>,
}

impl InviteNotice {
    fn of(issued: &IssuedInvite, reset: Option<(u64, u64)>) -> Self {
        Self {
            username: issued.user.username.as_str().to_owned(),
            token: issued.token.expose().to_owned(),
            expires: format_utc(issued.expires_at.as_secs()),
            reset,
        }
    }
}

async fn account_list(
    state: &AppState,
    admin: &AdminContext,
    invite: Option<InviteNotice>,
) -> Result<AccountList, ApiError> {
    match users::list_users(&state.pool).await {
        Ok(accounts) => Ok(AccountList {
            accounts: accounts.iter().map(AccountRow::from).collect(),
            own_id: admin.auth().user.id.clone(),
            invite,
        }),
        Err(err) => {
            tracing::error!(error = %err, "listing accounts failed");
            Err(ApiError::of(ErrorKind::InternalError))
        }
    }
}

async fn account_fragment(
    state: &AppState,
    admin: &AdminContext,
    invite: Option<InviteNotice>,
) -> Response {
    match account_list(state, admin, invite).await {
        Ok(list) => render(&list),
        Err(error) => error.into_response(),
    }
}

pub async fn accounts_page(State(state): State<AppState>, admin: AdminContext) -> Response {
    match account_list(&state, &admin, None).await {
        Ok(list) => render(&AccountsPage {
            shell: Shell::for_session(admin.auth(), "admin-accounts"),
            list,
        }),
        Err(error) => error.into_response(),
    }
}

/// The create-account form. Same field names as the JSON body.
#[derive(Deserialize)]
pub struct CreateForm {
    username: String,
    role: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    admin: AdminContext,
    Form(form): Form<CreateForm>,
) -> Response {
    match user_routes::create_for_admin(&state, &admin, &form.username, &form.role).await {
        Ok(issued) => account_fragment(&state, &admin, Some(InviteNotice::of(&issued, None))).await,
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
pub struct RoleForm {
    role: String,
}

pub async fn change_role(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
    Form(form): Form<RoleForm>,
) -> Response {
    match user_routes::change_role_for_admin(&state, &admin, &user_id, &form.role).await {
        Ok(_) => account_fragment(&state, &admin, None).await,
        Err(error) => error.into_response(),
    }
}

pub async fn reset_password(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
) -> Response {
    match user_routes::reset_for_admin(&state, &admin, &user_id).await {
        Ok(report) => {
            let notice = InviteNotice::of(
                &report.invite,
                Some((report.sessions_ended, report.devices_revoked)),
            );
            account_fragment(&state, &admin, Some(notice)).await
        }
        Err(error) => error.into_response(),
    }
}

pub async fn delete_account(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(user_id): Path<String>,
) -> Response {
    match user_routes::delete_for_admin(&state, &admin, &user_id).await {
        Ok(()) => account_fragment(&state, &admin, None).await,
        Err(error) => error.into_response(),
    }
}

// --- devices ---------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_devices.html")]
struct DevicesPage {
    shell: Shell,
    list: DeviceList,
}

#[derive(Template)]
#[template(path = "partials/admin_device_list.html")]
struct DeviceList {
    devices: Vec<DeviceRow>,
}

/// The same fields as `AdminDeviceView`, formatted. Metadata only.
struct DeviceRow {
    id: String,
    owner: String,
    name: String,
    platform: &'static str,
    last_seen: String,
    revoked: Option<String>,
}

impl From<&DeviceWithOwner> for DeviceRow {
    fn from(row: &DeviceWithOwner) -> Self {
        Self {
            id: row.device.id.clone(),
            owner: row.owner_username.clone(),
            name: row.device.name.as_str().to_owned(),
            platform: row.device.platform.as_str(),
            last_seen: format_utc(row.device.last_seen_at.as_secs()),
            revoked: row.device.revoked_at.map(|at| format_utc(at.as_secs())),
        }
    }
}

async fn device_list(state: &AppState) -> Result<DeviceList, ApiError> {
    match service::list_all_devices(&state.pool).await {
        Ok(rows) => Ok(DeviceList {
            devices: rows.iter().map(DeviceRow::from).collect(),
        }),
        Err(err) => {
            tracing::error!(error = %err, "listing all devices failed");
            Err(ApiError::of(ErrorKind::InternalError))
        }
    }
}

pub async fn devices_page(State(state): State<AppState>, admin: AdminContext) -> Response {
    match device_list(&state).await {
        Ok(list) => render(&DevicesPage {
            shell: Shell::for_session(admin.auth(), "admin-devices"),
            list,
        }),
        Err(error) => error.into_response(),
    }
}

pub async fn revoke_device(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(device_id): Path<String>,
) -> Response {
    match devices::revoke_any_for_admin(&state, &admin, &device_id).await {
        Ok(_) => match device_list(&state).await {
            Ok(list) => render(&list),
            Err(error) => error.into_response(),
        },
        Err(err) => devices::action_error(err).into_response(),
    }
}
