//! `GET /devices` and its writes: the caller's own devices, renaming and
//! revoking one, and creating a pairing code.
//!
//! Every write answers with the re-rendered device list (or, for a new
//! pairing code, the code itself), which htmx swaps into the page. The
//! work and the errors are the JSON routes': the same service functions,
//! always scoped to the caller with [`Scope::Owner`], and the same error
//! mapping, so "no such device" and "not yours" stay one answer here too.

use askama::Template;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{format_utc, render, render_fragment, Shell};
use crate::auth::time::UnixTime;
use crate::devices::service;
use crate::devices::store::{DeviceRecord, Scope};
use crate::error::{ApiError, ErrorKind};
use crate::routes::{devices, pairing, SessionContext};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesPage {
    shell: Shell,
    list: DeviceList,
}

/// The list on its own, as a write's answer.
#[derive(Template)]
#[template(path = "partials/device_list.html")]
struct DeviceList {
    devices: Vec<DeviceRow>,
}

struct DeviceRow {
    id: String,
    name: String,
    platform: &'static str,
    paired: String,
    last_seen: String,
    /// When it was revoked, for a revoked device.
    revoked: Option<String>,
}

impl From<&DeviceRecord> for DeviceRow {
    fn from(device: &DeviceRecord) -> Self {
        Self {
            id: device.id.clone(),
            name: device.name.as_str().to_owned(),
            platform: device.platform.as_str(),
            paired: format_utc(device.created_at.as_secs()),
            last_seen: format_utc(device.last_seen_at.as_secs()),
            revoked: device.revoked_at.map(|at| format_utc(at.as_secs())),
        }
    }
}

/// A freshly created pairing code, shown once.
#[derive(Template)]
#[template(path = "partials/pairing_code.html")]
struct PairingCodeView {
    code: String,
    expires: String,
}

async fn own_list(state: &AppState, session: &SessionContext) -> Result<DeviceList, ApiError> {
    let user_id = &session.auth().user.id;
    match service::list_own_devices(&state.pool, user_id).await {
        Ok(devices) => Ok(DeviceList {
            devices: devices.iter().map(DeviceRow::from).collect(),
        }),
        Err(err) => {
            tracing::error!(error = %err, "listing devices failed");
            Err(ApiError::of(ErrorKind::InternalError))
        }
    }
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    match own_list(&state, &session).await {
        Ok(list) => render(&DevicesPage {
            shell: Shell::for_session(session.auth(), "devices"),
            list,
        }),
        Err(error) => error.into_response(),
    }
}

/// The re-rendered list, after a write that succeeded.
async fn list_fragment(state: &AppState, session: &SessionContext) -> Response {
    match own_list(state, session).await {
        Ok(list) => render_fragment(&list),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
pub struct RenameForm {
    name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    session: SessionContext,
    Path(device_id): Path<String>,
    Form(form): Form<RenameForm>,
) -> Response {
    let user_id = session.auth().user.id.clone();
    let result =
        service::rename_device(&state.pool, Scope::Owner(&user_id), &device_id, &form.name).await;
    match result {
        Ok(_) => list_fragment(&state, &session).await,
        Err(err) => devices::action_error(err).into_response(),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    session: SessionContext,
    Path(device_id): Path<String>,
) -> Response {
    let user_id = session.auth().user.id.clone();
    let result = service::revoke_device(
        &state.pool,
        Scope::Owner(&user_id),
        &device_id,
        UnixTime::now(),
    )
    .await;
    match result {
        Ok(_) => list_fragment(&state, &session).await,
        Err(err) => devices::action_error(err).into_response(),
    }
}

pub async fn create_pairing_code(
    State(state): State<AppState>,
    session: SessionContext,
) -> Response {
    let user_id = &session.auth().user.id;
    match service::create_pairing_code(&state.pool, user_id, UnixTime::now()).await {
        // The one place besides the JSON route that the plaintext leaves
        // the server: in this response, to the account that owns it,
        // which is `no-store` like every page.
        Ok(created) => render_fragment(&PairingCodeView {
            code: created.code.display().expose().to_owned(),
            expires: format_utc(created.expires_at.as_secs()),
        }),
        Err(err) => pairing::create_code_error(err).into_response(),
    }
}
