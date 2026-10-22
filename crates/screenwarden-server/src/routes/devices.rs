//! Device management: an owner's own devices, and an admin's view of
//! all of them.
//!
//! `GET /api/v1/devices`, `PATCH /api/v1/devices/{id}` and
//! `POST /api/v1/devices/{id}/revoke` are owner-scoped. The owner's id
//! comes from the session the access layer resolved and is passed to
//! the store as a [`Scope`], so a handler cannot reach somebody else's
//! device by forgetting a `WHERE` clause.
//!
//! `GET /api/v1/admin/devices` and
//! `POST /api/v1/admin/devices/{id}/revoke` are admin-scoped.
//!
//! # What an admin may and may not see
//!
//! Metadata, and only metadata: id, owner, name, platform, and the
//! three timestamps. An admin manages accounts and devices and must
//! never reach a single event. That is not enforced by discipline
//! here - there is no service function that would return one, no
//! query in [`crate::devices::store`] that names the `events` table,
//! and `tests/no_event_reads.rs` fails the build if either stops
//! being true.
//!
//! # Revoking is not deleting
//!
//! Hence `POST .../revoke` rather than `DELETE`. The row stays, every
//! event the device reported stays, and the device simply stops being
//! able to authenticate - on its very next request, because
//! [`crate::auth::device::resolve`] re-reads the row every time.
//!
//! Revoking twice is not an error. The second call reports the same
//! state without claiming it just happened.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::time::UnixTime;
use crate::devices::name::DeviceNameError;
use crate::devices::service::{self, DeviceActionError};
use crate::devices::store::Scope;
use crate::error::{ApiError, ErrorKind};
use crate::routes::{AdminContext, AdminDeviceView, DeviceView, SessionContext};
use crate::state::AppState;

#[derive(Serialize)]
struct DeviceResponse {
    device: DeviceView,
}

#[derive(Serialize)]
struct DeviceListResponse {
    devices: Vec<DeviceView>,
}

#[derive(Serialize)]
struct AdminDeviceListResponse {
    devices: Vec<AdminDeviceView>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    name: String,
}

pub async fn list_own(State(state): State<AppState>, session: SessionContext) -> Response {
    let user_id = &session.auth().user.id;

    match service::list_own_devices(&state.pool, user_id).await {
        Ok(devices) => (
            StatusCode::OK,
            Json(DeviceListResponse {
                devices: devices.iter().map(DeviceView::from).collect(),
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "listing devices failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

pub async fn rename_own(
    State(state): State<AppState>,
    session: SessionContext,
    Path(device_id): Path<String>,
    Json(request): Json<RenameRequest>,
) -> Response {
    let user_id = session.auth().user.id.clone();

    let result = service::rename_device(
        &state.pool,
        Scope::Owner(&user_id),
        &device_id,
        &request.name,
    )
    .await;
    device_response(result)
}

pub async fn revoke_own(
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
    revoke_response(result)
}

pub async fn list_all(State(state): State<AppState>, _admin: AdminContext) -> Response {
    match service::list_all_devices(&state.pool).await {
        Ok(devices) => (
            StatusCode::OK,
            Json(AdminDeviceListResponse {
                devices: devices.iter().map(AdminDeviceView::from).collect(),
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "listing all devices failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

pub async fn revoke_any(
    State(state): State<AppState>,
    admin: AdminContext,
    Path(device_id): Path<String>,
) -> Response {
    let result =
        service::revoke_device(&state.pool, Scope::AnyDevice, &device_id, UnixTime::now()).await;

    if let Ok(report) = &result {
        tracing::info!(
            actor_id = %admin.auth().user.id,
            device_id = %report.device.id,
            user_id = %report.device.user_id,
            "admin revoked a device"
        );
    }
    revoke_response(result)
}

fn device_response(
    result: Result<crate::devices::store::DeviceRecord, DeviceActionError>,
) -> Response {
    match result {
        Ok(device) => (
            StatusCode::OK,
            Json(DeviceResponse {
                device: DeviceView::from(&device),
            }),
        )
            .into_response(),
        Err(err) => action_error(err).into_response(),
    }
}

fn revoke_response(result: Result<service::RevokeReport, DeviceActionError>) -> Response {
    match result {
        // The same 200 whether this call did the revoking or found it
        // already done: the caller asked for the device to be
        // revoked, and it is.
        Ok(report) => (
            StatusCode::OK,
            Json(DeviceResponse {
                device: DeviceView::from(&report.device),
            }),
        )
            .into_response(),
        Err(err) => action_error(err).into_response(),
    }
}

fn action_error(err: DeviceActionError) -> ApiError {
    match err {
        // One answer for "no such device" and "not yours". An owner
        // must not be able to probe which device ids exist on other
        // accounts, so the store does not distinguish them either.
        DeviceActionError::NotFound => ApiError::of(ErrorKind::NotFound),
        DeviceActionError::InvalidName(reason) => ApiError::of(match reason {
            DeviceNameError::Length => ErrorKind::DeviceNameLength,
            DeviceNameError::Charset => ErrorKind::DeviceNameCharset,
        }),
        DeviceActionError::Store(_) => {
            tracing::error!(error = %err, "a device action failed");
            ApiError::of(ErrorKind::InternalError)
        }
    }
}
