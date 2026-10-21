//! `POST /api/v1/events` - a device reports what it observed.
//! `GET /api/v1/device/me` - a device checks who it is and what time
//! the server thinks it is.
//!
//! Both are `Access::Device`: bearer token only, session cookie
//! refused, no `Origin` check, all attached from the route inventory.
//!
//! # Why ingest answers 200 with a list
//!
//! Only four things fail the whole request, and every one of them is a
//! property of the request rather than of any event in it: malformed
//! JSON, the wrong content type, a body over the per-route limit, and
//! a batch carrying more events than the cap. The first three are
//! refused by infrastructure before this handler runs - the body limit
//! is attached from the entry, and the normalizing middleware turns
//! serde's rejection into the uniform error shape without echoing the
//! body.
//!
//! Everything else is per event. A client that could not get rid of
//! one malformed event would retry the same batch forever, so the
//! request succeeds and each event gets its own verdict.
//!
//! # Why the response is keyed by index
//!
//! A rejected event's `event_id` is, by definition, input that failed
//! validation - so echoing it back is exactly what this codebase's
//! error discipline exists to prevent. The client sent an ordered
//! array and can line the results up against it positionally, which
//! costs it nothing and costs the server no decision about which
//! input is safe to reflect.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::device::DeviceContext;
use crate::auth::time::UnixTime;
use crate::devices::platform::Platform;
use crate::error::{ApiError, ErrorKind};
use crate::events::ingest::{self, MAX_BATCH_EVENTS};
use crate::events::validate::RawEvent;
use crate::state::AppState;

/// One event as it arrives on the wire.
///
/// `deny_unknown_fields`, like every other body in this server: a
/// stray or misspelled field is refused rather than silently ignored.
/// Note that this rejection *does* fail the whole request, because it
/// happens in serde before the handler sees anything - a client that
/// sends the wrong schema has a bug to fix, which is different from a
/// client sending one event whose values are out of range.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInput {
    event_id: String,
    start_ts: i64,
    duration_secs: i64,
    app_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

impl From<EventInput> for RawEvent {
    fn from(input: EventInput) -> Self {
        Self {
            event_id: input.event_id,
            start_ts: input.start_ts,
            duration_secs: input.duration_secs,
            app_id: input.app_id,
            label: input.label,
            domain: input.domain,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestRequest {
    events: Vec<EventInput>,
}

/// What one event did, by its position in the submitted array.
#[derive(Serialize)]
struct EventResult {
    index: usize,
    /// `accepted`, `duplicate` or `rejected`.
    status: &'static str,
    /// A code from the closed set in [`crate::events::validate`].
    /// Absent unless the status is `rejected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Serialize)]
struct IngestResponse {
    accepted: usize,
    duplicate: usize,
    rejected: usize,
    results: Vec<EventResult>,
    server_time: i64,
}

pub async fn ingest(
    State(state): State<AppState>,
    device: DeviceContext,
    Json(request): Json<IngestRequest>,
) -> Response {
    // The one whole-request refusal this handler makes itself. The
    // body limit bounds bytes; this bounds work, which is not the same
    // thing - 500 tiny events and 500 large ones cost the same number
    // of inserts.
    if request.events.len() > MAX_BATCH_EVENTS {
        return ApiError::of(ErrorKind::BatchTooLarge).into_response();
    }

    let now = UnixTime::now();
    let raw: Vec<RawEvent> = request.events.into_iter().map(RawEvent::from).collect();

    match ingest::ingest(
        &state.pool,
        &device.device().id,
        &raw,
        state.event_window,
        now,
    )
    .await
    {
        Ok(report) => {
            let (accepted, duplicate, rejected) = report.counts();
            let results = report
                .outcomes
                .iter()
                .enumerate()
                .map(|(index, outcome)| EventResult {
                    index,
                    status: outcome.status(),
                    reason: outcome.reason(),
                })
                .collect();

            (
                StatusCode::OK,
                Json(IngestResponse {
                    accepted,
                    duplicate,
                    rejected,
                    results,
                    server_time: now.as_secs(),
                }),
            )
                .into_response()
        }
        Err(err) => {
            // A constraint this server's own validator should have
            // caught lands here. Loud on purpose: it means the
            // validator and the schema disagree, which is a bug, not
            // a bad event.
            tracing::error!(
                error = %err,
                device_id = %device.device().id,
                "storing a batch of events failed"
            );
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

/// What a device is told about itself.
///
/// `server_time` is the point of this endpoint: the validator refuses
/// events dated too far into the future, and without a way to read the
/// server's clock a client with a skewed one would see rejections it
/// could not explain.
#[derive(Serialize)]
struct DeviceMeResponse {
    id: String,
    name: String,
    platform: &'static str,
    server_time: i64,
}

pub async fn device_me(device: DeviceContext) -> Response {
    let device = device.device();
    (
        StatusCode::OK,
        Json(DeviceMeResponse {
            id: device.id.clone(),
            name: device.name.as_str().to_owned(),
            platform: platform_str(device.platform),
            server_time: UnixTime::now().as_secs(),
        }),
    )
        .into_response()
}

/// The platform's wire value as a `&'static str`, so the response
/// type holds no allocation for it.
const fn platform_str(platform: Platform) -> &'static str {
    platform.as_str()
}
