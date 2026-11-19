//! `POST /api/v1/missions/sync` - a device pushes its mission, task
//! and time-entry edits and pulls everything after its cursor.
//!
//! `Access::Device`, like ingest: bearer token only, attached from the
//! route inventory. The handler is a thin adapter over
//! [`crate::missions::sync`]; the rules live there.
//!
//! Same answer shape as ingest for the same reasons: 200 with one
//! verdict per record, keyed by index so a rejected record's id is
//! never echoed. Only a malformed request, an oversized batch or a bad
//! cursor fail the whole call.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::device::DeviceContext;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::missions::sync::{self, Changes, Outcome, SyncError, MAX_BATCH_RECORDS};
use crate::missions::validate::{Mission, Task, TimeEntry};
use crate::state::AppState;

/// A mission, the same shape both ways.
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MissionRecord {
    /// Client-generated, 32 lowercase hex characters.
    id: String,
    title: String,
    /// Palette slot, 0-7.
    colour: i64,
    /// 0 means no goal.
    weekly_goal_secs: i64,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    why: Option<String>,
    /// `YYYY-MM-DD`.
    #[serde(default)]
    starts_on: Option<String>,
    /// `YYYY-MM-DD`.
    #[serde(default)]
    ends_on: Option<String>,
    archived: bool,
    deleted: bool,
    /// Your clock at the last edit. Last write wins on it.
    updated_at: i64,
}

impl From<MissionRecord> for Mission {
    fn from(r: MissionRecord) -> Self {
        Self {
            id: r.id,
            title: r.title,
            colour: r.colour,
            weekly_goal_secs: r.weekly_goal_secs,
            description: r.description,
            why: r.why,
            starts_on: r.starts_on,
            ends_on: r.ends_on,
            archived: r.archived,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<Mission> for MissionRecord {
    fn from(m: Mission) -> Self {
        Self {
            id: m.id,
            title: m.title,
            colour: m.colour,
            weekly_goal_secs: m.weekly_goal_secs,
            description: m.description,
            why: m.why,
            starts_on: m.starts_on,
            ends_on: m.ends_on,
            archived: m.archived,
            deleted: m.deleted,
            updated_at: m.updated_at,
        }
    }
}

/// A task, the same shape both ways.
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    id: String,
    /// `null`: no mission ("Other").
    #[serde(default)]
    mission_id: Option<String>,
    title: String,
    #[serde(default)]
    notes: Option<String>,
    /// `YYYY-MM-DD`, or `null` for the backlog.
    #[serde(default)]
    day: Option<String>,
    /// Fractional index key, base62, sorted bytewise within a day.
    position: String,
    /// `null` while open.
    #[serde(default)]
    done_at: Option<i64>,
    deleted: bool,
    updated_at: i64,
}

impl From<TaskRecord> for Task {
    fn from(r: TaskRecord) -> Self {
        Self {
            id: r.id,
            mission_id: r.mission_id,
            title: r.title,
            notes: r.notes,
            day: r.day,
            position: r.position,
            done_at: r.done_at,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<Task> for TaskRecord {
    fn from(t: Task) -> Self {
        Self {
            id: t.id,
            mission_id: t.mission_id,
            title: t.title,
            notes: t.notes,
            day: t.day,
            position: t.position,
            done_at: t.done_at,
            deleted: t.deleted,
            updated_at: t.updated_at,
        }
    }
}

/// Tracked time, the same shape both ways.
#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeEntryRecord {
    id: String,
    task_id: String,
    start_ts: i64,
    /// `null` while the timer runs.
    #[serde(default)]
    end_ts: Option<i64>,
    deleted: bool,
    updated_at: i64,
}

impl From<TimeEntryRecord> for TimeEntry {
    fn from(r: TimeEntryRecord) -> Self {
        Self {
            id: r.id,
            task_id: r.task_id,
            start_ts: r.start_ts,
            end_ts: r.end_ts,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<TimeEntry> for TimeEntryRecord {
    fn from(e: TimeEntry) -> Self {
        Self {
            id: e.id,
            task_id: e.task_id,
            start_ts: e.start_ts,
            end_ts: e.end_ts,
            deleted: e.deleted,
            updated_at: e.updated_at,
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    /// The `cursor` from your last sync, or 0 to pull everything.
    cursor: i64,
    #[serde(default)]
    missions: Vec<MissionRecord>,
    #[serde(default)]
    tasks: Vec<TaskRecord>,
    #[serde(default)]
    time_entries: Vec<TimeEntryRecord>,
}

/// What one pushed record did, by its position in its array.
#[derive(Serialize, ToSchema)]
struct RecordResult {
    index: usize,
    /// `applied`, `stale` or `rejected`.
    status: &'static str,
    /// Absent unless the status is `rejected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    reason: Option<&'static str>,
}

#[derive(Serialize, ToSchema)]
struct SyncResults {
    missions: Vec<RecordResult>,
    tasks: Vec<RecordResult>,
    time_entries: Vec<RecordResult>,
}

#[derive(Serialize, ToSchema)]
struct SyncChanges {
    missions: Vec<MissionRecord>,
    tasks: Vec<TaskRecord>,
    time_entries: Vec<TimeEntryRecord>,
}

#[derive(Serialize, ToSchema)]
struct SyncResponse {
    results: SyncResults,
    /// Every record changed after your cursor, tombstones included.
    changes: SyncChanges,
    /// Send this as `cursor` next time.
    cursor: i64,
    /// More changes wait; sync again (an empty push is fine).
    has_more: bool,
    server_time: i64,
}

fn results(outcomes: &[Outcome]) -> Vec<RecordResult> {
    outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| RecordResult {
            index,
            status: outcome.status(),
            reason: outcome.reason(),
        })
        .collect()
}

#[utoipa::path(
    post,
    path = "/api/v1/missions/sync",
    tag = "missions",
    operation_id = "sync_missions",
    summary = "Push mission edits and pull everyone else's (device)",
    request_body = SyncRequest,
    responses(
        (status = 200, description = "Every pushed record has its own verdict, by index, plus one page of changes.", body = SyncResponse),
        (status = 400, description = "`invalid_sync_cursor`: start over from 0.", body = crate::error::ErrorBody),
        (status = 413, description = "`batch_too_large` (more than 500 records) or `payload_too_large`.", body = crate::error::ErrorBody),
    )
)]
pub async fn sync(
    State(state): State<AppState>,
    device: DeviceContext,
    Json(request): Json<SyncRequest>,
) -> Response {
    if request.missions.len() + request.tasks.len() + request.time_entries.len() > MAX_BATCH_RECORDS
    {
        return ApiError::of(ErrorKind::BatchTooLarge).into_response();
    }

    let push = Changes {
        missions: request.missions.into_iter().map(Into::into).collect(),
        tasks: request.tasks.into_iter().map(Into::into).collect(),
        time_entries: request.time_entries.into_iter().map(Into::into).collect(),
    };
    let now = UnixTime::now();
    let user_id = &device.device().user_id;

    match sync::sync(&state.pool, user_id, request.cursor, &push, now).await {
        Ok(synced) => (
            StatusCode::OK,
            Json(SyncResponse {
                results: SyncResults {
                    missions: results(&synced.report.missions),
                    tasks: results(&synced.report.tasks),
                    time_entries: results(&synced.report.time_entries),
                },
                changes: SyncChanges {
                    missions: synced
                        .changes
                        .missions
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    tasks: synced.changes.tasks.into_iter().map(Into::into).collect(),
                    time_entries: synced
                        .changes
                        .time_entries
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                },
                cursor: synced.cursor,
                has_more: synced.has_more,
                server_time: now.as_secs(),
            }),
        )
            .into_response(),
        Err(SyncError::CursorInvalid) => ApiError::of(ErrorKind::SyncCursorInvalid).into_response(),
        Err(SyncError::Store(err)) => {
            tracing::error!(error = %err, user_id = %user_id, "missions sync failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}
