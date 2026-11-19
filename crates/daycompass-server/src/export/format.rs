//! The export document's sections, as they are serialized.
//!
//! Separate from the route views on purpose, even where the fields are
//! the same: this is a file format a person keeps, versioned by
//! [`FORMAT_VERSION`], and a later change to an endpoint's response must
//! not silently change it.
//!
//! What is never in here: password hashes, token hashes, sessions,
//! invites, pairing codes - and no `category` on an event. Events carry
//! none (`CLAUDE.md`); the account's own rules are exported next to
//! them. The built-in fallback (`categories::builtin`) is code, not
//! account data, and is not part of the document.

use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::account_log::LogEntry;
use crate::auth::store::UserRecord;
use crate::categories::store::CategoryRuleRecord;
use crate::devices::store::DeviceRecord;
use crate::events::store::QueriedEvent;
use crate::missions::validate::{
    Mission as MissionRecord, Review as ReviewRecord, ReviewGoal as ReviewGoalRecord,
    Task as TaskRecord, TimeEntry as TimeEntryRecord,
};

/// The value of the document's `format` field.
pub const FORMAT_NAME: &str = "daycompass-export";

/// Bumped on any change to the document's shape.
pub const FORMAT_VERSION: u32 = 4;

/// Everything before `events`, serialized in one go.
///
/// `events` and `complete` are not fields here: they are written by
/// [`super::service`] a page at a time, after this.
#[derive(Serialize, ToSchema)]
pub struct Head {
    pub format: &'static str,
    pub format_version: u32,
    pub exported_at: i64,
    pub account: Account,
    pub settings: Settings,
    pub devices: Vec<Device>,
    pub category_rules: Vec<CategoryRule>,
    pub account_log: Vec<AccountLogEntry>,
    pub missions: Vec<Mission>,
    pub tasks: Vec<Task>,
    pub time_entries: Vec<TimeEntry>,
    pub reviews: Vec<Review>,
}

/// The account itself. No password hash, no status: the first is a
/// secret, the second says nothing an account holding a session does
/// not already know.
#[derive(Serialize, ToSchema)]
pub struct Account {
    pub id: String,
    pub username: String,
    pub role: &'static str,
    pub created_at: i64,
}

impl From<&UserRecord> for Account {
    fn from(user: &UserRecord) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.as_str().to_owned(),
            role: user.role.as_str(),
            created_at: user.created_at.as_secs(),
        }
    }
}

/// What the account set on the dashboard. None of it is a secret, and
/// none of it is anyone else's.
#[derive(Serialize, ToSchema)]
pub struct Settings {
    /// An IANA name; `UTC` until one is picked.
    pub timezone: String,
    pub north_star: Option<String>,
    /// The weekday Today asks for a review on, 1 (Monday) to 7.
    pub review_day: i8,
    /// Whether the Missions pages show screen time.
    pub screen_time_in_missions: bool,
    /// The categories counted as distraction, sorted.
    pub distraction_categories: Vec<String>,
}

/// Same fields as `GET /api/v1/devices`.
#[derive(Serialize, ToSchema)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: &'static str,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
}

impl From<&DeviceRecord> for Device {
    fn from(device: &DeviceRecord) -> Self {
        Self {
            id: device.id.clone(),
            name: device.name.as_str().to_owned(),
            platform: device.platform.as_str(),
            created_at: device.created_at.as_secs(),
            last_seen_at: device.last_seen_at.as_secs(),
            revoked_at: device.revoked_at.map(|at| at.as_secs()),
        }
    }
}

/// Same fields as `GET /api/v1/category-rules`.
#[derive(Serialize, ToSchema)]
pub struct CategoryRule {
    pub id: String,
    pub kind: &'static str,
    pub pattern: String,
    pub category: String,
    pub created_at: i64,
}

impl From<&CategoryRuleRecord> for CategoryRule {
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

/// Same fields as `GET /api/v1/account/log`.
#[derive(Serialize, ToSchema)]
pub struct AccountLogEntry {
    pub kind: &'static str,
    pub actor_id: Option<String>,
    pub at: i64,
}

impl From<&LogEntry> for AccountLogEntry {
    fn from(entry: &LogEntry) -> Self {
        Self {
            kind: entry.kind.as_str(),
            actor_id: entry.actor_id.clone(),
            at: entry.at.as_secs(),
        }
    }
}

/// A mission. Deleted ones are not exported, so there is no `deleted`.
#[derive(Serialize, ToSchema)]
pub struct Mission {
    pub id: String,
    pub title: String,
    pub colour: i64,
    pub weekly_goal_secs: i64,
    pub description: Option<String>,
    pub why: Option<String>,
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
    pub archived: bool,
    pub updated_at: i64,
}

impl From<MissionRecord> for Mission {
    fn from(m: MissionRecord) -> Self {
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
            updated_at: m.updated_at,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct Task {
    pub id: String,
    pub mission_id: Option<String>,
    pub title: String,
    pub notes: Option<String>,
    pub day: Option<String>,
    pub position: String,
    pub done_at: Option<i64>,
    pub updated_at: i64,
}

impl From<TaskRecord> for Task {
    fn from(t: TaskRecord) -> Self {
        Self {
            id: t.id,
            mission_id: t.mission_id,
            title: t.title,
            notes: t.notes,
            day: t.day,
            position: t.position,
            done_at: t.done_at,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct TimeEntry {
    pub id: String,
    pub task_id: String,
    pub start_ts: i64,
    /// `null` for the timer that was running at export time.
    pub end_ts: Option<i64>,
    pub updated_at: i64,
}

impl From<TimeEntryRecord> for TimeEntry {
    fn from(e: TimeEntryRecord) -> Self {
        Self {
            id: e.id,
            task_id: e.task_id,
            start_ts: e.start_ts,
            end_ts: e.end_ts,
            updated_at: e.updated_at,
        }
    }
}

/// A weekly review. Deleted ones are not exported, like missions.
#[derive(Serialize, ToSchema)]
pub struct Review {
    /// The week's Monday.
    pub week_start: String,
    pub went_well: Option<String>,
    pub went_badly: Option<String>,
    pub change_next: Option<String>,
    pub goals: Vec<ReviewGoal>,
    pub updated_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ReviewGoal {
    pub mission_id: String,
    pub weekly_goal_secs: i64,
}

impl From<ReviewRecord> for Review {
    fn from(r: ReviewRecord) -> Self {
        Self {
            week_start: r.week_start,
            went_well: r.went_well,
            went_badly: r.went_badly,
            change_next: r.change_next,
            goals: r.goals.into_iter().map(ReviewGoal::from).collect(),
            updated_at: r.updated_at,
        }
    }
}

impl From<ReviewGoalRecord> for ReviewGoal {
    fn from(g: ReviewGoalRecord) -> Self {
        Self {
            mission_id: g.mission_id,
            weekly_goal_secs: g.weekly_goal_secs,
        }
    }
}

/// One event, exactly as reported. No `category` - see the module doc.
#[derive(Serialize, ToSchema)]
pub struct Event<'a> {
    pub device_id: &'a str,
    pub event_id: &'a str,
    pub start_ts: i64,
    pub duration_secs: i64,
    pub app_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub domain: Option<&'a str>,
}

impl<'a> From<&'a QueriedEvent> for Event<'a> {
    fn from(event: &'a QueriedEvent) -> Self {
        Self {
            device_id: &event.device_id,
            event_id: &event.event_id,
            start_ts: event.start_ts,
            duration_secs: event.duration_secs,
            app_id: &event.app_id,
            label: event.label.as_deref(),
            domain: event.domain.as_deref(),
        }
    }
}

/// The whole document as `docs/openapi.json` describes it.
///
/// Never constructed: [`super::service`] writes the document a page at
/// a time, which no single Rust value models. This type exists only so
/// the spec can describe what that stream adds up to.
#[derive(ToSchema)]
#[allow(dead_code)]
pub struct Document {
    /// Always `daycompass-export`.
    pub format: String,
    /// Bumped on any change to the document's shape.
    pub format_version: u32,
    pub exported_at: i64,
    pub account: Account,
    pub settings: Settings,
    pub devices: Vec<Device>,
    pub category_rules: Vec<CategoryRule>,
    pub account_log: Vec<AccountLogEntry>,
    pub missions: Vec<Mission>,
    pub tasks: Vec<Task>,
    pub time_entries: Vec<TimeEntry>,
    pub reviews: Vec<Review>,
    pub events: Vec<Event<'static>>,
    /// Always `true`, and always the last field. Missing means the
    /// export was cut off and must be discarded.
    pub complete: bool,
}
