//! The export document's sections, as they are serialized.
//!
//! Separate from the route views on purpose, even where the fields are
//! the same: this is a file format a person keeps, versioned by
//! [`FORMAT_VERSION`], and a later change to an endpoint's response must
//! not silently change it.
//!
//! What is never in here: password hashes, token hashes, sessions,
//! invites, pairing codes - and no `category` on an event. Events carry
//! none (`CLAUDE.md`); the rules are exported next to them, so a
//! category can be derived again from the file alone.

use serde::Serialize;

use crate::auth::account_log::LogEntry;
use crate::auth::store::UserRecord;
use crate::categories::store::CategoryRuleRecord;
use crate::devices::store::DeviceRecord;
use crate::events::store::QueriedEvent;

/// The value of the document's `format` field.
pub const FORMAT_NAME: &str = "daycompass-export";

/// Bumped on any change to the document's shape.
pub const FORMAT_VERSION: u32 = 1;

/// Everything before `events`, serialized in one go.
///
/// `events` and `complete` are not fields here: they are written by
/// [`super::service`] a page at a time, after this.
#[derive(Serialize)]
pub struct Head {
    pub format: &'static str,
    pub format_version: u32,
    pub exported_at: i64,
    pub account: Account,
    pub devices: Vec<Device>,
    pub category_rules: Vec<CategoryRule>,
    pub account_log: Vec<AccountLogEntry>,
}

/// The account itself. No password hash, no status: the first is a
/// secret, the second says nothing an account holding a session does
/// not already know.
#[derive(Serialize)]
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

/// Same fields as `GET /api/v1/devices`.
#[derive(Serialize)]
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
#[derive(Serialize)]
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
#[derive(Serialize)]
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

/// One event, exactly as reported. No `category` - see the module doc.
#[derive(Serialize)]
pub struct Event<'a> {
    pub device_id: &'a str,
    pub event_id: &'a str,
    pub start_ts: i64,
    pub duration_secs: i64,
    pub app_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
