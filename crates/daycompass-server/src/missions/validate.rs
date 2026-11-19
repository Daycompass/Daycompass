//! The four record types, and what makes one acceptable.
//!
//! Every rule is per record, and a failure rejects that record alone,
//! for the same reason as with events: a client that cannot get rid of
//! one bad record must not be stuck resending the whole batch.
//!
//! [`RejectReason`] is a closed set with constant codes, like
//! [`crate::events::validate::RejectReason`], so no part of a refused
//! record can be echoed back.
//!
//! References (`mission_id`, `task_id`, a review goal's mission) are
//! checked against the
//! database by [`super::sync`], not here: whether a mission exists is
//! not a property of the record that names it.
//!
//! # Tombstones
//!
//! A record with `deleted: true` is checked for its id and
//! `updated_at` only. Everything else in it is discarded, so a client
//! may send back a tombstone exactly as it received one, blank title
//! and all.

use serde::{Deserialize, Serialize};

use crate::auth::time::UnixTime;
use crate::categories::palette::SLOTS;
use crate::devices::name::is_forbidden;
use crate::events::validate::{canonical_event_id, MAX_CLOCK_SKEW};

pub const MAX_MISSION_TITLE_CHARS: usize = 100;
pub const MAX_TASK_TITLE_CHARS: usize = 200;
/// `description` and `why` on a mission.
pub const MAX_MISSION_TEXT_CHARS: usize = 2_000;
pub const MAX_NOTES_CHARS: usize = 4_000;
pub const MAX_POSITION_CHARS: usize = 64;
/// One week.
pub const MAX_WEEKLY_GOAL_SECS: i64 = 7 * 24 * 60 * 60;
/// `users.north_star`, also pinned by a CHECK in its migration.
pub const MAX_NORTH_STAR_CHARS: usize = 200;
/// Each of a review's three answers.
pub const MAX_REVIEW_TEXT_CHARS: usize = 2_000;
/// The most missions one review's goal snapshot may list.
pub const MAX_REVIEW_GOALS: usize = 100;

/// A mission, as sent, stored and returned.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub deleted: bool,
    pub updated_at: i64,
}

/// A task. `mission_id: None` is "Other"; `day: None` is the backlog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    pub mission_id: Option<String>,
    pub title: String,
    pub notes: Option<String>,
    pub day: Option<String>,
    pub position: String,
    pub done_at: Option<i64>,
    pub deleted: bool,
    pub updated_at: i64,
}

/// Tracked time on a task. `end_ts: None` is the running timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeEntry {
    pub id: String,
    pub task_id: String,
    pub start_ts: i64,
    pub end_ts: Option<i64>,
    pub deleted: bool,
    pub updated_at: i64,
}

/// A weekly review. Keyed by its week, not by an id: one week has one
/// review, whichever device writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// The week's Monday, `YYYY-MM-DD`.
    pub week_start: String,
    pub went_well: Option<String>,
    pub went_badly: Option<String>,
    pub change_next: Option<String>,
    /// The weekly goals the week is measured against.
    pub goals: Vec<ReviewGoal>,
    pub deleted: bool,
    pub updated_at: i64,
}

/// One mission's weekly goal, as a review keeps it. Stored as JSON in
/// `reviews.goals`, in exactly this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewGoal {
    pub mission_id: String,
    pub weekly_goal_secs: i64,
}

/// Why one record was not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Not 32 hex characters or a canonical UUID.
    IdMalformed,
    UpdatedAtInFuture,
    /// Blank, or over the field's maximum.
    TitleLength,
    /// `description`, `why` or `notes` over its maximum.
    TextLength,
    /// A control character (other than a newline in multi-line text)
    /// or a bidirectional override.
    ForbiddenCharacter,
    ColourOutOfRange,
    WeeklyGoalOutOfRange,
    /// Not a `YYYY-MM-DD` calendar date.
    DateMalformed,
    /// `ends_on` before `starts_on`.
    PeriodInverted,
    /// The mission does not exist in this account.
    MissionUnknown,
    /// The task does not exist in this account.
    TaskUnknown,
    PositionMalformed,
    DoneAtInFuture,
    StartInFuture,
    EndInFuture,
    EndNotAfterStart,
    /// A review's `week_start` is a date, but not a Monday.
    WeekStartNotMonday,
    /// A review lists more than [`MAX_REVIEW_GOALS`] goals, or one
    /// mission twice.
    GoalsMalformed,
}

/// Every variant, so tests can sweep the set.
pub const ALL_REJECT_REASONS: &[RejectReason] = &[
    RejectReason::IdMalformed,
    RejectReason::UpdatedAtInFuture,
    RejectReason::TitleLength,
    RejectReason::TextLength,
    RejectReason::ForbiddenCharacter,
    RejectReason::ColourOutOfRange,
    RejectReason::WeeklyGoalOutOfRange,
    RejectReason::DateMalformed,
    RejectReason::PeriodInverted,
    RejectReason::MissionUnknown,
    RejectReason::TaskUnknown,
    RejectReason::PositionMalformed,
    RejectReason::DoneAtInFuture,
    RejectReason::StartInFuture,
    RejectReason::EndInFuture,
    RejectReason::EndNotAfterStart,
    RejectReason::WeekStartNotMonday,
    RejectReason::GoalsMalformed,
];

impl RejectReason {
    /// The stable machine-readable code a client sees.
    pub const fn code(self) -> &'static str {
        match self {
            Self::IdMalformed => "id_malformed",
            Self::UpdatedAtInFuture => "updated_at_in_future",
            Self::TitleLength => "title_length",
            Self::TextLength => "text_length",
            Self::ForbiddenCharacter => "forbidden_character",
            Self::ColourOutOfRange => "colour_out_of_range",
            Self::WeeklyGoalOutOfRange => "weekly_goal_out_of_range",
            Self::DateMalformed => "date_malformed",
            Self::PeriodInverted => "period_inverted",
            Self::MissionUnknown => "mission_unknown",
            Self::TaskUnknown => "task_unknown",
            Self::PositionMalformed => "position_malformed",
            Self::DoneAtInFuture => "done_at_in_future",
            Self::StartInFuture => "start_ts_in_future",
            Self::EndInFuture => "end_ts_in_future",
            Self::EndNotAfterStart => "end_ts_not_after_start",
            Self::WeekStartNotMonday => "week_start_not_monday",
            Self::GoalsMalformed => "goals_malformed",
        }
    }
}

/// The latest instant a client clock may claim, see
/// [`crate::events::validate`] for why there is any slack at all.
fn latest(now: UnixTime) -> i64 {
    let skew = i64::try_from(MAX_CLOCK_SKEW.as_secs()).unwrap_or(i64::MAX);
    now.as_secs().saturating_add(skew)
}

/// The rules every record has, tombstone or not.
fn check_common(id: &str, updated_at: i64, now: UnixTime) -> Result<String, RejectReason> {
    let id = canonical_event_id(id).ok_or(RejectReason::IdMalformed)?;
    if updated_at > latest(now) {
        return Err(RejectReason::UpdatedAtInFuture);
    }
    Ok(id)
}

pub fn mission(raw: &Mission, now: UnixTime) -> Result<Mission, RejectReason> {
    let id = check_common(&raw.id, raw.updated_at, now)?;
    if raw.deleted {
        return Ok(Mission {
            id,
            title: String::new(),
            description: None,
            why: None,
            ..raw.clone()
        });
    }

    let title = check_line(&raw.title, MAX_MISSION_TITLE_CHARS)?;
    let description = check_text(raw.description.as_deref(), MAX_MISSION_TEXT_CHARS)?;
    let why = check_text(raw.why.as_deref(), MAX_MISSION_TEXT_CHARS)?;
    if !(0..i64::from(SLOTS)).contains(&raw.colour) {
        return Err(RejectReason::ColourOutOfRange);
    }
    if !(0..=MAX_WEEKLY_GOAL_SECS).contains(&raw.weekly_goal_secs) {
        return Err(RejectReason::WeeklyGoalOutOfRange);
    }
    let starts_on = raw.starts_on.as_deref().map(check_date).transpose()?;
    let ends_on = raw.ends_on.as_deref().map(check_date).transpose()?;
    // Canonical dates compare correctly as strings.
    if let (Some(start), Some(end)) = (&starts_on, &ends_on) {
        if end < start {
            return Err(RejectReason::PeriodInverted);
        }
    }

    Ok(Mission {
        id,
        title,
        colour: raw.colour,
        weekly_goal_secs: raw.weekly_goal_secs,
        description,
        why,
        starts_on,
        ends_on,
        archived: raw.archived,
        deleted: false,
        updated_at: raw.updated_at,
    })
}

pub fn task(raw: &Task, now: UnixTime) -> Result<Task, RejectReason> {
    let id = check_common(&raw.id, raw.updated_at, now)?;
    if raw.deleted {
        return Ok(Task {
            id,
            title: String::new(),
            notes: None,
            ..raw.clone()
        });
    }

    // A reference that cannot even be an id names no mission.
    let mission_id = raw
        .mission_id
        .as_deref()
        .map(|id| canonical_event_id(id).ok_or(RejectReason::MissionUnknown))
        .transpose()?;
    let title = check_line(&raw.title, MAX_TASK_TITLE_CHARS)?;
    let notes = check_text(raw.notes.as_deref(), MAX_NOTES_CHARS)?;
    let day = raw.day.as_deref().map(check_date).transpose()?;
    // Fractional index keys are base62; anything else would sort
    // differently on different clients.
    if raw.position.is_empty()
        || raw.position.len() > MAX_POSITION_CHARS
        || !raw.position.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(RejectReason::PositionMalformed);
    }
    if raw.done_at.is_some_and(|at| at > latest(now)) {
        return Err(RejectReason::DoneAtInFuture);
    }

    Ok(Task {
        id,
        mission_id,
        title,
        notes,
        day,
        position: raw.position.clone(),
        done_at: raw.done_at,
        deleted: false,
        updated_at: raw.updated_at,
    })
}

pub fn time_entry(raw: &TimeEntry, now: UnixTime) -> Result<TimeEntry, RejectReason> {
    let id = check_common(&raw.id, raw.updated_at, now)?;
    if raw.deleted {
        return Ok(TimeEntry { id, ..raw.clone() });
    }

    let task_id = canonical_event_id(&raw.task_id).ok_or(RejectReason::TaskUnknown)?;
    if raw.start_ts > latest(now) {
        return Err(RejectReason::StartInFuture);
    }
    if let Some(end) = raw.end_ts {
        if end <= raw.start_ts {
            return Err(RejectReason::EndNotAfterStart);
        }
        if end > latest(now) {
            return Err(RejectReason::EndInFuture);
        }
    }

    Ok(TimeEntry {
        id,
        task_id,
        start_ts: raw.start_ts,
        end_ts: raw.end_ts,
        deleted: false,
        updated_at: raw.updated_at,
    })
}

pub fn review(raw: &Review, now: UnixTime) -> Result<Review, RejectReason> {
    let week_start = check_date(&raw.week_start)?;
    let monday = raw
        .week_start
        .parse::<jiff::civil::Date>()
        .is_ok_and(|date| date.weekday() == jiff::civil::Weekday::Monday);
    if !monday {
        return Err(RejectReason::WeekStartNotMonday);
    }
    if raw.updated_at > latest(now) {
        return Err(RejectReason::UpdatedAtInFuture);
    }
    if raw.deleted {
        return Ok(Review {
            week_start,
            went_well: None,
            went_badly: None,
            change_next: None,
            ..raw.clone()
        });
    }

    let went_well = check_text(raw.went_well.as_deref(), MAX_REVIEW_TEXT_CHARS)?;
    let went_badly = check_text(raw.went_badly.as_deref(), MAX_REVIEW_TEXT_CHARS)?;
    let change_next = check_text(raw.change_next.as_deref(), MAX_REVIEW_TEXT_CHARS)?;
    if raw.goals.len() > MAX_REVIEW_GOALS {
        return Err(RejectReason::GoalsMalformed);
    }
    let mut goals: Vec<ReviewGoal> = Vec::with_capacity(raw.goals.len());
    for goal in &raw.goals {
        let mission_id =
            canonical_event_id(&goal.mission_id).ok_or(RejectReason::MissionUnknown)?;
        if !(0..=MAX_WEEKLY_GOAL_SECS).contains(&goal.weekly_goal_secs) {
            return Err(RejectReason::WeeklyGoalOutOfRange);
        }
        if goals.iter().any(|seen| seen.mission_id == mission_id) {
            return Err(RejectReason::GoalsMalformed);
        }
        goals.push(ReviewGoal {
            mission_id,
            weekly_goal_secs: goal.weekly_goal_secs,
        });
    }

    Ok(Review {
        week_start,
        went_well,
        went_badly,
        change_next,
        goals,
        deleted: false,
        updated_at: raw.updated_at,
    })
}

/// The account's North Star: one line, like a title. Blank clears it.
pub fn north_star(raw: &str) -> Result<Option<String>, RejectReason> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    check_line(raw, MAX_NORTH_STAR_CHARS).map(Some)
}

/// A one-line title: trimmed, non-blank, no control characters.
fn check_line(raw: &str, max: usize) -> Result<String, RejectReason> {
    if raw.chars().any(is_forbidden) {
        return Err(RejectReason::ForbiddenCharacter);
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().count() > max {
        return Err(RejectReason::TitleLength);
    }
    Ok(trimmed.to_owned())
}

/// Multi-line free text: newlines allowed, stored as sent, empty means
/// none.
fn check_text(raw: Option<&str>, max: usize) -> Result<Option<String>, RejectReason> {
    let Some(raw) = raw.filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if raw.chars().any(|c| c != '\n' && is_forbidden(c)) {
        return Err(RejectReason::ForbiddenCharacter);
    }
    if raw.chars().count() > max {
        return Err(RejectReason::TextLength);
    }
    Ok(Some(raw.to_owned()))
}

/// A calendar date, accepted only in its canonical `YYYY-MM-DD` form,
/// so equal days are equal strings.
fn check_date(raw: &str) -> Result<String, RejectReason> {
    match raw.parse::<jiff::civil::Date>() {
        Ok(date) if date.to_string() == raw => Ok(raw.to_owned()),
        _ => Err(RejectReason::DateMalformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn now() -> UnixTime {
        UnixTime::from_secs(NOW)
    }

    fn id(n: u32) -> String {
        format!("{n:032x}")
    }

    fn a_mission() -> Mission {
        Mission {
            id: id(1),
            title: "Maths".to_owned(),
            colour: 3,
            weekly_goal_secs: 36_000,
            description: None,
            why: None,
            starts_on: Some("2026-09-01".to_owned()),
            ends_on: Some("2027-07-31".to_owned()),
            archived: false,
            deleted: false,
            updated_at: NOW,
        }
    }

    fn a_task() -> Task {
        Task {
            id: id(2),
            mission_id: Some(id(1)),
            title: "Exercise 4".to_owned(),
            notes: Some("line one\nline two".to_owned()),
            day: Some("2026-11-19".to_owned()),
            position: "a0".to_owned(),
            done_at: None,
            deleted: false,
            updated_at: NOW,
        }
    }

    fn an_entry() -> TimeEntry {
        TimeEntry {
            id: id(3),
            task_id: id(2),
            start_ts: NOW - 600,
            end_ts: Some(NOW),
            deleted: false,
            updated_at: NOW,
        }
    }

    #[test]
    fn valid_records_pass_and_are_normalized() {
        let raw = Mission {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            title: "  Maths ".to_owned(),
            description: Some(String::new()),
            ..a_mission()
        };
        let valid = mission(&raw, now()).expect("valid");
        assert_eq!(valid.id, id(1));
        assert_eq!(valid.title, "Maths");
        assert_eq!(valid.description, None, "empty text is no text");

        assert_eq!(task(&a_task(), now()), Ok(a_task()));
        assert_eq!(time_entry(&an_entry(), now()), Ok(an_entry()));
    }

    #[test]
    fn each_rule_refuses_with_its_own_reason() {
        let cases: Vec<(Result<(), RejectReason>, RejectReason)> = vec![
            (
                mission(
                    &Mission {
                        id: "x".into(),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::IdMalformed,
            ),
            (
                mission(
                    &Mission {
                        updated_at: NOW + 301,
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::UpdatedAtInFuture,
            ),
            (
                mission(
                    &Mission {
                        title: "  ".into(),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::TitleLength,
            ),
            (
                mission(
                    &Mission {
                        title: "a\nb".into(),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::ForbiddenCharacter,
            ),
            (
                mission(
                    &Mission {
                        why: Some("x".repeat(2_001)),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::TextLength,
            ),
            (
                mission(
                    &Mission {
                        colour: 8,
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::ColourOutOfRange,
            ),
            (
                mission(
                    &Mission {
                        weekly_goal_secs: -1,
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::WeeklyGoalOutOfRange,
            ),
            (
                mission(
                    &Mission {
                        starts_on: Some("2026-9-1".into()),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::DateMalformed,
            ),
            (
                mission(
                    &Mission {
                        ends_on: Some("2026-08-31".into()),
                        ..a_mission()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::PeriodInverted,
            ),
            (
                task(
                    &Task {
                        mission_id: Some("x".into()),
                        ..a_task()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::MissionUnknown,
            ),
            (
                task(
                    &Task {
                        notes: Some("\u{202e}".into()),
                        ..a_task()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::ForbiddenCharacter,
            ),
            (
                task(
                    &Task {
                        day: Some("2026-02-30".into()),
                        ..a_task()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::DateMalformed,
            ),
            (
                task(
                    &Task {
                        position: "a-0".into(),
                        ..a_task()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::PositionMalformed,
            ),
            (
                task(
                    &Task {
                        done_at: Some(NOW + 301),
                        ..a_task()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::DoneAtInFuture,
            ),
            (
                time_entry(
                    &TimeEntry {
                        task_id: "x".into(),
                        ..an_entry()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::TaskUnknown,
            ),
            (
                time_entry(
                    &TimeEntry {
                        start_ts: NOW + 301,
                        end_ts: None,
                        ..an_entry()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::StartInFuture,
            ),
            (
                time_entry(
                    &TimeEntry {
                        end_ts: Some(NOW + 301),
                        ..an_entry()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::EndInFuture,
            ),
            (
                time_entry(
                    &TimeEntry {
                        end_ts: Some(NOW - 600),
                        ..an_entry()
                    },
                    now(),
                )
                .map(drop),
                RejectReason::EndNotAfterStart,
            ),
        ];
        for (index, (result, reason)) in cases.into_iter().enumerate() {
            assert_eq!(result, Err(reason), "case {index}");
        }
    }

    /// A tombstone sent back exactly as the server returned it - blank
    /// title and all - must pass, and must lose whatever text it had.
    #[test]
    fn a_tombstone_is_checked_for_id_and_time_only_and_keeps_no_text() {
        let raw = Mission {
            title: String::new(),
            why: Some("secret reason".into()),
            colour: 99,
            deleted: true,
            ..a_mission()
        };
        let valid = mission(&raw, now()).expect("a tombstone needs no title");
        assert_eq!((valid.title.as_str(), valid.why), ("", None));

        let valid = task(
            &Task {
                notes: Some("x".into()),
                deleted: true,
                ..a_task()
            },
            now(),
        )
        .expect("tombstone");
        assert_eq!((valid.title.as_str(), valid.notes), ("", None));

        assert_eq!(
            task(
                &Task {
                    id: "x".into(),
                    deleted: true,
                    ..a_task()
                },
                now()
            ),
            Err(RejectReason::IdMalformed)
        );
    }

    fn a_review() -> Review {
        Review {
            week_start: "2026-11-16".to_owned(),
            went_well: Some("Exercises\nevery day".to_owned()),
            went_badly: None,
            change_next: Some(String::new()),
            goals: vec![ReviewGoal {
                mission_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                weekly_goal_secs: 36_000,
            }],
            deleted: false,
            updated_at: NOW,
        }
    }

    #[test]
    fn a_review_is_keyed_by_a_monday_and_its_goals_are_checked() {
        let valid = review(&a_review(), now()).expect("valid");
        assert_eq!(valid.change_next, None, "empty text is no text");
        assert_eq!(valid.goals[0].mission_id, id(1));

        let refused = |raw: Review| review(&raw, now()).map(drop);
        let goal = |mission_id: String, weekly_goal_secs| ReviewGoal {
            mission_id,
            weekly_goal_secs,
        };
        assert_eq!(
            refused(Review {
                week_start: "2026-11-17".into(),
                ..a_review()
            }),
            Err(RejectReason::WeekStartNotMonday)
        );
        assert_eq!(
            refused(Review {
                week_start: "2026-11-16T00:00".into(),
                ..a_review()
            }),
            Err(RejectReason::DateMalformed)
        );
        assert_eq!(
            refused(Review {
                updated_at: NOW + 301,
                ..a_review()
            }),
            Err(RejectReason::UpdatedAtInFuture)
        );
        assert_eq!(
            refused(Review {
                went_badly: Some("x".repeat(MAX_REVIEW_TEXT_CHARS + 1)),
                ..a_review()
            }),
            Err(RejectReason::TextLength)
        );
        assert_eq!(
            refused(Review {
                goals: vec![goal("x".into(), 0)],
                ..a_review()
            }),
            Err(RejectReason::MissionUnknown)
        );
        assert_eq!(
            refused(Review {
                goals: vec![goal(id(1), MAX_WEEKLY_GOAL_SECS + 1)],
                ..a_review()
            }),
            Err(RejectReason::WeeklyGoalOutOfRange)
        );
        assert_eq!(
            refused(Review {
                goals: vec![goal(id(1), 0), goal(id(1), 60)],
                ..a_review()
            }),
            Err(RejectReason::GoalsMalformed)
        );
        assert_eq!(
            refused(Review {
                goals: (0..=MAX_REVIEW_GOALS as u32)
                    .map(|n| goal(id(n), 0))
                    .collect(),
                ..a_review()
            }),
            Err(RejectReason::GoalsMalformed)
        );

        let tombstone = review(
            &Review {
                deleted: true,
                ..a_review()
            },
            now(),
        )
        .expect("a tombstone");
        assert_eq!(
            (tombstone.went_well, tombstone.change_next),
            (None, None),
            "a tombstone keeps no text"
        );
    }

    #[test]
    fn every_code_is_distinct() {
        let codes: std::collections::HashSet<&str> =
            ALL_REJECT_REASONS.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), ALL_REJECT_REASONS.len());
    }

    #[test]
    fn a_north_star_is_one_trimmed_line_and_blank_clears_it() {
        assert_eq!(
            north_star("  Finish school well "),
            Ok(Some("Finish school well".to_owned()))
        );
        assert_eq!(north_star(" \t "), Ok(None));
        assert_eq!(
            north_star(&"a".repeat(MAX_NORTH_STAR_CHARS)).map(|s| s.map(|s| s.len())),
            Ok(Some(MAX_NORTH_STAR_CHARS))
        );
        assert_eq!(
            north_star(&"a".repeat(MAX_NORTH_STAR_CHARS + 1)),
            Err(RejectReason::TitleLength)
        );
        assert_eq!(
            north_star("one\ntwo"),
            Err(RejectReason::ForbiddenCharacter)
        );
    }
}
