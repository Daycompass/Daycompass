//! `GET /` - the overview: the caller's own screen time for today and
//! the last seven days, per category.
//!
//! A read into events, and the same one `GET /api/v1/stats` makes:
//! [`aggregate::daily_totals`] with the caller's own id, resolved from
//! the session. No parameter can point it at anyone else, and an admin
//! sees their own numbers here like everyone else.
//!
//! Days are UTC calendar days, because that is what the aggregation
//! returns; the page says so rather than pretending otherwise.

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use super::{render, Shell};
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::routes::SessionContext;
use crate::state::AppState;
use crate::stats::aggregate::{self, DailyCategoryTotal};

const DAY_SECS: i64 = 24 * 60 * 60;

/// How many days the overview covers, today included.
const DAYS: i64 = 7;

#[derive(Template)]
#[template(path = "overview.html")]
struct OverviewPage {
    shell: Shell,
    today: String,
    week: String,
    categories: Vec<CategoryRow>,
}

/// One category's week, as one bar.
struct CategoryRow {
    /// The category's own name, or "Uncategorized". Escaped by the
    /// template like every other value.
    name: String,
    duration: String,
    /// The bar's value and maximum, in seconds. `max` is the largest
    /// category's total, so the longest bar is full width.
    value: i64,
    max: i64,
    uncategorized: bool,
}

pub async fn page(State(state): State<AppState>, session: SessionContext) -> Response {
    let auth = session.auth();
    let now = UnixTime::now().as_secs();
    let today_start = now - now.rem_euclid(DAY_SECS);
    let start = today_start - (DAYS - 1) * DAY_SECS;
    let end = today_start + DAY_SECS;

    let days = match aggregate::daily_totals(&state.pool, &auth.user.id, start, end).await {
        Ok(days) => days,
        Err(err) => {
            tracing::error!(error = ?err, user_id = %auth.user.id, "aggregating the overview failed");
            return ApiError::of(ErrorKind::InternalError).into_response();
        }
    };

    let summary = Summary::of(&days, today_start);
    render(&OverviewPage {
        shell: Shell::for_session(auth, "overview"),
        today: format_duration(summary.today_secs),
        week: format_duration(summary.week_secs),
        categories: summary.rows(),
    })
}

/// The overview's numbers, folded from the sparse daily totals.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    today_secs: i64,
    week_secs: i64,
    /// Each category's total over the whole window, longest first, with
    /// the uncategorized total last whatever its size.
    per_category: Vec<(Option<String>, i64)>,
}

impl Summary {
    fn of(days: &[DailyCategoryTotal], today_start: i64) -> Self {
        let mut today_secs = 0;
        let mut week_secs = 0;
        let mut per_category: Vec<(Option<String>, i64)> = Vec::new();

        for day in days {
            week_secs += day.total_duration_secs;
            if day.day_start_ts == today_start {
                today_secs += day.total_duration_secs;
            }
            match per_category
                .iter_mut()
                .find(|(name, _)| *name == day.category)
            {
                Some((_, total)) => *total += day.total_duration_secs,
                None => per_category.push((day.category.clone(), day.total_duration_secs)),
            }
        }

        per_category.sort_by(|(a_name, a), (b_name, b)| {
            a_name
                .is_none()
                .cmp(&b_name.is_none())
                .then(b.cmp(a))
                .then_with(|| a_name.cmp(b_name))
        });

        Self {
            today_secs,
            week_secs,
            per_category,
        }
    }

    fn rows(&self) -> Vec<CategoryRow> {
        let max = self
            .per_category
            .iter()
            .map(|(_, total)| *total)
            .max()
            .unwrap_or(0)
            .max(1);
        self.per_category
            .iter()
            .map(|(name, total)| CategoryRow {
                name: name.clone().unwrap_or_else(|| "Uncategorized".to_owned()),
                duration: format_duration(*total),
                value: *total,
                max,
                uncategorized: name.is_none(),
            })
            .collect()
    }
}

/// `2h 14m`, `47m`, `0m` - the design system's time format. Whole
/// minutes, rounded down, so a total never reads as more than it was.
fn format_duration(secs: i64) -> String {
    let minutes = secs.max(0) / 60;
    let (hours, minutes) = (minutes / 60, minutes % 60);
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(day: i64, category: Option<&str>, secs: i64) -> DailyCategoryTotal {
        DailyCategoryTotal {
            day_start_ts: day,
            category: category.map(str::to_owned),
            total_duration_secs: secs,
        }
    }

    #[test]
    fn durations_use_the_design_system_format() {
        assert_eq!(format_duration(0), "0m");
        assert_eq!(format_duration(59), "0m");
        assert_eq!(format_duration(47 * 60), "47m");
        assert_eq!(format_duration(2 * 3600 + 14 * 60 + 59), "2h 14m");
        assert_eq!(format_duration(3600), "1h 0m");
        assert_eq!(format_duration(-5), "0m");
    }

    #[test]
    fn the_summary_folds_days_into_categories() {
        let today = 10 * DAY_SECS;
        let days = [
            total(today - DAY_SECS, Some("Study"), 600),
            total(today - DAY_SECS, None, 900),
            total(today, Some("Games"), 1200),
            total(today, Some("Study"), 300),
        ];
        let summary = Summary::of(&days, today);

        assert_eq!(summary.today_secs, 1500);
        assert_eq!(summary.week_secs, 3000);
        assert_eq!(
            summary.per_category,
            vec![
                (Some("Games".to_owned()), 1200),
                (Some("Study".to_owned()), 900),
                // Largest of all, and still last.
                (None, 900),
            ]
        );
    }

    #[test]
    fn the_longest_bar_is_full_and_an_empty_week_has_no_rows() {
        let today = 10 * DAY_SECS;
        let summary = Summary::of(&[total(today, Some("Study"), 120)], today);
        let rows = summary.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, rows[0].max);

        assert!(Summary::of(&[], today).rows().is_empty());
    }
}
