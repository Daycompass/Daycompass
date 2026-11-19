//! Screen time on the Missions pages: the account's own events set
//! against its tracked time - the distraction during an entry, a
//! category track under Today's timeline, the distraction of a week.
//!
//! Events still carry no category. Each is resolved here, at query
//! time, with the account's own rules and the built-in fallback
//! ([`Resolver`]), exactly as the overview resolves them. Overlaps are
//! summed as reported, as in the stats: two devices covering the same
//! minute count it twice.
//!
//! # Whose data this is
//!
//! The caller's own events only, read through
//! [`events::select_own_overlapping`], which is scoped by the caller's
//! own user id like every other event read. With the setting off
//! (`users.missions_screen_time = 0`) no event is read at all.

use sqlx::SqlitePool;

use super::store;
use crate::auth::store::StoreError;
use crate::categories::builtin;
use crate::categories::resolve::Resolver;
use crate::categories::service as categories;
use crate::events::store as events;

/// Spans of one category this close together are drawn as one.
const MERGE_GAP_SECS: i64 = 60;

/// What the account chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    /// Category names, sorted. Empty: no distraction number anywhere.
    pub distraction: Vec<String>,
}

pub async fn settings(pool: &SqlitePool, user_id: &str) -> Result<Settings, StoreError> {
    let mut conn = pool.acquire().await?;
    Ok(Settings {
        enabled: store::screen_time_enabled(&mut conn, user_id).await?,
        distraction: store::distraction_categories(&mut conn, user_id).await?,
    })
}

/// The categories an account can mark: those its own rules name, and
/// the built-in ones, sorted case-insensitively, each once.
pub async fn categories_offered(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<String>, StoreError> {
    let rules = categories::list_own_rules(pool, user_id).await?;
    let mut names: Vec<String> = rules
        .into_iter()
        .map(|rule| rule.category)
        .chain(builtin::names().into_iter().map(str::to_owned))
        .collect();
    names.sort_by_cached_key(|name| (name.to_lowercase(), name.clone()));
    names.dedup();
    Ok(names)
}

/// Saves both settings. A name that is not among
/// [`categories_offered`] is dropped rather than refused: a rule
/// deleted between showing the form and sending it is not an error, and
/// nothing else could name a category to mark.
pub async fn save_settings(
    pool: &SqlitePool,
    user_id: &str,
    enabled: bool,
    distraction: &[String],
) -> Result<Settings, StoreError> {
    let offered = categories_offered(pool, user_id).await?;
    let mut marked: Vec<String> = distraction
        .iter()
        .filter(|name| offered.contains(name))
        .cloned()
        .collect();
    marked.sort_unstable();
    marked.dedup();
    let mut tx = pool.begin().await?;
    store::set_screen_time(&mut tx, user_id, enabled, &marked).await?;
    tx.commit().await?;
    Ok(Settings {
        enabled,
        distraction: marked,
    })
}

/// One stretch of screen time, `[start, end)`, with its category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: i64,
    pub end: i64,
    /// `None`: no rule and no built-in entry matched.
    pub category: Option<String>,
    pub distraction: bool,
}

/// The account's screen time around one window, resolved.
pub struct ScreenTime {
    spans: Vec<Span>,
    /// Whether any category counts as distraction.
    marked: bool,
}

impl ScreenTime {
    /// Seconds of distraction inside `[start, end)`; `None` if the
    /// account marked no category, so there is no number to show.
    pub fn distraction_in(&self, (start, end): (i64, i64)) -> Option<i64> {
        self.marked.then(|| {
            self.spans
                .iter()
                .filter(|span| span.distraction)
                .map(|span| (span.end.min(end) - span.start.max(start)).max(0))
                .sum()
        })
    }

    /// The spans inside `[start, end)`, clipped to it, with spans of one
    /// category that overlap or nearly touch merged: what a timeline
    /// track draws. Sorted by category, then start.
    pub fn track(&self, (start, end): (i64, i64)) -> Vec<Span> {
        let mut clipped: Vec<Span> = self
            .spans
            .iter()
            .filter(|span| span.start < end && span.end > start)
            .map(|span| Span {
                start: span.start.max(start),
                end: span.end.min(end),
                ..span.clone()
            })
            .collect();
        clipped.sort_by(|a, b| (&a.category, a.start).cmp(&(&b.category, b.start)));
        let mut merged: Vec<Span> = Vec::new();
        for span in clipped {
            match merged.last_mut() {
                Some(last)
                    if last.category == span.category
                        && span.start <= last.end + MERGE_GAP_SECS =>
                {
                    last.end = last.end.max(span.end);
                }
                _ => merged.push(span),
            }
        }
        merged
    }
}

/// The account's screen time overlapping `window`, or `None` if the
/// account turned the integration off - in which case no event is read.
pub async fn load(
    pool: &SqlitePool,
    user_id: &str,
    window: (i64, i64),
) -> Result<Option<ScreenTime>, StoreError> {
    let settings = settings(pool, user_id).await?;
    if !settings.enabled {
        return Ok(None);
    }
    let rules = categories::list_own_rules(pool, user_id).await?;
    let resolver = Resolver::build(&rules);
    // shortcut: reads the window's events whole (a week at most); sum
    // in SQL per window instead if an account's week ever runs to many
    // tens of thousands of events.
    let spans = events::select_own_overlapping(pool, user_id, window.0, window.1)
        .await?
        .into_iter()
        .map(|event| {
            let category = resolver.category_for(&event.app_id, event.domain.as_deref());
            Span {
                start: event.start_ts,
                end: event.start_ts + event.duration_secs,
                distraction: category
                    .is_some_and(|category| settings.distraction.iter().any(|d| d == category)),
                category: category.map(str::to_owned),
            }
        })
        .collect();
    Ok(Some(ScreenTime {
        spans,
        marked: !settings.distraction.is_empty(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: i64, end: i64, category: Option<&str>, distraction: bool) -> Span {
        Span {
            start,
            end,
            category: category.map(str::to_owned),
            distraction,
        }
    }

    #[test]
    fn distraction_counts_marked_time_inside_the_window_only() {
        let screen = ScreenTime {
            spans: vec![
                span(0, 100, Some("Social"), true),
                span(50, 150, Some("Social"), true),
                span(100, 200, Some("Study"), false),
            ],
            marked: true,
        };
        // Overlaps count twice, as in the stats.
        assert_eq!(screen.distraction_in((50, 120)), Some(50 + 70));
        assert_eq!(screen.distraction_in((200, 300)), Some(0));

        let unmarked = ScreenTime {
            spans: screen.spans.clone(),
            marked: false,
        };
        assert_eq!(unmarked.distraction_in((0, 300)), None);
    }

    #[test]
    fn the_track_clips_and_merges_one_category_at_a_time() {
        let screen = ScreenTime {
            spans: vec![
                span(-50, 10, Some("Social"), true),
                span(30, 40, Some("Social"), true),
                span(200, 300, Some("Social"), true),
                span(20, 25, None, false),
            ],
            marked: true,
        };
        assert_eq!(
            screen.track((0, 250)),
            vec![
                span(20, 25, None, false),
                span(0, 40, Some("Social"), true),
                span(200, 250, Some("Social"), true),
            ]
        );
    }
}
