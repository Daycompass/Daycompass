//! An account's time zone: which IANA zone its days are counted in.
//!
//! Events are stored as UTC Unix seconds and stay that way. The zone is
//! applied when stats are read, never when events are written, so
//! changing it re-draws the day boundaries of the whole history at once
//! and loses nothing.
//!
//! The zone database is compiled into the binary (jiff's
//! `tzdb-bundle-always`), so a name is valid or not independent of the
//! host's `/usr/share/zoneinfo`.

use jiff::tz::TimeZone;
use jiff::Timestamp;
use sqlx::SqlitePool;

use crate::auth::store::StoreError;

/// Longest IANA name in the database is well under this.
const MAX_NAME_LEN: usize = 64;

/// How finely events are bucketed in SQL before being folded into
/// local days: every UTC offset in the database is a whole multiple of
/// 15 minutes, so no bucket straddles a local midnight.
pub const OFFSET_GRANULARITY_SECS: i64 = 15 * 60;

/// Why a time zone name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimeZone;

/// A validated IANA time zone name, in the database's own spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZoneName(String);

impl TimeZoneName {
    pub fn utc() -> Self {
        Self("UTC".to_owned())
    }

    /// Accepts only a name the bundled database knows. Surrounding
    /// whitespace is not trimmed, and a POSIX string such as
    /// `EST5EDT,M3.2.0,M11.1.0` is not a name, so it is refused rather
    /// than interpreted.
    pub fn parse(raw: &str) -> Result<Self, InvalidTimeZone> {
        if raw.is_empty()
            || raw.len() > MAX_NAME_LEN
            || !raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'))
        {
            return Err(InvalidTimeZone);
        }
        let zone = TimeZone::get(raw).map_err(|_| InvalidTimeZone)?;
        // The canonical spelling, so "europe/berlin" and "Europe/Berlin"
        // are stored identically.
        let name = zone.iana_name().ok_or(InvalidTimeZone)?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_utc(&self) -> bool {
        self.0 == "UTC"
    }

    /// The Unix timestamp of local midnight at the start of the day
    /// `ts` falls in. Follows the zone's own rules, so a day on which
    /// the clocks change is 23 or 25 hours long, and a zone whose
    /// midnight does not exist that day starts it at the first moment
    /// that does.
    pub fn day_start(&self, ts: i64) -> i64 {
        let Ok(instant) = Timestamp::from_second(ts) else {
            return ts;
        };
        let Ok(zone) = TimeZone::get(&self.0) else {
            return ts;
        };
        match instant.to_zoned(zone).start_of_day() {
            Ok(start) => start.timestamp().as_second(),
            Err(_) => ts,
        }
    }
}

/// Every name the bundled database knows, sorted - what a form offers
/// as suggestions.
pub fn available_names() -> Vec<String> {
    let mut names: Vec<String> = jiff::tz::db()
        .available()
        .map(|n| n.as_str().to_owned())
        .collect();
    names.sort_unstable();
    names
}

/// The account's stored zone. A missing user reads as UTC, like a
/// freshly migrated one.
pub async fn get_for_user(pool: &SqlitePool, user_id: &str) -> Result<TimeZoneName, StoreError> {
    let stored: Option<String> = sqlx::query_scalar("SELECT timezone FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    // The column is only ever written from a validated `TimeZoneName`,
    // so a value that no longer parses (a name dropped from a newer
    // database) falls back to UTC instead of failing every stats read.
    Ok(stored
        .and_then(|name| TimeZoneName::parse(&name).ok())
        .unwrap_or_else(TimeZoneName::utc))
}

pub async fn set_for_user(
    pool: &SqlitePool,
    user_id: &str,
    zone: &TimeZoneName,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE users SET timezone = ?1 WHERE id = ?2")
        .bind(zone.as_str())
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_parse_and_are_canonicalised() {
        assert_eq!(
            TimeZoneName::parse("Europe/Berlin").unwrap().as_str(),
            "Europe/Berlin"
        );
        assert_eq!(
            TimeZoneName::parse("europe/berlin").unwrap().as_str(),
            "Europe/Berlin"
        );
        assert!(TimeZoneName::parse("UTC").unwrap().is_utc());
    }

    #[test]
    fn anything_else_is_refused() {
        for raw in [
            "",
            " Europe/Berlin",
            "Mars/Olympus",
            "EST5EDT,M3.2.0,M11.1.0",
            "../etc/passwd",
            "Europe/Berlin\0",
            &"A".repeat(65),
        ] {
            assert_eq!(TimeZoneName::parse(raw), Err(InvalidTimeZone), "{raw:?}");
        }
    }

    #[test]
    fn a_day_starts_at_local_midnight_across_a_clock_change() {
        let berlin = TimeZoneName::parse("Europe/Berlin").unwrap();
        // 2026-03-29 is the spring-forward day: 23 hours long.
        // 2026-03-28 00:00 CET = 2026-03-27 23:00 UTC.
        let day_before = 1_774_652_400;
        assert_eq!(berlin.day_start(day_before + 3600), day_before);
        let spring = day_before + 24 * 3600;
        assert_eq!(berlin.day_start(spring + 3600), spring);
        // The next midnight is only 23 hours later.
        let after = spring + 23 * 3600;
        assert_eq!(berlin.day_start(after + 60), after);
        assert_eq!(berlin.day_start(after - 60), spring);
    }

    #[test]
    fn utc_days_are_whole_multiples_of_86400() {
        let utc = TimeZoneName::utc();
        assert_eq!(utc.day_start(86_400 * 5 + 3), 86_400 * 5);
    }
}
