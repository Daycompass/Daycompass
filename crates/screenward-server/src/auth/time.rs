//! Unix-second timestamps.
//!
//! Every timestamp in the auth tables is an INTEGER count of seconds
//! since the Unix epoch, UTC, as `CLAUDE.md` requires. [`UnixTime`]
//! wraps that so a raw `i64` cannot be mistaken for anything else, and
//! so arithmetic on it saturates instead of overflowing.
//!
//! The service layer never calls [`UnixTime::now`] itself: callers pass
//! the current time in. That keeps expiry logic a pure function of its
//! inputs, which is what makes it testable without sleeping or mocking
//! a clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(i64);

impl UnixTime {
    /// Reads the system clock.
    ///
    /// A clock set before 1970 yields 0 rather than a negative value, so
    /// that every stored timestamp stays non-negative. A wrong clock can
    /// make sessions expire early or late either way - this only keeps
    /// the representation sane.
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        Self(secs)
    }

    pub const fn from_secs(secs: i64) -> Self {
        Self(secs)
    }

    pub const fn as_secs(self) -> i64 {
        self.0
    }

    /// Adds a duration, saturating at [`i64::MAX`] rather than wrapping
    /// into the past - which for an expiry time would mean an
    /// immediately expired, or worse an eternally valid, row.
    pub fn saturating_add(self, duration: Duration) -> Self {
        let secs = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
        Self(self.0.saturating_add(secs))
    }

    /// Subtracts a duration, saturating at [`i64::MIN`].
    pub fn saturating_sub(self, duration: Duration) -> Self {
        let secs = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
        Self(self.0.saturating_sub(secs))
    }

    /// How long ago `earlier` was, or zero if it is in the future.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        let delta = self.0.saturating_sub(earlier.0);
        Duration::from_secs(u64::try_from(delta).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_after_the_epoch() {
        assert!(
            UnixTime::now().as_secs() > 1_700_000_000,
            "the system clock must be set to something plausible"
        );
    }

    #[test]
    fn round_trips_through_seconds() {
        assert_eq!(UnixTime::from_secs(1_234).as_secs(), 1_234);
    }

    #[test]
    fn ordering_follows_the_timestamp() {
        assert!(UnixTime::from_secs(1) < UnixTime::from_secs(2));
    }

    #[test]
    fn addition_saturates_instead_of_wrapping() {
        let base = UnixTime::from_secs(i64::MAX - 1);
        assert_eq!(
            base.saturating_add(Duration::from_secs(10)).as_secs(),
            i64::MAX,
            "an expiry far in the future must not wrap into the past"
        );
        assert_eq!(
            UnixTime::from_secs(0)
                .saturating_add(Duration::from_secs(u64::MAX))
                .as_secs(),
            i64::MAX
        );
    }

    #[test]
    fn subtraction_saturates() {
        assert_eq!(
            UnixTime::from_secs(i64::MIN + 1)
                .saturating_sub(Duration::from_secs(10))
                .as_secs(),
            i64::MIN
        );
    }

    #[test]
    fn elapsed_time_is_zero_for_a_future_instant() {
        let earlier = UnixTime::from_secs(100);
        let later = UnixTime::from_secs(160);
        assert_eq!(
            later.saturating_duration_since(earlier),
            Duration::from_secs(60)
        );
        assert_eq!(
            earlier.saturating_duration_since(later),
            Duration::ZERO,
            "a clock that went backwards must not report a huge age"
        );
    }
}
