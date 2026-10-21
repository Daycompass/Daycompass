//! A fixed-window rate limiter with a bounded amount of state.
//!
//! Written here rather than taken from a crate for one reason: the
//! bound. A keyed limiter that grows a map per key is a memory
//! exhaustion vector when the keys are attacker-chosen, and bounding it
//! is the part that needed the care, not the counting.
//!
//! Fixed windows only, never a lockout. A counter always expires on its
//! own, so nobody can put another account into a state that needs an
//! administrator to undo - which is itself an attack when the target is
//! someone else's account.
//!
//! ## What happens when the map is full
//!
//! First every window whose period has ended is dropped. If that is not
//! enough, the entry whose window started earliest is evicted and the
//! request is admitted.
//!
//! Admitting is the lesser evil. Refusing instead would mean an attacker
//! who fills the map denies service to everyone, and a lockout is
//! exactly what this limiter is supposed to be impossible. The cost of
//! admitting is that someone controlling more distinct keys than
//! `max_entries` can dilute the limit - but at that point they already
//! command `max_entries` times the per-key budget, so the eviction is
//! not what is buying them anything.
//!
//! Each bucket gets its own limiter and its own bound, so pressure on
//! one - say invented usernames - cannot evict another's entries.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::auth::time::UnixTime;
use crate::config::RateLimitRule;

/// What a limiter decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Refused until the current window ends.
    Limited {
        retry_after: Duration,
    },
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// One key's current window.
#[derive(Debug, Clone, Copy)]
struct Window {
    started_at: UnixTime,
    count: u32,
}

impl Window {
    fn has_ended(&self, length: Duration, now: UnixTime) -> bool {
        now.saturating_duration_since(self.started_at) >= length
    }
}

/// Counts requests per key within fixed windows.
#[derive(Debug)]
pub struct RateLimiter<K> {
    rule: RateLimitRule,
    max_entries: usize,
    windows: Mutex<HashMap<K, Window>>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(rule: RateLimitRule, max_entries: usize) -> Self {
        Self {
            rule,
            // Zero would mean holding no state and therefore enforcing
            // nothing; configuration rejects it, and this is the second
            // line of defence.
            max_entries: max_entries.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Records one request against `key` and says whether it may go
    /// ahead.
    pub fn check(&self, key: K, now: UnixTime) -> Decision {
        // Recovering from a poisoned lock rather than propagating the
        // panic: the critical section below cannot panic, and treating a
        // poisoned limiter as unusable would turn one unrelated panic
        // into rate limiting being off for the rest of the process.
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !windows.contains_key(&key) && windows.len() >= self.max_entries {
            self.make_room(&mut windows, now);
        }

        let window = windows.entry(key).or_insert(Window {
            started_at: now,
            count: 0,
        });

        if window.has_ended(self.rule.window, now) {
            window.started_at = now;
            window.count = 0;
        }

        if window.count >= self.rule.max {
            let elapsed = now.saturating_duration_since(window.started_at);
            return Decision::Limited {
                retry_after: self.rule.window.saturating_sub(elapsed),
            };
        }

        window.count += 1;
        Decision::Allowed
    }

    /// Frees one slot. Linear in the number of entries, but only runs
    /// once the map is at its bound.
    fn make_room(&self, windows: &mut HashMap<K, Window>, now: UnixTime) {
        windows.retain(|_, window| !window.has_ended(self.rule.window, now));

        if windows.len() < self.max_entries {
            return;
        }

        let oldest = windows
            .iter()
            .min_by_key(|(_, window)| window.started_at)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            windows.remove(&oldest);
        }
    }

    /// How many keys are currently tracked. For tests and diagnostics.
    pub fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// A rate limit key for a login attempt against one account name.
///
/// Holds a truncated SHA-256 of the normalized name rather than the name
/// itself, for two reasons: every entry is the same small fixed size
/// whatever was sent, and the limiter's state is not a list of the
/// account names people have been trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UsernameKey([u8; 16]);

impl UsernameKey {
    /// Normalizes the same way the username policy does - trim, then
    /// ASCII lowercase - before hashing.
    ///
    /// Applied to the raw input rather than to a validated [`Username`],
    /// so that input which would *fail* the policy still lands in a
    /// bucket. Otherwise an attacker could dodge the per-account limit
    /// by appending a character that makes the name invalid.
    ///
    /// [`Username`]: crate::auth::username::Username
    pub fn new(raw_username: &str) -> Self {
        let normalized = raw_username.trim().to_ascii_lowercase();
        let digest = Sha256::digest(normalized.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        Self(key)
    }
}

/// A rate limit key for one account, for the endpoints an
/// already-authenticated account can spend server work on.
///
/// Holds a truncated SHA-256 of the user id for the same two reasons as
/// [`UsernameKey`]: every entry is one fixed small size, and the
/// limiter's state is not a list of which accounts have been active.
///
/// Keyed by account rather than by address on purpose. The address a
/// logged-in client comes from can change between requests - mobile
/// networks, a VPN - while the thing being protected is one account's
/// share of the Argon2 capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserKey([u8; 16]);

impl UserKey {
    pub fn new(user_id: &str) -> Self {
        let digest = Sha256::digest(user_id.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        Self(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(max: u32, window_secs: u64) -> RateLimitRule {
        RateLimitRule {
            max,
            window: Duration::from_secs(window_secs),
        }
    }

    fn at(secs: i64) -> UnixTime {
        UnixTime::from_secs(secs)
    }

    #[test]
    fn requests_are_allowed_up_to_the_limit_then_refused() {
        let limiter = RateLimiter::new(rule(3, 60), 100);

        for attempt in 1..=3 {
            assert_eq!(
                limiter.check("key", at(1_000)),
                Decision::Allowed,
                "attempt {attempt} must be allowed"
            );
        }

        let decision = limiter.check("key", at(1_000));
        assert!(matches!(decision, Decision::Limited { .. }));
    }

    #[test]
    fn retry_after_counts_down_to_the_end_of_the_window() {
        let limiter = RateLimiter::new(rule(1, 60), 100);
        assert_eq!(limiter.check("key", at(1_000)), Decision::Allowed);

        assert_eq!(
            limiter.check("key", at(1_000)),
            Decision::Limited {
                retry_after: Duration::from_secs(60)
            }
        );
        assert_eq!(
            limiter.check("key", at(1_045)),
            Decision::Limited {
                retry_after: Duration::from_secs(15)
            }
        );
    }

    /// The counter always expires on its own. Nothing here can put a key
    /// into a state that needs an administrator to clear, which is what
    /// would let one person lock another out for good.
    #[test]
    fn the_window_expires_and_the_key_recovers() {
        let limiter = RateLimiter::new(rule(2, 60), 100);
        assert!(limiter.check("key", at(1_000)).is_allowed());
        assert!(limiter.check("key", at(1_000)).is_allowed());
        assert!(!limiter.check("key", at(1_000)).is_allowed());

        // Still refused one second before the window ends.
        assert!(!limiter.check("key", at(1_059)).is_allowed());
        // Allowed again the moment it ends.
        assert!(limiter.check("key", at(1_060)).is_allowed());
    }

    #[test]
    fn keys_are_counted_independently() {
        let limiter = RateLimiter::new(rule(1, 60), 100);
        assert!(limiter.check("first", at(1_000)).is_allowed());
        assert!(
            limiter.check("second", at(1_000)).is_allowed(),
            "one key hitting its limit must not affect another"
        );
        assert!(!limiter.check("first", at(1_000)).is_allowed());
    }

    /// The bound is the reason this limiter is hand-written: tracked
    /// state must not grow with attacker-chosen keys.
    #[test]
    fn the_number_of_tracked_keys_stays_within_the_bound() {
        let limiter = RateLimiter::new(rule(5, 60), 8);

        for key in 0..1_000 {
            limiter.check(key, at(1_000));
            assert!(
                limiter.tracked() <= 8,
                "tracked keys must never exceed the bound"
            );
        }
        assert_eq!(limiter.tracked(), 8);
    }

    #[test]
    fn expired_windows_are_reclaimed_before_anything_is_evicted() {
        let limiter = RateLimiter::new(rule(5, 60), 4);

        for key in 0..4 {
            limiter.check(key, at(1_000));
        }
        assert_eq!(limiter.tracked(), 4);

        // A new key once every window has ended: the stale ones are
        // dropped rather than one being evicted while three sit expired.
        limiter.check(99, at(2_000));
        assert_eq!(
            limiter.tracked(),
            1,
            "ended windows must be reclaimed first"
        );
    }

    /// Admitting rather than refusing when the map is full is the
    /// deliberate choice: refusing would let someone who fills the map
    /// deny service to everyone.
    #[test]
    fn a_full_map_still_admits_a_new_key() {
        let limiter = RateLimiter::new(rule(5, 60), 2);
        assert!(limiter.check("a", at(1_000)).is_allowed());
        assert!(limiter.check("b", at(1_000)).is_allowed());
        assert!(
            limiter.check("c", at(1_000)).is_allowed(),
            "a full limiter must not lock everybody out"
        );
        assert!(limiter.tracked() <= 2);
    }

    #[test]
    fn a_zero_bound_is_raised_to_one_rather_than_disabling_the_limiter() {
        let limiter = RateLimiter::new(rule(1, 60), 0);
        assert!(limiter.check("key", at(1_000)).is_allowed());
        assert!(
            !limiter.check("key", at(1_000)).is_allowed(),
            "the limiter must still count"
        );
    }

    #[test]
    fn a_limiter_is_usable_from_several_threads() {
        use std::sync::Arc;

        let limiter = Arc::new(RateLimiter::new(rule(100, 60), 64));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                for key in 0..50 {
                    limiter.check(key, at(1_000));
                }
            }));
        }
        for handle in handles {
            handle.join().expect("no thread may panic");
        }
        assert!(limiter.tracked() <= 64);
    }

    // --- username keys ------------------------------------------------

    #[test]
    fn username_keys_normalize_like_the_username_policy() {
        let canonical = UsernameKey::new("alice");
        for spelling in ["alice", "ALICE", "Alice", "  alice  ", "\talice\n"] {
            assert_eq!(
                UsernameKey::new(spelling),
                canonical,
                "{spelling:?} must share a bucket"
            );
        }
        assert_ne!(UsernameKey::new("bob"), canonical);
    }

    /// Input that would fail the username policy must still be bucketed,
    /// or appending one bad character would dodge the per-account limit.
    #[test]
    fn invalid_usernames_are_still_bucketed() {
        let weird = UsernameKey::new("alice!");
        assert_eq!(UsernameKey::new("ALICE!"), weird);
        assert_ne!(weird, UsernameKey::new("alice"));

        // And an enormous name still produces a fixed-size key.
        let huge: String = std::iter::repeat_n('x', 100_000).collect();
        let key = UsernameKey::new(&huge);
        assert_eq!(std::mem::size_of_val(&key), 16);
    }

    #[test]
    fn a_username_key_does_not_contain_the_name() {
        let key = UsernameKey::new("alice");
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains("alice"),
            "limiter state must not be a list of attempted account names"
        );
    }

    // --- account keys -------------------------------------------------

    /// Unlike a username, a user id is used exactly as given: it is
    /// already canonical, and folding case would merge two distinct ids.
    #[test]
    fn account_keys_are_per_id_and_fixed_size() {
        let key = UserKey::new("00000000-0000-7000-8000-000000000001");
        assert_eq!(key, UserKey::new("00000000-0000-7000-8000-000000000001"));
        assert_ne!(key, UserKey::new("00000000-0000-7000-8000-000000000002"));

        let huge: String = std::iter::repeat_n('x', 100_000).collect();
        assert_eq!(std::mem::size_of_val(&UserKey::new(&huge)), 16);
    }

    #[test]
    fn an_account_key_does_not_contain_the_id() {
        let id = "00000000-0000-7000-8000-000000000001";
        let rendered = format!("{:?}", UserKey::new(id));
        assert!(!rendered.contains(id));
    }

    /// The per-account limiter must count every attempt, not only the
    /// ones that turn out to be wrong: a correct-password flood is also
    /// a way to occupy the hashing permits.
    #[test]
    fn every_attempt_counts_against_the_account_limit() {
        let limiter = RateLimiter::new(rule(2, 60), 100);
        let key = UserKey::new("00000000-0000-7000-8000-000000000001");

        assert!(limiter.check(key, at(0)).is_allowed());
        assert!(limiter.check(key, at(0)).is_allowed());
        assert!(!limiter.check(key, at(0)).is_allowed());
        // A different account is unaffected.
        assert!(limiter
            .check(UserKey::new("00000000-0000-7000-8000-000000000002"), at(0))
            .is_allowed());
    }
}
