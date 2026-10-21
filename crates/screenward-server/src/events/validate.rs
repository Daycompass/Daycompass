//! What makes one reported event acceptable.
//!
//! Every rule here is applied per event, and a failure rejects that
//! event alone. A batch is never refused because one of its events is
//! bad: a client that cannot get rid of one malformed event would
//! retry the whole batch forever, so the batch succeeds and the one
//! event comes back with a reason.
//!
//! # The reasons are a closed set
//!
//! [`RejectReason`] follows [`crate::error::ErrorKind`]: the code is a
//! `const fn` returning `&'static str`, so no field of an event can
//! reach a client through it. That matters more here than elsewhere,
//! because these strings describe input that failed validation - which
//! is exactly the input that must not be echoed.
//!
//! # Time
//!
//! Three bounds, all against the server's clock:
//!
//! * `start_ts` may be at most [`MAX_CLOCK_SKEW`] in the future, which
//!   tolerates a client whose clock runs slightly fast.
//! * `start_ts + duration_secs` may be at most the same amount in the
//!   future, so a short event cannot be used to claim a long one that
//!   has not happened yet.
//! * `start_ts` may not be older than the configured window. Unlike
//!   the other two this is a *limit* rather than a correctness rule -
//!   it bounds how far back a device can write - so it is
//!   configurable, as `CLAUDE.md` requires of limits.
//!
//! Clock skew is why `GET /api/v1/device/me` returns `server_time`: a
//! client that finds its events rejected can see how far off it is.
//!
//! # Strings
//!
//! `app_id` is an **identifier**: it is bounds-checked and refused if
//! blank, and never modified. A server that silently rewrites an
//! identifier produces two ids for one application and nobody notices
//! until the statistics are wrong.
//!
//! `label` and `domain` are also stored as given, except that `domain`
//! is lowercased - hostnames are case-insensitive by definition, so
//! two spellings of one host must not become two hosts.
//!
//! No string may contain a control character or a bidirectional
//! override; the rule is [`crate::devices::name::is_forbidden`], shared
//! with the device name policy so the two cannot drift.

use std::time::Duration;

use crate::auth::time::UnixTime;
use crate::devices::name::is_forbidden;

/// How far into the future a client's clock may be ahead of the
/// server's before its events are refused.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Shortest and longest an event may last.
pub const MIN_DURATION_SECS: i64 = 1;
pub const MAX_DURATION_SECS: i64 = 86_400;

/// Bounds on the strings an event carries, in characters.
pub const MIN_APP_ID_CHARS: usize = 1;
pub const MAX_APP_ID_CHARS: usize = 256;
pub const MAX_LABEL_CHARS: usize = 128;
/// The longest a DNS name can be.
pub const MAX_DOMAIN_CHARS: usize = 253;
/// The longest one dot-separated label of a hostname can be.
pub const MAX_DOMAIN_LABEL_CHARS: usize = 63;

/// How many characters a canonical event id has: 32 hex digits.
pub const EVENT_ID_CHARS: usize = 32;

/// Why one event was not stored.
///
/// A closed set with constant codes, for the same reason
/// [`crate::error::ErrorKind`] is one: there is no constructor that
/// takes a `String`, so no part of a rejected event can be reflected
/// back to the client that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Not 32 lowercase hex characters, and not a canonical UUID.
    EventIdMalformed,
    DurationOutOfRange,
    StartInFuture,
    /// `start_ts + duration_secs` lands too far ahead.
    EndInFuture,
    StartTooOld,
    AppIdLength,
    /// Present but empty or only whitespace.
    AppIdBlank,
    LabelLength,
    DomainLength,
    /// Not shaped like a hostname - a scheme, a path, a port or a
    /// query would all land here.
    DomainMalformed,
    /// A control character or a text-direction override, in any field.
    ForbiddenCharacter,
}

/// Every variant, so tests can sweep the set.
pub const ALL_REJECT_REASONS: &[RejectReason] = &[
    RejectReason::EventIdMalformed,
    RejectReason::DurationOutOfRange,
    RejectReason::StartInFuture,
    RejectReason::EndInFuture,
    RejectReason::StartTooOld,
    RejectReason::AppIdLength,
    RejectReason::AppIdBlank,
    RejectReason::LabelLength,
    RejectReason::DomainLength,
    RejectReason::DomainMalformed,
    RejectReason::ForbiddenCharacter,
];

impl RejectReason {
    /// The stable machine-readable code a client sees.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EventIdMalformed => "event_id_malformed",
            Self::DurationOutOfRange => "duration_out_of_range",
            Self::StartInFuture => "start_ts_in_future",
            Self::EndInFuture => "end_ts_in_future",
            Self::StartTooOld => "start_ts_too_old",
            Self::AppIdLength => "app_id_length",
            Self::AppIdBlank => "app_id_blank",
            Self::LabelLength => "label_length",
            Self::DomainLength => "domain_length",
            Self::DomainMalformed => "domain_malformed",
            Self::ForbiddenCharacter => "forbidden_character",
        }
    }
}

/// Compile-time proof that every code is a constant, mirroring the
/// assertion in [`crate::error`]. A `const` cannot hold an allocation,
/// so interpolating a value into one of these would stop compiling.
const _: () = {
    let mut index = 0;
    while index < ALL_REJECT_REASONS.len() {
        let code: &'static str = ALL_REJECT_REASONS[index].code();
        assert!(!code.is_empty());
        index += 1;
    }
};

/// One event as the client sent it, before validation.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_id: String,
    pub start_ts: i64,
    pub duration_secs: i64,
    pub app_id: String,
    pub label: Option<String>,
    pub domain: Option<String>,
}

/// One event that passed every rule, in the form it will be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidEvent {
    /// Canonical: 32 lowercase hex characters, dashes removed.
    pub event_id: String,
    pub start_ts: i64,
    pub duration_secs: i64,
    pub app_id: String,
    pub label: Option<String>,
    /// Lowercased.
    pub domain: Option<String>,
}

/// The time bounds an event is checked against.
#[derive(Debug, Clone, Copy)]
pub struct EventWindow {
    /// How far back an event may be dated. Configurable, because it
    /// is a limit.
    pub max_age: Duration,
}

/// Checks one event.
///
/// The order is deliberate: the cheap, input-only rules run before the
/// time rules, so a client sees the structural problem with its event
/// rather than a time error that would go away once the structure was
/// fixed.
pub fn validate(
    raw: &RawEvent,
    window: EventWindow,
    now: UnixTime,
) -> Result<ValidEvent, RejectReason> {
    let event_id = canonical_event_id(&raw.event_id).ok_or(RejectReason::EventIdMalformed)?;

    let app_id = check_app_id(&raw.app_id)?;
    let label = raw.label.as_deref().map(check_label).transpose()?;
    let domain = raw.domain.as_deref().map(check_domain).transpose()?;

    if !(MIN_DURATION_SECS..=MAX_DURATION_SECS).contains(&raw.duration_secs) {
        return Err(RejectReason::DurationOutOfRange);
    }

    let skew = i64::try_from(MAX_CLOCK_SKEW.as_secs()).unwrap_or(i64::MAX);
    let latest_start = now.as_secs().saturating_add(skew);
    if raw.start_ts > latest_start {
        return Err(RejectReason::StartInFuture);
    }

    // Checked separately from the start: an event that begins now but
    // claims to last a day would otherwise record time that has not
    // happened.
    let end_ts = raw.start_ts.saturating_add(raw.duration_secs);
    if end_ts > latest_start {
        return Err(RejectReason::EndInFuture);
    }

    let oldest_start = now.saturating_sub(window.max_age).as_secs();
    if raw.start_ts < oldest_start {
        return Err(RejectReason::StartTooOld);
    }

    Ok(ValidEvent {
        event_id,
        start_ts: raw.start_ts,
        duration_secs: raw.duration_secs,
        app_id,
        label,
        domain,
    })
}

/// Normalizes a client-generated event id, or returns `None`.
///
/// Two spellings are accepted - 32 bare hex characters, and a
/// canonical dashed UUID - and both normalize to the bare form. That
/// is what makes idempotency hold for a client that changes how it
/// formats ids between versions: the same identifier in either
/// spelling collides on `UNIQUE (device_id, event_id)` rather than
/// producing two rows.
///
/// Uppercase hex is accepted and folded, since hex digits have no
/// meaning that depends on case.
pub fn canonical_event_id(raw: &str) -> Option<String> {
    // Bail before allocating on anything wildly out of range; a
    // dashed UUID is the longest accepted form.
    if raw.len() > 36 {
        return None;
    }

    let dashes: Vec<usize> = raw
        .char_indices()
        .filter(|(_, c)| *c == '-')
        .map(|(index, _)| index)
        .collect();

    // Either no dashes at all, or exactly the four of a canonical
    // UUID. "Somewhere in between" is a malformed id, not a spelling.
    if !(dashes.is_empty() || dashes == [8, 13, 18, 23]) {
        return None;
    }
    if !dashes.is_empty() && raw.len() != 36 {
        return None;
    }

    let bare: String = raw
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();

    if bare.len() != EVENT_ID_CHARS || !bare.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(bare)
}

/// `app_id` is an identifier: checked, never altered.
fn check_app_id(raw: &str) -> Result<String, RejectReason> {
    if raw.chars().any(is_forbidden) {
        return Err(RejectReason::ForbiddenCharacter);
    }
    let length = raw.chars().count();
    if !(MIN_APP_ID_CHARS..=MAX_APP_ID_CHARS).contains(&length) {
        return Err(RejectReason::AppIdLength);
    }
    // Checked after the length, so a single space is reported as the
    // blank it is rather than passing the length rule silently. The
    // value itself is not trimmed - that would be the server
    // rewriting an identifier.
    if raw.trim().is_empty() {
        return Err(RejectReason::AppIdBlank);
    }
    Ok(raw.to_owned())
}

fn check_label(raw: &str) -> Result<String, RejectReason> {
    if raw.chars().any(is_forbidden) {
        return Err(RejectReason::ForbiddenCharacter);
    }
    if raw.chars().count() > MAX_LABEL_CHARS {
        return Err(RejectReason::LabelLength);
    }
    Ok(raw.to_owned())
}

/// A bare hostname, and nothing resembling a URL.
///
/// The charset rule does most of the work: `/`, `:`, `?`, `#` and `@`
/// are all outside it, so a scheme, a port, a path, a query or
/// userinfo each fail without needing a rule of their own. Only ASCII
/// is accepted - an internationalised name must be punycoded by the
/// client, because accepting both forms would mean one host arriving
/// under two spellings.
fn check_domain(raw: &str) -> Result<String, RejectReason> {
    if raw.chars().any(is_forbidden) {
        return Err(RejectReason::ForbiddenCharacter);
    }
    if raw.chars().count() > MAX_DOMAIN_CHARS {
        return Err(RejectReason::DomainLength);
    }

    let lowered = raw.to_ascii_lowercase();
    // A single trailing dot is a legal, fully qualified spelling; drop
    // it so "example.com." and "example.com" are one host.
    let host = lowered.strip_suffix('.').unwrap_or(&lowered);

    if host.is_empty() {
        return Err(RejectReason::DomainMalformed);
    }

    for label in host.split('.') {
        let length = label.len();
        if length == 0 || length > MAX_DOMAIN_LABEL_CHARS {
            return Err(RejectReason::DomainMalformed);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RejectReason::DomainMalformed);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RejectReason::DomainMalformed);
        }
    }

    Ok(host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn now() -> UnixTime {
        UnixTime::from_secs(NOW)
    }

    fn window() -> EventWindow {
        EventWindow {
            max_age: Duration::from_secs(90 * 24 * 60 * 60),
        }
    }

    /// A valid event, which each test below perturbs in exactly one
    /// way. Starting from something that passes is what makes a
    /// failure attributable to the field under test.
    fn valid() -> RawEvent {
        RawEvent {
            event_id: "0123456789abcdef0123456789abcdef".to_owned(),
            start_ts: NOW - 3_600,
            duration_secs: 60,
            app_id: "org.example.browser".to_owned(),
            label: Some("Example Browser".to_owned()),
            domain: Some("example.com".to_owned()),
        }
    }

    fn check(raw: RawEvent) -> Result<ValidEvent, RejectReason> {
        validate(&raw, window(), now())
    }

    #[test]
    fn a_well_formed_event_is_accepted_unchanged() {
        let event = check(valid()).expect("the baseline must be valid");
        assert_eq!(event.event_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(event.start_ts, NOW - 3_600);
        assert_eq!(event.duration_secs, 60);
        assert_eq!(event.app_id, "org.example.browser");
        assert_eq!(event.label.as_deref(), Some("Example Browser"));
        assert_eq!(event.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn the_optional_fields_are_optional() {
        let event = check(RawEvent {
            label: None,
            domain: None,
            ..valid()
        })
        .expect("label and domain must be optional");
        assert!(event.label.is_none());
        assert!(event.domain.is_none());
    }

    // --- event ids ----------------------------------------------------

    #[test]
    fn both_accepted_event_id_spellings_normalize_to_one() {
        let bare = "0123456789abcdef0123456789abcdef";
        let dashed = "01234567-89ab-cdef-0123-456789abcdef";

        assert_eq!(canonical_event_id(bare).as_deref(), Some(bare));
        assert_eq!(
            canonical_event_id(dashed).as_deref(),
            Some(bare),
            "the two spellings of one id must collide, not duplicate"
        );
        assert_eq!(
            canonical_event_id(&bare.to_ascii_uppercase()).as_deref(),
            Some(bare),
            "hex has no case"
        );
        assert_eq!(
            canonical_event_id(&dashed.to_ascii_uppercase()).as_deref(),
            Some(bare)
        );
    }

    #[test]
    fn a_malformed_event_id_is_refused() {
        let cases = [
            ("empty", ""),
            ("31 characters", "0123456789abcdef0123456789abcde"),
            ("33 characters", "0123456789abcdef0123456789abcdef0"),
            ("not hex", "0123456789abcdef0123456789abcdeg"),
            (
                "dashes in the wrong places",
                "0123-456789abcdef0123456789abcdef",
            ),
            ("one dash too few", "0123456789ab-cdef-0123-456789abcdef"),
            ("a trailing dash", "0123456789abcdef0123456789abcdef-"),
            ("braced uuid", "{01234567-89ab-cdef-0123-456789abcdef}"),
            ("whitespace", " 0123456789abcdef0123456789abcdef"),
        ];

        for (label, candidate) in cases {
            assert_eq!(canonical_event_id(candidate), None, "{label}");
            assert_eq!(
                check(RawEvent {
                    event_id: candidate.to_owned(),
                    ..valid()
                }),
                Err(RejectReason::EventIdMalformed),
                "{label}"
            );
        }
    }

    #[test]
    fn an_enormous_event_id_is_refused_without_allocating() {
        let huge: String = std::iter::repeat_n('a', 1_000_000).collect();
        assert_eq!(canonical_event_id(&huge), None);
    }

    // --- duration -----------------------------------------------------

    /// Both bounds, and one step past each.
    #[test]
    fn the_duration_bounds_bite_exactly_where_they_are_written() {
        for (label, duration, expected) in [
            ("one below the minimum", MIN_DURATION_SECS - 1, false),
            ("the minimum", MIN_DURATION_SECS, true),
            ("the maximum", MAX_DURATION_SECS, true),
            ("one above the maximum", MAX_DURATION_SECS + 1, false),
            ("negative", -60, false),
        ] {
            // Start far enough back that a day-long event still ends
            // in the past, so this tests the duration and nothing else.
            let result = check(RawEvent {
                start_ts: NOW - MAX_DURATION_SECS - 3_600,
                duration_secs: duration,
                ..valid()
            });
            assert_eq!(result.is_ok(), expected, "{label} ({duration})");
            if !expected {
                assert_eq!(result.unwrap_err(), RejectReason::DurationOutOfRange);
            }
        }
    }

    // --- time ---------------------------------------------------------

    #[test]
    fn the_future_bound_on_the_start_bites_at_the_skew_allowance() {
        let skew = i64::try_from(MAX_CLOCK_SKEW.as_secs()).unwrap();

        let at_the_edge = check(RawEvent {
            start_ts: NOW + skew,
            duration_secs: MIN_DURATION_SECS,
            ..valid()
        });
        // The start is exactly at the allowance, but a one-second
        // event then ends one second past it, which the end rule
        // catches. That is the rule working, not an off-by-one.
        assert_eq!(at_the_edge.unwrap_err(), RejectReason::EndInFuture);

        assert_eq!(
            check(RawEvent {
                start_ts: NOW + skew + 1,
                ..valid()
            })
            .unwrap_err(),
            RejectReason::StartInFuture,
            "one second past the allowance must be refused"
        );
    }

    #[test]
    fn the_future_bound_on_the_end_bites_at_the_skew_allowance() {
        let skew = i64::try_from(MAX_CLOCK_SKEW.as_secs()).unwrap();

        // An event ending exactly at the allowance is fine.
        assert!(
            check(RawEvent {
                start_ts: NOW + skew - 60,
                duration_secs: 60,
                ..valid()
            })
            .is_ok(),
            "an end exactly at the allowance must be accepted"
        );

        // One second longer, and it claims time that has not happened.
        assert_eq!(
            check(RawEvent {
                start_ts: NOW + skew - 60,
                duration_secs: 61,
                ..valid()
            })
            .unwrap_err(),
            RejectReason::EndInFuture
        );
    }

    /// A start that is in the past but whose duration runs past the
    /// allowance: the case the end rule exists for.
    #[test]
    fn a_past_event_may_not_run_into_the_future() {
        assert_eq!(
            check(RawEvent {
                start_ts: NOW - 60,
                duration_secs: MAX_DURATION_SECS,
                ..valid()
            })
            .unwrap_err(),
            RejectReason::EndInFuture
        );
    }

    #[test]
    fn the_age_bound_bites_exactly_at_the_configured_window() {
        let max_age = i64::try_from(window().max_age.as_secs()).unwrap();

        assert!(
            check(RawEvent {
                start_ts: NOW - max_age,
                ..valid()
            })
            .is_ok(),
            "exactly at the window must be accepted"
        );
        assert_eq!(
            check(RawEvent {
                start_ts: NOW - max_age - 1,
                ..valid()
            })
            .unwrap_err(),
            RejectReason::StartTooOld,
            "one second older must be refused"
        );
    }

    /// The window is configurable, so a different one must actually
    /// move the boundary rather than the 90 days being baked in.
    #[test]
    fn the_age_bound_follows_the_configured_window() {
        let narrow = EventWindow {
            max_age: Duration::from_secs(3_600),
        };
        let raw = RawEvent {
            start_ts: NOW - 7_200,
            ..valid()
        };

        assert!(validate(&raw, window(), now()).is_ok());
        assert_eq!(
            validate(&raw, narrow, now()).unwrap_err(),
            RejectReason::StartTooOld
        );
    }

    // --- strings ------------------------------------------------------

    #[test]
    fn the_app_id_bounds_bite_exactly_where_they_are_written() {
        for (label, length, ok) in [
            ("the minimum", MIN_APP_ID_CHARS, true),
            ("the maximum", MAX_APP_ID_CHARS, true),
            ("one over the maximum", MAX_APP_ID_CHARS + 1, false),
        ] {
            let result = check(RawEvent {
                app_id: "x".repeat(length),
                ..valid()
            });
            assert_eq!(result.is_ok(), ok, "{label}");
            if !ok {
                assert_eq!(result.unwrap_err(), RejectReason::AppIdLength);
            }
        }

        assert_eq!(
            check(RawEvent {
                app_id: String::new(),
                ..valid()
            })
            .unwrap_err(),
            RejectReason::AppIdLength,
            "empty is below the minimum"
        );
    }

    /// Blank is refused, and - unlike a device name - never trimmed.
    /// The server must not rewrite an identifier.
    #[test]
    fn a_blank_app_id_is_refused_rather_than_trimmed() {
        for blank in [" ", "   ", "\u{a0}"] {
            assert_eq!(
                check(RawEvent {
                    app_id: blank.to_owned(),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::AppIdBlank,
                "{blank:?}"
            );
        }

        // And one with real content keeps its surrounding whitespace
        // exactly as sent.
        let event = check(RawEvent {
            app_id: "  org.example  ".to_owned(),
            ..valid()
        })
        .expect("padding is not a reason to refuse an identifier");
        assert_eq!(
            event.app_id, "  org.example  ",
            "an identifier must be stored exactly as sent"
        );
    }

    #[test]
    fn the_label_bound_bites_exactly_where_it_is_written() {
        assert!(check(RawEvent {
            label: Some("x".repeat(MAX_LABEL_CHARS)),
            ..valid()
        })
        .is_ok());

        assert_eq!(
            check(RawEvent {
                label: Some("x".repeat(MAX_LABEL_CHARS + 1)),
                ..valid()
            })
            .unwrap_err(),
            RejectReason::LabelLength
        );

        // An empty label is not a length error: it is a label that
        // says nothing, which is the client's business.
        assert!(check(RawEvent {
            label: Some(String::new()),
            ..valid()
        })
        .is_ok());
    }

    /// Lengths are counted in characters. A 128-character label of
    /// multi-byte characters is far over 128 bytes and must pass.
    #[test]
    fn string_lengths_are_measured_in_characters() {
        assert!(check(RawEvent {
            label: Some("\u{e4}".repeat(MAX_LABEL_CHARS)),
            ..valid()
        })
        .is_ok());
        assert_eq!(
            check(RawEvent {
                label: Some("\u{e4}".repeat(MAX_LABEL_CHARS + 1)),
                ..valid()
            })
            .unwrap_err(),
            RejectReason::LabelLength
        );
    }

    // --- domains ------------------------------------------------------

    #[test]
    fn ordinary_hostnames_are_accepted_and_lowercased() {
        for (sent, stored) in [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("Sub.Example.Com", "sub.example.com"),
            ("example.com.", "example.com"),
            ("a-b.example.com", "a-b.example.com"),
            ("localhost", "localhost"),
            ("192.0.2.10", "192.0.2.10"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ] {
            let event = check(RawEvent {
                domain: Some(sent.to_owned()),
                ..valid()
            })
            .unwrap_or_else(|err| panic!("{sent} must be accepted: {err:?}"));
            assert_eq!(event.domain.as_deref(), Some(stored), "{sent}");
        }
    }

    /// The point of the field: a hostname, never a URL. Each of these
    /// would be a browsing history if it were stored.
    #[test]
    fn anything_resembling_a_url_is_refused() {
        for candidate in [
            "https://example.com",
            "example.com/path",
            "example.com/path?q=secret",
            "example.com:443",
            "user@example.com",
            "//example.com",
            "example.com#fragment",
            "example.com?q=1",
        ] {
            assert_eq!(
                check(RawEvent {
                    domain: Some(candidate.to_owned()),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::DomainMalformed,
                "{candidate} must not be stored"
            );
        }
    }

    #[test]
    fn a_malformed_hostname_is_refused() {
        for candidate in [
            "",
            ".",
            "..",
            ".example.com",
            "example..com",
            "example.com..",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "\u{e4}example.com",
            "example.com\u{e4}",
        ] {
            assert_eq!(
                check(RawEvent {
                    domain: Some(candidate.to_owned()),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::DomainMalformed,
                "{candidate:?} must be refused"
            );
        }
    }

    #[test]
    fn the_domain_bounds_bite_exactly_where_they_are_written() {
        // One label at its maximum, and one character past it.
        let longest_label = "a".repeat(MAX_DOMAIN_LABEL_CHARS);
        assert!(check(RawEvent {
            domain: Some(format!("{longest_label}.example")),
            ..valid()
        })
        .is_ok());
        assert_eq!(
            check(RawEvent {
                domain: Some(format!(
                    "{}.example",
                    "a".repeat(MAX_DOMAIN_LABEL_CHARS + 1)
                )),
                ..valid()
            })
            .unwrap_err(),
            RejectReason::DomainMalformed
        );

        // The whole name at its maximum: four 63-character labels plus
        // three dots is 255, so trim to land exactly on 253.
        let at_max = format!(
            "{}.{}.{}.{}",
            "a".repeat(MAX_DOMAIN_LABEL_CHARS),
            "b".repeat(MAX_DOMAIN_LABEL_CHARS),
            "c".repeat(MAX_DOMAIN_LABEL_CHARS),
            "d".repeat(MAX_DOMAIN_CHARS - 3 - 3 * MAX_DOMAIN_LABEL_CHARS)
        );
        assert_eq!(at_max.chars().count(), MAX_DOMAIN_CHARS);
        assert!(
            check(RawEvent {
                domain: Some(at_max.clone()),
                ..valid()
            })
            .is_ok(),
            "exactly the maximum must be accepted"
        );

        assert_eq!(
            check(RawEvent {
                domain: Some(format!("{at_max}x")),
                ..valid()
            })
            .unwrap_err(),
            RejectReason::DomainLength,
            "one character over must be refused"
        );
    }

    // --- forbidden characters -----------------------------------------

    /// The rule is shared with the device name policy, and applies to
    /// every string an event carries.
    #[test]
    fn control_characters_and_bidi_overrides_are_refused_in_every_field() {
        for bad in ['\n', '\r', '\u{0}', '\u{7f}', '\u{202e}', '\u{2066}'] {
            assert_eq!(
                check(RawEvent {
                    app_id: format!("org.example{bad}"),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::ForbiddenCharacter,
                "app_id with U+{:04X}",
                u32::from(bad)
            );
            assert_eq!(
                check(RawEvent {
                    label: Some(format!("Browser{bad}")),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::ForbiddenCharacter,
                "label with U+{:04X}",
                u32::from(bad)
            );
            assert_eq!(
                check(RawEvent {
                    domain: Some(format!("example.com{bad}")),
                    ..valid()
                })
                .unwrap_err(),
                RejectReason::ForbiddenCharacter,
                "domain with U+{:04X}",
                u32::from(bad)
            );
        }
    }

    // --- the reason set -----------------------------------------------

    /// The codes are what a client branches on, so they must be
    /// distinct, stable-looking identifiers that carry no input.
    #[test]
    fn every_reason_has_a_distinct_plain_code() {
        for (index, reason) in ALL_REJECT_REASONS.iter().enumerate() {
            let code = reason.code();
            assert!(!code.is_empty(), "{reason:?}");
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{reason:?} is not a plain identifier: {code}"
            );
            for other in &ALL_REJECT_REASONS[index + 1..] {
                assert_ne!(code, other.code(), "{reason:?} and {other:?} share a code");
            }
        }
        assert_eq!(ALL_REJECT_REASONS.len(), 11);
    }
}
