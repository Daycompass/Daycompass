//! The two kinds of category rule, and what makes a pattern valid for
//! each.
//!
//! Deliberately **not** a reuse of [`crate::events::validate`]'s
//! `check_app_id`/`check_domain`: those validate what a *device*
//! reported, these validate what an *account* configured as a
//! standing preference. The shape rule happens to coincide today -
//! both reuse the same length constants and the same shared
//! [`is_forbidden`] character class - but the two are different
//! concepts, and a rule's pattern is not required to track whatever
//! an event's validator does in the future.

use std::fmt;

use crate::devices::name::is_forbidden;
use crate::events::validate::{
    MAX_APP_ID_CHARS, MAX_DOMAIN_CHARS, MAX_DOMAIN_LABEL_CHARS, MIN_APP_ID_CHARS,
};

/// Which field of an event a rule's pattern is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    AppId,
    Domain,
}

/// Every variant, so tests can sweep the set.
pub const ALL_KINDS: &[RuleKind] = &[RuleKind::AppId, RuleKind::Domain];

impl RuleKind {
    /// Parses the wire value. Case-insensitive and whitespace-trimmed,
    /// the same leniency [`crate::devices::platform::Platform::parse`]
    /// gives a closed set sent by a client.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "app_id" => Some(Self::AppId),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }

    /// The stored and returned spelling. Must match the CHECK
    /// constraint in migration `0005` exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppId => "app_id",
            Self::Domain => "domain",
        }
    }
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a pattern was rejected. Safe to show a client: every message
/// states a public rule and none echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// Present but empty or only whitespace. Only reachable for
    /// [`RuleKind::AppId`] - a domain pattern's emptiness is reported
    /// as [`Self::Malformed`] instead, the same split
    /// `events::validate` makes between `AppIdBlank` and
    /// `DomainMalformed`.
    Blank,
    /// Longer than the kind allows.
    Length,
    /// A domain pattern not shaped like a bare hostname - a scheme, a
    /// path, a port or a query would each land here. Only reachable
    /// for [`RuleKind::Domain`].
    Malformed,
    /// A control character or a text-direction override.
    Charset,
}

/// Normalizes and validates `raw` as a pattern for `kind`.
///
/// An `app_id` pattern is returned unchanged - it is an identifier,
/// never folded or trimmed, same as `events.app_id`. A `domain`
/// pattern is lowercased and has one trailing dot stripped, so that a
/// stored pattern and an event's already-normalized `domain` compare
/// equal with a plain `==`/`ends_with` rather than needing the
/// comparison itself to re-normalize anything.
pub fn normalize_pattern(kind: RuleKind, raw: &str) -> Result<String, PatternError> {
    match kind {
        RuleKind::AppId => normalize_app_id_pattern(raw),
        RuleKind::Domain => normalize_domain_pattern(raw),
    }
}

fn normalize_app_id_pattern(raw: &str) -> Result<String, PatternError> {
    if raw.chars().any(is_forbidden) {
        return Err(PatternError::Charset);
    }
    let length = raw.chars().count();
    if !(MIN_APP_ID_CHARS..=MAX_APP_ID_CHARS).contains(&length) {
        return Err(PatternError::Length);
    }
    // Checked after the length, so a single space is reported as the
    // blank it is rather than passing the length rule silently. Not
    // trimmed: the value stored is exactly what an `app_id` of the
    // same text would be.
    if raw.trim().is_empty() {
        return Err(PatternError::Blank);
    }
    Ok(raw.to_owned())
}

/// A bare hostname, and nothing resembling a URL - the same charset
/// rule `events::validate::check_domain` applies, repeated here rather
/// than shared across the module boundary (see this file's header).
fn normalize_domain_pattern(raw: &str) -> Result<String, PatternError> {
    if raw.chars().any(is_forbidden) {
        return Err(PatternError::Charset);
    }
    if raw.chars().count() > MAX_DOMAIN_CHARS {
        return Err(PatternError::Length);
    }

    let lowered = raw.to_ascii_lowercase();
    // A single trailing dot is a legal, fully qualified spelling; drop
    // it so "example.com." and "example.com" are one pattern.
    let host = lowered.strip_suffix('.').unwrap_or(&lowered);

    if host.is_empty() {
        return Err(PatternError::Malformed);
    }

    for label in host.split('.') {
        let length = label.len();
        if length == 0 || length > MAX_DOMAIN_LABEL_CHARS {
            return Err(PatternError::Malformed);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(PatternError::Malformed);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(PatternError::Malformed);
        }
    }

    Ok(host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips_through_its_wire_value() {
        for kind in ALL_KINDS {
            assert_eq!(RuleKind::parse(kind.as_str()), Some(*kind));
        }
    }

    #[test]
    fn kind_parsing_folds_case_and_whitespace() {
        for spelling in ["app_id", "App_Id", "APP_ID", "  app_id  ", "\tApp_Id\n"] {
            assert_eq!(RuleKind::parse(spelling), Some(RuleKind::AppId));
        }
        for spelling in ["domain", "Domain", "DOMAIN", "  domain  "] {
            assert_eq!(RuleKind::parse(spelling), Some(RuleKind::Domain));
        }
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        for unknown in ["", "label", "appid", "app-id", "dns"] {
            assert_eq!(RuleKind::parse(unknown), None, "{unknown:?} must not parse");
        }
    }

    #[test]
    fn an_app_id_pattern_is_accepted_unchanged() {
        let pattern = normalize_pattern(RuleKind::AppId, "org.Example.Browser")
            .expect("a well-formed app_id pattern must be accepted");
        assert_eq!(pattern, "org.Example.Browser", "case must be preserved");
    }

    #[test]
    fn an_app_id_pattern_is_not_trimmed() {
        // Unlike a domain, an app_id pattern is an identifier: leading
        // or trailing whitespace is part of the string, same as
        // `events::validate::check_app_id`.
        let pattern = normalize_pattern(RuleKind::AppId, " org.example.browser ")
            .expect("whitespace inside the bounds must still be accepted");
        assert_eq!(pattern, " org.example.browser ");
    }

    #[test]
    fn an_app_id_pattern_rejects_blank_and_oversized_input() {
        assert_eq!(
            normalize_pattern(RuleKind::AppId, "   "),
            Err(PatternError::Blank)
        );
        assert_eq!(
            normalize_pattern(RuleKind::AppId, ""),
            Err(PatternError::Length)
        );
        let too_long = "x".repeat(MAX_APP_ID_CHARS + 1);
        assert_eq!(
            normalize_pattern(RuleKind::AppId, &too_long),
            Err(PatternError::Length)
        );
        let longest = "x".repeat(MAX_APP_ID_CHARS);
        assert!(normalize_pattern(RuleKind::AppId, &longest).is_ok());
    }

    #[test]
    fn an_app_id_pattern_rejects_forbidden_characters() {
        assert_eq!(
            normalize_pattern(RuleKind::AppId, "org.example\nbrowser"),
            Err(PatternError::Charset)
        );
    }

    #[test]
    fn a_domain_pattern_is_lowercased() {
        assert_eq!(
            normalize_pattern(RuleKind::Domain, "GOOGLE.com").unwrap(),
            "google.com"
        );
    }

    #[test]
    fn a_domain_pattern_drops_one_trailing_dot() {
        assert_eq!(
            normalize_pattern(RuleKind::Domain, "example.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn a_domain_pattern_rejects_url_shapes() {
        for malformed in [
            "https://example.com",
            "example.com/path",
            "example.com:8080",
            "example.com?x=1",
            "user@example.com",
            "",
            ".",
            "example..com",
            "-example.com",
            "example-.com",
        ] {
            assert_eq!(
                normalize_pattern(RuleKind::Domain, malformed),
                Err(PatternError::Malformed),
                "{malformed:?} must be refused as malformed"
            );
        }
    }

    #[test]
    fn a_domain_pattern_rejects_oversized_input() {
        let too_long = format!("{}.com", "x".repeat(MAX_DOMAIN_CHARS));
        assert_eq!(
            normalize_pattern(RuleKind::Domain, &too_long),
            Err(PatternError::Length)
        );

        let label_too_long = format!("{}.com", "x".repeat(MAX_DOMAIN_LABEL_CHARS + 1));
        assert_eq!(
            normalize_pattern(RuleKind::Domain, &label_too_long),
            Err(PatternError::Malformed),
            "a too-long label is a shape problem, not a length-cap problem"
        );
    }

    #[test]
    fn a_domain_pattern_rejects_forbidden_characters() {
        assert_eq!(
            normalize_pattern(RuleKind::Domain, "example\n.com"),
            Err(PatternError::Charset)
        );
    }
}
