//! The category label policy.
//!
//! A category - "Social", "Study" - is a *display* string a person
//! chose, not an identifier: modeled directly on
//! [`crate::devices::name::DeviceName`], down to the bound values and
//! the order the two checks run in. See that module for the reasoning
//! this one does not repeat: trimming, the control/bidi charset rule,
//! and why the charset check has to run before the trim rather than
//! after it.

use std::fmt;

use crate::devices::name::is_forbidden;

/// Shortest accepted label, in characters, after trimming.
pub const MIN_CHARS: usize = 1;

/// Longest accepted label, in characters, after trimming.
pub const MAX_CHARS: usize = 64;

/// Why a category label was rejected. Safe to show a client: every
/// message states a public rule and none echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CategoryLabelError {
    #[error("the category must be between {MIN_CHARS} and {MAX_CHARS} characters long")]
    Length,

    #[error("the category may not contain control or text-direction characters")]
    Charset,
}

/// A validated, trimmed category label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryLabel(String);

impl CategoryLabel {
    pub fn parse(raw: &str) -> Result<Self, CategoryLabelError> {
        // The untrimmed input, for the same reason
        // `DeviceName::parse` checks it first: `str::trim` removes
        // several control characters, and checking the trimmed string
        // would quietly let "Study\n" through as "Study".
        if raw.chars().any(is_forbidden) {
            return Err(CategoryLabelError::Charset);
        }

        let trimmed = raw.trim();
        let length = trimmed.chars().count();
        if !(MIN_CHARS..=MAX_CHARS).contains(&length) {
            return Err(CategoryLabelError::Length);
        }

        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CategoryLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_label_is_accepted_as_written() {
        for raw in ["Social", "Study Time", "Arbeits-Apps", "\u{1f4f1} Apps"] {
            let parsed = CategoryLabel::parse(raw).unwrap_or_else(|err| panic!("{raw:?}: {err}"));
            assert_eq!(parsed.as_str(), raw);
        }
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            CategoryLabel::parse("  Social  ").unwrap().as_str(),
            "Social"
        );
    }

    #[test]
    fn a_control_character_trimming_would_remove_is_still_refused() {
        for raw in ["Social\n", "\nSocial", "Social\t"] {
            assert_eq!(
                CategoryLabel::parse(raw).unwrap_err(),
                CategoryLabelError::Charset,
                "{raw:?} must be refused, not trimmed away"
            );
        }
    }

    #[test]
    fn the_length_bounds_bite_exactly_where_they_are_written() {
        let shortest = "x".repeat(MIN_CHARS);
        let longest = "x".repeat(MAX_CHARS);
        let too_long = "x".repeat(MAX_CHARS + 1);

        assert!(CategoryLabel::parse(&shortest).is_ok());
        assert!(CategoryLabel::parse(&longest).is_ok());
        assert_eq!(
            CategoryLabel::parse("").unwrap_err(),
            CategoryLabelError::Length
        );
        assert_eq!(
            CategoryLabel::parse(&too_long).unwrap_err(),
            CategoryLabelError::Length
        );
        assert_eq!(
            CategoryLabel::parse("     ").unwrap_err(),
            CategoryLabelError::Length,
            "whitespace only is blank, not a label"
        );
    }

    #[test]
    fn bidirectional_overrides_are_refused() {
        let raw = format!("Social{}Study", '\u{202e}');
        assert_eq!(
            CategoryLabel::parse(&raw).unwrap_err(),
            CategoryLabelError::Charset
        );
    }
}
