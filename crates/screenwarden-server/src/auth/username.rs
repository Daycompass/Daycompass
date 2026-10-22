//! Username normalization and policy.
//!
//! A username is 3 to 32 characters from `[a-z0-9_.-]`, normalized to
//! lowercase. [`Username`] can only be built by going through
//! [`Username::parse`], so a value of this type is always already
//! normalized - there is no way to reach a lookup or an insert with a
//! raw, unnormalized string.

use std::fmt;

/// Shortest accepted username, in characters.
pub const MIN_CHARS: usize = 3;

/// Longest accepted username, in characters.
pub const MAX_CHARS: usize = 32;

/// Why a username was rejected. Safe to show a client: the rules are
/// public, and the message never echoes the input back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    #[error("the username must be between {MIN_CHARS} and {MAX_CHARS} characters long")]
    Length,

    #[error("the username may only contain a-z, 0-9, and the characters _ . -")]
    Charset,
}

/// A validated, lowercase username.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Username(String);

impl Username {
    /// Normalizes and validates `raw`.
    ///
    /// Surrounding whitespace is trimmed first, because a login form
    /// will happily submit it and no accepted character is whitespace,
    /// so trimming cannot merge two distinct usernames into one.
    ///
    /// Lowercasing is deliberately **ASCII-only**. Full Unicode
    /// lowercasing maps several non-ASCII characters onto ASCII ones -
    /// U+212A KELVIN SIGN becomes `k`, and Turkish dotted capital I
    /// becomes `i` - which would let visually distinct input normalize
    /// onto an existing account. With ASCII-only folding, anything
    /// outside ASCII stays outside and is rejected by the charset check
    /// below.
    pub fn parse(raw: &str) -> Result<Self, UsernameError> {
        let normalized = raw.trim().to_ascii_lowercase();

        let length = normalized.chars().count();
        if !(MIN_CHARS..=MAX_CHARS).contains(&length) {
            return Err(UsernameError::Length);
        }

        if !normalized
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
        {
            return Err(UsernameError::Charset);
        }

        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_simple_username() {
        assert_eq!(Username::parse("alice").unwrap().as_str(), "alice");
    }

    #[test]
    fn normalizes_to_lowercase() {
        for raw in ["ALICE", "Alice", "aLiCe"] {
            assert_eq!(
                Username::parse(raw).unwrap().as_str(),
                "alice",
                "{raw} must normalize to the same value"
            );
        }
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(Username::parse("  bob\t\n").unwrap().as_str(), "bob");
    }

    #[test]
    fn accepts_every_allowed_character() {
        let all = "abcdefghijklmnopqrstuvwxyz0123456789_.-";
        // 39 characters, so check it in two pieces that each fit the
        // length limit.
        let (first, second) = all.split_at(MAX_CHARS);
        assert_eq!(Username::parse(first).unwrap().as_str(), first);
        let padded = format!("ab{second}");
        assert_eq!(Username::parse(&padded).unwrap().as_str(), padded);
    }

    #[test]
    fn enforces_the_length_bounds() {
        let too_short: String = std::iter::repeat_n('a', MIN_CHARS - 1).collect();
        let shortest: String = std::iter::repeat_n('a', MIN_CHARS).collect();
        let longest: String = std::iter::repeat_n('a', MAX_CHARS).collect();
        let too_long: String = std::iter::repeat_n('a', MAX_CHARS + 1).collect();

        assert_eq!(Username::parse(&too_short), Err(UsernameError::Length));
        assert!(Username::parse(&shortest).is_ok());
        assert!(Username::parse(&longest).is_ok());
        assert_eq!(Username::parse(&too_long), Err(UsernameError::Length));
        assert_eq!(Username::parse(""), Err(UsernameError::Length));
        assert_eq!(Username::parse("   "), Err(UsernameError::Length));
    }

    #[test]
    fn rejects_characters_outside_the_charset() {
        for raw in [
            "alice bob",  // inner space
            "alice@host", // at sign
            "alice/bob",  // slash
            "alice:bob",  // colon
            "alice+bob",  // plus
            "alice\0bob", // NUL
            "alice\nbob", // inner newline
            "ali<ce",     // angle bracket
            "ali%27ce",   // percent
        ] {
            assert_eq!(
                Username::parse(raw),
                Err(UsernameError::Charset),
                "{raw:?} must be rejected"
            );
        }
    }

    /// ASCII-only folding is what keeps these out. Under full Unicode
    /// lowercasing, each of them would collapse onto a plain ASCII
    /// username and could shadow an existing account.
    #[test]
    fn rejects_non_ascii_that_would_fold_onto_ascii() {
        for raw in [
            "ali\u{212a}e",     // KELVIN SIGN lowercases to 'k'
            "al\u{0130}ce",     // dotted capital I lowercases to 'i'
            "\u{0410}lice",     // Cyrillic A, a homograph of 'A'
            "al\u{0131}ce",     // dotless i
            "alice\u{200b}bob", // zero-width space
            "\u{fb00}ice",      // ligature ff
        ] {
            assert_eq!(
                Username::parse(raw),
                Err(UsernameError::Charset),
                "{raw:?} must be rejected"
            );
        }
    }

    /// Two inputs that differ only in case or surrounding whitespace must
    /// produce byte-identical values, or the UNIQUE constraint on the
    /// column would not actually be case-insensitive.
    #[test]
    fn normalization_is_idempotent_and_collision_free() {
        let once = Username::parse(" ALICE ").unwrap();
        let twice = Username::parse(once.as_str()).unwrap();
        assert_eq!(once, twice);
        assert_eq!(once, Username::parse("alice").unwrap());
    }

    #[test]
    fn display_matches_as_str() {
        let username = Username::parse("alice.bob-1_2").unwrap();
        assert_eq!(username.to_string(), username.as_str());
    }
}
