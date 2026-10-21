//! The device name policy.
//!
//! A device name is a *display* string, not an identifier: a person
//! writes "Mika's Laptop" and later has to recognise it in a list. So
//! unlike [`crate::auth::username::Username`], there is no charset
//! restriction and no case folding - any script, any punctuation,
//! emoji. Three things are still refused.
//!
//! * **Blank, once trimmed.** A nameless row in a device list is
//!   unusable, and surrounding whitespace is not something anybody
//!   means to type.
//! * **Control characters.** A newline or a carriage return in a name
//!   would let a device inject a line into anything that renders names
//!   as text, and a `NUL` truncates in a surprising number of places.
//! * **Bidirectional overrides and isolates** (U+202A..=U+202E,
//!   U+2066..=U+2069). These reorder the characters *around* them when
//!   rendered, so a device could display in the dashboard as something
//!   other than what the owner approved - the same trick that makes a
//!   file called `exe.txt` look like a text file. They are refused
//!   rather than stripped, because silently altering a name the owner
//!   chose is its own surprise.
//!
//! The name **is** trimmed, deliberately unlike `app_id` in
//! [`crate::events::validate`], which is an identifier and is never
//! modified. A display string gets normalized; an identifier the
//! server quietly rewrites is a bug waiting to happen.
//!
//! Length is counted in characters, not bytes, so a name of accented
//! or non-Latin characters is not penalised for its encoding.

use std::fmt;

/// Shortest accepted name, in characters, after trimming.
pub const MIN_CHARS: usize = 1;

/// Longest accepted name, in characters, after trimming.
pub const MAX_CHARS: usize = 64;

/// Why a device name was rejected. Safe to show a client: every message
/// states a public rule and none echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceNameError {
    #[error("the device name must be between {MIN_CHARS} and {MAX_CHARS} characters long")]
    Length,

    #[error("the device name may not contain control or text-direction characters")]
    Charset,
}

/// A validated, trimmed device name.
///
/// Constructible only through [`DeviceName::parse`], so a value of this
/// type has always been through the policy - there is no way to reach
/// an insert with an unchecked string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName(String);

impl DeviceName {
    pub fn parse(raw: &str) -> Result<Self, DeviceNameError> {
        // The charset check runs on the *untrimmed* input, and must.
        // `str::trim` removes Unicode whitespace, which includes
        // several control characters - a trailing newline, tab or NEL
        // among them. Trimming first would therefore quietly strip
        // exactly the characters this rule exists to refuse, and
        // "Laptop\n" would be accepted as "Laptop". Checking the raw
        // input makes the rule mean what it says: no control
        // character anywhere, not even one that trimming would have
        // hidden.
        if raw.chars().any(is_forbidden) {
            return Err(DeviceNameError::Charset);
        }

        // What is left to trim is ordinary whitespace - spaces, and
        // the non-breaking kind - which is safe to drop.
        let trimmed = raw.trim();

        let length = trimmed.chars().count();
        if !(MIN_CHARS..=MAX_CHARS).contains(&length) {
            return Err(DeviceNameError::Length);
        }

        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Characters a display name may never contain.
///
/// Shared with the event validator, which applies the same rule to
/// every string an event carries. Written as one function so the two
/// cannot drift apart.
pub fn is_forbidden(c: char) -> bool {
    // `is_control` covers C0, DEL and C1 - every newline, tab and NUL.
    c.is_control()
        // LRE, RLE, PDF, LRO, RLO: legacy bidirectional overrides.
        || ('\u{202a}'..='\u{202e}').contains(&c)
        // LRI, RLI, FSI, PDI: the isolate family that replaced them.
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_name_is_accepted_as_written() {
        for raw in ["Laptop", "Mika's Laptop", "Arbeits-PC", "\u{1f4bb} work"] {
            let parsed = DeviceName::parse(raw).unwrap_or_else(|err| panic!("{raw:?}: {err}"));
            assert_eq!(parsed.as_str(), raw);
        }
    }

    /// Non-Latin scripts must work. A screen time tool for students is
    /// not an ASCII-only product.
    #[test]
    fn names_outside_ascii_are_accepted() {
        for raw in ["Wohnzimmer-PC", "\u{043d}\u{043e}\u{0443}\u{0442}", "\u{30ce}\u{30fc}\u{30c8}"]
        {
            assert!(DeviceName::parse(raw).is_ok(), "{raw:?} must be accepted");
        }
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(DeviceName::parse("  Laptop  ").unwrap().as_str(), "Laptop");
        // A non-breaking space is whitespace but not a control
        // character, so it is trimmed rather than refused.
        assert_eq!(
            DeviceName::parse("\u{a0}Laptop\u{a0}").unwrap().as_str(),
            "Laptop"
        );
    }

    /// Trimming must not become a way to smuggle a control character
    /// past the charset rule. `str::trim` removes several of them, so
    /// a tab or a newline at either end has to be refused by a check
    /// that runs *before* the trim - otherwise "Laptop\n" would be
    /// accepted as "Laptop" and the rule would be a half-truth.
    #[test]
    fn a_control_character_trimming_would_remove_is_still_refused() {
        for (label, raw) in [
            ("trailing newline", "Laptop\n"),
            ("leading newline", "\nLaptop"),
            ("trailing tab", "Laptop\t"),
            ("leading tab", "\tLaptop"),
            ("trailing carriage return", "Laptop\r"),
            ("trailing NEL", "Laptop\u{85}"),
            ("a form feed either side", "\u{c}Laptop\u{c}"),
        ] {
            assert_eq!(
                DeviceName::parse(raw).unwrap_err(),
                DeviceNameError::Charset,
                "{label} must be refused, not trimmed away"
            );
        }
    }

    /// Each bound, and one step past it. Length is counted after
    /// trimming, so the whitespace-padded cases check that too.
    #[test]
    fn the_length_bounds_bite_exactly_where_they_are_written() {
        let shortest = "x".repeat(MIN_CHARS);
        let longest = "x".repeat(MAX_CHARS);
        let too_long = "x".repeat(MAX_CHARS + 1);

        assert!(DeviceName::parse(&shortest).is_ok(), "the minimum is valid");
        assert!(DeviceName::parse(&longest).is_ok(), "the maximum is valid");

        assert_eq!(DeviceName::parse("").unwrap_err(), DeviceNameError::Length);
        assert_eq!(
            DeviceName::parse(&too_long).unwrap_err(),
            DeviceNameError::Length,
            "one character past the maximum must be refused"
        );

        // Trimming happens first, so these are the same two cases.
        assert_eq!(
            DeviceName::parse("     ").unwrap_err(),
            DeviceNameError::Length,
            "whitespace only is blank, not a name"
        );
        assert!(
            DeviceName::parse(&format!("  {longest}  ")).is_ok(),
            "padding must not count towards the maximum"
        );
    }

    /// Counted in characters, not bytes: a 64-character name of
    /// multi-byte characters is well over 64 bytes and must still pass.
    #[test]
    fn length_is_measured_in_characters() {
        let accented = "\u{e4}".repeat(MAX_CHARS);
        assert!(accented.len() > MAX_CHARS, "the test input must be wider");
        assert!(DeviceName::parse(&accented).is_ok());

        let one_too_many = "\u{e4}".repeat(MAX_CHARS + 1);
        assert_eq!(
            DeviceName::parse(&one_too_many).unwrap_err(),
            DeviceNameError::Length
        );
    }

    #[test]
    fn control_characters_are_refused() {
        for (label, raw) in [
            ("newline", "Laptop\nAdmin"),
            ("carriage return", "Laptop\rAdmin"),
            ("NUL", "Laptop\u{0}"),
            ("escape", "Laptop\u{1b}[31m"),
            ("DEL", "Laptop\u{7f}"),
            ("a C1 control", "Laptop\u{85}"),
        ] {
            assert_eq!(
                DeviceName::parse(raw).unwrap_err(),
                DeviceNameError::Charset,
                "{label} must be refused"
            );
        }
    }

    /// The reason this rule exists: without it a device can render in
    /// the dashboard as something other than what was approved.
    #[test]
    fn bidirectional_overrides_are_refused() {
        for marker in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ] {
            let raw = format!("Laptop{marker}revoked");
            assert_eq!(
                DeviceName::parse(&raw).unwrap_err(),
                DeviceNameError::Charset,
                "U+{:04X} must be refused",
                u32::from(marker)
            );
        }
    }

    /// The boundary of the two refused ranges: the characters either
    /// side of them are ordinary formatting marks and must be allowed,
    /// or the rule is quietly wider than it is documented to be.
    #[test]
    fn the_characters_bordering_the_refused_ranges_are_allowed() {
        for allowed in ['\u{2029}', '\u{202f}', '\u{2065}', '\u{206a}'] {
            // U+2029 is a paragraph separator, which `is_control` does
            // not cover; the others border the two bidi ranges.
            let raw = format!("Laptop{allowed}");
            assert!(
                DeviceName::parse(&raw).is_ok(),
                "U+{:04X} is outside the rule and must be allowed",
                u32::from(allowed)
            );
        }
    }

    /// Charset is checked before length, so an input that is both too
    /// long and full of control characters reports the charset. The
    /// order is what makes the message useful rather than misleading.
    #[test]
    fn the_charset_rule_is_reported_before_the_length_rule() {
        let raw = format!("{}\n", "x".repeat(MAX_CHARS + 10));
        assert_eq!(
            DeviceName::parse(&raw).unwrap_err(),
            DeviceNameError::Charset
        );
    }
}
