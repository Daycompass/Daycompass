//! A string that must never reach a log, an error message, or a panic.
//!
//! [`SecretString`] wraps one and takes three precautions:
//!
//! * [`std::fmt::Debug`] prints a placeholder, so `{:?}` on a struct
//!   containing one is safe. There is deliberately no `Display` and no
//!   `Serialize` impl, so the value cannot be formatted or serialized
//!   back out by accident.
//! * The buffer is zeroized on drop.
//! * Reading the value requires calling [`SecretString::expose`], which
//!   is easy to grep for in review.
//!
//! Zeroizing is a mitigation, not a guarantee. A `String` that grew by
//! reallocation leaves its old buffer behind untouched, and the HTTP
//! body this value was parsed from, plus any intermediate buffer serde
//! allocated while parsing, are outside this type's control. The point
//! is to shrink the window, not to promise the plaintext is gone.

use std::fmt;

use serde::de::{Deserialize, Deserializer, Visitor};
use zeroize::Zeroize;

/// Printed in place of the value.
const REDACTED: &str = "[redacted]";

/// Owns a sensitive string. See the module documentation.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Hands out the plaintext. Every call site is a place where the
    /// value could escape, so keep them few and short-lived.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Number of Unicode characters, for length policies that should not
    /// have to expose the value to count it.
    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }

    /// True if the value is empty or only whitespace.
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({REDACTED})")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            // Takes the already-owned buffer rather than copying it, so
            // there is one fewer plaintext allocation in flight.
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(SecretString::new(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretString::new(value.to_owned()))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built at runtime, so no secret-looking literal exists in the
    /// test source either.
    fn sample() -> String {
        std::iter::repeat_n('x', 20).collect()
    }

    #[test]
    fn debug_output_does_not_contain_the_value() {
        let value = sample();
        let secret = SecretString::new(value.clone());
        let debug = format!("{secret:?}");
        assert!(!debug.contains(&value), "Debug must not leak the value");
        assert_eq!(debug, format!("SecretString({REDACTED})"));
    }

    #[test]
    fn debug_output_is_redacted_when_nested_in_another_struct() {
        #[derive(Debug)]
        struct Wrapper {
            password: SecretString,
        }

        let value = sample();
        let wrapper = Wrapper {
            password: SecretString::new(value.clone()),
        };
        assert!(!format!("{wrapper:?}").contains(&value));
        // Also reads the field, so it is not merely Debug-formatted:
        // dead-code analysis ignores derived Debug impls.
        assert_eq!(wrapper.password.expose(), value);
    }

    #[test]
    fn expose_returns_the_value() {
        let value = sample();
        assert_eq!(SecretString::new(value.clone()).expose(), value);
    }

    #[test]
    fn char_count_counts_characters_not_bytes() {
        // Four characters, more than four bytes.
        let secret = SecretString::new("a\u{00e4}\u{20ac}\u{1f600}".to_owned());
        assert_eq!(secret.char_count(), 4);
    }

    #[test]
    fn is_blank_detects_empty_and_whitespace_only() {
        assert!(SecretString::new(String::new()).is_blank());
        assert!(SecretString::new(" \t\n ".to_owned()).is_blank());
        assert!(!SecretString::new(sample()).is_blank());
    }

    #[test]
    fn deserializes_from_a_json_string() {
        let value = sample();
        let json = serde_json::to_string(&value).expect("encoding must succeed");
        let secret: SecretString = serde_json::from_str(&json).expect("decoding must succeed");
        assert_eq!(secret.expose(), value);
    }

    #[test]
    fn deserializing_a_non_string_fails() {
        assert!(serde_json::from_str::<SecretString>("42").is_err());
        assert!(serde_json::from_str::<SecretString>("null").is_err());
    }
}
