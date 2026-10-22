//! The closed set of platforms a device may report.
//!
//! Parsed from a string at the edge rather than deserialized directly,
//! for the same reason [`crate::auth::role::Role`] is: an unknown value
//! becomes this server's own error from the closed set, not serde's
//! rejection text quoting what the client sent.
//!
//! The set is mirrored by a CHECK constraint on `devices.platform`, so
//! a value that got past this type would still be refused by the
//! database rather than stored.

use std::fmt;

/// What kind of machine a device runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Android,
    Windows,
    Macos,
    Linux,
    Ios,
}

/// Every variant, so tests can sweep the set and the parser round trip
/// can be checked in both directions.
pub const ALL_PLATFORMS: &[Platform] = &[
    Platform::Android,
    Platform::Windows,
    Platform::Macos,
    Platform::Linux,
    Platform::Ios,
];

impl Platform {
    /// Parses the wire value. Case-insensitive and whitespace-trimmed,
    /// because a client's build script is as likely to send `Linux` as
    /// `linux`, and neither spelling is ambiguous.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "android" => Some(Self::Android),
            "windows" => Some(Self::Windows),
            "macos" => Some(Self::Macos),
            "linux" => Some(Self::Linux),
            "ios" => Some(Self::Ios),
            _ => None,
        }
    }

    /// The stored and returned spelling. Must match the CHECK
    /// constraint in migration 0003 exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Ios => "ios",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_platform_round_trips_through_its_wire_value() {
        for platform in ALL_PLATFORMS {
            assert_eq!(
                Platform::parse(platform.as_str()),
                Some(*platform),
                "{platform} must parse back to itself"
            );
        }
    }

    #[test]
    fn parsing_folds_case_and_whitespace() {
        for spelling in ["linux", "Linux", "LINUX", "  linux  ", "\tLiNuX\n"] {
            assert_eq!(
                Platform::parse(spelling),
                Some(Platform::Linux),
                "{spelling:?} must parse"
            );
        }
    }

    #[test]
    fn an_unknown_platform_is_rejected() {
        for unknown in ["", "freebsd", "web", "android tv", "and roid", "ios2"] {
            assert_eq!(
                Platform::parse(unknown),
                None,
                "{unknown:?} must not be accepted"
            );
        }
    }

    /// The stored spelling is also what the CHECK constraint in
    /// migration 0003 lists. Drift here would mean a platform this type
    /// accepts that the database then refuses, at insert time.
    #[test]
    fn the_wire_values_are_lowercase_ascii() {
        for platform in ALL_PLATFORMS {
            let value = platform.as_str();
            assert!(!value.is_empty());
            assert!(
                value.chars().all(|c| c.is_ascii_lowercase()),
                "{value} must be plain lowercase ASCII"
            );
        }
    }

    #[test]
    fn the_set_has_no_duplicates() {
        for (index, platform) in ALL_PLATFORMS.iter().enumerate() {
            for other in &ALL_PLATFORMS[index + 1..] {
                assert_ne!(platform.as_str(), other.as_str());
            }
        }
        assert_eq!(ALL_PLATFORMS.len(), 5);
    }
}
