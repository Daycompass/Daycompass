//! Account roles.
//!
//! There are exactly two, matching the CHECK constraint in migration
//! 0002. Anything finer-grained is out of scope: an admin manages
//! accounts and devices and can never read another user's usage data,
//! which is a privacy rule enforced per endpoint rather than by adding
//! more roles.

use std::fmt;

/// What an account is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Manages accounts and devices. Cannot read another user's usage
    /// events or stats. Retention is not an admin setting: it is
    /// env-only, like every other operational limit.
    Admin,
    /// An ordinary account: its own devices, its own data.
    User,
}

impl Role {
    /// The value stored in the `users.role` column.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    /// Parses a value read back from the database. Returns `None` for
    /// anything else, so an unexpected row is reported as corrupt
    /// rather than silently treated as one of the known roles.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }

    pub const fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_stored_form() {
        for role in [Role::Admin, Role::User] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
    }

    #[test]
    fn only_admin_is_admin() {
        assert!(Role::Admin.is_admin());
        assert!(!Role::User.is_admin());
    }

    /// Case matters: the column stores exactly these two lowercase
    /// values, and anything else means the row is wrong.
    #[test]
    fn unknown_values_do_not_parse() {
        for raw in ["", "ADMIN", "Admin", "root", "superuser", "users", " admin"] {
            assert_eq!(Role::parse(raw), None, "{raw:?} must not parse");
        }
    }
}
