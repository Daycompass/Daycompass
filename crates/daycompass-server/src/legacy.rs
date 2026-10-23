//! Names this project used to have, before it was Daycompass.
//!
//! Two renames so far: Screenward -> Screenwarden -> Daycompass. Each
//! past name gets one entry here, which is the only place its literal
//! strings are written out. `config::check_for_legacy_env` and
//! `db::check_for_legacy_db_files` both walk [`GENERATIONS`] rather than
//! hardcoding a single old prefix or filename, so the next rename adds
//! one entry instead of touching either check's logic.
//!
//! Both checks share the same shape for the same reason: a stray
//! variable or data file from *any* past generation must refuse to
//! start rather than be silently ignored in favor of a default or an
//! empty database - see `config::check_for_legacy_env` and
//! `db::check_for_legacy_db_files` for what that refusal looks like.

/// One past generation of this project's name.
#[derive(Debug)]
pub struct Generation {
    /// Human-readable name, used only in messages (e.g. "Screenward").
    pub name: &'static str,
    /// Env var prefix this generation used, trailing underscore
    /// included.
    pub env_prefix: &'static str,
    /// Main SQLite filename this generation used.
    pub db_file_name: &'static str,
}

/// Every past generation, oldest first. Order does not matter for
/// correctness - each generation's env prefix and db filename are
/// checked independently - but oldest-first matches the order they
/// actually happened in, which is the order a reader expects.
pub const GENERATIONS: &[Generation] = &[
    Generation {
        name: "Screenward",
        env_prefix: "SCREENWARD_",
        db_file_name: "screenward.sqlite3",
    },
    Generation {
        name: "Screenwarden",
        env_prefix: "SCREENWARDEN_",
        db_file_name: "screenwarden.sqlite3",
    },
];

/// The env var prefix this generation - Daycompass - uses today. Only
/// used to tell an operator what to rename a legacy variable to.
pub const CURRENT_ENV_PREFIX: &str = "DAYCOMPASS_";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry's `env_prefix` must end in `_`, and no entry's prefix
    /// may be a prefix of another entry's or of [`CURRENT_ENV_PREFIX`] -
    /// otherwise the "starts_with" check in `config::find_legacy_var`
    /// could not tell two generations apart (this is the exact
    /// `SCREENWARD_` vs `SCREENWARDEN_` subtlety the rename-detection
    /// logic depends on getting right).
    #[test]
    fn no_generations_env_prefix_is_a_prefix_of_another() {
        let mut prefixes: Vec<&str> = GENERATIONS.iter().map(|g| g.env_prefix).collect();
        prefixes.push(CURRENT_ENV_PREFIX);

        for prefix in &prefixes {
            assert!(prefix.ends_with('_'), "{prefix} must end with '_'");
        }

        for (i, a) in prefixes.iter().enumerate() {
            for (j, b) in prefixes.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a} must not be a prefix of {b}");
                }
            }
        }
    }

    /// Same property as above, for the database filenames: no
    /// generation's filename may equal another's, and none may equal
    /// the current one (checked in `db.rs`, which owns that constant).
    #[test]
    fn no_two_generations_share_a_db_file_name() {
        let mut names: Vec<&str> = GENERATIONS.iter().map(|g| g.db_file_name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "a db_file_name is duplicated");
    }
}
