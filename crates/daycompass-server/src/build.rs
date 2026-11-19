//! What this binary is: its version, and the commit it was built from.
//!
//! Known at compile time only. The server never asks anyone whether a
//! newer version exists - it makes no outgoing requests at all - so the
//! dashboard shows this to admins and links to the releases instead.

/// The crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit this binary was built from, if the build was given one:
/// `DAYCOMPASS_BUILD_COMMIT` at compile time (the Dockerfile passes it
/// through from `--build-arg`). Ignored unless it looks like a commit.
pub fn commit() -> Option<&'static str> {
    option_env!("DAYCOMPASS_BUILD_COMMIT").filter(|commit| plausible(commit))
}

/// `0.0.0, commit 1a2b3c4`, or just the version without a commit.
pub fn label() -> String {
    match commit() {
        Some(commit) => format!("{VERSION}, commit {commit}"),
        None => VERSION.to_owned(),
    }
}

/// 7 to 40 lowercase hex characters: a short or full commit id.
fn plausible(commit: &str) -> bool {
    (7..=40).contains(&commit.len())
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_commit_id_counts_as_one() {
        assert!(plausible("1a2b3c4"));
        assert!(plausible(&"f".repeat(40)));
        assert!(!plausible("1a2b3c"), "too short");
        assert!(!plausible(&"f".repeat(41)), "too long");
        assert!(!plausible("1A2B3C4"), "upper case");
        assert!(!plausible("<b>main</b>"));
        assert!(!plausible(""));
    }
}
