//! Screenward backend entry point.
//!
//! This is a foundation-only skeleton: it starts, prints a status line,
//! and exits cleanly. No HTTP server, database, or authentication exists
//! yet - those arrive in later milestones.
#![forbid(unsafe_code)]

fn main() {
    run();
}

/// Starts up and shuts down cleanly. Returns the message it printed so
/// tests can assert on startup behavior without parsing stdout.
fn run() -> &'static str {
    let message = "screenward-server: starting (skeleton build, no services yet)";
    println!("{message}");
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_reports_a_startup_message() {
        assert_eq!(
            run(),
            "screenward-server: starting (skeleton build, no services yet)"
        );
    }
}
