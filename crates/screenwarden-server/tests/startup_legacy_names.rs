//! Verifies the legacy-name startup guard from the Screenward ->
//! Screenwarden rename: a stray `SCREENWARD_*` variable must refuse to
//! start, naming the variable, rather than silently falling back to a
//! default (loopback bind, no trusted proxies, the compiled-in rate
//! limits).
//!
//! Spawns the real binary rather than calling a function directly,
//! because what is under test is `main`'s ordering: the check must run
//! before `Config::from_env`, and only a real process boundary proves
//! that nothing upstream of it (argument parsing, logging setup) runs
//! first either.

use std::process::{Command, Stdio};

/// Runs the real binary with `vars` added to its environment, and
/// returns its exit code and stderr. The process's own environment is
/// inherited too - `PATH` is needed to resolve shared libraries - but
/// nothing in `vars` is ever a real credential, per `CLAUDE.md`.
fn run_with_vars(vars: &[(&str, &str)]) -> (i32, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_screenwarden-server"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in vars {
        command.env(key, value);
    }

    let output = command.output().expect("spawning the binary must succeed");
    let code = output
        .status
        .code()
        .expect("the process must exit, not be killed by a signal");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stderr)
}

#[test]
fn a_legacy_prefixed_variable_refuses_to_start_and_names_it() {
    let (code, stderr) = run_with_vars(&[("SCREENWARD_BIND_ADDR", "127.0.0.1:0")]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("SCREENWARD_BIND_ADDR"),
        "stderr must name the offending variable: {stderr}"
    );
    assert!(
        stderr.contains("SCREENWARDEN_BIND_ADDR"),
        "stderr must say what to rename it to: {stderr}"
    );
}

/// Control: an ordinary invalid configuration also exits 1, but its
/// message never mentions a `SCREENWARD_*` name. This is what proves the
/// message above is specific to the legacy-name check, rather than a
/// coincidence of every configuration failure mentioning the prefix.
#[test]
fn an_ordinary_invalid_configuration_fails_for_a_different_reason() {
    let (code, stderr) = run_with_vars(&[("SCREENWARDEN_BIND_ADDR", "not-an-address")]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        !stderr.contains("SCREENWARD_"),
        "an ordinary config error must not mention the legacy prefix: {stderr}"
    );
}
