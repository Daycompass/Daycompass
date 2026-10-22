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

use std::ffi::OsStr;
use std::process::{Command, Stdio};

/// Runs the real binary with `vars` added to its environment, and
/// returns its exit code and stderr. The process's own environment is
/// inherited too - `PATH` is needed to resolve shared libraries - but
/// nothing in `vars` is ever a real credential, per `CLAUDE.md`.
fn run_with_vars(vars: &[(&str, &str)]) -> (i32, String) {
    let pairs: Vec<(&OsStr, &OsStr)> = vars
        .iter()
        .map(|(key, value)| (OsStr::new(*key), OsStr::new(*value)))
        .collect();
    run_with_env(&pairs)
}

/// The `OsStr`-based core of [`run_with_vars`], used directly by the
/// non-UTF-8 tests below: a `&str` cannot hold invalid Unicode in the
/// first place, so exercising it needs a type that can.
fn run_with_env(vars: &[(&OsStr, &OsStr)]) -> (i32, String) {
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

/// `find_legacy_var` is `Iterator::find`, which stops at the first
/// match: if the legacy variable were enumerated before the
/// non-UTF-8 one, the old, buggy `std::env::vars()` would never reach
/// the bad entry and this test would pass for the wrong reason. `env`
/// on a `Command` tracks its explicit overrides in a `BTreeMap`, keyed
/// by the raw bytes, and emits them in that order - so every unrelated
/// name here is chosen to sort before `SCREENWARD_` (`'A' < 'S'`),
/// which guarantees the corrupt entry is reached first. Verified
/// empirically against this exact binary before relying on it.
const SORTS_BEFORE_LEGACY_PREFIX: &str = "AAAA_UNRELATED_VARIABLE";

/// `check_for_legacy_env` walks every variable in the process
/// environment, not just the ones it recognizes - so a variable
/// elsewhere whose *value* is not valid UTF-8 must not turn the check
/// itself into a panic (exit code 101). Combined with a real legacy
/// variable in the same run, so this also proves the check still does
/// its job rather than merely failing to crash.
#[cfg(unix)]
#[test]
fn an_invalid_value_on_an_unrelated_variable_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;

    let invalid_value = OsStr::from_bytes(&[0xFF, 0xFE]);
    let (code, stderr) = run_with_env(&[
        (OsStr::new(SORTS_BEFORE_LEGACY_PREFIX), invalid_value),
        (
            OsStr::new("SCREENWARD_BIND_ADDR"),
            OsStr::new("127.0.0.1:0"),
        ),
    ]);

    assert_ne!(code, 101, "must not panic: stderr: {stderr}");
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("SCREENWARD_BIND_ADDR"),
        "the legacy message must still appear: {stderr}"
    );
}

/// Same, for a variable *name* that is not valid UTF-8 rather than its
/// value. The invalid bytes are appended after an ASCII prefix that
/// still sorts before `SCREENWARD_`, for the same ordering reason as
/// [`SORTS_BEFORE_LEGACY_PREFIX`] above - a name starting with the raw
/// byte `0xFF` would sort *after* it instead, defeating the test.
#[cfg(unix)]
#[test]
fn an_invalid_name_on_an_unrelated_variable_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;

    let mut invalid_name_bytes = SORTS_BEFORE_LEGACY_PREFIX.as_bytes().to_vec();
    invalid_name_bytes.extend_from_slice(&[0xFF, 0xFE]);
    let invalid_name = OsStr::from_bytes(&invalid_name_bytes);

    let (code, stderr) = run_with_env(&[
        (invalid_name, OsStr::new("value")),
        (
            OsStr::new("SCREENWARD_BIND_ADDR"),
            OsStr::new("127.0.0.1:0"),
        ),
    ]);

    assert_ne!(code, 101, "must not panic: stderr: {stderr}");
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("SCREENWARD_BIND_ADDR"),
        "the legacy message must still appear: {stderr}"
    );
}
