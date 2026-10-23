//! Fails if `docs/wire-format.md` and `routes::INVENTORY` disagree
//! about which routes exist.
//!
//! The wire format file is where the Android client is going to be
//! written against, not against the Rust source behind it. CLAUDE.md
//! already asks for the two to be kept in sync per PR; this is what
//! actually enforces that, instead of relying on every future PR
//! remembering to.
//!
//! Every route gets a byte-exact HTML-comment anchor immediately
//! before its heading:
//!
//! ```markdown
//! <!-- route: POST /api/v1/users/{id}/password-reset -->
//! ### `POST /api/v1/users/{id}/password-reset`
//! ```
//!
//! Four checks below, each catching a different way the correspondence
//! could break:
//!
//!   1. Every [`INVENTORY`] entry has a matching anchor - a route added
//!      to the table with no documentation fails here.
//!   2. Every anchor names a real `INVENTORY` entry - catches a typo in
//!      the anchor, and stops a section from outliving the route it
//!      described once that route is removed.
//!   3. No anchor appears twice - two sections that both claim to be
//!      normative for the same route.
//!   4. Every anchor is immediately followed by its heading - an
//!      anchor that drifted away from the section it was meant to mark
//!      is as good as no anchor at all.
//!
//! Plus one test of the parser itself ([`the_scan_can_fail`]), since a
//! structural scan that has never been shown to reject anything proves
//! nothing about the ones that pass.
//!
//! # An honest limit
//!
//! This proves a *section exists* for every route, adjacent to its
//! anchor. It does not, and cannot, prove the section is *correct*: a
//! JSON example with a wrong field name passes every check here just
//! as well as a right one would. That part stays a human review, on
//! every PR that touches the wire format.
//!
//! # What this is not a placeholder for
//!
//! When utoipa/OpenAPI lands (see CLAUDE.md's roadmap), the anchor
//! convention and this test are what it *replaces*, not what it sits
//! alongside - a generated spec does not need a hand-written anchor to
//! prove a route is documented. Until then, this is the cheap version.

use std::path::{Path, PathBuf};

use daycompass_server::routes::INVENTORY;

/// Where `docs/wire-format.md` lives, relative to this crate.
///
/// Deliberately not `canonicalize()`d: if the file has moved, that call
/// fails before this function can return the path the caller actually
/// wants printed in a "could not find it" message.
fn wire_format_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("wire-format.md")
}

/// Reads `docs/wire-format.md`, panicking with the path on failure
/// rather than skipping the test - a missing file is a failure of the
/// thing this test checks, not an environment problem to shrug off.
fn read_wire_format() -> String {
    let path = wire_format_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()))
}

/// Every route anchor in `markdown`: `(1-based line number, method,
/// path)`.
///
/// Only lines matching the convention exactly are returned: `<!--
/// route: ` then the method, a single space, the path, then ` -->`,
/// with nothing else on the line. A line that is close but not exact -
/// wrong keyword, missing a space, wrong case - is silently not an
/// anchor, which is what [`the_scan_can_fail`] exists to prove rather
/// than assume.
fn anchors(markdown: &str) -> Vec<(usize, String, String)> {
    markdown
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let rest = line.trim().strip_prefix("<!-- route: ")?;
            let rest = rest.strip_suffix(" -->")?;
            let (method, path) = rest.split_once(' ')?;
            if method.is_empty() || path.is_empty() {
                return None;
            }
            Some((idx + 1, method.to_owned(), path.to_owned()))
        })
        .collect()
}

/// Every route in [`INVENTORY`] has a documentation anchor.
#[test]
fn every_route_in_the_inventory_is_documented() {
    let markdown = read_wire_format();
    let documented = anchors(&markdown);

    let missing: Vec<_> = INVENTORY
        .iter()
        .filter(|spec| {
            !documented
                .iter()
                .any(|(_, method, path)| method == spec.method && path == spec.path)
        })
        .collect();

    if missing.is_empty() {
        return;
    }

    let path = wire_format_path();
    let first = missing[0];
    let list = missing
        .iter()
        .map(|spec| format!("  - {} {}", spec.method, spec.path))
        .collect::<Vec<_>>()
        .join("\n");

    panic!(
        "{count} route(s) in INVENTORY have no documentation anchor in {doc}:\n{list}\n\n\
         Add an anchor immediately before each route's `###` heading, e.g.:\n\n\
         <!-- route: {method} {route_path} -->\n### `{method} {route_path}`\n",
        count = missing.len(),
        doc = path.display(),
        method = first.method,
        route_path = first.path,
    );
}

/// Every anchor in the document names a route that still exists.
///
/// The other direction from the test above: catches a typo in an
/// anchor, and stops a section from outliving the route it documented
/// if that route is ever removed from `INVENTORY`.
#[test]
fn every_anchor_names_a_real_route() {
    let markdown = read_wire_format();
    let documented = anchors(&markdown);

    let bogus: Vec<_> = documented
        .iter()
        .filter(|(_, method, path)| {
            !INVENTORY
                .iter()
                .any(|spec| spec.method == method && spec.path == path)
        })
        .collect();

    if bogus.is_empty() {
        return;
    }

    let list = bogus
        .iter()
        .map(|(line, method, path)| format!("  - line {line}: {method} {path}"))
        .collect::<Vec<_>>()
        .join("\n");

    panic!(
        "{count} anchor(s) in {doc} name a route that is not in INVENTORY \
         (removed, or a typo):\n{list}",
        count = bogus.len(),
        doc = wire_format_path().display(),
    );
}

/// No two sections both claim to be normative for the same route.
#[test]
fn no_anchor_appears_twice() {
    let markdown = read_wire_format();
    let documented = anchors(&markdown);

    let mut by_route: std::collections::BTreeMap<(String, String), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (line, method, path) in documented {
        by_route.entry((method, path)).or_default().push(line);
    }

    let duplicates: Vec<_> = by_route
        .into_iter()
        .filter(|(_, lines)| lines.len() > 1)
        .collect();

    if duplicates.is_empty() {
        return;
    }

    let list = duplicates
        .iter()
        .map(|((method, path), lines)| {
            let lines = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("  - {method} {path}: lines {lines}")
        })
        .collect::<Vec<_>>()
        .join("\n");

    panic!(
        "{count} route(s) have more than one anchor in {doc}:\n{list}",
        count = duplicates.len(),
        doc = wire_format_path().display(),
    );
}

/// Every anchor is immediately followed - skipping blank lines, never
/// skipping content - by a `###` heading naming the same method and
/// path.
///
/// This is what stops an anchor from being parked in a corner,
/// decoupled from any real content: an anchor with no heading right
/// after it is not documenting anything, whatever else is on the page.
#[test]
fn every_anchor_is_followed_by_its_heading() {
    let markdown = read_wire_format();
    let lines: Vec<&str> = markdown.lines().collect();
    let documented = anchors(&markdown);

    let violations: Vec<_> = documented
        .iter()
        .filter_map(|(line, method, path)| {
            // `line` is the anchor's own 1-based line number, so the
            // line right after it starts at index `line` (0-based).
            let next = lines
                .iter()
                .skip(*line)
                .find(|candidate| !candidate.trim().is_empty())
                .copied()
                .unwrap_or("");

            let ok = next.trim_start().starts_with("### ")
                && next.contains(method.as_str())
                && next.contains(path.as_str());

            if ok {
                None
            } else {
                Some(format!(
                    "  - line {line}: {method} {path} is not immediately followed \
                     by its heading (found {next:?})"
                ))
            }
        })
        .collect();

    if violations.is_empty() {
        return;
    }

    panic!(
        "{count} anchor(s) in {doc} are not immediately followed by a heading \
         naming the same method and path:\n{list}",
        count = violations.len(),
        doc = wire_format_path().display(),
        list = violations.join("\n"),
    );
}

/// The parser has to be able to fail, or it proves nothing about the
/// anchors that pass. Each of these is close enough to the convention
/// that a careless scan - one that just looks for the words "route",
/// the method and the path anywhere on the line - would accept it.
/// None of them actually satisfies the convention.
#[test]
fn the_scan_can_fail() {
    for bogus in [
        "<!--route: GET /x-->",    // no space after `<!--` or before `-->`
        "<!-- Route: GET /x -->",  // "Route", not "route"
        "<!-- route:GET /x -->",   // no space after the colon
        "<!-- route: GET /x-->",   // no space before the closing marker
        "<!-- route: GET -->",     // no path at all
        "route: GET /x",           // not an HTML comment at all
        "<!-- anchor: GET /x -->", // wrong keyword
    ] {
        assert!(
            anchors(bogus).is_empty(),
            "the scan must not accept this as an anchor: {bogus:?}"
        );
    }

    // The one form that does work, so the bogus cases above are failing
    // for the right reason and not because the parser is broken outright.
    assert_eq!(
        anchors("<!-- route: GET /healthz -->"),
        vec![(1, "GET".to_owned(), "/healthz".to_owned())]
    );

    // And it has to work past the first line too.
    assert_eq!(
        anchors("line one\n<!-- route: POST /api/v1/pair -->"),
        vec![(2, "POST".to_owned(), "/api/v1/pair".to_owned())]
    );
}
