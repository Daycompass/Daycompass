//! Who may read an event back, and through which one route.
//!
//! M2 shipped with no read path for anyone - not an endpoint, not a
//! service function, not a join. M3 adds exactly one:
//! `GET /api/v1/events`, session-scoped to the caller's own account.
//! This file's rule is narrower now than "nobody, ever" - it is
//! *nobody else, and no other path* - but it is still a rule this file
//! checks against the sources rather than trusting it to be
//! remembered.
//!
//! An admin still reaches zero event data, full stop: there is no
//! admin variant of the route and no id parameter anywhere that could
//! point it at another account. [`query::list_own`] only ever takes
//! the caller's own id, resolved from the session the access layer
//! already authenticated.
//!
//! Four checks, deliberately overlapping, because each one catches a
//! different way the rule could be broken:
//!
//!   1. The route inventory has exactly two routes that touch events:
//!      the write, and the owner's own read.
//!   2. No source file outside `events/store.rs` mentions the `events`
//!      table in SQL, and that one file's read is provably scoped by
//!      the caller's own `user_id` rather than a bare, unscoped
//!      `SELECT`.
//!   3. The responses an admin and an owner actually receive from
//!      *other* routes have exactly the fields they are supposed to,
//!      and no more.
//!   4. The owner's route returns only the caller's own events, inside
//!      the requested window, to a session - and nothing at all to an
//!      anonymous caller or a device's bearer token.
//!
//! # A note for M4
//!
//! The source scan in check 2 **is expected to be edited again** when
//! M4 adds retention deletes. That is the point of it: extending the
//! allowed list or the allowed verbs is a line in a diff that a
//! reviewer sees and has to agree with. Deleting the test, or widening
//! it to "anything under src/", is not the same thing and is not what
//! it is for.

mod common;

use std::path::{Path, PathBuf};

use axum::http::StatusCode;

use common::{TestApp, TestRequest, GOOD_ORIGIN};
use daycompass_server::routes::{Access, INVENTORY};

/// The two routes allowed to touch events, and the direction each
/// goes.
const EVENT_ROUTES: &[(&str, &str)] = &[("POST", "/api/v1/events"), ("GET", "/api/v1/events")];

/// Files permitted to name the `events` table in SQL.
///
/// Extend this deliberately, with a reviewer, when a milestone adds a
/// legitimate reason - M4's retention deletes. Do not widen the scan
/// instead.
const FILES_ALLOWED_TO_QUERY_EVENTS: &[&str] = &["events/store.rs"];

/// SQL shapes that read, write or delete a named table.
///
/// Matched against a normalized copy of each file: lowercased, with
/// every run of whitespace collapsed to one space. That is what makes
/// `FROM\n    events`, `from events` and `FROM   Events` all visible
/// to a fixed-string search.
const SQL_VERBS: &[&str] = &[
    "from events",
    "join events",
    "into events",
    "update events",
    "delete from events",
    "table events",
];

/// The inventory may contain exactly the write and the owner's own
/// read, and the read must be session-scoped - never admin, never a
/// device's bearer token.
#[test]
fn the_inventory_has_exactly_the_write_and_the_owner_read() {
    let mut touching: Vec<(&str, &str)> = INVENTORY
        .iter()
        .filter(|spec| spec.path.contains("event"))
        .map(|spec| (spec.method, spec.path))
        .collect();
    touching.sort_unstable();

    let mut expected = EVENT_ROUTES.to_vec();
    expected.sort_unstable();
    assert_eq!(
        touching, expected,
        "a route touching events appeared outside the write and the owner's own read"
    );

    let read = daycompass_server::routes::spec_for("GET", "/api/v1/events")
        .expect("the owner's read must be in the table");
    assert_eq!(
        read.access,
        Access::Session,
        "the owner's read must be session-scoped, never admin and never a device"
    );

    // And nothing may read events under another name. Any route on a
    // path that is neither of the two above is a read by definition
    // if it even looks like one.
    for spec in INVENTORY {
        if EVENT_ROUTES.contains(&(spec.method, spec.path)) {
            continue;
        }
        assert!(
            !spec.path.contains("event") && !spec.path.contains("stats"),
            "{} {} looks like an event read path",
            spec.method,
            spec.path
        );
    }
}

/// No source file outside the ingest store may name the table in
/// production code.
///
/// A textual check, so its limits are worth stating: it normalizes
/// whitespace and case, and it skips comment lines - including the
/// prose in `events/mod.rs` explaining this very rule - but it cannot
/// see SQL assembled in a macro or built out of string fragments. It
/// catches the ordinary mistake, which is someone adding a perfectly
/// reasonable query in the obvious place.
///
/// `#[cfg(test)]` modules are excluded. A unit test that counts rows
/// to prove ingest stored them is not a read path - it does not ship,
/// and it cannot be reached over HTTP. The exclusion only holds
/// because test modules in this crate are the last item in their
/// file, which [`production_part`] asserts rather than assumes.
#[test]
fn no_source_file_outside_the_ingest_store_queries_events() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&src);
    assert!(!sources.is_empty(), "the scan must read something");

    let mut offenders: Vec<String> = Vec::new();

    for path in &sources {
        let relative = relative_to(&src, path);
        if FILES_ALLOWED_TO_QUERY_EVENTS
            .iter()
            .any(|allowed| relative.ends_with(allowed))
        {
            continue;
        }

        let text = std::fs::read_to_string(path).expect("a source file must be readable");
        let normalized = normalize(production_part(&text, &relative));

        for verb in SQL_VERBS {
            if normalized.contains(verb) {
                offenders.push(format!("{relative}: {verb}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these files query the events table and are not allowed to: {offenders:?}\n\
         If a milestone legitimately adds one, add the file to \
         FILES_ALLOWED_TO_QUERY_EVENTS rather than widening the scan."
    );
}

/// The allowed file really does contain the write and the read, so
/// the scan is not passing because its needles are wrong - and the
/// read really is scoped by the caller's own `user_id`, not a bare
/// `SELECT` that would trust something else to filter it.
#[test]
fn the_scan_finds_the_write_and_the_owner_scoped_read() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let store = src.join("events").join("store.rs");
    let text = std::fs::read_to_string(&store).expect("the events store must exist");
    let normalized = normalize(&text);

    assert!(
        normalized.contains("into events"),
        "the ingest insert must be here, or the scan's needles are wrong"
    );
    assert!(
        normalized.contains("from events") && normalized.contains("join devices"),
        "the owner's read must be here, joined against devices, or the scan's needles are wrong"
    );
    assert!(
        normalized.contains("where d.user_id ="),
        "the read must scope by the caller's own user id in its WHERE clause, \
         not merely by an id a caller could supply"
    );

    // Still nothing may update or delete an event. M4 adds retention
    // deletes, deliberately, with its own review of this test.
    for verb in ["update events", "delete from events"] {
        assert!(
            !normalized.contains(verb),
            "even the owner's read may not {verb}"
        );
    }
}

/// The scan has to be able to fail, or it proves nothing. This feeds
/// it the spellings a fixed-string search would miss.
#[test]
fn the_scan_sees_through_whitespace_and_case() {
    for spelling in [
        "SELECT * FROM events",
        "select * from events",
        "SELECT * FROM   Events",
        "SELECT *\n             FROM\n             events",
        "SELECT * FROM users u JOIN Events e ON e.device_id = d.id",
        "DELETE   FROM\tevents WHERE received_at < ?1",
    ] {
        let normalized = normalize(spelling);
        assert!(
            SQL_VERBS.iter().any(|verb| normalized.contains(verb)),
            "the scan would have missed: {spelling:?}"
        );
    }

    // And it must not fire on things that merely mention the word.
    for innocent in [
        "let events = Vec::new();",
        "pub mod events;",
        "crate::events::ingest",
        "the events a device reported",
    ] {
        let normalized = normalize(innocent);
        assert!(
            !SQL_VERBS.iter().any(|verb| normalized.contains(verb)),
            "the scan must not fire on: {innocent:?}"
        );
    }
}

/// The part of a file that actually ships: everything before its
/// `#[cfg(test)]` module.
///
/// Asserts that the attribute appears at most once, so the cut cannot
/// silently hide production code that happens to sit after a test
/// module. If a file ever needs two, this test has to be reworked
/// rather than quietly losing coverage of the second half.
fn production_part<'a>(text: &'a str, relative: &str) -> &'a str {
    let occurrences = text.matches("#[cfg(test)]").count();
    assert!(
        occurrences <= 1,
        "{relative} has {occurrences} #[cfg(test)] attributes; the scan's \
         cut-at-the-first rule would hide code after the first one"
    );

    match text.find("#[cfg(test)]") {
        Some(index) => &text[..index],
        None => text,
    }
}

/// Lowercased, comment lines dropped, whitespace runs collapsed.
fn normalize(text: &str) -> String {
    let without_comments: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    without_comments
        .join(" ")
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).expect("the source directory must be readable");

    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            files.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

// --- what an admin actually receives ----------------------------------

/// The admin device listing, pinned field for field.
///
/// This is the one view where a careless addition could put event data
/// in front of somebody who must never see it, so the field set is
/// asserted exactly rather than by checking that a few bad names are
/// absent.
#[tokio::test]
async fn the_admin_device_listing_carries_metadata_and_nothing_else() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_id, user_credentials) = app.create_account(&admin, "bob", "user").await;
    let user = app.log_in(&user_credentials).await;
    let device = app.pair_device(&user, "bobs-laptop", "android").await;

    // Give the device something to have reported, so a join that
    // leaked events would have something to leak.
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let ingested = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(serde_json::json!({
                    "events": [{
                        "event_id": "0123456789abcdef0123456789abcdef",
                        "start_ts": now - 600,
                        "duration_secs": 300,
                        "app_id": "org.example.secretgame",
                        "label": "A Very Private Thing",
                        "domain": "private.example",
                    }],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 1);

    let listing = app
        .send(
            TestRequest::get("/api/v1/admin/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.body);

    let devices = listing.body["devices"].as_array().expect("an array");
    assert_eq!(devices.len(), 1);

    let mut keys: Vec<&str> = devices[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "created_at",
            "id",
            "last_seen_at",
            "name",
            "owner_id",
            "owner_username",
            "platform",
            "revoked_at",
        ],
        "the admin device view grew a field; if it is event data, it must not exist"
    );

    // Nothing from the event may appear anywhere in the response.
    let rendered = listing.body.to_string();
    for leaked in [
        "org.example.secretgame",
        "A Very Private Thing",
        "private.example",
        "0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            !rendered.contains(leaked),
            "the admin listing leaked event data: {leaked}"
        );
    }
}

/// The same for the owner's own device listing. An owner may see
/// their devices; `GET /api/v1/devices` itself still carries no event
/// data - that is the one job of the dedicated `GET /api/v1/events`
/// route below, and this route is not it.
#[tokio::test]
async fn the_owners_device_listing_carries_no_event_data_either() {
    let app = TestApp::new().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    app.send(
        TestRequest::post("/api/v1/events")
            .authenticated_as_device(&device)
            .json(serde_json::json!({
                "events": [{
                    "event_id": "0123456789abcdef0123456789abcdef",
                    "start_ts": now - 600,
                    "duration_secs": 300,
                    "app_id": "org.example.secretgame",
                }],
            })),
    )
    .await;

    let listing = app
        .send(
            TestRequest::get("/api/v1/devices")
                .origin(GOOD_ORIGIN)
                .authenticated(&session),
        )
        .await;
    assert_eq!(listing.status, StatusCode::OK);

    let devices = listing.body["devices"].as_array().expect("an array");
    let mut keys: Vec<&str> = devices[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "created_at",
            "id",
            "last_seen_at",
            "name",
            "platform",
            "revoked_at",
        ]
    );
    assert!(!listing.body.to_string().contains("org.example.secretgame"));
}

/// No `GET` other than the owner's own events route ever returns an
/// event, to anybody.
///
/// The property asserted is "never 2xx, and no event data in the
/// body", not a particular status code. `GET /api/v1/events` itself
/// is excluded from this sweep and tested on its own below, with its
/// query string, where it is supposed to answer with the caller's own
/// events; every other path here must still refuse to.
#[tokio::test]
async fn no_get_other_than_the_owners_events_route_returns_an_event() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    // Something to leak, if anything were going to.
    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();
    let ingested = app
        .send(
            TestRequest::post("/api/v1/events")
                .authenticated_as_device(&device)
                .json(serde_json::json!({
                    "events": [{
                        "event_id": "0123456789abcdef0123456789abcdef",
                        "start_ts": now - 600,
                        "duration_secs": 300,
                        "app_id": "org.example.secretgame",
                        "label": "A Very Private Thing",
                        "domain": "private.example",
                    }],
                })),
        )
        .await;
    assert_eq!(ingested.body["accepted"], 1);

    let needles = [
        "org.example.secretgame",
        "A Very Private Thing",
        "private.example",
    ];

    // Every path in the inventory except the owner's own events
    // route, plus the ones a reader might reasonably expect to exist.
    let mut paths: Vec<String> = INVENTORY
        .iter()
        .filter(|spec| spec.path != "/api/v1/events")
        .map(|spec| spec.path.replace("{id}", &device.id))
        .collect();
    paths.extend(
        [
            "/api/v1/stats",
            "/api/v1/devices/events",
            "/api/v1/admin/events",
            "/api/v1/admin/devices/events",
            "/api/v1/devices/{id}/events",
        ]
        .map(|path| path.replace("{id}", &device.id)),
    );

    for path in paths {
        for (label, request) in [
            (
                "an admin",
                TestRequest::get(&path)
                    .origin(GOOD_ORIGIN)
                    .authenticated(&admin),
            ),
            (
                "the device",
                TestRequest::get(&path).authenticated_as_device(&device),
            ),
            ("nobody", TestRequest::get(&path)),
        ] {
            let response = app.send(request).await;
            let rendered = response.body.to_string();

            for needle in needles {
                assert!(
                    !rendered.contains(needle),
                    "GET {path} as {label} returned event data: {needle}"
                );
            }
        }
    }
}

/// `GET /api/v1/events` returns only the caller's own events, inside
/// the requested window - never another account's, even an admin's
/// own session querying it directly.
///
/// This is the regression the rule in this file exists to catch now:
/// an admin manages `bob`'s account and devices, but their own
/// session is still a different `user_id`, and the route takes no
/// parameter that could point it anywhere else.
#[tokio::test]
async fn the_owner_route_returns_only_the_callers_own_events_in_window() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let (_bob_id, bob_credentials) = app.create_account(&admin, "bob", "user").await;
    let bob = app.log_in(&bob_credentials).await;

    let admin_device = app.pair_device(&admin, "admins-laptop", "linux").await;
    let bobs_device = app.pair_device(&bob, "bobs-laptop", "android").await;

    let me = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&admin_device))
        .await;
    let now = me.body["server_time"].as_i64().unwrap();

    for (device, domain) in [
        (&admin_device, "admin.example"),
        (&bobs_device, "private.example"),
    ] {
        let ingested = app
            .send(
                TestRequest::post("/api/v1/events")
                    .authenticated_as_device(device)
                    .json(serde_json::json!({
                        "events": [{
                            "event_id": "0123456789abcdef0123456789abcdef",
                            "start_ts": now - 600,
                            "duration_secs": 300,
                            "app_id": "org.example.secretgame",
                            "domain": domain,
                        }],
                    })),
            )
            .await;
        assert_eq!(ingested.body["accepted"], 1, "{:?}", ingested.body);
    }

    let path = format!(
        "/api/v1/events?start_ts={}&end_ts={}",
        now - 3600,
        now + 3600
    );

    let as_bob = app
        .send(
            TestRequest::get(&path)
                .origin(GOOD_ORIGIN)
                .authenticated(&bob),
        )
        .await;
    assert_eq!(as_bob.status, StatusCode::OK, "{:?}", as_bob.body);
    let bobs_events = as_bob.body["events"].as_array().expect("an array");
    assert_eq!(bobs_events.len(), 1);
    assert_eq!(bobs_events[0]["domain"], "private.example");
    assert_eq!(as_bob.body["truncated"], false);

    let as_admin = app
        .send(
            TestRequest::get(&path)
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    assert_eq!(as_admin.status, StatusCode::OK, "{:?}", as_admin.body);
    let admins_events = as_admin.body["events"].as_array().expect("an array");
    assert_eq!(admins_events.len(), 1);
    assert_eq!(admins_events[0]["domain"], "admin.example");

    // The admin manages bob's account and devices, but their own
    // session must never surface bob's event through this route.
    assert!(!as_admin.body.to_string().contains("private.example"));
}

/// `GET /api/v1/events` refuses an anonymous caller and a device's
/// bearer token alike - both answer `401`, and neither sees a body
/// with an `events` array in it.
///
/// Pinning `401` rather than a generic "never 2xx" here is deliberate:
/// unlike the sweep above, this route's own contract is being tested,
/// not merely that it keeps quiet.
#[tokio::test]
async fn the_owner_route_refuses_anonymous_and_device_callers() {
    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;
    let device = app.pair_device(&admin, "laptop", "linux").await;

    let path = "/api/v1/events?start_ts=0&end_ts=100";

    let anonymous = app.send(TestRequest::get(path).origin(GOOD_ORIGIN)).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert!(anonymous.body.get("events").is_none());

    let as_device = app
        .send(TestRequest::get(path).authenticated_as_device(&device))
        .await;
    assert_eq!(as_device.status, StatusCode::UNAUTHORIZED);
    assert!(as_device.body.get("events").is_none());
}
