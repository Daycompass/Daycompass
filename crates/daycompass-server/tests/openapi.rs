//! Keeps `docs/openapi.json` honest, and `wire-v1` stable.
//!
//! Five checks:
//!
//!   1. The committed spec is exactly what the code generates - a
//!      handler or view changed without regenerating fails here.
//!   2. The spec has an operation for every [`INVENTORY`] route and for
//!      nothing else.
//!   3. Each operation's security says what the route table enforces.
//!   4. `docs/openapi-wire-v1.json` - the contract the first clients are
//!      written against - is byte-for-byte the frozen file, pinned by
//!      hash, so it cannot be quietly edited to make check 5 pass.
//!   5. The current spec is backward compatible with wire-v1: nothing a
//!      v1 client sends or reads has been removed or retyped, and
//!      nothing new is required of it.
//!
//! Regenerate the spec with
//!
//! ```sh
//! cargo run -p daycompass-server --example openapi > docs/openapi.json
//! ```
//!
//! # What check 5 does and does not catch
//!
//! It walks schemas structurally: removed operations, parameters and
//! properties, changed types, newly required inputs, removed accepted
//! enum values, changed security, a removed success status. It does not
//! see behaviour - a field that keeps its type but changes meaning
//! passes. That stays a human review, like the prose in
//! `docs/wire-format.md`.
//!
//! A deliberate breaking change is a new wire version, not an edit to
//! the v1 file: a new frozen file, a new tag, and clients that opt in.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

use daycompass_server::routes::openapi::spec_json;
use daycompass_server::routes::{Access, INVENTORY};

/// SHA-256 of `docs/openapi-wire-v1.json`, as frozen.
///
/// Changing the file means changing this constant too, in the same
/// diff, where a reviewer sees both. See the module doc for what a
/// breaking change should be instead.
const WIRE_V1_SHA256: &str = "de47b5ded7a36dc13ff4fdb6c79950037ae294e1eac8a87d6fa5a8e82e191513";

fn docs(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(name)
}

fn read(name: &str) -> String {
    std::fs::read_to_string(docs(name)).unwrap_or_else(|err| panic!("reading docs/{name}: {err}"))
}

fn current() -> Value {
    serde_json::from_str(&spec_json()).expect("the generated spec is JSON")
}

fn wire_v1() -> Value {
    serde_json::from_str(&read("openapi-wire-v1.json")).expect("the wire-v1 spec is JSON")
}

// --- 1. drift ---------------------------------------------------------

#[test]
fn the_committed_spec_matches_the_code() {
    let committed = read("openapi.json");
    assert!(
        committed.trim_end() == spec_json(),
        "docs/openapi.json is out of date. Regenerate it:\n  \
         cargo run -p daycompass-server --example openapi > docs/openapi.json"
    );
}

// --- 2. coverage --------------------------------------------------------

fn operations(spec: &Value) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().expect("paths") {
        for method in item.as_object().expect("a path item").keys() {
            out.insert((method.to_uppercase(), path.clone()));
        }
    }
    out
}

#[test]
fn every_route_is_in_the_spec_and_nothing_else_is() {
    let documented = operations(&current());
    let routed: BTreeSet<(String, String)> = INVENTORY
        .iter()
        .map(|spec| (spec.method.to_owned(), spec.path.to_owned()))
        .collect();

    let missing: Vec<_> = routed.difference(&documented).collect();
    let extra: Vec<_> = documented.difference(&routed).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "routes without an operation: {missing:?}\noperations without a route: {extra:?}\n\
         Add the handler to `paths(...)` in src/routes/openapi.rs."
    );
}

// --- 3. security ----------------------------------------------------------

#[test]
fn every_operations_security_matches_the_route_table() {
    let spec = current();
    for route in INVENTORY {
        let operation = &spec["paths"][route.path][route.method.to_lowercase()];
        let schemes: BTreeSet<String> = operation["security"]
            .as_array()
            .unwrap_or_else(|| panic!("{} {} states no security", route.method, route.path))
            .iter()
            .flat_map(|requirement| requirement.as_object().unwrap().keys().cloned())
            .collect();

        let mut expected = BTreeSet::new();
        match route.access {
            Access::Session | Access::Admin => {
                expected.insert("session_cookie".to_owned());
                if route.csrf {
                    expected.insert("csrf_token".to_owned());
                }
            }
            Access::Device => {
                expected.insert("device_token".to_owned());
            }
            Access::Public | Access::BodySecret => {}
        }
        assert_eq!(schemes, expected, "{} {}", route.method, route.path);

        let responses = operation["responses"].as_object().unwrap();
        if !route.rate_limits.is_empty() {
            assert!(
                responses.contains_key("429"),
                "{} {} is rate limited but documents no 429",
                route.method,
                route.path
            );
        }
        if route.access.needs_session() || route.access.needs_device() {
            assert!(
                responses.contains_key("401"),
                "{} {}",
                route.method,
                route.path
            );
        }
    }
}

// --- 4. the frozen file -------------------------------------------------

#[test]
fn the_wire_v1_spec_is_the_frozen_one() {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(docs("openapi-wire-v1.json")).expect("docs/openapi-wire-v1.json");
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex, WIRE_V1_SHA256,
        "docs/openapi-wire-v1.json changed. It is the frozen v1 contract; \
         a breaking change is a new wire version, not an edit to this file."
    );
}

// --- 5. compatibility -----------------------------------------------------

#[test]
fn the_current_spec_is_backward_compatible_with_wire_v1() {
    let problems = incompatibilities(&wire_v1(), &current());
    assert!(
        problems.is_empty(),
        "breaking changes against wire-v1:\n  {}",
        problems.join("\n  ")
    );
}

/// The checker has to be able to fail, or check 5 proves nothing.
#[test]
fn the_compatibility_check_catches_each_kind_of_break() {
    let old = wire_v1();
    assert!(
        incompatibilities(&old, &old).is_empty(),
        "a spec is compatible with itself"
    );

    type Mutation = fn(&mut Value);
    let cases: &[(&str, Mutation)] = &[
        ("a removed operation", |spec| {
            spec["paths"]
                .as_object_mut()
                .unwrap()
                .remove("/api/v1/stats");
        }),
        ("a removed response field", |spec| {
            spec["components"]["schemas"]["DeviceView"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("name");
        }),
        ("a retyped response field", |spec| {
            spec["components"]["schemas"]["DeviceView"]["properties"]["created_at"]["type"] =
                Value::from("string");
        }),
        ("a response field that may now be null", |spec| {
            spec["components"]["schemas"]["DeviceView"]["properties"]["name"]["type"] =
                serde_json::json!(["string", "null"]);
        }),
        ("a newly required request field", |spec| {
            let schema = &mut spec["components"]["schemas"]["RenameRequest"];
            schema["properties"]["colour"] = serde_json::json!({ "type": "string" });
            schema["required"]
                .as_array_mut()
                .unwrap()
                .push("colour".into());
        }),
        ("a removed request field", |spec| {
            spec["components"]["schemas"]["CreateRuleRequest"]["properties"]
                .as_object_mut()
                .unwrap()
                .remove("category");
        }),
        ("a newly required query parameter", |spec| {
            spec["paths"]["/api/v1/devices"]["get"]["parameters"] = serde_json::json!([
                { "name": "page", "in": "query", "required": true, "schema": { "type": "integer" } }
            ]);
        }),
        ("a removed success status", |spec| {
            spec["paths"]["/api/v1/devices"]["get"]["responses"]
                .as_object_mut()
                .unwrap()
                .remove("200");
        }),
        ("changed security", |spec| {
            spec["paths"]["/api/v1/pair"]["post"]["security"] =
                serde_json::json!([{ "session_cookie": [] }]);
        }),
    ];

    for (what, mutate) in cases {
        let mut new = old.clone();
        mutate(&mut new);
        assert!(
            !incompatibilities(&old, &new).is_empty(),
            "the checker missed {what}"
        );
    }
}

/// Every way `new` would break a client written against `old`.
fn incompatibilities(old: &Value, new: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let old_ops = old["paths"].as_object().expect("paths");

    for (path, old_item) in old_ops {
        for (method, old_op) in old_item.as_object().expect("a path item") {
            let at = format!("{} {path}", method.to_uppercase());
            let new_op = &new["paths"][path][method];
            if new_op.is_null() {
                problems.push(format!("{at}: operation removed"));
                continue;
            }

            if old_op["security"] != new_op["security"] {
                problems.push(format!("{at}: security changed"));
            }

            check_parameters(&at, old, old_op, new, new_op, &mut problems);

            let old_body = &old_op["requestBody"];
            let new_body = &new_op["requestBody"];
            if old_body.is_null() && new_body["required"] == Value::Bool(true) {
                problems.push(format!("{at}: a request body is now required"));
            }
            if !old_body.is_null() {
                let old_schema = &old_body["content"]["application/json"]["schema"];
                let new_schema = &new_body["content"]["application/json"]["schema"];
                if new_schema.is_null() {
                    problems.push(format!("{at}: the request body is no longer accepted"));
                } else {
                    compare(
                        &format!("{at} request"),
                        Side::Request,
                        old,
                        old_schema,
                        new,
                        new_schema,
                        &mut problems,
                    );
                }
            }

            for (status, old_response) in old_op["responses"].as_object().expect("responses") {
                if !status.starts_with('2') {
                    continue;
                }
                let new_response = &new_op["responses"][status];
                if new_response.is_null() {
                    problems.push(format!("{at}: {status} response removed"));
                    continue;
                }
                let old_schema = &old_response["content"]["application/json"]["schema"];
                let new_schema = &new_response["content"]["application/json"]["schema"];
                if !old_schema.is_null() {
                    compare(
                        &format!("{at} {status}"),
                        Side::Response,
                        old,
                        old_schema,
                        new,
                        new_schema,
                        &mut problems,
                    );
                }
            }
        }
    }
    problems
}

fn check_parameters(
    at: &str,
    old: &Value,
    old_op: &Value,
    new: &Value,
    new_op: &Value,
    problems: &mut Vec<String>,
) {
    let params =
        |op: &Value| -> Vec<Value> { op["parameters"].as_array().cloned().unwrap_or_default() };
    let key = |p: &Value| {
        (
            p["name"].as_str().unwrap_or("").to_owned(),
            p["in"].as_str().unwrap_or("").to_owned(),
        )
    };
    let old_params = params(old_op);
    let new_params = params(new_op);

    for old_param in &old_params {
        match new_params.iter().find(|p| key(p) == key(old_param)) {
            None => problems.push(format!("{at}: parameter {:?} removed", key(old_param))),
            Some(new_param) => compare(
                &format!("{at} parameter {}", key(old_param).0),
                Side::Request,
                old,
                &old_param["schema"],
                new,
                &new_param["schema"],
                problems,
            ),
        }
    }
    for new_param in &new_params {
        let existed = old_params.iter().any(|p| key(p) == key(new_param));
        if !existed && new_param["required"] == Value::Bool(true) {
            problems.push(format!("{at}: new required parameter {:?}", key(new_param)));
        }
    }
}

/// Which direction data flows, which decides what "compatible" means:
/// a request may accept more than before, a response may promise more.
#[derive(Clone, Copy, PartialEq)]
enum Side {
    Request,
    Response,
}

fn resolve<'a>(spec: &'a Value, schema: &'a Value) -> &'a Value {
    match schema["$ref"].as_str() {
        Some(reference) => {
            let name = reference.rsplit('/').next().expect("a ref has a name");
            resolve(spec, &spec["components"]["schemas"][name])
        }
        None => schema,
    }
}

fn types(schema: &Value) -> BTreeSet<String> {
    match &schema["type"] {
        Value::String(one) => BTreeSet::from([one.clone()]),
        Value::Array(many) => many
            .iter()
            .filter_map(|t| t.as_str().map(str::to_owned))
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn compare(
    at: &str,
    side: Side,
    old_spec: &Value,
    old: &Value,
    new_spec: &Value,
    new: &Value,
    problems: &mut Vec<String>,
) {
    let old = resolve(old_spec, old);
    let new = resolve(new_spec, new);
    if new.is_null() {
        problems.push(format!("{at}: schema removed"));
        return;
    }

    let (old_types, new_types) = (types(old), types(new));
    let narrowed = match side {
        // A client may still send every type it could before.
        Side::Request => !old_types.is_subset(&new_types),
        // A client must not receive a type it was never told about.
        Side::Response => !new_types.is_subset(&old_types),
    };
    if narrowed && !(old_types.is_empty() && new_types.is_empty()) {
        problems.push(format!(
            "{at}: type changed from {old_types:?} to {new_types:?}"
        ));
    }

    if side == Side::Request {
        let (old_enum, new_enum) = (strings(&old["enum"]), strings(&new["enum"]));
        if !old_enum.is_empty() && !old_enum.is_subset(&new_enum) {
            problems.push(format!("{at}: accepted values removed"));
        }
    }

    let (old_required, new_required) = (strings(&old["required"]), strings(&new["required"]));
    match side {
        Side::Request => {
            for field in new_required.difference(&old_required) {
                problems.push(format!("{at}: field {field:?} is newly required"));
            }
        }
        Side::Response => {
            for field in old_required.difference(&new_required) {
                problems.push(format!("{at}: field {field:?} is no longer always present"));
            }
        }
    }

    if let Some(old_props) = old["properties"].as_object() {
        for (name, old_prop) in old_props {
            let new_prop = &new["properties"][name];
            if new_prop.is_null() {
                problems.push(format!("{at}: field {name:?} removed"));
            } else {
                compare(
                    &format!("{at}.{name}"),
                    side,
                    old_spec,
                    old_prop,
                    new_spec,
                    new_prop,
                    problems,
                );
            }
        }
    }

    if !old["items"].is_null() {
        compare(
            &format!("{at}[]"),
            side,
            old_spec,
            &old["items"],
            new_spec,
            &new["items"],
            problems,
        );
    }
}
