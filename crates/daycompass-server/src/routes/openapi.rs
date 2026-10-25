//! The OpenAPI description of this server, committed as
//! `docs/openapi.json`.
//!
//! Never served: there is no route for it, so it adds nothing to what
//! an instance exposes. Clients read the file from the repository.
//! Regenerate it with
//!
//! ```sh
//! cargo run -p daycompass-server --example openapi > docs/openapi.json
//! ```
//!
//! and `tests/openapi.rs` fails if the committed file and the code
//! disagree.
//!
//! # What comes from where
//!
//! Each handler's `#[utoipa::path]` states what only the handler knows:
//! its request and success bodies, and the errors its own logic
//! produces. Everything [`INVENTORY`] decides - which credential a route
//! takes, whether it needs `X-CSRF-Token`, whether it is rate limited -
//! is added here by [`FromInventory`] instead of being annotated by
//! hand, so the spec cannot claim a protection the route table does not
//! attach, or miss one it does.
//!
//! `docs/wire-format.md` stays the normative prose: sync behaviour,
//! idempotency, what each error code means in context. This file is the
//! machine-readable shape.

use utoipa::openapi::header::Header;
use utoipa::openapi::path::Operation;
use utoipa::openapi::response::{Response, ResponseBuilder};
use utoipa::openapi::schema::{Object, Ref, Type};
use utoipa::openapi::security::{
    ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityRequirement, SecurityScheme,
};
use utoipa::openapi::{Content, OpenApi as Spec, RefOr};
use utoipa::{Modify, OpenApi};

use super::{Access, OriginRule, RouteSpec, INVENTORY};
use crate::auth::cookie::COOKIE_NAME;
use crate::error::ErrorBody;

/// The security scheme names used in the spec.
const SESSION: &str = "session_cookie";
const CSRF: &str = "csrf_token";
const DEVICE: &str = "device_token";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Daycompass API",
        version = "1",
        description = "Self-hosted screen time backend. Normative prose - sync behaviour, \
                       idempotency, what each error code means in context - lives in \
                       docs/wire-format.md; this is the machine-readable shape.",
        license(name = "AGPL-3.0-only", identifier = "AGPL-3.0-only"),
    ),
    paths(
        super::health::healthz,
        super::setup::create_first_admin,
        super::auth::log_in,
        super::auth::log_out,
        super::auth::me,
        super::auth::change_password,
        super::users::create_user,
        super::users::list_users,
        super::users::change_role,
        super::users::delete_user,
        super::users::reset_password,
        super::invites::redeem,
        super::account::log,
        super::pairing::create_code,
        super::pairing::pair_device,
        super::events::ingest,
        super::events::list_own,
        super::events::device_me,
        super::categories::create_own,
        super::categories::list_own,
        super::categories::delete_own,
        super::stats::daily_totals,
        super::export::export_own,
        super::devices::list_own,
        super::devices::rename_own,
        super::devices::revoke_own,
        super::devices::list_all,
        super::devices::revoke_any,
    ),
    components(schemas(ErrorBody)),
    modifiers(&FromInventory),
)]
struct ApiDoc;

/// The spec as pretty-printed JSON, exactly as committed in
/// `docs/openapi.json` (without the trailing newline).
pub fn spec_json() -> String {
    let mut value = serde_json::to_value(ApiDoc::openapi())
        .expect("the OpenAPI document is always serializable");
    tidy_descriptions(&mut value);
    serde_json::to_string_pretty(&value).expect("a JSON value is always serializable")
}

/// Keeps rustdoc prose meant for this codebase's readers out of a file
/// meant for client authors.
///
/// utoipa turns every doc comment into a `description`. On a handler or
/// a whole type, that is design rationale ("this handler stays thin",
/// "deliberately not the full record") - dropped, since each operation
/// has its own `summary` and `docs/wire-format.md` has the prose. On a
/// field it is usually what a client needs, so it stays, with rustdoc's
/// `[`link`]` brackets reduced to plain code spans.
fn tidy_descriptions(spec: &mut serde_json::Value) {
    if let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) {
        for item in paths.values_mut().filter_map(|i| i.as_object_mut()) {
            for operation in item.values_mut().filter_map(|o| o.as_object_mut()) {
                operation.remove("description");
            }
        }
    }
    if let Some(schemas) = spec
        .pointer_mut("/components/schemas")
        .and_then(|s| s.as_object_mut())
    {
        for schema in schemas.values_mut().filter_map(|s| s.as_object_mut()) {
            schema.remove("description");
        }
    }
    unlink(spec);
}

fn unlink(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                match nested {
                    serde_json::Value::String(text) if key == "description" => {
                        *text = text.replace("[`", "`").replace("`]", "`");
                    }
                    _ => unlink(nested),
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(unlink),
        _ => {}
    }
}

/// Adds what [`INVENTORY`] decides to every operation: security, and the
/// error responses the access and rate-limit layers produce.
struct FromInventory;

impl Modify for FromInventory {
    fn modify(&self, spec: &mut Spec) {
        let components = spec.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            SESSION,
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                COOKIE_NAME,
                "The session cookie set by `POST /api/v1/auth/login`.",
            ))),
        );
        components.add_security_scheme(
            CSRF,
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-CSRF-Token",
                "The `csrf_token` from login or `GET /api/v1/auth/me`, on every write \
                 that requires it - always together with the session cookie.",
            ))),
        );
        let mut bearer = Http::new(HttpAuthScheme::Bearer);
        bearer.description =
            Some("The device token from `POST /api/v1/pair`. Never a session.".to_owned());
        components.add_security_scheme(DEVICE, SecurityScheme::Http(bearer));

        for route in INVENTORY {
            // A route missing from the spec is left alone here and
            // reported by `tests/openapi.rs`, which can fail; a modifier
            // cannot.
            let Some(item) = spec.paths.paths.get_mut(route.path) else {
                continue;
            };
            let operation = match route.method {
                "GET" => item.get.as_mut(),
                "POST" => item.post.as_mut(),
                "PATCH" => item.patch.as_mut(),
                "DELETE" => item.delete.as_mut(),
                _ => None,
            };
            if let Some(operation) = operation {
                apply(route, operation);
            }
        }
    }
}

fn apply(route: &RouteSpec, operation: &mut Operation) {
    operation.security = match route.access {
        Access::Session | Access::Admin if route.csrf => Some(vec![SecurityRequirement::new(
            SESSION,
            Vec::<String>::new(),
        )
        .add(CSRF, Vec::<String>::new())]),
        Access::Session | Access::Admin => Some(vec![SecurityRequirement::new(
            SESSION,
            Vec::<String>::new(),
        )]),
        Access::Device => Some(vec![SecurityRequirement::new(DEVICE, Vec::<String>::new())]),
        // No credential: an empty list rather than `None`, so the
        // operation says so explicitly instead of inheriting anything.
        Access::Public | Access::BodySecret => Some(Vec::new()),
    };

    if route.access.needs_session() || route.access.needs_device() {
        add_error(
            operation,
            "401",
            if route.access.needs_device() {
                "`unauthenticated`: no valid device token. Stop and re-pair; do not retry in a loop."
            } else {
                "`unauthenticated`: no valid session."
            },
        );
    }

    let mut forbidden: Vec<&str> = Vec::new();
    if route.access == Access::Admin {
        forbidden.push("`not_permitted` (not an admin)");
    }
    if route.csrf {
        forbidden.push("`csrf_token_missing` / `csrf_token_invalid`");
    }
    // The check skips safe methods, so a `GET` never answers this.
    if route.origin == OriginRule::Checked && !crate::auth::origin::is_safe_method(route.method) {
        forbidden.push("`origin_mismatch` (a present `Origin` names another site)");
    }
    if !forbidden.is_empty() {
        add_error(operation, "403", &forbidden.join(", or "));
    }

    if !route.rate_limits.is_empty() {
        let mut response = error_response("`rate_limited`. Wait for `Retry-After` seconds.");
        let mut retry_after = Header::new(Object::with_type(Type::Integer));
        retry_after.description = Some("Seconds until the window resets.".to_owned());
        response
            .headers
            .insert("Retry-After".to_owned(), RefOr::T(retry_after));
        insert_if_absent(operation, "429", response);
    }

    add_error(
        operation,
        "default",
        "Any other error, in the uniform shape. See the conventions in docs/wire-format.md.",
    );
}

fn add_error(operation: &mut Operation, status: &str, description: &str) {
    insert_if_absent(operation, status, error_response(description));
}

/// A status the handler already documents keeps the handler's own
/// description: it knows the codes its logic produces, which this
/// generic text does not.
fn insert_if_absent(operation: &mut Operation, status: &str, response: Response) {
    operation
        .responses
        .responses
        .entry(status.to_owned())
        .or_insert(RefOr::T(response));
}

fn error_response(description: &str) -> Response {
    ResponseBuilder::new()
        .description(description)
        .content(
            "application/json",
            Content::new(Some(Ref::from_schema_name("ErrorBody"))),
        )
        .build()
}
