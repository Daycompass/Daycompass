//! The server-rendered dashboard (M5): askama templates, htmx for the
//! writes, and nothing else on the client.
//!
//! These are thin handlers in the same sense as the JSON ones next to
//! them: they read the session the access layer resolved, call the same
//! service functions, and render the result. Every route here has an
//! entry in [`crate::routes::INVENTORY`] with [`Surface::Page`], and is
//! protected by exactly the layers that entry attaches.
//!
//! # What the browser runs
//!
//! One script, `htmx`, served from this binary. The Content-Security-
//! Policy (in [`crate::middleware`]) allows scripts, styles, fonts and
//! images from this origin only, and no inline script or style at all.
//! htmx is configured accordingly from a `<meta name="htmx-config">`
//! tag in the layout - no `eval`, no inline indicator styles, no
//! history snapshots (which would copy pages, CSRF token included, into
//! `localStorage`).
//!
//! # CSRF
//!
//! The same `X-CSRF-Token` header the API uses, so the same check
//! enforces it. The layout puts the session's token into `hx-headers`
//! on `<body>`, and htmx sends it with every request it makes. Writes
//! therefore need JavaScript; reading does not. The one write that
//! works without JavaScript is the login form, which has no session and
//! so no token - it is `Origin`-checked instead, exactly like the API
//! login.
//!
//! # How a refusal is shown
//!
//! [`render_errors`] wraps every page route, outside all of its other
//! layers. Whatever produced an error - a handler, the access layer, a
//! rate limit, the `Origin` check, an extractor - it is re-rendered from
//! its [`ErrorKind`] as HTML, with the status left as it was:
//!
//! * A plain page load without a session is sent to `/login` with a
//!   303, because that is what a person following a link wants.
//! * An htmx request gets a small fragment, swapped into the layout's
//!   `#dc-flash` area by `HX-Retarget`. Without a session it is also
//!   sent to `/login`, by `HX-Redirect`.
//! * Anything else gets a full error page.
//!
//! The message is always [`ErrorKind::message`], so no request input
//! reaches the page through an error, the same guarantee the JSON shape
//! gives.
//!
//! [`Surface::Page`]: crate::routes::Surface::Page

pub mod account;
pub mod admin;
pub mod assets;
pub mod categories;
pub mod devices;
pub mod login;
pub mod onboarding;
pub mod overview;

use askama::Template;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

use crate::auth::origin;
use crate::error::{ApiError, Deliberate, ErrorKind};

/// Where a browser without a session is sent.
const LOGIN_PATH: &str = "/login";

/// Whether htmx issued this request. htmx sets `HX-Request: true` on
/// every request it makes; a plain navigation or form post has none.
///
/// Only ever used to choose the *shape* of a response, never to decide
/// whether a request is allowed - the header is trivially forgeable,
/// and nothing about it is a credential.
pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("hx-request")
        .is_some_and(|value| value.as_bytes() == b"true")
}

/// Renders `template` as an HTML response.
///
/// A template that fails to render is a bug in this server, not
/// something the caller did, so it is logged and answered with the
/// generic internal error - never with the renderer's own message.
pub fn render<T: Template>(template: &T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "rendering a template failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

/// Renders `template` as the answer to a successful htmx write.
///
/// The same as [`render`], plus an out-of-band swap that empties the
/// layout's `#dc-flash`: an error banner from an earlier attempt would
/// otherwise stay on screen above a write that has since succeeded.
/// Only for fragments - a full page has its own, empty flash area.
pub fn render_fragment<T: Template>(template: &T) -> Response {
    match template.render() {
        Ok(mut html) => {
            html.push_str(FLASH_CLEAR);
            Html(html).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "rendering a template failed");
            ApiError::of(ErrorKind::InternalError).into_response()
        }
    }
}

/// An empty `#dc-flash`, swapped in by id wherever htmx finds it.
const FLASH_CLEAR: &str =
    r#"<div id="dc-flash" class="dc-flash" aria-live="polite" hx-swap-oob="true"></div>"#;

/// A redirect for after a successful form post: `HX-Redirect` for htmx,
/// a 303 for a plain form.
pub fn redirect_after_post(headers: &HeaderMap, to: &'static str) -> Response {
    if is_htmx(headers) {
        // A 200 with an empty body: htmx follows `HX-Redirect` and has
        // nothing to swap.
        (StatusCode::OK, [("hx-redirect", to)]).into_response()
    } else {
        see_other(to)
    }
}

fn see_other(to: &'static str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response()
}

/// The full-page view of an error.
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    title: &'static str,
    message: &'static str,
    code: &'static str,
    status: u16,
}

/// The htmx view of an error: one banner, swapped into `#dc-flash`.
#[derive(Template)]
#[template(path = "partials/error_banner.html")]
struct ErrorBanner {
    title: &'static str,
    message: &'static str,
    code: &'static str,
}

/// A short title for an error page, by status class. The detail is in
/// [`ErrorKind::message`]; this is only the heading above it.
fn title_for(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "You're not logged in",
        StatusCode::FORBIDDEN => "That's not allowed",
        StatusCode::NOT_FOUND => "Nothing here",
        StatusCode::TOO_MANY_REQUESTS => "Slow down a little",
        status if status.is_server_error() => "Something went wrong",
        _ => "That didn't work",
    }
}

/// Re-renders every error response of a page route as HTML. See the
/// module documentation for the three shapes.
pub async fn render_errors(request: Request, next: Next) -> Response {
    let htmx = is_htmx(request.headers());
    let safe = origin::is_safe_method(request.method().as_str());

    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }

    // Built by `ApiError`, the kind travels in the extensions. Anything
    // else - an extractor's bare rejection, say - is described from its
    // status alone, the same fallback the JSON normalization uses.
    let kind = response
        .extensions()
        .get::<ErrorKind>()
        .copied()
        .unwrap_or_else(|| ApiError::from_status(status).kind());
    let retry_after = response.headers().get(header::RETRY_AFTER).cloned();

    let unauthenticated = kind == ErrorKind::Unauthenticated;
    if unauthenticated && safe && !htmx {
        return see_other(LOGIN_PATH);
    }

    let title = title_for(kind.status());
    let mut page = if htmx {
        let mut fragment = render(&ErrorBanner {
            title,
            message: kind.message(),
            code: kind.code(),
        });
        let headers = fragment.headers_mut();
        headers.insert("hx-retarget", HeaderValue::from_static("#dc-flash"));
        headers.insert("hx-reswap", HeaderValue::from_static("innerHTML"));
        if unauthenticated {
            headers.insert("hx-redirect", HeaderValue::from_static(LOGIN_PATH));
        }
        fragment
    } else {
        render(&ErrorPage {
            title,
            message: kind.message(),
            code: kind.code(),
            status: kind.status().as_u16(),
        })
    };

    *page.status_mut() = kind.status();
    if let Some(value) = retry_after {
        page.headers_mut().insert(header::RETRY_AFTER, value);
    }
    // Already in its final shape, so the JSON normalization further out
    // must leave it alone.
    page.extensions_mut().insert(Deliberate);
    page.extensions_mut().insert(kind);
    page
}

/// What the app layout needs on every signed-in page.
pub struct Shell {
    /// Shown in the sidebar, to the account itself. Never logged.
    pub username: String,
    /// Put into `hx-headers` on `<body>`, which is how htmx sends it.
    pub csrf_token: String,
    /// Which navigation item is the current page: `overview`, `devices`,
    /// `categories`, `account`, `admin-accounts` or `admin-devices`.
    pub current: &'static str,
    /// Whether to show the admin links. Read from the account row this
    /// request resolved, like every role check; the admin routes check
    /// it again for themselves, so this decides visibility only.
    pub is_admin: bool,
}

impl Shell {
    pub fn for_session(auth: &crate::auth::extract::AuthSession, current: &'static str) -> Self {
        Self {
            username: auth.user.username.as_str().to_owned(),
            csrf_token: auth.csrf_token(),
            current,
            is_admin: auth.user.role.is_admin(),
        }
    }
}

/// `2026-10-25 17:03 UTC` - a Unix second as a UTC date and time.
///
/// Always UTC, labelled as such, whatever zone the account has set: a
/// log entry is a fact, not a day to be counted. Computed by
/// hand (the civil-from-days algorithm) rather than with a date crate,
/// since this is the only place a date is formatted.
pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let of_day = secs.rem_euclid(86_400);
    let (hour, minute) = (of_day / 3600, (of_day % 3600) / 60);

    // Howard Hinnant's days_from_civil, inverted.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting_matches_known_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_792_946_549), "2026-10-25 16:42 UTC");
        assert_eq!(format_utc(-1), "1969-12-31 23:59 UTC");
    }
}
