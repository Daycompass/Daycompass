//! The `Origin` header check for state-changing requests.
//!
//! This is defence in depth behind the CSRF token, aimed at the case
//! where a browser sends the session cookie on a request a hostile page
//! initiated. It is expressed as plain functions over strings rather
//! than as axum middleware, so the rule itself can be tested without
//! building a request.
//!
//! The rule, case by case:
//!
//! * `GET` and `HEAD` are exempt. They must not change state, so there
//!   is nothing for a forged one to accomplish. This is why an
//!   `origin_checked` entry in the route inventory still answers a
//!   foreign origin on a `GET`.
//! * A present `Origin` naming this instance is allowed. Both sides go
//!   through [`PublicUrl`]'s parser first, so an equivalent spelling
//!   matches: scheme and host are compared case-insensitively, and a
//!   port equal to the scheme's default is dropped, which makes
//!   `https://example.org:443` and `https://example.org` the same
//!   origin. The comparison is exact beyond that - no suffix matching,
//!   so `example.org.attacker.example` does not pass.
//! * A present `Origin` that names anything else is rejected, and so is
//!   one that does not parse as an origin at all. `null` is the case
//!   worth naming: a browser sends it for an opaque origin - a
//!   sandboxed iframe, a `data:` or `file:` document, some redirect
//!   chains - and it must not be treated as "no origin", because that
//!   is a value a hostile page *can* arrange. It parses as nothing, so
//!   it fails the comparison.
//! * **More than one** `Origin` header is rejected, as is a header
//!   whose bytes are not text. No browser sends either, and choosing
//!   one of several values would be a way to smuggle the wrong answer
//!   past this check. That part is in `crate::routes::access`, where
//!   the header list is still available; by the time a value reaches
//!   this module there is exactly one.
//! * An **absent** `Origin` is allowed, on every checked route. Non-
//!   browser clients - a sync client, curl, a script - send none, and
//!   refusing them would mean the API only worked from a browser. A
//!   browser always sends `Origin` on a cross-site state-changing
//!   request, so its absence is not something a hostile page can
//!   arrange.
//!
//! Allowing an absent header is only safe because it is not the only
//! check: every cookie-authenticated request independently requires a
//! valid CSRF token, which a hostile page cannot read.
//!
//! Login is the route where that permissiveness is load-bearing, and it
//! is worth being precise about what it does and does not cost. A
//! command line client logging in sends no `Origin` and is allowed. A
//! hostile page trying to log a victim into an attacker-controlled
//! account - login CSRF - cannot do the same: its request is cross-site,
//! so the browser attaches an `Origin`, which is then rejected. The
//! permissive case admits only callers that are not browsers, which are
//! the ones with no ambient cookie to abuse in the first place.
//!
//! Setup is the one state-changing endpoint exempt from this check
//! altogether. It carries no cookie, so there is no ambient credential
//! for a hostile page to ride on, and its protection is the unguessable
//! setup token. Which routes are checked is not decided here: it is the
//! `origin_checked` column of [`crate::routes::INVENTORY`].

use crate::config::PublicUrl;

/// True for methods that must not change state.
pub fn is_safe_method(method: &str) -> bool {
    // HEAD counts as safe: it is GET without a body, and axum derives it
    // from GET routes automatically.
    matches!(method, "GET" | "HEAD")
}

/// Whether a request with this method and `Origin` may proceed.
///
/// `origin` is `None` when the header is absent, and `Some` with the
/// exact header value when it is present.
pub fn is_allowed(method: &str, origin: Option<&str>, public_url: &PublicUrl) -> bool {
    if is_safe_method(method) {
        return true;
    }
    match origin {
        Some(value) => public_url.matches_origin_header(value),
        None => true,
    }
}

/// Like [`is_allowed`], but an **absent** `Origin` is refused too.
///
/// For the dashboard's own form posts (`OriginRule::Required` in
/// [`crate::routes::INVENTORY`]). The absent case is allowed above only
/// because native clients send no `Origin`; a dashboard route has no
/// such caller - only browsers, which always send one on a
/// state-changing request - so the exemption buys nothing there and is
/// dropped. That makes login CSRF impossible on these routes even for
/// a browser that, unlike every current one, left the header out.
pub fn is_allowed_requiring_presence(
    method: &str,
    origin: Option<&str>,
    public_url: &PublicUrl,
) -> bool {
    if is_safe_method(method) {
        return true;
    }
    origin.is_some_and(|value| public_url.matches_origin_header(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// The default configuration's origin, so the test does not have to
    /// construct one through a private constructor.
    fn public_url() -> PublicUrl {
        Config::defaults().public_url
    }

    #[test]
    fn safe_methods_are_exempt() {
        assert!(is_safe_method("GET"));
        assert!(is_safe_method("HEAD"));
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"] {
            assert!(!is_safe_method(method), "{method} must not be safe");
        }
    }

    /// A GET is allowed whatever its Origin says, because it changes
    /// nothing.
    #[test]
    fn a_safe_method_is_allowed_from_any_origin() {
        let url = public_url();
        for method in ["GET", "HEAD"] {
            assert!(is_allowed(method, None, &url));
            assert!(is_allowed(method, Some("https://attacker.example"), &url));
            assert!(is_allowed(method, Some("null"), &url));
        }
    }

    #[test]
    fn the_strict_rule_refuses_an_absent_origin_and_nothing_else_changes() {
        let url = public_url();
        assert!(!is_allowed_requiring_presence("POST", None, &url));
        assert!(is_allowed_requiring_presence(
            "POST",
            Some("http://127.0.0.1:8080"),
            &url
        ));
        for origin in ["https://attacker.example", "null"] {
            assert!(!is_allowed_requiring_presence("POST", Some(origin), &url));
        }
        // A GET is still exempt: it changes nothing.
        assert!(is_allowed_requiring_presence("GET", None, &url));
    }

    #[test]
    fn a_matching_origin_is_allowed() {
        let url = public_url();
        assert!(is_allowed("POST", Some("http://127.0.0.1:8080"), &url));
    }

    #[test]
    fn a_mismatched_origin_is_rejected() {
        let url = public_url();
        for origin in [
            "https://attacker.example",
            "http://127.0.0.1:9999",  // right host, wrong port
            "https://127.0.0.1:8080", // right authority, wrong scheme
            "http://127.0.0.2:8080",  // one digit off
            "null",                   // an opaque origin, e.g. a sandboxed frame
            "",
            "not a url",
        ] {
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                assert!(
                    !is_allowed(method, Some(origin), &url),
                    "{method} from {origin:?} must be rejected"
                );
            }
        }
    }

    /// Non-browser clients send no Origin and must still be able to log
    /// in. The CSRF token is what protects cookie-authenticated requests
    /// in this case.
    #[test]
    fn an_absent_origin_is_allowed_for_a_state_changing_request() {
        assert!(is_allowed("POST", None, &public_url()));
    }
}
