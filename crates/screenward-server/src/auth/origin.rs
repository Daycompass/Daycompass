//! The `Origin` header check for state-changing requests.
//!
//! This is defence in depth behind the CSRF token, aimed at the case
//! where a browser sends the session cookie on a request a hostile page
//! initiated. It is expressed as plain functions over strings rather
//! than as axum middleware, so the rule itself can be tested without
//! building a request.
//!
//! The rule:
//!
//! * `GET` and `HEAD` are exempt. They must not change state, so there
//!   is nothing for a forged one to accomplish.
//! * A present `Origin` that does not name this instance is rejected.
//! * An **absent** `Origin` is allowed. Non-browser clients - a sync
//!   client, curl, a script - send none, and refusing them would mean
//!   the API only worked from a browser. A browser, by contrast, always
//!   sends `Origin` on a cross-site state-changing request, so its
//!   absence is not something a hostile page can arrange.
//!
//! Allowing an absent header is only safe because it is not the only
//! check: every cookie-authenticated request independently requires a
//! valid CSRF token, which a hostile page cannot read. Setup is the one
//! state-changing endpoint with no cookie, and it is protected by the
//! unguessable setup token instead.

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
