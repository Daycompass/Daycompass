//! The session cookie, built and parsed by hand.
//!
//! Hand-rolled on purpose. There is exactly one cookie, its attributes
//! never vary, and writing the `Set-Cookie` value here means the exact
//! string is something a test can assert and a reviewer can read -
//! rather than the output of a builder whose defaults could change.
//!
//! The name uses the `__Host-` prefix, which a browser only accepts when
//! the cookie is `Secure`, has `Path=/`, and carries no `Domain`. That
//! makes it host-only: a sibling or parent domain cannot set or shadow
//! it, which is the attack a bare cookie name is open to. It also means
//! browsers will not store it over plain HTTP at all - inherent to the
//! prefix, and the reason local development needs TLS to exercise the
//! cookie path through a real browser.

/// Cookie holding the session token.
pub const COOKIE_NAME: &str = "__Host-dcs";

/// Attributes shared by setting and clearing the cookie.
///
/// `SameSite=Strict` means the browser does not send it on any
/// cross-site request, which is a second line of defence behind the
/// CSRF token rather than a replacement for it.
const ATTRIBUTES: &str = "Path=/; HttpOnly; Secure; SameSite=Strict";

/// The `Set-Cookie` value that stores `token`.
///
/// No `Max-Age` and no `Expires`: the server decides when a session ends
/// and enforces it on every request, so a client-side lifetime would
/// only ever be a second, weaker opinion about the same thing.
pub fn set(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; {ATTRIBUTES}")
}

/// The `Set-Cookie` value that clears the cookie.
///
/// `Max-Age=0` is the one place an age appears, because expiring the
/// cookie in the past is how a cookie is deleted.
pub fn clear() -> String {
    format!("{COOKIE_NAME}=; {ATTRIBUTES}; Max-Age=0")
}

/// Reads the session token out of the values of every `Cookie` header on
/// a request.
///
/// Returns `None` when the cookie appears more than once. A legitimate
/// client sends it once, and the `__Host-` prefix already stops another
/// host from adding a second copy, so a duplicate means something is
/// wrong; picking one of two candidate tokens is exactly the ambiguity a
/// cookie-shadowing attack wants. Failing closed costs at most a
/// re-login.
pub fn read<'a>(headers: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut found = None;

    for header in headers {
        for pair in header.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() != COOKIE_NAME {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value.trim());
        }
    }

    // An empty value is what `clear()` leaves behind; treat it as absent
    // rather than as a token that will never match anything.
    found.filter(|value| !value.is_empty())
}

/// Whether the session cookie appears on the request at all.
///
/// Used by the access layer to refuse a session cookie on a device
/// route. Deliberately not expressed as `read(..).is_some()`: `read`
/// returns `None` for a *duplicated* cookie, which would make two
/// copies of the cookie a way to slip past that refusal. A request
/// carrying this cookie should be refused by a device route whether or
/// not the value is usable.
///
/// It is also deliberately specific to this one cookie. A reverse
/// proxy or CDN that attaches cookies of its own must not break device
/// authentication, so "any cookie at all" would be the wrong rule.
pub fn is_present<'a>(headers: impl Iterator<Item = &'a str>) -> bool {
    headers.flat_map(|header| header.split(';')).any(|pair| {
        pair.split_once('=')
            .is_some_and(|(name, _)| name.trim() == COOKIE_NAME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attribute set is specified exactly, so it is asserted
    /// exactly. A silent change here would weaken every session.
    #[test]
    fn the_set_cookie_value_has_exactly_the_specified_attributes() {
        let value = set("dcs_token-placeholder");
        assert_eq!(
            value,
            "__Host-dcs=dcs_token-placeholder; Path=/; HttpOnly; Secure; SameSite=Strict"
        );

        // Spelled out individually too, so a failure says which
        // attribute went missing.
        assert!(value.starts_with("__Host-dcs="));
        assert!(value.contains("; Path=/"));
        assert!(value.contains("; HttpOnly"));
        assert!(value.contains("; Secure"));
        assert!(value.contains("; SameSite=Strict"));
        // A Domain attribute would break the __Host- prefix, and a
        // client-side lifetime is deliberately absent.
        assert!(!value.contains("Domain"));
        assert!(!value.contains("Max-Age"));
        assert!(!value.contains("Expires"));
    }

    #[test]
    fn clearing_expires_the_cookie_immediately() {
        let value = clear();
        assert_eq!(
            value,
            "__Host-dcs=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
        );
        // Same attributes as when set, or the browser would treat it as
        // a different cookie and leave the original in place.
        assert!(value.contains("; Path=/"));
        assert!(value.contains("; Secure"));
        assert!(!value.contains("Domain"));
    }

    #[test]
    fn reads_the_token_from_a_cookie_header() {
        assert_eq!(
            read(["__Host-dcs=abc".to_owned()].iter().map(String::as_str)),
            Some("abc")
        );
    }

    #[test]
    fn reads_the_token_alongside_other_cookies() {
        let header = "theme=dark; __Host-dcs=abc; locale=en";
        assert_eq!(read([header].into_iter()), Some("abc"));

        // Including when split across several headers, as HTTP/2 allows.
        assert_eq!(
            read(["theme=dark", "__Host-dcs=abc"].into_iter()),
            Some("abc")
        );
    }

    #[test]
    fn tolerates_whitespace_around_the_pair() {
        assert_eq!(read(["  __Host-dcs = abc  "].into_iter()), Some("abc"));
    }

    #[test]
    fn a_missing_or_empty_cookie_reads_as_absent() {
        for header in [
            "",
            "theme=dark",
            "__Host-dcs=",
            "dcs=abc",         // a different cookie name
            "__Host-dcsx=abc", // a name that merely starts the same
            "x__Host-dcs=abc", // and one that merely ends the same
            "__Host-dcs",      // no value at all
        ] {
            assert_eq!(read([header].into_iter()), None, "{header:?}");
        }
    }

    /// Two cookies of the same name leave no single right answer, so the
    /// request is treated as unauthenticated instead of guessing.
    #[test]
    fn a_duplicated_cookie_reads_as_absent() {
        assert_eq!(
            read(["__Host-dcs=first; __Host-dcs=second"].into_iter()),
            None
        );
        assert_eq!(
            read(["__Host-dcs=first", "__Host-dcs=second"].into_iter()),
            None
        );
    }

    /// The presence check is what a device route refuses on, so it has
    /// to see the cases `read` deliberately turns into `None`.
    #[test]
    fn presence_notices_a_cookie_read_refuses_to_use() {
        // A duplicate is unusable, but it is still present. Without
        // this, sending the cookie twice would slip past a device
        // route's refusal.
        assert_eq!(read(["__Host-dcs=a", "__Host-dcs=b"].into_iter()), None);
        assert!(is_present(["__Host-dcs=a", "__Host-dcs=b"].into_iter()));

        // So is a cleared one, which has an empty value.
        assert_eq!(read(["__Host-dcs="].into_iter()), None);
        assert!(is_present(["__Host-dcs="].into_iter()));

        assert!(is_present(["__Host-dcs=abc"].into_iter()));
        assert!(is_present(["other=1; __Host-dcs=abc; third=2"].into_iter()));
    }

    /// Only this cookie counts. A proxy or CDN attaching its own
    /// cookies must not be read as a Daycompass session.
    #[test]
    fn presence_ignores_every_other_cookie() {
        assert!(!is_present([].into_iter()));
        assert!(!is_present([""].into_iter()));
        assert!(!is_present(["cf_bm=abc; _ga=1; sessionid=2"].into_iter()));
        assert!(!is_present(["__Host-dcs_other=abc"].into_iter()));
        assert!(!is_present(["x__Host-dcs=abc"].into_iter()));
        // A bare name with no "=" is not a cookie pair.
        assert!(!is_present(["__Host-dcs"].into_iter()));
    }
}
