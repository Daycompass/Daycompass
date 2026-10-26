//! Pairing links: a pairing code together with the server it belongs
//! to, as one URI a client can read from a QR code.
//!
//! ```text
//! daycompass://pair?v=1&server=https%3A%2F%2Fexample.com&code=4K7M9QRT2V
//! ```
//!
//! A typed code only works because the person also types the server
//! address into the app. A scanned code carries both, so the link names
//! the server explicitly: the configured public URL, the same origin the
//! dashboard is served from and the `Origin` check compares against.
//!
//! The link holds nothing the code shown next to it does not: the same
//! secret, the same lifetime, single use. It is built in the one
//! response that shows the code and is never stored.
//!
//! # Why a custom scheme
//!
//! A phone's camera app hands a `daycompass://` link to the installed
//! client, and a scanner inside the client reads it just as well. An
//! `https://` link would open a browser instead, and would put the code
//! into a URL that browsers log, sync and send as a `Referer`.
//!
//! # What a client must do with it
//!
//! The server address comes from whoever printed the QR code, so a
//! client shows it to the person and pairs only once they confirm it -
//! otherwise anyone who can put a QR code in front of a student can
//! point their device at a server of their choosing. `docs/wire-format.md`
//! states this as part of the format.

use crate::auth::secret::SecretString;
use crate::devices::code::PairingCode;

/// The scheme and path every pairing link starts with.
pub const PREFIX: &str = "daycompass://pair";

/// The link format's version, the `v` parameter. A client refuses a
/// version it does not know rather than guessing at its fields.
pub const VERSION: u32 = 1;

/// The link for `code` on the server reachable at `public_url`.
///
/// `public_url` is the validated origin from the configuration, so it
/// has no path, query or userinfo; it is still percent-encoded, because
/// it travels as a query value. The code is the canonical form, without
/// the display dash: shorter, which keeps the QR code coarse.
pub fn pairing_uri(public_url: &str, code: &PairingCode) -> SecretString {
    SecretString::new(format!(
        "{PREFIX}?v={VERSION}&server={}&code={}",
        percent_encode(public_url),
        code.expose(),
    ))
}

/// Encodes everything but RFC 3986's unreserved characters. Stricter
/// than a query value needs, so a client's decoder never has to guess.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_carries_the_version_the_server_and_the_canonical_code() {
        let code = PairingCode::generate().unwrap();
        let uri = pairing_uri("https://example.com", &code);

        assert_eq!(
            uri.expose(),
            format!(
                "daycompass://pair?v=1&server=https%3A%2F%2Fexample.com&code={}",
                code.expose()
            )
        );
    }

    #[test]
    fn a_port_and_an_ipv6_host_are_encoded() {
        assert_eq!(
            percent_encode("http://192.0.2.10:8080"),
            "http%3A%2F%2F192.0.2.10%3A8080"
        );
        assert_eq!(
            percent_encode("http://[2001:db8::1]:8080"),
            "http%3A%2F%2F%5B2001%3Adb8%3A%3A1%5D%3A8080"
        );
    }

    #[test]
    fn the_code_in_a_link_redeems_like_the_typed_one() {
        let code = PairingCode::generate().unwrap();
        let uri = pairing_uri("https://example.com", &code);
        let presented = uri.expose().rsplit_once("code=").unwrap().1;

        assert_eq!(
            PairingCode::hash_presented(presented).unwrap().as_bytes(),
            code.hash().as_bytes()
        );
    }
}
