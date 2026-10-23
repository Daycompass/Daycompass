//! Per-session CSRF tokens, derived rather than stored.
//!
//! The CSRF token is `SHA-256(domain prefix || session token)`, encoded
//! as base64url without padding. Nothing about it is persisted, which
//! has one property that matters in practice: it survives a page reload
//! and is identical in every tab, because any tab holding the cookie can
//! re-derive it - and `GET /api/v1/auth/me` hands it back on request.
//!
//! The direction that matters is safe. Holding the CSRF token does not
//! yield the session token, because SHA-256 cannot be inverted; the
//! reverse is intentional. A hostile page cannot read either one: it can
//! make the browser *send* the cookie, but it cannot read a response
//! body from another origin, which is what it would need to learn the
//! CSRF token.
//!
//! The trade-off, stated plainly: a derived token cannot be rotated
//! independently of the session. With a stored hash, a leaked CSRF token
//! could be invalidated on its own; here the only remedy is to log out,
//! which replaces the session token the value derives from.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain separation, so this hash can never collide with the SHA-256 of
/// a token computed for any other purpose - in particular the session
/// token's own stored hash. Fixed length, so `prefix || token` has only
/// one possible reading. The version suffix leaves room to change the
/// derivation later without silently accepting old values.
///
/// Renamed from `screenward.csrf.v1` for the Screenward -> Screenwarden ->
/// Daycompass rename: pre-release, with no deployed instance and no live
/// session anywhere, so there was no CSRF token this change could
/// invalidate. That reasoning is specific to this moment - once an
/// instance exists with live sessions, changing these bytes invalidates
/// every one of them until the client re-reads `GET /api/v1/auth/me`,
/// and at that point the right call is almost certainly to leave this
/// constant alone rather than track the brand name again.
const DOMAIN_PREFIX: &[u8] = b"daycompass.csrf.v1\0";

/// Derives the CSRF token belonging to `session_token`.
pub fn derive(session_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PREFIX);
    hasher.update(session_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Checks a presented CSRF token against the one `session_token`
/// derives to.
///
/// The comparison is constant time, so it cannot be turned into a
/// byte-at-a-time oracle for guessing the expected value. Differing
/// lengths short-circuit, which leaks only the length - public
/// information, since the derivation always produces 43 characters.
pub fn verify(session_token: &str, presented: &str) -> bool {
    let expected = derive(session_token);
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::{Token, TokenKind};

    fn session_token() -> Token {
        Token::generate(TokenKind::Session).expect("the OS CSPRNG must be available")
    }

    #[test]
    fn derivation_is_deterministic() {
        let token = session_token();
        assert_eq!(derive(token.expose()), derive(token.expose()));
    }

    /// The property that makes a reload and a second tab work: nothing
    /// is stored, so the same cookie always yields the same value.
    #[test]
    fn the_same_session_always_derives_the_same_token() {
        let token = session_token();
        let from_first_tab = derive(token.expose());
        let from_second_tab = derive(token.expose());
        let after_a_reload = derive(token.expose());

        assert_eq!(from_first_tab, from_second_tab);
        assert_eq!(from_first_tab, after_a_reload);
        assert!(verify(token.expose(), &from_second_tab));
    }

    #[test]
    fn different_sessions_derive_different_tokens() {
        let first = session_token();
        let second = session_token();
        assert_ne!(derive(first.expose()), derive(second.expose()));
        assert!(!verify(first.expose(), &derive(second.expose())));
    }

    #[test]
    fn the_derived_token_has_the_expected_shape() {
        let derived = derive(session_token().expose());
        // 32 bytes as base64url without padding.
        assert_eq!(derived.len(), 43);
        assert!(derived
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(
            !derived.starts_with("dc"),
            "the derived token carries no token prefix"
        );
    }

    /// Preimage resistance is what keeps the weaker secret from
    /// revealing the stronger one.
    #[test]
    fn the_session_token_cannot_be_read_out_of_the_csrf_token() {
        let token = session_token();
        let derived = derive(token.expose());
        let body = &token.expose()[4..];

        assert!(!derived.contains(body));
        assert_ne!(derived, body);
    }

    /// Domain separation: the CSRF value must differ from the hash
    /// stored for the session itself, or one could stand in for the
    /// other.
    #[test]
    fn the_csrf_token_differs_from_the_stored_session_hash() {
        let token = session_token();
        let stored = URL_SAFE_NO_PAD.encode(token.hash().as_bytes());
        assert_ne!(derive(token.expose()), stored);
    }

    #[test]
    fn verification_rejects_anything_but_the_exact_token() {
        let token = session_token();
        let expected = derive(token.expose());

        assert!(verify(token.expose(), &expected));

        let mut truncated = expected.clone();
        truncated.pop();
        let mut extended = expected.clone();
        extended.push('A');

        // Flip the first character to something else in the alphabet.
        let mut tampered = expected.clone();
        let replacement = if expected.starts_with('A') { 'B' } else { 'A' };
        tampered.replace_range(0..1, &replacement.to_string());

        for candidate in [
            String::new(),
            truncated,
            extended,
            tampered,
            derive(session_token().expose()),
            expected.to_ascii_uppercase(),
            format!(" {expected}"),
            format!("{expected} "),
        ] {
            assert!(
                !verify(token.expose(), &candidate),
                "{candidate:?} must not verify"
            );
        }
    }
}
