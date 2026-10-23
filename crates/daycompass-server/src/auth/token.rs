//! Opaque bearer tokens: the session token that lives in the cookie, and
//! the one-shot token that creates the first admin.
//!
//! Wire format is a four-character prefix naming the kind, followed by 32
//! bytes of operating-system randomness encoded as base64url without
//! padding - always exactly 43 characters. 256 bits of entropy means a
//! token is not guessable and needs no rate limiting of its own.
//!
//! Only the SHA-256 of the *full* token string is ever stored, prefix
//! included. Covering the prefix means a setup token can never be
//! replayed as a session token even if two random bodies ever collided.
//! Looking a token up by its hash is fine - that is an index lookup on a
//! value derived from the secret, not a comparison of the secret - but
//! two tokens or two hashes are never compared with `==`; see
//! [`TokenHash::ct_eq`].

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::secret::SecretString;

/// Random bytes behind every token.
const TOKEN_BYTES: usize = 32;

/// 32 bytes as base64url without padding is always this long.
pub const TOKEN_BODY_CHARS: usize = 43;

/// Length of a SHA-256 digest.
pub const HASH_BYTES: usize = 32;

/// What a token is for. The prefix is part of the token and part of what
/// gets hashed, so kinds are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Session token, carried in the `__Host-dcs` cookie.
    Session,
    /// Bootstrap token that redeems once to create the first admin.
    Setup,
    /// Device token, carried in an `Authorization: Bearer` header by a
    /// paired client. Never in a cookie, and never accepted on a route
    /// that authenticates by session - the distinct prefix below is
    /// what makes that structural rather than a matter of discipline,
    /// since the prefix is part of what gets hashed.
    Device,
    /// One-time invite token that redeems to set a pending account's
    /// first password. Like the setup token, never in a cookie.
    Invite,
}

impl TokenKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Session => "dcs_",
            Self::Setup => "dcb_",
            Self::Device => "dcd_",
            Self::Invite => "dci_",
        }
    }
}

/// The OS random number generator refused to produce bytes. Treated as
/// fatal by callers: without randomness no token may be issued.
#[derive(Debug, thiserror::Error)]
#[error("the operating system random number generator is unavailable")]
pub struct RngUnavailable;

/// A freshly minted token. The plaintext exists here, in the response
/// that hands it to the client, and nowhere else on the server.
pub struct Token {
    kind: TokenKind,
    value: SecretString,
}

impl Token {
    /// Draws 32 fresh bytes from the OS CSPRNG and encodes them.
    pub fn generate(kind: TokenKind) -> Result<Self, RngUnavailable> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RngUnavailable)?;
        let mut body = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();

        let value = format!("{}{}", kind.prefix(), body);
        body.zeroize();

        Ok(Self {
            kind,
            value: SecretString::new(value),
        })
    }

    pub fn kind(&self) -> TokenKind {
        self.kind
    }

    /// The full token string, to be handed to the client exactly once.
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// What gets stored.
    pub fn hash(&self) -> TokenHash {
        TokenHash::digest(self.value.expose())
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value is a SecretString, which redacts itself; spelled out
        // here so adding a field later is a deliberate decision.
        f.debug_struct("Token")
            .field("kind", &self.kind)
            .field("value", &self.value)
            .finish()
    }
}

/// SHA-256 of a full token string. This is the only representation that
/// touches the database.
#[derive(Clone)]
pub struct TokenHash([u8; HASH_BYTES]);

impl TokenHash {
    fn digest(value: &str) -> Self {
        let mut out = [0u8; HASH_BYTES];
        out.copy_from_slice(&Sha256::digest(value.as_bytes()));
        Self(out)
    }

    /// Hashes a token a client presented, but only after checking it has
    /// the exact shape of `kind`: right prefix, exactly 43 body
    /// characters, and a canonical base64url encoding of 32 bytes.
    ///
    /// Returns `None` for anything malformed, so arbitrary client input
    /// never becomes a database lookup. The shape of a token is public
    /// information, so rejecting early leaks nothing.
    pub fn of_presented(kind: TokenKind, presented: &str) -> Option<Self> {
        let body = presented.strip_prefix(kind.prefix())?;
        if body.len() != TOKEN_BODY_CHARS {
            return None;
        }
        // Decoding rejects non-canonical trailing bits, so exactly one
        // string maps to any given 32-byte value. Without that check two
        // different strings could hash to two different rows for what is
        // really the same token.
        let decoded = URL_SAFE_NO_PAD.decode(body).ok()?;
        if decoded.len() != TOKEN_BYTES {
            return None;
        }
        Some(Self::digest(presented))
    }

    /// Rebuilds a hash read back from the database.
    pub fn from_stored(bytes: &[u8]) -> Option<Self> {
        let array: [u8; HASH_BYTES] = bytes.try_into().ok()?;
        Some(Self(array))
    }

    /// For binding into a query. Not secret: a SHA-256 digest of a
    /// 256-bit random value cannot be inverted, and presenting the hash
    /// does not authenticate anything - the API only ever accepts the
    /// preimage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time comparison. Used wherever two hashes are checked
    /// against each other rather than looked up, so the comparison
    /// cannot be turned into a byte-at-a-time oracle.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not a credential, but printing it would still let log readers
        // correlate sessions, so it stays out of logs.
        f.write_str("TokenHash([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_KIND: [TokenKind; 4] = [
        TokenKind::Session,
        TokenKind::Setup,
        TokenKind::Device,
        TokenKind::Invite,
    ];

    #[test]
    fn generated_tokens_have_the_documented_shape() {
        for kind in EVERY_KIND {
            let token = Token::generate(kind).expect("the OS CSPRNG must be available");
            let value = token.expose();
            assert_eq!(token.kind(), kind);
            assert!(value.starts_with(kind.prefix()));
            assert_eq!(value.len(), kind.prefix().len() + TOKEN_BODY_CHARS);
            let body = &value[kind.prefix().len()..];
            assert!(
                body.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "the body must be base64url without padding"
            );
        }
    }

    /// Distinct prefixes are the whole mechanism keeping one kind of
    /// token from being accepted as another, so every pair is checked
    /// rather than just the two that happen to be adjacent.
    #[test]
    fn every_kind_uses_a_distinct_prefix() {
        for (index, first) in EVERY_KIND.iter().enumerate() {
            for second in &EVERY_KIND[index + 1..] {
                assert_ne!(
                    first.prefix(),
                    second.prefix(),
                    "{first:?} and {second:?} share a prefix"
                );
            }
        }
        // A CSRF prefix used to exist here. CSRF tokens are now derived
        // from the session token instead of generated, so there is no
        // kind for them.
        assert_eq!(EVERY_KIND.len(), 4);
    }

    /// The pairwise sweep of what `a_token_is_not_accepted_as_the_other
    /// _kind` checks for one pair: no kind's token may be read as any
    /// other kind's. A device token presented as a session token is the
    /// case that matters most, and it fails here before any lookup.
    #[test]
    fn no_token_is_accepted_as_a_different_kind() {
        for issued in EVERY_KIND {
            let token = Token::generate(issued).expect("the OS CSPRNG must be available");
            for presented_as in EVERY_KIND {
                let accepted = TokenHash::of_presented(presented_as, token.expose()).is_some();
                assert_eq!(
                    accepted,
                    issued == presented_as,
                    "a {issued:?} token read as {presented_as:?}"
                );
            }
        }
    }

    #[test]
    fn two_generated_tokens_differ() {
        let first = Token::generate(TokenKind::Session).unwrap();
        let second = Token::generate(TokenKind::Session).unwrap();
        assert_ne!(first.expose(), second.expose());
        assert!(!first.hash().ct_eq(&second.hash()));
    }

    #[test]
    fn hashing_is_stable_and_matches_a_presented_token() {
        let token = Token::generate(TokenKind::Session).unwrap();
        assert!(token.hash().ct_eq(&token.hash()));

        let presented = TokenHash::of_presented(TokenKind::Session, token.expose())
            .expect("a freshly generated token must be well formed");
        assert!(token.hash().ct_eq(&presented));
    }

    #[test]
    fn the_prefix_is_part_of_the_hash() {
        // Same 43-character body under two prefixes must hash
        // differently, which is what stops a setup token being replayed
        // as a session token.
        let token = Token::generate(TokenKind::Session).unwrap();
        let body = &token.expose()[TokenKind::Session.prefix().len()..];

        let as_session = TokenHash::of_presented(
            TokenKind::Session,
            &format!("{}{body}", TokenKind::Session.prefix()),
        )
        .expect("well formed");
        let as_setup = TokenHash::of_presented(
            TokenKind::Setup,
            &format!("{}{body}", TokenKind::Setup.prefix()),
        )
        .expect("well formed");

        assert!(!as_session.ct_eq(&as_setup));
    }

    #[test]
    fn a_token_is_not_accepted_as_the_other_kind() {
        let session = Token::generate(TokenKind::Session).unwrap();
        assert!(TokenHash::of_presented(TokenKind::Setup, session.expose()).is_none());

        let setup = Token::generate(TokenKind::Setup).unwrap();
        assert!(TokenHash::of_presented(TokenKind::Session, setup.expose()).is_none());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let token = Token::generate(TokenKind::Session).unwrap();
        let value = token.expose();
        let prefix = TokenKind::Session.prefix();
        let body = &value[prefix.len()..];

        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("prefix only", prefix.to_owned()),
            ("body without a prefix", body.to_owned()),
            ("one character short", format!("{prefix}{}", &body[..42])),
            ("one character too long", format!("{prefix}{body}A")),
            ("uppercase prefix", format!("SWS_{body}")),
            (
                "character outside the alphabet",
                format!("{prefix}{}.{}", &body[..20], &body[21..]),
            ),
            ("padding added", format!("{prefix}{}=", &body[..42])),
            ("leading whitespace", format!(" {value}")),
            ("trailing whitespace", format!("{value} ")),
        ];

        for (label, candidate) in cases {
            assert!(
                TokenHash::of_presented(TokenKind::Session, &candidate).is_none(),
                "{label} must be rejected"
            );
        }
    }

    /// 43 base64url characters carry 258 bits, but a token is 256 bits,
    /// so the final character has two unused bits that must be zero. A
    /// character whose alphabet index is not a multiple of four sets
    /// them, and must be rejected - otherwise several distinct strings
    /// would decode to the same token yet hash differently.
    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        let token = Token::generate(TokenKind::Session).unwrap();
        let prefix = TokenKind::Session.prefix();
        let body = &token.expose()[prefix.len()..];

        // 'B' is alphabet index 1, so its low two bits are not zero.
        let tampered = format!("{prefix}{}B", &body[..TOKEN_BODY_CHARS - 1]);
        assert!(TokenHash::of_presented(TokenKind::Session, &tampered).is_none());

        // 'A' is index 0 and therefore canonical: the same construction
        // with a valid final character is accepted, which proves the
        // rejection above is about the trailing bits and not the splice.
        let canonical = format!("{prefix}{}A", &body[..TOKEN_BODY_CHARS - 1]);
        assert!(TokenHash::of_presented(TokenKind::Session, &canonical).is_some());
    }

    #[test]
    fn from_stored_accepts_only_full_length_digests() {
        let token = Token::generate(TokenKind::Session).unwrap();
        let hash = token.hash();

        let restored = TokenHash::from_stored(hash.as_bytes()).expect("round trip must work");
        assert!(restored.ct_eq(&hash));

        assert!(TokenHash::from_stored(&[]).is_none());
        assert!(TokenHash::from_stored(&[0u8; HASH_BYTES - 1]).is_none());
        assert!(TokenHash::from_stored(&[0u8; HASH_BYTES + 1]).is_none());
    }

    #[test]
    fn debug_output_leaks_neither_the_token_nor_the_hash() {
        let token = Token::generate(TokenKind::Session).unwrap();
        let value = token.expose().to_owned();
        let body = value[TokenKind::Session.prefix().len()..].to_owned();

        let token_debug = format!("{token:?}");
        assert!(!token_debug.contains(&body), "Debug must not leak the body");
        assert!(token_debug.contains("[redacted]"));
        assert!(token_debug.contains("Session"), "the kind is safe to show");

        let hash_debug = format!("{:?}", token.hash());
        assert_eq!(hash_debug, "TokenHash([redacted])");
    }

    #[test]
    fn hash_bytes_are_a_full_sha256_digest() {
        let token = Token::generate(TokenKind::Setup).unwrap();
        assert_eq!(token.hash().as_bytes().len(), HASH_BYTES);
    }
}
