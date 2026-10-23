//! Pairing codes: the short secret a person types into a new device.
//!
//! Unlike every other secret in this codebase, this one is read off a
//! screen and typed on a phone keyboard, so it is deliberately short.
//! Ten characters from a 32-character alphabet is about 50 bits, which
//! is the whole design constraint - everything below follows from it.
//!
//! # Why 50 bits is enough here, when 256 is the rule elsewhere
//!
//! Online guessing is bounded by the per-address and global rate limits
//! on the pairing endpoint; against 2^50 possibilities those limits make
//! guessing hopeless by many orders of magnitude.
//!
//! Offline guessing against a stolen database is the case worth being
//! precise about. Only hashes are stored, and SHA-256 of a 50-bit value
//! *is* brute-forceable on a GPU in hours. What makes that worthless is
//! the lifetime: a code is dead ten minutes after it is created, and a
//! spent or expired hash buys an attacker nothing. The window in which
//! a leaked hash is worth cracking is the window in which it is still
//! redeemable, and that is shorter than the crack.
//!
//! This is why the expiry is not a convenience feature and must not be
//! relaxed without revisiting the length.
//!
//! # The alphabet
//!
//! Crockford's base32: the digits and the uppercase letters, minus `I`,
//! `L`, `O` and `U`. The first three are dropped because they are
//! visually confusable with `1` and `0`; `U` is dropped so the encoding
//! cannot accidentally spell a short obscenity.
//!
//! Because those four characters are never *generated*, folding them on
//! input costs no entropy at all: [`PairingCode::canonical`] maps `I`
//! and `L` onto `1` and `O` onto `0`, so somebody reading `1` as `l`
//! still pairs their device. Case is folded and dashes and whitespace
//! are stripped for the same reason.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::auth::secret::SecretString;
use crate::auth::token::{RngUnavailable, HASH_BYTES};

/// The generation alphabet. Exactly 32 characters, which is what makes
/// the rejection sampling below exact.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many characters a code has.
pub const CODE_CHARS: usize = 10;

/// Where the display dash goes: `XXXXX-XXXXX`.
const GROUP: usize = 5;

/// A freshly generated pairing code.
///
/// The plaintext exists here and in the one response that shows it to
/// the person pairing a device. Only [`PairingCodeHash`] is stored.
pub struct PairingCode {
    /// Canonical form: uppercase, no dashes.
    value: SecretString,
}

impl PairingCode {
    /// Draws a code from the OS CSPRNG.
    ///
    /// Each character is one uniformly random alphabet index. The
    /// alphabet is exactly 32 long, so masking a byte with `0x1f` is
    /// already uniform - there is no modulo bias to reject, which is
    /// why this needs no sampling loop.
    pub fn generate() -> Result<Self, RngUnavailable> {
        let mut bytes = [0u8; CODE_CHARS];
        getrandom::fill(&mut bytes).map_err(|_| RngUnavailable)?;

        let mut value = String::with_capacity(CODE_CHARS);
        for byte in bytes {
            value.push(char::from(ALPHABET[usize::from(byte & 0x1f)]));
        }
        bytes.zeroize();

        Ok(Self {
            value: SecretString::new(value),
        })
    }

    /// The canonical form: ten characters, uppercase, no dashes. This
    /// is what gets hashed.
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// How the code is shown to a person: `XXXXX-XXXXX`.
    ///
    /// Only the grouping differs from [`PairingCode::expose`]; both
    /// hash to the same value, because the hash is always taken of the
    /// canonical form.
    pub fn display(&self) -> SecretString {
        let value = self.value.expose();
        SecretString::new(format!("{}-{}", &value[..GROUP], &value[GROUP..]))
    }

    pub fn hash(&self) -> PairingCodeHash {
        PairingCodeHash::digest(self.value.expose())
    }

    /// Normalizes something a person typed, returning `None` if it
    /// cannot be a code at all.
    ///
    /// Dashes and whitespace are dropped, letters are uppercased, and
    /// the four characters the alphabet omits are folded onto the ones
    /// they are confused with. Anything left outside the alphabet, or a
    /// length other than [`CODE_CHARS`], is rejected here - so a
    /// malformed code never becomes a database lookup, exactly as a
    /// malformed token never does.
    pub fn canonical(presented: &str) -> Option<String> {
        let mut out = String::with_capacity(CODE_CHARS);

        for raw in presented.chars() {
            let folded = match raw.to_ascii_uppercase() {
                '-' | ' ' | '\t' => continue,
                // Confusable with the digits, and never generated, so
                // accepting them costs nothing and saves a retype.
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            };
            if !ALPHABET.contains(&u8::try_from(folded).ok()?) {
                return None;
            }
            if out.len() == CODE_CHARS {
                // Too long. Bail now rather than growing the string.
                return None;
            }
            out.push(folded);
        }

        (out.len() == CODE_CHARS).then_some(out)
    }

    /// Hashes a presented code, after normalizing it.
    pub fn hash_presented(presented: &str) -> Option<PairingCodeHash> {
        Self::canonical(presented).map(|canonical| PairingCodeHash::digest(&canonical))
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value is a SecretString and redacts itself; spelled out
        // so that adding a field later is a deliberate decision.
        f.debug_struct("PairingCode")
            .field("value", &self.value)
            .finish()
    }
}

/// SHA-256 of a code's canonical form. The only representation stored.
#[derive(Clone)]
pub struct PairingCodeHash([u8; HASH_BYTES]);

impl PairingCodeHash {
    fn digest(canonical: &str) -> Self {
        let mut out = [0u8; HASH_BYTES];
        out.copy_from_slice(&Sha256::digest(canonical.as_bytes()));
        Self(out)
    }

    /// For binding into a query.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PairingCodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCodeHash([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_code_has_the_documented_shape() {
        for _ in 0..64 {
            let code = PairingCode::generate().expect("the OS CSPRNG must be available");
            let value = code.expose();
            assert_eq!(value.chars().count(), CODE_CHARS);
            assert!(
                value.bytes().all(|b| ALPHABET.contains(&b)),
                "a generated code must stay inside the alphabet: {value}"
            );
        }
    }

    /// The four omitted characters must never be generated, or the
    /// input folding would collapse two distinct codes onto one.
    #[test]
    fn the_alphabet_omits_every_confusable_character() {
        for omitted in [b'I', b'L', b'O', b'U'] {
            assert!(
                !ALPHABET.contains(&omitted),
                "{} must not be generated",
                char::from(omitted)
            );
        }
        assert_eq!(ALPHABET.len(), 32, "masking with 0x1f must stay unbiased");

        let mut sorted = *ALPHABET;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), 32, "the alphabet must have no repeats");
    }

    #[test]
    fn the_display_form_is_two_groups_of_five() {
        let code = PairingCode::generate().unwrap();
        let shown = code.display();
        let shown = shown.expose();

        assert_eq!(shown.len(), CODE_CHARS + 1);
        assert_eq!(shown.as_bytes()[GROUP], b'-');
        assert_eq!(shown.replace('-', ""), code.expose());
    }

    /// The display form, the canonical form and every spelling in
    /// between must hash identically, or a person who types what they
    /// see would not be able to pair.
    #[test]
    fn every_accepted_spelling_hashes_the_same() {
        let code = PairingCode::generate().unwrap();
        let canonical = code.expose().to_owned();
        let display = code.display();
        let display = display.expose().to_owned();

        let spellings = [
            canonical.clone(),
            display.clone(),
            canonical.to_ascii_lowercase(),
            display.to_ascii_lowercase(),
            format!("  {display}  "),
            display.replace('-', " "),
        ];

        for spelling in spellings {
            let hashed = PairingCode::hash_presented(&spelling)
                .unwrap_or_else(|| panic!("{spelling:?} must be accepted"));
            assert_eq!(
                hashed.as_bytes(),
                code.hash().as_bytes(),
                "{spelling:?} must hash to the stored value"
            );
        }
    }

    /// Folding is only safe because the targets are never generated.
    /// `I` must reach the same row as `1`, and `O` the same row as `0`.
    #[test]
    fn confusable_characters_fold_onto_the_generated_ones() {
        let canonical = "10101ABCDE";
        let expected = PairingCode::canonical(canonical).expect("the canonical form is valid");

        for typed in ["IOIOIABCDE", "lolol-abcde", "LOLOL ABCDE"] {
            assert_eq!(
                PairingCode::canonical(typed).as_deref(),
                Some(expected.as_str()),
                "{typed} must fold onto the generated spelling"
            );
        }
    }

    #[test]
    fn malformed_codes_are_rejected_before_any_lookup() {
        let cases = [
            ("empty", ""),
            ("one short", "0123456789".get(..9).unwrap()),
            ("one too long", "01234567890"),
            ("outside the alphabet", "0123456789!"),
            ("a letter outside base32", "0123456789\u{00e4}"),
            ("only dashes", "----------"),
            ("U is not in the alphabet", "U123456789"),
        ];

        for (label, candidate) in cases {
            assert!(
                PairingCode::canonical(candidate).is_none(),
                "{label} must be rejected"
            );
            assert!(
                PairingCode::hash_presented(candidate).is_none(),
                "{label} must not produce a hash"
            );
        }
    }

    /// A very long input must be refused without the normalizer having
    /// grown a string to match it.
    #[test]
    fn an_enormous_input_is_refused_cheaply() {
        let huge: String = std::iter::repeat_n('0', 1_000_000).collect();
        assert!(PairingCode::canonical(&huge).is_none());
    }

    #[test]
    fn two_generated_codes_differ() {
        let first = PairingCode::generate().unwrap();
        let second = PairingCode::generate().unwrap();
        assert_ne!(first.expose(), second.expose());
        assert_ne!(first.hash().as_bytes(), second.hash().as_bytes());
    }

    #[test]
    fn debug_output_leaks_neither_the_code_nor_its_hash() {
        let code = PairingCode::generate().unwrap();
        let value = code.expose().to_owned();

        let rendered = format!("{code:?}");
        assert!(!rendered.contains(&value), "the code must not appear");
        assert!(rendered.contains("[redacted]"));

        assert_eq!(format!("{:?}", code.hash()), "PairingCodeHash([redacted])");
    }

    #[test]
    fn a_stored_hash_is_a_full_digest() {
        let code = PairingCode::generate().unwrap();
        assert_eq!(code.hash().as_bytes().len(), HASH_BYTES);
    }
}
