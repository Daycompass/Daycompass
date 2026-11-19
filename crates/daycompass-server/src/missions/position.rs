//! Fractional index keys for `tasks.position`: a key strictly between
//! two others, so a task can be put anywhere without renumbering the
//! rest.
//!
//! The scheme is David Greenspan's, as in the `fractional-indexing`
//! packages' `generateKeyBetween` (base 62, `a0` as the first key): an
//! integer part whose first character encodes its length, then a
//! fraction without trailing zeros. The server uses it so a client
//! using one of those packages can insert between keys the server made,
//! and the other way round. Keys that are not in this scheme (the wire
//! format only asks for `0-9A-Za-z`) are refused here, never rewritten.

use super::validate::MAX_POSITION_CHARS;

const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ZERO: u8 = b'0';
const LAST: u8 = b'z';
/// The smallest integer part, which has no integer below it.
const SMALLEST_INTEGER: &[u8] = b"A00000000000000000000000000";

/// A key strictly between `a` and `b` (`None` meaning open-ended), or
/// `None` if either is not a key of this scheme, `a >= b`, or the result
/// would be longer than a position may be.
pub fn key_between(a: Option<&str>, b: Option<&str>) -> Option<String> {
    let a = a.map(str::as_bytes);
    let b = b.map(str::as_bytes);
    if let Some(a) = a {
        check(a)?;
    }
    if let Some(b) = b {
        check(b)?;
    }
    let key = match (a, b) {
        (None, None) => b"a0".to_vec(),
        (None, Some(b)) => {
            let (int, frac) = split(b)?;
            if int == SMALLEST_INTEGER {
                [int, &midpoint(&[], Some(frac))?].concat()
            } else if int.len() < b.len() {
                int.to_vec()
            } else {
                decrement(int)?
            }
        }
        (Some(a), None) => {
            let (int, frac) = split(a)?;
            match increment(int) {
                Some(next) => next,
                None => [int, &midpoint(frac, None)?].concat(),
            }
        }
        (Some(a), Some(b)) => {
            if a >= b {
                return None;
            }
            let (int_a, frac_a) = split(a)?;
            let (int_b, frac_b) = split(b)?;
            if int_a == int_b {
                [int_a, &midpoint(frac_a, Some(frac_b))?].concat()
            } else {
                match increment(int_a) {
                    Some(next) if next.as_slice() < b => next,
                    _ => [int_a, &midpoint(frac_a, None)?].concat(),
                }
            }
        }
    };
    if key.len() > MAX_POSITION_CHARS {
        return None;
    }
    String::from_utf8(key).ok()
}

fn digit(byte: u8) -> Option<usize> {
    DIGITS.iter().position(|&d| d == byte)
}

/// How long the integer part is, from its first character.
fn integer_len(head: u8) -> Option<usize> {
    match head {
        b'a'..=b'z' => Some(usize::from(head - b'a') + 2),
        b'A'..=b'Z' => Some(usize::from(b'Z' - head) + 2),
        _ => None,
    }
}

fn split(key: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = integer_len(*key.first()?)?;
    (len <= key.len()).then(|| key.split_at(len))
}

fn check(key: &[u8]) -> Option<()> {
    let (_int, frac) = split(key)?;
    // The smallest integer alone is no key: nothing could go before it.
    let valid = key != SMALLEST_INTEGER
        && frac.last() != Some(&ZERO)
        && key[1..].iter().all(|&b| digit(b).is_some());
    valid.then_some(())
}

/// A fraction strictly between `a` and `b` (`None`: one), neither with
/// a trailing zero.
fn midpoint(a: &[u8], b: Option<&[u8]>) -> Option<Vec<u8>> {
    if b.is_some_and(|b| a >= b)
        || a.last() == Some(&ZERO)
        || b.and_then(<[u8]>::last) == Some(&ZERO)
    {
        return None;
    }
    if let Some(b) = b {
        // The common prefix, with `a` padded by zeros.
        let n = b
            .iter()
            .enumerate()
            .take_while(|&(i, &d)| a.get(i).copied().unwrap_or(ZERO) == d)
            .count();
        if n > 0 {
            let rest = midpoint(a.get(n..).unwrap_or_default(), Some(&b[n..]))?;
            return Some([&b[..n], &rest].concat());
        }
    }
    let digit_a = a.first().map_or(Some(0), |&d| digit(d))?;
    let digit_b = match b {
        Some(b) => digit(*b.first()?)?,
        None => DIGITS.len(),
    };
    if digit_b > digit_a + 1 {
        Some(vec![DIGITS[(digit_a + digit_b).div_ceil(2)]])
    } else if let Some(b) = b.filter(|b| b.len() > 1) {
        Some(b[..1].to_vec())
    } else {
        let rest = midpoint(a.get(1..).unwrap_or_default(), None)?;
        Some([&[DIGITS[digit_a]], rest.as_slice()].concat())
    }
}

/// The next integer part, or `None` past the largest.
fn increment(int: &[u8]) -> Option<Vec<u8>> {
    let (head, mut digits) = (int[0], int[1..].to_vec());
    for d in digits.iter_mut().rev() {
        let next = digit(*d)? + 1;
        if next < DIGITS.len() {
            *d = DIGITS[next];
            return Some([&[head], digits.as_slice()].concat());
        }
        *d = ZERO;
    }
    let head = match head {
        b'Z' => return Some(b"a0".to_vec()),
        b'z' => return None,
        head => head + 1,
    };
    if head > b'a' {
        digits.push(ZERO);
    } else {
        digits.pop();
    }
    Some([&[head], digits.as_slice()].concat())
}

/// The previous integer part, or `None` below the smallest.
fn decrement(int: &[u8]) -> Option<Vec<u8>> {
    let (head, mut digits) = (int[0], int[1..].to_vec());
    for d in digits.iter_mut().rev() {
        let current = digit(*d)?;
        if current > 0 {
            *d = DIGITS[current - 1];
            return Some([&[head], digits.as_slice()].concat());
        }
        *d = LAST;
    }
    let head = match head {
        b'a' => return Some(b"Zz".to_vec()),
        b'A' => return None,
        head => head - 1,
    };
    if head < b'Z' {
        digits.push(LAST);
    } else {
        digits.pop();
    }
    Some([&[head], digits.as_slice()].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn between(a: Option<&str>, b: Option<&str>) -> Option<String> {
        key_between(a, b)
    }

    /// The reference implementation's own base-62 cases.
    #[test]
    fn matches_the_reference_implementation() {
        let cases: &[(Option<&str>, Option<&str>, &str)] = &[
            (None, None, "a0"),
            (None, Some("a0"), "Zz"),
            (None, Some("Zz"), "Zy"),
            (Some("a0"), None, "a1"),
            (Some("a1"), None, "a2"),
            (Some("a0"), Some("a1"), "a0V"),
            (Some("a1"), Some("a2"), "a1V"),
            (Some("a0V"), Some("a1"), "a0l"),
            (Some("Zz"), Some("a0"), "ZzV"),
            (Some("Zz"), Some("a1"), "a0"),
            (None, Some("Y00"), "Xzzz"),
            (Some("bzz"), None, "c000"),
            (Some("a0"), Some("a0V"), "a0G"),
            (Some("a0"), Some("a0G"), "a08"),
            (Some("b125"), Some("b129"), "b127"),
            (Some("a0"), Some("a1V"), "a1"),
            (Some("Zz"), Some("a01"), "a0"),
            (None, Some("a0V"), "a0"),
            (None, Some("b999"), "b99"),
            (
                None,
                Some("A000000000000000000000000001"),
                "A000000000000000000000000000V",
            ),
            (
                Some("zzzzzzzzzzzzzzzzzzzzzzzzzzy"),
                None,
                "zzzzzzzzzzzzzzzzzzzzzzzzzzz",
            ),
            (
                Some("zzzzzzzzzzzzzzzzzzzzzzzzzzz"),
                None,
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzV",
            ),
        ];
        for &(a, b, expected) in cases {
            assert_eq!(between(a, b).as_deref(), Some(expected), "{a:?} {b:?}");
        }
    }

    #[test]
    fn refuses_what_is_not_a_key_or_not_in_order() {
        let cases: &[(Option<&str>, Option<&str>)] = &[
            (None, Some("A00000000000000000000000000")),
            (Some("a00"), None),
            (Some("a00"), Some("a1")),
            (Some("0"), Some("1")),
            (Some("a1"), Some("a0")),
            (Some("a1"), Some("a1")),
            (Some("a"), None),
            (Some("a-"), None),
            (Some(""), None),
        ];
        for &(a, b) in cases {
            assert_eq!(between(a, b), None, "{a:?} {b:?}");
        }
    }

    #[test]
    fn repeated_inserts_stay_in_order_and_in_bounds() {
        // Always between the first two: the worst case for key growth.
        let (mut low, high) = ("a0".to_owned(), "a1".to_owned());
        for _ in 0..100 {
            let key = between(Some(&low), Some(&high)).expect("room");
            assert!(low < key && key < high && key.len() <= MAX_POSITION_CHARS);
            low = key;
        }
        let mut last = "a0".to_owned();
        for _ in 0..1000 {
            let key = between(Some(&last), None).expect("room");
            assert!(key > last);
            last = key;
        }
    }
}
