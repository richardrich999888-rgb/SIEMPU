//! Unpadded base64url (RFC 4648 §5) with the reference verifier's acceptance rule.
//!
//! The reference decodes with Node's lenient `Buffer.from(s, 'base64url')` and then requires
//! that re-encoding reproduces `s` exactly. Because the encoder only emits the URL-safe
//! alphabet without padding, that rule accepts exactly the canonical unpadded encodings.
//! [`decode_canonical`] implements the same acceptance set directly.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Encodes `bytes` as unpadded base64url.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // Pack up to three bytes big-endian into 24 bits, then emit 2..4 sextets.
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let emitted = chunk.len() + 1;
        for i in 0..emitted {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
        }
    }
    out
}

/// Decodes `text` only if it is the canonical unpadded base64url encoding of some byte string.
///
/// Rejected: characters outside the URL-safe alphabet (including `=`), a length congruent to 1
/// modulo 4, and non-zero unused trailing bits (all of which fail the reference round-trip).
#[must_use]
pub fn decode_canonical(text: &str) -> Option<Vec<u8>> {
    let input = text.as_bytes();
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= u32::from(sextet(c)?) << (18 - 6 * i);
        }
        // A chunk of k characters carries k-1 whole bytes; the remaining bits must be zero.
        let bytes = chunk.len() - 1;
        let unused_mask = (1u32 << (24 - 8 * bytes)) - 1;
        if n & unused_mask != 0 {
            return None;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode_canonical, encode};

    #[test]
    fn round_trips_all_tail_lengths() {
        for len in 0..=66u8 {
            let bytes: Vec<u8> = (0..len)
                .map(|i: u8| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let text = encode(&bytes);
            assert!(!text.contains('='));
            assert_eq!(
                decode_canonical(&text).as_deref(),
                Some(bytes.as_slice()),
                "len {len}"
            );
        }
    }

    #[test]
    fn matches_rfc4648_vectors_in_url_alphabet() {
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn rejects_non_canonical_forms() {
        for bad in [
            "Zm8=",
            "Zm9vYmFy=",
            "A",
            "Zm+v",
            "Zm/v",
            "Zm9",
            "Zm9 v",
            "Zm-\u{e9}",
        ] {
            assert_eq!(decode_canonical(bad), None, "{bad}");
        }
        // "Zm9" would be canonical for "fo" only if its unused bits were zero; "Zm8" is canonical.
        assert!(decode_canonical("Zm8").is_some());
    }
}
