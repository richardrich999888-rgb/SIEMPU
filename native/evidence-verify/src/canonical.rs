//! SIEPMU-CJSON-v1 canonical encoding (`spec/SIEPMU-CJSON-v1.md`).
//!
//! Reference implementation: `packages/protocol/canonical.mjs`. Rules:
//! 1. Object members are emitted sorted by name in **UTF-16 code-unit order** (the order of
//!    JavaScript `Array.prototype.sort` on strings), not UTF-8 byte or code-point order. The two
//!    differ when a name contains both a supplementary-plane character and one in U+E000..U+FFFF.
//! 2. Array order is preserved.
//! 3. Numbers must be safe integers (|n| <= 2^53 - 1) and not negative zero; they are emitted
//!    in plain decimal.
//! 4. Strings are escaped exactly as `JSON.stringify` escapes well-formed strings.
//! 5. A value nested deeper than [`MAX_CANONICAL_DEPTH`] is rejected (root is depth 0).
//!
//! This is a project encoding. It is not claimed to implement RFC 8785.

use crate::json::Value;
use std::cmp::Ordering;
use std::fmt::Write as _;

/// Maximum nesting depth of a canonical value (`depth > 64` fails in the reference).
pub const MAX_CANONICAL_DEPTH: usize = 64;

/// Largest integer n such that every integer in [-n, n] is exactly representable in binary64:
/// 2^53 - 1 (JavaScript `Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Canonical-encoding failure. Messages equal the reference implementation's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError(pub &'static str);

/// Returns true when `n` satisfies JavaScript `Number.isSafeInteger(n)`.
#[must_use]
// Exact comparison is the intended integrality test: trunc(n) == n holds precisely for
// integral binary64 values. A tolerance would accept non-integers.
#[allow(clippy::float_cmp)]
pub fn is_safe_integer(n: f64) -> bool {
    n.is_finite() && n.trunc() == n && n.abs() <= MAX_SAFE_INTEGER
}

/// Converts `n` to `i64` when it is a safe integer. Negative zero maps to 0; callers that must
/// reject it (canonical encoding) check the sign separately.
#[must_use]
pub fn as_safe_integer(n: f64) -> Option<i64> {
    // Lossless: a safe integer has magnitude below 2^53, well within i64.
    #[allow(clippy::cast_possible_truncation)]
    is_safe_integer(n).then_some(n as i64)
}

/// Encodes `value` as SIEPMU-CJSON-v1 text.
///
/// # Errors
/// Returns [`CanonicalError`] for non-safe-integer numbers, negative zero, or excess depth.
pub fn canonical(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    encode(value, 0, &mut out)?;
    Ok(out)
}

fn encode(value: &Value, depth: usize, out: &mut String) -> Result<(), CanonicalError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalError("Canonical value exceeds depth limit"));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => quote(s, out),
        Value::Number(n) => {
            if !is_safe_integer(*n) || (*n == 0.0 && n.is_sign_negative()) {
                return Err(CanonicalError("Canonical numbers must be safe integers"));
            }
            write_integer(*n, out);
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                encode(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_order(&a.0, &b.0));
            out.push('{');
            for (index, (name, member)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                quote(name, out);
                out.push(':');
                encode(member, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Lexicographic comparison of the UTF-16 encodings of `a` and `b`.
#[must_use]
pub fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Number of UTF-16 code units in `s` (JavaScript `String.prototype.length`).
#[must_use]
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Writes a safe integer in plain decimal. Caller guarantees `is_safe_integer(n)`.
pub(crate) fn write_integer(n: f64, out: &mut String) {
    if let Some(integer) = as_safe_integer(n) {
        let _ = write!(out, "{integer}");
    }
}

/// Appends `s` as a JSON string literal using the `JSON.stringify` escape set:
/// `"` and `\` are backslash-escaped; U+0008, U+0009, U+000A, U+000C, U+000D use their short
/// escapes; other code points below U+0020 use lowercase `\u00xx`; everything else (including
/// U+007F, U+2028 and U+2029) is emitted literally.
pub fn quote(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::{canonical, is_safe_integer, utf16_order, CanonicalError};
    use crate::json::parse;
    use std::cmp::Ordering;

    fn c(text: &str) -> Result<String, CanonicalError> {
        canonical(&parse(text).unwrap())
    }

    #[test]
    fn sorts_members_recursively_and_preserves_arrays() {
        assert_eq!(
            c(r#"{"b":1,"a":[3,{"d":0,"c":null}]}"#).unwrap(),
            r#"{"a":[3,{"c":null,"d":0}],"b":1}"#
        );
    }

    #[test]
    fn sorts_by_utf16_code_units_not_code_points() {
        // U+FF61 (one unit 0xFF61) vs U+1F600 (units 0xD83D 0xDE00): UTF-16 puts the emoji first,
        // code-point order would put it last.
        assert_eq!(utf16_order("\u{1F600}", "\u{FF61}"), Ordering::Less);
        assert_eq!(
            c("{\"\u{FF61}\":1,\"\u{1F600}\":2}").unwrap(),
            "{\"\u{1F600}\":2,\"\u{FF61}\":1}"
        );
    }

    #[test]
    fn escapes_strings_like_json_stringify() {
        assert_eq!(
            c(r#""\u0000\u001f\b\t\n\f\r\"\\/\u007f é""#).unwrap(),
            "\"\\u0000\\u001f\\b\\t\\n\\f\\r\\\"\\\\/\u{7f}\u{2028}é\""
        );
    }

    #[test]
    fn normalises_integral_number_lexemes() {
        assert_eq!(
            c("[1.0,1e2,-5,0,9007199254740991,-9007199254740991]").unwrap(),
            "[1,100,-5,0,9007199254740991,-9007199254740991]"
        );
    }

    #[test]
    fn rejects_non_safe_numbers_and_negative_zero() {
        for bad in [
            "1.5",
            "9007199254740992",
            "-9007199254740992",
            "1e400",
            "-0",
            "-0.0",
            "[0.1]",
        ] {
            assert_eq!(
                c(bad),
                Err(CanonicalError("Canonical numbers must be safe integers")),
                "{bad}"
            );
        }
        assert!(!is_safe_integer(f64::NAN));
    }

    #[test]
    fn enforces_depth_limit_at_64() {
        // 64 nested arrays: the innermost scalar sits at depth 64, which is allowed.
        let ok = "[".repeat(64) + "1" + &"]".repeat(64);
        assert!(c(&ok).is_ok());
        let deep = "[".repeat(65) + "1" + &"]".repeat(65);
        assert_eq!(
            c(&deep),
            Err(CanonicalError("Canonical value exceeds depth limit"))
        );
        // An empty container at depth 65 also fails: the check precedes the type dispatch.
        let deep_empty = "[".repeat(66) + &"]".repeat(66);
        assert!(c(&deep_empty).is_err());
    }
}
