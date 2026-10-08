//! Strict RFC 8259 JSON parser producing an order-preserving value tree.
//!
//! Why not a general-purpose JSON crate: the verifier must control three behaviours exactly,
//! and each is part of the SIEPMU-EVIDENCE-v1 contract (`spec/SIEPMU-EVIDENCE-v1.md` §3):
//!
//! * Numbers are converted with IEEE-754 round-to-nearest (`str::parse::<f64>`), which is the
//!   conversion `JSON.parse` performs. Canonical encoding later accepts only safe integers.
//! * Duplicate object member names are rejected (divergence D3: `JSON.parse` keeps the last).
//! * Escaped lone UTF-16 surrogates are rejected (divergence D1: `JSON.parse` keeps them).
//!
//! Nesting is bounded by [`MAX_PARSE_DEPTH`] so hostile input cannot exhaust the stack.

use std::fmt;

/// Maximum container nesting accepted by the parser. Canonical encoding separately limits
/// signed values to depth 64, so any input deeper than this would be rejected anyway.
pub const MAX_PARSE_DEPTH: usize = 128;

/// A parsed JSON value. Object members keep their input order; lookup is linear, which is
/// adequate for the small, schema-bounded objects the verifier inspects.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// JSON number after round-to-nearest conversion to binary64.
    Number(f64),
    /// JSON string (always valid Unicode scalar values).
    String(String),
    /// JSON array.
    Array(Vec<Value>),
    /// JSON object with unique member names in input order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Returns the member `key` when `self` is an object; `None` for every other type.
    /// This mirrors JavaScript property access on parsed JSON for non-inherited names.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Returns the string content when `self` is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// JavaScript truthiness of the value (used where the reference tests `if (value)`).
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0 && !n.is_nan(),
            Value::String(s) => !s.is_empty(),
            Value::Array(_) | Value::Object(_) => true,
        }
    }
}

/// A parse failure with the byte offset at which it was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable reason.
    pub reason: &'static str,
    /// Byte offset into the input.
    pub offset: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.reason, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Parses one complete JSON text. Leading/trailing JSON whitespace is allowed; anything else
/// after the value (including a byte-order mark before it) is an error.
///
/// # Errors
/// Returns [`ParseError`] for any input outside RFC 8259 or the restrictions listed above.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.bytes.len() {
        return Err(parser.error("unexpected trailing content"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, reason: &'static str) -> ParseError {
        ParseError {
            reason,
            offset: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_literal(&mut self, literal: &[u8], value: Value) -> Result<Value, ParseError> {
        if self.bytes[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.expect_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.expect_literal(b"false", Value::Bool(false)),
            Some(b'n') => self.expect_literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(self.error("nesting exceeds parser depth limit"));
        }
        self.pos += 1; // '{'
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected member name"));
            }
            let name_offset = self.pos;
            let name = self.string()?;
            if members.iter().any(|(k, _)| *k == name) {
                return Err(ParseError {
                    reason: "duplicate member name",
                    offset: name_offset,
                });
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            self.pos += 1;
            self.skip_whitespace();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(self.error("nesting exceeds parser depth limit"));
        }
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        let digits = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let mut value: u16 = 0;
        for &d in digits {
            let nibble = match d {
                b'0'..=b'9' => d - b'0',
                b'a'..=b'f' => d - b'a' + 10,
                b'A'..=b'F' => d - b'A' + 10,
                _ => return Err(self.error("invalid \\u escape")),
            };
            value = (value << 4) | u16::from(nibble);
        }
        self.pos += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.pos;
            // Copy the longest run of unescaped bytes. The input is &str, so any run that ends
            // on an ASCII delimiter is valid UTF-8 on its own.
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.push_str(
                std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|_| self.error("invalid UTF-8"))?,
            );
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                Some(_) => return Err(self.error("unescaped control character in string")),
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let Some(code) = self.peek() else {
            return Err(self.error("unterminated escape"));
        };
        self.pos += 1;
        let ch = match code {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => self.unicode_escape()?,
            _ => return Err(self.error("invalid escape")),
        };
        out.push(ch);
        Ok(())
    }

    /// Decodes `\uXXXX`, combining a high/low surrogate pair into one scalar value.
    /// A surrogate that is not part of a valid pair is rejected (divergence D1).
    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let first = self.hex4()?;
        let scalar = match first {
            0xD800..=0xDBFF => {
                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                    return Err(self.error("lone surrogate escape"));
                }
                self.pos += 2;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(self.error("lone surrogate escape"));
                }
                // UTF-16 decoding: 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00).
                0x10000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.error("lone surrogate escape")),
            _ => u32::from(first),
        };
        char::from_u32(scalar).ok_or_else(|| self.error("invalid scalar value"))
    }

    /// Validates the RFC 8259 number grammar, then converts the lexeme with round-to-nearest.
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number fraction"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number exponent"));
            }
            self.digits();
        }
        let lexeme = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.error("invalid number"))?;
        // Overflow yields ±infinity, exactly as JSON.parse does; canonical encoding rejects it.
        lexeme
            .parse::<f64>()
            .map(Value::Number)
            .map_err(|_| self.error("invalid number"))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Value, MAX_PARSE_DEPTH};

    #[test]
    fn parses_nested_document_preserving_member_order() {
        let v = parse(r#" {"b":[1,true,null],"a":{"z":"x"}} "#).unwrap();
        let Value::Object(members) = &v else {
            panic!("object expected")
        };
        assert_eq!(members[0].0, "b");
        assert_eq!(members[1].0, "a");
        assert_eq!(v.get("a").unwrap().get("z").unwrap().as_str(), Some("x"));
    }

    #[test]
    fn decodes_escapes_and_surrogate_pairs() {
        let v = parse(r#""\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00""#).unwrap();
        assert_eq!(
            v,
            Value::String("\"\\/\u{8}\u{c}\n\r\t\u{e9}\u{1F600}".into())
        );
    }

    #[test]
    fn converts_numbers_like_json_parse() {
        assert_eq!(parse("1.0").unwrap(), Value::Number(1.0));
        assert_eq!(parse("1e2").unwrap(), Value::Number(100.0));
        assert_eq!(
            parse("9007199254740993").unwrap(),
            Value::Number(9_007_199_254_740_992.0)
        );
        assert_eq!(parse("1e400").unwrap(), Value::Number(f64::INFINITY));
        let Value::Number(z) = parse("-0").unwrap() else {
            panic!()
        };
        assert!(z == 0.0 && z.is_sign_negative());
    }

    #[test]
    fn rejects_grammar_violations() {
        for bad in [
            "",
            " ",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "'x'",
            "tru",
            "nul",
            "\"\u{1}\"",
            "\"\\x\"",
            "\"abc",
            "[1 2]",
            "{} {}",
            "\u{feff}{}",
            "NaN",
            "Infinity",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_duplicate_member_names() {
        let err = parse(r#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(err.reason, "duplicate member name");
    }

    #[test]
    fn rejects_lone_surrogates() {
        for bad in [
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800\u0041""#,
            r#""\ud800x""#,
        ] {
            assert_eq!(
                parse(bad).unwrap_err().reason,
                "lone surrogate escape",
                "{bad}"
            );
        }
    }

    #[test]
    fn bounds_nesting_depth() {
        let ok = "[".repeat(MAX_PARSE_DEPTH) + &"]".repeat(MAX_PARSE_DEPTH);
        assert!(parse(&ok).is_ok());
        let deep = "[".repeat(MAX_PARSE_DEPTH + 1) + &"]".repeat(MAX_PARSE_DEPTH + 1);
        assert_eq!(
            parse(&deep).unwrap_err().reason,
            "nesting exceeds parser depth limit"
        );
        // Far beyond the limit must fail without stack exhaustion.
        assert!(parse(&"[".repeat(1_000_000)).is_err());
    }

    #[test]
    fn truthiness_matches_javascript() {
        for (text, truthy) in [
            ("null", false),
            ("false", false),
            ("0", false),
            ("\"\"", false),
            ("-0", false),
            ("true", true),
            ("1", true),
            ("\"0\"", true),
            ("[]", true),
            ("{}", true),
        ] {
            assert_eq!(parse(text).unwrap().is_truthy(), truthy, "{text}");
        }
    }
}
