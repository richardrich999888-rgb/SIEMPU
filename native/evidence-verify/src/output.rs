//! Serialises results exactly as the reference CLI does: `JSON.stringify(result, null, 2)` for
//! success and `JSON.stringify({valid:false,error})` for failure, preserving member order.

use crate::canonical::{is_safe_integer, quote, write_integer};
use crate::json::Value;

/// `JSON.stringify(value, null, 2)` for values whose numbers are safe integers.
#[must_use]
pub fn pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(value, 0, &mut out);
    out
}

fn indent(level: usize, out: &mut String) {
    out.push('\n');
    out.push_str(&"  ".repeat(level));
}

fn write_pretty(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(level + 1, out);
                write_pretty(item, level + 1, out);
            }
            indent(level, out);
            out.push(']');
        }
        Value::Object(members) if !members.is_empty() => {
            out.push('{');
            for (i, (name, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(level + 1, out);
                quote(name, out);
                out.push_str(": ");
                write_pretty(member, level + 1, out);
            }
            indent(level, out);
            out.push('}');
        }
        Value::Array(_) => out.push_str("[]"),
        Value::Object(_) => out.push_str("{}"),
        Value::Number(n) if is_safe_integer(*n) => write_integer(*n, out),
        // Results only contain counts and epochs, so a non-safe number cannot occur; it would
        // serialise as `null`, which is what JSON.stringify emits for non-finite numbers.
        Value::Null | Value::Number(_) => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) => quote(s, out),
    }
}

/// The single-line failure report.
#[must_use]
pub fn failure(message: &str) -> String {
    let mut out = String::from("{\"valid\":false,\"error\":");
    quote(message, &mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::{failure, pretty};
    use crate::json::parse;

    #[test]
    fn matches_json_stringify_indentation() {
        let v = parse(r#"{"a":true,"b":[],"c":{},"d":["x",{"e":1}]}"#).unwrap();
        assert_eq!(
            pretty(&v),
            "{\n  \"a\": true,\n  \"b\": [],\n  \"c\": {},\n  \"d\": [\n    \"x\",\n    {\n      \"e\": 1\n    }\n  ]\n}"
        );
    }

    #[test]
    fn failure_is_compact_and_escaped() {
        assert_eq!(
            failure("bad \"x\"\n"),
            r#"{"valid":false,"error":"bad \"x\"\n"}"#
        );
    }
}
