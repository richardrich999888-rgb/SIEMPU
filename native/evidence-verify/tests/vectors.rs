//! Conformance against the language-neutral vectors in `spec/vectors/` (generated from the
//! Node reference by `scripts/evidence-vectors.mjs`). Every case must match: success output
//! byte-for-byte, failure status, and the failure message wherever the vector fixes one.

use siepmu_evidence_verify::canonical::canonical;
use siepmu_evidence_verify::cli::run;
use siepmu_evidence_verify::json::{parse, Value};
use siepmu_evidence_verify::output::pretty;
use siepmu_evidence_verify::range::{verify_evidence_range, MAX_RANGE_RECORDS};
use std::path::{Path, PathBuf};

fn spec_file(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse(&text).expect("vector file is valid JSON")
}

fn cases(file: &Value) -> &[Value] {
    match file.get("cases") {
        Some(Value::Array(items)) => items,
        _ => panic!("vector file lacks cases"),
    }
}

fn str_of<'a>(case: &'a Value, name: &str) -> Option<&'a str> {
    case.get(name).and_then(Value::as_str)
}

/// Decodes standard base64 (used only for the raw-bytes vector).
fn base64_standard(text: &str) -> Vec<u8> {
    let sextet = |c: u8| -> u32 {
        u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 in vector"),
        })
    };
    let clean: Vec<u8> = text.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= sextet(c) << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..chunk.len()]);
    }
    out
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn canonical_vectors_conform() {
    let file = spec_file("canonical-v1.json");
    let all = cases(&file);
    assert!(all.len() >= 16, "canonical vector set unexpectedly small");
    for case in all {
        let id = str_of(case, "id").unwrap();
        let input = str_of(case, "input").unwrap();
        let outcome = parse(input)
            .map_err(|_| None)
            .and_then(|v| canonical(&v).map_err(|e| Some(e.0)));
        match (str_of(case, "canonical"), case.get("error")) {
            (Some(expected), _) => assert_eq!(outcome.as_deref(), Ok(expected), "{id}"),
            (None, Some(Value::String(message))) => {
                assert_eq!(outcome, Err(Some(message.as_str())), "{id}");
            }
            (None, Some(Value::Null)) => assert!(outcome.is_err(), "{id} must be rejected"),
            _ => panic!("{id}: malformed vector"),
        }
    }
}

#[test]
fn evidence_vectors_conform() {
    let file = spec_file("evidence-v1.json");
    let all = cases(&file);
    assert!(all.len() >= 60, "evidence vector set unexpectedly small");
    let dir = std::env::temp_dir().join(format!("siepmu-rust-vectors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Scratch(dir.clone());
    for case in all {
        let id = str_of(case, "id").unwrap();
        let paths = [
            ("@input", dir.join("input.json")),
            ("@key", dir.join("key.json")),
            ("@checkpoint", dir.join("checkpoint.json")),
        ];
        let input_bytes = match (str_of(case, "input"), str_of(case, "inputBase64")) {
            (Some(text), _) => text.as_bytes().to_vec(),
            (None, Some(b64)) => base64_standard(b64),
            _ => panic!("{id}: no input"),
        };
        std::fs::write(&paths[0].1, input_bytes).unwrap();
        std::fs::write(&paths[1].1, str_of(case, "key").unwrap()).unwrap();
        let _ = std::fs::remove_file(&paths[2].1);
        if let Some(text) = str_of(case, "checkpoint") {
            std::fs::write(&paths[2].1, text).unwrap();
        }
        let Some(Value::Array(argv)) = case.get("argv") else {
            panic!("{id}: argv")
        };
        let command_line: Vec<String> = argv
            .iter()
            .map(|a| {
                let a = a.as_str().unwrap();
                paths
                    .iter()
                    .find(|(p, _)| *p == a)
                    .map_or_else(|| a.to_owned(), |(_, path)| path.display().to_string())
            })
            .collect();
        let (status, stdout, stderr) = run(&command_line);
        let expect = case.get("expect").unwrap();
        let Some(Value::Number(expected_status)) = expect.get("status") else {
            panic!("{id}: status")
        };
        let expected_status = siepmu_evidence_verify::canonical::as_safe_integer(*expected_status);
        assert_eq!(
            Some(i64::from(status)),
            expected_status,
            "{id}: status (stderr {stderr})"
        );
        if let Some(expected) = expect.get("stdout").and_then(Value::as_str) {
            assert_eq!(stdout, expected, "{id}: stdout");
        }
        if let Some(Value::String(message)) = expect.get("error") {
            let report = parse(stderr.trim_end()).unwrap();
            assert_eq!(
                report.get("error").and_then(Value::as_str),
                Some(message.as_str()),
                "{id}: message"
            );
            assert_eq!(
                report.get("valid"),
                Some(&Value::Bool(false)),
                "{id}: valid flag"
            );
        }
    }
}

#[test]
fn evidence_range_vectors_conform() {
    let file = spec_file("evidence-range-v1.json");
    let all = cases(&file);
    assert!(all.len() >= 25, "range vector set unexpectedly small");
    for case in all {
        let id = str_of(case, "id").unwrap();
        let input = parse(str_of(case, "input").unwrap()).expect("input is JSON");
        let key = parse(str_of(case, "key").unwrap()).expect("key is JSON");
        let max = match case.get("maxRecords") {
            Some(Value::Number(n)) => usize::try_from(
                siepmu_evidence_verify::canonical::as_safe_integer(*n).expect("safe maxRecords"),
            )
            .expect("non-negative maxRecords"),
            None => MAX_RANGE_RECORDS,
            Some(_) => panic!("{id}: maxRecords"),
        };
        let outcome = verify_evidence_range(&input, &key, max);
        let expect = case.get("expect").unwrap();
        match expect.get("valid") {
            Some(Value::Bool(true)) => {
                let result = outcome.unwrap_or_else(|e| panic!("{id}: rejected: {e}"));
                assert_eq!(
                    Some(format!("{}\n", pretty(&result)).as_str()),
                    str_of(expect, "stdout"),
                    "{id}: stdout"
                );
            }
            Some(Value::Bool(false)) => {
                let error = outcome.expect_err(id);
                assert_eq!(
                    Some(error.message.as_str()),
                    str_of(expect, "error"),
                    "{id}"
                );
            }
            _ => panic!("{id}: malformed vector"),
        }
    }
}
