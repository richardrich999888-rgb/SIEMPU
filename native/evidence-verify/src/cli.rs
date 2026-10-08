//! Command-line contract shared with `apps/verifier/verify.mjs` (general mode only).
//!
//! `siepmu-evidence-verify INPUT TRUSTED_KEY [--mode evidence] [--checkpoint FILE]
//!  [--object-digest HEX] [--epoch N] [--object-id ID]`
//!
//! Exit status 0 with the pretty-printed result on stdout, or 1 with a one-line failure report
//! on stderr. `--mode release` and `--replay-store` are rejected: strict release acceptance
//! requires the durable replay store, which remains in the Node reference (ADR-012).

use crate::error::VerifyError;
use crate::evidence::{verify_evidence, Expectations};
use crate::json::{self, Value};
use crate::output;
use std::fs::File;
use std::io::Read;

/// Maximum accepted input file size (64 MiB), equal to the reference.
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

const USAGE: &str = "Usage: node apps/verifier/verify.mjs receipt-or-export.json trusted-public-key.json [--mode evidence|release] [--checkpoint saved-checkpoint.json] [--object-digest SHA256_HEX] [--epoch INTEGER] [--object-id ID] [--replay-store receipts.sqlite]";
const OPTIONS: [&str; 6] = [
    "--mode",
    "--checkpoint",
    "--object-digest",
    "--epoch",
    "--object-id",
    "--replay-store",
];

/// Parsed command line.
#[derive(Debug, Default)]
pub struct Arguments {
    /// Evidence input path.
    pub input: String,
    /// Trusted public JWK path.
    pub key: String,
    /// Optional externally saved checkpoint path.
    pub checkpoint: Option<String>,
    /// Expected bindings.
    pub expect: Expectations,
}

/// Parses arguments with the reference's validation order and messages.
///
/// # Errors
/// Usage errors and unsupported release mode.
pub fn parse_arguments(args: &[String]) -> Result<Arguments, VerifyError> {
    if args.len() < 2 || args.len() % 2 != 0 {
        return Err(VerifyError::protocol(USAGE));
    }
    let mut options: Vec<(&str, &str)> = Vec::new();
    for pair in args[2..].chunks(2) {
        let (option, value) = (pair[0].as_str(), pair[1].as_str());
        if !OPTIONS.contains(&option)
            || options.iter().any(|(o, _)| *o == option)
            || value.is_empty()
        {
            return Err(VerifyError::protocol(USAGE));
        }
        options.push((option, value));
    }
    let get = |name: &str| {
        options
            .iter()
            .find(|(o, _)| *o == name)
            .map(|(_, v)| (*v).to_owned())
    };
    let mode = get("--mode").unwrap_or_else(|| "evidence".to_owned());
    if mode != "evidence" && mode != "release" {
        return Err(VerifyError::protocol(USAGE));
    }
    if mode == "release" && get("--checkpoint").is_some() {
        return Err(VerifyError::protocol(
            "Verify chain checkpoints separately from release receipts",
        ));
    }
    if mode != "release" && get("--replay-store").is_some() {
        return Err(VerifyError::protocol(
            "A replay store requires --mode release",
        ));
    }
    let epoch = match get("--epoch") {
        None => None,
        Some(text) => Some(parse_epoch(&text)?),
    };
    if mode == "release" {
        return Err(VerifyError::input(
            "Strict release mode is not implemented by the Rust reference verifier; use apps/verifier/verify.mjs --mode release",
        ));
    }
    Ok(Arguments {
        input: args[0].clone(),
        key: args[1].clone(),
        checkpoint: get("--checkpoint"),
        expect: Expectations {
            object_digest: get("--object-digest"),
            epoch,
            object_id: get("--object-id"),
        },
    })
}

/// `^[1-9][0-9]*$` and a safe integer, as in the reference.
fn parse_epoch(text: &str) -> Result<i64, VerifyError> {
    let well_formed = text
        .bytes()
        .next()
        .is_some_and(|b| (b'1'..=b'9').contains(&b))
        && text.bytes().all(|b| b.is_ascii_digit());
    let value = text
        .parse::<f64>()
        .ok()
        .and_then(crate::canonical::as_safe_integer);
    match (well_formed, value) {
        (true, Some(n)) => Ok(n),
        _ => Err(VerifyError::protocol(
            "Expected epoch must be a positive safe integer",
        )),
    }
}

/// Reads and parses a JSON file: regular file, at most [`MAX_INPUT_BYTES`], valid UTF-8.
///
/// The size bound is enforced on bytes actually read, not only on metadata, because an open
/// file can grow. Invalid UTF-8 is rejected (divergence D2: the reference substitutes U+FFFD).
///
/// # Errors
/// File access, size, encoding and JSON syntax failures (implementation-specific messages,
/// except the size and regular-file messages, which equal the reference).
pub fn read_json(path: &str) -> Result<Value, VerifyError> {
    let file =
        File::open(path).map_err(|e| VerifyError::input(format!("Cannot open {path}: {e}")))?;
    let metadata = file
        .metadata()
        .map_err(|e| VerifyError::input(format!("Cannot inspect {path}: {e}")))?;
    if !metadata.is_file() {
        return Err(VerifyError::protocol(
            "Verifier input must be a regular file",
        ));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(VerifyError::protocol("Verifier input file exceeds 64 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| VerifyError::input(format!("Cannot read {path}: {e}")))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(VerifyError::protocol("Verifier input file exceeds 64 MiB"));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| VerifyError::input(format!("Input is not valid UTF-8: {path}")))?;
    json::parse(&text).map_err(|e| VerifyError::input(format!("Invalid JSON in {path}: {e}")))
}

/// Runs the CLI and returns `(exit status, stdout, stderr)`; pure apart from reading files.
#[must_use]
pub fn run(args: &[String]) -> (i32, String, String) {
    let outcome = parse_arguments(args).and_then(|parsed| {
        let input = read_json(&parsed.input)?;
        let key = read_json(&parsed.key)?;
        let checkpoint = parsed.checkpoint.as_deref().map(read_json).transpose()?;
        verify_evidence(&input, &key, checkpoint.as_ref(), &parsed.expect)
    });
    match outcome {
        Ok(result) => (0, output::pretty(&result) + "\n", String::new()),
        Err(error) => (1, String::new(), output::failure(&error.message) + "\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_arguments, parse_epoch};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn rejects_malformed_option_lists() {
        for bad in [
            vec!["a"],
            vec!["a", "b", "--epoch"],
            vec!["a", "b", "--unknown", "x"],
            vec!["a", "b", "--epoch", "1", "--epoch", "2"],
            vec!["a", "b", "--object-id", ""],
            vec!["a", "b", "--mode", "fast"],
        ] {
            assert!(
                parse_arguments(&args(&bad))
                    .unwrap_err()
                    .message
                    .starts_with("Usage:"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn enforces_mode_option_constraints() {
        let e = parse_arguments(&args(&["a", "b", "--mode", "release", "--checkpoint", "c"]))
            .unwrap_err();
        assert_eq!(
            e.message,
            "Verify chain checkpoints separately from release receipts"
        );
        let e = parse_arguments(&args(&["a", "b", "--replay-store", "s"])).unwrap_err();
        assert_eq!(e.message, "A replay store requires --mode release");
        let e = parse_arguments(&args(&["a", "b", "--mode", "release"])).unwrap_err();
        assert!(!e.parity && e.message.contains("not implemented"));
    }

    #[test]
    fn validates_epoch_text() {
        assert_eq!(parse_epoch("7").unwrap(), 7);
        assert_eq!(
            parse_epoch("9007199254740991").unwrap(),
            9_007_199_254_740_991
        );
        for bad in ["0", "07", "-1", "1.0", "1e3", "", "9007199254740992", " 1"] {
            assert!(parse_epoch(bad).is_err(), "{bad}");
        }
    }
}
