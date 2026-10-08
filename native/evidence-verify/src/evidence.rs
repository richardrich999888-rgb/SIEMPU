//! SIEPMU-EVIDENCE-v1 general-mode verification (`spec/SIEPMU-EVIDENCE-v1.md` §5–§7).
//!
//! Reference: `verifyEvidence` in `apps/verifier/verify.mjs`. This module is pure: it takes
//! parsed values and returns a result value or an error. It performs no I/O and never
//! contacts an authority. Strict release mode (durable replay store) is not implemented here.

use crate::canonical::{as_safe_integer, utf16_len, MAX_SAFE_INTEGER};
use crate::error::VerifyError;
use crate::json::Value;
use crate::signature::{digest, TrustedKey};

/// Previous-hash value of the first chain record: 64 ASCII zeros.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum number of records accepted in one chain export.
pub const MAX_RECORDS: usize = 100_000;

/// Maximum UTF-16 length of an expected object ID supplied by the operator.
pub const MAX_OBJECT_ID_UNITS: usize = 128;

// 2^53 - 1 as an integer; the f64 constant is exact, so the conversion is lossless.
#[allow(clippy::cast_possible_truncation)]
const MAX_SAFE_INTEGER_I64: i64 = MAX_SAFE_INTEGER as i64;

const LIMIT_SIGNATURE: &str = "Signature authenticates the packet under the supplied key; it does not prove factual truth or current authorization.";
const LIMIT_BINDINGS: &str = "Expected binding checks compare only the supplied expected values with signed receipt fields; they do not establish correctness of omitted expectations.";
const LIMIT_AUTHENTICITY: &str =
    "Authenticity is relative to the independently supplied trusted public key, not factual truth.";
const LIMIT_WITH_CHECKPOINT: &str =
    "Suffix-truncation detection is bounded by the externally saved checkpoint.";
const LIMIT_WITHOUT_CHECKPOINT: &str =
    "No external checkpoint supplied: an earlier valid chain and its checkpoint can be replayed without detection.";
const LIMIT_HARDWARE: &str =
    "This does not prove hardware-backed signing, reliable wall-clock time, or freedom from authority compromise.";

/// Expected bindings supplied independently of the packet under verification.
#[derive(Debug, Default, Clone)]
pub struct Expectations {
    /// Expected `details.objectDigest` (SHA-256 of the ciphertext bytes).
    pub object_digest: Option<String>,
    /// Expected `details.authorityEpoch`.
    pub epoch: Option<i64>,
    /// Expected `objectId`.
    pub object_id: Option<String>,
}

impl Expectations {
    fn any(&self) -> bool {
        self.object_digest.is_some() || self.epoch.is_some() || self.object_id.is_some()
    }
}

fn ensure(condition: bool, message: &str) -> Result<(), VerifyError> {
    if condition {
        Ok(())
    } else {
        Err(VerifyError::protocol(message))
    }
}

fn is_lower_hex64(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The value as an integer when it is a JSON number satisfying `Number.isSafeInteger`.
/// Comparing these integers is equivalent to the reference's `===` on numbers, because a
/// non-safe number can never equal the safe integer it is compared with.
fn safe_integer(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => as_safe_integer(*n),
        _ => None,
    }
}

fn non_empty_string(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

/// Requires `value` to be an object whose member names are exactly `names` (any order).
///
/// # Errors
/// `Expected object` for non-objects; `Unexpected or missing packet members` otherwise.
pub fn exact_members(value: &Value, names: &[&str]) -> Result<(), VerifyError> {
    let Value::Object(members) = value else {
        return Err(VerifyError::protocol("Expected object"));
    };
    let same =
        members.len() == names.len() && names.iter().all(|n| members.iter().any(|(k, _)| k == n));
    ensure(same, "Unexpected or missing packet members")
}

fn num(n: i64) -> Value {
    // Only safe integers reach here, and every safe integer is exactly representable.
    #[allow(clippy::cast_precision_loss)]
    Value::Number(n as f64)
}
fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}
fn member(name: &str, value: Value) -> (String, Value) {
    (name.to_owned(), value)
}

struct Checkpoint {
    sequence: i64,
    head_hash: String,
}

fn checkpoint_payload(packet: &Value, key: &TrustedKey) -> Result<Checkpoint, VerifyError> {
    let payload = key.verify_packet(packet)?;
    exact_members(payload, &["sequence", "headHash", "issuedAt"])?;
    let sequence = safe_integer(payload.get("sequence")).filter(|n| *n >= 0);
    ensure(sequence.is_some(), "Invalid checkpoint sequence")?;
    let issued = safe_integer(payload.get("issuedAt")).filter(|n| *n >= 0);
    ensure(issued.is_some(), "Invalid checkpoint time")?;
    ensure(
        is_lower_hex64(payload.get("headHash")),
        "Invalid checkpoint hash",
    )?;
    Ok(Checkpoint {
        sequence: sequence.unwrap_or_default(),
        head_hash: payload
            .get("headHash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Checks a signed release-issuance payload against independently supplied expectations and
/// returns the checked bindings in reference member order.
fn expected_bindings(payload: &Value, expect: &Expectations) -> Result<Value, VerifyError> {
    let details = payload.get("details");
    let field = |name: &str| details.and_then(|d| d.get(name));
    ensure(
        payload.get("eventType").and_then(Value::as_str) == Some("RELEASE_ISSUED")
            && payload.get("decision").and_then(Value::as_str) == Some("RELEASED"),
        "Expected a release issuance receipt for object binding checks",
    )?;
    ensure(
        is_lower_hex64(field("objectDigest")),
        "Receipt lacks a valid object digest",
    )?;
    let epoch = safe_integer(payload.get("epoch")).filter(|n| *n > 0);
    ensure(
        epoch.is_some() && safe_integer(field("authorityEpoch")) == epoch,
        "Receipt authority epoch is missing or inconsistent",
    )?;
    ensure(
        non_empty_string(payload.get("objectId")),
        "Receipt lacks an object ID",
    )?;

    let mut checked = Vec::new();
    if let Some(expected) = &expect.object_digest {
        ensure(
            is_lower_hex64(Some(&Value::String(expected.clone()))),
            "Expected object digest must be lowercase SHA-256 hex",
        )?;
        ensure(
            field("objectDigest").and_then(Value::as_str) == Some(expected),
            "Expected object digest mismatch",
        )?;
        checked.push(member("objectDigest", text(expected)));
    }
    if let Some(expected) = expect.epoch {
        ensure(
            expected > 0 && expected <= MAX_SAFE_INTEGER_I64,
            "Expected epoch must be a positive safe integer",
        )?;
        ensure(
            safe_integer(field("authorityEpoch")) == Some(expected),
            "Expected authority epoch mismatch",
        )?;
        checked.push(member("authorityEpoch", num(expected)));
    }
    if let Some(expected) = &expect.object_id {
        let units = utf16_len(expected);
        ensure(
            units > 0 && units <= MAX_OBJECT_ID_UNITS,
            "Invalid expected object ID",
        )?;
        ensure(
            payload.get("objectId").and_then(Value::as_str) == Some(expected),
            "Expected object ID mismatch",
        )?;
        checked.push(member("objectId", text(expected)));
    }
    Ok(Value::Object(checked))
}

fn verify_single(
    input: &Value,
    key: &TrustedKey,
    external_checkpoint: Option<&Value>,
    expect: &Expectations,
) -> Result<Value, VerifyError> {
    ensure(
        !external_checkpoint.is_some_and(Value::is_truthy),
        "A chain export is required with an external checkpoint",
    )?;
    let payload = key.verify_packet(input)?;
    let binding = expect.any();
    let checked = if binding {
        Some(expected_bindings(payload, expect)?)
    } else {
        None
    };
    let mut result = vec![
        member("valid", Value::Bool(true)),
        member("type", text("signed-packet")),
        member("keyId", input.get("keyId").cloned().unwrap_or(Value::Null)),
        member("bindingVerified", Value::Bool(binding)),
    ];
    if let Some(checked) = checked {
        result.push(member("expectedBindings", checked));
    }
    result.push(member(
        "limitations",
        Value::Array(vec![text(LIMIT_SIGNATURE), text(LIMIT_BINDINGS)]),
    ));
    Ok(Value::Object(result))
}

fn verify_record(
    record: &Value,
    index: usize,
    head_hash: &str,
    key: &TrustedKey,
) -> Result<(), VerifyError> {
    let payload = key.verify_packet(record)?;
    ensure(
        matches!(payload, Value::Object(_)),
        "Invalid record payload",
    )?;
    // Record n (1-based) must carry sequence n. Indices are bounded by MAX_RECORDS.
    let expected_sequence = i64::try_from(index + 1).ok();
    ensure(
        expected_sequence.is_some() && safe_integer(payload.get("sequence")) == expected_sequence,
        &format!("Sequence discontinuity at record {}", index + 1),
    )?;
    ensure(
        payload.get("previousHash").and_then(Value::as_str) == Some(head_hash),
        &format!("Previous hash mismatch at record {}", index + 1),
    )?;
    ensure(
        non_empty_string(payload.get("eventId")) && non_empty_string(payload.get("eventType")),
        "Invalid evidence event",
    )?;
    let non_negative = |name: &str| safe_integer(payload.get(name)).is_some_and(|n| n >= 0);
    ensure(
        non_negative("timestamp") && non_negative("epoch"),
        "Invalid evidence time or epoch",
    )
}

fn verify_chain(
    input: &Value,
    records: &[Value],
    key: &TrustedKey,
    external_checkpoint: Option<&Value>,
) -> Result<Value, VerifyError> {
    exact_members(input, &["records", "checkpoint"])?;
    ensure(
        records.len() <= MAX_RECORDS,
        "Evidence export exceeds verifier record limit",
    )?;
    // hashes[i] is the chain head after i records; hashes[0] is the genesis value.
    let mut hashes: Vec<String> = Vec::with_capacity(records.len() + 1);
    hashes.push(GENESIS.to_owned());
    for (index, record) in records.iter().enumerate() {
        verify_record(record, index, &hashes[index], key)?;
        hashes.push(digest(record)?);
    }
    let head_hash = hashes[records.len()].clone();
    let supplied = checkpoint_payload(input.get("checkpoint").unwrap_or(&Value::Null), key)?;
    let length = i64::try_from(records.len())
        .map_err(|_| VerifyError::protocol("Evidence export exceeds verifier record limit"))?;
    ensure(
        supplied.sequence == length && supplied.head_hash == head_hash,
        "Export checkpoint does not match chain head",
    )?;
    let external = external_checkpoint.filter(|v| v.is_truthy());
    if let Some(saved) = external {
        let saved = checkpoint_payload(saved, key)?;
        ensure(
            saved.sequence <= length,
            "Chain truncated before externally saved checkpoint",
        )?;
        // saved.sequence is non-negative and no larger than records.len(), so it indexes hashes.
        let position = usize::try_from(saved.sequence).unwrap_or(usize::MAX);
        ensure(
            hashes.get(position).is_some_and(|h| *h == saved.head_hash),
            "Chain conflicts with externally saved checkpoint",
        )?;
    }
    let length_value = num(length);
    Ok(Value::Object(vec![
        member("valid", Value::Bool(true)),
        member("type", text("evidence-chain")),
        member("records", length_value),
        member("headHash", text(&head_hash)),
        member("checkpointVerified", Value::Bool(true)),
        member(
            "externalCheckpointVerified",
            Value::Bool(external.is_some()),
        ),
        member(
            "limitations",
            Value::Array(vec![
                text(LIMIT_AUTHENTICITY),
                text(if external.is_some() {
                    LIMIT_WITH_CHECKPOINT
                } else {
                    LIMIT_WITHOUT_CHECKPOINT
                }),
                text(LIMIT_HARDWARE),
            ]),
        ),
    ]))
}

/// Verifies a signed packet or an evidence-chain export under `trusted_jwk`.
///
/// `external_checkpoint` follows JavaScript truthiness (a falsy JSON value counts as absent),
/// matching the reference. Returns the result object in reference member order.
///
/// # Errors
/// Any failed check; see the specification for the complete list and order.
pub fn verify_evidence(
    input: &Value,
    trusted_jwk: &Value,
    external_checkpoint: Option<&Value>,
    expect: &Expectations,
) -> Result<Value, VerifyError> {
    let key = TrustedKey::from_jwk(trusted_jwk)?;
    match input.get("records") {
        Some(Value::Array(records)) => {
            ensure(
                !expect.any(),
                "Expected object bindings apply to a single release receipt; verify the chain separately",
            )?;
            verify_chain(input, records, &key, external_checkpoint)
        }
        _ => verify_single(input, &key, external_checkpoint, expect),
    }
}
