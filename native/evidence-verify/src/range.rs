//! SIEPMU-EVIDENCE-RANGE-v1: verification of an evidence range that extends an already-trusted
//! chain head (`spec/SIEPMU-EVIDENCE-RANGE-v1.md`, ADR-014).
//!
//! Reference: `verifyEvidenceRange` in `apps/verifier/verify.mjs`. Pure: parsed values in, a
//! result value or an error out; no I/O. The base position is trusted input (an independently
//! retained, previously verified head); this module proves only that the records extend it.
//! Cost is linear in the number of records in the range, independent of the base sequence.

use crate::error::VerifyError;
use crate::evidence::{
    checkpoint_payload, ensure, exact_members, is_lower_hex64, member, num, safe_integer, text,
    verify_record, GENESIS, LIMIT_AUTHENTICITY, LIMIT_HARDWARE, MAX_SAFE_INTEGER_I64,
};
use crate::json::Value;
use crate::signature::{digest, TrustedKey};

/// Default maximum number of records in one range (reference `MAX_RANGE_RECORDS`).
pub const MAX_RANGE_RECORDS: usize = 4096;

const LIMIT_BASE: &str = "The range proves extension of the supplied base only; the base must come from an independently retained, previously verified head.";

/// Verifies `{ base: { sequence, headHash }, records, checkpoint }` under `trusted_jwk`.
///
/// Checks, in the reference order: trusted key; exact members of the input and of `base`;
/// base sequence (safe, non-negative), base hash (lowercase 64-hex) and genesis consistency;
/// `records` is an array within `max_records`; the end sequence is a safe integer; every
/// record links to its predecessor; the signed checkpoint names exactly the resulting head.
///
/// # Errors
/// Any failed check, with the message fixed by the specification.
pub fn verify_evidence_range(
    input: &Value,
    trusted_jwk: &Value,
    max_records: usize,
) -> Result<Value, VerifyError> {
    let key = TrustedKey::from_jwk(trusted_jwk)?;
    exact_members(input, &["base", "records", "checkpoint"])?;
    let base = input.get("base").unwrap_or(&Value::Null);
    exact_members(base, &["sequence", "headHash"])?;
    let from = safe_integer(base.get("sequence")).filter(|n| *n >= 0);
    let from = from.ok_or_else(|| VerifyError::protocol("Invalid range base sequence"))?;
    ensure(
        is_lower_hex64(base.get("headHash")),
        "Invalid range base hash",
    )?;
    let base_hash = base
        .get("headHash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    ensure(
        (from == 0) == (base_hash == GENESIS),
        "Inconsistent range base genesis reference",
    )?;
    let Some(Value::Array(records)) = input.get("records") else {
        return Err(VerifyError::protocol("Range records must be an array"));
    };
    ensure(
        max_records > 0 && records.len() <= max_records,
        "Evidence range exceeds record limit",
    )?;
    // Every expected sequence must be a safe integer (reference rationale: no divergence at 2^53).
    let count = i64::try_from(records.len())
        .map_err(|_| VerifyError::protocol("Evidence range exceeds record limit"))?;
    let to = from
        .checked_add(count)
        .filter(|n| *n <= MAX_SAFE_INTEGER_I64)
        .ok_or_else(|| VerifyError::protocol("Range end sequence is not a safe integer"))?;
    let mut head_hash = base_hash.to_owned();
    for (sequence, record) in (from + 1..=to).zip(records) {
        verify_record(record, sequence, &head_hash, &key)?;
        head_hash = digest(record)?;
    }
    let supplied = checkpoint_payload(input.get("checkpoint").unwrap_or(&Value::Null), &key)?;
    ensure(
        supplied.sequence == to && supplied.head_hash == head_hash,
        "Range checkpoint does not match range head",
    )?;
    Ok(Value::Object(vec![
        member("valid", Value::Bool(true)),
        member("type", text("evidence-range")),
        member("fromSequence", num(from)),
        member("toSequence", num(to)),
        member("records", num(count)),
        member("headHash", text(&head_hash)),
        member("checkpointVerified", Value::Bool(true)),
        member(
            "limitations",
            Value::Array(vec![
                text(LIMIT_AUTHENTICITY),
                text(LIMIT_BASE),
                text(LIMIT_HARDWARE),
            ]),
        ),
    ]))
}
