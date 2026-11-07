//! An offline snapshot bridge, not a login provider or a release authority.
//! Uses the actual pinned NEXORA signed-head and Merkle implementation.
//! Source evidence is independently verified under an operator-supplied SIEPMU key
//! and retained checkpoint before sealing and again during verification.

use aip_crypto::{merkle_leaf, sha256};
use aip_nexora::{verify_signed_head, MerkleTree, NexoraSigner, NexoraTrustAnchors, SignedHead};
use aip_types::canonical::{put_bytes, put_domain, put_str};
use aip_types::{AlgorithmId, Signature};
use serde::{Deserialize, Serialize};
use siepmu_evidence_verify::canonical::canonical;
use siepmu_evidence_verify::evidence::{exact_members, verify_evidence, Expectations};
use siepmu_evidence_verify::json::{parse, Value};
use siepmu_evidence_verify::signature::TrustedKey;

pub const PROFILE: &str = "SIEPMU-NEXORA-SNAPSHOT-v1";
pub const MAX_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const LEAF_DOMAIN: &str = "SYNTRIASS/SIEPMU/NEXORA/SNAPSHOT/v1";
const LOG_DOMAIN: &str = "SYNTRIASS/SIEPMU/NEXORA/SNAPSHOT-LOG/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub profile: String,
    pub authority_key_id: String,
    /// Canonical source bytes, kept distinct from AIP execution-proof formats.
    pub evidence: String,
    pub head: SignedHead,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub signer_id: String,
    pub key_version: u32,
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningMaterial {
    pub anchor: Anchor,
    pub private_key: [u8; 32],
}

fn ensure(ok: bool, code: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(code.to_owned())
    }
}

/// Strict parsing also rejects duplicate keys at every nesting level. Re-serialization
/// equality rejects extra members inside upstream structs without changing upstream code.
pub fn strict_json<T>(text: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    ensure(text.len() <= MAX_FILE_BYTES, "INPUT_TOO_LARGE")?;
    parse(text).map_err(|_| "INVALID_JSON".to_owned())?;
    let parsed: T = serde_json::from_str(text).map_err(|_| "INVALID_SCHEMA".to_owned())?;
    let original: serde_json::Value = serde_json::from_str(text).map_err(|_| "INVALID_JSON")?;
    let encoded = serde_json::to_value(&parsed).map_err(|_| "INVALID_SCHEMA")?;
    ensure(original == encoded, "UNKNOWN_OR_MISSING_FIELDS")?;
    Ok(parsed)
}

fn anchors(anchor: &Anchor) -> Result<NexoraTrustAnchors, String> {
    ensure(
        !anchor.signer_id.is_empty() && anchor.signer_id.len() <= 128 && anchor.key_version > 0,
        "INVALID_ANCHOR",
    )?;
    Ok(NexoraTrustAnchors::new().trust(&anchor.signer_id, anchor.key_version, &anchor.public_key))
}

fn source(
    evidence: &str,
    trusted_key: &Value,
    retained_checkpoint: &Value,
) -> Result<(String, String, Value), String> {
    ensure(evidence.len() <= MAX_EVIDENCE_BYTES, "EVIDENCE_TOO_LARGE")?;
    let input = parse(evidence).map_err(|_| "INVALID_EVIDENCE_JSON")?;
    exact_members(&input, &["records", "checkpoint"]).map_err(|_| "CHAIN_EXPORT_REQUIRED")?;
    // An actual independently retained signed checkpoint is mandatory, never null.
    exact_members(retained_checkpoint, &["payload", "signature", "keyId"])
        .map_err(|_| "RETAINED_CHECKPOINT_REQUIRED")?;
    let result = verify_evidence(
        &input,
        trusted_key,
        Some(retained_checkpoint),
        &Expectations::default(),
    )
    .map_err(|e| format!("SOURCE_EVIDENCE_REJECTED: {}", e.message))?;
    let key = TrustedKey::from_jwk(trusted_key).map_err(|_| "INVALID_AUTHORITY_KEY")?;
    let bytes = canonical(&input).map_err(|_| "INVALID_CANONICAL_EVIDENCE")?;
    ensure(bytes.len() <= MAX_EVIDENCE_BYTES, "EVIDENCE_TOO_LARGE")?;
    Ok((bytes, key.key_id().to_owned(), result))
}

fn leaf(key_id: &str, evidence: &str) -> [u8; 32] {
    let mut bytes = Vec::new();
    put_domain(&mut bytes, LEAF_DOMAIN);
    put_str(&mut bytes, PROFILE);
    put_str(&mut bytes, key_id);
    put_bytes(&mut bytes, evidence.as_bytes());
    merkle_leaf(&bytes)
}

fn log_id(root: &[u8; 32]) -> [u8; 16] {
    let mut bytes = Vec::new();
    put_domain(&mut bytes, LOG_DOMAIN);
    bytes.extend_from_slice(root);
    let hash = sha256(&bytes);
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

pub fn seal(
    evidence: &str,
    trusted_key: &Value,
    retained_checkpoint: &Value,
    material: &SigningMaterial,
    issued_at_ms: u64,
) -> Result<Snapshot, String> {
    ensure(issued_at_ms <= 9_007_199_254_740_991, "INVALID_TIME")?;
    let (evidence, key_id, _) = source(evidence, trusted_key, retained_checkpoint)?;
    let trust = anchors(&material.anchor)?;
    let signer = NexoraSigner::new(
        &material.anchor.signer_id,
        material.anchor.key_version,
        &material.private_key,
        &material.anchor.public_key,
    )
    .map_err(|_| "INVALID_SIGNER")?;
    let mut tree = MerkleTree::new();
    tree.append_hash(leaf(&key_id, &evidence));
    let head = SignedHead {
        version: 1,
        log_id: log_id(&tree.root()),
        size: tree.size(),
        root: tree.root(),
        prev_head: [0; 32],
        issued_at_ms,
        signer_id: material.anchor.signer_id.clone(),
        key_version: material.anchor.key_version,
        signature: Signature {
            algorithm: AlgorithmId::Ed25519,
            signer_id: String::new(),
            timestamp: 0,
            nonce: [0; 16],
            payload_hash: [0; 32],
            signature_bytes: Vec::new(),
        },
    };
    let head = signer.resign(head).map_err(|_| "NEXORA_SIGNING_FAILED")?;
    verify_signed_head(&head, &trust).map_err(|_| "SIGNER_KEY_PAIR_MISMATCH")?;
    Ok(Snapshot {
        profile: PROFILE.to_owned(),
        authority_key_id: key_id,
        evidence,
        head,
    })
}

pub fn verify(
    snapshot: &Snapshot,
    trusted_key: &Value,
    retained_checkpoint: &Value,
    anchor: &Anchor,
) -> Result<serde_json::Value, String> {
    ensure(snapshot.profile == PROFILE, "UNSUPPORTED_PROFILE")?;
    ensure(
        snapshot.head.size == 1
            && snapshot.head.prev_head == [0; 32]
            && snapshot.head.issued_at_ms <= 9_007_199_254_740_991,
        "INVALID_SNAPSHOT_HEAD",
    )?;
    verify_signed_head(&snapshot.head, &anchors(anchor)?).map_err(|_| "NEXORA_HEAD_REJECTED")?;
    let (bytes, key_id, result) = source(&snapshot.evidence, trusted_key, retained_checkpoint)?;
    ensure(bytes == snapshot.evidence, "NON_CANONICAL_EVIDENCE")?;
    ensure(
        key_id == snapshot.authority_key_id,
        "AUTHORITY_KEY_MISMATCH",
    )?;
    let root = leaf(&key_id, &bytes);
    ensure(
        root == snapshot.head.root && log_id(&root) == snapshot.head.log_id,
        "COMMITMENT_MISMATCH",
    )?;
    let source_result: serde_json::Value =
        serde_json::from_str(&canonical(&result).map_err(|_| "SOURCE_RESULT_INVALID")?)
            .map_err(|_| "SOURCE_RESULT_INVALID")?;
    Ok(serde_json::json!({
        "valid": true,
        "profile": PROFILE,
        "scope": "HISTORICAL_EVIDENCE_AUTHENTICITY",
        "authorityKeyId": key_id,
        "nexoraHeadDigest": hex(&snapshot.head.digest()),
        "evidenceDigest": hex(&sha256(bytes.as_bytes())),
        "sourceVerification": source_result,
        "authorizesLogin": false,
        "authorizesRelease": false,
        "limitations": [
            "Authenticity is relative to independently supplied authority and NEXORA keys.",
            "Rollback detection is bounded by the independently retained SIEPMU checkpoint.",
            "Independent snapshots do not establish a continuous NEXORA log or current personnel status.",
            "A valid historical login event is not a fresh authentication challenge."
        ]
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
