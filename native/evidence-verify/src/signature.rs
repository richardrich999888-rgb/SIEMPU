//! Trusted P-256 key handling and ECDSA verification over canonical payloads.
//!
//! Contract (`spec/SIEPMU-EVIDENCE-v1.md` §4): the trusted key is a public EC JWK on P-256 with
//! canonical 32-byte `x`/`y`; its key ID is the lowercase hex SHA-256 of the SIEPMU-CJSON-v1
//! encoding of the complete JWK object; a signature is a 64-byte IEEE P1363 `r || s` pair over
//! SHA-256 of the canonical payload bytes.

use crate::base64url;
use crate::canonical::canonical;
use crate::error::VerifyError;
use crate::json::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

/// Lowercase hexadecimal SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 0x0f)]));
    }
    out
}

/// SHA-256 hex digest of the canonical encoding of `value`.
///
/// # Errors
/// Propagates canonical-encoding failures with the reference message.
pub fn digest(value: &Value) -> Result<String, VerifyError> {
    Ok(sha256_hex(canonical(value)?.as_bytes()))
}

/// A validated trusted signing key.
#[derive(Debug)]
pub struct TrustedKey {
    key: VerifyingKey,
    key_id: String,
}

impl TrustedKey {
    /// Validates `jwk` in the reference order: type/curve/no private part, coordinates,
    /// curve point, then key ID derivation.
    ///
    /// # Errors
    /// Fails closed on any deviation from a public P-256 JWK.
    pub fn from_jwk(jwk: &Value) -> Result<Self, VerifyError> {
        let is_public_p256 = jwk.get("kty").and_then(Value::as_str) == Some("EC")
            && jwk.get("crv").and_then(Value::as_str) == Some("P-256")
            && jwk.get("d").is_none();
        if !is_public_p256 {
            return Err(VerifyError::protocol(
                "Trusted key must be public P-256 JWK",
            ));
        }
        let mut coordinates = [[0u8; 32]; 2];
        for (slot, name) in coordinates.iter_mut().zip(["x", "y"]) {
            let bytes = jwk
                .get(name)
                .and_then(Value::as_str)
                .and_then(base64url::decode_canonical)
                .filter(|b| b.len() == 32)
                .ok_or_else(|| VerifyError::protocol("Invalid trusted key coordinate"))?;
            slot.copy_from_slice(&bytes);
        }
        let point = EncodedPoint::from_affine_coordinates(
            &coordinates[0].into(),
            &coordinates[1].into(),
            false,
        );
        // Rejects points not on the curve and the identity, as Node's createPublicKey does
        // (message differs: implementation-specific input error).
        let key = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| VerifyError::input("Trusted key is not a valid P-256 public point"))?;
        let key_id = digest(jwk)?;
        Ok(Self { key, key_id })
    }

    /// The key ID packets must carry.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Verifies a signed packet `{payload, signature, keyId}` and returns its payload.
    ///
    /// Check order equals the reference: member set, key ID, canonical payload encoding,
    /// signature encoding, then the ECDSA equation.
    ///
    /// # Errors
    /// Fails closed with the reference message for every rejected packet.
    pub fn verify_packet<'a>(&self, packet: &'a Value) -> Result<&'a Value, VerifyError> {
        crate::evidence::exact_members(packet, &["payload", "signature", "keyId"])?;
        if packet.get("keyId").and_then(Value::as_str) != Some(self.key_id.as_str()) {
            return Err(VerifyError::protocol("Signing key ID mismatch"));
        }
        let payload = packet.get("payload").unwrap_or(&Value::Null);
        let message = canonical(payload)?;
        let raw = signature_bytes(packet.get("signature"))?;
        // A 64-byte string with r or s outside [1, n-1] cannot be a valid signature; Node's
        // verify returns false for it, so it maps to the same message here.
        let valid = Signature::from_slice(&raw)
            .is_ok_and(|sig| self.key.verify(message.as_bytes(), &sig).is_ok());
        if !valid {
            return Err(VerifyError::protocol("Signature invalid"));
        }
        Ok(payload)
    }
}

fn signature_bytes(value: Option<&Value>) -> Result<Vec<u8>, VerifyError> {
    let text = value
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or_else(|| VerifyError::protocol("Invalid signature encoding"))?;
    base64url::decode_canonical(text)
        .filter(|raw| raw.len() == 64)
        .ok_or_else(|| VerifyError::protocol("Invalid P1363 signature"))
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, TrustedKey};
    use crate::json::parse;

    // RFC 6979 A.2.5 P-256 public key (a published test key, not a credential).
    const RFC6979_X: &str = "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y";
    const RFC6979_Y: &str = "eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk";

    fn jwk(extra: &str) -> String {
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC6979_X}","y":"{RFC6979_Y}"{extra}}}"#)
    }

    #[test]
    fn sha256_matches_fips180_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn accepts_public_jwk_and_derives_canonical_key_id() {
        let key = TrustedKey::from_jwk(&parse(&jwk("")).unwrap()).unwrap();
        let expected = sha256_hex(
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{RFC6979_X}","y":"{RFC6979_Y}"}}"#)
                .as_bytes(),
        );
        assert_eq!(key.key_id(), expected);
    }

    #[test]
    fn rejects_private_wrong_curve_and_bad_coordinates() {
        let cases = [
            (jwk(r#","d":"AA""#), "Trusted key must be public P-256 JWK"),
            (
                jwk("").replace("P-256", "P-384"),
                "Trusted key must be public P-256 JWK",
            ),
            (
                jwk("").replace("\"EC\"", "\"OKP\""),
                "Trusted key must be public P-256 JWK",
            ),
            (
                jwk("").replace(RFC6979_X, "AAAA"),
                "Invalid trusted key coordinate",
            ),
            (
                jwk("").replace(RFC6979_Y, &format!("{RFC6979_Y}=")),
                "Invalid trusted key coordinate",
            ),
        ];
        for (text, message) in cases {
            assert_eq!(
                TrustedKey::from_jwk(&parse(&text).unwrap())
                    .unwrap_err()
                    .message,
                message
            );
        }
        assert_eq!(
            TrustedKey::from_jwk(&parse("[]").unwrap())
                .unwrap_err()
                .message,
            "Trusted key must be public P-256 JWK"
        );
    }

    #[test]
    fn rejects_off_curve_point() {
        let off = jwk("").replace(RFC6979_Y, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE");
        let err = TrustedKey::from_jwk(&parse(&off).unwrap()).unwrap_err();
        assert!(
            !err.parity,
            "off-curve rejection is an implementation-specific input error"
        );
    }
}
