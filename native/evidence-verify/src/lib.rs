//! Independent Rust verifier for SIEPMU signed evidence.
//!
//! Implements SIEPMU-CJSON-v1 (`spec/SIEPMU-CJSON-v1.md`) and the general mode of
//! SIEPMU-EVIDENCE-v1 (`spec/SIEPMU-EVIDENCE-v1.md`): a single signed packet with optional
//! expected release bindings, or a hash-chained export with its signed checkpoint and an
//! optional externally saved checkpoint. It also implements SIEPMU-EVIDENCE-RANGE-v1
//! (`spec/SIEPMU-EVIDENCE-RANGE-v1.md`): a range of records extending a trusted head (ADR-014).
//!
//! The crate verifies statements under an independently supplied public key. It holds no
//! private keys, performs no network I/O and does not establish current authorization.

pub mod base64url;
pub mod canonical;
pub mod cli;
pub mod error;
pub mod evidence;
pub mod json;
pub mod output;
pub mod range;
pub mod signature;
