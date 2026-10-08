//! Splits verifier cost into parse, canonical+hash and ECDSA verification for one input file.
//! Usage: cargo run --release --example profile -- CHAIN.json KEY.json
use siepmu_evidence_verify::canonical::canonical;
use siepmu_evidence_verify::json::{parse, Value};
use siepmu_evidence_verify::signature::{sha256_hex, TrustedKey};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let text = std::fs::read_to_string(&args[0]).expect("input");
    let key = TrustedKey::from_jwk(
        &parse(&std::fs::read_to_string(&args[1]).expect("key")).expect("key json"),
    )
    .expect("key");
    let t = Instant::now();
    let input = parse(&text).expect("json");
    let parse_ms = t.elapsed().as_secs_f64() * 1e3;
    let Some(Value::Array(records)) = input.get("records") else {
        panic!("chain expected")
    };
    let t = Instant::now();
    for r in records {
        let _ = sha256_hex(canonical(r).expect("canonical").as_bytes());
    }
    let hash_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    for r in records {
        key.verify_packet(r).expect("valid");
    }
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    println!("records={} parse_ms={parse_ms:.1} canonical_hash_ms={hash_ms:.1} verify_packet_ms={verify_ms:.1} per_verify_us={:.1}", records.len(), verify_ms * 1e3 / f64::from(u32::try_from(records.len()).expect("record count fits u32")));
}
