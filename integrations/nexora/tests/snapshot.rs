use aip_crypto::generate_ed25519_keypair;
use aip_nexora::{leaf_hash, LeafKind, NexoraSigner};
use siepmu_evidence_verify::json::{parse, Value};
use siepmu_nexora_bridge::{
    seal, strict_json, verify, Anchor, SigningMaterial, Snapshot, MAX_EVIDENCE_BYTES,
};

fn fixture() -> (String, Value, Value, SigningMaterial) {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/vectors/evidence-v1.json")).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "accept-chain")
        .unwrap();
    let evidence = case["input"].as_str().unwrap().to_owned();
    let input: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    let checkpoint = parse(&input["checkpoint"].to_string()).unwrap();
    let key = parse(case["key"].as_str().unwrap()).unwrap();
    let pair = generate_ed25519_keypair();
    let material = SigningMaterial {
        anchor: Anchor {
            signer_id: "synthetic-nexora-custodian".to_owned(),
            key_version: 1,
            public_key: pair.public_key.try_into().unwrap(),
        },
        private_key: pair.private_key.try_into().unwrap(),
    };
    (evidence, key, checkpoint, material)
}

#[test]
fn frozen_siepmu_chain_is_sealed_by_real_nexora_and_never_grants_access() {
    let (evidence, key, checkpoint, material) = fixture();
    let snapshot = seal(&evidence, &key, &checkpoint, &material, 1700000000100).unwrap();
    let encoded = serde_json::to_string(&snapshot).unwrap();
    let decoded: Snapshot = strict_json(&encoded).unwrap();
    let result = verify(&decoded, &key, &checkpoint, &material.anchor).unwrap();
    assert_eq!(result["scope"], "HISTORICAL_EVIDENCE_AUTHENTICITY");
    assert_eq!(result["authorizesLogin"], false);
    assert_eq!(result["authorizesRelease"], false);
    assert_eq!(result["sourceVerification"]["valid"], true);
    assert_eq!(snapshot.head.size, 1);
}

#[test]
fn mutated_head_fields_and_untrusted_signer_or_key_version_fail_closed() {
    let (evidence, key, checkpoint, material) = fixture();
    let snapshot = seal(&evidence, &key, &checkpoint, &material, 1700000000100).unwrap();
    let changes: Vec<fn(&mut Snapshot)> = vec![
        |s| s.profile.push('x'),
        |s| s.authority_key_id.push('x'),
        |s| s.head.root[0] ^= 1,
        |s| s.head.log_id[0] ^= 1,
        |s| s.head.issued_at_ms += 1,
        |s| s.head.key_version += 1,
        |s| s.head.version += 1,
        |s| s.head.signer_id.push('x'),
        |s| s.head.prev_head[0] = 1,
        |s| s.head.size = 2,
        |s| s.head.signature.signature_bytes[0] ^= 1,
        |s| s.evidence = s.evidence.replace("synthetic vector", "forged authority"),
    ];
    for change in changes {
        let mut bad = snapshot.clone();
        change(&mut bad);
        assert!(verify(&bad, &key, &checkpoint, &material.anchor).is_err());
    }
    let (_, _, _, stranger) = fixture();
    assert!(verify(&snapshot, &key, &checkpoint, &stranger.anchor).is_err());
    let mut old_version = material.anchor.clone();
    old_version.key_version += 1;
    assert!(verify(&snapshot, &key, &checkpoint, &old_version).is_err());
}

#[test]
fn even_a_trusted_nexora_signer_cannot_substitute_an_aip_leaf_kind() {
    let (evidence, key, checkpoint, material) = fixture();
    let mut snapshot = seal(&evidence, &key, &checkpoint, &material, 1700000000100).unwrap();
    snapshot.head.root = leaf_hash(LeafKind::Reconciliation, snapshot.evidence.as_bytes());
    let signer = NexoraSigner::new(
        &material.anchor.signer_id,
        1,
        &material.private_key,
        &material.anchor.public_key,
    )
    .unwrap();
    snapshot.head = signer.resign(snapshot.head).unwrap();
    assert_eq!(
        verify(&snapshot, &key, &checkpoint, &material.anchor).unwrap_err(),
        "COMMITMENT_MISMATCH"
    );
}

#[test]
fn invalid_source_and_missing_or_forged_external_checkpoint_are_never_sealed() {
    let (evidence, key, checkpoint, material) = fixture();
    assert!(seal(&evidence, &key, &Value::Null, &material, 1).is_err());
    let mut bad: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    bad["records"][0]["payload"]["actorId"] = "forged-person".into();
    assert!(seal(&bad.to_string(), &key, &checkpoint, &material, 1).is_err());
    let packet = bad["checkpoint"].to_string();
    assert!(seal(&packet, &key, &checkpoint, &material, 1).is_err());
    let mut forged = bad["checkpoint"].clone();
    forged["payload"]["sequence"] = 99.into();
    assert!(seal(
        &evidence,
        &key,
        &parse(&forged.to_string()).unwrap(),
        &material,
        1
    )
    .is_err());
    assert!(seal(&evidence, &Value::Null, &checkpoint, &material, 1).is_err());
    assert!(seal(
        &" ".repeat(MAX_EVIDENCE_BYTES + 1),
        &key,
        &checkpoint,
        &material,
        1
    )
    .is_err());
}

#[test]
fn strict_input_rejects_unknown_nested_members_and_duplicate_keys() {
    let (evidence, key, checkpoint, material) = fixture();
    let snapshot = seal(&evidence, &key, &checkpoint, &material, 1).unwrap();
    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["head"]["signature"]["authorizesLogin"] = true.into();
    assert!(strict_json::<Snapshot>(&value.to_string()).is_err());
    let encoded = serde_json::to_string(&snapshot).unwrap();
    let duplicate = encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert_ne!(duplicate, encoded);
    assert!(strict_json::<Snapshot>(&duplicate).is_err());
    assert!(strict_json::<Snapshot>(&encoded.replace("\"size\":1", "\"size\":1e100")).is_err());
}

#[test]
fn mismatched_signing_keys_and_noncanonical_source_are_refused() {
    let (evidence, key, checkpoint, mut material) = fixture();
    let (_, _, _, other) = fixture();
    material.anchor.public_key = other.anchor.public_key;
    assert!(seal(&evidence, &key, &checkpoint, &material, 1).is_err());
    let snapshot = seal(&evidence, &key, &checkpoint, &other, 1).unwrap();
    let mut changed = snapshot;
    changed.evidence.push(' ');
    assert!(verify(&changed, &key, &checkpoint, &other.anchor).is_err());
}

#[test]
fn dependency_inventory_matches_every_locked_package_and_immutable_upstream_revision() {
    let lock = include_str!("../Cargo.lock");
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../dependencies.json")).unwrap();
    let digest: String = aip_crypto::sha256(lock.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(inventory["lockSha256"], digest);
    let packages = inventory["packages"].as_array().unwrap();
    let blocks: Vec<_> = lock.split("[[package]]").skip(1).collect();
    assert_eq!(packages.len(), blocks.len());
    for block in blocks {
        let field = |name: &str| {
            block.lines().find_map(|line| {
                line.strip_prefix(&format!("{name} = \""))
                    .and_then(|v| v.strip_suffix('"'))
            })
        };
        let name = field("name").unwrap();
        let version = field("version").unwrap();
        let source = field("source").unwrap_or("local workspace");
        let listed: Vec<_> = packages
            .iter()
            .filter(|p| p["name"] == name && p["version"] == version && p["source"] == source)
            .collect();
        assert_eq!(listed.len(), 1, "missing or duplicate {name} {version}");
        if let Some(checksum) = field("checksum") {
            assert_eq!(listed[0]["checksum"], checksum);
        }
        if source.starts_with("git+") {
            assert!(source.ends_with(inventory["upstreamRevision"].as_str().unwrap()));
            assert_eq!(listed[0]["license"], "LicenseRef-Proprietary");
        }
    }
}
