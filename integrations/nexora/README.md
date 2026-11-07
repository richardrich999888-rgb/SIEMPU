# SIEPMU / VANIAN NEXORA evidence bridge

Optional laboratory operator tool. It connects actual SIEPMU signed authentication
and exchange evidence to the pinned VANIAN NEXORA implementation. It runs offline
after building and provisioning its inputs. It does not issue login sessions,
authenticate a live person, evaluate release policy or release document keys.

## What is connected

The bridge imports `aip-nexora`, `aip-crypto` and `aip-types` directly from
`richardrich999888-rgb/AIP-agent-identity-protocol-` at immutable revision
`4ee39f359430277a48c34b957609104d3cf781f6`. It calls NEXORA's `MerkleTree`,
`NexoraSigner` and `verify_signed_head`; it does not recreate their cryptography.
The source export is checked by `siepmu-evidence-verify` before sealing and again
during verification, under an independently supplied authority key and checkpoint.

| Step                      | Meaning                                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Existing SIEPMU login     | Password/TOTP plus fresh signed device challenge; current user/device status remains enforced                           |
| Protected evidence export | Admin/auditor downloads the signed chain through existing `/api/evidence/export`                                        |
| Source verification       | Check signatures, sequence, links and an independently retained checkpoint                                              |
| NEXORA sealing            | Commit the canonical export and authority key ID to a domain-separated snapshot leaf; sign its head with the NEXORA key |
| Offline verification      | Independently check both authority and NEXORA keys, source evidence and snapshot binding                                |

The new container format is `SIEPMU-NEXORA-SNAPSHOT-v1`, with an unchanged NEXORA
v1 signed head over a single leaf. Its leaf uses the distinct
`SYNTRIASS/SIEPMU/NEXORA/SNAPSHOT/v1` domain and AIP's length-prefixed encoder.
The log ID is a domain-separated hash of that leaf, truncated to 16 bytes.
The profile requires size 1 and a zero previous head. These are independent sealed
snapshots, not an append-only NEXORA log. Existing SIEPMU custody remains responsible
for continuity; rollback detection is bounded by the retained checkpoint supplied.

SIEPMU evidence is never relabelled as an AIP execution proof or reconciliation.
The existing AIP `nexora-verify` command expects AIP execution bundles; use this
bridge's `verify` command for the SIEPMU snapshot profile.

## Operator workflow

Build with Rust 1.97.0 (the tested toolchain). The first dependency retrieval needs
network access. This tool is separate from the ordinary exchange image and its
locked dependency graph is audited independently. The [dependency inventory](dependencies.json) records exact versions, registry checksums, source revisions and manifest licence declarations.

```sh
npm run build:nexora
mkdir -p .data/nexora
chmod 700 .data/nexora
integrations/nexora/target/release/siepmu-nexora-bridge init \
  .data/nexora/signer-private.json .data/nexora/nexora-public.json \
  laboratory-custodian 1
```

The operator places the protected evidence export, independently trusted authority
public JWK and independently retained signed checkpoint in the paths below. Obtain
the retained checkpoint from the separately maintained custody/verification record;
copying the checkpoint from an untrusted export adds no independent rollback bound.
Distribute the public NEXORA anchor through an independently trusted channel.

```sh
integrations/nexora/target/release/siepmu-nexora-bridge seal \
  .data/nexora/evidence.json .data/nexora/authority-public.json \
  .data/nexora/retained-checkpoint.json .data/nexora/signer-private.json \
  .data/nexora/snapshot.json

integrations/nexora/target/release/siepmu-nexora-bridge verify \
  .data/nexora/snapshot.json .data/nexora/authority-public.json \
  .data/nexora/retained-checkpoint.json .data/nexora/nexora-public.json
```

Files are created exclusively with owner-only permissions. Existing files are never
overwritten. Symlink/special-file inputs, non-private signing files, oversized input,
unknown members and duplicate JSON keys are rejected. If `init` creates the private
file but cannot create the public anchor, it reports failure and retains the private
file for operator recovery; it never prints private material.

The tool currently requires Unix file semantics. Source evidence is limited to
4 MiB and files to 16 MiB. The output says `HISTORICAL_EVIDENCE_AUTHENTICITY`,
`authorizesLogin: false` and `authorizesRelease: false`. A valid older login record
does not demonstrate present key possession or current personnel status. Repeated
offline verification of historical evidence is allowed; it is not a replayable login.

## Key and licensing boundary

The laboratory signer uses a software Ed25519 key; hardware custody, reliable
wall-clock time, independent assessment and operational approval are not established.
The snapshot can contain sensitive identity/operational metadata from its source,
so retain its admin/auditor access and handling restrictions. It excludes endpoint
private keys, passwords, MFA secrets and session tokens by using the existing
redacted evidence export; acceptance tests check those exclusions.

The bridge source follows the repository's Apache-2.0 licence. Referenced VANIAN
crates declare `LicenseRef-Proprietary`; no upstream source is copied or relicensed.
Treat distribution of a linked binary as subject to those upstream rights. The
optional integration is excluded from Docker and signed offline releases, and it
does not add an npm dependency to the application.

## Verification

```sh
cargo fmt --manifest-path integrations/nexora/Cargo.toml --all --check
cargo clippy --manifest-path integrations/nexora/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path integrations/nexora/Cargo.toml --locked
cargo audit --file integrations/nexora/Cargo.lock --deny warnings
npm run build:nexora
npm run test:nexora
```

`SIEPMU_NEXORA_BRIDGE` may point tests at an already built binary. Tests exercise
real authority login/binding events, offline verification with the authority closed,
altered evidence, wrong trust roots, unknown schemas, stale checkpoint bounds,
revocation, private-file permissions, symlinks and overwrite refusal. NEXORA proofs
are explicitly tested as invalid substitutes for sessions and device challenges.

Personnel credential federation remains a separate integration task requiring an
issuer/enrollment mapping, approved trust roots, key lifecycle and freshness rules.
This bridge makes no TRL advancement or operational qualification claim.
