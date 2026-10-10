# 07 — Air-gap-native enclave architecture (Track E)

Status: **architecture and gap analysis.** What exists today is marked _implemented_ with its evidence; the
rest is design. A firewall-separated network is **not** an air gap and is never described as one here. Any
transfer across a classified or isolated boundary requires an authorised mechanism the sponsor provides;
this repository implements only synthetic, laboratory transfer workflows.

## 1. Enclave composition (one site, no external network)

```text
 ┌───────────────────────── isolated enclave (no route to the Internet) ─────────────────────────┐
 │  Endpoints ──TLS/mTLS──► Gateway ──► Authority ◄──mTLS──► Custodian (separate host + key)   │
 │                                 └──► Relay (ciphertext)       Collector (redacted telemetry)  │
 │  Local identity + MFA   Local PKI (offline root)   Local time source   Local package mirror   │
 └───────────────────────────────▲──────────────────────────────────────────────────────────────┘
                                 │ authorised transfer only (sponsor mechanism; lab: signed media)
                         Import/export station (outside or at the boundary)
```

## 2. Requirement-by-requirement status

| Requirement                              | Status                             | Evidence / design                                                                                                       |
| ---------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Local identity and MFA                   | Implemented                        | Password scrypt + TOTP in authority; no external IdP                                                                    |
| Local authorization                      | Implemented                        | Authority policy, release transaction                                                                                   |
| Local keys                               | Implemented (software)             | Lab PKI `deployment/secure/lab-pki.mjs`; offline root ceremony not defined                                              |
| Encrypted storage                        | Partial                            | Ciphertext at relay; TOTP seeds encrypted; authority DB not encrypted at rest                                           |
| Local monitoring                         | Implemented                        | Collector, admin console                                                                                                |
| Signed offline installation              | Implemented                        | `packages/release/offline.mjs`; tampered and rollback bundles rejected (mission step 17)                                |
| Signed updates, rollback prevention      | Implemented (bundle version check) | Same; no hardware monotonic counter                                                                                     |
| Controlled import/export                 | Not implemented                    | Design §3                                                                                                               |
| Independent evidence custody             | Implemented                        | Separate custodian host and key; incremental (ADR-014)                                                                  |
| Recovery without Internet                | Implemented (lab)                  | Encrypted backup/restore; quarantine until custody confirms; no anchor-reset ceremony                                   |
| No dependency on foreign SaaS at runtime | Implemented                        | Zero runtime npm deps; no external calls at runtime                                                                     |
| Time source                              | Gap                                | Leases and TOTP need bounded clock skew; enclave needs a local reference (GNSS-disciplined or manual, sponsor decision) |

## 3. Controlled import/export (design, laboratory only)

1. **Export**: produce a signed, content-addressed bundle (`manifest.json` with SHA-256 of every file, signed
   by an export key separate from the authority key; evidence range + checkpoint for audit transfer). Media is
   write-once where available.
2. **Transfer**: physical media through the sponsor's authorised process. Not modelled in code.
3. **Import**: verify manifest signature against a pinned import trust anchor, verify every digest, reject
   unknown files, enforce monotonic bundle version, quarantine to a staging area, then apply. This reuses the
   offline-bundle verifier pattern already implemented for software updates.
4. **Evidence transfer**: an evidence range plus checkpoint (SIEPMU-EVIDENCE-RANGE-v1) lets an external auditor
   verify a period's decisions against a previously retained checkpoint without exporting the whole history.
   This is a direct use of the D-T5-01 work.

## 4. Supply of software into the enclave

Offline npm-free runtime (Node binary + `dist/`), digest-pinned base image or native install, SBOM in the
bundle, signatures verified on import. Reproducible-build evidence is **not** established yet (build output
has not been independently rebuilt and compared byte-for-byte); this is required before claiming that an
enclave runs exactly the reviewed source.

## 5. Failure and recovery in isolation

| Failure                     | Behaviour                                                                                                                                                  |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Custodian down              | Authority returns 503 for protected routes (fail closed); resumes on return                                                                                |
| Authority DB restored older | Quarantined (rollback); needs dual-controlled anchor reset (gap)                                                                                           |
| Custodian DB lost           | Authority cannot obtain a lease; re-bootstrap requires an explicit operator ceremony (`allowBootstrap`), recorded as evidence — ceremony not yet specified |
| Relay down                  | Submission refused, nothing half-written (Demo 4)                                                                                                          |
| Clock drift                 | Leases/TOTP fail closed beyond tolerance                                                                                                                   |

## 6. Secure BOSS Linux profile (future, not tested)

Requirements for a sovereign OS profile: Node 24 runtime available or built from source; OpenSSL ≥ 3.5 for the
laboratory PQC path; kernel with namespaces for the testbed. No test has been run on Secure BOSS Linux; any
compatibility statement must wait for an executed run with recorded package versions.
