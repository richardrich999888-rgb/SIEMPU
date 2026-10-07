# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

## Build versus buy decisions
| Need | Preferred | Why | Gate |
|---|---|---|---|
| Policy-epoch issuing transaction | KEEP INTERNAL | Custom invariant already exercised; central to differentiation | model & regression tests |
| Envelope/authenticated context format | KEEP INTERNAL but external review | protocol compatibility tightly coupled | cryptographer assessment |
| Endpoint crypto primitive implementations | USE vetted platform providers | never implement AES/ECDSA by hand | cross-provider conformance, SAG later |
| Cryptographic device integration | ADAPTER to standard interface | HSM vendor lock-in avoidance | PKCS#11 mechanism and key-custody test |
| Browser identity | FIDO2/WebAuthn as additive | resists phishing better than TOTP | browser support and recovery design |
| Policy engine | KEEP integrated short-term | OPA add-on adds failure and consistency boundaries | consider when complexity needs it |
| TLS/PKI | STANDARD LIBRARY + controlled issuer | mature transport infrastructure | authenticated ingress certificate tests |
| Audit storage | BUILD external checkpoint integration | gap is trust custody not blockchain | tamper/snapshot recovery tests |
| EDR/NDR/SIEM | USE separate defensive product | no need to write detection engine | redaction/privacy and CPU budget |
| Network simulation | tc/netem + Toxiproxy | deterministic, simple reproducible | repeatability and log hash |
| Vulnerability/SBOM | FIX existing CodeQL+Trivy first | current release blockers | exact-head all gates PASS |
| Military adaptor | BUILD synthetic neutral shell; sponsor interfaces external | unknown classified interface unavailable | authorised IAF interface owner |

## Hard requirements for adoption
Permit/restrictions of licenses including AGPL and non-commercial research licenses; export/import controls; no copyleft leakage into proprietary linking unless legally approved; vendor provenance; vulnerability advisory; supported OS/CPU; signed binary; secure offline mirror; key ownership; sponsor cryptographic acceptance. No weighted score overrides a failed hard gate.

## Supply chain flow
Pinned source and reproducible build recipe -> SBOM (app + image) -> SCA/CVE triage -> static/secret scans -> permission-minimal CI -> signed manifest/images (proposed) -> offline trust roots -> acceptance verification + rollback path. Exclude private annexures, .env, secrets and operational materials from public repo.
