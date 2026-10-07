# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

| ID | Risk | Severity before mitigation | Evidence | Mitigation and owner |
|---|---|---|---|---|
| RISK-01 | HEAD image has unresolved high/critical scanner findings | CRITICAL | Trivy HEAD run 37678323924: Debian 60, Node 12 findings | DevSecOps: save JSON/SBOM, dedupe, refresh base, assess fixed/unfixed CVEs, rescan |
| RISK-02 | CodeQL SARIF gate fails parsing | HIGH | “Finding does not resolve to an unambiguous rule” | AppSec: inspect SARIF original, fix rule ID mapping, unit tests, don't bypass alerts |
| RISK-03 | SAG-graded crypto not approved | CRITICAL programme | public PS-69 requirement | IAF sponsor authorised route; provider seam with fail-closed interoperability |
| RISK-04 | Single SQLite authority failure/rollback | HIGH | same-host design | signed off-host checkpoint, restore and rollback adversarial tests; HA strategy only after invariant proof |
| RISK-05 | software/browser key theft | HIGH | software device proof + vault | FIDO2/TPM/HSM experiment, threat-driven endpoint management |
| RISK-06 | stale offline grants / revocation ambiguity | HIGH | revocation cannot recall old keys | document issuance linearization, isolation tests, recipient re-auth |
| RISK-07 | no approved military legacy connector | HIGH | synthetic /api/integration/validate only | independent mock and IAF-SPONSOR-REQUIRED interface register |
| RISK-08 | default HTTP not public Internet ready | CRITICAL | deployment docs | TLS/mTLS, trust anchor/pinning, certificate-expiry negative tests |
| RISK-09 | telemetry leaks metadata/keys | HIGH | logging/alerts exist | strict allowlist, adversarial log capture, SOC redaction |
| RISK-10 | capacity unknown | MEDIUM | 30 sequential loopback objects | multi-node WAN load tests, official SLA clarification |
| RISK-11 | supply chain/toolchain sovereignty | MEDIUM/HIGH | public GitHub and registries currently used | offline signed mirrors, licence/export/vendor review |
| RISK-12 | hardware vendors unsupported in India | MEDIUM | no verified quotes | supplier RFI, backup vendor, spare/firmware support |
| RISK-13 | no independent assurance or witnessed testbed | HIGH | only local recorded evidence | independent assessor, documented testbed, evidence signature |
| RISK-14 | diverged branches produce silent loss | HIGH | feature vs HPSC one commit divergence | explicit conflict review, cherry-pick or merge with tests |
| RISK-15 | applicant commitments not reconciled | HIGH | annexures unavailable | SYNTRIASS owner baseline from authoritative signed submission |
Risk status: open. Numeric risk probabilities would be invented without empirical frequency data.
