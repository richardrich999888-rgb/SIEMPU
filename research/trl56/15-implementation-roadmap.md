# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

## Dependencies, not invented iDEX deadlines
| Phase | Entry | Work | Exit |
|---|---|---|---|
| P0 baseline (est. 1–2 engineering weeks) | repo write and sponsor context | freeze SHAs, branch divergence review, reconcile filed annexures/requirements, triage CI blockers | clean candidate + documented source digest + preliminary sponsor register |
| P1 relevant lab (est. 2–4 weeks, excludes equipment lead time) | P0 + lab approval | TLS, test VLANs, netem, telemetry and synthetic adapter; source-tagged evidence agent | deterministic multi-unit environment and signed test inventory |
| P2 CTE TRL5 validation (est. 3–6 weeks) | P1 environment + requirements | T5-01–08, off-host evidence, remediation/regression, independent witness | complete CTE-specific relevant-environment evidence (not self-declared TRL) |
| P3 representative TRL6 engineering (est. 6–12+ weeks) | P2 and sponsor config | multiple hosts, hardware crypto/auth, mature PKI/TLS, mock/authorised integration, ops/runbooks | representative prototype with documented unresolved sponsor blockers |
| P4 TRL6 demo (est. 2–4 weeks) | P3 & acceptance plan | live E2E story, chaos recovery, security/performance and independent review | reviewer package + clear pass/fail and sponsor decision |
| P5 qualification later | P4 | external grading, formal QA, provisioning, supply chain, possible HA | only formal acceptance evidence supports claims |

Durations are internal rough staffing assumptions and exclude agency access/procurement/permit lead time; they are not iDEX milestones. Roles: system architect, crypto/security engineer, client/backend engineer, network test lead, independent V&V, DevSecOps, procurement liaison. Every phase needs requirement IDs, owner, SHA, acceptance metric, evidence path and exit authority.

## Top twenty action priorities
1 Triaged Trivy; 2 fix CodeQL SARIF gate; 3 exact-head native+browser+container release; 4 branch divergence merge review; 5 reconcile original submitted annexures; 6 sponsor requirements and minimum CTE list; 7 security-reviewed TLS/mTLS; 8 separate physical/virtual lab networks; 9 deterministic netem profiles; 10 key provider seam; 11 SAG/IAF question dossier; 12 independent checkpoint; 13 rollback/restore negative tests; 14 offline/revocation WAN matrix; 15 FIDO2/TPM proof; 16 independent synthetic adapter; 17 redacted monitoring pipeline; 18 load/fanout experiments; 19 signed build provenance/offline release; 20 independent security/TRL test witness.
