# PR #15 / PR #16 reconciliation matrix

Base `main` `ad80210`. PR #15 `codex/siepmu-trl5-trl6-engineering` `32b4a1c`.
PR #16 `codex/siepmu-q-agile` `a4abc80`. Integration branch
`claude/siepmu-engineering-recovery-3nwgc8`. Decision record: [ADR-006](../decisions/ADR-006-reconciliation-base.md).

Measured on 2026-10-08: PR #15 changes 120 files and PR #16 changes 133. They share 84 changed
paths: 61 byte-identical, 23 divergent. 34 paths exist only in PR #15 and 48 only in PR #16.

## Root cause of PR #16 CI failure

Five PR #16 files contain invalid UTF-8. Re-encoding the damaged spans as base64 shows tool-output
truncation markers ("…105 tokens truncated…") and text from unrelated modules, so the
publication path base64-decoded mixed content. Hosted run 37716985109 (native: check, lint,
format, coverage) and 37716985101 (`sarif-gate.test.mjs`; CodeQL gate `SyntaxError` in
`scripts/sarif-gate.mjs`) are fully explained by these files. The container job was skipped
because `native` failed. Reproduced locally on Node 24.21.0 with identical gate outcomes.

| File                                       | Recovery                                                                                 |
| ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `scripts/sarif-gate.mjs`                   | PR #15 version (intact, same function)                                                   |
| `docs/deployment.md`, `docs/testing.md`    | PR #15 versions                                                                          |
| `packages/pqc-lab/envelope.mjs`            | Not recoverable after byte 3373; no module imported it. Rewritten in `cfdaae1` (ADR-010) |
| `research/defence-comparison/sources.json` | D01–D03 exact; D04 partial; D05–D15 flagged `RECORD_LOST_IN_PUBLICATION`                 |

Prevention: `scripts/text-integrity.mjs` (run by `npm run check`) detects all five.

## Divergent shared files (23)

| File                                                     | Taken                                                          | Reason                                                                                    |
| -------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`                               | PR #15 + new `pqc-lab` job, `claude/**` push trigger           | PR #16 deleted the netem testbed job and engineering evidence step                        |
| `apps/admin-console/admin.mjs`                           | PR #16                                                         | Strict superset: atomic role+duty update, observations panel, checkpoint signature status |
| `apps/unit-client/browser-check.mjs`                     | PR #16                                                         | Adds Chromium shell-upgrade and role-transition checks                                    |
| `apps/unit-client/sw.js`                                 | Merged                                                         | PR #16 immutable cache-first generations; cache v6 (ADR-007)                              |
| `apps/verifier/verify.mjs`                               | PR #15 + v3 crypto provenance (`cfdaae1`)                      | PR #16 dropped `objectSchemaVersion` checks                                               |
| `deployment/secure/lab-pki.mjs`                          | PR #15                                                         | PR #16 rewrite drops CRL, revocation, expiry issuance used by TLS tests                   |
| `docs/api.openapi.json`                                  | PR #15                                                         | PR #16 lacks PR #15 routes (authorize, custody)                                           |
| `docs/deployment.md`, `docs/testing.md`                  | PR #15                                                         | PR #16 corrupted                                                                          |
| `docs/protocols/IMPLEMENTATION_CONTRACT.md`              | PR #15 + PR #16 contract paragraphs                            | Both statements hold on the integrated code                                               |
| `package.json`                                           | PR #15                                                         | PR #16 removed `test:engineering`, testbed and offline-release scripts                    |
| `packages/crypto/crypto.mjs`                             | Merged                                                         | PR #15 provider interface; PR #16 self-contained module graph (ADR-007)                   |
| `packages/mission/policy.mjs`                            | Merged                                                         | Labels re-exported from `crypto.mjs`                                                      |
| `packages/object-format/types.d.ts`                      | PR #15 + v3 types, wrap v2 (`cfdaae1`)                         |                                                                                           |
| `scripts/sarif-gate.mjs`                                 | PR #15                                                         | PR #16 corrupted                                                                          |
| `services/admission/integrity.mjs`                       | PR #15 + v3 branch (`cfdaae1`)                                 | PR #15 uses the shared schema module                                                      |
| `services/control/core.mjs`                              | PR #15 + PR #16 `dutyVisible` + v3-safe label checks           | PR #16 removed custody quarantine, FLASH approval, static routing (ADR-009)               |
| `services/control/server.mjs`                            | PR #15 + strict `SIEPMU_ALLOW_PQC_LAB` (`cfdaae1`)             | PR #16 removed TLS, custody, telemetry; its flag was never read by `Authority`            |
| `services/evidence/decision.mjs`                         | PR #15 + validated crypto evidence (`cfdaae1`)                 |                                                                                           |
| `services/relay/client.mjs`, `services/relay/server.mjs` | PR #15                                                         | PR #16 removed TLS client/server                                                          |
| `services/web/server.mjs`                                | PR #15                                                         | PR #16 removed TLS 1.3 upstream pinning and secure-origin checks                          |
| `tests/verifier-replay.test.mjs`                         | PR #15; v3 provenance cases in `tests/pqc/end-to-end.test.mjs` |                                                                                           |

## Branch-unique subsystems

| Subsystem                                                                                            | Source | Disposition                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| TLS 1.3/mTLS `packages/transport/tls.mjs`, `deployment/secure/harness.mjs`                           | PR #15 | Kept                                                                                                                                                 |
| `packages/transport/mtls.mjs`, `deployment/secure/{stack,run}.mjs`                                   | PR #16 | Not ported: duplicate, weaker transport                                                                                                              |
| Checkpoint custody, recovery quarantine `services/evidence/`                                         | PR #15 | Kept                                                                                                                                                 |
| Monitoring collector `services/monitoring/`                                                          | PR #15 | Kept                                                                                                                                                 |
| FLASH dual control, `004-release-approvals.sql`                                                      | PR #15 | Kept; extended to every labelled schema                                                                                                              |
| Offline release `packages/release/offline.mjs`                                                       | PR #15 | Kept; lab package excluded (ADR-008)                                                                                                                 |
| 10-zone netem testbed `deployment/testbed/{provision,run,unit}.mjs`                                  | PR #15 | Kept                                                                                                                                                 |
| Integration adapter `services/integration/`                                                          | PR #15 | Kept                                                                                                                                                 |
| `services/integration-adapter/`, `deployment/testbed/legacy-emulator.mjs`                            | PR #16 | Not ported: duplicate adapter. Its extra negative tests (freshness, ambiguous restart quarantine, capacity) are a follow-up against PR #15's adapter |
| Provider engine `packages/crypto-provider/`                                                          | PR #16 | Ported; `pqc-identifiers.mjs` added                                                                                                                  |
| PQC lab `packages/pqc-lab/`                                                                          | PR #16 | Ported except corrupted `envelope.mjs`                                                                                                               |
| Authority registry `services/crypto-policy/registry.mjs`                                             | PR #16 | Ported; imports neutral identifiers only                                                                                                             |
| `004-crypto-policy.sql`                                                                              | PR #16 | Ported as `005-crypto-policy.sql`                                                                                                                    |
| Fault proxy `deployment/testbed/fault-proxy.mjs`                                                     | PR #16 | Ported; tests re-targeted onto PR #15 TLS stack                                                                                                      |
| Tests: crypto-agility, pqc, protocol-reconciliation, network-failure, browser shell-upgrade          | PR #16 | Ported. `protocol-reconciliation` uses IMMEDIATE instead of FLASH (FLASH needs approval)                                                             |
| Research: cryptographic-standards, defence-comparison, `20-q-agile-execution.md`, key-custody matrix | PR #16 | Ported                                                                                                                                               |
