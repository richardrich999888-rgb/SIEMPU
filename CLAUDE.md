# AIRON–SIEPMU — project instructions for Claude Code

SYNTRIASS laboratory prototype for **iDEX DISC-14, IAF Problem Statement 69: Secure Information
Exchange Platform for Military Units (SIEPMU) on Public Internet**. Repository slug is `SIEMPU`;
the product acronym is **SIEPMU**. All data is synthetic. Nothing here is IAF-approved,
SAG-graded, independently assessed or operationally deployed.

**Start every session by reading [docs/engineering/CURRENT_STATE.md](docs/engineering/CURRENT_STATE.md).**
It holds the inspected SHA, branch/PR state, last verified results, open defects and the next task.

## What the system does

Units exchange end-to-end encrypted objects over an untrusted network. Endpoints encrypt and
sign. The ciphertext relay stores ciphertext only. The control authority stores opaque wrapped
keys and releases one only after a **transactional re-check of current policy** (users, devices,
roles, duty roles, unit/mission policy, grant expiry, global epoch, FLASH approval, crypto policy).
Every decision is a signed, hash-chained evidence record checked by an independent verifier.

## Source-of-truth hierarchy (highest first)

1. Executed results on an exact SHA (hosted CI run, `artifacts/validation/report.json`).
2. Source code and tests on the current branch.
3. `docs/engineering/CURRENT_STATE.md`, `docs/decisions/ADR-*.md`.
4. `research/trl56/` (validated research records; statuses frozen at the main baseline).
5. `docs/application/` filed-application material: **applicant commitments, not IAF policy**.
6. PR descriptions and conversational memory: claims only, never evidence.

## Repository map

```text
apps/unit-client/      browser endpoint, encrypted vault, service worker (sw.js)
apps/admin-console/    role-gated operator console      apps/verifier/  independent CLI
services/control/      authority: identity, policy, admission, release, evidence (core.mjs)
services/relay/        ciphertext-only blob service     services/web/  TLS gateway, same-origin proxy
services/evidence/     checkpoint custodian + recovery guard
services/monitoring/   signed redacted telemetry collector
services/integration/  synthetic military-interface adapter
services/admission/    persisted-envelope integrity     services/crypto-policy/  authority PQC registry
packages/crypto/       classical endpoint crypto + wire contract (browser module)
packages/crypto-provider/  provider engine, suite policy, key lifecycle, PQC identifiers
packages/pqc-lab/      LAB ONLY endpoint ML-KEM/ML-DSA/X-Wing providers (excluded from releases)
packages/transport/    TLS 1.3 / mTLS              packages/release/  signed offline bundles
database/migrations/   checksummed SQL (never edit an applied migration)
deployment/            secure lab PKI/harness, 10-zone netem testbed, fault proxy
```

Details: `.claude/skills/siepmu-architecture/`.

## Non-negotiable invariants

- Plaintext and recipient private keys exist only at endpoints. Never move them into control,
  relay, gateway, adapter, collector or custodian to simplify anything.
- Key release happens inside one authority transaction that re-validates **current** policy.
  Revocation committed first blocks issuance; an issuance committed first cannot be recalled.
  Never claim retroactive or instantaneous revocation of disclosed content.
- Signed decision evidence is written in the same transaction as the state change. Concealment
  (opaque 404 for duty-restricted parties) happens only after commit.
- Unknown schema versions, extra fields or unknown suites fail closed. A failed or unavailable
  provider never falls back to another provider or a weaker suite.
- Laboratory PQC suites are disallowed unless `SIEPMU_ALLOW_PQC_LAB=1` and the crypto policy
  lists them. `packages/pqc-lab` never ships in `dist/`, the container or offline bundles.
- `packages/crypto/crypto.mjs` statically imports **only** `canonical.mjs` (service-worker
  upgrade invariant; see ADR-007).
- No secrets in Git. No suppression of CodeQL/secret-scan findings. No lowering of gates.
- Never remove or weaken a negative security test to get green.

Full list and rationale: `.claude/skills/siepmu-authorization/` and `docs/decisions/`.

## Validation commands (verified in package.json)

Node **24.21.0** (CI) / `>=24.19.0 <25`. Runtime has zero npm dependencies.

```sh
npm ci --ignore-scripts
npm run validate          # check, lint, typecheck, format, coverage tests, security, build, sbom, demo
npm run test:e2e          # three HTTP acceptance scenarios
npm run test:security     # security regression subset
npm run test:engineering  # TLS, custody, FLASH, monitoring, offline release, providers
npm ci --prefix packages/pqc-lab --ignore-scripts && npm --prefix packages/pqc-lab test
npm run test:browser:isolated   # Chromium; needs Playwright browser
python3 research/trl56/validate.py --self-test
```

Run one file: `node --test --test-concurrency=1 tests/<file>.test.mjs`. CI: `.github/workflows/ci.yml`
(native, pqc-lab, container, browser, testbed) and `security.yml` (regression, secrets, CodeQL).

## Evidence and claims rules

- Report results only from commands run on a stated SHA. Never copy an old result forward.
- Separate statuses: engineering implementation, lab validation, relevant-environment validation,
  representative demonstration, independent assessment, sponsor acceptance, SAG grading,
  operational authorization. Only the first two can be established in this repository.
- Use "post-quantum", "quantum-resistant candidate", "crypto-agile". Never "quantum-proof",
  "unhackable", "military-grade", "certified".
- Duty roles, FLASH dual control and priorities are **provisional applicant policy**.
- Unknown military interface or policy: build a synthetic adapter and record the sponsor question
  (`research/trl56/16-iaf-clarification-register.md`). Never invent a classified interface.

## Branch and PR workflow

Never push to `main`; never force-push or rewrite another agent's branch. Port changes
selectively and record provenance SHAs in commit messages. Do not merge PRs. See
`.claude/skills/siepmu-github-handover/`.

## Skills

| Skill                              | Use for                                                  |
| ---------------------------------- | -------------------------------------------------------- |
| `siepmu-project-context`           | Challenge, applicant scope, source documents             |
| `siepmu-architecture`              | Services, trust boundaries, source map                   |
| `siepmu-crypto-agility`            | Providers, suites, envelope versions, PQC lab, downgrade |
| `siepmu-authorization`             | Release transaction, revocation, duty roles, FLASH       |
| `siepmu-secure-deployment`         | TLS/mTLS, zones, container, offline install, updates     |
| `siepmu-testing-and-assurance`     | Commands, test map, evidence recording                   |
| `siepmu-trl-readiness`             | Work packages, CTEs, external gates, status language     |
| `siepmu-github-handover`           | Branches, PR reconciliation, CI diagnosis, handover      |
| `siepmu-defence-integration`       | Synthetic adapters, sponsor questions                    |
| `siepmu-research-and-dependencies` | Standards, libraries, licences, supply chain             |

Before ending a session or at context compaction: update `docs/engineering/CURRENT_STATE.md`
with the branch, last passing validation SHA, unresolved failures and the next executable task.
