# Hostile evaluator record

> **Historical record.** This internal review was made on an earlier source state (three-process
> stack, Node 24.19.0) and is kept unchanged as a dated record. For current evidence see
> [FROZEN_BASELINE.md](FROZEN_BASELINE.md), [PS69_COMPLIANCE.md](PS69_COMPLIANCE.md) and
> [../trl/TRL_ASSESSMENT.md](../trl/TRL_ASSESSMENT.md). Its 0–5 review levels are not TRL numbers.

This is an **internal builder-side review**, not an independent IAF evaluation. It uses source inspection, the recorded local test output, real-browser result and measured synthetic benchmark. It does not assign an IAF selection probability.

## Review basis

| Field               | Observed basis                                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Date / evaluator    | 8 October 2026 IST; internal engineering review                                                                                       |
| Source state        | Working branch under active fixes; final release must pin full commit and rerun                                                       |
| Runtime             | Node 24.19.0; local Linux synthetic three-process deployment; real Chromium 153                                                       |
| Evidence            | Node coverage output; browser JSON; benchmark JSON; recovery and authority tests                                                      |
| Verification roots  | Synthetic independently provided keys/checkpoints in detached tests; production custody unresolved                                    |
| Faults exercised    | Two policy/issuance commit orders, before/after commit crashes, restart, relay/evidence failure, real browser offline/reload          |
| Defects corrected   | Body binding, encoding/public-key shape, signed snapshot consistency, stale vault writes and browser label issues; see regression log |
| Open delivery gates | Exact-head hosted checks/scans and release packaging; external operational assurance                                                  |

## Decision rubric

**REJECT operational deployment** while external cryptographic qualification, approved hosting, managed-device assurance, live integration and independent acceptance are unresolved. This does not imply rejection of a funded prototype development proposal.

**MAYBE for development selection** if the core workflow is reproducible, failures are disclosed and a credible assurance plan addresses the gaps.

**SELECT for a bounded pilot** is a committee decision, not a label this project can award itself. It requires the sponsor's agreed acceptance evidence, budget, team assessment and risk acceptance.

Do not derive an overall score from missing results. Mark each dimension 0–5 only after inspecting the evidence: 0 absent; 1 narrative; 2 code only; 3 repeatable lab evidence; 4 independently witnessed intended-environment evidence; 5 sponsor-accepted operational evidence. These are review levels, not TRL numbers.

| Dimension                                 | Weight | Internal score (0–5) | Evidence / limitation                                                                         |
| ----------------------------------------- | -----: | -------------------: | --------------------------------------------------------------------------------------------- |
| Explicit PS-69 workflow                   |    25% |                    3 | Repeatable lab text/file/API evidence; external crypto/integration gates remain               |
| Access control and E2EE boundary          |    25% |                    3 | Negative API and native/browser crypto tests; trusted endpoint/authority limits               |
| Authority race and restart safety         |    20% |                    3 | Separate-process race/crash/recovery evidence; no exhaustive formal proof                     |
| Evidence independence and reproducibility |    10% |                    3 | Detached verifier and anchored negatives; signer trust remains                                |
| Integration, usability and operation      |    10% |                    2 | Working UI and synthetic adapter; no approved live integration or full operational envelope   |
| Qualification and programme credibility   |    10% |                    1 | Requirements/assurance plan; sponsor acceptance and approved programme budget not established |

Weighted internal **assurance-maturity score: 54/100** under this rubric. Lab evidence has a ceiling of 3/5; this is deliberately not a product-quality, TRL or committee score. Verdict: **MAYBE for funded development, REJECT for operational deployment today**. The strongest improvement is independent intended-environment evidence and sponsor resolution of crypto/integration requirements, not additional architecture features.

## Questions the demonstration must withstand

| Question                                                | Evidence needed / acceptable limitation                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Why select this over existing collaboration software?   | Sponsor-specific workflow fit and measured authority-change control; secure messaging itself is established.                                |
| What is innovative?                                     | A narrow engineering hypothesis compared against a good queue + current-policy baseline; no novelty conclusion.                             |
| What happens if a device is revoked while disconnected? | Queued content cannot bypass current release checks; offline endpoint cannot know the change instantly.                                     |
| What happens when policy changes during dispatch?       | Identify release linearisation point and deterministic interleaving tests; disclose post-commit recall limit.                               |
| What prevents replay?                                   | Nonces and durable object/decision/delivery uniqueness; restart evidence.                                                                   |
| What does E2EE protect and what can the server see?     | Exact content-key custody and metadata view; distinguish trusted gate from blind store.                                                     |
| What does a receipt prove?                              | Signer committed these bound inputs/outcome; it does not prove endpoint truth, policy correctness or complete history without a checkpoint. |
| How does this integrate?                                | Versioned authenticated test adapter; no claim of a live AFNET connection.                                                                  |
| What is the SAG path?                                   | Sponsor-confirmed suite/grading process and evidence still required; standard algorithms alone do not satisfy it.                           |
| Why trust a startup?                                    | Inspectable evidence, bounded scope, independent validation plan and named accountable operators; no appeal to branding.                    |
| What are budget and timeline?                           | Founder-approved numbers and external dependencies; engineering cannot invent commitments.                                                  |
| What remains?                                           | Current claims register, failed tests and release gates; do not substitute roadmap for implementation.                                      |

## Ten plausible rejection reasons and response

| Risk                                                   | Highest-impact response                                                         | Evidence status                                                      |
| ------------------------------------------------------ | ------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Baseline secure exchange does not work reliably        | Demonstrate MFA, roles, file/text and receipt end to end                        | Local automated evidence present; retain final commit-specific rerun |
| Gate can be bypassed via a direct API/store path       | Trace every usable-payload/key path; test forbidden direct access               | Local automated evidence present; retain final commit-specific rerun |
| Race safety fails                                      | Serialize final release with policy changes; inject every supported race window | Local automated evidence present; retain final commit-specific rerun |
| Restart forgets revocation or duplicates delivery      | Durable transactions, recovery and unique effect keys                           | Local automated evidence present; retain final commit-specific rerun |
| “E2EE” actually decrypts at the service                | Show client key custody and controlled storage inspection                       | Local automated evidence present; retain final commit-specific rerun |
| Evidence verifier trusts keys supplied by the attacker | Pin independent root/checkpoint; corrupt/reorder/truncate cases                 | Local automated evidence present; retain final commit-specific rerun |
| Device trust is a cosmetic indicator                   | Show proof of possession; label hardware/posture unverified                     | Software proof measured; hardware trust remains unverified           |
| No differentiation from mature products                | Compare a competent baseline on identical failures/cost                         | Comparative experiment required                                      |
| SAG/integration/QA route is unclear                    | Secure sponsor decisions and an acceptance plan                                 | External decision required                                           |
| Scope, financial claims or readiness are overstated    | Freeze claims with exact evidence; founder-approved programme plan              | Audit before external use                                            |

For each reproduced defect append: attack, preconditions, expected result, actual result, evidence path, severity, fix commit, regression command/result, remaining limitation. Do not write “fixed” from source inspection alone.
