# Hostile evaluator record

This is an evidence collection template, not a completed independent evaluation. Fill it from a frozen run. A build author filling this record is not an independent assessor.

## Run identity

| Field                                      | Value        |
| ------------------------------------------ | ------------ |
| Date / evaluator                           | NOT RECORDED |
| Full commit / dirty-tree status            | NOT RECORDED |
| Deployment, OS, CPU and dependency lock    | NOT RECORDED |
| Commands and evidence bundle               | NOT RECORDED |
| Trusted verification key/checkpoint source | NOT RECORDED |
| Fault injection and simulated features     | NOT RECORDED |
| Observed failures                          | NOT RECORDED |

## Decision rubric

**REJECT operational deployment** while external cryptographic qualification, approved hosting, managed-device assurance, live integration and independent acceptance are unresolved. This does not imply rejection of a funded prototype development proposal.

**MAYBE for development selection** if the core workflow is reproducible, failures are disclosed and a credible assurance plan addresses the gaps.

**SELECT for a bounded pilot** is a committee decision, not a label this project can award itself. It requires the sponsor's agreed acceptance evidence, budget, team assessment and risk acceptance.

Do not derive an overall score from missing results. Mark each dimension 0–5 only after inspecting the evidence: 0 absent; 1 narrative; 2 code only; 3 repeatable lab evidence; 4 independently witnessed intended-environment evidence; 5 sponsor-accepted operational evidence. These are review levels, not TRL numbers.

| Dimension                                 | Weight | Score        | Evidence / limitation |
| ----------------------------------------- | -----: | ------------ | --------------------- |
| Explicit PS-69 workflow                   |    25% | NOT ASSESSED |                       |
| Access control and E2EE boundary          |    25% | NOT ASSESSED |                       |
| Authority race and restart safety         |    20% | NOT ASSESSED |                       |
| Evidence independence and reproducibility |    10% | NOT ASSESSED |                       |
| Integration, usability and operation      |    10% | NOT ASSESSED |                       |
| Qualification and programme credibility   |    10% | NOT ASSESSED |                       |

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

| Risk                                                   | Highest-impact response                                                         | Evidence status                       |
| ------------------------------------------------------ | ------------------------------------------------------------------------------- | ------------------------------------- |
| Baseline secure exchange does not work reliably        | Demonstrate MFA, roles, file/text and receipt end to end                        | Check current run                     |
| Gate can be bypassed via a direct API/store path       | Trace every usable-payload/key path; test forbidden direct access               | Check current run                     |
| Race safety fails                                      | Serialize final release with policy changes; inject every supported race window | Check current run                     |
| Restart forgets revocation or duplicates delivery      | Durable transactions, recovery and unique effect keys                           | Check current run                     |
| “E2EE” actually decrypts at the service                | Show client key custody and controlled storage inspection                       | Check current run                     |
| Evidence verifier trusts keys supplied by the attacker | Pin independent root/checkpoint; corrupt/reorder/truncate cases                 | Check current run                     |
| Device trust is a cosmetic indicator                   | Show proof of possession; label hardware/posture unverified                     | Software boundary only until measured |
| No differentiation from mature products                | Compare a competent baseline on identical failures/cost                         | Comparative experiment required       |
| SAG/integration/QA route is unclear                    | Secure sponsor decisions and an acceptance plan                                 | External decision required            |
| Scope, financial claims or readiness are overstated    | Freeze claims with exact evidence; founder-approved programme plan              | Audit before external use             |

For each reproduced defect append: attack, preconditions, expected result, actual result, evidence path, severity, fix commit, regression command/result, remaining limitation. Do not write “fixed” from source inspection alone.
