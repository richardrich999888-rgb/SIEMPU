# Concurrent development: credit and integration boundaries

Final refresh: 8 October 2026 (India). The initial inventory had 14 remote branches; the refreshed inventory has **16**, including this reconciliation branch and a newly observed filed-application alignment branch. Exact observed heads and changed paths are in [branch-inventory.json](branch-inventory.json). Subsequent branch movement requires another dated comparison.

This is a targeted source and hosted-status review. It does not replace a complete independent security audit or a combined-branch test. The frozen delivered implementation remains `49774e2111197412efb31d459317c0df23a838af` for the baseline tables elsewhere in this dossier.

## Draft PR13: duty-role and priority alignment

Head: `7320eb1803a318f62f7f70bd23f3273129a2686a`, branch `feature/disc14-ps69-filed-application-alignment`. [PR13](https://github.com/richardrich999888-rgb/SIEMPU/pull/13) was draft and unmerged at inspection.

Source inspection confirms:

- An additive `duty_role` migration and six-role/four-priority policy module.
- Schema-v2 priority/domain fields included in the authenticated context; the classical cryptographic suite remains unchanged.
- Sender and recipient duty checks at submission/release, version-downgrade rejection for assigned duty roles, metadata filtering and object-ID probe rejection.
- Client/admin integration and new policy/authority negative tests.
- Deliberately narrower auditor/admin content rights than the submitted broad resource wording; these are proposed security corrections requiring scope review.

[Run 37687923040](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37687923040) reported success for native, browser, container, CodeQL, Gitleaks and packaging. This is evidence for that PR test context, not main or a combination with PR2. This review did not independently extract and recount its native test artifact.

**Credit:** WP21 is now `PARTIAL_BRANCH_IMPLEMENTATION`, not entirely unstarted. Main still lacks this change. The additive role assignment is optional; it is not yet an approved mandatory fleet policy. The inspected tests cover important negative paths but do not demonstrate every role/priority/action combination or an approved IAF role matrix.

Annexure 3 additionally proposes a distinct authorization action for highest-priority messages. Eligibility to write such a message is not that approval workflow. A25/T5-13 tracks this remaining scope decision explicitly.

## Draft PR2: foundation hardening

Head: `40ab9d038cd521e29ebd57b5e7dde041f9c61212`, branch `feature/repository-foundation`. [PR2](https://github.com/richardrich999888-rgb/SIEMPU/pull/2) was draft and unmerged at inspection.

The source/diff includes strict persisted-envelope schema/signature/binding revalidation, richer transactional decision evidence, verifier/replay changes, identity-recovery durability cleanup, API/typing/tests and an independently pinned Node 24.21.0 image candidate. It replaces the current quality workflow with separate CI and security workflows and changes release automation placement.

The [CI run 37686786979](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37686786979) reported native/browser/container success; [security run 37686786781](https://github.com/richardrich999888-rgb/SIEMPU/actions/runs/37686786781) reported CodeQL/secrets/dependency-regression success. These observed job outcomes are separate from the frozen 87-test main evidence. Higher test counts asserted in branch documentation are not transferred to main or independently recounted here.

## Concrete integration issue

`services/admission/integrity.mjs` in PR2 checks a fixed schema-v1 field set and explicitly requires `schemaVersion === 1`. PR13 introduces schema v2 with signed priority/domain fields. Combining both changes without adapting strict stored-envelope validation can HOLD every valid v2 object. Removing the new integrity check to make v2 pass would lose the hardening.

WP23 / INT-01 requires:

1. One reviewed versioned envelope definition used consistently by encryption, ingestion, persisted-state revalidation and evidence verification.
2. Valid v1/v2 compatibility tests plus negative signature, stored-metadata, downgrade, duty-policy and object-ID disclosure cases.
3. Migration/recovery and role-change-at-issuance tests preserving the same authority/issuance/evidence transaction boundary.
4. Carrying this dossier's research-consistency gate into any replacement CI workflow.
5. A new combined candidate with its own source digest and full hosted validation. Neither branch's passing run proves their combination.

These draft branches were inspected and credited, not merged or modified by the research reconciliation. Dependency-update branches remain individual proposals. No runtime upgrade or role-policy change is smuggled into this documentation change.
