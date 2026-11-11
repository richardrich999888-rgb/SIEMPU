# AIRON–SIEPMU: request for technical sponsorship

SYNTRIASS Labs Pvt. Ltd. | iDEX DISC-14, PS-69 | P0-046 applicant laboratory candidate

## Operational purpose

PS-69 seeks secure information exchange between military units over the public Internet, with
end-to-end encryption, multifactor authentication, granular permissions, secure protocols and
monitoring and existing-system integration; SAG grading remains required, not established.
AIRON–SIEPMU addresses the
exchange and assurance problem with a working synthetic-data prototype. SAG grading is not
established; no operational IAF interface or classified data has been used.

## Working prototype and technical contribution

Endpoints encrypt and sign objects; an untrusted relay holds ciphertext. The authority releases a
wrapped key only after a transactional check of current policy, identity/device, mission, duty role,
expiry and revocation. The specific SYNTRIASS engineering contribution is the policy-epoch release
composition with signed state commitments, independently checkable evidence, checkpoint custody
and fenced recovery. Standard cryptographic primitives, TLS and MFA are not claimed as inventions;
novelty, exclusivity and patentability require separate prior-art review.

The P0-046 candidate reconciles PR #44's guarded control/relay/monitoring recovery with PR #45's
bounded archive and ciphertext/reference checks. It preserves divergent-history rejection, retained
checkpoint pins, explicit reviewer approval, generation-based writer handover and fresh leases.
Verification reports QUARANTINED or VERIFIED and never grants operational activation. Exact
revision, measured results and retained failures are attached in the assurance manifest.

## Maturity and evidence limits

The internal assessment remains provisional TRL 4. Laboratory campaigns cover signed-history
forks, partial authorization rollback, corrupt stores, process termination, custody interruption,
conflicting writers, lost handover responses and post-restore policy denial. Measurements compare
identical synthetic workloads on pinned baselines and the candidate. Hosted network profiles add
namespace/container isolation and impairment; shared hardware/administration does not establish
independent custody or an IAF-relevant environment. All 19 qualification gaps remain open/partial.

## Proposed supervised evaluation

Agree a non-classified evaluation scope and thresholds, then reproduce encrypted exchange,
revocation, rollback refusal, network recovery and evidence verification on nominated hosts.
Separate sender, control/relay and recipient/verifier roles, independently administer custody,
and use the supplied identity/crypto/endpoint profile. Freeze source and binary/module versions;
retain observer-controlled checkpoints and artifacts. Record failures and required remediation
before any TRL, grading or operational decision.

## Support requested

1. Nominate an IAF technical point of contact and agree the PS-69 operating and evaluation scope.
2. Guide a proposed service-sponsored SAG scope request and the pending module/profile decision,
   test procedures; confirm fees and any applicable waiver in writing.
3. Provide or nominate representative hosts, independent custody/observer administration and
   authorised identity/endpoint interfaces for the supervised campaign.
4. Consider a scoped six-month funded-development programme. The existing planning model is
   INR 59.225 lakh before unknown SDK/module, laboratory, tax and financing charges: INR 51.50 lakh
   estimated subtotal plus 15% contingency. Every priced amount is a management estimate, not a
   quotation or approved budget. M0 scoping allocation is INR 2.575 lakh of that subtotal. Scope,
   quotations, eligibility, matching funds and IP terms must be agreed before an application or
   commitment. This software iteration authorises no new spending.

No grant, procurement commitment, government relationship, SAG grade, TRL 5 qualification or
operational approval is implied. The request is for technical scoping, supervised validation and
consideration of an applicable funding route, not automatic acceptance.

Sources: official PS-69 indexed challenge; DRDO Support to Indian Industry; MoD revised testing
SOP announcement of 7 October 2026; P0-041_FUNDING_VALIDATION_PLAN.md (management estimates).
Full URLs, source caveats and the current gap register accompany the technical report.
