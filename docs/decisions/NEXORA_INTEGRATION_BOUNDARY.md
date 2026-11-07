# NEXORA integration boundary for SIEPMU

Status: proposed, not implemented or validated across repositories. Date: 2026-11-07.
User intent: reuse VANIAN's NEXORA for authentication in the IAF PS-69 platform.

## Inspected source

The AIP repository's `claude/codebase-production-readiness-wm6idp` head
`4ee39f359430277a48c34b957609104d3cf781f6` contains
[`aip-nexora`](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/4ee39f359430277a48c34b957609104d3cf781f6/aip-standalone/aip-nexora/src/lib.rs):
signed heads, Merkle inclusion/consistency proofs, portable proof verification,
replay tracking and offline verification. The implementation explicitly delegates
identity, authorization and reconciliation to their respective components.
Older sections of `NEXORA_BOUNDARY.md` describe missing functionality; its later
gate notes and actual source supersede those historical statements. No AIP tests
were executed during this inspection.

## Proposed composition

| Question                                                     | Responsible component                                                                                           |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Which person and device does this key belong to?             | Controlled enrollment and an operator-approved identity trust root                                              |
| Does the claimant control that key now?                      | Fresh, short-lived, single-use challenge bound to the service, device and session; applicable MFA               |
| May this identity receive this object now?                   | Existing SIEPMU transactional authority, including revocation, duty/mission policy, expiry and crypto policy    |
| Were these recorded decisions altered, reordered or removed? | Existing SIEPMU evidence/custody checks, with a proposed NEXORA commitment bridge and independent retained head |

SIEPMU already implements password/TOTP authentication followed by a signed device
challenge. NEXORA can add portable evidence of those events. Using its signed
records as an identity credential would additionally require an explicitly defined
issuer, enrollment mapping, credential format, key lifecycle and proof-of-possession
login protocol. A self-issued key or a valid historical proof does not establish
current personnel status or permission to obtain a document.

## Integration work and acceptance

1. Select and pin the reviewed AIP revision; reconcile its license, dependencies,
   schemas, canonical encodings, algorithms and trust anchors with SIEPMU. Never
   relabel SIEPMU evidence as an AIP execution proof.
2. Define a versioned bridge over verified SIEPMU evidence, preserving source
   bytes, their digest, authority identity, event sequence, device/user binding,
   policy epoch and source verdict. Keep plaintext, credentials and private keys
   out of proof exports. Define retention and access for sensitive metadata.
3. Validate exported commitments independently against an operator-provisioned
   trust root and an independently retained head. Report unavailable evidence or
   stale revocation state explicitly. Historical verification cannot mint a session
   or release a wrapped key.
4. If credential-based login is added, require challenge freshness, service and
   session binding, atomic single use, current key/device/user status, MFA policy,
   bounded attempts and session expiry. Preserve the existing authority check at
   every key release.
5. Test wrong issuer/key/audience, stale/replayed challenges, concurrent replay,
   revoked users/devices, old key versions, mutated/reordered/truncated evidence,
   unavailable anchors and mismatched encodings. Passing a commitment check must
   never override a denied release or elevate an unknown verdict.

This is an integration design, not a claim of live authentication integration,
independent assessment, sponsor acceptance or a TRL increase.
