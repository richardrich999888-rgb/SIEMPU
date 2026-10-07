# ADR-003: serialised current-authority capability issuance

Status: accepted design; invariant remains a test obligation.

## Context

An earlier allow decision is unsafe to reuse after authority changes. A queue, a signature or an admission cache alone does not close the check/send race. Physical network delivery cannot be atomically committed with a policy database.

## Decision

Define **release as committed capability issuance**: the authority authorises returning the envelope and recipient-wrapped key for one immutable object. It is not the instant a packet crosses the network or a user reads plaintext.

Use one transactional authority database. Final recipient claims and authority updates both use `BEGIN IMMEDIATE`. The claim validates the bound session/proof, current user/device status, sender and recipient authority, role, mission, policy edge, grant, object expiry and expected epoch while holding the write transaction. It atomically stores a unique issuance, signed receipt, evidence-chain append and state transition. Commit is the linearisation point; only then may the response expose the wrapped key.

`READY` is provisional preparation, not a release capability. An epoch mismatch enters HOLD/re-evaluation. Before returning wrapped keys on a retry, recheck current authority even when the issuance identity is durable and idempotent. Idempotence must not become a redisclosure bypass.

Submission may leave orphan ciphertext after a failed authority transaction; ciphertext alone is not release. Bound its retention and resource cost. An acknowledgement marks accepted client ACK, not proof of human reading. Receiver deduplication prevents repeated application effects; the network can still deliver duplicate responses.

## Safety statement to test

No capability is issued under an authority state superseded before its issuance transaction commits. If the policy-update transaction commits first, an old prepared decision cannot issue. If issuance commits first, later revocation cannot guarantee recall. This is local serialised authority consistency, not instantaneous global revocation or atomic physical delivery.

Creation grants prove bounded delegation, not trusted historical creation time. Server admission requires the grant to remain valid. An untrusted endpoint clock cannot prove that an offline object was created before a grant expired. No offline peer delivery bypass exists in this profile.

## Evidence required

- Independent connections/processes test both commit orders; a single-thread helper is insufficient race evidence.
- Failures before commit leave no partial issuance/evidence; failures after commit preserve one durable issuance.
- Restart preserves revoked users/devices/sessions, epochs and dedup state.
- Duplicate claims and acknowledgements preserve one application effect; revoked retries return no wrapped key.
- The detached verifier checks binding, signature and ordered hash chain. Detecting suffix truncation requires an independently saved expected checkpoint.

Crash recovery is not proof against an attacker restoring an entire old database snapshot. Signed evidence proves what a signer committed, not the truth of endpoint assertions or correctness of policy.
