# AIRON–SIEPMU Defence Research | 2026-10-08

STATUS: engineering proposal / evidence-based roadmap. Does not establish IAF/SAG approval, TRL progression, vendor quotation or classified access. Baseline f6d75cf6b105319ca0d6942b2bbc196750a0b230.

## End-to-end sponsor-reviewable scenario
A synthetic information owner enrols Unit A and Unit B with approved mock unit IDs, hardware-backed authentication where prototyped, roles and fixed mission scope. Sender authenticates, signs and encrypts a synthetic text and file package. Relay carries ciphertext. Control authorises recipient at current epoch, issues wrapped key and signed audit evidence. Recipient decrypts, verifies and acknowledges. Network impairment isolates Unit B, causing new data to queue; administrator revokes Unit B's permission, then reconnects. Queue remains HOLD without fresh wrapped key. Independently operated mock connector receives schema-conformant authorised payload envelope. Detached reviewer validates audit root and independently retained checkpoint.

## Live demonstration order
1. Freeze release manifest, workstation firmware, service hashes and ephemeral lab secrets.
2. Prove TLS certificates and service authentication, MFA, bound unit permissions.
3. Capture ingress/relay payload: ciphertext only.
4. Measure connected text/file exchange (p50/p95, file digest and ACK).
5. Apply controlled loss, latency, DNS failure and power/service restart.
6. Reconnect; verify current policy and block revoked recipient; illustrate limitation of previously issued keys.
7. View synthetic security alert, incident owner and containment procedure; inspect for plaintext leaks.
8. Validate mock external connector's replay/malformed-schema failures.
9. Restore encrypted backups, verify signed receipt, review rollback-detection limitation.
10. Export signed, timestamped evidence and independent reviewer sign-off.

## Stress and negative profile
At least a structured parameter sweep: client count, concurrent submissions, encrypted attachment sizes, repeated reconnects, prolonged outage, high loss, certificate expiry, clock drift, revoked hardware proof, service outage, corrupted backup and stale epoch. Values are provisional until approved by sponsor; never present them as mandatory defence thresholds.

## Exit gate
A near-representative integrated prototype demonstrates the complete information-exchange lifecycle under relevant conditions; measured limits and red/amber defects documented; verification lab/IAF review status explicit; secure cryptographic provider/approvals tracked separately. No TRL6 self-certification by planning.
