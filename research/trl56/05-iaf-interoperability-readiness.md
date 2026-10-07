# SYNTRIASS AIRON–SIEPMU — TRL 5/6 Defence Ecosystem Research

Review date: 2026-10-08 (India). Frozen implementation: `main` at `49774e2111197412efb31d459317c0df23a838af`.
Engineering plan for synthetic, authorised tests; not SAG/IAF approval or a TRL award.
Source hierarchy: official PS-69, filed-proposal copies, frozen code and execution evidence, then candidate documentation.
See [source register](source-evidence-register.json) and [proposal reconciliation](17-proposal-reconciliation.md).

## Boundary first

No IAF internal interface, network or military identifier has been observed. Every real interface remains **IAF-SPONSOR-REQUIRED**. Existing code has an authenticated /api/integration/validate synthetic schema validator, not a live connector.

## Versioned synthetic contract

Proposed neutral information-exchange envelope:
{
"schemaVersion": "1.0",
"exchangeId": "uuid-v4",
"sourceUnitAlias": "LAB-UNIT-A",
"destinationUnitAlias": "LAB-UNIT-B",
"purpose": "SYNTHETIC-EXERCISE",
"createdAt": "ISO-8601",
"expiresAt": "ISO-8601",
"policyReference": "opaque",
"payloadType": "application/octet-stream",
"payloadDigest": "sha256:<hex>",
"payloadCiphertextReference": "opaque",
"senderSignatureReference": "opaque",
"receiptRequested": true
}
This is a design proposal, not an approved military schema. Strong validate IDs, max lengths, content type, signature, idempotence, TTL, replay and schema version. _Never_ permit plaintext from an unknown adapter to bypass release policy.

## Proposed adapter design

1. An independent, nonprivileged connector owns the synthetic external-system interface.
2. Input is authenticated over mTLS, schema-validated and canonicalized; untrusted fields remain data.
3. A policy-bound release request passes through existing control authority. No adapter can mint grants or skip epoch checks.
4. Sender endpoint encrypts before untrusted transport.
5. Return signed receipt referencing exchangeId/hash/result, no plaintext in telemetry.
6. Reject unknown source/system, invalid signature, excessive file, stale epoch, malformed schema and replay.

## Interface catalogue

| Interface                   | Owner                     | Current                      | Required verification                  |
| --------------------------- | ------------------------- | ---------------------------- | -------------------------------------- |
| SIEPMU HTTP/OpenAPI gateway | Internal                  | Implemented                  | pin/complete schema, authZ boundary    |
| Synthetic legacy mock       | Internal separate process | To implement                 | accepted, denied, malformed, duplicate |
| PKI identity federation     | Sponsor                   | IAF-SPONSOR-REQUIRED         | trust anchor/revocation rules          |
| Military data format        | Sponsor                   | IAF-SPONSOR-REQUIRED         | classification/releasability/schema    |
| Military network gateway    | Sponsor                   | IAF-SPONSOR-REQUIRED         | authorised trial only                  |
| Cross-domain transfer       | Sponsor                   | OUT OF SCOPE absent approval | no inferred guard                      |

Use a 100% synthetic stand-alone mock legacy application with separate keys, network namespace and logs, and log every boundary crossing. Never treat open data schemas as a substitute for IAF integration approval.
