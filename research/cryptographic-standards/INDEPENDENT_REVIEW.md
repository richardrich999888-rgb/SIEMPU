# Independent cryptographic review gate

Status: OPEN. No independent cryptographic assessor has approved these providers or their application composition. Laboratory profiles are forbidden by production crypto policy.

| Review item                  | Required evidence / decision                                                                                                     | Current boundary                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Threat model                 | Endpoint compromise, relay/control compromise, harvest-now/decrypt-later, traffic analysis, key lifetime and revocation ordering | Laboratory assumptions documented; external agreement pending                    |
| Algorithm/version selection  | Exact FIPS revisions and errata; X-Wing draft pin; suite identifiers distinct from envelope schema                               | Source/version inventory available                                               |
| Published composition        | Verify upstream X-Wing implementation and all domain-separation bytes; assess application KEM-DEM binding and canonical bytes    | Author KATs pass; independent protocol analysis pending                          |
| Conformance                  | Full ACVP modes and negative cases; independent provider interoperability; import/export formats                                 | Selected keygen KATs, complete author X-Wing KATs and bidirectional interop only |
| Randomness and side channels | Qualified entropy, constant-time implementation evidence, JIT/GC leakage assessment                                              | Native platform entropy used; Noble JS explicitly unqualified                    |
| Key authentication           | Enrollment trust, sender signatures, recipient key substitution, authorized rotation and key-ID binding                          | Integration tests required for the complete v3 path                              |
| Downgrade                    | Tampered suite/provider identifiers, unknown suites, provider failure, revoked/deprecated keys                                   | Provider/engine negative tests; complete deployment policy review pending        |
| Private key custody          | OS isolation, backup/recovery, nonexportable hardware handles, attestation chain                                                 | Software handles only; no hardware or attestation claim                          |
| Release invariant            | Current authorization under concurrent revoke/release, process crash and restore                                                 | Release integration evidence must be attached separately                         |
| Evidence independence        | External checkpoint custody, signature verification, trusted freshness, rollback/replay rejection                                | Existing verifier must be exercised against new suite evidence                   |
| Browser/native clients       | Exact supported versions, capability probe, dependency supply chain, no server-side workaround                                   | Native laboratory provider implemented; browser qualification pending            |
| Deployment and performance   | Reproducible installation, offline dependencies, workload/CPU/memory/network results, operational limits                         | Isolated lockfile and benchmark runner supplied; field hardware pending          |
| Approval                     | Named assessor, scope, tested commit and signed findings disposition                                                             | Externally blocked until an assessor is engaged                                  |

Record assessor identity, date, source revision, environment, evidence hashes, open findings and the precise permitted deployment scope. No unchecked item may be represented as passed merely because the unit tests succeed.
