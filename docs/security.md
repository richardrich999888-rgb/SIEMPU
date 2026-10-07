# Implemented security boundaries

[Authority](../services/control/core.mjs) enforces mandatory password/TOTP authentication, durable replay counters, expiring/revocable sessions, approved device binding, one-use operation proofs including request-body hashes, current roles/unit/mission policy and object recipient checks. Admin role does not confer content-decryption rights. Passwords use scrypt; TOTP seeds are encrypted under a separate server master key. Metadata databases are not wholly encrypted.

[HTTP control](../services/control/server.mjs) validates JSON/type/size/path/origin, returns request IDs and redacted errors, and logs structured result/latency fields. [Gateway](../services/web/server.mjs) adds fixed-upstream proxying, Host/origin restrictions, security headers and static-path limits. [Relay workload authentication](../services/relay/auth.mjs) binds requests and rejects replay; internal HTTP does not conceal metadata.

File names/MIME/payload shapes are checked by [crypto](../packages/crypto/crypto.mjs); content is never executed or centrally previewed. This is not antivirus, CDR or malicious-document isolation. The browser uses safe text rendering, encrypted local storage and memory-only sessions. Client distribution and endpoint integrity remain trusted.

See the [threat ledger](threat-model/README.md), [regression log](security/SECURITY_REGRESSION_LOG.md), [tests](testing.md), [supply chain](SUPPLY_CHAIN_SECURITY.md) and [deployment](deployment.md). Local pattern checks do not establish that every vulnerability or secret has been found. No external penetration test, hardware assurance, SAG grading or IAF approval is claimed.
