# Executed tests and reproduction

Run `npm ci --ignore-scripts`, then `npm run verify`, `npm run test:coverage`, `node scripts/demo.mjs`. The root verification command runs syntax, lint, format, scoped type checking, Node tests, narrow security rules, build and SBOM. Read the exact exit status/output; this document is not an assertion that every future checkout passes.

| Layer                        | Actual files / scope                                                                                                                                                                         |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Crypto / verifier            | `tests/crypto.test.mjs`: native/WebCrypto interoperability, context substitution, wrong keys, vault, encoding, independent bindings and checkpoint tamper                                    |
| Authority / security / races | `tests/authority.test.mjs`: MFA/roles/devices/sessions, direct object access, revocation, two commit orders, crashes, retry and restart                                                      |
| HTTP integration             | `tests/http.test.mjs`; relay/web `.test.mjs` files: running services, request validation, proxy and workload isolation                                                                       |
| Recovery                     | `tests/recovery.test.mjs`: encrypted restore and migration upgrade/checksum; `tests/additional-boundaries.test.mjs`: offline identity recovery, MFA vector and relay/evidence fault rollback |
| Browser store                | `apps/unit-client/vault-store.test.mjs` and `challenge.test.mjs`: durable writes, Web Locks, stale tabs, challenge scope and receipt scope                                                   |
| Browser E2E                  | `apps/unit-client/browser-check.mjs`; [executed Chromium record](testing/browser-validation.md)                                                                                              |
| SAST gate regression         | `scripts/sarif-gate.test.mjs`: scanner report fail/allow behaviour                                                                                                                           |
| Acceptance                   | `scripts/demo.mjs`: synthetic real HTTP exchange, denied user, disconnected queue, authority change, selective release and race                                                              |
| Performance                  | `scripts/benchmark.mjs`: bounded sequential loopback profile                                                                                                                                 |

Coverage gate: lines 85%, branches 75%, functions 85% over configured services/packages/verifier/gate scope; see `package.json` for exact include/exclude filters. UI, test helpers and other scripts are not all included. Changing scope changes percentages, so use the generated report for the exact run rather than a stale global badge.

The local real Chromium run passed UI MFA, device binding, E2EE text, safe text rendering, policy hold/release, encrypted storage and actual offline/reload. A subsequent real-browser run also exercised fresh enrollment/approval, body substitution and signing-oracle rejection, Web Locks serialization and stale-peer vault protection; consult the latest browser record. Browser file-download and other engines remain outside this scope. Remote Actions jobs, CodeQL/Gitleaks/Trivy and actual container startup are separate gates: inspect their exact-head run before claiming pass. No external penetration test is represented.
