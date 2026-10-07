# Engineering standards for this repository

These are enforcement requirements for the accepted Node 24 implementation. Actual runnable commands and their results belong in the root README and generated validation evidence; this document does not claim the gates already ran.

## Source and contracts

- Use ES modules, explicit imports and small modules with single ownership. Keep protocol validation, cryptography, authority transactions and HTTP adaptation distinct.
- Use one formatting convention and automated syntax/lint checks. Check JavaScript types through the configured static checker/JSDoc scope; do not call syntax parsing a complete type check. Report unchecked paths.
- Keep protocol encodings versioned. Centralise safe integer, identifier, enum, size and unknown-field validation. Avoid implicit coercion at security boundaries.
- Do not duplicate authorisation in UI-only checks. Revalidate current user/device/session/role and object scope at the final mutation/release transaction.
- Use purposeful commits, for example `fix(admission): recheck revoked recipient on retry`. Reference the regression and requirement. Do not stage runtime secrets, databases or private audit inputs.

## HTTP and errors

- Require JSON content type for mutations and same-origin policy where applicable; set secure headers. Apply body limits before expensive crypto/parsing.
- Return stable error codes and request/correlation identifiers. Keep secrets, filesystem internals and stack traces out of responses.
- Allow-list mutable fields. Use parameterised SQL and opaque identifiers; filenames never become server storage paths.
- Distinguish denial, hold/uncertainty, malformed request, conflict and unavailable authority. No catch block may turn an error into permission.
- Mutation success means its required state and evidence committed; a response sent before commit is forbidden.

## Logging and configuration

- Log structured event type, service, timestamp, request ID, actor/object where necessary, result and reason. Restrict identifiers and retention to operational need.
- Never log protected plaintext, passwords, MFA seeds/codes, bearer tokens, private keys, content keys or raw request bodies carrying them. Error logging must follow the same rule.
- Validate configuration at startup. Refuse insecure non-loopback deployment, missing mandatory secrets and accidental production/dev mixing. Examples contain names and safe placeholders only.
- No deterministic production identities or automatic demo fallback. Synthetic bootstrap requires an explicit demo command and generated credentials stored outside source.

## Persistence and migrations

- Use ordered versioned migrations and an applied-migration ledger. Validate empty, existing and unsupported-future databases.
- No silently destructive migration. Preserve a tested backup and rollback/recovery procedure; do not downgrade security epochs during recovery.
- Keep policy update and capability issuance in the same authority transaction model. Evidence append participates in that transaction.
- Bound retained blobs, pending objects, request nonces and alerts. Document limits; an orphan ciphertext is a resource cost even though it cannot release content.

## Test and release discipline

- Use isolated temporary databases and synthetic content. Never share runtime credentials or mutable global state between tests.
- Test the public API path in addition to helper functions. A denied request must cause zero protected mutation and no usable-key disclosure.
- Concurrency tests use independent processes/connections and deterministic barriers. Record which interleavings are tested rather than claiming all schedules.
- Every confirmed security defect needs a regression. Include pre/post-commit failures, restart, duplicate retries and external-checkpoint verification.
- Coverage guides missing security branches; do not replace behavioural tests with a percentage. Exclusions and unexecuted browser/container tests remain visible.
- Release gates must influence success/failure, not only produce reports. An unavailable scanner is NOT RUN/BLOCKED, not clean. Separate local checks from remotely executed CI.
- Generate dependency/runtime SBOM, checksums, source/configuration provenance and test references. No npm runtime dependencies does not remove Node/OpenSSL/SQLite/container obligations.
- Production deployment requires an explicit environment and approval strategy. Do not invent a cloud target or place production credentials into a local workflow.
