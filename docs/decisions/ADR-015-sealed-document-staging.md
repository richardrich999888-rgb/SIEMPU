# ADR-015: source-sealed document staging

Status: implemented; local laboratory results on candidate `11f0768` are recorded in CURRENT_STATE.
Hosted final-candidate validation remains pending at this documentation edit.
Date: 7 November 2026. Baseline: PR #32 at `5c465d290a002a551a83ef74b235cd5a97990da8`.

## Problem and decision

Legacy `/v1/messages` accepts plaintext and runs a managed endpoint inside the adapter.
Its source outbox persists the plaintext file payload in base64. TLS does not change that
trust boundary. Existing negative tests deliberately retain this observation.

The v2 path separates ciphertext transport from authority admission. The originating
endpoint encrypts and signs using the existing object protocol. It persists the sealed
object and a detached, domain-separated transport manifest before network I/O. The connector
receives only the ciphertext, manifest and its signature. **The full object envelope and
wrapped content key never enter this connector.** Sending an envelope to an untrusted
connector could let it disclose a wrapped key to the recipient before authorized release.

The connector stages ciphertext in the existing blind relay. The source subsequently
submits the original sealed object directly through the existing authority path with its
own bound session and fresh operation proof. Authority policy, device checks, FLASH rules,
revocation, admission and later release are unchanged. A STAGED_CIPHERTEXT response never
means ADMITTED, RELEASED or DELIVERED. The source verifies the signed SUBMITTED receipt,
including object, ciphertext and envelope digests, before recording admission.

The authority still performs its normal relay PUT. This intentionally duplicates the data
transfer and preserves current admission/relay integrity semantics. Removing that extra PUT
needs a separately reviewed protocol change; no throughput improvement is claimed here.

## Implemented boundaries

- `packages/integration/sealed-transfer.mjs`: exact v2 manifest, source signature, digest,
  size/freshness/scope checks, private SQLite opening and persistent configuration binding.
- `services/integration/sealed-adapter.mjs`: serial bounded staging, durable retry/replay
  records, entry/byte budgets, pinned-mTLS HTTP service, no personnel credentials or endpoint keys.
- `services/integration/sealed-server.mjs`: standalone process with public source/destination
  configuration and data-plane credentials only. It rejects the legacy endpoint-profile and
  platform-login configuration. The relay client has a distinct laboratory mTLS identity.
- `apps/document-system/sealed-outbox.mjs`: source-side encryption, bounded durable outbox,
  keyed document conflict detection and row integrity, direct authority admission/status.
  The independent 32-byte outbox HMAC key stays at the source and must survive restart.
- `deployment/secure/sealed-adapter-process.mjs`: starts the real connector process from an
  explicit environment allowlist. It does not pass source login material into that process.

The transport manifest is signed over exactly domain, version, requestId, issuedAt, objectId,
senderUserId, senderDeviceId, recipientUserId and ciphertextHash. Only schema version 2 is
supported. Freshness is +/-300 seconds. Cached staging acknowledgements record a previous
successful staging; they are not a guarantee that a relay still holds a blob. Source admission
resubmits and validates the bytes, including after a lost staging response or restart.

The adapter defaults to 32 pending requests, 10000 durable records, 16 MiB of retained request
text, 32 HTTP connections, 384 KiB HTTP bodies, 15-second request timeout and 5-second header
timeout. The source defaults to 32 pending operations, 10000 rows and 32 MiB of sealed/transfer
text. SQLite overhead, TLS memory, WAL and full filesystem quotas need separate operational
limits. Counts are process-local; sharing one store across multiple workers is unsupported.
Records are never silently evicted; full capacity refuses new work. Configuration changes or
lost bindings with retained state require reviewed migration. Expired pending transfers are
refused; automatic renewal/resealing or transfer-to-v1 fallback is not implemented.

## Legacy compatibility and assessment

Legacy server startup is disabled unless `SIEPMU_ENABLE_LEGACY_PLAINTEXT_ADAPTER=1`.
Existing historical demo/test harnesses explicitly set it so their negative behavior remains
tested. The new v2 service has a separate entry point and never serves `/v1/messages`.
Do not enable the legacy path in a deployment whose connector is declared untrusted.
There is no in-place migration of legacy plaintext outboxes or secure erasure of their backups.

No existing military interface is inferred. The document schema remains synthetic. Both
source and destination are trusted endpoints. The connector still needs a TLS private key
and relay workload credential, but no document-encryption key, endpoint signing key, bearer
session, grant or wrapped content key. Routing IDs, timing, ciphertext size and digests remain
observable. The staging identity is a pinned public key, not a live personnel-revocation check;
a revoked sender may stage opaque bytes until its pin is withdrawn, but normal authority
admission/release still rejects revoked identities.

Canary scans cover inspected requests, declared stores/configuration and logs; they do not
prove absence from all memory, swap, core dumps or independently administered hosts. This
laboratory harness shares a host/kernel and administrative trust domain. Representative
multi-host isolation and accepted integration placement remain external validation work.
The G05 design blocker is reduced to PARTIAL_LAB for the new path, while legacy exposure,
migration, real-interface mapping and accepted deployment configuration remain unresolved.
Provisional system TRL 4 and the outstanding TRL 5 assessment gates remain unchanged.

## Validation obligations

Retain exact source identity and test logs for schema/signature tampering, plaintext/wrap
rejection, time skew/expiry, replay/restart, queue mutation/overflow, storage/key/configuration
corruption, byte/entry limits, mTLS denial, false staging/admission receipts and real endpoint
exchange. Include revocation after staging, before admission, and verify zero new authority
objects. Run the existing full native/E2E, browser, Rust, container, security and network jobs.
The historical G18 failure is not explained or closed by this protocol redesign.
