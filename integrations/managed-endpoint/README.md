# AIRON managed endpoint companion

This is a separate, optional Linux x64 package for connecting an enrolled workstation to
the existing SIEPMU platform. It combines the PKCS11 token provider, isolated ClamAV file
inspection and the TLS endpoint SDK. It does not start an authority, relay, web server or
browser bridge. The main application's npm runtime dependency count remains zero.

SAG grading is not established. This is a synthetic-data laboratory candidate, not an
approved classified-data deployment. Physical hardware qualification, managed-device
enforcement and IAF acceptance remain external requirements.

## Separate build and verification

From a clean, committed repository checkout:

```sh
node integrations/managed-endpoint/bundle.mjs artifacts/managed-endpoint-pack
node integrations/managed-endpoint/verify.mjs artifacts/managed-endpoint-pack EXPECTED_MANIFEST_SHA256
cd artifacts/managed-endpoint-pack
npm test
```

The builder prints the manifest digest. Retain that value through a trusted channel and
verify with a separately trusted copy of `verify.mjs`. Verification checks every file and
rejects extra files and symlinks. A matching digest proves package integrity, not grading.
The exported package imports its own `lib/` sources and works outside the parent checkout.
It includes the Python lock, worker and license notices, but no credentials, provisioned
keys, token databases, antivirus signatures or native binaries. It does not fetch code on
startup. Native dependencies must be provisioned on the endpoint separately.

## Required dependencies

| Dependency                           | Selection                                                               | Purpose                                                   |
| ------------------------------------ | ----------------------------------------------------------------------- | --------------------------------------------------------- |
| Node                                 | >=24.19.0 <25                                                           | Endpoint SDK and software content encryption              |
| CPython / python-pkcs11 / asn1crypto | CPython 3.12 Linux x64; 0.10.1 / 1.5.1 with wheel hashes                | Token operations                                          |
| PKCS11 module                        | Operator-selected module, binary hash, token serial and public-key pins | Signing and ECDH; SoftHSM 2.7.0 is the tested emulator    |
| ClamAV                               | 1.5.4, official current signatures                                      | File inspection before send and after receive             |
| Bubblewrap / prlimit                 | 0.13.1 / recorded OS binary hash                                        | Linux namespaces, read-only mounts and per-process limits |
| TLS trust                            | Operator-provisioned CA; optional endpoint certificate and key          | TLS 1.3 with certificate and hostname verification        |

Install Python into its own virtual environment using `--require-hashes --only-binary=:all:`
with `lib/integrations/pkcs11/requirements.txt`. Native setup, exact crypto boundaries and
Ubuntu launcher permissions are described in the two integration READMEs under `lib/`.
The administrator supplies the runtime image, signature snapshot and private 0700 tmpfs.
The application does not install host exceptions or weaken isolation automatically.

## Public configuration and separate secrets

`validateConfiguration(config)` requires exactly these top-level members:

- `schemaVersion: 1` and `url`: a plain HTTPS origin, without path, credentials or query.
- `authorityKey`: the independently trusted P-256 authority public JWK.
- `profile`: `username`, `userId`, `deviceId`, `unitId`, plus `signing` and `encryption`.
  Each key contains only `handleId` and its previously trusted public JWK.
- `pkcs11`: the existing provider's public configuration, including Python/module/worker
  hashes, token label/serial and optional laboratory `softhsmConfig`. Never include a PIN.
- `inspection`: the existing ClamAV configuration with a mandatory `sandbox` configuration.
  The executable must be the pinned `bin/clamscan` inside that sandbox's runtime image.

Unknown fields, software private JWKs, missing isolation and TLS callback overrides are
refused. The enrolled token objects must already exist and be approved through the platform's
enrollment workflow. Startup opens and verifies those objects; it never auto-enrolls or
approves a user, creates replacement keys or falls back to software keys.

```js
import { openManagedEndpoint } from './index.mjs';

const endpoint = await openManagedEndpoint({
  config: approvedPublicConfiguration,
  tls: { ca: provisionedCaBytes },
  credentials: { password: personnelPassword, totpSecret: personnelTotpSecret },
  getPin: async () => operatorSecretSource.getTokenPin(),
});
try {
  await endpoint.authenticate();
  const payload = endpoint.createFilePayload('synthetic.txt', 'text/plain', syntheticBytes);
  const submitted = await endpoint.send(trustedRecipient, payload);
  // The recipient uses receiveWithRelease(objectId, trustedSenderSigningKey), then acknowledge.
  console.log(submitted.receipt.payload.objectId);
} finally {
  endpoint.close();
}
```

All names supplied by the host in this example are explicit deployment inputs, not shipped
defaults. Supply passwords, TOTP material, PINs and TLS private keys through protected runtime
channels. Do not put them in public configuration, argv or package files. JavaScript strings
cannot be reliably erased; trusted host memory, dump/swap policy and credential lifecycle are
still required. `close()` invalidates local handles and sessions; it does not delete token
objects, revoke server sessions or erase plaintext already returned to the caller.

The frozen facade exposes authentication, send, receive, list and acknowledgement operations.
Send always inspects files before encryption/submission; receive inspects decrypted files before
returning them. No raw client/provider, arbitrary request or uninspected-submit entry point is
exposed. Operations are serialized by refusal, not an unbounded queue. Startup runs a benign
isolated scan before requesting the token PIN. An unavailable dependency blocks startup.
Authentication remains the platform's existing personnel/device flow; token possession alone
does not grant authority. The optional persistent outbox is described below.

## Continuity options

`openManagedEndpoint` accepts `sessionRenewal` (boolean, default true) and an optional
`outbox: {database, key, maxEntries?, maxBytes?}`. `database` is an absolute path in an
existing private directory; `key` is a separately provisioned 32-byte Buffer. Keep this key
out of public configuration, Git and the database directory. Lost keys make queued work
unrecoverable. The default limits are 1,000 entries and 64 MiB of serialized encrypted rows;
the filesystem/WAL also needs an operational quota.

After authenticating, call `refreshCreationGrant()` to cache a signed creation grant.
`queue(recipient,payload,options)` scans and seals into durable encrypted storage without
network access; it needs a still-valid cached grant. Restart with the same storage key,
configuration and enrolled token. `listQueue()` shows IDs/state/expiry; `flushQueue(limit=32)`
submits pending work through current authority checks. Expired objects become HELD; errors
leave pending work for an explicit retry. `removeQueued(id)` discards local work, including
submitted records, without recalling content or guaranteeing physical erasure.

When an outbox is configured, `send()` also persists the sealed object before its first
submission. A lost response leaves that exact object PENDING; inspect `listQueue()` and
use `flushQueue()` after reconnecting or restarting. Do not repeat `send()` with the same
plaintext to recover an ambiguous result: that creates a new object. Each flush makes one
explicit attempt per pending object, obtains a fresh device proof and applies current
authority checks. Only a verified signed submission receipt marks the record SUBMITTED;
submission is distinct from recipient delivery and its acknowledgement. Submitted rows
remain until explicitly removed and count toward capacity. An unconfigured outbox provides
no durable online-send recovery. Whole-store rollback and loss of the storage key remain
outside this continuity guarantee.

Renewal is attempted before protected operations within two minutes of session expiry.
`renewSession()` can also be requested explicitly while the session remains valid. Fresh TOTP,
device proof and current session/user/device checks are required. Denial or an ambiguous
renewal response clears the local session; the package never falls back to password login.
Call `authenticate()` explicitly after expiry or failure. This is the existing synthetic
TOTP model, not an approved unattended personnel/service identity. A timed idle session may
expire because this compact package does not run an autonomous background login loop.
See `docs/decisions/ADR-016-continuity-mechanisms.md` in the source repository for limits.

## Evidence and limits

`npm test` in the extracted package runs offline configuration/refusal checks. It does not
claim native scanner/token success. The combined native workflow builds the package and uses
its exported entry point with real SoftHSM, isolated ClamAV, TLS 1.3 and a synthetic authority.
It tests benign exchange, outbound and inbound EICAR refusal, untrusted TLS issuer rejection,
no raw bypass API, concurrent operations and closure. The test CA and token credentials are
generated in a temporary directory and are not packaged. The authority is in process and its
relay is a test store; this is not a separate-host operational trial.

Before publication, run the full repository validation and E2E gates on the exact commit.
Record final package digest, native workflow result and remaining failures in the companion PR.
Native prerequisites missing or isolation denied are failures, not skipped tests.
This package does not establish hardware custody, all-file-type safety, browser/MDM enforcement,
aggregate cgroup limits, service failover, independent assessment or operational authorization.
