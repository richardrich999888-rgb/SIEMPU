# Managed endpoint file inspection

This is an optional **laboratory adapter**, not a complete endpoint protection product.
It is intended for a separately managed source/recipient host. The browser, old
integration harnesses and default SDK instances remain `UNSCANNED`. Do not infer
malware protection from encryption, a file extension, MIME type or an admission receipt.

## Wiring

Pass a `ClamAvInspector` from `packages/file-inspection/clamav.mjs` as `fileInspector`
when constructing `IntegrationEndpoint`. Supply an absolute `executable`, its reviewed
`executableSha256`, an absolute official signature `database` directory and an absolute
`tempRoot`. The default file bound is 512 KiB, one active scan per inspector, a 30-second
process deadline and a two-day database age limit. These are laboratory policy choices,
not IAF requirements. The document outbox retains its existing smaller transport bounds.

```js
const fileInspector = new ClamAvInspector(operatorProvisionedScannerConfiguration);
const endpoint = new IntegrationEndpoint({ ...endpointConfiguration, fileInspector });
if (endpoint.fileInspectionMode !== 'ENDPOINT_REQUIRED') throw Error('Inspection required');
```

The caller must import both classes and provision the configurations. No scanner is
installed or downloaded at runtime. No plaintext scan API is exposed by a service.

`seal` / `sealUsingGrant` inspect file bytes before encryption; `receiveWithRelease`
inspects verified, decrypted file bytes before returning them to the application.
`DocumentInbox` refuses a failed inspection and sends no delivery acknowledgement.
Authority release may already have occurred; refusal cannot undo key issuance. The
normal authorization, revocation, crypto provider and evidence paths are unchanged.
Retrying an already sealed outbox row reuses its ciphertext; it does not obtain a fresh
sender scan verdict. The recipient scans each decrypted retrieval with its current engine.

The SDK copies payloads before asynchronous work and checks the result against the
snapshot's SHA-256 and size. The inspector copies input before its first await. Scanner
results are local process outputs, not remote attestation, authority evidence or proof
against a compromised endpoint. A hostile or unmanaged sender can use another client.
Text messages are outside this file-only policy; no content-classification/DLP claim is made.

## Failure behavior and host boundary

The adapter invokes an explicitly pinned executable without a shell, streams only the
file bytes to stdin, passes no original filename, and discards raw diagnostics. It uses
an isolated environment and a private 0700 temporary directory. Only exit zero plus the
exact `stdin: OK` report is accepted. Empty files, oversized inputs, alerts, incomplete
reports, stderr diagnostics, unavailable/changed executables, timeouts, output overflow
and cleanup failures are refused. No detection result means `NO_THREAT_DETECTED`, not
proof that a file is harmless. There is no fallback scanner or automatic deletion of
the user's source document.

Flags require official databases, reject databases older than the configured age,
enable encrypted-document/archive and macro alerts, and enable exceeded-limit alerts.
The scan budget is 8 MiB expanded data, 100 members and nesting depth 8. Broken-executable
and broken-media alerts are enabled; they do not establish complete format validation.
Unknown or unsupported options fail the scan. No unsupported file-type safety promise
is made. This is neither content disarm/reconstruction nor a safe document viewer.

The operator must provision a private **memory-backed** temp root, restrictive directory
ownership, a read-only engine/library installation and trusted system time. The adapter
does not verify the backing filesystem, prevent disk-backed swap/core dumps, sandbox
native parsers, constrain total native memory, attest the host, or replace endpoint
management. Mount namespaces, a dedicated unprivileged account, process/memory limits,
network denial, swap/core policy and signed database updates remain deployment work.
ClamAV can create temporary plaintext; cleanup is not secure erasure on disk. The
executable hash detects a changed entry point but is not protection against a privileged
attacker replacing it between checking and execution, or changing linked libraries.

## Dependencies and acceptance

There are no new npm packages. ClamAV is an **external optional dependency**, absent
from the released container and npm inventory. Review its exact engine, shared libraries,
signature database, notices and OS SBOM before enabling it. The primary program is
GPL-2.0; linked/bundled components have additional notices. No ClamAV source or binary
is copied into this repository, and its licence is not replaced by the repository's
Apache-2.0 licence. Redistribution/licence review remains an operator release gate.

`tests/file-inspection.test.mjs` uses a clearly labelled subprocess double for failure
cases and real application cryptography/authority with an in-process transport for SDK
checks. These tests do not demonstrate malware-detection quality or actual engine success.

Run the separate external-engine gate with the provisioned configuration:

```sh
SIEPMU_CLAMAV_CONFIG=/absolute/operator/scanner.json node --test --test-concurrency=1 tests/file-inspection/clamav.check.mjs
```

It requires a benign-file success, EICAR refusal and expanded-size-limit refusal, without
silently skipping when configuration is absent. Extend qualification with encrypted and
malformed formats, archive depth, stale/future databases, tampered updates, endpoint
resource pressure, and the sponsor-approved representative file corpus. Browser/managed
helper integration, safe viewers and host isolation remain open under IAF-G11.

On 8 November 2026 the locally extracted Ubuntu package `1.5.3+dfsg-0ubuntu0.24.04.1`
reported ClamAV `1.5.3`. The real adapter refused a missing official database with
`FILE_INSPECTION_INCOMPLETE`. A fresh official database download returned HTTP 403;
the positive external-engine gate has **not** been completed. No production engine
version is selected or declared vulnerability-cleared by this experiment.

Primary references retrieved 8 November 2026:

- [ClamAV scanning options and trust boundary](https://docs.clamav.net/manual/Usage/Scanning.html).
  Specifies local engine operation, skip behavior and encrypted-content alerts.
- [Signature management](https://docs.clamav.net/manual/Usage/SignatureManagement.html).
  Specifies FreshClam database updates; availability is not an offline update procedure.
- [Upstream clamscan manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in).
  Documents the database-age failure flag; main is a moving reference, not a release pin.
- Installed Ubuntu package copyright file and `clamscan --help`, inspected locally for
  the exact test build. Package digest and execution limitations are in the local
  experiment record; production dependency review remains pending.

This change does not establish SAG grading, authorization to handle classified data,
IAF interoperability or a higher TRL. Current platform assessment is unchanged.
