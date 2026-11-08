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

Run the separate Linux external-engine evidence gate with the provisioned configuration
and a new output directory (the parent directory must already exist):

```sh
npm run test:clamav -- /absolute/operator/scanner.json artifacts/clamav-run-001
```

The gate checks the pinned executable hash, the exact reviewed laboratory version 1.5.4,
a current-user-owned 0700 tmpfs temporary root, a clean source checkout, and a dedicated
database snapshot. That snapshot must contain one `main.cvd` or `main.cld`, one
`daily.cvd` or `daily.cld`, and optionally one bytecode database plus matching `.sign`
sidecars named with the upstream version, such as `main-63.cvd.sign`. Each sidecar
version must match its database header; native verification still authenticates the
content. Other files, symlinks, empty databases and duplicate formats are refused. Copy
completed updates from the supported updater into this dedicated snapshot; do not point
the gate at its live working directory. Inventory checks do not authenticate signatures.
The unchanged native adapter still enforces official databases and its freshness bound.

The gate runs `tests/file-inspection/clamav.check.mjs`, requiring benign-file success,
EICAR refusal and expanded-size-limit refusal. All three must pass with zero skips,
cancellations or TODOs; a zero exit alone is insufficient. `report.json` binds the result
to the commit/source digest, executable/configuration and database hashes. It refuses
changed inputs/source and never overwrites an earlier run. Missing prerequisites produce
`BLOCKED`, `NOT_EXECUTED` and a nonzero command exit; executed test failures produce
`FAIL`. Reports retain counts and a TAP digest, without raw diagnostics or operator paths.
The regression suite tests this evidence gate, not antivirus detection quality.

This preflight is an explicit laboratory command, not enforcement added to every SDK scan.
Its exact-version allowlist is a reviewed selection, not a vulnerability-free claim;
review upstream advisories before any new run or deployment. Linked libraries, shell
launchers/interpreters, system time, swap, dumps, mount races and parser isolation still
need an independently reviewed endpoint configuration. Extend qualification with encrypted and
malformed formats, archive depth, stale/future databases, tampered updates, endpoint
resource pressure, and the sponsor-approved representative file corpus. Browser/managed
helper integration, safe viewers and host isolation remain open under IAF-G11.

The first 8 November 2026 probe used ClamAV 1.5.3 only to observe missing-database
refusal. Subsequent upstream advisory review identified security fixes in 1.5.4; do not
reuse 1.5.3 for acceptance or deployment. The replacement official 1.5.4 Linux package
matched its release-metadata SHA-256 and started successfully. Its real missing-database
scan also returned `FILE_INSPECTION_INCOMPLETE`. The separate acceptance command reports
`BLOCKED` because official databases are absent. Benign/EICAR/expanded-file acceptance
is still **not executed**, and no production engine version has been qualified.

Correction to the earlier download investigation: upstream explicitly disallows scripted
curl/wget signature downloads. The supported CVDUpdate 1.2.0 updater was installed in an
isolated laboratory Python environment but failed its system-resolver DNS TXT query for
`current.cvd.clamav.net` before downloading. FreshClam previously failed initialization
under this container's user/group restrictions. No DNS-policy bypass, unofficial mirror,
freshness relaxation or fabricated signature database was used. Provide permitted DNS
and HTTPS access on a separate managed test host, use FreshClam/CVDUpdate, then repeat
the command above. Observe updater retry/cooldown instructions.

`.github/workflows/clamav-native.yml` provides a separate synthetic hosted experiment.
It downloads the exact 1.5.4 package, verifies the pinned SHA-256, extracts without a
system install, and runs FreshClam as the unprivileged hosted user. The native package's
CVD certificate directory is explicitly configured. The updater makes one bounded
attempt; a failed update yields an empty snapshot and a blocked acceptance report.
Only selected package hashes and the redacted acceptance report are uploaded. This
workflow initially triggers on changes to its own file on the acceptance branch; it
also supports manual dispatch. It does not run duplicate downloads for pull requests.
Do not rerun after an upstream rate-limit/denial without honoring its cooldown and
resolving the stated cause. Hosted results must be observed before being claimed. The initial hosted attempt
downloaded and tested daily 28177, main 63 and bytecode 339 successfully, then exposed
a filename mismatch in our preflight: FreshClam uses versioned `.cvd.sign` names. The
preflight and regression coverage now follow that documented format; the first run
remains a blocked result, not a detection pass. Final rerun results are recorded in PR #35.

See `docs/testing/endpoint-inspection-engine-probe-1.5.4.json` for the exact observed
package/binary/library hashes and negative-only execution. The package digest comparison
is not detached-signature verification or a complete native-library/OS SBOM.

Primary references retrieved 8 November 2026:

- [ClamAV scanning options and trust boundary](https://docs.clamav.net/manual/Usage/Scanning.html).
  Specifies local engine operation, skip behavior and encrypted-content alerts.
- [Signature management](https://docs.clamav.net/manual/Usage/SignatureManagement.html).
  Specifies FreshClam database updates; availability is not an offline update procedure.
- [Upstream clamscan manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in).
  Documents the database-age failure flag; main is a moving reference, not a release pin.
- [ClamAV 1.5.4 release](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4)
  and [security patch notice](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html).
  Upstream reports fixes affecting 1.5.3; this establishes patch rationale, not independent evaluation.
- [Pinned FreshClam 1.5.4 signature naming source](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/libfreshclam/libfreshclam_internal.c).
  Uses `<database>-<version>.cvd.sign`; inspected after the hosted preflight refusal.
- [FreshClam FAQ](https://docs.clamav.net/faq/faq-freshclam.html) and
  [CVDUpdate](https://github.com/Cisco-Talos/cvdupdate). Specify supported updater methods.
  CVDUpdate 1.2.0 was installed for the local experiment only, not as an application dependency.
- Installed Ubuntu package copyright file and `clamscan --help`, inspected locally for
  the exact test build. Package digest and execution limitations are in the local
  experiment record; production dependency review remains pending.

This change does not establish SAG grading, authorization to handle classified data,
IAF interoperability or a higher TRL. Current platform assessment is unchanged.
