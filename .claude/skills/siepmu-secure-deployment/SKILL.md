---
name: siepmu-secure-deployment
description: TLS 1.3 and mutual TLS, deployment profiles, trust zones, the 10-zone netem testbed, container hardening, lab PKI and certificate rotation/revocation, signed offline installation, updates and rollback protection for SIEPMU. Use before changing packages/transport, deployment/, Dockerfile, compose.yaml, packages/release, scripts/build.mjs, CI deployment jobs, or service startup and environment handling.
---

# SIEPMU secure deployment

## Profiles (`packages/transport/tls.mjs`, `secureProfile()`)

`SIEPMU_PROFILE` is `development` (default, loopback HTTP), `secure` or `isolated` (TLS 1.3
only). Unknown values throw. `SIEPMU_ALLOW_REMOTE_HTTP=1` is rejected in secure profiles. Services
refuse non-loopback HTTP binds unless explicitly allowed in development.

Transport rules: `minVersion = maxVersion = TLSv1.3`, `rejectUnauthorized: true`, session tickets
disabled, mTLS identities allowlisted by SHA-256 certificate pin (`clientFingerprints`), peer
certificate expiry rechecked per request, optional CRL (`SIEPMU_TLS_CRL`). `requestBytes()` rejects
redirects, oversize bodies, interrupted responses and deadline overruns; it cannot downgrade
`https:` to `http:`.

## Secure lab stack (`deployment/secure/`)

- `lab-pki.mjs` `generateLabPKI(dir)`: disposable P-256 CA (7 days), `issue(name, {wrongHost, expired})`,
  `material(name)`, `pin(name)`, `revoke(name)` -> CRL. Never ship the CA key.
- `harness.mjs` `prepareSecureLab`, `labEnvironment`, `startSecureStack(dir)` -> five processes
  (web, control, relay, checkpoint, collector) with role identities; `stopRole`/`start` for outage
  tests; `secureApiTransport(baseUrl, tls)` for clients.
- Recovery guard: control blocks key-bearing routes (`503 RECOVERY_QUARANTINED`) while the
  checkpoint custodian is unreachable or disagrees (`services/evidence/custody.mjs`).

## Testbed (`deployment/testbed/`)

`provision.mjs` writes `artifacts/testbed/compose.json` (10 zones, separate networks/mounts);
`run.mjs` executes workloads under netem profiles from `profiles.json` (N0 clean, N1 100±20 ms,
N2 150 ms + 2 % loss, N3 512 kbit, N4/N5 disconnect, N8 WAN-isolated) and writes
`artifacts/testbed/measurements.json`. CI job `testbed` requires `successfulExchanges == 75` and
no failures on the exact `GITHUB_SHA`. netem needs CAP_NET_ADMIN; local sandboxes usually cannot run it.
`fault-proxy.mjs` is a deterministic userspace HTTP fault injector (not netem) used by
`tests/network-failure/recovery.test.mjs`.

## Container (`Dockerfile`, `compose.yaml`)

Two-stage build; runtime copies only `dist/` (from `scripts/build.mjs` allowlist) and `deployment/`.
UID 1000, read-only root, dropped capabilities, no-new-privileges (see
`docs/secure-airgap-profile.md`). CI `container` job builds, runs a three-service deployment,
verifies crypto/policy in containers, scans the image and generates an SBOM.
`packages/pqc-lab` and any `node_modules` never enter `dist/` (ADR-008).

## Offline installation and rollback (`packages/release/offline.mjs`, `scripts/offline-release.mjs`)

`node scripts/offline-release.mjs build <dest> <version>` requires a clean tree and a
0600 `SIEPMU_RELEASE_KEY`. Bundles embed the Node runtime, per-file SHA-256, a signed manifest;
install rejects traversal, symlinks, special files, oversize, trust-root changes and version
rollback unless a separately signed rollback authorization is present. Ledger lives outside the
installed tree (`SIEPMU_RELEASE_LEDGER`). Excludes `RELEASE_EXCLUDED_PATHS`.

## Required checks for deployment changes

```sh
npm run test:engineering                       # tls, secure-stack, custody, monitoring, FLASH, offline release, providers
node --test --test-concurrency=1 tests/network-failure/recovery.test.mjs tests/independent-services.test.mjs
npm run build && npm run sbom
docker build --pull -t syntriass-siepmu:local .   # where Docker is available
```

Negative cases that must keep passing: wrong CA, wrong hostname, expired cert, revoked cert,
unpinned client identity, plaintext override in secure profile, redirect, oversize response,
custodian outage, rollback without authorization, symlink in bundle.

## Forbidden

Plain HTTP between services in secure profiles; disabling verification; TLS < 1.3; sharing one
certificate across roles; committing keys or `.data/`; adding lab code or dev tools to the image;
weakening `.dockerignore`.

## Definition of done

Commands above pass locally; hosted `container` and `testbed` jobs pass on the pushed SHA;
`docs/deployment.md` and `docs/secure-airgap-profile.md` updated.

## Known limitations

Lab PKI is synthetic and short-lived; no HSM-backed CA, OCSP or real IAF PKI. Single host for
the secure stack test; the testbed is containers on one runner, not distributed hardware.
