# SYNTRIASS SIEPMU-69 demonstrator

A working, synthetic-data prototype for secure inter-unit information exchange over an untrusted network. The repository slug is `SIEMPU`; the official challenge acronym is **SIEPMU**.

**Status: PROTOTYPE with measured engineering tests.** This is not IAF approved, SAG graded, operationally accredited, externally penetration tested, or a patentability claim. See [implementation status](docs/IMPLEMENTATION_STATUS.md), [limitations](docs/limitations.md) and [claims](docs/claims.md).

The central experiment is **policy-epoch-bound release**: ciphertext can be queued or relayed, but recipient-wrapped key material stays behind an authority check. A transaction revalidates current users, devices, roles, mission membership, destination policy, grant expiry and epoch, then commits one signed issuance and its evidence. Revocation committed first blocks release. An issuance committed first may already be usable and cannot be recalled.

## Run locally

Requires Node **24.19.0**, npm and a current browser with WebCrypto. Runtime services use Node built-ins; npm dependencies are development tools only.

```sh
git clone https://github.com/richardrich999888-rgb/SIEMPU.git
cd SIEMPU
git switch feature/repository-foundation
npm ci --ignore-scripts
npm run bootstrap
npm start
```

Open **http://127.0.0.1:8080**. Three processes run on loopback: web gateway `8080`, control authority `8081`, ciphertext relay `8082`. Stop with Ctrl-C. Provisioning refuses to overwrite an existing database. Use a new `SIEPMU_DATA_DIR` for another demo.

Bootstrap creates randomly generated **synthetic** credentials, keys and MFA seeds in `.data/demo-profiles.json` (private, ignored by Git). On the login screen:

1. Import this provisioning file, select `alice`, and choose a new vault passphrase. Import pins the authority key and encrypts the selected device keys locally.
2. Enter the selected profile's username/password from the private provisioning file.
3. Obtain a current six-digit demo authenticator code in a separate terminal:

```sh
node scripts/bootstrap.mjs otp alice
```

4. Authenticate. The provisioned device binds through a signed challenge. Never reuse a consumed TOTP in the same time window.
5. Use a separate browser profile/context for `bob` and `admin`. The console is at `/admin`. Never use these fixtures for operational data.

The browser encrypts plaintext and recipient key material before submission. Importing provisioning secrets is a **demo-only offline provisioning convenience**. New user/device enrollment is also available through the UI; a device needs administrator approval before binding.

## Reproduce the evidence

```sh
npm run verify
npm run test:coverage
node scripts/demo.mjs
node scripts/benchmark.mjs
node apps/verifier/verify.mjs artifacts/demo/receipt.json artifacts/demo/public-key.json
node apps/verifier/verify.mjs artifacts/demo/evidence.json artifacts/demo/public-key.json --checkpoint artifacts/demo/checkpoint.json
```

`demo.mjs` provisions its own temporary identities and starts all three services on available ports. It exercises real HTTP exchange, a disconnected backlog, recipient revocation, selective release and detached evidence verification. `benchmark.mjs` measures a sequential synthetic loopback workload; it is not a WAN or capacity benchmark. Generated results live in `artifacts/`, outside source control.

Run the three named HTTP acceptance scenarios with `make e2e`. Browser acceptance provisions and cleans up an isolated deployment with `make browser`, after installing Playwright Chromium. The direct `node apps/unit-client/browser-check.mjs` runner also supports a fresh running deployment. See [client instructions](apps/unit-client/README.md). Container and browser tests have dedicated CI jobs; configuration alone is not a passing result.

## What is implemented

| Area           | Implementation                                                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Identity       | Password scrypt, mandatory TOTP, durable replay floor, session expiry/revocation, device approval and signed possession challenges               |
| Authorization  | Server-enforced roles, unit/mission policies, current device/user state, signed operation/body binding                                           |
| E2EE           | P-256 ECDH/HKDF/AES-256-GCM content-key wrapping, AES-GCM payload, P-256 signatures; no server plaintext                                         |
| Offline client | Encrypted local vault, bounded cached creation grant, durable queue and local-only restart; fresh authentication required for network submission |
| Admission      | Creation grant plus current authority, global policy epoch, transactional issuance and retry revalidation                                        |
| Evidence       | Signed hash chain, signed receipts/checkpoints, detached verifier; independently retained checkpoint needed to detect valid-prefix truncation    |
| Storage        | Versioned SQLite migrations, separate ciphertext database, encrypted TOTP seeds and encrypted endpoint vault                                     |
| Operations     | Structured redacted logs, counters/alerts, admin console, health checks, encrypted backup/restore                                                |
| Delivery       | Native development environment, Docker/Compose definitions, CI security/quality jobs, release artifacts/SBOM                                     |

## Repository map

```text
apps/unit-client/       browser application and encrypted offline queue
apps/admin-console/     role-gated operational console
apps/verifier/          independent evidence verification CLI
services/control/      identity, policy, admission and transactional evidence
services/relay/        ciphertext-only service and workload authentication
services/web/          static gateway and same-origin API proxy
packages/crypto/       browser/Node endpoint encryption and vault
packages/protocol/     named canonical JSON encoding
database/migrations/   checksummed, versioned schema changes
scripts/               bootstrap, demo, benchmark, backup and release tooling
tests/                 independent peer, race, crash and security regression tests
deployment/            container helpers
docs/                   requirements, decisions, controls, evidence and limitations
```

## Boundaries to understand

- The control authority holds opaque wrapped keys. Compromising it can cause premature release even though it does not possess recipient private keys. The relay alone cannot decrypt stored ciphertext.
- Software key possession is not TPM attestation. A compromised endpoint or malicious client distribution can expose content. Static recipient keys provide no forward secrecy.
- Metadata includes identities, unit/mission labels, timing, ciphertext sizes and routing context. This prototype does not hide traffic patterns. The directory currently exposes enrolled active identities/devices to authenticated bound users.
- Local queueing is implemented; disconnected peer-to-peer delivery, air-gap transfer and cross-domain guards are not.
- SQLite serializes authority updates on one host. This is not a horizontally available authority, classified multi-level system or full distributed zero-trust infrastructure.
- Database snapshot rollback is not automatically prevented. Retain checkpoints independently and revalidate authority during recovery.
- The crypto suite is a demonstration suite, not a SAG-graded implementation. Live IAF integration is not present; the integration route validates a synthetic schema only.
- Public deployment requires a configured TLS ingress and approved operational controls. The default cleartext listeners are local-only.

See the [HPSC runbook](docs/hpsc/demo-runbook.md), [protocol contract](docs/protocols/IMPLEMENTATION_CONTRACT.md), [deployment](docs/deployment.md), [supply chain](docs/SUPPLY_CHAIN_SECURITY.md) and [traceability](docs/TRACEABILITY_MATRIX.md).
