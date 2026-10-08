# Authenticated synthetic laboratory deployment

This profile runs the existing web, control and ciphertext relay handlers on three separate HTTPS listeners in one Node process. It executes real TLS, not a TLS configuration sketch. It is not evidence of independently administered hosts, a field deployment, certificate lifecycle qualification, SAG grading or IAF authorization.

## Trust boundaries

| Connection                          | Enforcement                                                                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Endpoint → web                      | TLS 1.3, CA chain/hostname validation and configured server certificate pin in the automated peer; browser operators must install the disposable lab CA explicitly |
| Web → control                       | TLS 1.3; both CA validation and exact allowed web certificate fingerprint                                                                                          |
| Control → relay                     | TLS 1.3; both CA validation and exact allowed control certificate fingerprint; existing request HMAC and nonce checks remain active                                |
| Synthetic legacy endpoint → adapter | TLS 1.3 and source certificate allowlist, separately signed versioned request, signed-source mission/unit scope                                                    |
| Adapter → public web API            | TLS 1.3 with pinned web identity; endpoint supplies its current MFA/device-bound session and one-use operation proof                                               |

CA membership alone does not authorize a service role. Same-CA certificates in another role receive `SERVICE_IDENTITY_DENIED`. Hostname validation remains active when certificate pinning is used. Unsupported configuration fails before listening. There is no TLS verification bypass or HTTP fallback in the secure profile.

## Repeatable local operation

Prerequisites: Node 24.19.x or another supported Node 24 patch, OpenSSL CLI for disposable certificates, and already installed pinned development tools if running tests. No new npm dependency is required. Normal runtime has no mandatory external cloud dependency.

From the repository root, create synthetic application data and a separate disposable PKI directory:

```sh
SIEPMU_DATA_DIR=.data/secure-lab node scripts/bootstrap.mjs
node --input-type=module -e "import { createLabPki } from './deployment/secure/lab-pki.mjs'; createLabPki('.data/secure-lab-pki')"
node deployment/secure/run.mjs .data/secure-lab .data/secure-lab-pki 8443
```

Open `https://127.0.0.1:8443` only after explicitly trusting the disposable CA for this isolated laboratory. Do not disable browser certificate verification. Generated private keys stay in the caller's private directory; no PEM private keys, provisioning credentials or live certificates belong in git. The lab issuer is valid two days and leaf certificates one day. Generate a fresh directory for a new run; do not replace active service identities without a coordinated pin update. Delete only the explicitly disposable data/PKI directories to reset the lab.

`SIEPMU_ALLOW_PQC_LAB=1` is an explicit experimental opt-in passed to the authority; the separate suite-policy gate still applies. Omission disables the lab flag. Other values reject startup. This option does not make the transport post-quantum and is not approval to use a hybrid suite operationally.

Tests use fresh OS temporary directories, listen only on loopback, generate fresh CA/service keys, provision synthetic users and remove their state when complete:

```sh
node --test --test-concurrency=1 tests/transport/mtls.test.mjs tests/integration/synthetic-adapter.test.mjs tests/network-failure/recovery.test.mjs
```

## Remaining deployment work

The launcher is a local lab harness. Independent process/host isolation, managed DNS, host firewall rules, VLANs, external certificate issuance/rotation, CRL/OCSP procedures, unattended secrets injection, hardware protection and operator-owned backup custody require a representative environment. Existing container build/release, SBOM and recovery workflows remain separate gates; this profile does not claim a new container or offline installation test was executed. Node TLS behavior is based on the [Node 24 TLS API](https://nodejs.org/download/release/v24.19.0/docs/api/tls.html).
