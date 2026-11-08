# Optional PKCS#11 endpoint integration

This implements the existing P-256 endpoint provider port using `python-pkcs11` 0.10.1.
Long-term signing and ECDH keys are generated on the selected token and requested with
sensitive/non-extractable attributes. Every operation reopens the pinned token, checks
those attributes and binds its public key to the originally selected key. The managed
endpoint SDK accepts this provider through its existing `provider` constructor argument.
Services receive public enrollment keys and ciphertext, never token credentials or private keys.

The tested token is **SoftHSM 2.7.0, a software emulator**. Hardware custody, a vendor module,
physical tamper resistance, protected authentication paths, IAF approval and SAG grading
are not established. `hardwareBacked` and `sagGraded` deliberately remain false.

## Install and select explicitly

Use an isolated CPython 3.12 / Linux x86_64 environment. The exact direct/transitive wheels
are pinned by hash; do not install these packages into the root Node application.

```sh
python3.12 -m venv /operator/provisioned/pkcs11-venv
/operator/provisioned/pkcs11-venv/bin/pip install --require-hashes --only-binary=:all: \
  -r integrations/pkcs11/requirements.txt
```

Create `createPkcs11Provider` with absolute `python` and `module` paths, their SHA-256
pins, `workerSha256`, exact `tokenLabel` and `tokenSerial`, and an operator-owned `getPin`
callback. The callback supplies the PIN in memory; it is transmitted over a private
stdin pipe, never command arguments or environment variables. No PIN is stored in a
profile or report. JavaScript/Python strings are not securely erasable: a trusted endpoint,
process isolation, swap/dump policy and vendor PIN procedures remain required.
`softhsmConfig` is a laboratory-only explicit configuration file; omit it for other modules.

Call `generateOpaqueDeviceKeys()` on `createObjectCryptography(provider)` for enrollment.
Persist only the returned public keys and handle IDs. On restart, call
`provider.openKey(id, purpose, previouslyTrustedPublicKey)` and construct the endpoint
profile with the returned handles. Enroll/approve through the authority's existing workflow;
this provider never grants personnel authority. `destroy(handle)` invalidates local handles,
including previously resolved references; it does **not** erase a persistent token object.
Production object deletion, backup, rollover, lockout recovery and dual control are vendor
ceremonies, not implemented provisioning claims. Partial generation can leave an orphaned
object requiring operator cleanup.

Unavailable modules/tokens, wrong PINs, changed executable/module/worker hashes, missing
attributes, wrong key purposes and substituted public keys fail closed. No alternate
provider is selected. One request is allowed at a time; subprocess time/output/input are
bounded. The Python environment, native dependencies and configuration must be protected
against modification. Hash checks are not host attestation or a defense against a privileged
actor racing a file replacement. Review/install the complete environment as an immutable unit.

## Exact crypto boundary

The token performs ECDSA over SHA-256 digests and P-256 ECDH. ECDH outputs a **derived
session secret**, which reaches endpoint software for HKDF and AES-GCM. Content encryption,
wrapping, hashing and outbound ephemeral ECDH remain in WebCrypto. This is not an all-HSM
crypto boundary or a SAG-selected algorithm implementation. The shared classical object
format is unchanged; outbound ephemeral private keys now stay non-extractable and are
never serialized into JWK. Importing software EC private keys through this provider is refused.
The browser and the separate v3/PQC provider engine are not wired to this optional provider.

## Reproduce the native gate

Provide `SIEPMU_PKCS11_LAB_CONFIG` pointing to JSON with absolute `python`, `module` and
`util` (SoftHSM provisioning utility) paths. Do not include a PIN. The test creates and
removes its own synthetic token and generated credentials. Missing prerequisites fail.

```sh
node --test --test-reporter=tap tests/pkcs11/provider.check.mjs
```

The nine-test report covers native attribute/export behavior; bidirectional v1/v2 objects;
changed inputs, wrong PIN/token/purpose; restart with public-key pinning; no software-key
fallback; invalidated handles; token removal; and SDK enrollment, device proof, encryption,
policy-authorized release plus a denied reverse-unit release. The SDK fixture uses a real
in-process authority with a synthetic clock advance for a fresh TOTP counter; it does not
claim a new network/TLS test. Hosted workflow: `.github/workflows/endpoint-native.yml`.

## Dependency and review record — 8 November 2026

| Component                                | Selection                                                | Role / license                                    |
| ---------------------------------------- | -------------------------------------------------------- | ------------------------------------------------- |
| python-pkcs11                            | 0.10.1, exact CPython 3.12 Linux wheel                   | PKCS#11 binding / MIT                             |
| asn1crypto                               | 1.5.1, exact wheel                                       | public EC parameter/SPKI encoding / MIT           |
| SoftHSM                                  | 2.7.0, commit `13e6e86b83748fef74046dbf0c91f664b7acc1c3` | test emulator only / BSD-2-Clause                 |
| CPython, OpenSSL and OS loader libraries | recorded on the executing host                           | deployment inventory and advisory review required |

Upstream sources: [binding](https://github.com/pyauth/python-pkcs11),
[release/wheel metadata](https://pypi.org/project/python-pkcs11/0.10.1/),
[API documentation](https://python-pkcs11.readthedocs.io/en/latest/api.html),
[SoftHSM release](https://github.com/softhsm/SoftHSMv2/releases/tag/2.7.0),
[SoftHSM advisory page](https://github.com/softhsm/SoftHSMv2/security).
Published advisory-page inspection is not a complete vulnerability assessment. The isolated
Python lock is included in repository vulnerability scanning. License texts are retained in
`notices/`. No upstream binaries or production credentials are committed.
