# HPSC demonstration package: four reproducible demonstrations

**Frozen build:** see [FROZEN_BASELINE.md](FROZEN_BASELINE.md).

**Rules:**

- Every demonstration uses fresh synthetic identities, a fresh lab PKI and temporary storage.
- Each one writes a report with the commit it ran from and its PASS/FAIL per step.
- Never present a recorded run as live. If a live step fails, show the failure and the report from
  the frozen build's hosted CI run.
- No real, operational or classified data, ever.

## Preparation (once, on the presentation laptop)

```sh
git clone https://github.com/richardrich999888-rgb/SIEMPU && cd SIEMPU
git checkout <frozen SHA from FROZEN_BASELINE.md>
npm ci --ignore-scripts                 # Node 24.21.0 (>=24.19 <25); openssl on PATH
npm run build:native                    # optional: Rust verifier (cargo 1.97.0)
npm run demo:hpsc        # dry run of all four demos; index in artifacts/hpsc-rehearsal/index.md
```

**Reset:** `rm -rf artifacts/demo artifacts/trust-before-release artifacts/demo-document-exchange artifacts/demo-monitoring-recovery artifacts/hpsc-rehearsal`.

The runs leave no other state behind.

**Test credentials procedure:**

- The scripted demonstrations generate their own users, TOTP secrets and device keys in a temporary
  directory, and delete them on exit.
- For the live browser walkthrough, `npm run bootstrap` writes a private provisioning file under
  `.data/` (mode 0600). One-time codes come from `node scripts/bootstrap.mjs otp <username>`.
- Never display the provisioning file on screen. Delete `.data/` after the session.

## Demo 1: Secure exchange (≈ 4 min live; script 1.5 s)

|                 |                                                                                                                                         |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Live path       | `npm run bootstrap` then `npm start`. Open `http://127.0.0.1:8080` in three isolated browser profiles (Unit A, Unit B, admin)           |
| Show            | MFA login; device approval; A sends text and a file to B; B decrypts; an unrelated Unit C user is refused; ciphertext only at the relay |
| Scripted backup | `npm run demo`: 9 steps, PASS in 1.5 s on the build host. Writes `artifacts/demo/{receipt,evidence,checkpoint,public-key}.json`         |
| Verify          | `node apps/verifier/verify.mjs artifacts/demo/evidence.json artifacts/demo/public-key.json --checkpoint artifacts/demo/checkpoint.json` |
| Expected        | Exact bytes delivered; denied user gets no key; verifier ACCEPT                                                                         |
| Limits          | Single host; software device keys; classical suite not SAG graded                                                                       |
| Recovery        | Ctrl-C, `rm -rf .data`, re-bootstrap (≈ 30 s), or switch to the scripted run                                                            |

## Demo 2: Trust Before Release (≈ 3 min; script ≈ 9 s)

|          |                                                                                                                                                                                                                                                                                                |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command  | `npm run demo:trust-before-release` (set `SIEPMU_TBR_ITERATIONS=5` for a faster run)                                                                                                                                                                                                           |
| Show     | Five-process TLS/mTLS stack; Unit A is cut off by the fault proxy; a recipient is revoked while A is offline; A reconnects; the revoked recipient's object is **HELD** with a signed decision and the eligible one is **released**; downgrade rejected; authority restart; strict verification |
| Expected | 14/14 PASS; `artifacts/trust-before-release/report.md` lists the steps and timings                                                                                                                                                                                                             |
| Say      | "Release is decided by current authority at the moment of release. A key issued before revocation cannot be recalled, and we do not claim otherwise."                                                                                                                                          |
| Limits   | Fault proxy, not a WAN; single host; laboratory PQC content suite                                                                                                                                                                                                                              |
| Recovery | Re-run (fresh state each run), or show the hosted CI `native-evidence` report for the frozen SHA                                                                                                                                                                                               |

## Demo 3: Existing-system integration (≈ 2 min; script ≈ 2.5 s)

|          |                                                                                                                                                                                                                                                                                                                                                                                 |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command  | `npm run demo:documents`                                                                                                                                                                                                                                                                                                                                                        |
| Show     | A separate synthetic document system hands a document to the adapter (its own process, mTLS-pinned source). Duplicate → same object; altered replay → refused; unauthorised destination → refused; unpinned source → refused; destination system decrypts, validates and returns a signed DELIVERY_ACK; source sees DELIVERED; evidence verified by the Node and Rust verifiers |
| Expected | 10/10 PASS; `artifacts/demo-document-exchange/report.md`                                                                                                                                                                                                                                                                                                                        |
| Say      | "This is a synthetic document application, not AFNET or e-Office. It shows that an approved interface can be bound to the adapter without touching the security core."                                                                                                                                                                                                          |
| Recovery | Re-run, or show the hosted report                                                                                                                                                                                                                                                                                                                                               |

## Demo 4: Monitoring and recovery (≈ 3 min; script ≈ 3.5 s)

|          |                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command  | `npm run demo:monitoring`                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Show     | Failed MFA → 401; wrong role → 403 + ACCESS_DENIED; policy withdrawn → HELD with signed decision; policy restored → re-evaluated and released; relay stopped → submission refused with nothing half-written → restarted; authority restarted → retry returns the **same** issuance; device revoked; independent collector shows the alerts with no content; operator acknowledges; non-operator refused; evidence verified, tampered copy rejected |
| Expected | 11/11 PASS; `artifacts/demo-monitoring-recovery/report.md`                                                                                                                                                                                                                                                                                                                                                                                         |
| Say      | "Monitoring is rule-based today. Analytics and SOC integration are funded work."                                                                                                                                                                                                                                                                                                                                                                   |
| Limits   | Process restarts stand in for failures; the gateway's readiness does not reflect relay health                                                                                                                                                                                                                                                                                                                                                      |
| Recovery | Re-run, or show the hosted report                                                                                                                                                                                                                                                                                                                                                                                                                  |

## Evidence to bring

- The four reports from the frozen-build run.
- The hosted CI run links for the frozen SHA (`FROZEN_BASELINE.md`).
- `docs/trl/TRL_ASSESSMENT.md`, `docs/hpsc/PS69_COMPLIANCE.md` and `CLAIMS_REGISTER.yaml`.

Keep the trusted public key and checkpoint on separate media from the evidence they verify.
