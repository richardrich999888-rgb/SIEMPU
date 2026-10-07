# Reproducible HPSC runbook

Use synthetic content and a fresh deployment. Freeze the commit and save evidence before presenting. No operational information is permitted in this lab.

```sh
npm ci --ignore-scripts
npm run verify
npm run test:coverage
node scripts/demo.mjs
node apps/verifier/verify.mjs artifacts/demo/receipt.json artifacts/demo/public-key.json
node apps/verifier/verify.mjs artifacts/demo/evidence.json artifacts/demo/public-key.json --checkpoint artifacts/demo/checkpoint.json
```

The demo provisions temporary random identities, starts the real three-process HTTP stack, exchanges/decrypts an object, denies an unrelated user, creates two local queued objects without contacting services, revokes one recipient, reconnects selectively, fences a policy change between READY and claim and exports signed evidence. It stops and removes temporary private state; generated public synthetic evidence remains in `artifacts/demo`.

This scripted disconnect is logical network absence during creation. The separate [real browser run](../testing/browser-validation.md) tested browser network-offline plus reload. Race/crash/restart and tamper tests belong to the automated suite; do not imply the shorter demo script exercises every fault itself.

For the visual story: `npm run bootstrap`, `npm start`, open `http://127.0.0.1:8080`, use isolated contexts for Alice/Bob/admin and the private generated provisioning file. Obtain MFA via `node scripts/bootstrap.mjs otp alice` (change name as needed). See [client instructions](../../apps/unit-client/README.md) and [ten-minute story](story.md). For automated browser acceptance follow `browser-check.mjs` instructions against a fresh deployment; it consumes OTPs and changes synthetic policies.

A trust root supplied alongside untrusted evidence is not independently trusted. The demo public key/checkpoint are reproducibility fixtures; in evaluation retain them separately before an attack/rollback test. Show the trusted release boundary and post-commit recall limit. Mark software devices, synthetic integration and local bearer honestly.
