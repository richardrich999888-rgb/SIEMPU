# Browser client

The unit client and administration console are native browser modules served by the web gateway. Use `http://127.0.0.1:8080/` locally. Network deployment requires HTTPS; WebCrypto and service workers require a secure browser context. `/admin` opens the same authenticated application at its authority console.

## First use

1. Run the repository bootstrap and start commands.
2. On the authority-trust screen, expand **Import a provisioned synthetic demo device**. Select the generated `demo-profiles.json`, choose one synthetic username and enter a new vault passphrase of at least 12 characters. The provisioned authority public key must match the server. This imports only that user's device keys and pins the authority key; the app does not persist the bootstrap password or TOTP seed.
3. Authenticate using the profile's password and a current TOTP. `node scripts/bootstrap.mjs otp alice` prints the current synthetic code for Alice. Successful login binds the imported device and refreshes signed authority, directory and creation-grant snapshots.
4. Use another isolated browser profile/context for Bob or the administrator. This keeps the demo's endpoint identities separate. Ordinary users can also generate a fresh vault, enroll a device and wait for administrative approval.
5. Alice selects Bob's provisioned device, creates a synthetic message and submits. Bob opens **Objects & receipts**, validates release, verifies the sender signature and decrypts locally.

## Local storage and disconnect behavior

Passwords, TOTP seeds and bearer tokens are never saved in browser storage. The bearer exists only in tab memory. Device private keys, queued encrypted submissions, cached signed authority metadata and the decrypted inbox are inside a PBKDF2/AES-GCM encrypted vault. The vault passphrase is separate from the login password and is retained only while unlocked. JavaScript cannot guarantee physical memory erasure, and compromised endpoint/client software remains inside the trust boundary.

The local outbox is saved before upload. A failed request leaves the item queued. Reconnection refreshes current authority and submits/re-evaluates each item separately. Objects denied by current policy remain held. An object expires no later than its creation grant; replacing a cached grant does not rewrite an existing object's signed envelope.

**Simulate disconnect** disables the client's API transport and is explicitly labeled as a simulation. A public static app-shell service worker additionally allows a previously loaded application to reopen during a real network outage. It caches only an explicit source-asset allowlist, never API responses, user data or credentials. Offline unlock uses cached user/device metadata solely for local UI operations; it does not authorize server access. Reconnection after a reload requires fresh MFA authentication. Expired grants and detected backward clock movement prevent new creation. A software clock is not trusted proof of creation time.

The worker is part of the trusted client-distribution boundary. Old app-shell cache versions are removed on activation; deployment operators must version the cache when changing its asset set. Cache deletion, browser storage eviction, private-mode limits and an unprimed shell can prevent offline reload. This is not an air-gap delivery implementation.

The demonstrator caps browser file attachments at 512 KiB to fit encrypted browser storage. Files use `application/octet-stream` and attachment downloads; no content is executed or automatically opened. Plaintext malware scanning is **not implemented**. Browser-storage capacity and simultaneous-tab use limit scale. A compare-before-write check rejects stale tabs instead of silently replacing a newer encrypted vault; export pending local work before reconciling such a conflict.

## Authority and receipt verification

An explicit first-use decision or a trusted provisioning file pins the authority key. The client verifies signed control, directory, grant and receipt packets, compares unsigned directory views to their signed contents, checks receipt object/envelope digests, and uses the sender key from the verified directory. A valid receipt is not proof of factual truth or human reading. A later revocation cannot recall an already released key or plaintext.

## Validation status

- JavaScript syntax checks: executed.
- Stale-tab overwrite and blocked-storage regression tests: executed with `node --test apps/unit-client/vault-store.test.mjs`.
- Real-browser end-to-end run: see repository execution evidence. Browser availability must be established before claiming this layer passed; static checks and API tests do not establish browser behavior.

`browser-check.mjs` is a real-browser acceptance runner for an already running **fresh synthetic** deployment. Install Playwright and its Chromium binary in a separate test environment, then set `SIEPMU_PLAYWRIGHT_MODULE` to that environment's Playwright module (or install it where Node can resolve it). The runner performs genuine browser UI operations and fails if the executable is unavailable.

```sh
SIEPMU_BROWSER_PROFILES=.data/demo-profiles.json \
SIEPMU_PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
node apps/unit-client/browser-check.mjs
```

The runner changes the synthetic Unit A → Unit B policy and consumes current TOTP codes. Use a fresh isolated fixture. Its output and screenshots are written only after actual execution; the source file itself is not a passing test result.
