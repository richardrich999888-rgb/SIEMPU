/** Actual-browser acceptance runner. Requires a running, fresh synthetic deployment. */
import { readFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { totp } from '../../services/control/primitives.mjs';
import { checkShellUpgrades } from '../../tests/browser/shell-upgrade.mjs';

const base = new URL(process.env.SIEPMU_URL || 'http://127.0.0.1:8080');
if (!['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname))
  throw new Error('Browser acceptance runner is restricted to a local synthetic deployment.');
const profilesPath = resolve(process.env.SIEPMU_BROWSER_PROFILES || '.data/demo-profiles.json');
const provisioning = JSON.parse(await readFile(profilesPath, 'utf8'));
if (provisioning.synthetic !== true) throw new Error('Synthetic provisioning profile required.');
const { chromium } = await import(process.env.SIEPMU_PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({
  headless: true,
  args: ['--disable-gpu', '--disable-software-rasterizer', '--no-zygote'],
  ...(process.env.SIEPMU_CHROMIUM_PATH ? { executablePath: process.env.SIEPMU_CHROMIUM_PATH } : {}),
});
const errors = [];
const results = [];
const vaultSecret = randomBytes(24).toString('base64url');
const artifactDir = resolve(process.env.SIEPMU_BROWSER_ARTIFACTS || 'artifacts/browser');
await mkdir(artifactDir, { recursive: true });

async function checkTrustStorageRecovery() {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const page = await context.newPage();
  const startupErrors = [];
  page.on('pageerror', (error) => startupErrors.push(error.message));
  try {
    await context.addInitScript(() => {
      localStorage.setItem(
        'siepmu.authority.pin.v1',
        JSON.stringify({ d: 'synthetic-invalid-pin' }),
      );
      localStorage.setItem('siepmu.public-meta.v1', JSON.stringify({ version: 'malformed-cache' }));
      globalThis.__siepmuStorageFailures = { remove: 0, cache: 0 };
      const remove = Storage.prototype.removeItem;
      const set = Storage.prototype.setItem;
      Storage.prototype.removeItem = function (key) {
        if (key === 'siepmu.authority.pin.v1') {
          globalThis.__siepmuStorageFailures.remove++;
          throw new DOMException('Synthetic storage removal denial', 'SecurityError');
        }
        return remove.call(this, key);
      };
      Storage.prototype.setItem = function (key, value) {
        if (key === 'siepmu.public-meta.v1') {
          globalThis.__siepmuStorageFailures.cache++;
          throw new DOMException('Synthetic cache write denial', 'SecurityError');
        }
        return set.call(this, key, value);
      };
    });
    await context.route('**/api/meta', (route) => route.abort(), { times: 1 });
    await page.goto(base.href);
    await page.getByRole('button', { name: 'Retry connection', exact: true }).waitFor();
    assert.ok((await page.locator('#main').innerText()).includes('Authority unavailable'));
    await page.getByRole('button', { name: 'Retry connection', exact: true }).click();
    await page
      .getByRole('button', { name: 'Trust independently verified authority', exact: true })
      .waitFor();
    await page
      .locator('#notice')
      .filter({ hasText: 'Public metadata could not be cached' })
      .waitFor();
    const failures = await page.evaluate(() => globalThis.__siepmuStorageFailures);
    assert.ok(failures.remove >= 2, 'Both startup attempts must reach the denied pin removal');
    assert.equal(failures.cache, 1, 'Live metadata must reach the denied cache write');
    assert.deepEqual(
      startupErrors,
      [],
      'Storage denial must not cause an uncaught startup failure',
    );
    results.push(
      'Malformed cached trust/metadata and blocked storage removal recover to visible trust UI without uncaught startup errors',
    );
  } finally {
    await context.close();
  }
}

async function loginUser(username) {
  const profile = provisioning.profiles.find((p) => p.username === username);
  assert.ok(profile, `Missing ${username} profile`);
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto(new URL(username === 'admin' ? '/admin' : '/', base).href);
  await page.getByText('Import a provisioned synthetic demo device', { exact: true }).click();
  await page.getByLabel('Provisioning profile file').setInputFiles(profilesPath);
  await page.getByLabel('Profile username').selectOption({ label: username });
  await page.getByLabel('New vault passphrase', { exact: true }).fill(vaultSecret);
  await page
    .getByRole('button', { name: 'Import & encrypt selected profile', exact: true })
    .click();
  await page.getByLabel('Username', { exact: true }).fill(username);
  await page.getByLabel('Password', { exact: true }).fill(profile.password);
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(profile.totpSecret));
  await page.getByRole('button', { name: 'Authenticate with MFA', exact: true }).click();
  await page.locator('#device-status').filter({ hasText: '· bound' }).waitFor();
  return { page, context, profile };
}
async function createMessage(page, message) {
  await page.getByRole('button', { name: 'Secure exchange', exact: true }).click();
  const bob = provisioning.profiles.find((p) => p.username === 'bob');
  await page.getByLabel('Recipient device').selectOption(bob.deviceId);
  await page.getByLabel('Message', { exact: true }).fill(message);
  await page
    .getByRole('button', { name: /^(Seal & submit securely|Seal into offline queue)$/ })
    .click();
}
async function setPolicy(page, allow) {
  await page.getByRole('button', { name: 'Policies', exact: true }).click();
  await page.getByLabel('From unit', { exact: true }).selectOption(provisioning.units.A);
  await page.getByLabel('To unit', { exact: true }).selectOption(provisioning.units.B);
  await page.getByLabel('Decision', { exact: true }).selectOption(String(allow));
  await page.getByRole('button', { name: 'Commit policy change', exact: true }).click();
  await page.locator('#notice').filter({ hasText: 'Policy committed' }).waitFor();
}

async function enrollFreshDevice(admin) {
  const profile = provisioning.profiles.find((p) => p.username === 'bravo');
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    serviceWorkers: 'block',
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(error.message));
  const meta = await (await context.request.get(new URL('/api/meta', base).href)).json();
  assert.deepEqual(meta.serverPublicKey, provisioning.serverPublicKey);
  await page.goto(base.href);
  await page
    .getByRole('button', { name: 'Trust independently verified authority', exact: true })
    .click();
  await page.getByLabel('Username', { exact: true }).fill(profile.username);
  await page.getByLabel('Password', { exact: true }).fill(profile.password);
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(profile.totpSecret));
  await page.getByRole('button', { name: 'Authenticate with MFA', exact: true }).click();
  await page.getByText('Authenticated as bravo.', { exact: true }).waitFor();
  await page.getByLabel('Vault username', { exact: true }).fill('bravo');
  await page.getByLabel('Vault passphrase', { exact: true }).fill(vaultSecret);
  await page.getByRole('button', { name: 'Create a new device vault', exact: true }).click();
  await page.getByLabel('Enrollment label', { exact: true }).fill('bravo browser device');

  let enrollmentRequests = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/api/devices/enroll')) enrollmentRequests++;
  });
  await context.route(
    '**/api/auth/challenge',
    async (route) => {
      const response = await route.fetch();
      const reply = await response.json();
      reply.challenge.requestHash = '0'.repeat(64);
      await route.fulfill({ response, json: reply });
    },
    { times: 1 },
  );
  await page.getByRole('button', { name: 'Enroll device', exact: true }).click();
  await page
    .locator('#notice')
    .filter({ hasText: 'does not match the locally intended operation' })
    .waitFor();
  assert.equal(
    enrollmentRequests,
    0,
    'Mismatched challenge must be rejected before device proof is sent',
  );
  results.push('Browser rejects a modified signing challenge before producing an enrollment proof');

  await context.route(
    '**/api/devices/enroll',
    async (route) => {
      const body = route.request().postDataJSON();
      body.encryptionPublicKey = provisioning.profiles.find(
        (p) => p.username === 'alice',
      ).keys.encryption.publicKey;
      await route.continue({ postData: JSON.stringify(body) });
    },
    { times: 1 },
  );
  await page.getByRole('button', { name: 'Enroll device', exact: true }).click();
  await page.locator('#notice').filter({ hasText: 'PROOF_BODY_MISMATCH' }).waitFor();
  results.push(
    'Server rejects enrollment encryption-key substitution after the browser signed the challenge',
  );

  await page.getByRole('button', { name: 'Enroll device', exact: true }).click();
  await page.locator('#notice').filter({ hasText: 'Device enrolled.' }).waitFor();
  await page.getByRole('button', { name: 'Bind existing device', exact: true }).click();
  await page.locator('#notice').filter({ hasText: 'DEVICE_UNTRUSTED' }).waitFor();
  await admin.page.getByRole('button', { name: 'Refresh console', exact: true }).click();
  await admin.page.getByRole('button', { name: 'Devices & sessions', exact: true }).click();
  await admin.page
    .getByRole('row')
    .filter({ hasText: 'bravo browser device' })
    .getByRole('button', { name: 'Approve', exact: true })
    .click();
  await admin.page.locator('#notice').filter({ hasText: 'Device approved.' }).waitFor();
  await page.getByRole('button', { name: 'Bind existing device', exact: true }).click();
  await page
    .locator('#device-status')
    .filter({ hasText: 'bravo browser device · bound' })
    .waitFor();
  results.push(
    'Fresh browser key generation, signed enrollment, pre-approval rejection, administrator approval and binding',
  );
  return { page, context };
}

async function checkRoleTransition(admin, auditor) {
  await admin.page.getByRole('button', { name: 'Units & users', exact: true }).click();
  const generic = admin.page.getByLabel('Generic role for bravo', { exact: true });
  const duty = admin.page.getByLabel('Duty position for bravo', { exact: true });
  const row = admin.page.getByRole('row').filter({ has: generic });
  const apply = async () => {
    const button = await row
      .getByRole('button', { name: 'Apply roles', exact: true })
      .elementHandle();
    await button.click();
    await button.waitForElementState('hidden');
    await admin.page.locator('#notice').filter({ hasText: 'saved atomically' }).waitFor();
  };
  await duty.selectOption('FIELD_OPERATOR');
  await apply();
  await generic.selectOption('auditor');
  await duty.selectOption('AUDIT_OFFICER');
  const mutation = admin.page.waitForRequest(
    (request) => request.method() === 'PATCH' && request.url().includes('/api/admin/users/'),
  );
  await apply();
  const request = await mutation;
  assert.equal(request.postDataJSON().role, 'auditor');
  assert.equal(request.postDataJSON().dutyRole, 'AUDIT_OFFICER');
  await admin.page.locator('#notice').filter({ hasText: 'saved atomically' }).waitFor();
  // Re-read authority data so selected options alone cannot satisfy this assertion.
  const refresh = await admin.page
    .getByRole('button', { name: 'Refresh console', exact: true })
    .elementHandle();
  await refresh.click();
  await refresh.waitForElementState('hidden');
  await generic.filter({ has: admin.page.locator('option[value="auditor"]:checked') }).waitFor();
  assert.equal(await generic.inputValue(), 'auditor');
  assert.equal(await duty.inputValue(), 'AUDIT_OFFICER');
  await auditor.page.getByRole('button', { name: 'Refresh authority', exact: true }).click();
  await auditor.page.getByRole('button', { name: 'Administration', exact: true }).click();
  await auditor.page.getByText('Release and security observations', { exact: true }).waitFor();
  await auditor.page.getByRole('button', { name: 'Units & users', exact: true }).click();
  assert.equal(
    await auditor.page.getByRole('button', { name: 'Apply roles', exact: true }).count(),
    0,
  );
  assert.equal(
    await auditor.page
      .getByRole('button', { name: 'Create user & MFA enrollment', exact: true })
      .count(),
    0,
  );
  results.push(
    'Administrator atomically changes operator/FIELD_OPERATOR to auditor/AUDIT_OFFICER; refreshed authority confirms both and auditor UI remains read-only',
  );
  await auditor.page.getByRole('button', { name: 'Evidence & integration', exact: true }).click();
  await auditor.context.route(
    '**/api/evidence/checkpoint',
    async (route) => {
      const response = await route.fetch();
      const checkpoint = await response.json();
      checkpoint.payload.sequence++;
      await route.fulfill({ response, json: checkpoint });
    },
    { times: 1 },
  );
  await auditor.page.getByRole('button', { name: 'Save external checkpoint', exact: true }).click();
  await auditor.page
    .locator('#notice')
    .filter({ hasText: 'signature could not be verified' })
    .waitFor();
  assert.equal(
    await auditor.page
      .getByText('No checkpoint signature checked in this view.', { exact: true })
      .count(),
    1,
  );
  const checkpointDownload = auditor.page.waitForEvent('download');
  await auditor.page.getByRole('button', { name: 'Save external checkpoint', exact: true }).click();
  await checkpointDownload;
  await auditor.page
    .getByText(/^Checkpoint signature verified with the pinned authority key:/)
    .waitFor();
  results.push(
    'Read-only auditor rejects a tampered checkpoint and displays verified status only after a valid signature check',
  );
  await auditor.context.close();
}

async function checkConcurrentVaultLocks(owner) {
  const peer = await owner.context.newPage();
  await peer.goto(base.href);
  const key = 'siepmu.browser-lock-regression';
  await owner.page.evaluate((name) => localStorage.removeItem(name), key);
  const attempt = (page, value) =>
    page.evaluate(
      async ({ key, value }) => {
        const { commitEncryptedVaultLocked } = await import('/apps/unit-client/vault-store.mjs');
        try {
          await commitEncryptedVaultLocked(localStorage, navigator.locks, key, null, {
            ciphertext: value,
          });
          return 'committed';
        } catch (error) {
          if (error.message.includes('another tab')) return 'stale';
          throw error;
        }
      },
      { key, value },
    );
  const outcomes = await Promise.all([
    attempt(owner.page, 'first-sealed-fixture'),
    attempt(peer, 'second-sealed-fixture'),
  ]);
  assert.deepEqual(outcomes.sort(), ['committed', 'stale']);
  await owner.page.evaluate((name) => localStorage.removeItem(name), key);
  await peer.close();
  results.push(
    'Actual browser Web Locks serialize two tabs and reject the stale encrypted-vault write',
  );
}

// Bounded retry: a single refresh can race the sender's prepare round trip.
const REFRESH_ATTEMPTS = 20;
const REFRESH_INTERVAL_MS = 250;
async function refreshUntilReleasable(page) {
  const action = page.getByRole('button', { name: 'Validate release & decrypt', exact: true });
  for (let i = 0; i < REFRESH_ATTEMPTS; i++) {
    await page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
    if ((await action.count()) > 0) return;
    await page.waitForTimeout(REFRESH_INTERVAL_MS);
  }
  throw new Error('Recipient never observed a releasable object');
}

async function exchangeFile(alice, bob) {
  await alice.page.getByRole('button', { name: 'Secure exchange', exact: true }).click();
  const recipient = provisioning.profiles.find((p) => p.username === 'bob');
  await alice.page.getByLabel('Recipient device').selectOption(recipient.deviceId);
  let submitted = 0;
  const countSubmission = (request) => {
    if (request.method() === 'POST' && request.url().endsWith('/api/objects')) submitted++;
  };
  alice.page.on('request', countSubmission);
  await alice.page.getByLabel('Attach a file').setInputFiles({
    name: '..',
    mimeType: 'text/html',
    buffer: Buffer.from('<script>syntheticUnsafeName</script>'),
  });
  await alice.page.getByRole('button', { name: 'Seal & submit securely', exact: true }).click();
  await alice.page.locator('#notice').filter({ hasText: 'Unsafe file name' }).waitFor();
  assert.equal(submitted, 0, 'Unsafe filename must fail before any object submission');
  results.push('Unsafe dot-dot file name rejected in browser before object submission');

  const filename = 'synthetic-evidence.txt';
  const bytes = Buffer.from(
    'SIEPMU synthetic UTF-8 file\nIntegrity check: தமிழ் · हिन्दी · Δ\n',
    'utf8',
  );
  // An untrusted MIME hint is intentionally supplied; the client must treat it as opaque binary.
  const cardsBefore = await alice.page.locator('.object-card').count();
  await alice.page
    .getByLabel('Attach a file')
    .setInputFiles({ name: filename, mimeType: 'text/html', buffer: bytes });
  await alice.page.getByRole('button', { name: 'Seal & submit securely', exact: true }).click();
  // An earlier object's card can still show a stale READY badge, so wait for the NEW card
  // (outbox renders newest first) rather than any READY badge.
  await alice.page.waitForFunction(
    (n) => document.querySelectorAll('.object-card').length === n,
    cardsBefore + 1,
  );
  await alice.page.locator('.object-card').first().locator('.badge.ready').waitFor();
  await refreshUntilReleasable(bob.page);
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.locator('.object-body').filter({ hasText: filename }).waitFor();
  await bob.page.evaluate(() => {
    const original = URL.createObjectURL;
    URL.createObjectURL = function (blob) {
      globalThis.__siepmuDownloadMime = blob.type;
      return original.call(this, blob);
    };
  });
  const received = bob.page.waitForEvent('download');
  await bob.page
    .getByRole('button', { name: 'Download encrypted-transfer attachment', exact: true })
    .click();
  const download = await received;
  assert.equal(download.suggestedFilename(), filename);
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), bytes);
  assert.equal(
    await bob.page.evaluate(() => globalThis.__siepmuDownloadMime),
    'application/octet-stream',
  );
  alice.page.off('request', countSubmission);
  results.push(
    'Real file-input encryption, recipient release/decryption and attachment download preserve exact UTF-8 bytes and filename',
  );
  results.push(
    'Untrusted HTML MIME hint is replaced by application/octet-stream for attachment download',
  );
}

try {
  await checkShellUpgrades(browser, results);
  await checkTrustStorageRecovery();
  const alice = await loginUser('alice');
  const bob = await loginUser('bob');
  const admin = await loginUser('admin');
  results.push('MFA, encrypted provisioning vault and device binding through real browser UI');
  const bravo = await enrollFreshDevice(admin);
  await checkRoleTransition(admin, bravo);
  await checkConcurrentVaultLocks(alice);
  const message = `Synthetic browser exchange ${Date.now()} <img src=x onerror="globalThis.__siepmuXss=1">`;
  await createMessage(alice.page, message);
  await alice.page.locator('.badge.ready').waitFor();
  await bob.page.getByRole('button', { name: 'Objects & receipts', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.getByText(message, { exact: true }).waitFor();
  assert.equal(await bob.page.evaluate(() => globalThis.__siepmuXss), undefined);
  assert.equal(await bob.page.locator('.object-body img').count(), 0);
  results.push(
    'End-to-end text encryption, release, browser decryption, ACK and untrusted text rendering',
  );
  await exchangeFile(alice, bob);

  await alice.page.getByRole('button', { name: 'Simulate disconnect', exact: true }).click();
  const queuedMessage = `Queued during authority change ${Date.now()}`;
  await createMessage(alice.page, queuedMessage);
  await alice.page.locator('.badge.queued').waitFor();
  await setPolicy(admin.page, false);
  await alice.page.getByRole('button', { name: 'Reconnect & validate', exact: true }).click();
  await alice.page.locator('.badge.held').first().waitFor();
  // The hold is explained in operator terms with the authority code preserved (ADR-012).
  const notice = alice.page.locator('.decision', { hasText: 'Code: POLICY_DENIED' }).first();
  await notice.waitFor();
  assert.match(await notice.innerText(), /No current exchange policy/);
  assert.equal(await notice.getAttribute('role'), 'note');
  results.push(
    'Durable local queue and current-policy hold after simulated disconnect/reconnection',
  );
  results.push('Held object shows an operator explanation with the authority code (POLICY_DENIED)');
  await setPolicy(admin.page, true);
  await alice.page
    .getByRole('button', { name: 'Synchronize eligible objects', exact: true })
    .click();
  await alice.page.locator('.badge.ready').waitFor();
  await bob.page.getByRole('button', { name: 'Refresh objects', exact: true }).click();
  await bob.page.getByRole('button', { name: 'Validate release & decrypt', exact: true }).click();
  await bob.page.getByText(queuedMessage, { exact: true }).waitFor();
  results.push('Permitted current-policy release after explicit authority change');

  const stored = await alice.page.evaluate(() =>
    JSON.stringify(Object.fromEntries(Object.entries(localStorage))),
  );
  assert.ok(!stored.includes(message), 'Plaintext message must not appear in localStorage');
  assert.ok(
    !stored.includes(alice.profile.keys.signing.privateKey.d),
    'Private key must not appear in localStorage',
  );
  assert.ok(
    !stored.includes(alice.profile.password),
    'Login password must not appear in localStorage',
  );
  assert.ok(
    !stored.includes(alice.profile.totpSecret),
    'TOTP seed must not appear in localStorage',
  );
  results.push(
    'Encrypted local persistence and no stored bootstrap credentials/private key plaintext',
  );

  await alice.page.evaluate(() => navigator.serviceWorker.ready);
  await alice.context.setOffline(true);
  await alice.page.reload({ waitUntil: 'domcontentloaded' });
  await alice.page.getByLabel('Vault username', { exact: true }).fill('alice');
  await alice.page.getByLabel('Vault passphrase', { exact: true }).fill(vaultSecret);
  await alice.page.getByRole('button', { name: 'Unlock encrypted vault', exact: true }).click();
  await alice.page.locator('#identity').filter({ hasText: 'offline grant only' }).waitFor();
  await createMessage(alice.page, `Offline browser-restart queue ${Date.now()}`);
  await alice.page.locator('.badge.queued').waitFor();
  results.push(
    'Real browser offline reload, encrypted vault unlock and bounded local queue creation',
  );
  await alice.context.setOffline(false);
  await alice.page.getByRole('button', { name: 'Reconnect & validate', exact: true }).click();
  await alice.page.getByRole('button', { name: 'Authenticate with MFA', exact: true }).waitFor();
  results.push('Fresh MFA required before post-reload server reconnection');

  await bob.page.screenshot({ path: resolve(artifactDir, 'recipient.png'), fullPage: true });
  await admin.page.screenshot({ path: resolve(artifactDir, 'authority.png'), fullPage: true });
  assert.deepEqual(errors, [], 'No uncaught browser runtime errors');
  console.log(
    JSON.stringify({ status: 'PASS', browser: browser.version(), assertions: results }, null, 2),
  );
} catch (error) {
  let index = 0;
  for (const context of browser.contexts()) {
    for (const page of context.pages()) {
      await page
        .screenshot({ path: resolve(artifactDir, `failure-${index++}.png`), fullPage: true })
        .catch(() => {});
    }
  }
  console.error(
    JSON.stringify(
      { status: 'FAIL', assertionsCompleted: results, browserErrors: errors, error: error.message },
      null,
      2,
    ),
  );
  throw error;
} finally {
  await browser.close();
}
