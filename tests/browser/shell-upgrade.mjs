/** Actual Chromium regression for partial app-shell upgrades; isolated public assets only. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve('.');
const currentWorker = await readFile(resolve(root, 'apps/unit-client/sw.js'), 'utf8');
const legacyWorker = await readFile(new URL('./fixtures/legacy-sw.txt', import.meta.url), 'utf8');
const legacyCanonical = await readFile(
  new URL('./fixtures/legacy-canonical.txt', import.meta.url),
  'utf8',
);

export async function checkShellUpgrades(browser, results) {
  let generation = 'legacy';
  let failedPath = null;
  let deniedRequests = 0;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('cache-control', 'no-store');
    if (path === failedPath) {
      deniedRequests++;
      response.destroy();
      return;
    }
    if (path === '/sw.js') {
      response.setHeader('content-type', 'text/javascript');
      response.setHeader('service-worker-allowed', '/');
      response.end(
        generation === 'legacy'
          ? legacyWorker
          : generation === 'next'
            ? currentWorker.replace(/shell-v\d+/, 'shell-next-test')
            : currentWorker,
      );
      return;
    }
    if (path === '/api/private') {
      response.setHeader('content-type', 'application/json');
      response.end('{"synthetic":"uncacheable"}');
      return;
    }
    if (['/', '/unit', '/admin', '/admin/'].includes(path) || path.endsWith('/index.html')) {
      response.setHeader('content-type', 'text/html');
      response.end(
        '<!doctype html><p id="result">loading</p><script type="module" src="/apps/unit-client/app.mjs"></script>',
      );
      return;
    }
    if (path === '/apps/unit-client/app.mjs') {
      response.setHeader('content-type', 'text/javascript');
      response.end(
        generation === 'legacy'
          ? "document.querySelector('#result').textContent = 'legacy'; navigator.serviceWorker.register('/sw.js').catch(() => {});"
          : `import { sha256, generateDeviceKeys, encryptObject, decryptObject, signPacket, keyId, createTextPayload, unpackPayload } from '/packages/crypto/crypto.mjs';
             const keys = await generateDeviceKeys();
             const context = { schemaVersion: 2, objectId: crypto.randomUUID(), senderUserId: 'alice',
               recipientUserId: 'bob', senderDeviceId: 'device-a', recipientDeviceId: 'device-b',
               senderUnitId: 'unit-a', recipientUnitId: 'unit-b', missionId: 'TEST', classification: 'DEMO', action: 'deliver',
               createdAt: 1, expiresAt: 2, creationGrant: await signPacket(keys.signing.privateKey, { epoch: 1 }),
               recipientKeyId: await keyId(keys.encryption.publicKey), keyVersion: 1, cryptoSuite: 'P256-HKDF-SHA256-AES256GCM',
               messagePriority: 'ROUTINE', messageDomain: 'GENERAL' };
             const sealed = await encryptObject(context, createTextPayload('offline upgrade'), keys.encryption.publicKey, keys.signing.privateKey);
             const plain = await decryptObject(sealed, keys.encryption.privateKey, keys.signing.publicKey);
             if (unpackPayload(plain).text !== 'offline upgrade') throw Error('Upgrade roundtrip failed');
             document.querySelector('#result').textContent = '${generation}:' + await sha256('shell');
             navigator.serviceWorker.register('/sw.js').catch(() => {});`,
      );
      return;
    }
    if (path === '/packages/protocol/canonical.mjs' && generation === 'legacy') {
      response.setHeader('content-type', 'text/javascript');
      response.end(legacyCanonical);
      return;
    }
    if (!/^\/(apps|packages)\/[a-zA-Z0-9_./-]+$/.test(path) || path.includes('..')) {
      response.writeHead(404).end();
      return;
    }
    try {
      response.setHeader('content-type', path.endsWith('.css') ? 'text/css' : 'text/javascript');
      response.end(await readFile(resolve(root, '.' + path)));
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((ready) => server.listen(0, '127.0.0.1', ready));
  const base = `http://127.0.0.1:${server.address().port}`;
  const context = await browser.newContext();
  let page = await context.newPage();
  const pageErrors = [];
  context.on('page', (nextPage) =>
    nextPage.on('pageerror', (error) => pageErrors.push(error.message)),
  );
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const update = () =>
    page.evaluate(async () => {
      const registration = await navigator.serviceWorker.getRegistration();
      await registration.update();
      const worker = registration.installing;
      if (!worker) return registration.waiting ? 'installed' : 'unchanged';
      return new Promise((resolveState) => {
        const changed = () => {
          if (['installed', 'redundant'].includes(worker.state)) resolveState(worker.state);
        };
        worker.addEventListener('statechange', changed);
        changed();
      });
    });
  try {
    await page.goto(base);
    await page.locator('#result').filter({ hasText: 'legacy' }).waitFor();
    await page.evaluate(() => navigator.serviceWorker.ready);
    await page.reload();
    generation = 'current';
    failedPath = '/packages/protocol/canonical.mjs';
    assert.equal(await update(), 'redundant', 'Partial upgrade must not install');
    await page.reload();
    await page.locator('#result').filter({ hasText: 'current:' }).waitFor();
    assert.ok(deniedRequests > 0, 'Dependency outage was exercised');
    await context.setOffline(true);
    await page.reload();
    await page.locator('#result').filter({ hasText: 'current:' }).waitFor();
    results.push(
      'Legacy network-first worker survives interrupted crypto upgrade and real offline v2 encryption/decryption with cached legacy canonical module',
    );

    await context.setOffline(false);
    failedPath = null;
    assert.equal(await update(), 'installed', 'Complete generation waits for old clients to close');
    await page.close();
    page = await context.newPage();
    await page.goto(base);
    await page.locator('#result').filter({ hasText: 'current:' }).waitFor();
    generation = 'next';
    failedPath = '/packages/protocol/canonical.mjs';
    assert.equal(await update(), 'redundant');
    await page.reload();
    await page.locator('#result').filter({ hasText: 'current:' }).waitFor();
    await context.setOffline(true);
    await page.reload();
    await page.locator('#result').filter({ hasText: 'current:' }).waitFor();
    results.push(
      'Installed immutable shell stays usable online and offline when next-generation dependency transfer fails',
    );

    await context.setOffline(false);
    failedPath = null;
    assert.equal(await update(), 'installed');
    await page.close();
    page = await context.newPage();
    await page.goto(base + '/admin');
    await page.locator('#result').filter({ hasText: 'next:' }).waitFor();
    await page.evaluate(() => fetch('/api/private'));
    const cacheKeys = await page.evaluate(async () => {
      const names = await caches.keys();
      const paths = await Promise.all(
        names.map(async (name) =>
          (await (await caches.open(name)).keys()).map((request) => new URL(request.url).pathname),
        ),
      );
      return { names, paths: paths.flat() };
    });
    assert.deepEqual(cacheKeys.names, ['siepmu-public-shell-next-test']);
    assert.ok(!cacheKeys.paths.some((path) => path.startsWith('/api/')));
    await context.setOffline(true);
    await page.reload();
    await page.locator('#result').filter({ hasText: 'next:' }).waitFor();
    assert.deepEqual(pageErrors, []);
    results.push(
      'Completed shell activates after old clients close, caches admin route offline, retires old generations and excludes API responses',
    );
  } catch (error) {
    throw new Error(`${error.message}; browser errors: ${JSON.stringify(pageErrors)}`, {
      cause: error,
    });
  } finally {
    await context.close();
    await new Promise((done) => server.close(done));
  }
}
