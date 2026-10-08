import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pair } from './helpers/client.mjs';
import { packet, canonical, hash } from '../services/control/primitives.mjs';
import { buildOfflineBundle, installOfflineBundle } from '../packages/release/offline.mjs';

test('signed offline package installs with bundled runtime; tampering, rollback, traversal and interruptions fail closed', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-offline-')),
    keys = pair(),
    recovery = pair();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, 'source');
  mkdirSync(source);
  for (const dir of ['apps', 'services', 'packages', 'database', 'scripts', 'deployment'])
    mkdirSync(join(source, dir));
  writeFileSync(
    join(source, 'services', 'proof.mjs'),
    "console.log('OFFLINE_RUNTIME_VERIFIED');\n",
  );
  const revision = 'a'.repeat(40),
    bundle = join(root, 'bundle'),
    destination = join(root, 'installed'),
    ledger = join(root, 'independent', 'floor.json');
  const manifest = buildOfflineBundle({
    source,
    destination: bundle,
    signingKey: keys.privateKey,
    version: 2,
    revision,
  });
  const opts = { bundle, destination, ledger, trustedKey: keys.publicKey };
  assert.throws(
    () => installOfflineBundle({ ...opts, trustedKey: recovery.publicKey, initialize: true }),
    /SIGNATURE/,
  );
  assert.throws(() => installOfflineBundle(opts), /LEDGER_MISSING/);
  assert.throws(
    () =>
      installOfflineBundle({
        ...opts,
        initialize: true,
        fault: () => {
          throw new Error('POWER_LOSS');
        },
      }),
    /POWER_LOSS/,
  );
  const installed = installOfflineBundle({ ...opts, initialize: true });
  assert.equal(
    execFileSync(
      join(installed.release, 'runtime/node'),
      [join(installed.release, 'app/services/proof.mjs')],
      { env: { PATH: '/nonexistent' }, encoding: 'utf8' },
    ).trim(),
    'OFFLINE_RUNTIME_VERIFIED',
  );
  assert.equal(installOfflineBundle(opts).digest, installed.digest);
  const file = join(bundle, 'files', 'app/services/proof.mjs');
  writeFileSync(file, 'tamper');
  assert.throws(() => installOfflineBundle(opts), /DIGEST/);
  writeFileSync(file, "console.log('OFFLINE_RUNTIME_VERIFIED');\n");
  const original = readFileSync(join(bundle, 'manifest.json'));
  const altered = structuredClone(manifest.payload);
  altered.files[0].path = '../escape';
  writeFileSync(join(bundle, 'manifest.json'), canonical(packet(keys.privateKey, altered)));
  assert.throws(() => installOfflineBundle(opts), /PATH/);
  writeFileSync(join(bundle, 'manifest.json'), original);
  symlinkSync(file, join(bundle, 'files', 'link'));
  assert.throws(() => installOfflineBundle(opts), /UNSAFE/);
  rmSync(join(bundle, 'files', 'link'));
  const lower = { ...manifest.payload, version: 1 },
    low = packet(keys.privateKey, lower);
  writeFileSync(join(bundle, 'manifest.json'), canonical(low));
  assert.throws(() => installOfflineBundle(opts), /ROLLBACK/);
  const auth = packet(recovery.privateKey, {
    action: 'AUTHORIZE_LAB_ROLLBACK',
    fromDigest: installed.digest,
    toDigest: hash(canonical(low)),
    floor: 2,
    expiresAt: Date.now() + 60000,
    nonce: crypto.randomUUID(),
  });
  const rolled = installOfflineBundle({
    ...opts,
    rollbackAuthorization: auth,
    recoveryKey: recovery.publicKey,
  });
  assert.equal(rolled.version, 1);
  assert.equal(JSON.parse(readFileSync(ledger)).floor, 2);
  writeFileSync(join(bundle, 'manifest.json'), original);
  assert.throws(
    () =>
      installOfflineBundle({
        ...opts,
        fault: (stage) => {
          if (stage === 'before-activate') throw new Error('POWER_LOSS');
        },
      }),
    /ROLLBACK/,
  );
  assert.equal(JSON.parse(readFileSync(ledger)).digest, rolled.digest);
});

test('clean application bundle boots without npm or remote package retrieval', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-offline-app-')),
    keys = pair();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bundle = join(root, 'bundle');
  const result = buildOfflineBundle({
    source: resolve('.'),
    destination: bundle,
    signingKey: keys.privateKey,
    version: 1,
    revision: 'b'.repeat(40),
  });
  assert.equal(
    result.payload.files.some(
      (x) =>
        x.path.includes('node_modules') ||
        x.path.endsWith('.key') ||
        x.path.endsWith('demo-profiles.json') ||
        x.path.includes('pqc-lab'),
    ),
    false,
  );
  const installed = installOfflineBundle({
    bundle,
    destination: join(root, 'install'),
    ledger: join(root, 'trust', 'floor.json'),
    trustedKey: keys.publicKey,
    initialize: true,
  });
  const app = join(installed.release, 'app'),
    node = join(installed.release, 'runtime/node');
  const output = execFileSync(
    node,
    [
      '--input-type=module',
      '-e',
      "const {generateDeviceKeys}=await import('./packages/crypto/crypto.mjs'); const {Authority}=await import('./services/control/core.mjs'); const {createWebServer}=await import('./services/web/server.mjs'); await generateDeviceKeys(); if(typeof Authority!=='function'||typeof createWebServer!=='function')throw Error('missing'); console.log('OFFLINE_APPLICATION_MODULES_VERIFIED');",
    ],
    {
      cwd: app,
      env: { PATH: '/nonexistent', NODE_OPTIONS: '--disable-warning=ExperimentalWarning' },
      encoding: 'utf8',
    },
  );
  assert.match(output, /OFFLINE_APPLICATION_MODULES_VERIFIED/);
});
