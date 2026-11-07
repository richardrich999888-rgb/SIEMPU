import test from 'node:test';
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { provision } from '../helpers/fixture.mjs';
import { ApiClient, createObject, decryptObject } from '../helpers/client.mjs';
import {
  startSecureStack,
  prepareSecureLab,
  secureApiTransport,
} from '../../deployment/secure/harness.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';

test('lab startup waits for authenticated custody even when gateway and relay are ready', async (t) => {
  const f = await provision(),
    lab = prepareSecureLab(f.dir),
    gate = join(f.dir, 'start-custodian');
  let origin, stack;
  const starting = startSecureStack(f.dir, {
    lab,
    spawnService(executable, args, options) {
      origin = options.env.SIEPMU_PUBLIC_ORIGIN;
      if (args[0] !== 'services/evidence/server.mjs') return spawn(executable, args, options);
      // Hold only the real custodian at a deterministic barrier. Other services start normally.
      const wrapper = `import {existsSync} from 'node:fs'; import {resolve} from 'node:path'; import {pathToFileURL} from 'node:url';
      while (!existsSync(process.env.SIEPMU_TEST_CUSTODY_GATE)) await new Promise(r=>setTimeout(r,20));
      process.argv[1]=resolve('services/evidence/server.mjs'); await import(pathToFileURL(process.argv[1]).href);`;
      return spawn(executable, ['--input-type=module', '-e', wrapper], {
        ...options,
        env: { ...options.env, SIEPMU_TEST_CUSTODY_GATE: gate },
      });
    },
  });
  // Observe rejection immediately as well as retaining the original promise for cleanup.
  const outcome = starting.then(
    (s) => {
      stack = s;
      return 'READY';
    },
    () => 'FAILED',
  );
  t.after(async () => {
    writeFileSync(gate, 'release');
    await starting.catch(() => {});
    await stack?.stop();
    await rm(f.dir, { recursive: true, force: true });
  });
  let gatewayReady = false;
  for (let i = 0; i < 80; i++) {
    try {
      gatewayReady =
        (
          await requestBytes(origin + '/health/ready', {
            tls: { ca: lab.pki.material('unit-a').ca },
            timeoutMs: 100,
          })
        ).status === 200;
    } catch {}
    if (gatewayReady) break;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(gatewayReady, true, 'gateway and relay reach readiness while custodian is blocked');
  assert.equal(
    await Promise.race([outcome, new Promise((r) => setTimeout(() => r('WAITING'), 250))]),
    'WAITING',
  );
  writeFileSync(gate, 'release');
  stack = await starting;
  await new ApiClient(
    secureApiTransport(stack.baseUrl, stack.tls),
    f.profiles.alice,
  ).authenticate();
});

test('complete TLS/mTLS exchange with independent custody, unauthorized client and outage recovery', async (t) => {
  const f = await provision(),
    stack = await startSecureStack(f.dir);
  t.after(async () => {
    await stack.stop();
    await rm(f.dir, { recursive: true, force: true });
  });
  const transport = secureApiTransport(stack.baseUrl, stack.tls);
  const a = new ApiClient(transport, f.profiles.alice),
    b = new ApiClient(transport, f.profiles.bob),
    denied = new ApiClient(transport, f.profiles.eve);
  for (const c of [a, b, denied]) await c.authenticate();
  const object = createObject(f.profiles.alice, f.profiles.bob, await a.grant(), {
    data: 'SYNTHETIC isolated enclave',
  });
  await a.submit(object);
  await a.prepare(object.envelope.objectId);
  assert.equal((await denied.claim(object.envelope.objectId, 1)).status, 404);
  const released = await b.claim(object.envelope.objectId, 1);
  assert.equal(released.status, 200, JSON.stringify(released));
  assert.equal(
    decryptObject(released.body, f.profiles.bob).bytes.toString(),
    'SYNTHETIC isolated enclave',
  );
  const wrong = await requestBytes(`https://127.0.0.1:${stack.ports.control}/api/meta`, {
    tls: stack.pki.material('unit-denied'),
  });
  assert.equal(wrong.status, 403);
  await stack.stopRole('checkpoint');
  assert.equal((await b.request('GET', '/api/control')).status, 503);
  stack.start('checkpoint');
  let restored = false;
  for (let i = 0; i < 60; i++) {
    if ((await b.request('GET', '/api/control')).status === 200) {
      restored = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.equal(restored, true);
  assert.equal(stack.logs().includes('SYNTHETIC isolated enclave'), false);
});
