import test from 'node:test';
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { provision } from '../helpers/fixture.mjs';
import { ApiClient, createObject, decryptObject } from '../helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../../deployment/secure/harness.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';

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
