import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { provision } from './helpers/fixture.mjs';
import { startSecureStack, freePort } from '../deployment/secure/harness.mjs';
import { requestBytes } from '../packages/transport/tls.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';

test('independent adapter and collector processes enforce mTLS, exchange, idempotency, redaction and acknowledgement', async (t) => {
  const f = await provision(),
    stack = await startSecureStack(f.dir),
    port = await freePort();
  let child;
  t.after(async () => {
    if (child && child.exitCode === null) {
      const done = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      await done;
    }
    await stack.stop();
    await rm(f.dir, { recursive: true, force: true });
  });
  const profilePath = join(f.dir, 'adapter-profile.json'),
    destPath = join(f.dir, 'destinations.json');
  writeFileSync(profilePath, JSON.stringify(f.profiles.alice), { mode: 0o600 });
  writeFileSync(
    destPath,
    JSON.stringify([
      {
        userId: f.profiles.bob.userId,
        deviceId: f.profiles.bob.deviceId,
        unitId: f.profiles.bob.unitId,
        encryptionPublicKey: f.profiles.bob.keys.encryption.publicKey,
      },
    ]),
    { mode: 0o600 },
  );
  const env = {
    ...stack.env,
    SIEPMU_ADAPTER_PORT: String(port),
    SIEPMU_ADAPTER_PROFILE: profilePath,
    SIEPMU_ADAPTER_DESTINATIONS: destPath,
    SIEPMU_ADAPTER_DB: join(f.dir, 'adapter.sqlite'),
    SIEPMU_PLATFORM_URL: stack.baseUrl,
    SIEPMU_ADAPTER_TLS_CERT: join(stack.pki.dir, 'adapter.crt'),
    SIEPMU_ADAPTER_TLS_KEY: join(stack.pki.dir, 'adapter.key'),
    SIEPMU_ADAPTER_TLS_CLIENT_PINS: stack.pki.pin('adapter-client'),
    SIEPMU_ADAPTER_CLIENT_TLS_CERT: join(stack.pki.dir, 'unit-a.crt'),
    SIEPMU_ADAPTER_CLIENT_TLS_KEY: join(stack.pki.dir, 'unit-a.key'),
  };
  child = spawn(process.execPath, ['services/integration/server.mjs'], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  child.stdout.on('data', (b) => (logs += b));
  child.stderr.on('data', (b) => (logs += b));
  const url = `https://127.0.0.1:${port}/v1/messages`,
    tls = stack.pki.material('adapter-client');
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(logs);
    try {
      await requestBytes(url, { tls });
      break;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  const recipient = new IntegrationEndpoint({
    url: stack.baseUrl,
    tls: stack.tls,
    profile: f.profiles.bob,
    authorityKey: f.provisioned.serverPublicKey,
  });
  await recipient.authenticate();
  const body = {
    version: 1,
    requestId: crypto.randomUUID(),
    issuedAt: Date.now(),
    senderUserId: f.profiles.alice.userId,
    destinationUserId: f.profiles.bob.userId,
    payload: recipient.crypto.createTextPayload('SYNTHETIC_SECRET_CANARY'),
  };
  const send = (value = body, identity = tls) =>
    requestBytes(url, {
      method: 'POST',
      tls: identity,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(value),
    });
  const accepted = await send();
  assert.equal(accepted.status, 200, accepted.body.toString());
  const reply = JSON.parse(accepted.body),
    duplicate = await send();
  assert.equal(duplicate.body.toString(), accepted.body.toString());
  const plaintext = await recipient.receive(
    reply.objectId,
    f.profiles.alice.keys.signing.publicKey,
  );
  assert.equal(recipient.crypto.unpackPayload(plaintext).text, 'SYNTHETIC_SECRET_CANARY');
  for (const changed of [
    { ...body, version: 2 },
    { ...body, issuedAt: 0 },
    { ...body, senderUserId: f.profiles.bob.userId },
    { ...body, destinationUserId: f.profiles.eve.userId },
    { ...body, payload: recipient.crypto.createTextPayload('changed') },
    { ...body, extra: true },
  ])
    assert.equal((await send(changed)).status, 409);
  assert.equal((await send(body, stack.pki.material('unit-denied'))).status, 403);
  const eventsUrl = `https://127.0.0.1:${stack.ports.collector}/v1/events`,
    operator = stack.pki.material('operator-client');
  let events = [];
  for (let i = 0; i < 50; i++) {
    events = JSON.parse((await requestBytes(eventsUrl, { tls: operator })).body).events;
    if (events.some((x) => x.event.eventType === 'RELEASE_ISSUED')) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(events.some((x) => x.event.eventType === 'RELEASE_ISSUED'));
  assert.equal(JSON.stringify(events).includes('SYNTHETIC_SECRET_CANARY'), false);
  const ack = await requestBytes(eventsUrl.replace('/events', '/ack'), {
    method: 'POST',
    tls: operator,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ eventId: events[0].event.eventId, disposition: 'INVESTIGATING' }),
  });
  assert.equal(ack.status, 200);
  assert.equal(
    (await requestBytes(eventsUrl, { tls: stack.pki.material('control-client') })).status,
    403,
  );
  assert.equal(
    readFileSync(join(f.dir, 'adapter.sqlite')).includes(Buffer.from('SYNTHETIC_SECRET_CANARY')),
    false,
  );
  assert.equal(logs.includes('SYNTHETIC_SECRET_CANARY'), false);
});
