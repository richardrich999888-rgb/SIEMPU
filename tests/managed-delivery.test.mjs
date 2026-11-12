import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { readFileSync, rmSync } from 'node:fs';
import { provision } from './helpers/fixture.mjs';
import { ApiClient } from './helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { createTransportServer, requestBytes } from '../packages/transport/tls.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { ManagedOutbox } from '../integrations/managed-endpoint/outbox.mjs';
import { sendWithOutbox, submitFromOutbox } from '../integrations/managed-endpoint/delivery.mjs';

// A loopback-only TLS fault injector forwards to real authority/relay/custody processes.
// It can discard an actual response, never invent an acceptance, signature, or key release.
async function fixture(t, { maxEntries = 8 } = {}) {
  const f = await provision();
  let stack, server, store;
  t.after(async () => {
    store?.close();
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      });
    }
    await stack?.stop();
    rmSync(f.dir, { recursive: true, force: true });
  });
  stack = await startSecureStack(f.dir);
  const fault = { mode: 'none', submissions: 0, receipts: [], errors: [] };
  server = createTransportServer(async (req, res) => {
    try {
      const chunks = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) throw new Error('FIXTURE_BODY_BOUND');
        chunks.push(chunk);
      }
      const submission = req.method === 'POST' && req.url === '/api/objects';
      if (submission) fault.submissions++;
      if (submission && fault.mode === 'before') return res.destroy();
      const reply = await requestBytes(stack.baseUrl + req.url, {
        method: req.method,
        tls: stack.tls,
        headers: {
          'content-type': 'application/json',
          ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}),
        },
        body: chunks.length ? Buffer.concat(chunks) : undefined,
      });
      if (submission && reply.status === 200) {
        fault.receipts.push(JSON.parse(reply.body).receipt);
        if (fault.mode === 'after') return res.destroy();
        if (fault.mode === 'tamper') {
          const altered = JSON.parse(reply.body);
          altered.receipt.signature = 'A'.repeat(86);
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(JSON.stringify(altered));
        }
      }
      res.writeHead(reply.status, { 'content-type': 'application/json' });
      res.end(reply.body);
    } catch (error) {
      fault.errors.push(error.message);
      res.destroy();
    }
  }, stack.pki.material('web'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = 'https://127.0.0.1:' + server.address().port;
  const endpointFor = async (profile) => {
    const endpoint = new IntegrationEndpoint({
      url,
      tls: stack.tls,
      profile,
      authorityKey: f.provisioned.serverPublicKey,
    });
    await endpoint.authenticate();
    return endpoint;
  };
  const alice = await endpointFor(f.profiles.alice);
  const admin = new ApiClient(secureApiTransport(stack.baseUrl, stack.tls), f.profiles.admin);
  await admin.authenticate();
  const config = {
    database: join(f.dir, 'managed-queue.sqlite'),
    key: randomBytes(32),
    binding: { url, deviceId: f.profiles.alice.deviceId },
    maxEntries,
  };
  store = new ManagedOutbox(config);
  const peer = {
    userId: f.profiles.bob.userId,
    deviceId: f.profiles.bob.deviceId,
    unitId: f.profiles.bob.unitId,
    encryptionPublicKey: f.profiles.bob.keys.encryption.publicKey,
  };
  const evidence = async (id, type) => {
    const { records } = await admin.ok('GET', '/api/evidence/export');
    const selected = records.filter(
      (r) => r.payload.objectId === id && r.payload.eventType === type,
    );
    for (const record of selected)
      assert.equal(await alice.crypto.verifyPacket(alice.authorityKey, record), true);
    return selected;
  };
  const restart = () => {
    store.close();
    store = new ManagedOutbox(config);
    return store;
  };
  return { ...f, alice, admin, peer, config, fault, store, restart, endpointFor, evidence };
}

test('online send persists before transmission; lost real acknowledgement recovers after restart exactly once', async (t) => {
  const f = await fixture(t);
  const text = 'SYNTHETIC_MANAGED_ACK_LOSS_CANARY';
  f.fault.mode = 'after';
  await assert.rejects(
    sendWithOutbox(f.alice, f.store, f.peer, f.alice.crypto.createTextPayload(text)),
    { code: 'ECONNRESET', requestStage: 'OBJECT_SUBMISSION' },
  );
  assert.equal(f.fault.submissions, 1, 'no hidden automatic retry');
  assert.equal(
    f.fault.receipts.length,
    1,
    'actual authority accepted before the response was lost',
  );
  const [pending] = f.store.list();
  assert.equal(pending.state, 'PENDING');
  f.store.close();
  assert.equal(readFileSync(f.config.database).includes(Buffer.from(text)), false);
  const resumed = f.restart();
  f.fault.mode = 'none';
  const first = await submitFromOutbox(f.alice, resumed, pending.id);
  const duplicate = await submitFromOutbox(f.alice, resumed, pending.id);
  assert.deepEqual(first.receipt, f.fault.receipts[0]);
  assert.deepEqual(duplicate.receipt, first.receipt);
  assert.equal((await f.evidence(pending.id, 'SUBMITTED')).length, 1);
  assert.equal(resumed.get(pending.id).state, 'SUBMITTED');
  const bob = await f.endpointFor(f.profiles.bob);
  const delivered = await bob.receiveWithRelease(
    pending.id,
    f.profiles.alice.keys.signing.publicKey,
  );
  assert.equal(bob.crypto.unpackPayload(delivered.plaintext).text, text);
  const ack = await bob.acknowledge(pending.id, delivered.release);
  assert.equal(await bob.crypto.verifyPacket(bob.authorityKey, ack), true);
  assert.deepEqual(f.fault.errors, []);
});

test('interrupted online send stays queued and a revoked sender cannot resume submission', async (t) => {
  const f = await fixture(t);
  f.fault.mode = 'before';
  await assert.rejects(
    sendWithOutbox(f.alice, f.store, f.peer, f.alice.crypto.createTextPayload('synthetic revoked')),
    { code: 'ECONNRESET', requestStage: 'OBJECT_SUBMISSION' },
  );
  const [pending] = f.store.list();
  assert.equal((await f.evidence(pending.id, 'SUBMITTED')).length, 0);
  const revoke = await f.admin.admin(
    'POST',
    `/api/admin/devices/${f.profiles.alice.deviceId}/revoke`,
  );
  assert.equal(revoke.status, 200);
  const resumed = f.restart();
  f.fault.mode = 'none';
  await assert.rejects(submitFromOutbox(f.alice, resumed, pending.id), (error) =>
    [401, 403].includes(error.status),
  );
  assert.equal(resumed.get(pending.id).state, 'PENDING');
  assert.equal((await f.evidence(pending.id, 'SUBMITTED')).length, 0);
  assert.equal((await f.evidence(pending.id, 'RELEASE_ISSUED')).length, 0);
  assert.equal(f.fault.submissions, 1, 'revoked device proof refused before a second submit');
  assert.deepEqual(f.fault.errors, []);
});

test('persistent response loss remains bounded and a full outbox refuses a new object before publishing', async (t) => {
  const f = await fixture(t, { maxEntries: 1 });
  f.fault.mode = 'after';
  await assert.rejects(
    sendWithOutbox(f.alice, f.store, f.peer, f.alice.crypto.createTextPayload('synthetic bounded')),
    { code: 'ECONNRESET', requestStage: 'OBJECT_SUBMISSION' },
  );
  const [pending] = f.store.list();
  for (let i = 0; i < 2; i++)
    await assert.rejects(submitFromOutbox(f.alice, f.store, pending.id), { code: 'ECONNRESET' });
  assert.equal(f.fault.submissions, 3, 'exactly one transmission per explicit attempt');
  assert.equal(f.store.list().length, 1);
  assert.equal(f.store.get(pending.id).state, 'PENDING');
  await assert.rejects(
    sendWithOutbox(
      f.alice,
      f.store,
      f.peer,
      f.alice.crypto.createTextPayload('synthetic over capacity'),
    ),
    { code: 'OUTBOX_CAPACITY' },
  );
  assert.equal(f.fault.submissions, 3, 'capacity failure must not publish the new object');
  assert.equal((await f.evidence(pending.id, 'SUBMITTED')).length, 1);
  f.fault.mode = 'none';
  await submitFromOutbox(f.alice, f.restart(), pending.id);
  assert.deepEqual(f.fault.errors, []);
});

test('an altered acknowledgement cannot mark a queued submission successful', async (t) => {
  const f = await fixture(t);
  f.fault.mode = 'tamper';
  await assert.rejects(
    sendWithOutbox(f.alice, f.store, f.peer, f.alice.crypto.createTextPayload('synthetic receipt')),
    /SUBMISSION_RECEIPT/,
  );
  const [pending] = f.store.list();
  assert.equal(pending.state, 'PENDING');
  f.fault.mode = 'none';
  await submitFromOutbox(f.alice, f.restart(), pending.id);
  assert.equal((await f.evidence(pending.id, 'SUBMITTED')).length, 1);
  assert.deepEqual(f.fault.errors, []);
});

test('expired and held queue entries never contact the authority', async (t) => {
  const f = await fixture(t);
  const sealed = await f.alice.seal(f.peer, f.alice.crypto.createTextPayload('synthetic expiry'));
  sealed.envelope.expiresAt = Date.now() - 1;
  const id = f.store.enqueue(sealed);
  await assert.rejects(submitFromOutbox(f.alice, f.store, id), { code: 'EXPIRED_OBJECT' });
  assert.equal(f.store.get(id).state, 'HELD');
  assert.equal(f.store.get(id).reason, 'EXPIRED_OBJECT');
  await assert.rejects(submitFromOutbox(f.alice, f.store, id), { code: 'OUTBOX_STATE' });
  assert.equal(f.fault.submissions, 0);
  assert.equal((await f.evidence(id, 'SUBMITTED')).length, 0);
});
