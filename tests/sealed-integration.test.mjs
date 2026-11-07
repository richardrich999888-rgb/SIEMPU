import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, generateKeyPairSync } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical, hash, sign, packet } from '../services/control/primitives.mjs';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';
import {
  TRANSFER_DOMAIN,
  TRANSFER_WINDOW_MS,
  privateDatabase,
} from '../packages/integration/sealed-transfer.mjs';
import {
  SealedAdapter,
  createSealedAdapterServer,
} from '../services/integration/sealed-adapter.mjs';
import { startSealedAdapter } from '../services/integration/sealed-server.mjs';
import { startAdapter } from '../services/integration/server.mjs';
import { SealedDocumentOutbox } from '../apps/document-system/sealed-outbox.mjs';
import { adapterTransport } from '../apps/document-system/outbox.mjs';
import { DocumentInbox } from '../apps/document-system/inbox.mjs';
import { SYNTHETIC_MARKING } from '../apps/document-system/document.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { startLabSealedAdapter } from '../deployment/secure/sealed-adapter-process.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { generateLabPKI } from '../deployment/secure/lab-pki.mjs';
import { requestBytes } from '../packages/transport/tls.mjs';
import { provision } from './helpers/fixture.mjs';
import { ApiClient } from './helpers/client.mjs';

const keys = () => {
  const p = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: p.privateKey.export({ format: 'jwk' }),
    publicKey: p.publicKey.export({ format: 'jwk' }),
  };
};
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function fixture(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-sealed-')),
    signing = keys();
  const source = {
    userId: randomUUID(),
    deviceId: randomUUID(),
    signingPublicKey: signing.publicKey,
  };
  const destinations = [randomUUID()],
    calls = [];
  const relay = {
    health: async () => true,
    putBlob: async (digest, bytes) => {
      calls.push({ digest, bytes: Buffer.from(bytes) });
      return { hash: digest, size: bytes.length };
    },
  };
  const database = join(dir, 'adapter.sqlite');
  const adapter = new SealedAdapter({ database, source, destinations, relay, ...options });
  t.after(() => {
    try {
      adapter.close();
    } catch {}
    rmSync(dir, { recursive: true, force: true });
  });
  const request = (change = {}, bytes = randomBytes(32)) => {
    const manifest = {
      domain: TRANSFER_DOMAIN,
      version: 2,
      requestId: randomUUID(),
      issuedAt: Date.now(),
      objectId: randomUUID(),
      senderUserId: source.userId,
      senderDeviceId: source.deviceId,
      recipientUserId: destinations[0],
      ciphertextHash: hash(bytes),
      ...change,
    };
    return {
      manifest,
      signature: sign(signing.privateKey, manifest),
      ciphertext: bytes.toString('base64url'),
    };
  };
  return { dir, source, destinations, signing, relay, calls, adapter, database, request };
}

test('sealed transport rejects plaintext, wrapped keys, forged scope, tampering and time violations before staging', async (t) => {
  const f = fixture(t),
    good = f.request();
  const cases = [
    null,
    [],
    { ...good, payload: { data: 'SYNTHETIC_PLAINTEXT' } },
    { ...good, envelope: { wrappedKey: 'SYNTHETIC_WRAP' } },
    { ...good, token: 'SYNTHETIC_TOKEN' },
    f.request({ domain: 'OTHER' }),
    f.request({ version: 1 }),
    f.request({ requestId: 'x' }),
    f.request({ senderUserId: randomUUID() }),
    f.request({ senderDeviceId: randomUUID() }),
    f.request({ recipientUserId: randomUUID() }),
    f.request({ issuedAt: Date.now() - TRANSFER_WINDOW_MS - 1 }),
    f.request({ issuedAt: Date.now() + TRANSFER_WINDOW_MS + 5000 }),
    { ...good, signature: 'a'.repeat(86) },
    { ...good, ciphertext: randomBytes(32).toString('base64url') },
    { ...good, ciphertext: '*' },
    f.request({}, Buffer.alloc(256 * 1024 + 1)),
    f.request({}, Buffer.alloc(15)),
  ];
  for (const value of cases) await assert.rejects(f.adapter.stage(value));
  assert.equal(f.calls.length, 0);
  assert.equal(f.adapter.db.prepare('SELECT count(*) n FROM transfers').get().n, 0);
  assert.equal((await f.adapter.stage(good)).state, 'STAGED_CIPHERTEXT');
  assert.equal('endpoint' in f.adapter, false);
});

test('sealed staging preserves byte identity across lost relay responses, restart and duplicate requests', async (t) => {
  const f = fixture(t),
    body = f.request(),
    put = f.relay.putBlob;
  f.relay.putBlob = async (...args) => {
    await put(...args);
    throw new Error('SIMULATED_LOSS_AFTER_RELAY_COMMIT');
  };
  await assert.rejects(f.adapter.stage(body), /SIMULATED_LOSS/);
  assert.equal(f.adapter.pending, 0);
  f.adapter.close();
  f.relay.putBlob = put;
  const second = new SealedAdapter({ ...f, database: f.database });
  t.after(() => second.close());
  const receipt = await second.stage(body);
  assert.deepEqual(await second.stage(body), receipt);
  assert.equal(f.calls.length, 2);
  assert.deepEqual(f.calls[0], f.calls[1]);
  const changed = f.request(
    { ...body.manifest, ciphertextHash: hash(Buffer.alloc(32, 4)) },
    Buffer.alloc(32, 4),
  );
  await assert.rejects(second.stage(changed), /IDEMPOTENCY_CONFLICT/);
  assert.equal(f.calls.length, 2);
});

test('sealed adapter configuration cannot silently reuse retained state under a new identity or routing scope', async (t) => {
  const f = fixture(t);
  await f.adapter.stage(f.request());
  f.adapter.close();
  for (const change of [
    { source: { ...f.source, userId: randomUUID() } },
    { destinations: [randomUUID()] },
    { source: { ...f.source, signingPublicKey: keys().publicKey } },
  ])
    assert.throws(() => new SealedAdapter({ ...f, ...change }), /CONFIG_MISMATCH/);
  assert.throws(
    () => new SealedAdapter({ ...f, source: { ...f.source, password: 'NO' } }),
    /SOURCE_CONFIG/,
  );
  assert.throws(
    () =>
      new SealedAdapter({ ...f, source: { ...f.source, signingPublicKey: f.signing.privateKey } }),
    /SOURCE_CONFIG/,
  );
  const db = privateDatabase(f.database);
  db.exec('DELETE FROM binding');
  db.close();
  assert.throws(() => new SealedAdapter(f), /CONFIG_MISSING/);
});

test('sealed adapter bounds queued work and freezes requests before awaits', async (t) => {
  const f = fixture(t, { maxPending: 2 }),
    held = deferred(),
    entered = deferred(),
    put = f.relay.putBlob;
  f.relay.putBlob = async (...args) => {
    entered.resolve();
    await held.promise;
    return put(...args);
  };
  const a = f.adapter.stage(f.request());
  await entered.promise;
  const body = f.request(),
    saved = structuredClone(body),
    b = f.adapter.stage(body);
  body.ciphertext = 'mutated';
  body.manifest.recipientUserId = randomUUID();
  const burst = await Promise.allSettled(
    Array.from({ length: 20 }, () => f.adapter.stage(f.request())),
  );
  assert.ok(burst.every((r) => r.status === 'rejected' && r.reason.message === 'TRANSFER_BUSY'));
  assert.equal((await f.adapter.readiness()).ready, false);
  held.resolve();
  await Promise.all([a, b]);
  assert.equal(f.calls[1].digest, saved.manifest.ciphertextHash);
  assert.equal(f.adapter.pending, 0);
  assert.equal((await f.adapter.readiness()).ready, true);
});

test('sealed staging expires queued work and refuses false relay receipts without dropping history', async (t) => {
  const f = fixture(t),
    held = deferred(),
    entered = deferred(),
    put = f.relay.putBlob,
    body = f.request();
  f.relay.putBlob = async (...args) => {
    entered.resolve();
    await held.promise;
    return put(...args);
  };
  const first = f.adapter.stage(f.request());
  await entered.promise;
  const second = f.adapter.stage(body),
    refusal = assert.rejects(second, /TRANSFER_EXPIRED/);
  t.mock.method(Date, 'now', () => body.manifest.issuedAt + TRANSFER_WINDOW_MS + 1);
  held.resolve();
  await first;
  await refusal;
  assert.equal(f.calls.length, 1);
  t.mock.restoreAll();
  f.relay.putBlob = async () => ({ hash: '0'.repeat(64), size: 32 });
  await assert.rejects(f.adapter.stage(body), /TRANSFER_RELAY_RECEIPT/);
  assert.equal(
    f.adapter.db.prepare('SELECT response FROM transfers WHERE id=?').get(body.manifest.requestId)
      .response,
    null,
  );
  f.relay.putBlob = put;
  await f.adapter.stage(body);
});

test('sealed staging enforces durable entry/byte limits and retains cached receipts', async (t) => {
  const f = fixture(t, { maxEntries: 1 }),
    first = f.request();
  const receipt = await f.adapter.stage(first);
  await assert.rejects(f.adapter.stage(f.request()), /TRANSFER_CAPACITY/);
  assert.deepEqual(await f.adapter.stage(first), receipt);
  assert.equal((await f.adapter.readiness()).ready, false);
  const small = fixture(t, { maxStoredBytes: 10 });
  await assert.rejects(small.adapter.stage(small.request()), /TRANSFER_CAPACITY/);
  assert.equal(small.calls.length, 0);
  for (const maxPending of [0, 1.5, 129])
    assert.throws(() => new SealedAdapter({ ...f, maxPending }), /TRANSFER_LIMIT/);
  f.relay.health = async () => {
    throw Error('SYNTHETIC_SECRET');
  };
  const state = await f.adapter.readiness();
  assert.equal(state.checks.relay, false);
  assert.equal(JSON.stringify(state).includes('SYNTHETIC_SECRET'), false);
});

test('private transfer stores reject shared files and symlinks; sealed startup rejects endpoint credentials', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-sealed-mode-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'shared');
  writeFileSync(path, '', { mode: 0o644 });
  assert.throws(() => privateDatabase(path), /PERMISSIONS/);
  const link = join(dir, 'link');
  symlinkSync(path, link);
  assert.throws(() => privateDatabase(link));
  await assert.rejects(
    startSealedAdapter({ SIEPMU_ADAPTER_PROFILE: 'secret-profile' }),
    /SEALED_ADAPTER_CONFIG/,
  );
  await assert.rejects(startAdapter({}), /LEGACY_PLAINTEXT_ADAPTER_DISABLED/);
  await assert.rejects(
    startSealedAdapter({ SIEPMU_RELAY_URL: 'http://127.0.0.1' }),
    /SEALED_ADAPTER_TLS/,
  );
});

test('sealed HTTP service requires pinned mTLS, rejects credential forwarding and never serves the plaintext API', async (t) => {
  const f = fixture(t),
    pki = generateLabPKI(join(f.dir, 'pki'));
  pki.issue('adapter');
  pki.issue('source');
  pki.issue('denied');
  assert.throws(() => createSealedAdapterServer({ adapter: f.adapter }), /MTLS_REQUIRED/);
  const server = createSealedAdapterServer({
    adapter: f.adapter,
    tls: { ...pki.material('adapter'), requestCert: true, clientFingerprints: [pki.pin('source')] },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise((r) => {
        server.close(r);
        server.closeAllConnections();
      }),
  );
  const url = `https://127.0.0.1:${server.address().port}`;
  const send = (path, headers = {}, identity = 'source', body = f.request()) =>
    requestBytes(url + path, {
      method: 'POST',
      tls: pki.material(identity),
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
  assert.equal((await send('/v2/ciphertext')).status, 200);
  assert.equal((await send('/v1/messages')).status, 404);
  assert.equal((await send('/v2/ciphertext', {}, 'denied')).status, 403);
  assert.equal(
    (await send('/v2/ciphertext', { authorization: 'Bearer SYNTHETIC_TOKEN' })).status,
    409,
  );
  assert.equal(
    (await send('/v2/ciphertext', {}, 'source', { payload: 'SYNTHETIC_PLAINTEXT' })).status,
    409,
  );
  assert.equal(
    (await send('/v2/ciphertext', {}, 'source', { data: 'a'.repeat(400 * 1024) })).status,
    409,
  );
  const ready = await requestBytes(url + '/ready', { tls: pki.material('source') });
  assert.equal(JSON.parse(ready.body).ready, true);
  assert.equal(f.calls.length, 1);
});

function sourceFixture(t, options = {}) {
  const f = fixture(t),
    encryption = keys(),
    authority = keys(),
    crypto = createObjectCryptography(),
    calls = { seal: 0, submit: 0, send: 0 };
  const destination = {
    userId: f.destinations[0],
    deviceId: randomUUID(),
    unitId: randomUUID(),
    encryptionPublicKey: encryption.publicKey,
  };
  const endpoint = {
    profile: { userId: f.source.userId, deviceId: f.source.deviceId, keys: { signing: f.signing } },
    crypto,
    authorityKey: authority.publicKey,
    async seal(recipient, payload) {
      calls.seal++;
      const bytes = randomBytes(32);
      const envelope = {
        objectId: randomUUID(),
        senderUserId: f.source.userId,
        senderDeviceId: f.source.deviceId,
        recipientUserId: recipient.userId,
        ciphertextHash: hash(bytes),
      };
      return {
        envelope,
        signature: sign(f.signing.privateKey, envelope),
        ciphertext: bytes.toString('base64url'),
      };
    },
    async submit(sealed) {
      calls.submit++;
      return {
        object: { id: sealed.envelope.objectId },
        receipt: packet(authority.privateKey, {
          eventType: 'SUBMITTED',
          objectId: sealed.envelope.objectId,
          details: {
            objectDigest: sealed.envelope.ciphertextHash,
            envelopeDigest: hash(canonical(sealed.envelope)),
          },
        }),
      };
    },
    async listObjects() {
      return [];
    },
  };
  const dedupKey = randomBytes(32),
    database = join(f.dir, 'outbox.sqlite');
  const send = async (method, path, body) => {
    calls.send++;
    return { status: 200, body: await f.adapter.stage(body) };
  };
  const settings = { database, endpoint, destinations: [destination], send, dedupKey, ...options };
  const outbox = new SealedDocumentOutbox(settings);
  t.after(() => {
    try {
      outbox.close();
    } catch {}
  });
  const document = (change = {}) => ({
    version: 1,
    documentId: randomUUID(),
    reference: 'SYN/001',
    title: 'Synthetic document',
    marking: SYNTHETIC_MARKING,
    body: 'SYNTHETIC_CONTENT_CANARY',
    originatorUserId: f.source.userId,
    destinationUserId: destination.userId,
    ...change,
  });
  return { ...f, endpoint, calls, database, dedupKey, settings, outbox, document };
}

test('sealed outbox serializes duplicate documents, authenticates durable state and rejects content conflicts', async (t) => {
  const f = sourceFixture(t),
    doc = f.document();
  const answers = await Promise.all([f.outbox.submit(doc), f.outbox.submit(doc)]);
  assert.deepEqual(answers[0], answers[1]);
  assert.equal(f.calls.seal, 1);
  assert.equal(f.calls.submit, 1);
  await assert.rejects(f.outbox.submit({ ...doc, body: 'changed' }), /DOCUMENT_CONFLICT/);
  await assert.rejects(
    f.outbox.submit(f.document({ originatorUserId: randomUUID() })),
    /SENDER_DENIED/,
  );
  await assert.rejects(
    f.outbox.submit(f.document({ destinationUserId: randomUUID() })),
    /DESTINATION_DENIED/,
  );
  f.outbox.db.prepare('UPDATE sealed_outbox SET response=?').run('{"state":"DELIVERED"}');
  await assert.rejects(f.outbox.submit(doc), /STORAGE_INTEGRITY/);
  await assert.rejects(f.outbox.status(doc.documentId), /STORAGE_INTEGRITY/);
  assert.equal(f.calls.submit, 1);
});

test('sealed outbox retains the original ciphertext across ambiguous admission, restart and key mismatch', async (t) => {
  const f = sourceFixture(t),
    doc = f.document(),
    submit = f.endpoint.submit;
  f.endpoint.submit = async (sealed) => {
    await submit(sealed);
    throw Error('SIMULATED_ADMISSION_RESPONSE_LOSS');
  };
  await assert.rejects(f.outbox.submit(doc), /SIMULATED_ADMISSION/);
  const stored = f.outbox.db.prepare('SELECT * FROM sealed_outbox').get();
  f.outbox.close();
  assert.throws(
    () => new SealedDocumentOutbox({ ...f.settings, dedupKey: randomBytes(32) }),
    /CONFIG_MISMATCH/,
  );
  f.endpoint.submit = submit;
  const reopened = new SealedDocumentOutbox(f.settings);
  t.after(() => reopened.close());
  const accepted = await reopened.submit(doc);
  assert.equal(accepted.objectId, JSON.parse(stored.sealed).envelope.objectId);
  assert.equal(f.calls.seal, 1);
  f.endpoint.listObjects = async () => [{ id: accepted.objectId, state: 'DELIVERED' }];
  assert.equal((await reopened.status(doc.documentId)).state, 'DELIVERED');
  f.endpoint.listObjects = async () => [];
  await assert.rejects(reopened.status(doc.documentId), /DOCUMENT_UNKNOWN/);
});

test('source admission requires a bound authority receipt; staging cannot award acceptance', async (t) => {
  const f = sourceFixture(t),
    doc = f.document();
  f.endpoint.submit = async () => ({
    object: { id: randomUUID() },
    receipt: { payload: { eventType: 'SUBMITTED' }, signature: 'forged' },
  });
  await assert.rejects(f.outbox.submit(doc), /ADMISSION_RECEIPT/);
  assert.equal(f.outbox.db.prepare('SELECT response FROM sealed_outbox').get().response, null);
  f.outbox.send = async () => ({ status: 200, body: { accepted: true } });
  await assert.rejects(f.outbox.submit(doc), /STAGING_REJECTED/);
});

test('sealed outbox bounds capacity and queued work without persisting plaintext or unkeyed document hashes', async (t) => {
  const f = sourceFixture(t, { maxPending: 1, maxEntries: 1 }),
    held = deferred(),
    entered = deferred(),
    seal = f.endpoint.seal;
  f.endpoint.seal = async (...args) => {
    entered.resolve();
    await held.promise;
    return seal(...args);
  };
  const doc = f.document(),
    first = f.outbox.submit(doc);
  await entered.promise;
  await assert.rejects(f.outbox.submit(f.document()), /OUTBOX_BUSY/);
  doc.body = 'SYNTHETIC_MUTATED';
  held.resolve();
  await first;
  await assert.rejects(f.outbox.submit(f.document()), /OUTBOX_CAPACITY/);
  const stored = JSON.stringify(f.outbox.db.prepare('SELECT * FROM sealed_outbox').all());
  for (const canary of [
    'SYNTHETIC_CONTENT_CANARY',
    'SYNTHETIC_MUTATED',
    Buffer.from('SYNTHETIC_CONTENT_CANARY').toString('base64url'),
  ])
    assert.equal(stored.includes(canary), false);
  const tiny = sourceFixture(t, { maxStoredBytes: 1 });
  await assert.rejects(tiny.outbox.submit(tiny.document()), /OUTBOX_CAPACITY/);
  assert.equal(tiny.calls.send, 0);
  assert.throws(
    () => new SealedDocumentOutbox({ ...f.settings, dedupKey: undefined }),
    /KEY_REQUIRED/,
  );
});

async function secureFixture(t) {
  const f = await provision(),
    stack = await startSecureStack(f.dir),
    work = mkdtempSync(join(tmpdir(), 'siepmu-sealed-process-'));
  let adapter;
  t.after(async () => {
    await adapter?.stop();
    await stack.stop();
    rmSync(work, { recursive: true, force: true });
    rmSync(f.dir, { recursive: true, force: true });
  });
  const endpointFor = async (profile) => {
    const e = new IntegrationEndpoint({
      url: stack.baseUrl,
      tls: stack.tls,
      profile,
      authorityKey: f.provisioned.serverPublicKey,
    });
    await e.authenticate();
    return e;
  };
  const source = await endpointFor(f.profiles.alice),
    recipient = await endpointFor(f.profiles.bob);
  const dest = {
    userId: f.profiles.bob.userId,
    deviceId: f.profiles.bob.deviceId,
    unitId: f.profiles.bob.unitId,
    encryptionPublicKey: f.profiles.bob.keys.encryption.publicKey,
  };
  const start = async () => {
    adapter = await startLabSealedAdapter({
      stack,
      dir: work,
      source: f.profiles.alice,
      destinations: [dest],
    });
    return adapter;
  };
  adapter = await start();
  return {
    ...f,
    stack,
    work,
    source,
    recipient,
    dest,
    start,
    get adapter() {
      return adapter;
    },
  };
}

test('real sealed adapter and source restart preserve E2E delivery while excluding plaintext, wraps and endpoint keys from the connector', async (t) => {
  const f = await secureFixture(t),
    dedupKey = randomBytes(32),
    database = join(f.dir, 'sealed-source.sqlite');
  const doc = {
    version: 1,
    documentId: randomUUID(),
    reference: 'SYN/SEALED/001',
    title: 'Synthetic sealed handoff',
    marking: SYNTHETIC_MARKING,
    body: 'SYNTHETIC_SEALED_BOUNDARY_CANARY',
    originatorUserId: f.profiles.alice.userId,
    destinationUserId: f.profiles.bob.userId,
  };
  const intercepted = [];
  let lose = true;
  const send = async (...args) => {
    intercepted.push(structuredClone(args[2]));
    const r = await adapterTransport(f.adapter.url, f.adapter.sourceTls)(...args);
    if (lose) {
      lose = false;
      throw Error('SIMULATED_LOSS_AFTER_STAGING');
    }
    return r;
  };
  let outbox = new SealedDocumentOutbox({
    database,
    endpoint: f.source,
    destinations: [f.dest],
    send,
    dedupKey,
  });
  t.after(() => {
    try {
      outbox.close();
    } catch {}
  });
  await assert.rejects(outbox.submit(doc), /SIMULATED_LOSS/);
  assert.deepEqual(
    await f.recipient.listObjects(),
    [],
    'staging does not admit an object or release a key',
  );
  const wire = canonical(intercepted[0]);
  for (const secret of [
    doc.body,
    Buffer.from(doc.body).toString('base64url'),
    'wrappedKey',
    'creationGrant',
    'password',
    'totpSecret',
    f.profiles.alice.keys.signing.privateKey.d,
    f.profiles.bob.keys.encryption.privateKey.d,
  ])
    assert.equal(wire.includes(secret), false, secret.slice(0, 10));
  outbox.close();
  await f.adapter.stop();
  await f.start();
  outbox = new SealedDocumentOutbox({
    database,
    endpoint: f.source,
    destinations: [f.dest],
    send,
    dedupKey,
  });
  const accepted = await outbox.submit(doc);
  assert.equal(accepted.state, 'ADMITTED');
  assert.deepEqual(intercepted[0], intercepted[1]);
  const inbox = new DocumentInbox({
    endpoint: f.recipient,
    senders: new Map([[f.profiles.alice.userId, f.profiles.alice.keys.signing.publicKey]]),
  });
  const [delivered] = await inbox.poll();
  assert.equal(delivered.outcome, 'DELIVERED');
  assert.deepEqual(delivered.document, doc);
  assert.equal((await outbox.status(doc.documentId)).state, 'DELIVERED');
  for (const name of readdirSync(f.work)) {
    const b = readFileSync(join(f.work, name));
    for (const secret of [
      doc.body,
      Buffer.from(doc.body).toString('base64url'),
      f.profiles.alice.password,
      f.profiles.alice.totpSecret,
      f.profiles.alice.keys.signing.privateKey.d,
      'wrappedKey',
    ])
      assert.equal(b.includes(secret), false, name);
  }
  for (const name of readdirSync(f.dir).filter((n) => n.startsWith('sealed-source.sqlite'))) {
    const b = readFileSync(join(f.dir, name));
    assert.equal(b.includes(doc.body), false);
    assert.equal(b.includes(Buffer.from(doc.body).toString('base64url')), false);
  }
  assert.equal(f.adapter.logs().includes(doc.body), false);
  assert.equal(JSON.stringify(f.adapter.env).includes(f.profiles.alice.password), false);
  const admin = new ApiClient(secureApiTransport(f.stack.baseUrl, f.stack.tls), f.profiles.admin);
  await admin.authenticate();
  const { records } = await admin.ok('GET', '/api/evidence/export');
  assert.equal(
    records.filter(
      (r) => r.payload.objectId === accepted.objectId && r.payload.eventType === 'SUBMITTED',
    ).length,
    1,
  );
  t.diagnostic(
    'Synthetic process/restart trial: ciphertext staged; admission and release retained at authority; endpoint-only decryption PASS. Same-kernel laboratory evidence.',
  );
});

test('revocation between ciphertext staging and admission prevents a real object from entering the authority', async (t) => {
  const f = await secureFixture(t),
    admin = new ApiClient(secureApiTransport(f.stack.baseUrl, f.stack.tls), f.profiles.admin);
  await admin.authenticate();
  const send = async (...args) => {
    const r = await adapterTransport(f.adapter.url, f.adapter.sourceTls)(...args);
    const revoked = await admin.admin(
      'POST',
      `/api/admin/devices/${f.profiles.alice.deviceId}/revoke`,
    );
    assert.equal(revoked.status, 200);
    return r;
  };
  const outbox = new SealedDocumentOutbox({
    database: join(f.dir, 'sealed-source.sqlite'),
    endpoint: f.source,
    destinations: [f.dest],
    send,
    dedupKey: randomBytes(32),
  });
  t.after(() => outbox.close());
  const doc = {
    version: 1,
    documentId: randomUUID(),
    reference: 'SYN/REVOKE',
    title: 'Synthetic revoked handoff',
    marking: SYNTHETIC_MARKING,
    body: 'SYNTHETIC_REVOKED_CANARY',
    originatorUserId: f.profiles.alice.userId,
    destinationUserId: f.profiles.bob.userId,
  };
  await assert.rejects(outbox.submit(doc), /PLATFORM_REQUEST_REJECTED/);
  assert.deepEqual(await f.recipient.listObjects(), []);
  assert.equal(outbox.db.prepare('SELECT response FROM sealed_outbox').get().response, null);
});
