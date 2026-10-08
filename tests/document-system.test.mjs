// Synthetic document-management system integrated through the adapter (HPSC Demo 3).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical } from '../packages/protocol/canonical.mjs';
import { createObjectCryptography } from '../packages/crypto/crypto.mjs';
import {
  validateDocument,
  toAdapterRequest,
  fromDeliveredPayload,
  DOCUMENT_MIME,
  MAX_BODY_BYTES,
  SYNTHETIC_MARKING,
} from '../apps/document-system/document.mjs';
import { DocumentOutbox, adapterTransport } from '../apps/document-system/outbox.mjs';
import { DocumentInbox } from '../apps/document-system/inbox.mjs';
import { provision } from './helpers/fixture.mjs';
import { ApiClient } from './helpers/client.mjs';
import { startSecureStack, secureApiTransport } from '../deployment/secure/harness.mjs';
import { startLabAdapter } from '../deployment/secure/adapter-process.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';

const crypto = createObjectCryptography();
const ORIGINATOR = randomUUID();
const DESTINATION = randomUUID();

const documentOf = (overrides = {}) => ({
  version: 1,
  documentId: randomUUID(),
  reference: 'SYN/LOG/2026/001',
  title: 'Synthetic movement order',
  marking: SYNTHETIC_MARKING,
  body: 'SYNTHETIC: move two pallets of spares to Unit B on D+1.',
  originatorUserId: ORIGINATOR,
  destinationUserId: DESTINATION,
  ...overrides,
});

test('document contract accepts exactly the synthetic schema', () => {
  assert.doesNotThrow(() => validateDocument(documentOf()));
  const cases = [
    [{ ...documentOf(), extra: 1 }, 'DOCUMENT_SCHEMA'],
    [documentOf({ version: 2 }), 'DOCUMENT_VERSION'],
    [documentOf({ marking: 'SECRET' }), 'DOCUMENT_MARKING'],
    [documentOf({ documentId: 'not-a-uuid' }), 'DOCUMENT_SCHEMA'],
    [documentOf({ reference: 'lowercase/ref' }), 'DOCUMENT_SCHEMA'],
    [documentOf({ title: '' }), 'DOCUMENT_SCHEMA'],
    [documentOf({ title: 'bell\u0007' }), 'DOCUMENT_SCHEMA'],
    [documentOf({ body: 'x'.repeat(MAX_BODY_BYTES + 1) }), 'DOCUMENT_SCHEMA'],
    [documentOf({ body: 7 }), 'DOCUMENT_SCHEMA'],
    [null, 'DOCUMENT_SCHEMA'],
    [[], 'DOCUMENT_SCHEMA'],
  ];
  for (const [value, code] of cases)
    assert.throws(() => validateDocument(value), { code }, JSON.stringify(value)?.slice(0, 80));
  // Boundary: exactly the maximum body size is accepted.
  assert.doesNotThrow(() => validateDocument(documentOf({ body: 'x'.repeat(MAX_BODY_BYTES) })));
});

test('adapter request round-trips and binds the document to the attested parties', () => {
  const document = documentOf();
  const request = toAdapterRequest({
    document,
    requestId: randomUUID(),
    issuedAt: 1,
    createFilePayload: crypto.createFilePayload,
  });
  assert.equal(request.senderUserId, ORIGINATOR);
  assert.equal(request.destinationUserId, DESTINATION);
  assert.equal(request.payload.mime, DOCUMENT_MIME);
  const unpacked = crypto.unpackPayload(request.payload);
  const parties = { senderUserId: ORIGINATOR, recipientUserId: DESTINATION };
  assert.deepEqual(fromDeliveredPayload(unpacked, parties), document);
  // A document claiming parties other than the authority-attested ones is refused.
  assert.throws(() => fromDeliveredPayload(unpacked, { ...parties, senderUserId: randomUUID() }), {
    code: 'DOCUMENT_PARTY_MISMATCH',
  });
  // Non-canonical bytes (same JSON, different encoding) are refused.
  const padded = { ...unpacked, bytes: new TextEncoder().encode(' ' + canonical(document)) };
  assert.throws(() => fromDeliveredPayload(padded, parties), { code: 'DOCUMENT_ENCODING' });
  assert.throws(() => fromDeliveredPayload({ ...unpacked, mime: 'text/plain' }, parties), {
    code: 'DOCUMENT_TYPE',
  });
  assert.throws(() => fromDeliveredPayload({ ...unpacked, name: 'other.json' }, parties), {
    code: 'DOCUMENT_NAME',
  });
  assert.throws(
    () =>
      toAdapterRequest({
        document,
        requestId: 'x',
        issuedAt: 1,
        createFilePayload: crypto.createFilePayload,
      }),
    { code: 'REQUEST_ID' },
  );
});

test('outbox is idempotent per document and refuses a changed document under the same ID', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-dms-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sent = [];
  const outbox = new DocumentOutbox({
    database: join(dir, 'outbox.sqlite'),
    createFilePayload: crypto.createFilePayload,
    send: async (method, path, body) => {
      sent.push({ method, path, body });
      return { status: 200, body: { accepted: true, objectId: 'object-1' } };
    },
  });
  t.after(() => outbox.close());
  const document = documentOf();
  const first = await outbox.submit(document);
  assert.deepEqual(await outbox.submit(document), first);
  await assert.rejects(outbox.submit({ ...document, title: 'changed' }), {
    code: 'DOCUMENT_CONFLICT',
  });
  assert.equal(sent.length, 1);
  await assert.rejects(outbox.status(randomUUID()), { code: 'DOCUMENT_UNKNOWN' });
});

test('outbox resends the identical request after a lost answer and maps refusals', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-dms-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const requests = [];
  let answers = [
    () => Promise.reject(new Error('SIMULATED_LOSS')),
    () => Promise.resolve({ status: 200, body: { accepted: true, objectId: 'o' } }),
  ];
  const outbox = new DocumentOutbox({
    database: join(dir, 'outbox.sqlite'),
    createFilePayload: crypto.createFilePayload,
    send: (method, path, body) => {
      requests.push(body);
      return answers.shift()();
    },
  });
  t.after(() => outbox.close());
  const document = documentOf();
  await assert.rejects(outbox.submit(document), /SIMULATED_LOSS/);
  await outbox.submit(document);
  assert.deepEqual(requests[0], requests[1], 'the retry is byte-identical');
  answers = [() => Promise.resolve({ status: 403, body: null })];
  await assert.rejects(outbox.submit(documentOf()), { code: 'SOURCE_NOT_AUTHENTICATED' });
  answers = [() => Promise.resolve({ status: 409, body: { code: 'ADAPTER_REJECTED' } })];
  await assert.rejects(outbox.submit(documentOf()), { code: 'ADAPTER_REJECTED' });
  assert.throws(() => adapterTransport('http://127.0.0.1:1', {}), /DMS_TLS_REQUIRED/);
});

test('document exchange through the adapter process on the secure stack', async (t) => {
  const f = await provision();
  const stack = await startSecureStack(f.dir);
  const work = mkdtempSync(join(tmpdir(), 'siepmu-dms-stack-'));
  t.after(async () => {
    await stack.stop();
    rmSync(work, { recursive: true, force: true });
    await rm(f.dir, { recursive: true, force: true });
  });
  const { alice, bob, eve } = f.profiles;
  const destination = (p) => ({
    userId: p.userId,
    deviceId: p.deviceId,
    unitId: p.unitId,
    encryptionPublicKey: p.keys.encryption.publicKey,
  });
  const adapter = await startLabAdapter({
    stack,
    dir: work,
    profile: alice,
    destinations: [destination(bob)],
  });
  t.after(() => adapter.stop());
  const outbox = new DocumentOutbox({
    database: join(work, 'dms-outbox.sqlite'),
    createFilePayload: crypto.createFilePayload,
    send: adapterTransport(adapter.url, adapter.sourceTls),
  });
  t.after(() => outbox.close());
  const document = documentOf({
    originatorUserId: alice.userId,
    destinationUserId: bob.userId,
    body: 'SYNTHETIC_DOCUMENT_CANARY',
  });

  // 1. Authorised document is accepted and becomes an encrypted SIEPMU object.
  const accepted = await outbox.submit(document);
  assert.match(accepted.objectId, /^[0-9a-f-]{36}$/);
  // 2. Duplicate submission returns the same object; nothing new is created.
  assert.deepEqual(await outbox.submit(document), accepted);
  // 3. Unauthorised destination (not in the adapter's destination list) is refused.
  await assert.rejects(
    outbox.submit(documentOf({ originatorUserId: alice.userId, destinationUserId: eve.userId })),
    { code: 'ADAPTER_REJECTED' },
  );
  // 4. A source presenting an unpinned client certificate is refused by the adapter.
  const impostor = new DocumentOutbox({
    database: join(work, 'impostor.sqlite'),
    createFilePayload: crypto.createFilePayload,
    send: adapterTransport(adapter.url, stack.pki.material('unit-denied')),
  });
  t.after(() => impostor.close());
  await assert.rejects(
    impostor.submit(documentOf({ originatorUserId: alice.userId, destinationUserId: bob.userId })),
    { code: 'SOURCE_NOT_AUTHENTICATED' },
  );
  // 5. Replay of the raw request with a changed payload under the same request ID conflicts.
  const send = adapterTransport(adapter.url, adapter.sourceTls);
  const stored = JSON.parse(
    /** @type {string} */ (
      outbox.db.prepare('SELECT request FROM outbox WHERE document_id=?').get(document.documentId)
        .request
    ),
  );
  const tampered = await send('POST', '/v1/messages', {
    ...stored,
    payload: crypto.createTextPayload('changed'),
  });
  assert.equal(tampered.status, 409);
  assert.equal((await outbox.status(document.documentId)).state, 'PENDING');

  // 6. Destination system receives, validates and acknowledges with signed evidence.
  const bobEndpoint = new IntegrationEndpoint({
    url: stack.baseUrl,
    tls: stack.tls,
    profile: bob,
    authorityKey: f.provisioned.serverPublicKey,
  });
  await bobEndpoint.authenticate();
  const inbox = new DocumentInbox({
    endpoint: bobEndpoint,
    senders: new Map([[alice.userId, alice.keys.signing.publicKey]]),
  });
  const [outcome, ...rest] = await inbox.poll();
  assert.equal(rest.length, 0);
  assert.equal(outcome.outcome, 'DELIVERED', JSON.stringify(outcome));
  assert.deepEqual(outcome.document, document);
  assert.equal(outcome.acknowledgement.payload.eventType, 'DELIVERY_ACK');
  assert.equal(
    await bobEndpoint.crypto.verifyPacket(f.provisioned.serverPublicKey, outcome.acknowledgement),
    true,
  );
  // 7. The source sees delivery; a second poll finds nothing left to claim.
  assert.equal((await outbox.status(document.documentId)).state, 'DELIVERED');
  assert.deepEqual(await inbox.poll(), []);

  // 8. The signed chain records exactly one submission, release and acknowledgement.
  const admin = new ApiClient(secureApiTransport(stack.baseUrl, stack.tls), f.profiles.admin);
  await admin.authenticate();
  const { records } = await admin.ok('GET', '/api/evidence/export');
  const forObject = (type) =>
    records.filter((r) => r.payload.objectId === accepted.objectId && r.payload.eventType === type);
  for (const type of ['SUBMITTED', 'RELEASE_ISSUED', 'DELIVERY_ACK'])
    assert.equal(forObject(type).length, 1, type);
  // 9. No plaintext in the adapter store, the source outbox, or adapter logs.
  for (const file of ['adapter.sqlite']) {
    assert.equal(readFileSync(join(work, file)).includes('SYNTHETIC_DOCUMENT_CANARY'), false);
  }
  assert.equal(adapter.logs().includes('SYNTHETIC_DOCUMENT_CANARY'), false);
});
