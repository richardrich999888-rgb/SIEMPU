import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrivateKey,
  sign as nativeSign,
  createPublicKey,
  verify as nativeVerify,
} from 'node:crypto';
import { canonical } from '../packages/protocol/canonical.mjs';
import {
  b64,
  unb64,
  sha256,
  generateDeviceKeys,
  sign,
  verify,
  keyId,
  signPacket,
  verifyPacket,
  encryptObject,
  decryptObject,
  sealVault,
  openVault,
  createTextPayload,
  createFilePayload,
  unpackPayload,
  validatePayload,
} from '../packages/crypto/crypto.mjs';
import { verifyEvidence } from '../apps/verifier/verify.mjs';
import {
  decode as serverDecode,
  validateKey as serverValidateKey,
  packet as serverPacket,
} from '../services/control/primitives.mjs';

const alice = await generateDeviceKeys();
const bob = await generateDeviceKeys();
const authority = await generateDeviceKeys();
const epoch = 5;
const grant = await signPacket(authority.signing.privateKey, {
  userId: 'alice',
  deviceId: 'alice-device',
  unitId: 'unit-a',
  missionIds: ['exercise'],
  epoch,
  issuedAt: 100,
  expiresAt: 10000,
  maxSensitivity: 'DEMO',
});
async function fixture() {
  const context = {
    schemaVersion: 1,
    objectId: crypto.randomUUID(),
    senderUserId: 'alice',
    senderDeviceId: 'alice-device',
    senderUnitId: 'unit-a',
    recipientUserId: 'bob',
    recipientDeviceId: 'bob-device',
    recipientUnitId: 'unit-b',
    recipientKeyId: await keyId(bob.encryption.publicKey),
    missionId: 'exercise',
    classification: 'DEMO',
    action: 'deliver',
    createdAt: 200,
    expiresAt: 9000,
    creationGrant: grant,
    cryptoSuite: 'P256-HKDF-SHA256-AES256GCM',
    keyVersion: 1,
  };
  const payload = createTextPayload('Synthetic exercise message. No operational data.');
  return {
    context,
    payload,
    sealed: await encryptObject(
      context,
      payload,
      bob.encryption.publicKey,
      alice.signing.privateKey,
    ),
  };
}
const copy = (value) => structuredClone(value);

test('canonical encoding has stable field ordering and rejects ambiguous values', () => {
  assert.equal(
    canonical({ z: 1, a: [null, true, 'x'], nested: { z: 2, a: 0 } }),
    '{"a":[null,true,"x"],"nested":{"a":0,"z":2},"z":1}',
  );
  for (const value of [
    undefined,
    NaN,
    Infinity,
    0.1,
    -0,
    9007199254740992,
    new Date(),
    { a: undefined },
    [, 1],
    {
      get a() {
        throw new Error('must not execute');
      },
    },
  ])
    assert.throws(() => canonical(value));
  const circular = {};
  circular.self = circular;
  assert.throws(() => canonical(circular));
  const disguisedSparse = new Array(2);
  disguisedSparse[1] = 1;
  disguisedSparse.extra = 2;
  assert.throws(() => canonical(disguisedSparse));
  const accessorArray = [1];
  Object.defineProperty(accessorArray, '0', {
    enumerable: true,
    get() {
      throw new Error('must not execute');
    },
  });
  assert.throws(() => canonical(accessorArray), /accessors/);
});
test('base64url accepts exact encodings and rejects alternate encodings', () => {
  const bytes = new Uint8Array([0, 255, 254, 1]);
  assert.deepEqual(unb64(b64(bytes)), bytes);
  for (const input of ['_w==', '_x', 'A', 'a+b', 'abc\n']) assert.throws(() => unb64(input));
});
test('server base64url decoder rejects alternate encodings with unused-bit changes', () => {
  assert.deepEqual(serverDecode('_w'), Buffer.from([255]));
  for (const value of ['_x', '_y', '_z', 'AA=', 'A', 'AA\n'])
    assert.throws(() => serverDecode(value));
});
test('server public key validation rejects private members even when empty', () => {
  assert.deepEqual(serverValidateKey(alice.signing.publicKey), alice.signing.publicKey);
  assert.throws(() => serverValidateKey({ ...alice.signing.publicKey, d: '' }));
  assert.throws(() => serverValidateKey({ ...alice.signing.publicKey, d: null }));
  assert.throws(() => serverValidateKey(alice.signing.privateKey));
});
test('native signed packet and body-hash operation helper interoperate with WebCrypto', async (t) => {
  const { coreFixture } = await import('./helpers/fixture.mjs');
  const f = await coreFixture(t);
  await f.clients.admin.authenticate();
  const body = {
    fromUnit: f.provisioned.units.A,
    toUnit: f.provisioned.units.B,
    missionId: 'DEMO-MISSION',
    allow: false,
  };
  const proof = await f.clients.admin.proof('admin:PUT:/api/admin/policies', body);
  const challenge = JSON.parse(
    f.authority.get('SELECT payload FROM challenges WHERE id=?', proof.challengeId).payload,
  );
  assert.equal(challenge.requestHash, await sha256(canonical(body)));
  assert.equal(
    await verify(f.profiles.admin.keys.signing.publicKey, challenge, proof.signature),
    true,
  );
  const changed = { ...challenge, requestHash: await sha256(canonical({ ...body, allow: true })) };
  assert.equal(
    await verify(f.profiles.admin.keys.signing.publicKey, changed, proof.signature),
    false,
  );
  const nativePacket = serverPacket(f.authority.key, challenge);
  assert.equal(await verifyPacket(f.provisioned.serverPublicKey, nativePacket), true);
  assert.equal(
    await verifyPacket(f.provisioned.serverPublicKey, { ...nativePacket, payload: changed }),
    false,
  );
});
test('browser signatures interoperate with native Node P1363 signatures', async () => {
  const value = { challenge: 'one-use', epoch: 1 };
  const signature = await sign(alice.signing.privateKey, value);
  assert.equal(unb64(signature).length, 64);
  assert.equal(
    nativeVerify(
      'sha256',
      Buffer.from(canonical(value)),
      {
        key: createPublicKey({ key: alice.signing.publicKey, format: 'jwk' }),
        dsaEncoding: 'ieee-p1363',
      },
      Buffer.from(signature, 'base64url'),
    ),
    true,
  );
  const serverSignature = nativeSign('sha256', Buffer.from(canonical(value)), {
    key: createPrivateKey({ key: alice.signing.privateKey, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  assert.equal(await verify(alice.signing.publicKey, value, serverSignature), true);
  assert.equal(await verify(bob.signing.publicKey, value, signature), false);
  assert.equal(await verify(alice.signing.publicKey, { ...value, epoch: 2 }, signature), false);
  assert.equal(await verify({ ...alice.signing.publicKey, crv: 'P-384' }, value, signature), false);
  assert.equal(await verify(alice.signing.privateKey, value, signature), false);
});
test('signed packets bind the independently trusted key ID', async () => {
  assert.equal(await verifyPacket(authority.signing.publicKey, grant), true);
  assert.equal(await verifyPacket(alice.signing.publicKey, grant), false);
  assert.equal(
    await verifyPacket(authority.signing.publicKey, { ...grant, keyId: 'f'.repeat(64) }),
    false,
  );
  assert.equal(await verifyPacket(authority.signing.publicKey, { ...grant, unbound: true }), false);
});
test('object round trip, randomized encryption, text and file payloads', async () => {
  const { context, payload, sealed } = await fixture();
  const result = await decryptObject(sealed, bob.encryption.privateKey, alice.signing.publicKey);
  assert.deepEqual(result, payload);
  assert.equal(unpackPayload(result).text, 'Synthetic exercise message. No operational data.');
  assert.notEqual(
    (await encryptObject(context, payload, bob.encryption.publicKey, alice.signing.privateKey))
      .ciphertext,
    sealed.ciphertext,
  );
  const filePayload = createFilePayload('synthetic.bin', '', new Uint8Array([0, 1, 254, 255]));
  const file = await encryptObject(
    context,
    filePayload,
    bob.encryption.publicKey,
    alice.signing.privateKey,
  );
  assert.deepEqual(
    unpackPayload(await decryptObject(file, bob.encryption.privateKey, alice.signing.publicKey))
      .bytes,
    new Uint8Array([0, 1, 254, 255]),
  );
});
test('wrong recipient and wrong sender keys cannot open an object', async () => {
  const { sealed } = await fixture();
  await assert.rejects(
    decryptObject(sealed, alice.encryption.privateKey, alice.signing.publicKey),
    /Recipient key/,
  );
  await assert.rejects(
    decryptObject(sealed, bob.encryption.privateKey, bob.signing.publicKey),
    /signature/,
  );
});
test('every security context member is signature bound', async () => {
  const { sealed } = await fixture();
  for (const field of [
    'objectId',
    'senderUserId',
    'senderDeviceId',
    'senderUnitId',
    'recipientUserId',
    'recipientDeviceId',
    'recipientUnitId',
    'recipientKeyId',
    'missionId',
    'classification',
    'action',
    'createdAt',
    'expiresAt',
    'creationGrant',
    'cryptoSuite',
    'keyVersion',
    'nonce',
    'ciphertextHash',
  ]) {
    const bad = copy(sealed);
    if (typeof bad.envelope[field] === 'number') bad.envelope[field] += 1;
    else if (field === 'creationGrant') bad.envelope[field].payload.epoch += 1;
    else bad.envelope[field] += 'x';
    await assert.rejects(
      decryptObject(bad, bob.encryption.privateKey, alice.signing.publicKey),
      undefined,
      field,
    );
  }
});
test('ciphertext corruption is rejected even before authenticated decryption', async () => {
  const { sealed } = await fixture();
  const bad = copy(sealed);
  const bytes = unb64(bad.ciphertext);
  bytes[0] ^= 1;
  bad.ciphertext = b64(bytes);
  await assert.rejects(
    decryptObject(bad, bob.encryption.privateKey, alice.signing.publicKey),
    /integrity/,
  );
});
test('signed corrupted key wrap and altered AAD fail authenticated decryption', async () => {
  const { sealed } = await fixture();
  const badWrap = copy(sealed);
  const bytes = unb64(badWrap.envelope.wrappedKey.ciphertext);
  bytes[0] ^= 1;
  badWrap.envelope.wrappedKey.ciphertext = b64(bytes);
  badWrap.signature = await sign(alice.signing.privateKey, badWrap.envelope);
  await assert.rejects(
    decryptObject(badWrap, bob.encryption.privateKey, alice.signing.publicKey),
    /authentication failed/,
  );
  const changed = copy(sealed);
  changed.envelope.missionId = 'different';
  changed.signature = await sign(alice.signing.privateKey, changed.envelope);
  await assert.rejects(
    decryptObject(changed, bob.encryption.privateKey, alice.signing.publicKey),
    /authentication failed/,
  );
});
test('encryption rejects recipient key substitutions and unsupported context', async () => {
  const { context, payload } = await fixture();
  await assert.rejects(
    encryptObject(context, payload, alice.encryption.publicKey, alice.signing.privateKey),
    /key ID mismatch/,
  );
  await assert.rejects(
    encryptObject(
      { ...context, extra: true },
      payload,
      bob.encryption.publicKey,
      alice.signing.privateKey,
    ),
  );
  await assert.rejects(
    encryptObject(
      { ...context, expiresAt: context.createdAt },
      payload,
      bob.encryption.publicKey,
      alice.signing.privateKey,
    ),
  );
});
test('payload checks reject path traversal, HTML-as-text, malformed content and invalid UTF-8', () => {
  for (const name of ['../private', 'a\\b', '\u0000bad', '..'])
    assert.throws(() => createFilePayload(name, 'application/octet-stream', new Uint8Array()));
  assert.throws(() =>
    validatePayload({
      kind: 'text',
      name: 'a.html',
      mime: 'text/html',
      data: b64(new TextEncoder().encode('<script>')),
    }),
  );
  assert.throws(() => validatePayload({ ...createTextPayload('ok'), data: '_w' }));
  assert.throws(() => createFilePayload('a', 'text/plain\r\nx: y', new Uint8Array()));
});
test('vault round trip, random salt and IV, wrong passphrase and metadata tamper', async () => {
  const value = {
    keys: alice,
    outbox: [{ id: 'synthetic', message: 'encrypted locally' }],
    clockFloor: 1000,
  };
  const packet = await sealVault(value, 'synthetic vault password');
  assert.deepEqual(await openVault(packet, 'synthetic vault password'), value);
  assert.notEqual(
    (await sealVault(value, 'synthetic vault password')).ciphertext,
    packet.ciphertext,
  );
  await assert.rejects(openVault(packet, 'different vault password'), /unlock failed/);
  await assert.rejects(
    openVault({ ...packet, iterations: 1 }, 'synthetic vault password'),
    /Unsupported/,
  );
  const bad = copy(packet);
  const bytes = unb64(bad.ciphertext);
  bytes[0] ^= 1;
  bad.ciphertext = b64(bytes);
  await assert.rejects(openVault(bad, 'synthetic vault password'), /unlock failed/);
  await assert.rejects(sealVault(value, 'short'), /12/);
});

async function evidence(count = 3) {
  const records = [];
  let previousHash = '0'.repeat(64);
  for (let sequence = 1; sequence <= count; sequence++) {
    const record = await signPacket(authority.signing.privateKey, {
      sequence,
      previousHash,
      eventId: crypto.randomUUID(),
      eventType: 'SYNTHETIC_TEST',
      timestamp: sequence * 100,
      epoch,
      actorId: 'synthetic',
      details: { index: sequence },
    });
    records.push(record);
    previousHash = await sha256(canonical(record));
  }
  const checkpoint = await signPacket(authority.signing.privateKey, {
    sequence: count,
    headHash: previousHash,
    issuedAt: 500,
  });
  return { records, checkpoint };
}
test('detached verifier accepts signed packets and chained evidence with saved checkpoint', async () => {
  assert.equal((await verifyEvidence(grant, authority.signing.publicKey)).valid, true);
  const chain = await evidence();
  const result = await verifyEvidence(chain, authority.signing.publicKey, {
    checkpoint: chain.checkpoint,
  });
  assert.equal(result.records, 3);
  assert.equal(result.externalCheckpointVerified, true);
  await assert.rejects(verifyEvidence(chain, bob.signing.publicKey), /key ID/);
});
test('detached verifier member check is unambiguous for names containing the old separator', async () => {
  // Regression: members were compared as sort().join('|'), so one member named "keyId|payload"
  // matched the expected pair. Found while porting the verifier to Rust (ADR-012).
  await assert.rejects(
    verifyEvidence({ 'keyId|payload': 'x', signature: 'y' }, authority.signing.publicKey),
    /Unexpected or missing packet members/,
  );
  const chain = await evidence();
  chain.checkpoint = await signPacket(authority.signing.privateKey, {
    'headHash|issuedAt': chain.checkpoint.payload.headHash,
    sequence: chain.checkpoint.payload.sequence,
  });
  await assert.rejects(
    verifyEvidence(chain, authority.signing.publicKey),
    /Unexpected or missing packet members/,
  );
});
test('detached verifier detects tamper, ordering and deletion', async () => {
  const chain = await evidence();
  const tamper = copy(chain);
  tamper.records[0].payload.details.index = 900;
  await assert.rejects(verifyEvidence(tamper, authority.signing.publicKey), /Signature/);
  const reorder = copy(chain);
  [reorder.records[0], reorder.records[1]] = [reorder.records[1], reorder.records[0]];
  await assert.rejects(verifyEvidence(reorder, authority.signing.publicKey), /Sequence/);
  const deletion = copy(chain);
  deletion.records.splice(1, 1);
  await assert.rejects(verifyEvidence(deletion, authority.signing.publicKey), /Sequence/);
  const suffix = copy(chain);
  suffix.records.pop();
  await assert.rejects(verifyEvidence(suffix, authority.signing.publicKey), /checkpoint/);
});
test('saved checkpoint detects valid signed prefix replay; embedded old checkpoint alone cannot', async () => {
  const chain = await evidence();
  const prefix = {
    records: chain.records.slice(0, 2),
    checkpoint: await signPacket(authority.signing.privateKey, {
      sequence: 2,
      headHash: await sha256(canonical(chain.records[1])),
      issuedAt: 250,
    }),
  };
  const withoutExternal = await verifyEvidence(prefix, authority.signing.publicKey);
  assert.equal(withoutExternal.valid, true);
  assert.equal(withoutExternal.externalCheckpointVerified, false);
  await assert.rejects(
    verifyEvidence(prefix, authority.signing.publicKey, { checkpoint: chain.checkpoint }),
    /truncated/,
  );
  assert.equal(
    (await verifyEvidence(chain, authority.signing.publicKey, { checkpoint: prefix.checkpoint }))
      .valid,
    true,
  );
});
test('saved checkpoint rejects alternate correctly signed chain at same sequence', async () => {
  const chain = await evidence();
  const alternate = await evidence();
  await assert.rejects(
    verifyEvidence(chain, authority.signing.publicKey, { checkpoint: alternate.checkpoint }),
    /conflicts/,
  );
});

async function releaseReceipt() {
  return signPacket(authority.signing.privateKey, {
    sequence: 1,
    previousHash: '0'.repeat(64),
    eventId: crypto.randomUUID(),
    eventType: 'RELEASE_ISSUED',
    timestamp: 1000,
    epoch,
    actorId: 'bob',
    objectId: crypto.randomUUID(),
    decision: 'RELEASED',
    details: { authorityEpoch: epoch, objectDigest: 'a'.repeat(64) },
  });
}
test('detached receipt verification compares independent expected digest, epoch and object ID', async () => {
  const receipt = await releaseReceipt();
  const options = {
    objectDigest: receipt.payload.details.objectDigest,
    epoch,
    objectId: receipt.payload.objectId,
  };
  const result = await verifyEvidence(receipt, authority.signing.publicKey, options);
  assert.equal(result.bindingVerified, true);
  assert.deepEqual(result.expectedBindings, {
    objectDigest: options.objectDigest,
    authorityEpoch: epoch,
    objectId: options.objectId,
  });
  await assert.rejects(
    verifyEvidence(receipt, authority.signing.publicKey, {
      ...options,
      objectDigest: 'b'.repeat(64),
    }),
    /Expected object digest mismatch/,
  );
  await assert.rejects(
    verifyEvidence(receipt, authority.signing.publicKey, { ...options, epoch: epoch + 1 }),
    /Expected authority epoch mismatch/,
  );
  await assert.rejects(
    verifyEvidence(receipt, authority.signing.publicKey, {
      ...options,
      objectId: crypto.randomUUID(),
    }),
    /Expected object ID mismatch/,
  );
  assert.equal((await verifyEvidence(receipt, authority.signing.publicKey)).bindingVerified, false);
});
test('expected-binding mode rejects contradictory signed epochs, non-release packets and ambiguous chain selection', async () => {
  const receipt = await releaseReceipt();
  const contradictory = await signPacket(authority.signing.privateKey, {
    ...receipt.payload,
    details: { ...receipt.payload.details, authorityEpoch: epoch + 1 },
  });
  assert.equal(await verifyPacket(authority.signing.publicKey, contradictory), true);
  await assert.rejects(
    verifyEvidence(contradictory, authority.signing.publicKey, { epoch }),
    /inconsistent/,
  );
  await assert.rejects(
    verifyEvidence(grant, authority.signing.publicKey, { epoch }),
    /release issuance/,
  );
  await assert.rejects(
    verifyEvidence(await evidence(), authority.signing.publicKey, { epoch }),
    /single release receipt/,
  );
  await assert.rejects(
    verifyEvidence(receipt, authority.signing.publicKey, { objectDigest: 'NOT-A-DIGEST' }),
    /lowercase SHA-256/,
  );
  await assert.rejects(
    verifyEvidence(receipt, authority.signing.publicKey, { epoch: '5' }),
    /positive safe integer/,
  );
});
test('detached verifier CLI rejects validly signed receipts for the wrong expected digest or epoch', async (t) => {
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const dir = await mkdtemp(join(tmpdir(), 'siepmu-verifier-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const receipt = await releaseReceipt();
  const receiptPath = join(dir, 'receipt.json'),
    keyPath = join(dir, 'public-key.json');
  await Promise.all([
    writeFile(receiptPath, JSON.stringify(receipt)),
    writeFile(keyPath, JSON.stringify(authority.signing.publicKey)),
  ]);
  const cli = fileURLToPath(new URL('../apps/verifier/verify.mjs', import.meta.url));
  const run = (...args) =>
    promisify(execFile)(process.execPath, [cli, receiptPath, keyPath, ...args]);
  const success = await run(
    '--object-digest',
    receipt.payload.details.objectDigest,
    '--epoch',
    String(epoch),
    '--object-id',
    receipt.payload.objectId,
  );
  assert.equal(JSON.parse(success.stdout).bindingVerified, true);
  for (const [flag, value, message] of [
    ['--object-digest', 'b'.repeat(64), 'Expected object digest mismatch'],
    ['--epoch', String(epoch + 1), 'Expected authority epoch mismatch'],
  ]) {
    await assert.rejects(
      run(flag, value),
      (error) => error.code === 1 && JSON.parse(error.stderr).error === message,
    );
  }
  await assert.rejects(run('--epoch', '1e3'), (error) => error.code === 1);
  await assert.rejects(run('--epoch', '5', '--epoch', '5'), (error) => error.code === 1);
});

test('WebCrypto endpoint interoperates with production authority and independent native peer', async (t) => {
  const { coreFixture } = await import('./helpers/fixture.mjs');
  const { createObject, decryptObject: peerDecrypt } = await import('./helpers/client.mjs');
  const f = await coreFixture(t);
  await f.clients.alice.authenticate();
  await f.clients.bob.authenticate();
  await f.clients.admin.authenticate();
  const grant = await f.clients.alice.grant();
  assert.equal(await verifyPacket(f.provisioned.serverPublicKey, grant), true);
  const native = createObject(f.profiles.alice, f.profiles.bob, grant, {
    name: 'native.txt',
    data: 'Native-to-WebCrypto synthetic content',
  });
  assert.equal(
    unpackPayload(
      await decryptObject(
        native,
        f.profiles.bob.keys.encryption.privateKey,
        f.profiles.alice.keys.signing.publicKey,
      ),
    ).text,
    'Native-to-WebCrypto synthetic content',
  );
  const { ciphertextHash, nonce, wrappedKey, ...context } = native.envelope;
  const sealed = await encryptObject(
    context,
    createTextPayload('WebCrypto-to-native synthetic content'),
    f.profiles.bob.keys.encryption.publicKey,
    f.profiles.alice.keys.signing.privateKey,
  );
  const submitted = await f.clients.alice.submit(sealed);
  assert.equal(submitted.object.state, 'PENDING');
  assert.equal(await verifyPacket(f.provisioned.serverPublicKey, submitted.receipt), true);
  const prepared = await f.clients.alice.prepare(context.objectId);
  assert.equal(prepared.body.object.state, 'READY');
  const control = await f.clients.bob.ok('GET', '/api/control');
  assert.equal(await verifyPacket(f.provisioned.serverPublicKey, control), true);
  const claimed = await f.clients.bob.claim(context.objectId, control.payload.epoch);
  assert.equal(claimed.status, 200, JSON.stringify(claimed.body));
  assert.equal(
    peerDecrypt(claimed.body, f.profiles.bob).bytes.toString(),
    'WebCrypto-to-native synthetic content',
  );
  assert.equal(
    unpackPayload(
      await decryptObject(
        claimed.body,
        f.profiles.bob.keys.encryption.privateKey,
        f.profiles.alice.keys.signing.publicKey,
      ),
    ).text,
    'WebCrypto-to-native synthetic content',
  );
  const exported = await f.clients.admin.ok('GET', '/api/evidence/export');
  assert.equal(
    (
      await verifyEvidence(exported, f.provisioned.serverPublicKey, {
        checkpoint: exported.checkpoint,
      })
    ).valid,
    true,
  );
});
