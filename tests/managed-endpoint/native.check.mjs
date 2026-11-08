// Both native integrations plus TLS and the actual in-process authority. Synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPkcs11Provider } from '../../integrations/pkcs11/provider.mjs';
import { createObjectCryptography } from '../../packages/crypto/crypto.mjs';
import { canonical } from '../../packages/protocol/canonical.mjs';
import { createTransportServer } from '../../packages/transport/tls.mjs';
import { generateLabPKI } from '../../deployment/secure/lab-pki.mjs';
import { coreFixture } from '../helpers/fixture.mjs';
import { createObject } from '../helpers/client.mjs';

for (const k of ['SIEPMU_PKCS11_LAB_CONFIG', 'SIEPMU_CLAMAV_CONFIG', 'SIEPMU_MANAGED_PACK_ENTRY'])
  if (!process.env[k]) throw new Error(k + ' is required; native acceptance was not executed');
const { openManagedEndpoint } = await import(
  pathToFileURL(resolve(process.env.SIEPMU_MANAGED_PACK_ENTRY))
);
const external = JSON.parse(readFileSync(process.env.SIEPMU_PKCS11_LAB_CONFIG, 'utf8'));
const inspection = JSON.parse(readFileSync(process.env.SIEPMU_CLAMAV_CONFIG, 'utf8'));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

test('separate package: token + isolated scanner + TLS + authority exchange', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-managed-native-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const tokens = join(dir, 'tokens');
  mkdirSync(tokens, { mode: 0o700 });
  const conf = join(dir, 'softhsm.conf');
  writeFileSync(
    conf,
    `directories.tokendir = ${tokens}\nobjectstore.backend = file\nlog.level = ERROR\n`,
    { mode: 0o600 },
  );
  const pin = randomBytes(16).toString('hex'),
    env = { PATH: '/usr/bin:/bin', SOFTHSM2_CONF: conf };
  const init = spawnSync(
    external.util,
    [
      '--init-token',
      '--free',
      '--label',
      'SIEPMU-managed-test',
      '--so-pin',
      randomBytes(16).toString('hex'),
      '--pin',
      pin,
    ],
    { env, timeout: 10000 },
  );
  assert.equal(init.status, 0, 'synthetic token provisioning failed');
  const serial = spawnSync(
    external.python,
    [
      '-I',
      '-c',
      'import pkcs11,sys; print(pkcs11.lib(sys.argv[1]).get_token(token_label="SIEPMU-managed-test").serial.decode())',
      external.module,
    ],
    { env, timeout: 10000, encoding: 'utf8' },
  );
  assert.equal(serial.status, 0, 'synthetic token discovery failed');
  const pkcs11 = {
    python: external.python,
    pythonSha256: sha(external.python),
    module: external.module,
    moduleSha256: sha(external.module),
    workerSha256: sha(resolve('integrations/pkcs11/worker.py')),
    tokenLabel: 'SIEPMU-managed-test',
    tokenSerial: serial.stdout.trim(),
    softhsmConfig: conf,
  };
  const provider = createPkcs11Provider({ ...pkcs11, getPin: async () => pin });
  const token = createObjectCryptography(provider);
  const f = await coreFixture(t);
  await f.clients.admin.authenticate();
  const profiles = {},
    keys = {};
  for (const name of ['alice', 'bob']) {
    await f.clients[name].authenticate();
    keys[name] = await token.generateOpaqueDeviceKeys();
    const enrollment = {
      label: 'synthetic-managed-device',
      signingPublicKey: keys[name].signing.publicKey,
      encryptionPublicKey: keys[name].encryption.publicKey,
    };
    const challenge = await f.clients[name].ok('POST', '/api/auth/challenge', {
      purpose: 'enroll',
      requestHash: await token.sha256(canonical(enrollment)),
    });
    const enrolled = await f.clients[name].ok('POST', '/api/devices/enroll', {
      ...enrollment,
      challengeId: challenge.challengeId,
      signature: await token.sign(keys[name].signing.privateKey, challenge.challenge),
    });
    assert.equal(
      (await f.clients.admin.admin('POST', `/api/admin/devices/${enrolled.device.id}/approve`))
        .status,
      200,
    );
    profiles[name] = { ...f.profiles[name], keys: keys[name], deviceId: enrolled.device.id };
  }
  const pki = generateLabPKI(join(dir, 'pki')),
    material = pki.issue('web');
  let submissions = 0;
  const protocols = new Set();
  const server = createTransportServer(async (req, res) => {
    protocols.add(req.socket.getProtocol());
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const data = Buffer.concat(chunks).toString();
    if (req.method === 'POST' && req.url === '/api/objects') submissions++;
    const reply = await f.transport(
      req.method,
      req.url,
      data ? JSON.parse(data) : undefined,
      req.headers.authorization?.replace(/^Bearer /, ''),
    );
    res.writeHead(reply.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(reply.body));
  }, material);
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => new Promise((done) => server.close(done)));
  const url = 'https://127.0.0.1:' + server.address().port;
  const config = (name) => {
    const p = profiles[name];
    return {
      schemaVersion: 1,
      url,
      authorityKey: f.provisioned.serverPublicKey,
      pkcs11,
      inspection,
      profile: {
        username: p.username,
        userId: p.userId,
        deviceId: p.deviceId,
        unitId: p.unitId,
        signing: {
          handleId: p.keys.signing.privateKey.handleId,
          publicKey: p.keys.signing.publicKey,
        },
        encryption: {
          handleId: p.keys.encryption.privateKey.handleId,
          publicKey: p.keys.encryption.publicKey,
        },
      },
    };
  };
  const credentials = (name) => ({
    password: profiles[name].password,
    totpSecret: profiles[name].totpSecret,
  });
  // Both the authority and client share this synthetic clock. TLS still verifies a real lab CA.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 30000 });
  const left = await openManagedEndpoint({
    config: config('alice'),
    tls: { ca: material.ca },
    credentials: credentials('alice'),
    getPin: async () => pin,
  });
  const right = await openManagedEndpoint({
    config: config('bob'),
    tls: { ca: material.ca },
    credentials: credentials('bob'),
    getPin: async () => pin,
  });
  t.after(() => {
    left.close();
    right.close();
  });
  const destination = {
    userId: profiles.bob.userId,
    deviceId: profiles.bob.deviceId,
    unitId: profiles.bob.unitId,
    encryptionPublicKey: keys.bob.encryption.publicKey,
  };
  await t.test(
    'facade exposes no raw provider, bypass submit or usable unbound session',
    async () => {
      assert.equal(Object.isFrozen(left), true);
      for (const field of ['call', 'crypto', 'submit', 'seal', 'provider', 'profile', 'token'])
        assert.equal(left[field], undefined);
      assert.equal(left.status().authenticated, false);
      await left.authenticate();
      await right.authenticate();
      assert.equal(left.status().authenticated, true);
      assert.deepEqual([...protocols], ['TLSv1.3']);
    },
  );
  await t.test(
    'scans, encrypts, submits, decrypts, rescans and acknowledges a benign file',
    async () => {
      const sent = await left.send(
        destination,
        left.createFilePayload(
          'synthetic.txt',
          'text/plain',
          Buffer.from('SYNTHETIC MANAGED FILE'),
        ),
      );
      const id = sent.receipt.payload.objectId;
      const received = await right.receiveWithRelease(id, keys.alice.signing.publicKey);
      assert.equal(
        Buffer.from(received.plaintext.data, 'base64url').toString(),
        'SYNTHETIC MANAGED FILE',
      );
      await right.acknowledge(id, received.release);
    },
  );
  const eicar = Buffer.from(
    'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-' + 'STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
  );
  await t.test('outbound EICAR is denied before object submission', async () => {
    const before = submissions;
    await assert.rejects(
      left.send(destination, left.createFilePayload('synthetic.txt', 'text/plain', eicar)),
      { code: 'FILE_INSPECTION_DETECTED' },
    );
    assert.equal(submissions, before);
  });
  await t.test(
    'a valid encrypted EICAR object from another client is denied after decryption',
    async () => {
      const malicious = createObject(
        f.profiles.alice,
        profiles.bob,
        await f.clients.alice.grant(),
        { kind: 'file', name: 'synthetic.txt', data: eicar },
      );
      await f.clients.alice.submit(malicious);
      await assert.rejects(
        right.receive(malicious.envelope.objectId, f.profiles.alice.keys.signing.publicKey),
        { code: 'FILE_INSPECTION_DETECTED' },
      );
    },
  );
  await t.test('untrusted TLS issuer fails authentication without a bound session', async () => {
    const other = generateLabPKI(join(dir, 'other-pki')).issue('other');
    const refused = await openManagedEndpoint({
      config: config('alice'),
      tls: { ca: other.ca },
      credentials: credentials('alice'),
      getPin: async () => pin,
    });
    try {
      await assert.rejects(refused.authenticate());
      assert.equal(refused.status().authenticated, false);
    } finally {
      refused.close();
    }
  });
  await t.test('concurrency and closed handles are refused', async () => {
    const running = right.listObjects();
    assert.throws(() => right.close(), { code: 'MANAGED_ENDPOINT_BUSY' });
    await assert.rejects(right.listObjects(), { code: 'MANAGED_ENDPOINT_BUSY' });
    await running;
    right.close();
    right.close();
    await assert.rejects(right.authenticate(), { code: 'MANAGED_ENDPOINT_CLOSED' });
    assert.equal(right.status().authenticated, false);
  });
});
