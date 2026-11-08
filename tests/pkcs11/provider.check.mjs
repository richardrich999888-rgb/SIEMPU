import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createPkcs11Provider } from '../../integrations/pkcs11/provider.mjs';
import { createObjectCryptography, DEMO_SUITE } from '../../packages/crypto/crypto.mjs';

import { coreFixture } from '../helpers/fixture.mjs';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { canonical } from '../../packages/protocol/canonical.mjs';

const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
// Explicit opt-in native gate; missing external installation is a failure, never a skip.
const external = JSON.parse(readFileSync(process.env.SIEPMU_PKCS11_LAB_CONFIG, 'utf8'));

test('real PKCS#11 endpoint integration with SoftHSM (software emulator)', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-pkcs11-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const tokens = join(dir, 'tokens');
  mkdirSync(tokens, { mode: 0o700 });
  const conf = join(dir, 'softhsm.conf');
  writeFileSync(
    conf,
    `directories.tokendir = ${tokens}\nobjectstore.backend = file\nlog.level = ERROR\n`,
    { mode: 0o600 },
  );
  const pin = randomBytes(16).toString('hex');
  const env = { PATH: '/usr/bin:/bin', SOFTHSM2_CONF: conf };
  // Generated synthetic PINs only. Production provisioning is an operator/vendor ceremony.
  const init = spawnSync(
    external.util,
    [
      '--init-token',
      '--free',
      '--label',
      'SIEPMU-test',
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
      'import pkcs11,sys; print(pkcs11.lib(sys.argv[1]).get_token(token_label="SIEPMU-test").serial.decode())',
      external.module,
    ],
    { env, timeout: 10000, encoding: 'utf8' },
  );
  assert.equal(serial.status, 0, 'token discovery failed');
  const options = {
    python: external.python,
    pythonSha256: sha(external.python),
    module: external.module,
    moduleSha256: sha(external.module),
    workerSha256: sha(resolve('integrations/pkcs11/worker.py')),
    tokenLabel: 'SIEPMU-test',
    tokenSerial: serial.stdout.trim(),
    softhsmConfig: conf,
    getPin: async () => pin,
  };
  const provider = createPkcs11Provider(options),
    token = createObjectCryptography(provider);
  const software = createObjectCryptography();
  const a = await token.generateOpaqueDeviceKeys(),
    b = await software.generateOpaqueDeviceKeys();
  await t.test(
    'token private keys cannot be exported, cloned or used for another purpose',
    async () => {
      assert.equal('d' in a.signing.privateKey, false);
      await assert.rejects(
        provider.subtle.exportKey('jwk', provider.resolve(a.signing.privateKey, 'sign')),
      );
      assert.throws(() => provider.resolve(a.signing.privateKey, 'deriveBits'), /USAGE/);
      await assert.rejects(token.sign(structuredClone(a.signing.privateKey), {}), /HANDLE/);
      await assert.rejects(
        provider.openKey(a.signing.privateKey.handleId, 'deriveBits', a.signing.publicKey),
        /OPERATION_FAILED/,
      );
      const direct = spawnSync(
        external.python,
        [
          '-I',
          '-c',
          `
import pkcs11,sys
from pkcs11 import Attribute as A,ObjectClass as O
with pkcs11.lib(sys.argv[1]).get_token(token_label='SIEPMU-test').open(user_pin=sys.stdin.read()) as s:
 k=s.get_key(object_class=O.PRIVATE_KEY,id=bytes.fromhex(sys.argv[2]))
 try:
  k[A.VALUE]
 except pkcs11.AttributeSensitive:
  print('EXPORT_DENIED')
`,
          external.module,
          a.signing.privateKey.handleId,
        ],
        { input: pin, env, timeout: 10000, encoding: 'utf8' },
      );
      assert.equal(direct.status, 0);
      assert.equal(direct.stdout.trim(), 'EXPORT_DENIED');
    },
  );
  await t.test(
    'both directions preserve v1/v2 object format and reject tampered envelopes',
    async () => {
      for (const [sender, recipient, from, to] of [
        [token, software, a, b],
        [software, token, b, a],
      ])
        for (const schemaVersion of [1, 2]) {
          const context = {
            schemaVersion,
            objectId: crypto.randomUUID(),
            senderUserId: 'a',
            senderDeviceId: 'a-device',
            senderUnitId: 'unit-a',
            recipientUserId: 'b',
            recipientDeviceId: 'b-device',
            recipientUnitId: 'unit-b',
            recipientKeyId: await recipient.keyId(to.encryption.publicKey),
            missionId: 'synthetic',
            classification: 'DEMO',
            action: 'deliver',
            createdAt: 1,
            expiresAt: 100,
            creationGrant: await sender.signPacket(from.signing.privateKey, { epoch: 1 }),
            cryptoSuite: DEMO_SUITE,
            keyVersion: 1,
            ...(schemaVersion === 2
              ? { messagePriority: 'ROUTINE', messageDomain: 'GENERAL' }
              : {}),
          };
          const payload = sender.createTextPayload('SYNTHETIC TOKEN INTEROPERABILITY');
          const object = await sender.encryptObject(
            context,
            payload,
            to.encryption.publicKey,
            from.signing.privateKey,
          );
          assert.deepEqual(
            await recipient.decryptObject(object, to.encryption.privateKey, from.signing.publicKey),
            payload,
          );
          const modified = structuredClone(object);
          modified.envelope.nonce = 'A'.repeat(16);
          await assert.rejects(
            recipient.decryptObject(modified, to.encryption.privateKey, from.signing.publicKey),
          );
        }
    },
  );
  await t.test('restart resumes only a public-key-pinned token object', async () => {
    const reopened = createPkcs11Provider(options);
    const key = await reopened.openKey(a.signing.privateKey.handleId, 'sign', a.signing.publicKey);
    assert.equal(
      await software.verify(
        a.signing.publicKey,
        { restart: true },
        await createObjectCryptography(reopened).sign(key.privateKey, { restart: true }),
      ),
      true,
    );
    await assert.rejects(
      reopened.openKey(a.signing.privateKey.handleId, 'sign', b.signing.publicKey),
      /SUBSTITUTED/,
    );
    await assert.rejects(
      reopened.openKey('0'.repeat(32), 'sign', a.signing.publicKey),
      /OPERATION_FAILED/,
    );
  });
  await t.test(
    'software private import and long-term software generation are refused',
    async () => {
      const raw = await software.generateDeviceKeys();
      await assert.rejects(token.sign(raw.signing.privateKey, {}), /PRIVATE_IMPORT_DENIED/);
      await assert.rejects(token.generateDeviceKeys(), /SOFTWARE_KEY_DENIED/);
      const foreign = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits'],
      );
      await assert.rejects(
        provider.subtle.deriveBits(
          { name: 'ECDH', public: foreign.publicKey },
          foreign.privateKey,
          256,
        ),
        /USAGE/,
      );
    },
  );
  await t.test(
    'changed module, wrong PIN and wrong token identity fail without fallback',
    async () => {
      for (const change of [
        { moduleSha256: '0'.repeat(64) },
        { getPin: async () => randomBytes(16).toString('hex') },
        { tokenSerial: 'UNKNOWN-SERIAL' },
        { workerSha256: '0'.repeat(64) },
        { pythonSha256: '0'.repeat(64) },
      ]) {
        const bad = createPkcs11Provider({ ...options, ...change });
        await assert.rejects(
          bad.openKey(a.signing.privateKey.handleId, 'sign', a.signing.publicKey),
          /PKCS11_/,
        );
      }
    },
  );
  await t.test(
    'managed endpoint enrolls a token device and exchanges policy-authorized objects',
    async (st) => {
      const f = await coreFixture(t);
      await f.clients.admin.authenticate();
      await f.clients.alice.login();
      const enrollment = {
        label: 'synthetic-token-device',
        signingPublicKey: a.signing.publicKey,
        encryptionPublicKey: a.encryption.publicKey,
      };
      const challenge = await f.clients.alice.ok('POST', '/api/auth/challenge', {
        purpose: 'enroll',
        requestHash: await token.sha256(canonical(enrollment)),
      });
      const enrolled = await f.clients.alice.ok('POST', '/api/devices/enroll', {
        ...enrollment,
        challengeId: challenge.challengeId,
        signature: await token.sign(a.signing.privateKey, challenge.challenge),
      });
      assert.equal(
        (await f.clients.admin.admin('POST', `/api/admin/devices/${enrolled.device.id}/approve`))
          .status,
        200,
      );
      const profile = { ...f.profiles.alice, keys: a, deviceId: enrolled.device.id };
      const make = async (profile, selected) => {
        const endpoint = new IntegrationEndpoint({
          url: 'https://synthetic.invalid',
          tls: {},
          profile,
          authorityKey: f.provisioned.serverPublicKey,
          provider: selected,
        });
        endpoint.call = async (method, path, body) => {
          const reply = await f.transport(method, path, body, endpoint.token);
          if (reply.status !== 200)
            throw Object.assign(new Error('SYNTHETIC_AUTHORITY_REFUSED'), {
              code: reply.body.code,
            });
          return reply.body;
        };
        await endpoint.authenticate();
        return endpoint;
      };
      // Advance the shared synthetic authority/endpoint clock; do not bypass TOTP replay protection.
      st.mock.timers.enable({ apis: ['Date'], now: Date.now() + 30000 });
      const left = await make(profile, provider),
        right = await make(f.profiles.bob);
      for (const [from, to] of [
        [left, right],
        [right, left],
      ]) {
        const destination = {
          userId: to.profile.userId,
          deviceId: to.profile.deviceId,
          unitId: to.profile.unitId,
          encryptionPublicKey: to.profile.keys.encryption.publicKey,
        };
        const payload = from.crypto.createTextPayload('SYNTHETIC TOKEN SDK EXCHANGE');
        const sealed = await from.seal(destination, payload);
        await from.submit(sealed);
        if (from === right) {
          // The fixture permits Alpha -> Bravo only. A token does not override unit policy.
          await assert.rejects(
            to.receiveWithRelease(sealed.envelope.objectId, from.profile.keys.signing.publicKey),
            { code: 'POLICY_DENIED' },
          );
          continue;
        }
        const received = await to.receiveWithRelease(
          sealed.envelope.objectId,
          from.profile.keys.signing.publicKey,
        );
        assert.deepEqual(received.plaintext, payload);
      }
    },
  );
  await t.test(
    'concurrent token requests are bounded and retained resolved handles are invalidated',
    async () => {
      const first = token.sign(a.signing.privateKey, { one: 1 });
      await assert.rejects(token.sign(a.signing.privateKey, { two: 2 }), /BUSY/);
      await first;
      const stale = provider.resolve(a.signing.privateKey, 'sign');
      provider.destroy(a.signing.privateKey);
      await assert.rejects(
        provider.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, stale, new Uint8Array()),
        /USAGE/,
      );
      await assert.rejects(token.sign(a.signing.privateKey, {}), /DESTROYED/);
    },
  );
  await t.test('token removal refuses an existing encryption handle', async () => {
    const peer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ]);
    renameSync(tokens, tokens + '-removed');
    mkdirSync(tokens, { mode: 0o700 });
    await assert.rejects(
      provider.subtle.deriveBits(
        { name: 'ECDH', public: peer.publicKey },
        provider.resolve(a.encryption.privateKey, 'deriveBits'),
        256,
      ),
      /OPERATION_FAILED/,
    );
  });
  assert.equal(provider.capabilities.hardwareBacked, false);
  assert.equal(provider.capabilities.sagGraded, false);
});
