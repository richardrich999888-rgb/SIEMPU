// Executes real endpoint cryptography over the normal HTTPS authority path.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { ManagedOutbox } from '../../integrations/managed-endpoint/outbox.mjs';
import { hash } from '../../services/control/primitives.mjs';

const [directory, operation, argument] = process.argv.slice(2),
  dir = resolve(directory);
const read = (name) => JSON.parse(readFileSync(join(dir, name)));
const config = read('endpoint.json'),
  profile = read('state/profile.json'),
  peer = read('state/peer.json');
if (config.mode !== 'software-sdk') throw new Error('USE_NATIVE_MANAGED_DRIVER_FOR_TOKEN_PROFILE');
const client = new IntegrationEndpoint({
  url: config.url,
  tls: { ca: readFileSync(join(dir, 'keys/ca.crt')) },
  profile,
  authorityKey: read('state/authority-public.json'),
  sessionRenewal: true,
});
const sessionFile = join(dir, 'session-private.json');
if (existsSync(sessionFile)) Object.assign(client, read('session-private.json'));
const saveSession = () =>
  writeFileSync(sessionFile, JSON.stringify({ token: client.token, expiresAt: client.expiresAt }), {
    mode: 0o600,
  });
const q = () =>
  new ManagedOutbox({
    database: join(dir, 'state/outbox.sqlite'),
    key: readFileSync(join(dir, 'outbox-secret')),
    binding: { url: config.url, authorityKey: client.authorityKey, deviceId: profile.deviceId },
    maxEntries: 100,
    maxBytes: 4 * 1024 * 1024,
  });
let result;
const started = performance.now();
try {
  if (operation === 'probe') {
    result = await client.call('GET', '/health/ready');
  } else if (operation === 'init' || operation === 'login') {
    await client.authenticate();
    if (operation === 'init') {
      const grant = await client.call('POST', '/api/grants', {
        proof: await client.proof('grant'),
      });
      assert.equal(await client.crypto.verifyPacket(client.authorityKey, grant), true);
      const store = q();
      try {
        store.saveGrant(grant);
      } finally {
        store.close();
      }
    }
    result = { authenticated: true, deviceId: profile.deviceId };
  } else if (operation === 'queue' || operation === 'send') {
    const kind = argument === 'text' ? 'text' : 'file',
      size = kind === 'text' ? 64 : Number(argument ?? 4096);
    assert.ok(Number.isSafeInteger(size) && size >= 1 && size <= 262144);
    const bytes = Buffer.alloc(size, 83);
    const payload =
      kind === 'text'
        ? client.crypto.createTextPayload(bytes.toString())
        : client.crypto.createFilePayload('synthetic.bin', 'application/octet-stream', bytes);
    const store = q();
    try {
      const sealed = await client.sealUsingGrant(peer, payload, store.grant());
      const objectId = store.enqueue(sealed);
      if (operation === 'send') {
        await client.submit(sealed);
        store.update(objectId, 'SUBMITTED');
      }
      result = {
        objectId,
        sha256: hash(bytes),
        bytes: size,
        kind,
        queueDepth: store.list().length,
      };
    } finally {
      store.close();
    }
  } else if (operation === 'submit') {
    const store = q();
    try {
      const item = store.get(argument);
      assert.ok(item);
      const submitted = await client.submit(item.sealed);
      store.update(argument, 'SUBMITTED');
      result = { objectId: argument, accepted: true, receipt: submitted.receipt };
    } finally {
      store.close();
    }
  } else if (operation === 'list') {
    result = { objectIds: (await client.listObjects()).map((object) => object.id) };
  } else if (operation === 'prepare-claim') {
    const control = await client.signed('/api/control');
    const body = { expectedEpoch: control.payload.epoch };
    const proof = await client.proof('claim:' + argument, body);
    writeFileSync(
      join(dir, 'claim-private.json'),
      JSON.stringify({ objectId: argument, body, proof }),
      { mode: 0o600 },
    );
    result = { objectId: argument, prepared: true, epoch: body.expectedEpoch };
  } else if (operation === 'deny') {
    const prepared = read('claim-private.json');
    assert.equal(prepared.objectId, argument);
    const path = `/api/objects/${argument}/claim`;
    try {
      await client.call('POST', path, { ...prepared.body, proof: prepared.proof });
      throw new Error('UNAUTHORIZED_RELEASE');
    } catch (error) {
      if (![401, 403].includes(error.status)) throw error;
      result = {
        denied: true,
        status: error.status,
        code: error.code,
        path,
        boundary: 'claim endpoint refused a proof prepared before revocation',
      };
    }
  } else if (operation === 'receive') {
    const r = await client.receiveWithRelease(argument, peer.senderSigningPublicKey);
    const p = client.crypto.unpackPayload(r.plaintext),
      bytes = p.kind === 'text' ? Buffer.from(p.text) : Buffer.from(p.bytes);
    const ack = await client.acknowledge(argument, r.release);
    result = {
      objectId: argument,
      sha256: hash(bytes),
      bytes: bytes.length,
      release: r.release,
      ack,
    };
  } else if (operation === 'revoke-recipient') {
    const path = '/api/admin/devices/' + peer.deviceId + '/revoke';
    const before = Date.now();
    const receipt = await client.call('POST', path, {
      proof: await client.proof('admin:POST:' + path, {}),
    });
    result = { revoked: true, requestStartedAt: before, responseReceivedAt: Date.now(), receipt };
  } else if (operation === 'control') {
    await client.signed('/api/control');
    result = { authorized: true };
  } else if (operation === 'queue-status') {
    const store = q();
    try {
      result = { entries: store.list() };
    } finally {
      store.close();
    }
  } else throw new Error('UNKNOWN_ENDPOINT_OPERATION');
  saveSession();
  console.log(
    JSON.stringify({
      ok: true,
      operation,
      result,
      elapsedMs: performance.now() - started,
      resources: process.resourceUsage(),
      rss: process.memoryUsage().rss,
    }),
  );
} catch (error) {
  saveSession();
  console.log(
    JSON.stringify({
      ok: false,
      operation,
      status: error.status ?? null,
      code: /^[A-Z0-9_]{1,100}$/.test(error.code ?? '')
        ? error.code
        : error.message === 'UNAUTHORIZED_RELEASE'
          ? error.message
          : 'ENDPOINT_OPERATION_FAILED',
      elapsedMs: performance.now() - started,
    }),
  );
  process.exitCode = 1;
}
