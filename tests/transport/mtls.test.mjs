import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { createServer } from 'node:https';
import { secureFixture } from './fixture.mjs';
import { createObject, decryptObject } from '../helpers/client.mjs';
import {
  secureFetch,
  secureServerFactory,
  secureClientOptions,
} from '../../packages/transport/mtls.mjs';
import { createLabPki } from '../../deployment/secure/lab-pki.mjs';
import { listen, closeServer } from '../../deployment/secure/stack.mjs';

test('TLS web plus role-pinned mTLS services preserve encrypted exchange and current revocation', async (t) => {
  const f = await secureFixture(t);
  const { alice, bob, admin } = f.clients;
  for (const c of [alice, bob, admin]) await c.authenticate();
  assert.equal((await f.fetch(`${f.baseUrl}/health/ready`)).status, 200);
  const bytes = Buffer.from(Array.from({ length: 32768 }, (_, i) => i % 251));
  const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
    kind: 'file',
    data: bytes,
  });
  await alice.submit(object);
  await alice.prepare(object.envelope.objectId);
  const epoch = (await bob.ok('GET', '/api/control')).payload.epoch;
  const claim = await bob.claim(object.envelope.objectId, epoch);
  assert.equal(claim.status, 200);
  assert.deepEqual(decryptObject(claim.body, f.profiles.bob).bytes, bytes);
  const pending = createObject(f.profiles.alice, f.profiles.bob, await alice.grant());
  await alice.submit(pending);
  await alice.prepare(pending.envelope.objectId);
  assert.equal(
    (
      await admin.admin('PUT', '/api/admin/policies', {
        fromUnit: f.profiles.alice.unitId,
        toUnit: f.profiles.bob.unitId,
        missionId: 'DEMO-MISSION',
        allow: false,
      })
    ).status,
    200,
  );
  const denied = await bob.claim(pending.envelope.objectId, epoch);
  assert.equal(denied.status, 409);
  assert.equal(JSON.stringify(denied.body).includes('wrappedKey'), false);
  assert.equal(denied.body.receipt.payload.eventType, 'RELEASE_DENIED');
});

test('TLS trust, service role and server identity fail closed with no weaker transport', async (t) => {
  const f = await secureFixture(t);
  const { control, web, untrusted } = f.pki.identities;
  const noCert = secureFetch({ ca: f.pki.ca, serverPin: control.pin });
  await assert.rejects(noCert(`${f.controlUrl}/health`));
  const wrongRole = secureFetch({ ...untrusted, serverPin: control.pin });
  assert.equal((await wrongRole(`${f.controlUrl}/health`)).status, 403);
  const good = secureFetch({ ...web, serverPin: control.pin });
  assert.equal((await good(`${f.controlUrl}/health`)).status, 200);
  const other = createLabPki(join(f.dir, 'other-pki'));
  await assert.rejects(
    secureFetch({ ...other.identities.web, ca: f.pki.ca, serverPin: control.pin })(
      `${f.controlUrl}/health`,
    ),
  );
  await assert.rejects(secureFetch({ ca: other.ca, serverPin: web.pin })(`${f.baseUrl}/health`));
  await assert.rejects(
    secureFetch({ ca: f.pki.ca, serverPin: control.pin })(`${f.baseUrl}/health`),
    /SERVICE_IDENTITY_DENIED/,
  );
  await assert.rejects(good('http://127.0.0.1/health'), /HTTPS/);
  assert.throws(() => secureServerFactory({ ...web, allowedClientPins: [] }), /explicit peer/);
  assert.throws(
    () => secureClientOptions({ ca: f.pki.ca, serverPin: web.pin, key: web.key }),
    /complete/,
  );
  const opts = secureClientOptions({ ca: f.pki.ca, serverPin: web.pin });
  assert.ok(
    opts.checkServerIdentity('incorrect.invalid', {
      subjectaltname: 'DNS:localhost',
      fingerprint256: web.pin,
    }),
  );
});

test('HTTPS client bounds response bytes, redirects and request duration', async (t) => {
  const f = await secureFixture(t);
  const web = f.pki.identities.web;
  const server = createServer({ key: web.key, cert: web.cert }, (req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: f.baseUrl });
      res.end();
    } else if (req.url === '/slow') setTimeout(() => res.end('late'), 100);
    else res.end('A'.repeat(512));
  });
  const url = await listen(server);
  t.after(() => closeServer(server));
  const bounded = secureFetch(
    { ca: f.pki.ca, serverPin: web.pin },
    { maxResponseBytes: 64, timeoutMs: 30 },
  );
  await assert.rejects(bounded(url + '/large'), /limit/);
  await assert.rejects(bounded(url + '/redirect'), /redirect/);
  await assert.rejects(bounded(url + '/slow'), /timed out/);
  await assert.rejects(bounded(url, { body: { unsupported: true } }), /bounded byte/);
});
