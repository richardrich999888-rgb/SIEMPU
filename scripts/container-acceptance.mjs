/** Exercise the actual built container using disposable synthetic provisioning. */
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { ApiClient, httpTransport, createObject, decryptObject } from '../tests/helpers/client.mjs';
const url = new URL(process.env.SIEPMU_URL ?? 'http://127.0.0.1:8080');
assert.ok(
  ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname),
  'Container acceptance is local synthetic only',
);
const file = process.env.SIEPMU_CONTAINER_PROFILES;
if (!file) throw new Error('Supply disposable container profiles file');
const fixture = JSON.parse(await readFile(file, 'utf8'));
assert.equal(fixture.synthetic, true);
const profiles = Object.fromEntries(fixture.profiles.map((p) => [p.username, p]));
const transport = httpTransport(url.origin);
const alice = new ApiClient(transport, profiles.alice),
  bob = new ApiClient(transport, profiles.bob),
  admin = new ApiClient(transport, profiles.admin);
for (const c of [alice, bob, admin]) await c.authenticate();
const object = createObject(profiles.alice, profiles.bob, await alice.grant(), {
  kind: 'file',
  name: 'container-proof.txt',
  data: 'Synthetic container deployment evidence',
});
await alice.submit(object);
assert.equal((await alice.prepare(object.envelope.objectId)).body.object.state, 'READY');
const epoch = (await bob.ok('GET', '/api/control')).payload.epoch;
const released = await bob.claim(object.envelope.objectId, epoch);
assert.equal(released.status, 200);
assert.equal(
  decryptObject(released.body, profiles.bob).bytes.toString(),
  'Synthetic container deployment evidence',
);
await admin.admin('PUT', '/api/admin/policies', {
  fromUnit: fixture.units.A,
  toUnit: fixture.units.B,
  missionId: 'DEMO-MISSION',
  allow: false,
});
const denied = await bob.claim(object.envelope.objectId, epoch);
assert.equal(denied.status, 409);
assert.ok(!JSON.stringify(denied.body).includes('wrappedKey'));
const exported = await admin.ok('GET', '/api/evidence/export');
const { verifyEvidence } = await import('../apps/verifier/verify.mjs');
assert.equal((await verifyEvidence(exported, fixture.serverPublicKey)).valid, true);
console.log(
  JSON.stringify({
    status: 'PASS',
    scope:
      'Actual built container: MFA/device binding, encrypted file exchange, policy revocation, no key redisclosure, detached chain verification',
  }),
);
