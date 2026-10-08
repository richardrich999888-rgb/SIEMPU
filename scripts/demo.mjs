// Isolated synthetic acceptance demonstration through the real HTTP services.
import assert from 'node:assert/strict';
import { rm, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { httpFixture } from '../tests/helpers/fixture.mjs';
import { createObject, decryptObject, enrollUser } from '../tests/helpers/client.mjs';
import { verifyReleaseReceipt } from '../apps/verifier/verify.mjs';

const results = [];
const record = (step, outcome, evidence = {}) => {
  results.push({ step, outcome, ...evidence });
  console.log(`${outcome}: ${step}`);
};
const f = await httpFixture();
try {
  const { alice, bob, eve, admin } = f.clients;
  for (const client of [alice, bob, eve, admin]) await client.authenticate();
  record('Password, TOTP and software-device proof for four synthetic users', 'PASS');
  const colleague = await enrollUser(admin, {
    username: 'bob-backup',
    unitId: f.provisioned.units.B,
  });
  record('Administrative enrollment and approval of second Unit B recipient', 'PASS');
  const grant = await alice.grant();
  const normal = createObject(f.profiles.alice, f.profiles.bob, grant, {
    data: 'SYNTHETIC successful first exchange',
  });
  await alice.submit(normal);
  await alice.prepare(normal.envelope.objectId);
  let control = await alice.ok('GET', '/api/control');
  const unauthorized = await eve.claim(normal.envelope.objectId, control.payload.epoch);
  assert.ok([403, 404].includes(unauthorized.status));
  record('Unrelated Unit C user cannot claim Unit B content', 'PASS', {
    status: unauthorized.status,
  });
  const delivered = await bob.claim(normal.envelope.objectId, control.payload.epoch);
  assert.equal(delivered.status, 200);
  assert.equal(
    decryptObject(delivered.body, f.profiles.bob).bytes.toString(),
    'SYNTHETIC successful first exchange',
  );
  record('Endpoint encrypt → blind relay → endpoint decrypt', 'PASS');

  // No calls to either service occur while constructing these local ciphertext objects.
  const pendingRevoked = createObject(f.profiles.alice, f.profiles.bob, grant, {
    data: 'SYNTHETIC offline queue: must hold',
  });
  const pendingEligible = createObject(f.profiles.alice, colleague.profile, grant, {
    data: 'SYNTHETIC offline queue: may release',
  });
  record('Two queued objects created without contacting the services', 'PASS', {
    limitation:
      'Logical network absence during local creation; not a radio outage or OS firewall test.',
  });
  const changed = await admin.admin('PATCH', `/api/admin/users/${f.profiles.bob.userId}`, {
    active: false,
  });
  assert.equal(changed.status, 200);
  record('Recipient authority revoked while sender queue is disconnected', 'PASS');
  await alice.submit(pendingRevoked);
  await alice.submit(pendingEligible);
  const held = await alice.prepare(pendingRevoked.envelope.objectId);
  assert.equal(held.body.object.state, 'HELD');
  const allowed = await alice.prepare(pendingEligible.envelope.objectId);
  assert.equal(allowed.body.object.state, 'READY');
  control = await alice.ok('GET', '/api/control');
  const selectiveEpoch = control.payload.epoch;
  const selective = await colleague.client.claim(
    pendingEligible.envelope.objectId,
    control.payload.epoch,
  );
  assert.equal(selective.status, 200);
  assert.equal(
    decryptObject(selective.body, colleague.profile).bytes.toString(),
    'SYNTHETIC offline queue: may release',
  );
  record(
    'Reconnection selectively holds revoked recipient and releases eligible recipient',
    'PASS',
    {
      heldObject: pendingRevoked.envelope.objectId,
      releasedObject: pendingEligible.envelope.objectId,
    },
  );

  const racing = createObject(f.profiles.alice, colleague.profile, await alice.grant(), {
    data: 'SYNTHETIC race target',
  });
  await alice.submit(racing);
  await alice.prepare(racing.envelope.objectId);
  control = await alice.ok('GET', '/api/control');
  await admin.admin('PUT', '/api/admin/policies', {
    fromUnit: f.provisioned.units.A,
    toUnit: f.provisioned.units.B,
    missionId: 'DEMO-MISSION',
    allow: false,
  });
  const stale = await colleague.client.claim(racing.envelope.objectId, control.payload.epoch);
  assert.equal(stale.status, 409);
  record('Policy changes between READY and final claim; stale epoch is fenced', 'PASS', {
    staleEpoch: control.payload.epoch,
    status: stale.status,
  });
  const receipt = selective.body.receipt;
  const destination = resolve(process.env.SIEPMU_EVIDENCE_DIR || 'artifacts/demo');
  await mkdir(destination, { recursive: true });
  const verified = await verifyReleaseReceipt(receipt, f.provisioned.serverPublicKey, {
    objectDigest: pendingEligible.envelope.ciphertextHash,
    objectId: pendingEligible.envelope.objectId,
    epoch: selectiveEpoch,
    replayStore: resolve(destination, 'verified-receipts.sqlite'),
  });
  assert.equal(verified.strictReleaseVerified, true);
  record('Independent strict receipt verification with durable replay rejection', 'PASS');

  const evidence = await admin.ok('GET', '/api/evidence/export');
  await writeFile(resolve(destination, 'receipt.json'), JSON.stringify(receipt, null, 2));
  await writeFile(
    resolve(destination, 'public-key.json'),
    JSON.stringify(f.provisioned.serverPublicKey, null, 2),
  );
  await writeFile(resolve(destination, 'evidence.json'), JSON.stringify(evidence, null, 2));
  await writeFile(
    resolve(destination, 'checkpoint.json'),
    JSON.stringify(evidence.checkpoint, null, 2),
  );
  await writeFile(
    resolve(destination, 'results.json'),
    JSON.stringify(
      {
        synthetic: true,
        timestamp: new Date().toISOString(),
        results,
        limitations: [
          'Local HTTP over loopback; TLS belongs to configured network deployment.',
          'No SAG grading, hardware attestation, IAF approval, or patent conclusion.',
          'Commit is issuance boundary; later revocation cannot recall an already released key.',
        ],
      },
      null,
      2,
    ),
  );
  console.log('Synthetic evidence written to ' + destination);
} finally {
  await f.stop();
  await rm(f.dir, { recursive: true, force: true });
}
