import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { httpFixture, root } from '../../helpers/fixture.mjs';
import { createObject, decryptObject, hash, unb64 } from '../../helpers/client.mjs';

const execute = promisify(execFile);

test(
  'vertical slice: Unit A encrypts, real relay stores ciphertext only, Unit B decrypts and acknowledges, detached verifier accepts',
  { timeout: 45000 },
  async (t) => {
    const f = await httpFixture(t);
    const { alice, bob, admin } = f.clients;
    for (const client of [alice, bob, admin]) await client.authenticate();
    const plaintext = 'SYNTHETIC ACCEPTANCE: Unit A to Unit B logistics file';
    const object = createObject(f.profiles.alice, f.profiles.bob, await alice.grant(), {
      kind: 'file',
      name: 'synthetic-logistics.txt',
      data: plaintext,
    });
    const id = object.envelope.objectId;
    const expectedDigest = hash(unb64(object.ciphertext));
    assert.equal((await alice.submit(object)).object.state, 'PENDING');
    const prepared = await alice.prepare(id);
    assert.equal(prepared.status, 200);
    assert.equal(prepared.body.object.state, 'READY');
    assert.ok(!JSON.stringify(prepared.body).includes('wrappedKey'));
    const current = await bob.ok('GET', '/api/control');
    const epoch = current.payload.epoch;
    const claimed = await bob.claim(id, epoch);
    assert.equal(claimed.status, 200, JSON.stringify(claimed.body));
    const decrypted = decryptObject(claimed.body, f.profiles.bob);
    assert.equal(decrypted.bytes.toString(), plaintext);
    assert.equal(decrypted.name, 'synthetic-logistics.txt');
    const receiptId = claimed.body.receipt.payload.eventId;
    const acknowledged = await bob.request('POST', `/api/objects/${id}/ack`, {
      receiptId,
      proof: await bob.proof('ack:' + id, { receiptId }),
    });
    assert.equal(acknowledged.status, 200, JSON.stringify(acknowledged.body));
    assert.equal(acknowledged.body.object.state, 'DELIVERED');
    assert.equal(acknowledged.body.receipt.payload.details.issuanceEventId, receiptId);
    const evidence = await admin.ok('GET', '/api/evidence/export');
    assert.equal(
      evidence.records.filter(
        (r) => r.payload.objectId === id && r.payload.eventType === 'RELEASE_ISSUED',
      ).length,
      1,
    );

    // Inspect the real relay process's disk database, never the core fixture's Map.
    const relayPath = join(f.dir, 'relay', 'relay.sqlite');
    const db = new DatabaseSync(relayPath, { readOnly: true });
    try {
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all()
        .map((r) => r.name);
      assert.deepEqual(tables, ['blobs', 'workload_nonces']);
      assert.deepEqual(
        db
          .prepare('PRAGMA table_info(blobs)')
          .all()
          .map((r) => r.name),
        ['hash', 'ciphertext', 'size', 'created_at'],
      );
      const rows = db.prepare('SELECT * FROM blobs').all();
      assert.equal(rows.length, 1);
      const stored = Buffer.from(rows[0].ciphertext);
      assert.deepEqual(stored, unb64(object.ciphertext));
      assert.equal(rows[0].hash, expectedDigest);
      assert.equal(rows[0].size, stored.length);
      for (const forbidden of [
        plaintext,
        Buffer.from(plaintext).toString('base64url'),
        'wrappedKey',
        object.envelope.wrappedKey.ciphertext,
      ]) {
        assert.equal(stored.includes(Buffer.from(forbidden)), false);
      }
      assert.deepEqual(
        db
          .prepare('PRAGMA table_info(workload_nonces)')
          .all()
          .map((r) => r.name),
        ['nonce', 'expires_at'],
      );
    } finally {
      db.close();
    }

    // Detached verification continues after all three HTTP services have stopped.
    await f.stop();
    const disk = await readFile(relayPath);
    for (const forbidden of [plaintext, 'wrappedKey', object.envelope.wrappedKey.ciphertext]) {
      assert.equal(disk.includes(Buffer.from(forbidden)), false);
    }
    const receiptPath = join(f.dir, 'receipt.json');
    const exportPath = join(f.dir, 'export.json');
    const checkpointPath = join(f.dir, 'saved-checkpoint.json');
    await Promise.all([
      writeFile(receiptPath, JSON.stringify(claimed.body.receipt)),
      writeFile(exportPath, JSON.stringify(evidence)),
      writeFile(checkpointPath, JSON.stringify(evidence.checkpoint)),
    ]);
    const verifier = join(root, 'tools', 'verify');
    const accepted = JSON.parse(
      (
        await execute(verifier, [
          receiptPath,
          join(f.dir, 'public-key.json'),
          '--mode',
          'release',
          '--object-digest',
          expectedDigest,
          '--epoch',
          String(epoch),
          '--object-id',
          id,
          '--replay-store',
          join(f.dir, 'receipt-replays.sqlite'),
        ])
      ).stdout,
    );
    assert.equal(accepted.strictReleaseVerified, true);
    assert.equal(accepted.replayRecorded, true);
    assert.equal(accepted.receiptId, receiptId);
    const chain = JSON.parse(
      (
        await execute(verifier, [
          exportPath,
          join(f.dir, 'public-key.json'),
          '--checkpoint',
          checkpointPath,
        ])
      ).stdout,
    );
    assert.equal(chain.externalCheckpointVerified, true);
    t.diagnostic(
      'Synthetic loopback HTTP; acknowledgement proves a client action, not human reading. Relay schema permits ciphertext and operational metadata only.',
    );
  },
);
