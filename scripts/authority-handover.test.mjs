import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync, symlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { coreFixture } from '../tests/helpers/fixture.mjs';
import { pair } from '../tests/helpers/client.mjs';
import { packet, verifyPacket } from '../services/control/primitives.mjs';
import {
  CheckpointCustodian,
  authoritySnapshot,
  authorizationDigest,
} from '../services/evidence/custody.mjs';
import { handoverFromFiles } from './authority-handover.mjs';

async function inputs(t) {
  const f = await coreFixture(t),
    key = pair(),
    writer = pair();
  const database = join(f.dir, 'handover.sqlite');
  const custody = new CheckpointCustodian({
    database,
    authorityKey: f.provisioned.serverPublicKey,
    signingKey: key.privateKey,
    allowBootstrap: true,
  });
  await custody.accept(
    packet(f.authority.key, {
      version: 1,
      nonce: crypto.randomUUID(),
      issuedAt: Date.now(),
      stateDigest: authorizationDigest(f.authority),
      evidence: authoritySnapshot(f.authority),
    }),
  );
  const checkpoint = f.authority.checkpoint().payload,
    epoch = f.authority.epoch();
  const request = {
    writerKey: writer.publicKey,
    expectedGeneration: 0,
    expectedAnchor: {
      sequence: checkpoint.sequence,
      headHash: checkpoint.headHash,
      stateDigest: authorizationDigest(f.authority),
    },
    authority: { epoch: epoch.epoch, revocationVersion: epoch.revocation_version },
  };
  custody.close();
  chmodSync(database, 0o600);
  const paths = ['authority.json', 'custodian.json', 'request.json'].map((name) =>
    join(f.dir, name),
  );
  [f.provisioned.serverPublicKey, key.privateKey, request].forEach((value, i) =>
    writeFileSync(paths[i], JSON.stringify(value), { mode: 0o600, flag: 'wx' }),
  );
  return { ...f, args: [database, ...paths], key };
}

test('local handover emits a signed receipt and rejects a stale repeat without changing generation', async (t) => {
  const f = await inputs(t);
  const receipt = handoverFromFiles(f.args);
  assert.ok(verifyPacket(f.key.publicKey, receipt));
  assert.equal(receipt.payload.generation, 1);
  assert.throws(() => handoverFromFiles(f.args), /GENERATION_CHANGED/);
});

test('handover input reader rejects symlinks, exposed keys, non-files, malformed and oversized input', async (t) => {
  const f = await inputs(t),
    linked = join(f.dir, 'linked.json');
  symlinkSync(f.args[2], linked);
  assert.throws(() => handoverFromFiles([f.args[0], f.args[1], linked, f.args[3]]));
  chmodSync(f.args[2], 0o644);
  assert.throws(() => handoverFromFiles(f.args), /HANDOVER_FILE_INVALID/);
  chmodSync(f.args[2], 0o600);
  assert.throws(
    () => handoverFromFiles([f.args[0], f.args[1], f.dir, f.args[3]]),
    /HANDOVER_FILE_INVALID/,
  );
  writeFileSync(f.args[3], '{broken');
  assert.throws(() => handoverFromFiles(f.args), SyntaxError);
  writeFileSync(f.args[3], ' '.repeat(16385));
  assert.throws(() => handoverFromFiles(f.args), /HANDOVER_FILE_INVALID/);
});

test('handover cannot bootstrap a missing database or follow a database symlink', async (t) => {
  const f = await inputs(t),
    missing = join(f.dir, 'missing.sqlite'),
    linked = join(f.dir, 'linked.sqlite');
  assert.throws(() => handoverFromFiles([missing, ...f.args.slice(1)]));
  assert.equal(existsSync(missing), false);
  symlinkSync(f.args[0], linked);
  assert.throws(
    () => handoverFromFiles([linked, ...f.args.slice(1)]),
    /HANDOVER_DATABASE_REQUIRED/,
  );
});
