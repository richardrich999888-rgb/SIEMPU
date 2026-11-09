import test from 'node:test';
import assert from 'node:assert/strict';
import fs, {
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  rmSync,
  cpSync,
  existsSync,
  mkdirSync,
  symlinkSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  generateKeyPairSync,
} from 'node:crypto';
import { initDemo } from '../scripts/bootstrap.mjs';
import { backup, restore } from '../scripts/backup.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { Authority } from '../services/control/core.mjs';
import { packet, hash, canonical, publicJwk } from '../services/control/primitives.mjs';
import { verifyEvidence } from '../apps/verifier/verify.mjs';
import { spawnSync } from 'node:child_process';

// Every checked-in migration must be applied; derive the count instead of pinning it.
const MIGRATION_COUNT = readdirSync(new URL('../database/migrations/', import.meta.url)).filter(
  (name) => name.endsWith('.sql'),
).length;
test('full evidence verifier preserves optional-anchor forms and published error order', async () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
    format: 'jwk',
  });
  const record = packet(key, {
    sequence: 1,
    previousHash: '0'.repeat(64),
    eventId: 'synthetic',
    eventType: 'TEST',
    timestamp: 1,
    epoch: 1,
  });
  const input = {
    records: [record],
    checkpoint: packet(key, { sequence: 1, headHash: hash(canonical(record)), issuedAt: 1 }),
  };
  for (const checkpoint of [undefined, null, false, 0, '']) {
    const result = await verifyEvidence(input, publicJwk(key), { checkpoint });
    assert.equal(result.valid, true);
    assert.equal(result.externalCheckpointVerified, false);
  }
  const invalidRecord = structuredClone(input);
  invalidRecord.records[0].signature = 'bad';
  await assert.rejects(
    verifyEvidence(invalidRecord, publicJwk(key), { checkpoint: {} }),
    /Invalid P1363 signature/,
  );
  const invalidHead = {
    ...input,
    checkpoint: packet(key, { sequence: 1, headHash: 'b'.repeat(64), issuedAt: 1 }),
  };
  await assert.rejects(
    verifyEvidence(invalidHead, publicJwk(key), { checkpoint: {} }),
    /Export checkpoint does not match chain head/,
  );
});
// Test-only construction of correctly authenticated but inconsistent archives.
function rewriteSyntheticArchive(source, destination, pass, signingKey, mutate) {
  const outer = JSON.parse(readFileSync(source));
  const key = scryptSync(pass, Buffer.from(outer.salt, 'base64'), 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  const decrypt = createDecipheriv('aes-256-gcm', key, Buffer.from(outer.iv, 'base64'));
  decrypt.setAAD(Buffer.from(outer.format));
  decrypt.setAuthTag(Buffer.from(outer.tag, 'base64'));
  const content = JSON.parse(
    Buffer.concat([decrypt.update(Buffer.from(outer.ciphertext, 'base64')), decrypt.final()]),
  );
  mutate(content);
  content.manifest = packet(signingKey, content.manifest.payload);
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(outer.format));
  const ciphertext = Buffer.concat([cipher.update(canonical(content)), cipher.final()]);
  writeFileSync(
    destination,
    JSON.stringify({
      ...outer,
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    }),
    { mode: 0o600, flag: 'wx' },
  );
}
test('encrypted backup restores schema, identity, revocation and evidence; tamper/old checkpoints fail', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-recovery-'));
  try {
    const dir = join(temp, 'source');
    const profile = await initDemo(dir);
    const relay = createRelayServer({
      database: join(dir, 'relay', 'relay.sqlite'),
      secret: Buffer.from(readFileSync(join(dir, 'relay.secret'), 'utf8'), 'hex'),
    });
    relay.close();
    const a = new Authority({
      dbPath: join(dir, 'control.sqlite'),
      signingKey: JSON.parse(readFileSync(join(dir, 'server-key.json'))),
      masterKey: readFileSync(join(dir, 'master.key')),
    });
    a.tx(() => {
      a.run(
        "UPDATE devices SET status='revoked' WHERE id=?",
        profile.profiles.find((p) => p.username === 'eve').deviceId,
      );
      a.run('UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1');
      a.event('RECOVERY_TEST', 'system');
    });
    const checkpoint = a.checkpoint();
    a.close();
    const archive = join(temp, 'backup.enc');
    const pass = 'Synthetic backup testing passphrase';
    backup(dir, archive, pass);
    const checkpointFile = join(temp, 'checkpoint.json');
    writeFileSync(checkpointFile, JSON.stringify(checkpoint));
    const cli = (destination, anchor) =>
      spawnSync(
        process.execPath,
        [
          'scripts/backup.mjs',
          'restore',
          archive,
          destination,
          join(dir, 'public-key.json'),
          ...(anchor === undefined ? [] : [anchor]),
        ],
        { encoding: 'utf8', env: { PATH: process.env.PATH, SIEPMU_BACKUP_PASSPHRASE: pass } },
      );
    assert.notEqual(cli(join(temp, 'missing-anchor')).status, 0);
    const cliResult = cli(join(temp, 'cli-restored'), checkpointFile);
    assert.equal(cliResult.status, 0, cliResult.stderr);
    assert.equal(JSON.parse(cliResult.stdout).anchor, 'INDEPENDENT_CHECKPOINT_VERIFIED');
    writeFileSync(checkpointFile, 'null');
    assert.notEqual(cli(join(temp, 'null-anchor'), checkpointFile).status, 0);
    const destination = join(temp, 'restored');
    restore(archive, destination, pass, profile.serverPublicKey, { checkpoint });
    const db = new DatabaseSync(join(destination, 'control.sqlite'));
    assert.equal(db.prepare('SELECT epoch FROM authority').get().epoch, 2);
    assert.equal(
      db
        .prepare('SELECT status FROM devices WHERE id=?')
        .get(profile.profiles.find((p) => p.username === 'eve').deviceId).status,
      'revoked',
    );
    assert.equal(db.prepare('SELECT count(*) n FROM schema_migrations').get().n, MIGRATION_COUNT);
    assert.equal(
      db.prepare('SELECT hash FROM evidence ORDER BY sequence DESC LIMIT 1').get().hash,
      checkpoint.payload.headHash,
    );
    db.close();
    assert.throws(() =>
      restore(archive, join(temp, 'wrong'), pass + 'wrong', profile.serverPublicKey, {
        checkpoint,
      }),
    );
    const key = JSON.parse(readFileSync(join(dir, 'server-key.json')));
    const future = packet(key, {
      sequence: checkpoint.payload.sequence + 1,
      headHash: 'a'.repeat(64),
      issuedAt: Date.now(),
    });
    writeFileSync(checkpointFile, JSON.stringify(future));
    assert.notEqual(cli(join(temp, 'cli-stale'), checkpointFile).status, 0);
    for (const invalid of [
      { sequence: -1, headHash: 'a'.repeat(64), issuedAt: Date.now() },
      { sequence: '1', headHash: 'a'.repeat(64), issuedAt: Date.now() },
    ]) {
      assert.throws(
        () =>
          restore(archive, join(temp, 'invalid-anchor'), pass, profile.serverPublicKey, {
            checkpoint: packet(key, invalid),
          }),
        /predates/,
      );
    }
    assert.throws(
      () =>
        restore(archive, join(temp, 'old'), pass, profile.serverPublicKey, { checkpoint: future }),
      /predates/,
    );
    const changed = JSON.parse(readFileSync(archive));
    changed.tag = Buffer.alloc(16).toString('base64');
    writeFileSync(join(temp, 'changed.enc'), JSON.stringify(changed));
    assert.throws(() =>
      restore(join(temp, 'changed.enc'), join(temp, 'tampered'), pass, profile.serverPublicKey, {
        checkpoint,
      }),
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
test('restore proves retained ancestry, rejects signed divergent/corrupt histories and publishes only complete state', async (t) => {
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-restore-anchors-'));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const dir = join(temp, 'source'),
    fork = join(temp, 'fork');
  const profile = await initDemo(dir);
  createRelayServer({
    database: join(dir, 'relay', 'relay.sqlite'),
    secret: Buffer.from(readFileSync(join(dir, 'relay.secret'), 'utf8'), 'hex'),
  }).close();
  cpSync(dir, fork, { recursive: true });
  const signingKey = JSON.parse(readFileSync(join(dir, 'server-key.json')));
  const open = (directory) =>
    new Authority({
      dbPath: join(directory, 'control.sqlite'),
      signingKey,
      masterKey: readFileSync(join(directory, 'master.key')),
    });
  const a = open(dir);
  a.tx(() => a.event('RETAINED_HISTORY', 'system'));
  const checkpoint = a.checkpoint();
  a.tx(() => a.event('LEGITIMATE_EXTENSION', 'system'));
  a.close();
  const b = open(fork);
  b.tx(() => b.event('DIVERGENT_HISTORY', 'system'));
  b.tx(() => b.event('LATER_FORK_EVENT', 'system'));
  b.close();
  const pass = 'Synthetic recovery test passphrase';
  const good = join(temp, 'good.enc'),
    bad = join(temp, 'fork.enc');
  backup(dir, good, pass);
  backup(fork, bad, pass);
  const noStaging = () =>
    assert.deepEqual(
      readdirSync(temp).filter((s) => s.startsWith('.siepmu-restore-')),
      [],
    );
  const rejected = (archive, suffix, anchor = checkpoint, pattern) => {
    const dest = join(temp, suffix);
    assert.throws(
      () => restore(archive, dest, pass, profile.serverPublicKey, { checkpoint: anchor }),
      pattern,
    );
    assert.equal(existsSync(dest), false, 'failure must not publish destination');
    noStaging();
  };
  for (const options of [undefined, {}, { checkpoint: undefined }, { checkpoint: null }]) {
    const dest = join(temp, 'unanchored');
    assert.throws(
      () => restore(good, dest, pass, profile.serverPublicKey, options),
      /checkpoint required/,
    );
    assert.equal(existsSync(dest), false);
  }
  rejected(bad, 'fork-rejected', checkpoint, /conflicts with externally saved checkpoint/);
  // Legitimate ancestors and a retained genesis anchor remain valid.
  for (const [name, anchor] of [
    ['ancestor', checkpoint],
    [
      'genesis',
      packet(signingKey, { sequence: 0, headHash: '0'.repeat(64), issuedAt: Date.now() }),
    ],
  ]) {
    const dest = join(temp, name);
    mkdirSync(dest, { mode: 0o700 });
    restore(good, dest, pass, profile.serverPublicKey, { checkpoint: anchor });
    const restored = open(dest);
    assert.equal(
      restored.get('SELECT hash FROM evidence WHERE sequence=?', checkpoint.payload.sequence).hash,
      checkpoint.payload.headHash,
    );
    restored.close();
  }
  rejected(
    good,
    'invalid-genesis',
    packet(signingKey, { sequence: 0, headHash: 'a'.repeat(64), issuedAt: Date.now() }),
  );
  for (const [name, mutate] of [
    [
      'signature',
      (db) => {
        const row = db.prepare('SELECT record FROM evidence WHERE sequence=1').get();
        const record = JSON.parse(row.record);
        record.payload.eventType = 'ALTERED';
        db.prepare('UPDATE evidence SET record=?,hash=? WHERE sequence=1').run(
          canonical(record),
          hash(canonical(record)),
        );
      },
    ],
    [
      'stored-hash',
      (db) => db.prepare('UPDATE evidence SET hash=? WHERE sequence=1').run('f'.repeat(64)),
    ],
    ['gap', (db) => db.exec('DELETE FROM evidence WHERE sequence=1')],
  ]) {
    const corrupted = join(temp, 'corrupt-' + name);
    cpSync(dir, corrupted, { recursive: true });
    const db = new DatabaseSync(join(corrupted, 'control.sqlite'));
    mutate(db);
    db.close();
    const archive = join(temp, name + '.enc');
    backup(corrupted, archive, pass);
    rejected(archive, 'rejected-' + name);
  }
  for (const [name, mutate, pattern] of [
    [
      'false-head',
      (c) => {
        c.manifest.payload.checkpoint.headHash = 'b'.repeat(64);
      },
      /manifest checkpoint does not match/,
    ],
    [
      'file-name-collision',
      (c) => {
        const name = Object.keys(c.files).sort().join();
        c.files = { [name]: Buffer.from('synthetic').toString('base64') };
        c.manifest.payload.files = { [name]: hash(Buffer.from('synthetic')) };
      },
      /file manifest/,
    ],
    [
      'extra-digest',
      (c) => {
        c.manifest.payload.files.extra = 'a'.repeat(64);
      },
      /file manifest/,
    ],
    [
      'base64',
      (c) => {
        c.files['master.key'] += '\n';
      },
      /file encoding/,
    ],
    [
      'key-substitution',
      (c) => {
        const bytes = Buffer.from(JSON.stringify(profile.profiles[0].keys.signing.publicKey));
        c.files['public-key.json'] = bytes.toString('base64');
        c.manifest.payload.files['public-key.json'] = hash(bytes);
      },
      /authority key mismatch/,
    ],
    [
      'head-type',
      (c) => {
        c.manifest.payload.checkpoint.sequence = '3';
      },
      /manifest schema/,
    ],
  ]) {
    const archive = join(temp, name + '.enc');
    rewriteSyntheticArchive(good, archive, pass, signingKey, mutate);
    rejected(archive, 'rejected-' + name, checkpoint, pattern);
  }
  const outer = JSON.parse(readFileSync(good));
  outer.salt += '\n';
  const malformed = join(temp, 'outer.enc');
  writeFileSync(malformed, JSON.stringify(outer));
  rejected(malformed, 'rejected-outer', checkpoint, /Backup encoding/);
  const occupied = join(temp, 'occupied');
  mkdirSync(occupied);
  writeFileSync(join(occupied, 'preserve'), 'unrelated');
  assert.throws(
    () => restore(good, occupied, pass, profile.serverPublicKey, { checkpoint }),
    /empty real directory/,
  );
  assert.equal(readFileSync(join(occupied, 'preserve'), 'utf8'), 'unrelated');
  const link = join(temp, 'link');
  const empty = join(temp, 'empty');
  mkdirSync(empty);
  symlinkSync(empty, link);
  assert.throws(
    () => restore(good, link, pass, profile.serverPublicKey, { checkpoint }),
    /empty real directory/,
  );
  assert.deepEqual(readdirSync(empty), []);
  // Inject a local storage failure after one successful staged write. This is not a
  // power-loss simulation and does not assert persistence guarantees from the filesystem.
  const realWrite = fs.writeFileSync;
  let writes = 0;
  const mocked = t.mock.method(fs, 'writeFileSync', (...args) => {
    if (String(args[0]).includes('/.siepmu-restore-') && ++writes === 2)
      throw Object.assign(new Error('Synthetic disk write failure'), { code: 'EIO' });
    return realWrite(...args);
  });
  syncBuiltinESMExports();
  try {
    rejected(good, 'write-failed', checkpoint, /Synthetic disk write failure/);
  } finally {
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
  const recovered = join(temp, 'write-failed');
  restore(good, recovered, pass, profile.serverPublicKey, { checkpoint });
  assert.ok(existsSync(join(recovered, 'control.sqlite')));
  noStaging();
});
test('versioned migrations upgrade v1 and reject a modified applied migration', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-migrate-'));
  try {
    await initDemo(temp);
    const key = JSON.parse(readFileSync(join(temp, 'server-key.json'))),
      masterKey = readFileSync(join(temp, 'master.key'));
    const db = new DatabaseSync(join(temp, 'control.sqlite'));
    db.exec(
      "DROP TABLE counters; DROP INDEX evidence_sequence; DELETE FROM schema_migrations WHERE version='002-observability.sql'",
    );
    db.close();
    const a = new Authority({ dbPath: join(temp, 'control.sqlite'), signingKey: key, masterKey });
    assert.equal(a.get('SELECT count(*) n FROM schema_migrations').n, MIGRATION_COUNT);
    a.run("UPDATE schema_migrations SET checksum='bad' WHERE version='001-initial.sql'");
    a.close();
    assert.throws(
      () => new Authority({ dbPath: join(temp, 'control.sqlite'), signingKey: key, masterKey }),
      /checksum/,
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
