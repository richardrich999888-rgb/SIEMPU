import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { initDemo } from '../scripts/bootstrap.mjs';
import { backup, restore } from '../scripts/backup.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { Authority } from '../services/control/core.mjs';
import { packet } from '../services/control/primitives.mjs';
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
    assert.equal(db.prepare('SELECT count(*) n FROM schema_migrations').get().n, 2);
    assert.equal(
      db.prepare('SELECT hash FROM evidence ORDER BY sequence DESC LIMIT 1').get().hash,
      checkpoint.payload.headHash,
    );
    db.close();
    assert.throws(() =>
      restore(archive, join(temp, 'wrong'), pass + 'wrong', profile.serverPublicKey),
    );
    const key = JSON.parse(readFileSync(join(dir, 'server-key.json')));
    const future = packet(key, {
      sequence: checkpoint.payload.sequence + 1,
      headHash: 'a'.repeat(64),
      issuedAt: Date.now(),
    });
    assert.throws(
      () =>
        restore(archive, join(temp, 'old'), pass, profile.serverPublicKey, { checkpoint: future }),
      /predates/,
    );
    const changed = JSON.parse(readFileSync(archive));
    changed.tag = Buffer.alloc(16).toString('base64');
    writeFileSync(join(temp, 'changed.enc'), JSON.stringify(changed));
    assert.throws(() =>
      restore(join(temp, 'changed.enc'), join(temp, 'tampered'), pass, profile.serverPublicKey),
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
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
    assert.equal(a.get('SELECT count(*) n FROM schema_migrations').n, 2);
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
