import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, chmodSync, symlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { ManagedOutbox } from '../integrations/managed-endpoint/outbox.mjs';
import { openPrivateDatabase } from '../packages/storage/private-sqlite.mjs';

function setup(t, overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-outbox-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = {
    database: join(dir, 'queue.sqlite'),
    key: randomBytes(32),
    binding: { user: 'synthetic' },
    ...overrides,
  };
  return { dir, config };
}
const object = () => ({
  envelope: { objectId: randomUUID(), expiresAt: Date.now() + 60000 },
  ciphertext: 'SYNTHETIC_STORAGE_CANARY',
});

test('encrypted outbox survives restart without leaking payload or cached grant and preserves held state', (t) => {
  const { config } = setup(t),
    sealed = object();
  let q = new ManagedOutbox(config);
  q.saveGrant({ payload: { expiresAt: Date.now() + 60000 }, signature: 'SYNTHETIC_GRANT_CANARY' });
  const id = q.enqueue(sealed);
  assert.equal(q.list()[0].state, 'PENDING');
  q.update(id, 'HELD', 'EXPIRED_OBJECT');
  q.close();
  assert.equal(
    readFileSync(config.database).includes(Buffer.from('SYNTHETIC_STORAGE_CANARY')),
    false,
  );
  assert.equal(
    readFileSync(config.database).includes(Buffer.from('SYNTHETIC_GRANT_CANARY')),
    false,
  );
  q = new ManagedOutbox(config);
  assert.deepEqual(q.get(id).sealed, sealed);
  assert.equal(q.list()[0].reason, 'EXPIRED_OBJECT');
  assert.equal(q.grant().signature, 'SYNTHETIC_GRANT_CANARY');
  q.remove(id);
  assert.equal(q.list().length, 0);
  q.close();
  q.close();
  assert.throws(() => q.list(), /CLOSED/);
});

test('outbox refuses key/config substitution, row swaps and corrupt ciphertext', (t) => {
  const { config } = setup(t);
  const q = new ManagedOutbox(config),
    a = q.enqueue(object()),
    b = q.enqueue(object());
  q.close();
  assert.throws(() => new ManagedOutbox({ ...config, key: randomBytes(32) }), /BINDING/);
  assert.throws(() => new ManagedOutbox({ ...config, binding: { user: 'other' } }), /BINDING/);
  const db = new DatabaseSync(config.database);
  const bytes = db.prepare('SELECT encrypted FROM outbox WHERE id=?').get(a).encrypted;
  db.prepare('UPDATE outbox SET encrypted=? WHERE id=?').run(bytes, b);
  db.close();
  const reopened = new ManagedOutbox(config);
  assert.throws(() => reopened.get(b), /INTEGRITY/);
  assert.throws(() => reopened.list(), /INTEGRITY/);
  reopened.close();
});

test('outbox capacity is durable across instances, never evicts and rejects unsafe storage', (t) => {
  const { config, dir } = setup(t, { maxEntries: 1, maxBytes: 2048 });
  const first = new ManagedOutbox(config),
    second = new ManagedOutbox(config);
  const a = object();
  first.enqueue(a);
  assert.throws(() => second.enqueue(object()), /CAPACITY/);
  assert.throws(() => first.enqueue(a), /DUPLICATE/);
  assert.throws(() => second.saveGrant({ data: 'x'.repeat(3000) }), /CAPACITY/);
  assert.equal(first.list().length, 1);
  assert.throws(() => first.remove('grant'), /OBJECT/);
  first.close();
  second.close();
  symlinkSync(config.database, join(dir, 'link.sqlite'));
  assert.throws(() => openPrivateDatabase(join(dir, 'link.sqlite')));
  chmodSync(config.database, 0o644);
  assert.throws(() => new ManagedOutbox(config), /PERMISSIONS/);
  const publicDir = join(dir, 'public');
  mkdirSync(publicDir);
  chmodSync(publicDir, 0o755);
  assert.throws(() => openPrivateDatabase(join(publicDir, 'q.sqlite')), /DIRECTORY/);
  assert.throws(() => openPrivateDatabase('relative.sqlite'), /PATH/);
});
