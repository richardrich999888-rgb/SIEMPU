import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  readFileSync,
  cpSync,
  rmSync,
  existsSync,
  readdirSync,
  writeFileSync,
  truncateSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, createCipheriv } from 'node:crypto';
import { hash, canonical, packet } from '../services/control/primitives.mjs';
import { initDemo } from '../scripts/bootstrap.mjs';
import { backup, restore, readBackup, BACKUP_LIMITS } from '../scripts/backup.mjs';
import { createRelayServer } from '../services/relay/server.mjs';
import { Authority } from '../services/control/core.mjs';
import { ApiClient, coreTransport, createObject, decryptObject } from './helpers/client.mjs';

let root, source, profile, checkpoint, object;
const pass = 'Synthetic cross-store recovery passphrase';
before(async () => {
  root = mkdtempSync(join(tmpdir(), 'siepmu-recovery-stores-'));
  source = join(root, 'source');
  profile = await initDemo(source);
  createRelayServer({
    database: join(source, 'relay/relay.sqlite'),
    secret: Buffer.alloc(32),
  }).close();
  const db = new DatabaseSync(join(source, 'relay/relay.sqlite'));
  const a = new Authority({
    dbPath: join(source, 'control.sqlite'),
    signingKey: JSON.parse(readFileSync(join(source, 'server-key.json'))),
    masterKey: readFileSync(join(source, 'master.key')),
    relay: {
      putBlob: async (digest, bytes) =>
        db
          .prepare('INSERT INTO blobs VALUES(?,?,?,?)')
          .run(digest, bytes, bytes.length, Date.now()),
    },
  });
  try {
    const alice = profile.profiles.find((p) => p.username === 'alice');
    const bob = profile.profiles.find((p) => p.username === 'bob');
    const client = await new ApiClient(coreTransport(a), alice).authenticate();
    object = createObject(alice, bob, await client.grant());
    await client.submit(object);
    checkpoint = a.checkpoint();
  } finally {
    a.close();
    db.close();
  }
});
after(() => rmSync(root, { recursive: true, force: true }));

for (const [name, database, sql, expected] of [
  [
    'missing ciphertext',
    'relay/relay.sqlite',
    'DELETE FROM blobs',
    /Backup referenced ciphertext missing/,
  ],
  [
    'corrupt ciphertext',
    'relay/relay.sqlite',
    'UPDATE blobs SET ciphertext=zeroblob(size)',
    /Backup relay blob integrity/,
  ],
  [
    'false length',
    'relay/relay.sqlite',
    'UPDATE blobs SET size=size+1',
    /Backup relay blob integrity/,
  ],
  [
    'invalid blob digest',
    'relay/relay.sqlite',
    "UPDATE blobs SET hash='malformed'",
    /Backup relay blob integrity/,
  ],
  ['missing relay schema', 'relay/relay.sqlite', 'DROP TABLE blobs', /Backup relay schema/],
  [
    'object binding corruption',
    'control.sqlite',
    "UPDATE objects SET digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    /Backup stored object integrity/,
  ],
]) {
  test(`restore refuses ${name} before publication`, () => {
    const dir = join(root, name),
      archive = join(root, name + '.enc'),
      dest = join(root, name + '-restored');
    cpSync(source, dir, { recursive: true });
    const db = new DatabaseSync(join(dir, database));
    db.exec(sql);
    db.close();
    // Correctly signed and encrypted archive; file authentication alone cannot prove consistency.
    backup(dir, archive, pass);
    assert.throws(
      () => restore(archive, dest, pass, profile.serverPublicKey, { checkpoint }),
      expected,
    );
    assert.equal(existsSync(dest), false);
    assert.deepEqual(
      readdirSync(root).filter((n) => n.startsWith('.siepmu-restore-')),
      [],
    );
  });
}

test('complete restored ciphertext decrypts only with the recipient fixture key', () => {
  const archive = join(root, 'complete.enc'),
    dest = join(root, 'complete');
  backup(source, archive, pass);
  restore(archive, dest, pass, profile.serverPublicKey, { checkpoint });
  const db = new DatabaseSync(join(dest, 'relay/relay.sqlite'), { readOnly: true });
  try {
    const row = db
      .prepare('SELECT ciphertext FROM blobs WHERE hash=?')
      .get(object.envelope.ciphertextHash);
    const restored = {
      ...object,
      senderSigningPublicKey: profile.profiles.find((p) => p.username === 'alice').keys.signing
        .publicKey,
      ciphertext: Buffer.from(row.ciphertext).toString('base64url'),
    };
    assert.equal(
      decryptObject(
        restored,
        profile.profiles.find((p) => p.username === 'bob'),
      ).bytes.toString(),
      'SYNTHETIC: routine logistics message',
    );
    assert.throws(() =>
      decryptObject(
        restored,
        profile.profiles.find((p) => p.username === 'eve'),
      ),
    );
  } finally {
    db.close();
  }
});

test('unreferenced intact ciphertext is preserved without being granted authority', () => {
  const dir = join(root, 'orphan-source'),
    archive = join(root, 'orphan.enc'),
    dest = join(root, 'orphan-restored');
  cpSync(source, dir, { recursive: true });
  const db = new DatabaseSync(join(dir, 'relay/relay.sqlite'));
  const bytes = Buffer.alloc(32, 1);
  db.prepare('INSERT INTO blobs VALUES(?,?,?,?)').run(hash(bytes), bytes, bytes.length, Date.now());
  db.close();
  backup(dir, archive, pass);
  restore(archive, dest, pass, profile.serverPublicKey, { checkpoint });
  const restored = new DatabaseSync(join(dest, 'relay/relay.sqlite'), { readOnly: true });
  assert.equal(restored.prepare('SELECT count(*) n FROM blobs').get().n, 2);
  restored.close();
});

test('archive path, buffer and file-type limits reject before parsing or publication', () => {
  const sparse = join(root, 'oversize.enc');
  writeFileSync(sparse, '');
  truncateSync(sparse, BACKUP_LIMITS.archive + 1);
  assert.throws(
    () => readBackup(sparse, pass, profile.serverPublicKey, checkpoint),
    /Backup input size or type limit/,
  );
  assert.throws(
    () =>
      readBackup(
        Buffer.alloc(BACKUP_LIMITS.archive + 1),
        pass,
        profile.serverPublicKey,
        checkpoint,
      ),
    /Backup input size or type limit/,
  );
  assert.throws(
    () => readBackup(root, pass, profile.serverPublicKey, checkpoint),
    /Backup input size or type limit/,
  );
  const link = join(root, 'linked.enc');
  symlinkSync(sparse, link);
  assert.throws(() => readBackup(link, pass, profile.serverPublicKey, checkpoint), /ELOOP/);
});

test('backup creation refuses oversized metadata and never silently omits files', () => {
  const dir = join(root, 'large-metadata'),
    archive = join(root, 'large-metadata.enc');
  cpSync(source, dir, { recursive: true });
  writeFileSync(join(dir, 'relay.secret'), Buffer.alloc(BACKUP_LIMITS.metadata + 1));
  assert.throws(() => backup(dir, archive, pass), /Backup input size or type limit/);
  assert.equal(existsSync(archive), false);
});

function oversizedArchive(file, value) {
  const archive = join(root, 'limits-original.enc');
  if (!existsSync(archive)) backup(source, archive, pass);
  const { manifest, decoded } = readBackup(archive, pass, profile.serverPublicKey, checkpoint);
  decoded.set(file, value);
  const files = Object.fromEntries([...decoded].map(([n, b]) => [n, b.toString('base64')]));
  const payload = {
    ...manifest.payload,
    files: Object.fromEntries([...decoded].map(([n, b]) => [n, hash(b)])),
  };
  const key = JSON.parse(readFileSync(join(source, 'server-key.json')));
  const salt = randomBytes(32),
    iv = randomBytes(12),
    derived = scryptSync(pass, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const cipher = createCipheriv('aes-256-gcm', derived, iv);
  cipher.setAAD(Buffer.from('SIEPMU_BACKUP_V1'));
  const ciphertext = Buffer.concat([
    cipher.update(canonical({ manifest: packet(key, payload), files })),
    cipher.final(),
  ]);
  return Buffer.from(
    JSON.stringify({
      format: 'SIEPMU_BACKUP_V1',
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    }),
  );
}
for (const [name, file, size] of [
  ['metadata', 'relay.secret', BACKUP_LIMITS.metadata + 1],
  ['aggregate decoded bytes', 'relay/relay.sqlite', BACKUP_LIMITS.decoded],
])
  test(`authenticated archive cannot exceed ${name} limit`, () => {
    const archive = oversizedArchive(file, Buffer.alloc(size));
    assert.ok(archive.length < BACKUP_LIMITS.archive);
    assert.throws(
      () => readBackup(archive, pass, profile.serverPublicKey, checkpoint),
      /Backup decoded size limit/,
    );
  });
