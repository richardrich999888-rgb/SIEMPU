import { DatabaseSync } from 'node:sqlite';
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  existsSync,
  rmSync,
  lstatSync,
  renameSync,
  rmdirSync,
} from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { verifyEvidenceRecords } from '../apps/verifier/verify.mjs';
import { assertAuthorizationCommit } from '../services/evidence/authorization-state.mjs';
import {
  packet,
  verifyPacket,
  hash,
  publicJwk,
  canonical,
} from '../services/control/primitives.mjs';
const names = [
  'control.sqlite',
  'server-key.json',
  'master.key',
  'relay.secret',
  'public-key.json',
];
const sameMembers = (value, expected) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(),
    wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((name, i) => name === wanted[i]);
};
const validHead = (head) =>
  sameMembers(head, ['sequence', 'headHash']) &&
  Number.isSafeInteger(head.sequence) &&
  head.sequence >= 0 &&
  typeof head.headHash === 'string' &&
  /^[a-f0-9]{64}$/.test(head.headHash) &&
  (head.sequence === 0) === (head.headHash === '0'.repeat(64));
function emptyDestination(destination) {
  let stat;
  try {
    stat = lstatSync(destination);
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || readdirSync(destination).length)
    throw new Error('Restore destination must be an empty real directory');
  return stat;
}
function verifyRestoredHistory(directory, trustedPublicKey, checkpoint, head) {
  const db = new DatabaseSync(join(directory, 'control.sqlite'), { readOnly: true });
  try {
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;');
    const integrity = db.prepare('PRAGMA quick_check').all();
    if (integrity.length !== 1 || integrity[0].quick_check !== 'ok')
      throw new Error('Backup database integrity');
    function* records() {
      for (const row of db
        .prepare('SELECT sequence,record,hash FROM evidence ORDER BY sequence')
        .iterate()) {
        const record = JSON.parse(row.record);
        if (row.sequence !== record.payload?.sequence || hash(canonical(record)) !== row.hash)
          throw new Error('Backup evidence row mismatch');
        yield record;
      }
    }
    const result = verifyEvidenceRecords(records(), trustedPublicKey, { checkpoint });
    if (result.records !== head.sequence || result.headHash !== head.headHash)
      throw new Error('Backup manifest checkpoint does not match history');
    // Read-only view: never run migrations or create a fresh seal over restored bytes.
    // This maintenance archive supports the default classical runtime configuration.
    assertAuthorizationCommit({
      publicKey: trustedPublicKey,
      get: (sql, ...args) => db.prepare(sql).get(...args),
      all: (sql, ...args) => db.prepare(sql).all(...args),
      epoch: () => db.prepare('SELECT * FROM authority WHERE id=1').get(),
      checkpoint: () => ({ payload: head }),
      crypto: { allowPqcLab: false },
    });
  } finally {
    db.close();
  }
}
function snapshot(source, dest) {
  const db = new DatabaseSync(source);
  try {
    db.exec('PRAGMA busy_timeout=5000');
    db.prepare('VACUUM INTO ?').run(dest);
  } finally {
    db.close();
  }
}
export function backup(dir, destination, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 16)
    throw new Error('Backup passphrase must have at least 16 characters');
  dir = resolve(dir);
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-backup-'));
  try {
    snapshot(join(dir, 'control.sqlite'), join(temp, 'control.sqlite'));
    const relay = join(dir, 'relay', 'relay.sqlite');
    if (!existsSync(relay))
      throw new Error('Relay database missing; supply the three-service data directory');
    mkdirSync(join(temp, 'relay'));
    snapshot(relay, join(temp, 'relay', 'relay.sqlite'));
    const fileNames = [...names, 'relay/relay.sqlite'];
    const files = Object.fromEntries(
      fileNames.map((name) => [
        name,
        readFileSync(name.endsWith('.sqlite') ? join(temp, name) : join(dir, name)).toString(
          'base64',
        ),
      ]),
    );
    const key = JSON.parse(readFileSync(join(dir, 'server-key.json')));
    const db = new DatabaseSync(join(temp, 'control.sqlite'));
    const row = db
      .prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1')
      .get();
    db.close();
    const manifest = packet(key, {
      format: 'SIEPMU_BACKUP_V1',
      createdAt: Date.now(),
      checkpoint: { sequence: row?.sequence ?? 0, headHash: row?.hash ?? '0'.repeat(64) },
      files: Object.fromEntries(
        Object.entries(files).map(([name, data]) => [name, hash(Buffer.from(data, 'base64'))]),
      ),
    });
    const salt = randomBytes(32),
      iv = randomBytes(12),
      derived = scryptSync(passphrase, salt, 32, {
        N: 32768,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      }),
      cipher = createCipheriv('aes-256-gcm', derived, iv);
    cipher.setAAD(Buffer.from('SIEPMU_BACKUP_V1'));
    const ciphertext = Buffer.concat([
      cipher.update(canonical({ manifest, files })),
      cipher.final(),
    ]);
    writeFileSync(
      destination,
      JSON.stringify({
        format: 'SIEPMU_BACKUP_V1',
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
      }),
      { mode: 0o600, flag: 'wx' },
    );
    return { manifest, publicKey: publicJwk(key) };
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}
export function restore(archive, destination, passphrase, trustedPublicKey, { checkpoint } = {}) {
  destination = resolve(destination);
  const priorDestination = emptyDestination(destination);
  if (checkpoint === undefined || checkpoint === null)
    throw new Error('Independently retained checkpoint required');
  if (
    !verifyPacket(trustedPublicKey, checkpoint) ||
    !sameMembers(checkpoint.payload, ['headHash', 'issuedAt', 'sequence']) ||
    !validHead({ sequence: checkpoint.payload.sequence, headHash: checkpoint.payload.headHash }) ||
    !Number.isSafeInteger(checkpoint.payload.issuedAt) ||
    checkpoint.payload.issuedAt < 0
  )
    throw new Error('Backup predates or conflicts with trusted checkpoint');
  const p = JSON.parse(readFileSync(archive));
  if (
    !sameMembers(p, ['format', 'salt', 'iv', 'ciphertext', 'tag']) ||
    p.format !== 'SIEPMU_BACKUP_V1'
  )
    throw new Error('Backup format');
  for (const [name, size] of [
    ['salt', 32],
    ['iv', 12],
    ['tag', 16],
    ['ciphertext', null],
  ]) {
    if (typeof p[name] !== 'string') throw new Error('Backup encoding');
    const bytes = Buffer.from(p[name], 'base64');
    if (
      bytes.toString('base64') !== p[name] ||
      (size === null ? !bytes.length : bytes.length !== size)
    )
      throw new Error('Backup encoding');
  }
  const key = scryptSync(passphrase, Buffer.from(p.salt, 'base64'), 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(p.iv, 'base64'));
  d.setAAD(Buffer.from(p.format));
  d.setAuthTag(Buffer.from(p.tag, 'base64'));
  const content = JSON.parse(
    Buffer.concat([d.update(Buffer.from(p.ciphertext, 'base64')), d.final()]),
  );
  if (!verifyPacket(trustedPublicKey, content.manifest)) throw new Error('Backup signature');
  const manifest = content.manifest.payload;
  if (
    !sameMembers(content, ['manifest', 'files']) ||
    !sameMembers(manifest, ['format', 'createdAt', 'checkpoint', 'files']) ||
    manifest.format !== 'SIEPMU_BACKUP_V1' ||
    !Number.isSafeInteger(manifest.createdAt) ||
    manifest.createdAt < 0 ||
    !validHead(manifest.checkpoint)
  )
    throw new Error('Backup manifest schema');
  if (
    checkpoint.payload.sequence > manifest.checkpoint.sequence ||
    (checkpoint.payload.sequence === manifest.checkpoint.sequence &&
      checkpoint.payload.headHash !== manifest.checkpoint.headHash)
  )
    throw new Error('Backup predates or conflicts with trusted checkpoint');
  const allowed = [...names, 'relay/relay.sqlite'];
  if (!sameMembers(content.files, allowed) || !sameMembers(manifest.files, allowed))
    throw new Error('Backup file manifest');
  const decoded = new Map();
  for (const [name, data] of Object.entries(content.files)) {
    if (typeof data !== 'string') throw new Error('Backup file encoding');
    const bytes = Buffer.from(data, 'base64');
    if (bytes.toString('base64') !== data) throw new Error('Backup file encoding');
    if (hash(bytes) !== manifest.files[name]) throw new Error('Backup digest');
    decoded.set(name, bytes);
  }
  const restoredKey = JSON.parse(decoded.get('server-key.json'));
  if (
    canonical(publicJwk(restoredKey)) !== canonical(trustedPublicKey) ||
    canonical(JSON.parse(decoded.get('public-key.json'))) !== canonical(trustedPublicKey) ||
    !verifyPacket(trustedPublicKey, packet(restoredKey, { purpose: 'SIEPMU_BACKUP_KEY_CHECK_V1' }))
  )
    throw new Error('Backup authority key mismatch');
  // Offline, exclusive maintenance in an operator-controlled parent directory. Staging
  // keeps verification/write failures from publishing a partial service directory.
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  const staging = mkdtempSync(join(dirname(destination), '.siepmu-restore-'));
  try {
    mkdirSync(join(staging, 'relay'), { mode: 0o700 });
    for (const [name, bytes] of decoded)
      writeFileSync(join(staging, name), bytes, { mode: 0o600, flag: 'wx' });
    verifyRestoredHistory(staging, trustedPublicKey, checkpoint, manifest.checkpoint);
    const current = emptyDestination(destination);
    if (current?.ino !== priorDestination?.ino || current?.dev !== priorDestination?.dev)
      throw new Error('Restore destination changed');
    if (current) rmdirSync(destination);
    renameSync(staging, destination);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  return content.manifest;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, a, b, c, checkpointPath, ...extra] = process.argv.slice(2);
  if (extra.length) throw new Error('Unexpected backup arguments');
  const pass = process.env.SIEPMU_BACKUP_PASSPHRASE;
  if (command === 'create') {
    if (process.env.SIEPMU_MAINTENANCE_CONFIRMED !== '1')
      throw new Error(
        'Stop all services and set SIEPMU_MAINTENANCE_CONFIRMED=1 for coherent control/relay snapshot',
      );
    const r = backup(a, b, pass);
    console.log(
      JSON.stringify({ status: 'backup-created', checkpoint: r.manifest.payload.checkpoint }),
    );
  } else if (command === 'restore') {
    if (!c || !checkpointPath)
      throw new Error('Provide independently retained public-key.json and checkpoint.json');
    const r = restore(a, b, pass, JSON.parse(readFileSync(c)), {
      checkpoint: JSON.parse(readFileSync(checkpointPath)),
    });
    console.log(
      JSON.stringify({
        status: 'restored',
        checkpoint: r.payload.checkpoint,
        anchor: 'INDEPENDENT_CHECKPOINT_VERIFIED',
        warning: 'Revalidate current personnel/device policy and custody before service restart',
      }),
    );
  } else
    throw new Error(
      'Usage: backup.mjs create DATA_DIR ARCHIVE | restore ARCHIVE EMPTY_DIR TRUSTED_PUBLIC_KEY TRUSTED_CHECKPOINT',
    );
}
