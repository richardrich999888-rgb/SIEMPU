import { DatabaseSync } from 'node:sqlite';
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  existsSync,
  rmSync,
  chmodSync,
} from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { pathToFileURL } from 'node:url';
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
  if (existsSync(destination) && readdirSync(destination).length)
    throw new Error('Restore destination must be empty');
  const p = JSON.parse(readFileSync(archive));
  if (p.format !== 'SIEPMU_BACKUP_V1') throw new Error('Backup format');
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
  if (checkpoint) {
    if (
      !verifyPacket(trustedPublicKey, checkpoint) ||
      checkpoint.payload.sequence > content.manifest.payload.checkpoint.sequence ||
      (checkpoint.payload.sequence === content.manifest.payload.checkpoint.sequence &&
        checkpoint.payload.headHash !== content.manifest.payload.checkpoint.headHash)
    )
      throw new Error('Backup predates or conflicts with trusted checkpoint');
  }
  const allowed = [...names, 'relay/relay.sqlite'];
  if (Object.keys(content.files).sort().join() !== allowed.sort().join())
    throw new Error('Backup file manifest');
  for (const [name, data] of Object.entries(content.files)) {
    if (hash(Buffer.from(data, 'base64')) !== content.manifest.payload.files[name])
      throw new Error('Backup digest');
  }
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  chmodSync(destination, 0o700);
  mkdirSync(join(destination, 'relay'), { mode: 0o700 });
  for (const [name, data] of Object.entries(content.files))
    writeFileSync(join(destination, name), Buffer.from(data, 'base64'), {
      mode: 0o600,
      flag: 'wx',
    });
  return content.manifest;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, a, b, c] = process.argv.slice(2);
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
    if (!c) throw new Error('Provide independently retained public-key.json');
    const r = restore(a, b, pass, JSON.parse(readFileSync(c)));
    console.log(
      JSON.stringify({
        status: 'restored',
        checkpoint: r.payload.checkpoint,
        warning:
          'Database rollback protection requires an external checkpoint; revalidate authority before service restart',
      }),
    );
  } else
    throw new Error(
      'Usage: backup.mjs create DATA_DIR ARCHIVE | restore ARCHIVE EMPTY_DIR TRUSTED_PUBLIC_KEY',
    );
}
