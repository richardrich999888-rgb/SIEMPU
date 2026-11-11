// Synthetic, single-process control/relay maintenance drill; not full-system DR.
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync, rmSync } from 'node:fs';
import { tmpdir, cpus } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { performance } from 'node:perf_hooks';
import { snapshot } from '../sag/package.mjs';
import { fingerprint, insist } from '../sag/format.mjs';
import { initDemo } from '../../scripts/bootstrap.mjs';
import { backup, restore, BACKUP_LIMITS } from '../../scripts/backup.mjs';
import { Authority } from '../../services/control/core.mjs';
import { createRelayServer } from '../../services/relay/server.mjs';
import {
  ApiClient,
  coreTransport,
  createObject,
  decryptObject,
} from '../../tests/helpers/client.mjs';

const before = snapshot(process.cwd()),
  rows = [];
for (const objects of [0, 20, 60]) {
  const temp = mkdtempSync(join(tmpdir(), 'siepmu-recovery-growth-'));
  try {
    const dir = join(temp, 'source'),
      profiles = await initDemo(dir);
    createRelayServer({
      database: join(dir, 'relay/relay.sqlite'),
      secret: Buffer.alloc(32),
    }).close();
    const relay = new DatabaseSync(join(dir, 'relay/relay.sqlite'));
    const a = new Authority({
      dbPath: join(dir, 'control.sqlite'),
      signingKey: JSON.parse(readFileSync(join(dir, 'server-key.json'))),
      masterKey: readFileSync(join(dir, 'master.key')),
      relay: {
        putBlob: async (digest, bytes) =>
          relay
            .prepare('INSERT INTO blobs VALUES(?,?,?,?)')
            .run(digest, bytes, bytes.length, Date.now()),
      },
    });
    let checkpoint;
    const alice = profiles.profiles.find((p) => p.username === 'alice'),
      bob = profiles.profiles.find((p) => p.username === 'bob');
    const data = 'SYNTHETIC'.padEnd(4096, '.');
    const costs = [],
      submitted = [];
    try {
      const sender = await new ApiClient(coreTransport(a), alice).authenticate();
      const grant = await sender.grant();
      for (let n = 0; n < objects; n++) {
        const object = createObject(alice, bob, grant, { data });
        const start = performance.now();
        await sender.submit(object);
        costs.push(performance.now() - start);
        submitted.push(object);
      }
      checkpoint = a.checkpoint();
    } finally {
      a.close();
      relay.close();
    }
    const archive = join(temp, 'backup.enc'),
      dest = join(temp, 'restored');
    const cpu = process.cpuUsage();
    let start = performance.now();
    backup(dir, archive, 'Synthetic measurement passphrase');
    const backupMs = performance.now() - start;
    start = performance.now();
    restore(archive, dest, 'Synthetic measurement passphrase', profiles.serverPublicKey, {
      checkpoint,
    });
    const restoreMs = performance.now() - start;
    const restored = new DatabaseSync(join(dest, 'relay/relay.sqlite'), { readOnly: true });
    let decrypted = 0;
    try {
      for (const object of submitted) {
        const row = restored
          .prepare('SELECT ciphertext FROM blobs WHERE hash=?')
          .get(object.envelope.ciphertextHash);
        const result = decryptObject(
          {
            ...object,
            senderSigningPublicKey: alice.keys.signing.publicKey,
            ciphertext: Buffer.from(row.ciphertext).toString('base64url'),
          },
          bob,
        );
        insist(result.bytes.toString() === data, 'RESTORED_PLAINTEXT_MISMATCH');
        decrypted++;
      }
    } finally {
      restored.close();
    }
    rows.push({
      objects,
      decrypted,
      evidenceRecords: checkpoint.payload.sequence,
      submitMs: costs,
      backupMs,
      restoreMs,
      archiveBytes: statSync(archive).size,
      controlMainBytes: statSync(join(dir, 'control.sqlite')).size,
      controlWalBytes: existsSync(join(dir, 'control.sqlite-wal'))
        ? statSync(join(dir, 'control.sqlite-wal')).size
        : 0,
      relayMainBytes: statSync(join(dir, 'relay/relay.sqlite')).size,
      relayWalBytes: existsSync(join(dir, 'relay/relay.sqlite-wal'))
        ? statSync(join(dir, 'relay/relay.sqlite-wal')).size
        : 0,
      cpuMicroseconds: process.cpuUsage(cpu),
      maxRssKiB: process.resourceUsage().maxRSS,
    });
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}
const after = snapshot(process.cwd());
insist(
  before.commit === after.commit && fingerprint(before.index) === fingerprint(after.index),
  'SOURCE_CHANGED',
);
writeFileSync(
  resolve(process.argv[2]),
  JSON.stringify(
    {
      kind: 'P0_044_RECOVERY_GROWTH_LAB',
      commit: before.commit,
      tree: before.tree,
      sourceFingerprint: fingerprint(before.index),
      runtime: { node: process.version, openssl: process.versions.openssl, cpu: cpus()[0]?.model },
      limits: BACKUP_LIMITS,
      rows,
      limitations: [
        'Same process, shared administrator and filesystem; repeated sizes, not independent replicates.',
        'CPU spans backup, restore and recipient decryption; peak RSS is process lifetime high-water mark.',
        'Zero writes during snapshot; no operational RPO, power-loss durability, failover or all-store RTO claim.',
        'Local fresh state hashing remains linear in authorization rows; no pruning or evidence deletion is implemented.',
        'Fresh policy/custody revalidation and other service/key stores remain outside this maintenance restore.',
      ],
    },
    null,
    2,
  ) + '\n',
  { flag: 'wx', mode: 0o600 },
);
