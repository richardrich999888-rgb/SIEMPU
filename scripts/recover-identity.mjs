/** Offline administrator recovery. Requires the authority's local secret files. */
import { readFileSync, writeFileSync, openSync, closeSync, fsyncSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Authority } from '../services/control/core.mjs';
import { base32, passwordHash, seal } from '../services/control/primitives.mjs';
export function recoverIdentity(dir, username, output) {
  const a = new Authority({
    dbPath: join(dir, 'control.sqlite'),
    signingKey: JSON.parse(readFileSync(join(dir, 'server-key.json'))),
    masterKey: readFileSync(join(dir, 'master.key')),
  });
  let outputDescriptor;
  try {
    const user = a.get('SELECT * FROM users WHERE username=?', username);
    if (!user) throw new Error('Unknown recovery identity');
    const password = randomBytes(24).toString('base64url'),
      totpSecret = base32(randomBytes(20));
    // Atomically reserve a new private output before changing credentials.
    // O_EXCL rejects existing files/symlinks without a check-then-open race.
    try {
      outputDescriptor = openSync(output, 'wx', 0o600);
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error('Recovery output must be a new private file');
      throw error;
    }
    writeFileSync(
      outputDescriptor,
      JSON.stringify(
        {
          username,
          password,
          totpSecret,
          userId: user.id,
          warning:
            'Private recovery material. Credentials activate only if recovery succeeds. Import MFA securely; destroy this file afterward.',
        },
        null,
        2,
      ),
    );
    // A write/durability failure leaves current credentials unchanged. A later
    // database failure can leave an inactive recovery file, never a secret lost
    // because credentials committed before the output was created.
    fsyncSync(outputDescriptor);
    // Persist the new directory entry before credentials become active. This
    // controlled-maintenance utility requires a filesystem supporting fsync
    // on directories; failure is fail-closed before the database transaction.
    const directoryDescriptor = openSync(dirname(resolve(output)), 'r');
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
    a.tx(() => {
      a.run(
        'UPDATE users SET password=?,totp=?,totp_floor=-1 WHERE id=?',
        passwordHash(password),
        seal(totpSecret, a.masterKey),
        user.id,
      );
      a.run('UPDATE sessions SET revoked=1 WHERE user_id=?', user.id);
      a.run(
        'UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1 WHERE id=1',
      );
      a.event('OFFLINE_IDENTITY_RECOVERY', 'local-maintenance', {
        details: { userId: user.id, allSessionsRevoked: true, devicesUnchanged: true },
      });
      a.alert('IDENTITY_RECOVERY', user.id, 'OFFLINE_ADMINISTRATOR_RECOVERY');
    });
    return { username, allSessionsRevoked: true, epoch: a.epoch().epoch };
  } finally {
    try {
      if (outputDescriptor !== undefined) closeSync(outputDescriptor);
    } finally {
      a.close();
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.SIEPMU_MAINTENANCE_CONFIRMED !== '1')
    throw new Error(
      'Stop services; recovery requires controlled local maintenance and SIEPMU_MAINTENANCE_CONFIRMED=1',
    );
  const [username, output] = process.argv.slice(2);
  if (!username || !output)
    throw new Error('Usage: recover-identity.mjs USERNAME NEW_PRIVATE_OUTPUT_FILE');
  console.log(
    JSON.stringify(
      recoverIdentity(resolve(process.env.SIEPMU_DATA_DIR ?? '.data'), username, resolve(output)),
    ),
  );
}
