/** Offline administrator recovery. Requires the authority's local secret files. */
import { readFileSync, writeFileSync, openSync, closeSync, fsyncSync, unlinkSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Authority } from '../services/control/core.mjs';
import { base32, passwordHash, seal } from '../services/control/primitives.mjs';
export function recoverIdentity(dir, username, output) {
  let outputFd;
  try {
    // O_EXCL rejects occupied files and symlinks without a check-then-open race.
    outputFd = openSync(output, 'wx', 0o600);
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('Recovery output must be a new private file');
    throw error;
  }
  let a;
  let committed = false;
  try {
    a = new Authority({
      dbPath: join(dir, 'control.sqlite'),
      signingKey: JSON.parse(readFileSync(join(dir, 'server-key.json'))),
      masterKey: readFileSync(join(dir, 'master.key')),
    });
    const user = a.get('SELECT * FROM users WHERE username=?', username);
    if (!user) throw new Error('Unknown recovery identity');
    const password = randomBytes(24).toString('base64url'),
      totpSecret = base32(randomBytes(20));
    // Reserve and durably write the private output before changing identity state.
    // Concurrent recovery to the same output fails before any database mutation.
    writeFileSync(
      outputFd,
      JSON.stringify(
        {
          username,
          password,
          totpSecret,
          userId: user.id,
          warning:
            'Private recovery material. Valid only after recovery reports success; import MFA securely and destroy this file afterward.',
        },
        null,
        2,
      ),
    );
    fsyncSync(outputFd);
    // Persist the new filename before activating credentials that depend on it.
    // Directory fsync must be supported; a durability failure stays fail-closed
    // before the credential transaction and removes the inactive output below.
    const outputDirectoryFd = openSync(dirname(resolve(output)), 'r');
    try {
      fsyncSync(outputDirectoryFd);
    } finally {
      closeSync(outputDirectoryFd);
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
    committed = true;
    return { username, allSessionsRevoked: true, epoch: a.epoch().epoch };
  } finally {
    try {
      a?.close();
    } finally {
      closeSync(outputFd);
      if (!committed) unlinkSync(output);
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
