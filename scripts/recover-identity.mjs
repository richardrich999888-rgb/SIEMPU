/** Offline administrator recovery. Requires the authority's local secret files. */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Authority } from '../services/control/core.mjs';
import { base32, passwordHash, seal } from '../services/control/primitives.mjs';
export function recoverIdentity(dir, username, output) {
  if (existsSync(output)) throw new Error('Recovery output must be a new private file');
  const a = new Authority({
    dbPath: join(dir, 'control.sqlite'),
    signingKey: JSON.parse(readFileSync(join(dir, 'server-key.json'))),
    masterKey: readFileSync(join(dir, 'master.key')),
  });
  try {
    const user = a.get('SELECT * FROM users WHERE username=?', username);
    if (!user) throw new Error('Unknown recovery identity');
    const password = randomBytes(24).toString('base64url'),
      totpSecret = base32(randomBytes(20));
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
    writeFileSync(
      output,
      JSON.stringify(
        {
          username,
          password,
          totpSecret,
          userId: user.id,
          warning:
            'Private one-time recovery material. Import MFA securely; destroy this file afterward.',
        },
        null,
        2,
      ),
      { mode: 0o600, flag: 'wx' },
    );
    return { username, allSessionsRevoked: true, epoch: a.epoch().epoch };
  } finally {
    a.close();
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
