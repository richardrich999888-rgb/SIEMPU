import { mkdirSync, writeFileSync, existsSync, chmodSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { Authority } from '../services/control/core.mjs';
import {
  publicJwk,
  canonical,
  base32,
  passwordHash,
  seal,
  totp,
} from '../services/control/primitives.mjs';
function keypair() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = privateKey.export({ format: 'jwk' });
  return { publicKey: publicJwk(jwk), privateKey: { ...publicJwk(jwk), d: jwk.d } };
}
export async function initDemo(dir) {
  dir = resolve(dir);
  if (existsSync(resolve(dir, 'control.sqlite')))
    throw new Error('Refusing to overwrite existing database; use a new demo directory');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const signing = keypair(),
    master = randomBytes(32);
  const save = (name, value) =>
    writeFileSync(resolve(dir, name), value, { mode: 0o600, flag: 'wx' });
  save('server-key.json', JSON.stringify(signing.privateKey));
  save('public-key.json', JSON.stringify(signing.publicKey, null, 2));
  save('master.key', master);
  save('relay.secret', randomBytes(32).toString('hex'));
  const a = new Authority({
    dbPath: resolve(dir, 'control.sqlite'),
    signingKey: signing.privateKey,
    masterKey: master,
  });
  const units = { A: randomUUID(), B: randomUUID(), C: randomUUID() };
  const profiles = [];
  a.tx(() => {
    for (const [name, id] of Object.entries(units))
      a.run('INSERT INTO units VALUES(?,?)', id, 'Unit ' + name);
    for (const [username, unit, role] of [
      ['admin', 'A', 'admin'],
      ['alice', 'A', 'operator'],
      ['bob', 'B', 'operator'],
      ['bravo', 'B', 'operator'],
      ['eve', 'C', 'viewer'],
    ]) {
      const id = randomUUID(),
        deviceId = randomUUID(),
        password = randomBytes(18).toString('base64url'),
        secret = base32(randomBytes(20)),
        keys = { signing: keypair(), encryption: keypair() };
      a.run(
        'INSERT INTO users(id,username,password,totp,unit_id,role,missions) VALUES(?,?,?,?,?,?,?)',
        id,
        username,
        passwordHash(password),
        seal(secret, master),
        units[unit],
        role,
        canonical(['DEMO-MISSION']),
      );
      a.run(
        'INSERT INTO devices VALUES(?,?,?,?,?,?,?)',
        deviceId,
        id,
        username + ' provisioned device',
        canonical(keys.signing.publicKey),
        canonical(keys.encryption.publicKey),
        'approved',
        Date.now(),
      );
      profiles.push({
        username,
        password,
        totpSecret: secret,
        userId: id,
        unitId: units[unit],
        deviceId,
        role,
        keys,
      });
    }
    a.run('INSERT INTO policies VALUES(?,?,?,1)', units.A, units.B, 'DEMO-MISSION');
    a.event('DEMO_PROVISIONED', 'offline-bootstrap', {
      details: { synthetic: true, profileCount: profiles.length },
    });
  });
  a.close();
  chmodSync(resolve(dir, 'control.sqlite'), 0o600);
  const result = { synthetic: true, serverPublicKey: signing.publicKey, profiles, units };
  save('demo-profiles.json', JSON.stringify(result, null, 2));
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const dir = resolve(process.env.SIEPMU_DATA_DIR ?? '.data');
  if (process.argv[2] === 'otp') {
    const profiles = JSON.parse(readFileSync(resolve(dir, 'demo-profiles.json')));
    const name = process.argv[3];
    const p = profiles.profiles.find((x) => x.username === name);
    if (!p) throw new Error('Supply demo username');
    console.log(totp(p.totpSecret));
  } else {
    await initDemo(dir);
    console.log(
      JSON.stringify({
        status: 'initialized',
        directory: dir,
        profilesFile: resolve(dir, 'demo-profiles.json'),
        warning:
          'Synthetic demo secrets; keep private. Login requires current TOTP. Provisioning does not certify trust.',
      }),
    );
  }
}
