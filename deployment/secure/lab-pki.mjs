/** Synthetic short-lived CA. Private material stays in the caller's 0700 disposable directory. */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { certificatePin } from '../../packages/transport/mtls.mjs';

export function createLabPki(directory) {
  const dir = resolve(directory);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  run(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-keyout',
    'ca.key',
    '-out',
    'ca.pem',
    '-days',
    '2',
    '-subj',
    '/CN=SIEPMU SYNTHETIC LAB CA',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  );
  chmodSync(resolve(dir, 'ca.key'), 0o600);
  const ca = readFileSync(resolve(dir, 'ca.pem'));
  const identities = {};
  for (const name of ['web', 'control', 'relay', 'adapter', 'legacy', 'untrusted']) {
    run(
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-keyout',
      `${name}.key`,
      '-out',
      `${name}.csr`,
      '-subj',
      `/CN=SIEPMU synthetic ${name}`,
    );
    writeFileSync(
      resolve(dir, `${name}.ext`),
      'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n',
      { mode: 0o600 },
    );
    run(
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      'ca.pem',
      '-CAkey',
      'ca.key',
      '-CAcreateserial',
      '-out',
      `${name}.pem`,
      '-days',
      '1',
      '-extfile',
      `${name}.ext`,
    );
    chmodSync(resolve(dir, `${name}.key`), 0o600);
    const cert = readFileSync(resolve(dir, `${name}.pem`));
    identities[name] = {
      key: readFileSync(resolve(dir, `${name}.key`)),
      cert,
      ca,
      pin: certificatePin(cert),
    };
  }
  return { ca, identities };
}
