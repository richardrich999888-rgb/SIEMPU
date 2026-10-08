import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, chmodSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { X509Certificate } from 'node:crypto';

// Disposable laboratory CA only. Never export this CA key into a deployment package.
export function generateLabPKI(directory) {
  const dir = resolve(directory);
  if (/[\r\n]/.test(dir)) throw new Error('Invalid PKI directory');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (readdirSync(dir).length) throw new Error('PKI destination must be empty');
  const run = (args) =>
    execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  const write = (name, data) => writeFileSync(join(dir, name), data, { mode: 0o600, flag: 'wx' });
  run(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ca.key']);
  chmodSync(join(dir, 'ca.key'), 0o600);
  run([
    'req',
    '-new',
    '-x509',
    '-sha256',
    '-days',
    '7',
    '-key',
    'ca.key',
    '-out',
    'ca.crt',
    '-subj',
    '/CN=SIEPMU disposable laboratory CA',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  mkdirSync(join(dir, 'issued'), { mode: 0o700 });
  write('index', '');
  write('serial', '1000\n');
  write('crlnumber', '1000\n');
  write(
    'ca.cnf',
    `[ca]\ndefault_ca=lab\n[lab]\ndatabase=index\nnew_certs_dir=issued\ncertificate=ca.crt\nprivate_key=ca.key\nserial=serial\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_days=2\ndefault_crl_days=1\npolicy=names\nunique_subject=no\n[names]\ncommonName=supplied\n`,
  );
  const issue = (name, { wrongHost = false, expired = false } = {}) => {
    if (!/^[a-z][a-z0-9-]{0,40}$/.test(name)) throw new Error('Invalid laboratory identity');
    run([
      'genpkey',
      '-algorithm',
      'EC',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-out',
      name + '.key',
    ]);
    chmodSync(join(dir, name + '.key'), 0o600);
    run(['req', '-new', '-key', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + name]);
    write(
      name + '.ext',
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyAgreement\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${wrongHost ? 'wrong.invalid' : name + ',DNS:localhost,IP:127.0.0.1'}\n`,
    );
    run([
      'ca',
      '-batch',
      '-config',
      'ca.cnf',
      '-in',
      name + '.csr',
      '-out',
      name + '.crt',
      '-notext',
      '-extfile',
      name + '.ext',
      ...(expired ? ['-startdate', '20000101000000Z', '-enddate', '20000102000000Z'] : []),
    ]);
    return material(name);
  };
  const material = (name) => ({
    ca: readFileSync(join(dir, 'ca.crt')),
    cert: readFileSync(join(dir, name + '.crt')),
    key: readFileSync(join(dir, name + '.key')),
  });
  const pin = (name) =>
    new X509Certificate(readFileSync(join(dir, name + '.crt'))).fingerprint256
      .replaceAll(':', '')
      .toLowerCase();
  const revoke = (name) => {
    run(['ca', '-batch', '-config', 'ca.cnf', '-revoke', name + '.crt']);
    run(['ca', '-batch', '-config', 'ca.cnf', '-gencrl', '-out', 'revoked.crl']);
    return readFileSync(join(dir, 'revoked.crl'));
  };
  return { dir, issue, material, pin, revoke };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const pki = generateLabPKI(process.argv[2] ?? '.data/lab-pki');
  const names = [
    'web',
    'control',
    'relay',
    'collector',
    'checkpoint',
    'adapter',
    'web-client',
    'control-client',
    'observer-client',
    'adapter-client',
    'unit-a',
    'unit-b',
    'unit-denied',
  ];
  for (const name of names) pki.issue(name);
  writeFileSync(
    join(pki.dir, 'identities.json'),
    JSON.stringify(Object.fromEntries(names.map((n) => [n, pki.pin(n)])), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  console.log(
    JSON.stringify({ status: 'LAB_PKI_CREATED', directory: pki.dir, days: 2, production: false }),
  );
}
