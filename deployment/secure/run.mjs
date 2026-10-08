/** Explicit local synthetic lab launcher. Existing provisioning and PKI are required. */
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { certificatePin } from '../../packages/transport/mtls.mjs';
import { startSecureStack } from './stack.mjs';

const [dataPath, pkiPath, portText = '8443'] = process.argv.slice(2);
if (
  !dataPath ||
  !pkiPath ||
  !/^\d+$/.test(portText) ||
  Number(portText) < 1024 ||
  Number(portText) > 65535
)
  throw new Error('Usage: node deployment/secure/run.mjs DATA_DIRECTORY PKI_DIRECTORY [8443]');
const directory = resolve(dataPath),
  pkiDirectory = resolve(pkiPath);
const ca = await readFile(resolve(pkiDirectory, 'ca.pem'));
const identities = {};
for (const name of ['web', 'control', 'relay']) {
  const keyPath = resolve(pkiDirectory, `${name}.key`);
  if ((await stat(keyPath)).mode & 0o077)
    throw new Error('TLS private key must have 0600 permissions');
  const cert = await readFile(resolve(pkiDirectory, `${name}.pem`));
  identities[name] = { ca, cert, key: await readFile(keyPath), pin: certificatePin(cert) };
}
for (const name of ['server-key.json', 'master.key', 'relay.secret'])
  if ((await stat(resolve(directory, name))).mode & 0o077)
    throw new Error('Application secret must have 0600 permissions');
const flag = process.env.SIEPMU_ALLOW_PQC_LAB;
if (flag !== undefined && flag !== '1')
  throw new Error('SIEPMU_ALLOW_PQC_LAB accepts only 1 or omission');
const stack = await startSecureStack({
  directory,
  pki: { ca, identities },
  webPort: Number(portText),
  allowPqcLab: flag === '1',
});
console.log(
  JSON.stringify({
    synthetic: true,
    topology: 'one process, three isolated HTTPS listeners',
    baseUrl: stack.baseUrl,
    transport: 'TLS1.3 ingress; pinned mTLS internal',
    pqcLab: flag === '1',
  }),
);
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, async () => {
    if (stopping) return;
    stopping = true;
    await stack.stop();
  });
