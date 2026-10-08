import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { IntegrationEndpoint } from '../../packages/integration/client.mjs';
import { hash } from '../../services/control/primitives.mjs';
const read = (name) => JSON.parse(readFileSync('/state/' + name + '.json'));
const client = new IntegrationEndpoint({
  url: 'https://web:8080',
  tls: { ca: readFileSync('/keys/ca.crt') },
  profile: read('profile'),
  authorityKey: read('authority-public'),
});
const peer = read('peer'),
  [command, arg] = process.argv.slice(2);
const save = (name, obj) =>
  writeFileSync('/state/' + name + '.json', JSON.stringify(obj), { mode: 0o600 });
if (existsSync('/state/session.json')) client.token = read('session').token;
let result;
if (command === 'init') {
  await client.authenticate();
  const grant = await client
    .call('POST', '/api/grants', { proof: await client.proof('grant') })
    .catch(() => null);
  save('session', { token: client.token, grant });
  result = { authenticated: true };
} else if (command === 'queue' || command === 'send') {
  const bytes = Number(arg ?? 4096);
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 262144) throw new Error('WORKLOAD_SIZE');
  const payload = client.crypto.createFilePayload(
    'synthetic.bin',
    'application/octet-stream',
    new Uint8Array(bytes).fill(83),
  );
  const started = performance.now(),
    sealed = await client.sealUsingGrant(peer, payload, read('session').grant),
    encrypted = performance.now();
  save('queued', sealed);
  const sent = command === 'send' ? await client.submit(sealed) : null;
  result = {
    objectId: sealed.envelope.objectId,
    bytes,
    sha256: hash(Buffer.alloc(bytes, 83)),
    encryptionMs: encrypted - started,
    submissionMs: sent ? performance.now() - encrypted : null,
    queued: true,
  };
} else if (command === 'submit') {
  const queued = read('queued'),
    result = await client.submit(queued);
  console.log(JSON.stringify({ objectId: result.object.id, accepted: true }));
  process.exit(0);
} else if (command === 'receive' || command === 'deny') {
  const started = performance.now();
  try {
    const payload = await client.receive(arg, peer.senderSigningPublicKey),
      plain = client.crypto.unpackPayload(payload);
    result = {
      delivered: true,
      bytes: plain.bytes.length,
      sha256: hash(plain.bytes),
      receiveMs: performance.now() - started,
    };
    if (command === 'deny') throw new Error('UNAUTHORIZED_DELIVERY');
  } catch (error) {
    if (command !== 'deny' || ![403, 404, 409].includes(error.status)) throw error;
    result = { denied: true, status: error.status };
  }
} else if (command === 'revoke-sender') {
  const path = '/api/admin/devices/' + peer.senderDeviceId + '/revoke';
  await client.call('POST', path, { proof: await client.proof('admin:POST:' + path, {}) });
  result = { revoked: true };
} else if (command === 'control') {
  const started = performance.now();
  await client.signed('/api/control');
  result = { authorized: true, latencyMs: performance.now() - started };
} else throw new Error('Unknown workload operation');
console.log(JSON.stringify(result));
