// Optional native path. Requires genuinely enrolled keys and the real inspection sandbox.
// There is no software fallback, mock key provider or simulated inspection success.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { openManagedEndpoint } from '../../integrations/managed-endpoint/index.mjs';
import { hash } from '../../services/control/primitives.mjs';
const [directory, op, arg] = process.argv.slice(2),
  dir = resolve(directory);
const json = (name) => JSON.parse(readFileSync(join(dir, name)));
const inputs = json('native-inputs.json');
const client = await openManagedEndpoint({
  config: json('managed-config.json'),
  credentials: json('credentials-private.json'),
  tls: { ca: readFileSync(join(dir, 'ca.crt')) },
  getPin: async () => {
    const pin = process.env.SIEPMU_LAB_TOKEN_PIN;
    if (!pin) throw new Error('TOKEN_PIN_REQUIRED');
    return pin;
  },
  outbox: { database: join(dir, 'outbox.sqlite'), key: readFileSync(join(dir, 'outbox-secret')) },
});
try {
  let result;
  if (op === 'init') {
    await client.authenticate();
    result = await client.refreshCreationGrant();
  } else if (op === 'queue') {
    const size = Number(arg ?? 4096);
    if (!Number.isSafeInteger(size) || size < 1 || size > 262144) throw new Error('WORKLOAD_SIZE');
    const bytes = Buffer.alloc(size, 83);
    result = await client.queue(
      inputs.peer,
      client.createFilePayload('synthetic.bin', 'application/octet-stream', bytes),
    );
    result.sha256 = hash(bytes);
  } else if (op === 'flush') {
    await client.authenticate();
    result = await client.flushQueue(32);
  } else if (op === 'receive') {
    await client.authenticate();
    const r = await client.receiveWithRelease(arg, inputs.senderSigningPublicKey);
    const plain = client.unpackPayload(r.plaintext),
      ack = await client.acknowledge(arg, r.release);
    result = {
      objectId: arg,
      sha256: hash(plain.bytes),
      bytes: plain.bytes.length,
      release: r.release,
      ack,
    };
  } else if (op === 'list') {
    result = await client.listQueue();
  } else throw new Error('NATIVE_OPERATION');
  const record = {
    operation: op,
    result,
    status: client.status(),
    physicalToken: 'REQUIRES_EXTERNAL_HARDWARE_INVENTORY',
  };
  writeFileSync(join(dir, 'last-result.json'), JSON.stringify(record, null, 2) + '\n', {
    mode: 0o600,
  });
  console.log(JSON.stringify(record));
} finally {
  client.close();
}
