import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ClamAvInspector } from '../packages/file-inspection/clamav.mjs';
import { IntegrationEndpoint } from '../packages/integration/client.mjs';
import { DocumentInbox } from '../apps/document-system/inbox.mjs';
import { coreFixture } from './helpers/fixture.mjs';

const hash = (b) => createHash('sha256').update(b).digest('hex');
const clean = (b) => ({
  version: 1,
  status: 'NO_THREAT_DETECTED',
  sha256: hash(b),
  bytes: b.length,
});
const refused = (code) => Object.assign(new Error(code), { code });
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

// Subprocess protocol double, NOT ClamAV. Real-engine checks have a separate opt-in runner.
function scanner(t, mode = 'ok', options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-inspection-test-'));
  t.after(() => rmSync(dir, { force: true, recursive: true }));
  const executable = join(dir, 'scanner.mjs');
  writeFileSync(
    executable,
    `#!${process.execPath}
import { statSync } from 'node:fs';
import { basename } from 'node:path';
const args = process.argv.slice(2);
const mode = basename(args.find(a => a.startsWith('--database=')).slice(11));
for (const flag of ['--official-db-only=yes', '--fail-if-cvd-older-than=2',
 '--alert-exceeds-max=yes', '--alert-encrypted=yes', '--alert-macros=yes',
 '--max-filesize=524288', '--max-scansize=8M', '--max-files=100', '--max-recursion=8'])
 if (!args.includes(flag)) process.exit(9);
if (args.at(-1) !== '-' || (statSync(process.cwd()).mode & 0o777) !== 0o700 ||
 process.env.SIEPMU_SCAN_CANARY || process.env.LD_PRELOAD) process.exit(9);
if (mode === 'timeout') { process.stdin.resume(); setInterval(() => {}, 1000); }
else {
 for await (const chunk of process.stdin) { void chunk; }
 if (mode === 'detected') { process.stdout.write('stdin: SYNTHETIC_SIGNATURE FOUND\\n'); process.exitCode = 1; }
 else if (mode === 'error') { process.stdout.write('SYNTHETIC_CONTENT_MUST_NOT_ESCAPE\\n'); process.exitCode = 2; }
 else if (mode === 'diagnostic') { process.stderr.write('SYNTHETIC_CONTENT_MUST_NOT_ESCAPE\\n'); }
 else if (mode === 'flood') process.stdout.write('x'.repeat(20000));
 else if (mode === 'empty') { /* no result */ }
 else if (mode === 'skipped') process.stdout.write('stdin: Empty file\\n');
 else process.stdout.write('stdin: OK\\n');
}
`,
    { mode: 0o700 },
  );
  const settings = {
    executable,
    executableSha256: hash(readFileSync(executable)),
    database: join(dir, mode),
    tempRoot: dir,
    ...options,
  };
  return { inspector: new ClamAvInspector(settings), settings, dir };
}

test('local scanner consumes a private byte snapshot, with strict flags and a clean temporary directory', async (t) => {
  const f = scanner(t);
  const bytes = Buffer.from('SYNTHETIC_FILE_CANARY');
  const expected = clean(bytes);
  process.env.SIEPMU_SCAN_CANARY = 'must-not-reach-child';
  t.after(() => delete process.env.SIEPMU_SCAN_CANARY);
  const pending = f.inspector.inspect(bytes);
  bytes.fill(0);
  assert.deepEqual(await pending, expected);
  assert.deepEqual(readdirSync(f.dir), ['scanner.mjs']);
});

for (const [mode, code] of [
  ['detected', 'DETECTED'],
  ['error', 'INCOMPLETE'],
  ['diagnostic', 'DIAGNOSTIC'],
  ['flood', 'OUTPUT_LIMIT'],
  ['empty', 'INCOMPLETE'],
  ['skipped', 'INCOMPLETE'],
  ['timeout', 'TIMEOUT'],
])
  test(`local scanner blocks ${mode} without leaking diagnostics`, async (t) => {
    const f = scanner(t, mode, { timeoutMs: mode === 'timeout' ? 300 : 10000 });
    await assert.rejects(f.inspector.inspect(Buffer.from('SYNTHETIC_FILE')), (error) => {
      assert.equal(error.code, 'FILE_INSPECTION_' + code);
      assert.equal(error.message, error.code);
      assert.equal(JSON.stringify(error).includes('MUST_NOT_ESCAPE'), false);
      return true;
    });
    assert.deepEqual(readdirSync(f.dir), ['scanner.mjs']);
  });

test('scanner bounds, engine identity and overload fail closed', async (t) => {
  const f = scanner(t, 'timeout', { timeoutMs: 300 });
  for (const bad of [null, 'text', Buffer.alloc(0), Buffer.alloc(512 * 1024 + 1)])
    await assert.rejects(f.inspector.inspect(bad), /FILE_INSPECTION_SIZE/);
  for (const change of [
    { executable: 'clamscan' },
    { executableSha256: 'x' },
    { maxBytes: Infinity },
    { timeoutMs: 0 },
    { maxDatabaseAgeDays: 0 },
    { tempRoot: 'relative' },
  ])
    assert.throws(() => new ClamAvInspector({ ...f.settings, ...change }), /CONFIG/);
  const first = f.inspector.inspect(Buffer.from('file'));
  await assert.rejects(f.inspector.inspect(Buffer.from('file')), /BUSY/);
  await assert.rejects(first, /TIMEOUT/);
  writeFileSync(f.settings.executable, '# changed');
  await assert.rejects(f.inspector.inspect(Buffer.from('file')), /ENGINE_CHANGED/);
  rmSync(f.settings.executable);
  await assert.rejects(f.inspector.inspect(Buffer.from('file')), /UNAVAILABLE/);
});

async function endpointFixture(t, inspector) {
  const f = await coreFixture(t);
  const make = async (profile, fileInspector = inspector) => {
    const endpoint = new IntegrationEndpoint({
      url: 'https://synthetic.invalid',
      tls: {},
      profile,
      authorityKey: f.provisioned.serverPublicKey,
      fileInspector,
    });
    // Real authority and cryptography, in-process transport; no HTTP/TLS claim for this test.
    endpoint.call = async (method, path, body) => {
      const r = await f.transport(method, path, body, endpoint.token);
      if (r.status !== 200) throw refused(r.body.code ?? 'REQUEST_FAILED');
      return r.body;
    };
    await endpoint.authenticate();
    return endpoint;
  };
  const bob = f.profiles.bob;
  return {
    ...f,
    make,
    source: await make(f.profiles.alice),
    destination: {
      userId: bob.userId,
      deviceId: bob.deviceId,
      unitId: bob.unitId,
      encryptionPublicKey: bob.keys.encryption.publicKey,
    },
  };
}

test('endpoint seals the inspected snapshot and inspects again before returning decrypted files', async (t) => {
  const entered = deferred(),
    release = deferred();
  let calls = 0;
  const f = await endpointFixture(t, {
    inspect: async (bytes) => {
      calls++;
      if (calls === 1) {
        entered.resolve();
        await release.promise;
      }
      return clean(bytes);
    },
  });
  const payload = f.source.crypto.createFilePayload(
    'synthetic.txt',
    'text/plain',
    Buffer.from('ORIGINAL'),
  );
  const pending = f.source.seal(f.destination, payload);
  await entered.promise;
  payload.data = Buffer.from('REPLACEMENT').toString('base64url');
  release.resolve();
  const sealed = await pending;
  await f.source.submit(sealed);
  const recipient = await f.make(f.profiles.bob);
  const result = await recipient.receiveWithRelease(
    sealed.envelope.objectId,
    f.profiles.alice.keys.signing.publicKey,
  );
  assert.equal(Buffer.from(result.plaintext.data, 'base64url').toString(), 'ORIGINAL');
  assert.equal(calls, 2);
  assert.equal(f.source.fileInspectionMode, 'ENDPOINT_REQUIRED');
});

test('sender denies detections, failures and mismatched scanner receipts before encryption', async (t) => {
  let verdict;
  const f = await endpointFixture(t, {
    inspect: async (bytes) => {
      if (verdict instanceof Error) throw verdict;
      return verdict ?? clean(bytes);
    },
  });
  let encryptions = 0;
  const encrypt = f.source.crypto.encryptObject;
  f.source.crypto = {
    ...f.source.crypto,
    encryptObject: (...args) => {
      encryptions++;
      return encrypt(...args);
    },
  };
  const payload = f.source.crypto.createFilePayload(
    'synthetic.txt',
    'text/plain',
    Buffer.from('FILE'),
  );
  const grant = await f.source.call('POST', '/api/grants', {
    proof: await f.source.proof('grant'),
  });
  for (const bad of [
    refused('FILE_INSPECTION_DETECTED'),
    new Error('SECRET_PATH'),
    {},
    { ...clean(Buffer.from('OTHER')) },
    { ...clean(Buffer.from('FILE')), version: 2 },
    { ...clean(Buffer.from('FILE')), bytes: 5 },
    { ...clean(Buffer.from('FILE')), unrecognized: true },
    { ...clean(Buffer.from('FILE')), status: 'SKIPPED' },
  ]) {
    verdict = bad;
    await assert.rejects(f.source.sealUsingGrant(f.destination, payload, grant), (error) => {
      assert.match(error.message, /^FILE_INSPECTION_/);
      assert.equal(error.message.includes('SECRET_PATH'), false);
      return true;
    });
  }
  assert.equal(encryptions, 0);
  verdict = undefined;
  await f.source.sealUsingGrant(f.destination, payload, grant);
  assert.equal(encryptions, 1);
});

test('recipient inspection refusal exposes no document and never acknowledges delivery', async (t) => {
  const f = await endpointFixture(t, null);
  assert.equal(f.source.fileInspectionMode, 'UNSCANNED');
  const recipient = await f.make(f.profiles.bob, {
    inspect: async () => {
      throw refused('FILE_INSPECTION_DETECTED');
    },
  });
  const sealed = await f.source.seal(
    f.destination,
    f.source.crypto.createFilePayload(
      'synthetic.txt',
      'text/plain',
      Buffer.from('HIDDEN_SYNTHETIC'),
    ),
  );
  await f.source.submit(sealed);
  const inbox = new DocumentInbox({
    endpoint: recipient,
    senders: new Map([[f.profiles.alice.userId, f.profiles.alice.keys.signing.publicKey]]),
  });
  const outcomes = await inbox.poll();
  assert.deepEqual(outcomes, [
    { objectId: sealed.envelope.objectId, outcome: 'REFUSED', code: 'FILE_INSPECTION_DETECTED' },
  ]);
  assert.equal((await recipient.listObjects())[0].state, 'RELEASED');
  assert.equal(JSON.stringify(outcomes).includes('HIDDEN_SYNTHETIC'), false);
});

test('text remains explicitly outside file inspection and invalid inspector configuration is rejected', async () => {
  const settings = { url: 'https://synthetic.invalid', tls: {}, profile: {}, authorityKey: {} };
  assert.throws(() => new IntegrationEndpoint({ ...settings, fileInspector: {} }), /CONFIG/);
  const endpoint = new IntegrationEndpoint({
    ...settings,
    fileInspector: {
      inspect: () => {
        throw Error('not a file');
      },
    },
  });
  const text = endpoint.crypto.createTextPayload('SYNTHETIC_TEXT');
  assert.deepEqual(await endpoint.inspectPayload(text), text);
});
