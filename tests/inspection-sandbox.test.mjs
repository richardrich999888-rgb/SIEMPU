import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BubblewrapSandbox } from '../packages/file-inspection/sandbox.mjs';
import { ClamAvInspector } from '../packages/file-inspection/clamav.mjs';
const digest = (b) => createHash('sha256').update(b).digest('hex');
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-sandbox-contract-'));
  const temp = mkdtempSync('/dev/shm/siepmu-sandbox-contract-');
  t.after(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(temp, { recursive: true, force: true });
  });
  const runtimeRoot = join(root, 'image');
  mkdirSync(runtimeRoot);
  mkdirSync(join(runtimeRoot, 'bin'));
  const code = '#!/bin/sh\nexit 99\n';
  const executable = join(runtimeRoot, 'bin/clamscan');
  writeFileSync(executable, code, { mode: 0o755 });
  const bwrap = join(root, 'bwrap'),
    prlimit = join(root, 'prlimit');
  for (const path of [bwrap, prlimit]) writeFileSync(path, code, { mode: 0o755 });
  const database = join(root, 'database');
  mkdirSync(database);
  const config = {
    bwrap,
    bwrapSha256: digest(code),
    prlimit,
    prlimitSha256: digest(code),
    runtimeRoot,
    files: { 'bin/clamscan': digest(code) },
  };
  return {
    root,
    temp,
    executable,
    database,
    config,
    call: { executable, database, directory: temp, timeoutMs: 10000 },
    args: ['--database=' + database, '--tempdir=' + temp, '-'],
  };
}
test('sandbox command contains a private namespace, exact image, bounded tmpfs and no inherited environment', async (t) => {
  const f = fixture(t);
  const command = await new BubblewrapSandbox(f.config).prepare(f.args, f.call);
  assert.equal(command.executable, f.config.prlimit);
  for (const flag of [
    '--unshare-all',
    '--clearenv',
    '--die-with-parent',
    '--new-session',
    '--core=0',
    '--as=4294967296',
    '--fsize=16777216',
    '--nofile=128',
  ])
    assert.ok(command.args.includes(flag));
  assert.deepEqual(
    command.args.slice(command.args.indexOf('--size'), command.args.indexOf('--size') + 4),
    ['--size', '16777216', '--tmpfs', '/tmp'],
  );
  assert.ok(command.args.includes('--database=/signatures'));
  assert.ok(command.args.includes('--tempdir=/tmp'));
  assert.equal(command.args.includes('--bind'), false);
});
test('sandbox refuses unreviewed paths, hashes, writable tools, foreign files and symlinks', async (t) => {
  const f = fixture(t);
  for (const change of [
    { runtimeRoot: '/' },
    { bwrap: 'bwrap' },
    { bwrapSha256: 'x' },
    { files: { 'bin/../secret': digest('a') } },
    { files: {} },
  ])
    assert.throws(() => new BubblewrapSandbox({ ...f.config, ...change }), /CONFIG/);
  await assert.rejects(
    new BubblewrapSandbox({ ...f.config, bwrapSha256: '0'.repeat(64) }).prepare(f.args, f.call),
    /CHANGED/,
  );
  chmodSync(f.config.bwrap, 0o777);
  await assert.rejects(new BubblewrapSandbox(f.config).prepare(f.args, f.call), /CHANGED/);
  chmodSync(f.config.bwrap, 0o755);
  const extra = join(f.config.runtimeRoot, 'bin/extra');
  writeFileSync(extra, 'unreviewed');
  await assert.rejects(new BubblewrapSandbox(f.config).prepare(f.args, f.call), /CHANGED/);
  rmSync(extra);
  symlinkSync(f.executable, extra);
  await assert.rejects(new BubblewrapSandbox(f.config).prepare(f.args, f.call), /CHANGED/);
  rmSync(extra);
  await assert.rejects(
    new BubblewrapSandbox({
      ...f.config,
      files: { ...f.config.files, 'bin/missing': digest('') },
    }).prepare(f.args, f.call),
    /CHANGED/,
  );
  await assert.rejects(
    new BubblewrapSandbox(f.config).prepare(f.args, { ...f.call, executable: '/bin/true' }),
    /CONFIG/,
  );
  chmodSync(f.temp, 0o755);
  await assert.rejects(new BubblewrapSandbox(f.config).prepare(f.args, f.call), /TEMP/);
});
test('a selected sandbox cannot fall back when its launcher refuses to start', async (t) => {
  const f = fixture(t);
  const inspector = new ClamAvInspector({
    executable: f.executable,
    executableSha256: f.config.files['bin/clamscan'],
    database: f.database,
    tempRoot: f.temp,
    sandbox: new BubblewrapSandbox(f.config),
  });
  await assert.rejects(
    inspector.inspect(Buffer.from('synthetic')),
    /FILE_INSPECTION_INCOMPLETE|FILE_INSPECTION_IO/,
  );
  assert.throws(
    () =>
      new ClamAvInspector({
        executable: f.executable,
        executableSha256: digest(''),
        database: f.database,
        tempRoot: f.temp,
        sandbox: {},
      }),
    /CONFIG/,
  );
});
