// Opt-in real namespace test. Failure to create isolation is a failure, never a skip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, cpSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { BubblewrapSandbox } from '../../packages/file-inspection/sandbox.mjs';
import { ClamAvInspector } from '../../packages/file-inspection/clamav.mjs';
test('actual Linux namespace denies network, host files and writes and applies resource limits', async (t) => {
  const settings = JSON.parse(readFileSync(process.env.SIEPMU_CLAMAV_CONFIG, 'utf8'));
  const original = settings.sandbox.runtimeRoot,
    root = original + '-probe';
  cpSync(original, root, { recursive: true, errorOnExist: true, force: false });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const built = spawnSync(
    'gcc',
    [
      '-O2',
      '-Wall',
      '-Wextra',
      '-Werror',
      'tests/file-inspection/isolation-probe.c',
      '-o',
      join(root, 'bin/clamscan'),
    ],
    { encoding: 'utf8' },
  );
  assert.equal(built.status, 0, 'native isolation probe did not compile');
  settings.executable = join(root, 'bin/clamscan');
  settings.executableSha256 = createHash('sha256')
    .update(readFileSync(settings.executable))
    .digest('hex');
  settings.sandbox.runtimeRoot = root;
  settings.sandbox.files['bin/clamscan'] = settings.executableSha256;
  // Synthetic probe only: diagnose namespace/loader setup without processing user content.
  const profile = new BubblewrapSandbox(settings.sandbox);
  const command = await profile.prepare([], {
    ...settings,
    directory: settings.tempRoot,
    timeoutMs: 10000,
  });
  const preflight = spawnSync(command.executable, command.args, {
    input: Buffer.alloc(0),
    env: { LANG: 'C', PATH: '/usr/bin:/bin' },
    timeout: 10000,
    encoding: 'utf8',
  });
  assert.equal(
    preflight.status,
    0,
    `Synthetic isolation preflight: ${preflight.stderr?.slice(0, 2048) ?? 'no diagnostics'}`,
  );
  const inspector = new ClamAvInspector({
    ...settings,
    sandbox: new BubblewrapSandbox(settings.sandbox),
  });
  assert.equal((await inspector.inspect(Buffer.from('SYNTHETIC'))).status, 'NO_THREAT_DETECTED');
  writeFileSync(join(root, 'bin/unreviewed'), 'synthetic');
  await assert.rejects(inspector.inspect(Buffer.from('SYNTHETIC')), /SANDBOX_CHANGED/);
});
