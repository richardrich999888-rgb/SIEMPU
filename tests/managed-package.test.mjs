import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  copyFileSync,
  writeFileSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildCompanion, sourceFiles } from '../integrations/managed-endpoint/bundle.mjs';
import { verifyCompanion } from '../integrations/managed-endpoint/verify.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'siepmu-managed-package-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const files = [
    ...sourceFiles,
    ...['package.json', 'README.md', 'verify.mjs', 'self-test.mjs'].map(
      (p) => 'integrations/managed-endpoint/' + p,
    ),
    'LICENSE',
  ];
  for (const file of files) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    copyFileSync(file, join(root, file));
  }
  writeFileSync(join(root, '.gitignore'), 'artifacts/\n.data/\n');
  const git = (...args) => execFileSync('git', args, { cwd: root, stdio: 'pipe' });
  git('init', '-q');
  git('add', '.');
  git(
    '-c',
    'user.name=Laboratory fixture',
    '-c',
    'user.email=fixture@example.invalid',
    'commit',
    '-qm',
    'Synthetic packaging fixture',
  );
  return { root, git };
}

test('standalone package resolves its import closure outside the repository and excludes runtime secrets', (t) => {
  const { root } = fixture(t);
  mkdirSync(join(root, '.data'));
  writeFileSync(join(root, '.data/server-key.json'), 'SYNTHETIC SECRET MUST NOT SHIP');
  const result = buildCompanion(root, 'artifacts/companion');
  assert.equal(
    verifyCompanion(result.package, result.manifestSha256).integrity,
    'MATCHES_EXPECTED_DIGEST',
  );
  const manifest = JSON.parse(readFileSync(join(result.package, 'manifest.json')));
  assert.equal(
    manifest.files.some((f) => /server-key|\.data|core\.mjs|server\.mjs|\.html$/.test(f.path)),
    false,
  );
  assert.equal(
    JSON.parse(readFileSync(join(result.package, 'package.json'))).dependencies,
    undefined,
  );
  const output = execFileSync(process.execPath, ['--test', 'self-test.mjs'], {
    cwd: result.package,
    encoding: 'utf8',
    timeout: 30000,
    env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
  });
  assert.match(output, /pass 5/);
  assert.throws(() => verifyCompanion(result.package), /INTEGRITY/);
});

test('separate verifier refuses changed bytes, unlisted files and symlinks', (t) => {
  const { root } = fixture(t),
    result = buildCompanion(root, 'artifacts/companion');
  const file = join(result.package, 'index.mjs'),
    original = readFileSync(file);
  writeFileSync(file, Buffer.concat([original, Buffer.from('// changed')]));
  assert.throws(() => verifyCompanion(result.package, result.manifestSha256), /INTEGRITY/);
  writeFileSync(file, original);
  const extra = join(result.package, 'unexpected');
  writeFileSync(extra, 'unlisted');
  assert.throws(() => verifyCompanion(result.package, result.manifestSha256), /INTEGRITY/);
  rmSync(extra);
  symlinkSync(file, extra);
  assert.throws(() => verifyCompanion(result.package, result.manifestSha256), /INTEGRITY/);
});

test('builder refuses dirty and Git-hidden source edits', (t) => {
  const { root, git } = fixture(t),
    file = sourceFiles[0];
  writeFileSync(join(root, file), '// changed');
  assert.throws(() => buildCompanion(root, 'artifacts/dirty'), /CLEAN_COMMITTED/);
  git('update-index', '--assume-unchanged', file);
  assert.throws(() => buildCompanion(root, 'artifacts/hidden'), /SOURCE_DIFFERS/);
});
