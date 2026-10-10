// Tests for scripts/check-claims.sh. Each case builds a throwaway git repository so that no
// violating phrase is ever tracked in this repository.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SCRIPT = resolve('scripts/check-claims.sh');

/** Runs the gate over a temporary repository holding `files` (and an optional allow list). */
function gate(files, allow = null) {
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-claims-'));
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    for (const [name, text] of Object.entries(files)) {
      mkdirSync(join(dir, name, '..'), { recursive: true });
      writeFileSync(join(dir, name), text);
    }
    if (allow !== null) {
      mkdirSync(join(dir, 'scripts'), { recursive: true });
      writeFileSync(join(dir, 'scripts/check-claims.allow'), allow);
    }
    execFileSync('git', ['add', '-A'], { cwd: dir });
    const r = spawnSync('bash', [SCRIPT, dir], { encoding: 'utf8' });
    return { status: r.status, out: r.stdout + r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('unqualified assertions fail, in any case and with or without a hyphen', () => {
  for (const line of [
    'The module is FIPS validated.',
    'Uses a fips-validated provider.',
    'SAG-graded encryption is provided.',
    'The suite is SAG approved for use.',
    'Status: SAG graded',
  ]) {
    const r = gate({ 'doc.md': `${line}\n` });
    assert.equal(r.status, 1, line);
    assert.match(r.out, /unqualified assurance claim at doc\.md:1/);
  }
});

test('negated statements pass', () => {
  for (const line of [
    'This prototype is not FIPS validated.',
    'We never claim SAG graded status.',
    'No component is SAG-approved.',
    "It isn't FIPS-validated yet.",
    'Avoid "SAG graded" in all material.',
  ])
    assert.equal(gate({ 'doc.md': `${line}\n` }).status, 0, line);
});

test('unrelated text and untracked files are ignored', () => {
  assert.equal(
    gate({ 'doc.md': 'FIPS 203 ML-KEM and SAGA pattern; validated input.\n' }).status,
    0,
  );
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-claims-untracked-'));
  try {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    writeFileSync(join(dir, 'untracked.md'), 'The module is FIPS validated.\n');
    assert.equal(spawnSync('bash', [SCRIPT, dir]).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('allow list: a justified entry passes; a stale or malformed entry fails', () => {
  const files = { 'req.md': '8. SAG-graded encryption\n' };
  assert.equal(gate(files, 'req.md\t8. SAG-graded encryption\tquotes the requirement\n').status, 0);
  const stale = gate(files, 'req.md\t8. SAG-graded encryption\tok\nother.md\tgone\tstale\n');
  assert.equal(stale.status, 1);
  assert.match(stale.out, /stale allow entry/);
  assert.equal(gate(files, 'req.md\tmissing justification\n').status, 2);
  // An allow entry for one file does not cover the same text in another file.
  assert.equal(
    gate(
      { ...files, 'other.md': '8. SAG-graded encryption\n' },
      'req.md\t8. SAG-graded encryption\tok\n',
    ).status,
    1,
  );
});

test('the repository itself passes the gate', () => {
  const r = spawnSync('bash', [SCRIPT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});
