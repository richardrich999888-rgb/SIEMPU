// Tests for the KAT harness (assurance/kat). Records written inline below are SYNTHETIC parser
// and plumbing fixtures with arbitrary values and fake adapters; they are not NIST vectors and
// make no conformance claim. Conformance cases come only from vendored files.

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { parseRsp } from '../assurance/kat/core/rsp.mjs';
import {
  STATUS,
  compareHex,
  compareDecision,
  setStatus,
  algorithmStatus,
} from '../assurance/kat/core/verdict.mjs';
import { renderMarkdown } from '../assurance/kat/core/report.mjs';
import { ALGORITHMS, STRUCTURAL_NOT_RUN } from '../assurance/kat/core/catalog.mjs';
import * as suites from '../assurance/kat/suites.mjs';
import {
  aesGcmFailureModes,
  ecdsaFailureModes,
  deterministicP256,
  pattern,
} from '../assurance/kat/failure-modes.mjs';
import { platform, fixedWidth } from '../assurance/kat/adapters/platform.mjs';
import { runKat } from '../assurance/kat/run.mjs';

const ROOT = resolve('.');

test('parseRsp: comments, accumulated sections, section reset, flags', () => {
  const text = [
    '# CAVS 99.0 (synthetic parser fixture)',
    '',
    '[Keylen = 256]',
    '[Taglen = 128]',
    '',
    'Count = 0',
    'Key = 00',
    '',
    'Count = 1',
    'Key = 01',
    'FAIL',
    '',
    '[Keylen = 128]',
    '',
    'Count = 0',
    'Key = 02',
  ].join('\n');
  const { comments, records } = parseRsp(text);
  assert.deepEqual(comments, ['CAVS 99.0 (synthetic parser fixture)']);
  assert.equal(records.length, 3);
  assert.deepEqual(records[0].section, { Keylen: '256', Taglen: '128' });
  assert.deepEqual(records[1].flags, ['FAIL']);
  // A header after records starts a new section (no stale Taglen).
  assert.deepEqual(records[2].section, { Keylen: '128' });
  assert.deepEqual(parseRsp('[P-256,SHA-256]\nMsg = aa\n').records[0].section, {
    label: 'P-256,SHA-256',
  });
});

test('parseRsp: fails closed on unknown lines and duplicate fields', () => {
  assert.throws(() => parseRsp('Count = 0\n%%garbage%%\n'), /Unrecognised/);
  assert.throws(() => parseRsp('Count = 0\nCount = 1\n'), /Duplicate/);
  assert.throws(() => parseRsp(42), TypeError);
});

test('verdicts: hex comparison, decisions, set and algorithm status', () => {
  assert.deepEqual(compareHex('ABCD', Uint8Array.of(0xab, 0xcd)), { pass: true, reason: null });
  assert.equal(compareHex('abce', Uint8Array.of(0xab, 0xcd)).pass, false);
  assert.equal(compareHex('zz', new Uint8Array(1)).pass, false);
  assert.equal(compareDecision(false, true).pass, false);
  assert.equal(compareDecision(true, true).pass, true);
  assert.equal(setStatus([]), STATUS.NOT_RUN);
  assert.equal(setStatus([{ pass: true }], 'reason'), STATUS.NOT_RUN);
  assert.equal(setStatus([{ pass: true }, { pass: false }]), STATUS.FAIL);
  assert.equal(algorithmStatus([STATUS.PASS, STATUS.FAIL]), STATUS.FAIL);
  assert.equal(algorithmStatus([STATUS.NOT_RUN, STATUS.PASS]), STATUS.PASS);
  // NOT-RUN alone is never promoted to PASS.
  assert.equal(algorithmStatus([STATUS.NOT_RUN]), STATUS.NOT_RUN);
});

test('sha256 suite: plumbing with a fake digest; Monte Carlo and bit-oriented files are NOT-RUN', async () => {
  const rsp = 'Len = 0\nMsg = 00\nMD = aa\n\nLen = 8\nMsg = 01\nMD = bb\n';
  const fake = async (msg) => Uint8Array.of(msg.length === 0 ? 0xaa : 0xbb);
  const ok = await suites.sha256Rsp(rsp, fake);
  assert.equal(ok.cases.length, 2);
  assert.ok(ok.cases.every((c) => c.pass));
  const bad = await suites.sha256Rsp(rsp, async () => Uint8Array.of(0));
  assert.equal(bad.failures.length, 2);
  assert.match(
    (await suites.sha256Rsp('Seed = 00\nCOUNT = 0\nMD = 00\n', fake)).notRunReason,
    /Monte/,
  );
  assert.match(
    (await suites.sha256Rsp('Len = 1\nMsg = 80\nMD = 00\n', fake)).notRunReason,
    /bit-oriented/,
  );
});

test('aes-gcm suite: a FAIL record passes only if decryption is rejected', async () => {
  const rsp =
    '[Keylen = 256]\n[Taglen = 128]\n\nCount = 0\nKey = 00\nIV = 00\nCT = \nAAD = \nTag = 00\nFAIL\n';
  const rejecting = {
    aesGcmDecrypt: async () => {
      throw new Error('auth');
    },
  };
  const accepting = { aesGcmDecrypt: async () => new Uint8Array(0) };
  assert.equal((await suites.aesGcmRsp(rsp, rejecting)).cases[0].pass, true);
  const r = await suites.aesGcmRsp(rsp, accepting);
  assert.equal(r.cases[0].pass, false);
  assert.match(r.failures[0].reason, /accepted an invalid case/);
});

test('ecdsa suite: only the [P-256,SHA-256] section is run; Result P/F maps to accept/reject', async () => {
  const rsp = [
    '[P-256,SHA-256]',
    '',
    'Msg = 00',
    'Qx = 01',
    'Qy = 02',
    'R = 03',
    'S = 04',
    'Result = F (3 - S changed)',
    '',
    '[P-384,SHA-384]',
    '',
    'Msg = 00',
    'Qx = 01',
    'Qy = 02',
    'R = 03',
    'S = 04',
    'Result = P (0 )',
  ].join('\n');
  const r = await suites.ecdsaSigVerRsp(rsp, async () => false);
  assert.equal(r.cases.length, 1);
  assert.equal(r.skipped, 1);
  assert.equal(r.cases[0].pass, true);
  assert.equal(fixedWidth('01', 32).length, 32);
  assert.throws(() => fixedWidth('00'.repeat(33), 32), RangeError);
});

test('failure-mode checks detect a broken implementation (they can fail)', async () => {
  const broken = {
    ...platform,
    aesGcmDecrypt: async () =>
      new TextEncoder().encode('SIEPMU KAT failure-mode plaintext (synthetic)'),
    ecdsaVerifyWeb: async () => true,
    ecdsaVerifyNode: async () => true,
  };
  const aes = await aesGcmFailureModes(broken);
  assert.equal(aes.filter((r) => r.status === STATUS.FAIL).length, 7);
  const ec = await ecdsaFailureModes(broken);
  assert.equal(ec.filter((r) => r.status === STATUS.FAIL).length, 8);
});

test('failure-mode checks pass on the real platform primitives', async () => {
  for (const r of [...(await aesGcmFailureModes(platform)), ...(await ecdsaFailureModes(platform))])
    assert.equal(r.status, STATUS.PASS, `${r.algorithm}: ${r.check}`);
});

test('deterministic inputs: P-256 keys and byte patterns are reproducible', () => {
  const a = deterministicP256('label');
  const b = deterministicP256('label');
  assert.deepEqual(a.qx, b.qx);
  assert.notDeepEqual(deterministicP256('other').qx, a.qx);
  assert.deepEqual([...pattern(3, 0xfe)], [0xfe, 0xff, 0x00]);
});

test('runner: missing operator vectors are NOT-RUN with a reason and never counted as passes', async () => {
  const run = await runKat({
    root: ROOT,
    listFiles: () => [],
    loadHybrid: async () => ({ module: null, version: null, reason: 'not installed (test)' }),
  });
  const byId = Object.fromEntries(run.algorithms.map((a) => [a.id, a]));
  for (const id of ['sha256', 'aes256gcm', 'hkdf', 'ecdsa', 'xwing', 'overlay']) {
    assert.equal(byId[id].status, STATUS.NOT_RUN, id);
    assert.ok(byId[id].sets.every((s) => typeof s.reason === 'string' && s.reason.length > 0));
  }
  assert.equal(byId.overlay.sets[0].reason, STRUCTURAL_NOT_RUN['overlay:combiner']);
  // Only executed cases are counted.
  assert.equal(run.summary.casesRun, 6);
});

test('runner: a failing operator vector file makes the campaign FAIL', async () => {
  const run = await runKat({
    root: ROOT,
    listFiles: (_root, dir) =>
      dir === 'vectors/sha256'
        ? [
            {
              path: 'vectors/sha256/synthetic.rsp',
              text: 'Len = 0\nMsg = 00\nMD = 00\n',
              sha256: '0'.repeat(64),
            },
          ]
        : [],
    loadHybrid: async () => ({ module: null, version: null, reason: 'n/a' }),
  });
  const sha = run.algorithms.find((a) => a.id === 'sha256');
  assert.equal(sha.status, STATUS.FAIL);
  assert.equal(run.summary.outcome, STATUS.FAIL);
});

test('vendored campaign: published NIST ACVP keyGen and X-Wing author vectors pass', async () => {
  const run = await runKat({ root: ROOT });
  const byId = Object.fromEntries(run.algorithms.map((a) => [a.id, a]));
  for (const id of ['mlkem768', 'mlkem1024', 'mldsa65']) {
    const keygen = byId[id].sets[0];
    assert.equal(keygen.status, STATUS.PASS, id);
    assert.equal(keygen.cases, 2, id);
  }
  assert.ok(run.failureModes.every((f) => f.status === STATUS.PASS));
  assert.equal(ALGORITHMS.length, run.algorithms.length);
});

test('report: generated text carries the scope disclaimer and never claims validation', async () => {
  const run = await runKat({ root: ROOT, listFiles: () => [] });
  const md = renderMarkdown({
    ...run,
    revision: { commit: 'f'.repeat(40), dirty: false },
    command: 'node assurance/kat/run.mjs',
    startedAt: '2026-01-01T00:00:00.000Z',
    runtime: { 'Node.js': 'test' },
  });
  assert.match(md, /\*\*not\*\* CAVP\/ACVP algorithm validation/);
  assert.match(md, /\*\*not\*\* FIPS 140-3 module validation/);
  assert.match(md, /NOT-RUN/);
  assert.doesNotMatch(md, /\b(?:FIPS validated|SAG graded|SAG approved|certified)\b/i);
});

test('readBounded: reads exactly, fails closed above the limit and on non-files', async () => {
  const { readBounded, readVectorFile } = await import('../assurance/kat/io/sources.mjs');
  const { mkdtempSync, writeFileSync, openSync, closeSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'siepmu-kat-read-'));
  try {
    const data = Buffer.from(pattern(200000, 7));
    writeFileSync(join(dir, 'v.bin'), data);
    const fd = openSync(join(dir, 'v.bin'), 'r');
    try {
      assert.deepEqual(readBounded(fd, 200000), data);
    } finally {
      closeSync(fd);
    }
    const fd2 = openSync(join(dir, 'v.bin'), 'r');
    try {
      assert.throws(() => readBounded(fd2, 199999), /exceeds/);
    } finally {
      closeSync(fd2);
    }
    const dirFd = openSync(dir, 'r');
    try {
      assert.throws(() => readBounded(dirFd, 10), /Not a regular file/);
    } finally {
      closeSync(dirFd);
    }
    assert.equal(readVectorFile(dir, 'v.bin').text.length > 0, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
