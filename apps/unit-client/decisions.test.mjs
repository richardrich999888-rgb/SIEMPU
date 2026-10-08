import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { EXPLAINED_CODES, decisionSummary, describeState, explainDecision } from './decisions.mjs';

const source = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
/** Every decision code the authority can emit, read from its sources so new codes fail here. */
function emittedCodes() {
  const codes = new Set();
  for (const path of [
    'services/control/core.mjs',
    'services/crypto-policy/registry.mjs',
    'services/admission/integrity.mjs',
  ]) {
    const text = source(path);
    for (const m of text.matchAll(/return '([A-Z][A-Z0-9_]+)'/g)) codes.add(m[1]);
    for (const m of text.matchAll(/\? null : '([A-Z][A-Z0-9_]+)'/g)) codes.add(m[1]);
  }
  const core = source('services/control/core.mjs');
  for (const code of ['EPOCH_MISMATCH', 'RECOVERY_QUARANTINED']) {
    assert.ok(core.includes(`'${code}'`), `${code} no longer emitted; update this test`);
    codes.add(code);
  }
  return codes;
}

test('every decision code emitted by the authority has an explanation', () => {
  const emitted = emittedCodes();
  assert.ok(emitted.size >= 30, `scan found only ${emitted.size} codes`);
  const missing = [...emitted].filter((code) => !EXPLAINED_CODES.includes(code));
  assert.deepEqual(missing, []);
  const stale = EXPLAINED_CODES.filter((code) => !emitted.has(code));
  assert.deepEqual(stale, [], 'explanations for codes the authority no longer emits');
});

test('explanations are complete, bounded and route to a defined action', () => {
  for (const code of EXPLAINED_CODES) {
    const d = explainDecision(code);
    assert.equal(d.code, code);
    for (const text of [d.title, d.explanation, d.guidance]) {
      assert.equal(typeof text, 'string');
      assert.ok(text.length > 5 && text.length <= 140, `${code}: ${text}`);
    }
    assert.ok(['retry', 'resend', 'administrator', 'security', 'wait'].includes(d.action));
    assert.ok(['info', 'warning', 'blocked'].includes(d.severity));
  }
  assert.equal(explainDecision('EPOCH_MISMATCH').action, 'retry');
  assert.equal(explainDecision('USER_REVOKED').action, 'administrator');
  assert.equal(explainDecision('OBJECT_SIGNATURE_INVALID').severity, 'blocked');
  assert.equal(explainDecision('RECOVERY_QUARANTINED').action, 'wait');
});

test('unknown, malformed and hostile codes fail safe without echoing arbitrary text', () => {
  for (const code of [
    undefined,
    null,
    42,
    {},
    '',
    'lowercase',
    '__proto__',
    'constructor',
    'toString',
  ]) {
    const d = explainDecision(code);
    assert.equal(d.title, 'Held by the authority');
    assert.equal(d.severity, 'blocked');
    assert.equal(d.code, 'UNKNOWN');
  }
  const injected = explainDecision('<img src=x onerror=alert(1)>');
  assert.equal(injected.code, 'UNKNOWN');
  assert.equal(explainDecision('NEW_FUTURE_CODE').code, 'NEW_FUTURE_CODE');
  assert.equal(explainDecision('NEW_FUTURE_CODE').title, 'Held by the authority');
});

test('state descriptions never present an unknown state as released', () => {
  for (const state of ['PENDING', 'READY', 'HELD', 'RELEASED', 'DELIVERED'])
    assert.notEqual(describeState(state), describeState('BOGUS'));
  assert.match(describeState('BOGUS'), /not released/);
  assert.match(describeState('hasOwnProperty'), /not released/);
});

test('summary carries title, code and guidance only', () => {
  assert.equal(
    decisionSummary('USER_REVOKED'),
    'Account deactivated (USER_REVOKED). Contact your administrator. The object stays held until authority changes.',
  );
});
