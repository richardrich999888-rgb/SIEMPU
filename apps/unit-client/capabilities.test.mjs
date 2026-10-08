import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { can, capabilitiesFor, experienceFor } from './capabilities.mjs';

test('each role receives exactly the capabilities the authority enforces', () => {
  const matrix = {
    operator: ['exchange.receive', 'exchange.send'],
    viewer: ['exchange.receive'],
    admin: ['admin.manage', 'evidence.export'],
    auditor: ['evidence.export'],
  };
  for (const [role, expected] of Object.entries(matrix))
    assert.deepEqual([...capabilitiesFor({ role })].sort(), expected, role);
  assert.equal(
    can({ role: 'operator', dutyRole: 'UNIT_COMMANDER' }, 'exchange.approveFlash'),
    true,
  );
  assert.equal(
    can({ role: 'operator', dutyRole: 'SIGNALS_OFFICER' }, 'exchange.approveFlash'),
    false,
  );
  assert.equal(can({ role: 'viewer', dutyRole: 'UNIT_COMMANDER' }, 'exchange.approveFlash'), false);
  assert.equal(can({ role: 'admin' }, 'exchange.send'), false);
  assert.equal(can({ role: 'auditor' }, 'admin.manage'), false);
});

test('one interface per role; unknown and inherited roles get nothing', () => {
  assert.equal(experienceFor({ role: 'operator' }), 'unit-operator');
  assert.equal(experienceFor({ role: 'viewer' }), 'unit-operator');
  assert.equal(experienceFor({ role: 'admin' }), 'administrator');
  assert.equal(experienceFor({ role: 'auditor' }), 'security-evaluation');
  for (const user of [
    null,
    undefined,
    {},
    { role: 'root' },
    { role: '__proto__' },
    { role: 'toString' },
    { role: ['admin'] },
  ]) {
    assert.equal(experienceFor(user), null);
    assert.equal(capabilitiesFor(user).size, 0);
  }
});

test('role checks in the authority still match this model (drift guard)', () => {
  const core = readFileSync(new URL('../../services/control/core.mjs', import.meta.url), 'utf8');
  assert.match(core, /const roles = \['admin', 'operator', 'viewer', 'auditor'\];/);
  assert.match(core, /grant\(s\) \{\s*s = this\.bound\(s\);\s*this\.role\(s, \['operator'\]\);/);
  assert.match(
    core,
    /su\.role !== 'operator' \|\| !\['operator', 'viewer'\]\.includes\(ru\.role\)/,
  );
  assert.match(
    core,
    /change\(s, fn, eventType = 'AUTHORITY_CHANGED'\) \{[\s\S]{0,120}this\.role\(s, \['admin'\]\);/,
  );
  assert.match(
    core,
    /\/api\/evidence\/export'[\s\S]{0,200}this\.role\(s, \['admin', 'auditor'\]\);/,
  );
  assert.match(core, /s\.user\.dutyRole === 'UNIT_COMMANDER'/);
});
