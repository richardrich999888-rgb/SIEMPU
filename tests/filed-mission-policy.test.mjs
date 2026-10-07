import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MESSAGE_PRIORITIES,
  MESSAGE_DOMAINS,
  DUTY_ROLES,
  validMissionProfile,
  compatibleDutyRole,
  dutyMessageAllowed,
  senderDutyAllowed,
  recipientDutyAllowed,
} from '../packages/mission/policy.mjs';

test('filed annexure has exactly six duty roles and four priority tiers', () => {
  assert.deepEqual(DUTY_ROLES, [
    'UNIT_COMMANDER',
    'SIGNALS_OFFICER',
    'INTELLIGENCE_ANALYST',
    'FIELD_OPERATOR',
    'AUDIT_OFFICER',
    'SYSTEM_ADMIN',
  ]);
  assert.deepEqual(MESSAGE_PRIORITIES, [
    'FLASH',
    'IMMEDIATE',
    'PRIORITY',
    'ROUTINE',
  ]);
  assert.deepEqual(MESSAGE_DOMAINS, ['GENERAL', 'INTEL']);
});

test('filed priority policy denies forbidden roles and tiers', () => {
  assert.equal(dutyMessageAllowed('UNIT_COMMANDER', 'FLASH', 'GENERAL'), true);
  assert.equal(dutyMessageAllowed('SIGNALS_OFFICER', 'FLASH', 'INTEL'), true);
  assert.equal(dutyMessageAllowed('FIELD_OPERATOR', 'FLASH', 'GENERAL'), false);
  assert.equal(dutyMessageAllowed('FIELD_OPERATOR', 'IMMEDIATE', 'GENERAL'), false);
  assert.equal(dutyMessageAllowed('FIELD_OPERATOR', 'PRIORITY', 'GENERAL'), true);
  assert.equal(dutyMessageAllowed('FIELD_OPERATOR', 'PRIORITY', 'INTEL'), false);
  assert.equal(dutyMessageAllowed('INTELLIGENCE_ANALYST', 'IMMEDIATE', 'INTEL'), true);
  assert.equal(dutyMessageAllowed('INTELLIGENCE_ANALYST', 'FLASH', 'INTEL'), false);
  assert.equal(dutyMessageAllowed('INTELLIGENCE_ANALYST', 'PRIORITY', 'GENERAL'), false);
  for (const role of ['AUDIT_OFFICER', 'SYSTEM_ADMIN'])
    for (const priority of MESSAGE_PRIORITIES)
      assert.equal(dutyMessageAllowed(role, priority, 'GENERAL'), false);
});

test('unknown profiles and role spoofing fail closed', () => {
  assert.equal(validMissionProfile('ROUTINE', 'GENERAL'), true);
  for (const value of ['flash', 'UNCLASSIFIED', '*', '__proto__', '', null])
    assert.equal(validMissionProfile(value, 'GENERAL'), false);
  assert.equal(dutyMessageAllowed('__proto__', 'FLASH', 'GENERAL'), false);
  assert.equal(compatibleDutyRole('admin', 'UNIT_COMMANDER'), false);
  assert.equal(compatibleDutyRole('viewer', 'SYSTEM_ADMIN'), false);
  assert.equal(compatibleDutyRole('auditor', 'AUDIT_OFFICER'), true);
  assert.equal(senderDutyAllowed('viewer', 'UNIT_COMMANDER', 'ROUTINE', 'GENERAL'), false);
  assert.equal(recipientDutyAllowed('auditor', 'UNIT_COMMANDER', 'ROUTINE', 'GENERAL'), false);
  assert.equal(recipientDutyAllowed('viewer', 'FIELD_OPERATOR', 'ROUTINE', 'GENERAL'), true);
});
