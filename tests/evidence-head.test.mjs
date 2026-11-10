import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { coreFixture } from './helpers/fixture.mjs';
import { pair } from './helpers/client.mjs';
import { verifyPacket } from '../services/control/primitives.mjs';
import {
  readEvidenceHead,
  assertAuthorizationCommit,
} from '../services/evidence/authorization-state.mjs';
import { CheckpointCustodian, createRecoveryGuard } from '../services/evidence/custody.mjs';

test('local state checks avoid throwaway checkpoints while seals and exported checkpoints stay signed', async (t) => {
  const f = await coreFixture(t);
  const checkpoint = f.authority.checkpoint.bind(f.authority);
  f.authority.checkpoint = () => {
    throw new Error('UNNECESSARY_CHECKPOINT_SIGNATURE');
  };
  assertAuthorizationCommit(f.authority);
  f.authority.tx(() => f.authority.event('SYNTHETIC_HEAD_TEST', 'test'));
  assertAuthorizationCommit(f.authority);
  const seal = JSON.parse(f.authority.get('SELECT seal FROM authorization_commit WHERE id=1').seal);
  assert.equal(verifyPacket(f.authority.publicKey, seal), true);
  const signed = checkpoint();
  assert.equal(verifyPacket(f.authority.publicKey, signed), true);
  assert.deepEqual(readEvidenceHead(f.authority), {
    sequence: signed.payload.sequence,
    headHash: signed.payload.headHash,
  });
  signed.payload.headHash = 'f'.repeat(64);
  assert.equal(verifyPacket(f.authority.publicKey, signed), false);
});

test('head observation follows transaction rollback and independent SQLite writes without caching', async (t) => {
  const f = await coreFixture(t);
  const before = readEvidenceHead(f.authority);
  assert.throws(
    () =>
      f.authority.tx(() => {
        f.authority.event('SYNTHETIC_ROLLED_BACK', 'test');
        assert.equal(readEvidenceHead(f.authority).sequence, before.sequence + 1);
        throw new Error('INTERRUPTED');
      }),
    /INTERRUPTED/,
  );
  assert.deepEqual(readEvidenceHead(f.authority), before);
  assertAuthorizationCommit(f.authority);
  const other = new DatabaseSync(join(f.dir, 'control.sqlite'));
  t.after(() => other.close());
  other.prepare('UPDATE evidence SET hash=? WHERE sequence=?').run('e'.repeat(64), before.sequence);
  assert.equal(readEvidenceHead(f.authority).headHash, 'e'.repeat(64));
  assert.throws(() => assertAuthorizationCommit(f.authority), /AUTHORIZATION_COMMIT_MISMATCH/);
});

for (const incremental of [false, true]) {
  test(`${incremental ? 'incremental' : 'full'} custody still rejects changed heads after a valid lease`, async (t) => {
    const f = await coreFixture(t);
    const key = pair();
    const custodian = new CheckpointCustodian({
      database: ':memory:',
      authorityKey: f.authority.publicKey,
      signingKey: key.privateKey,
      allowBootstrap: true,
    });
    t.after(() => custodian.close());
    const guard = createRecoveryGuard({
      custodianKey: key.publicKey,
      exchange: (r) => custodian.accept(r),
      ...(incremental ? { anchorQuery: (r) => custodian.anchor(r) } : {}),
    });
    f.authority.recoveryGuard = guard;
    await guard.authorize(f.authority);
    assert.equal(guard.allows(f.authority), true);
    f.authority.run(
      'UPDATE evidence SET hash=? WHERE sequence=?',
      'd'.repeat(64),
      readEvidenceHead(f.authority).sequence,
    );
    assert.equal(guard.allows(f.authority), false);
    await assert.rejects(guard.authorize(f.authority), { code: 'RECOVERY_QUARANTINED' });
    assert.equal(guard.state, 'QUARANTINED');
    assert.equal(guard.reason, 'AUTHORIZATION_COMMIT_MISMATCH');
  });
}
