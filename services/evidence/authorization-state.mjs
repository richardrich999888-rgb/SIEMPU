import { canonical, hash, packet, verifyPacket } from '../control/primitives.mjs';
import { exactMembers } from './incremental.mjs';

// Fresh local database observation only: this is NOT a signed checkpoint or a trust root.
// Local comparisons need the head bytes, not a new signature that is immediately discarded.
// Never cache this result: transaction rollback and out-of-band changes must remain visible.
export function readEvidenceHead(authority) {
  const last = authority.get('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1');
  return { sequence: last?.sequence ?? 0, headHash: last?.hash ?? '0'.repeat(64) };
}

/**
 * Versioned digest of authentication and release-policy state. Challenge creation/consumption
 * and session changes have evidence events, so an unchanged head cannot hide their rollback.
 * Credentials stay inside this hash; they are never exported to the custodian or audit log.
 * A legacy digest is deliberately not accepted as an equivalent state (see ADR-017).
 */
export function authorizationDigest(authority) {
  return hash(
    canonical({
      profile: 'SIEPMU_AUTHORIZATION_STATE_V2',
      authority: authority.epoch(),
      users: authority.all(
        'SELECT id,username,password,totp,totp_floor,unit_id,role,missions,active,duty_role FROM users ORDER BY id',
      ),
      devices: authority.all(
        'SELECT id,user_id,signing_key,encryption_key,status FROM devices ORDER BY id',
      ),
      policies: authority.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id'),
      sessions: authority.all('SELECT * FROM sessions ORDER BY id'),
      challenges: authority.all('SELECT * FROM challenges ORDER BY id'),
      cryptoPolicy: authority.all('SELECT * FROM crypto_policy ORDER BY id'),
      cryptoKeys: authority.all('SELECT * FROM crypto_keys ORDER BY key_id'),
      releaseApprovals: authority.all('SELECT * FROM release_approvals ORDER BY object_id'),
      allowPqcLab: authority.crypto.allowPqcLab,
    }),
  );
}
/** A commit seal is made within the SAME SQLite transaction as the state and history.
 * Never generate a seal during recovery: that would sign attacker-restored state. */
export function sealAuthorizationCommit(authority) {
  const head = readEvidenceHead(authority);
  const commit = packet(authority.key, {
    version: 1,
    kind: 'AUTHORIZATION_COMMIT',
    sequence: head.sequence,
    headHash: head.headHash,
    stateDigest: authorizationDigest(authority),
  });
  authority.run(
    'INSERT INTO authorization_commit VALUES(1,?) ON CONFLICT(id) DO UPDATE SET seal=excluded.seal',
    canonical(commit),
  );
}
export function assertAuthorizationCommit(authority) {
  const row = authority.get('SELECT seal FROM authorization_commit WHERE id=1');
  if (!row) throw new Error('AUTHORIZATION_COMMIT_MISSING');
  const seal = JSON.parse(row.seal),
    p = seal.payload,
    head = readEvidenceHead(authority);
  if (
    !verifyPacket(authority.publicKey, seal) ||
    !exactMembers(p, ['version', 'kind', 'sequence', 'headHash', 'stateDigest']) ||
    p.version !== 1 ||
    p.kind !== 'AUTHORIZATION_COMMIT' ||
    p.sequence !== head.sequence ||
    p.headHash !== head.headHash ||
    p.stateDigest !== authorizationDigest(authority)
  )
    throw new Error('AUTHORIZATION_COMMIT_MISMATCH');
}
