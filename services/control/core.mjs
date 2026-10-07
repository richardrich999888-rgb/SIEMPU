import { buildInfo } from './build-info.mjs';
import {
  DUTY_ROLES,
  validMissionProfile,
  compatibleDutyRole,
  senderDutyAllowed,
  recipientDutyAllowed,
} from '../../packages/mission/policy.mjs';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { randomUUID, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  canonical,
  hash,
  decode,
  publicJwk,
  validateKey,
  keyId,
  verify,
  packet,
  verifyPacket,
  passwordHash,
  passwordCheck,
  seal,
  unseal,
  base32,
  totpCounter,
} from './primitives.mjs';
export class AppError extends Error {
  constructor(status, code, message = code, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}
export const fail = (status, code, message, extra) => {
  throw new AppError(status, code, message, extra);
};
const assert = (v, code = 'INVALID_INPUT', status = 400) => {
  if (!v) fail(status, code);
};
const str = (v, max = 150) => typeof v === 'string' && v.length > 0 && v.length <= max;
const roles = ['admin', 'operator', 'viewer', 'auditor'];
const mission = (v) => typeof v === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(v);
const uuid = (v) =>
  typeof v === 'string' &&
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const parse = (v) => JSON.parse(v);

// Public capabilities are explicitly dispatched and cannot select protected
// handlers. Login itself always checks password and MFA before issuing a session.
const publicHealth = (authority) => {
  authority.get('SELECT 1');
  return { status: 200, body: { status: 'ok', service: 'control', version: '0.1.0' } };
};
const publicMetadata = (authority) => ({
  status: 200,
  body: {
    version: '0.1.0',
    build: buildInfo(),
    serverPublicKey: authority.publicKey,
    serverKeyId: keyId(authority.publicKey),
    limits: { objectBytes: 1048576, sessionSeconds: 900, grantSeconds: 3600 },
    securityProfile: 'PROTOTYPE / software device keys / no SAG approval',
  },
});
const publicLogin = (authority, body, context) => ({
  status: 200,
  body: authority.login(body, context.ip ?? 'local'),
});
export class Authority {
  constructor({ dbPath, signingKey, masterKey, hooks = {}, relay }) {
    this.key = signingKey;
    this.publicKey = publicJwk(signingKey);
    this.masterKey = masterKey;
    this.hooks = hooks;
    this.relay = relay;
    this.db = new DatabaseSync(dbPath);
    this.db.exec(
      'PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;',
    );
    this.migrate();
    this.dummyPassword = passwordHash(randomBytes(20).toString('hex'));
  }
  migrate() {
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)',
    );
    const dir = fileURLToPath(new URL('../../database/migrations/', import.meta.url));
    for (const name of readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .sort()) {
      const sql = readFileSync(dir + name, 'utf8'),
        digest = hash(sql),
        old = this.get('SELECT * FROM schema_migrations WHERE version=?', name);
      if (old) {
        if (old.checksum !== digest) throw new Error('Migration checksum mismatch');
        continue;
      }
      this.tx(() => {
        this.db.exec(sql);
        this.run('INSERT INTO schema_migrations VALUES(?,?,?)', name, digest, Date.now());
      });
    }
  }
  get(sql, ...args) {
    return this.db.prepare(sql).get(...args);
  }
  all(sql, ...args) {
    return this.db.prepare(sql).all(...args);
  }
  run(sql, ...args) {
    return this.db.prepare(sql).run(...args);
  }
  close() {
    this.db.close();
  }
  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn();
      this.db.exec('COMMIT');
      return r;
    } catch (e) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      throw e;
    }
  }
  epoch() {
    return this.get('SELECT * FROM authority WHERE id=1');
  }
  policyDigest() {
    return hash(
      canonical(this.all('SELECT * FROM policies ORDER BY from_unit,to_unit,mission_id')),
    );
  }
  user(row) {
    return row
      ? {
          id: row.id,
          username: row.username,
          unitId: row.unit_id,
          role: row.role,
          dutyRole: row.duty_role ?? null,
          missionIds: parse(row.missions),
          active: !!row.active,
        }
      : null;
  }
  device(row) {
    return row
      ? {
          id: row.id,
          userId: row.user_id,
          unitId: this.get('SELECT unit_id FROM users WHERE id=?', row.user_id).unit_id,
          label: row.label,
          status: row.status,
          signingPublicKey: parse(row.signing_key),
          encryptionPublicKey: parse(row.encryption_key),
          createdAt: row.created_at,
        }
      : null;
  }
  object(row) {
    if (!row) return null;
    const e = parse(row.envelope);
    return {
      id: row.id,
      objectId: row.id,
      senderUserId: row.sender_id,
      recipientUserId: row.recipient_id,
      senderDeviceId: row.sender_device,
      recipientDeviceId: row.recipient_device,
      senderUnitId: e.senderUnitId,
      recipientUnitId: e.recipientUnitId,
      missionId: e.missionId,
      classification: e.classification,
      messagePriority: e.messagePriority ?? null,
      messageDomain: e.messageDomain ?? null,
      state: row.state,
      reason: row.reason,
      preparedEpoch: row.prepared_epoch,
      ciphertextHash: row.digest,
      createdAt: row.created_at,
      expiresAt: e.expiresAt,
    };
  }
  count(name) {
    this.run(
      'INSERT INTO counters(name,value) VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1',
      name,
    );
  }
  alert(kind, actor, reason) {
    this.run(
      'INSERT INTO alerts VALUES(?,?,?,?,?)',
      randomUUID(),
      kind,
      actor ?? null,
      Date.now(),
      reason,
    );
    this.count('securityEvents');
  }
  event(eventType, actorId, extra = {}) {
    const last = this.get('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1');
    const p = {
      sequence: (last?.sequence ?? 0) + 1,
      previousHash: last?.hash ?? '0'.repeat(64),
      eventId: randomUUID(),
      eventType,
      timestamp: Date.now(),
      epoch: this.epoch().epoch,
      actorId: actorId ?? 'system',
      ...extra,
    };
    const rec = packet(this.key, p);
    this.run(
      'INSERT INTO evidence VALUES(?,?,?)',
      p.sequence,
      canonical(rec),
      hash(canonical(rec)),
    );
    return rec;
  }
  checkpoint() {
    const last = this.get('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1');
    return packet(this.key, {
      sequence: last?.sequence ?? 0,
      headHash: last?.hash ?? '0'.repeat(64),
      issuedAt: Date.now(),
    });
  }
  rate(bucket, limit, windowMs = 60000) {
    const now = Date.now(),
      window = Math.floor(now / windowMs);
    const blocked = this.tx(() => {
      const old = this.get('SELECT * FROM rate_limits WHERE bucket=?', bucket);
      const n = old?.window === window ? old.count + 1 : 1;
      this.run(
        'INSERT INTO rate_limits VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET window=excluded.window,count=excluded.count',
        bucket,
        window,
        n,
      );
      return n > limit;
    });
    if (blocked) fail(429, 'RATE_LIMITED');
  }
  authenticate(token) {
    assert(typeof token === 'string' && token.length >= 32, 'UNAUTHENTICATED', 401);
    const s = this.get('SELECT * FROM sessions WHERE token_hash=?', hash(token));
    assert(s && !s.revoked && s.expires_at > Date.now(), 'SESSION_INVALID', 401);
    const u = this.get('SELECT * FROM users WHERE id=?', s.user_id);
    assert(u?.active, 'USER_REVOKED', 401);
    return { ...s, user: this.user(u) };
  }
  bound(s) {
    const fresh = this.get('SELECT * FROM sessions WHERE id=?', s.id);
    assert(fresh && !fresh.revoked && fresh.expires_at > Date.now(), 'SESSION_INVALID', 401);
    const u = this.get('SELECT * FROM users WHERE id=?', fresh.user_id);
    assert(u?.active, 'USER_REVOKED', 401);
    const d = this.get('SELECT * FROM devices WHERE id=?', fresh.device_id);
    assert(d && d.user_id === fresh.user_id && d.status === 'approved', 'DEVICE_UNTRUSTED', 403);
    return {
      ...fresh,
      user: this.user(u),
      device: this.device(d),
      ...(s.proofEvidence ? { proofEvidence: s.proofEvidence } : {}),
    };
  }
  role(s, allowed) {
    assert(allowed.includes(s.user.role), 'FORBIDDEN', 403);
  }
  login(body, ip) {
    assert(str(body.username, 80) && str(body.password, 256) && str(body.otp, 6));
    this.rate('login-ip:' + ip, 40);
    this.rate('login-user:' + body.username, 8);
    const row = this.get('SELECT * FROM users WHERE username=?', body.username);
    const ok = passwordCheck(body.password, row?.password ?? this.dummyPassword);
    let counter = -1;
    if (row && ok && row.active)
      counter = totpCounter(unseal(row.totp, this.masterKey), body.otp, row.totp_floor);
    if (counter < 0) {
      this.tx(() => {
        this.alert('AUTH_FAILURE', row?.id, 'LOGIN_DENIED');
        this.event('AUTH_FAILURE', row?.id, { reason: 'LOGIN_DENIED' });
      });
      fail(401, 'LOGIN_DENIED');
    }
    const token = randomBytes(32).toString('base64url'),
      id = randomUUID(),
      expiresAt = Date.now() + 900000;
    this.tx(() => {
      const current = this.get('SELECT totp_floor FROM users WHERE id=?', row.id);
      assert(counter > current.totp_floor, 'MFA_REPLAY', 401);
      this.run('UPDATE users SET totp_floor=? WHERE id=?', counter, row.id);
      this.run(
        'INSERT INTO sessions(id,token_hash,user_id,expires_at) VALUES(?,?,?,?)',
        id,
        hash(token),
        row.id,
        expiresAt,
      );
      this.event('LOGIN', row.id);
    });
    return { token, user: this.user(row), expiresAt };
  }
  challenge(s, b) {
    assert(['enroll', 'bind', 'operation'].includes(b.purpose));
    if (b.purpose === 'operation') {
      s = this.bound(s);
      assert(
        str(b.operation, 250) &&
          typeof b.requestHash === 'string' &&
          /^[a-f0-9]{64}$/.test(b.requestHash),
      );
    }
    if (b.purpose === 'enroll')
      assert(typeof b.requestHash === 'string' && /^[a-f0-9]{64}$/.test(b.requestHash));
    if (b.purpose === 'bind') {
      assert(uuid(b.deviceId));
      const d = this.get('SELECT * FROM devices WHERE id=?', b.deviceId);
      assert(d && d.user_id === s.user_id, 'DEVICE_UNTRUSTED', 403);
    }
    const challengeId = randomUUID(),
      challenge = {
        domain: 'SIEPMU_DEVICE_PROOF_V1',
        nonce: randomBytes(32).toString('base64url'),
        sessionId: s.id,
        purpose: b.purpose,
        expiresAt: Date.now() + 60000,
      };
    if (b.deviceId) challenge.deviceId = b.deviceId;
    if (b.purpose === 'enroll') challenge.requestHash = b.requestHash;
    if (b.purpose === 'operation') {
      challenge.deviceId = s.device_id;
      challenge.operation = b.operation;
      challenge.requestHash = b.requestHash;
    }
    this.run(
      'INSERT INTO challenges(id,session_id,payload,expires_at) VALUES(?,?,?,?)',
      challengeId,
      s.id,
      canonical(challenge),
      challenge.expiresAt,
    );
    return { challengeId, challenge };
  }
  proof(s, p, purpose, operation, key, deviceId) {
    assert(p && uuid(p.challengeId) && str(p.signature, 150), 'PROOF_REQUIRED', 403);
    const c = this.get('SELECT * FROM challenges WHERE id=?', p.challengeId);
    assert(
      c && !c.used && c.session_id === s.id && c.expires_at > Date.now(),
      'PROOF_REPLAY_OR_EXPIRED',
      403,
    );
    const v = parse(c.payload);
    assert(
      v.purpose === purpose &&
        (!operation || v.operation === operation) &&
        (!deviceId || v.deviceId === deviceId),
      'PROOF_SCOPE',
      403,
    );
    assert(verify(key, v, p.signature), 'INVALID_PROOF', 403);
    this.run('UPDATE challenges SET used=1 WHERE id=?', c.id);
  }
  operation(s, b, op) {
    s = this.bound(s);
    const body = { ...b };
    delete body.proof;
    if (!b.proof) {
      delete body.challengeId;
      delete body.signature;
    }
    const pr = b.proof ?? b;
    const challenge = this.get('SELECT payload FROM challenges WHERE id=?', pr.challengeId ?? '');
    assert(
      challenge && parse(challenge.payload).requestHash === hash(canonical(body)),
      'PROOF_BODY_MISMATCH',
      403,
    );
    this.tx(() => this.proof(s, pr, 'operation', op, s.device.signingPublicKey, s.device_id));
    s.proofEvidence = {
      challengeId: pr.challengeId,
      challengeDigest: hash(challenge.payload),
      sessionId: s.id,
    };
    return s;
  }
  grant(s) {
    s = this.bound(s);
    this.role(s, ['operator']);
    const a = this.epoch(),
      now = Date.now();
    return packet(this.key, {
      grantId: randomUUID(),
      userId: s.user.id,
      deviceId: s.device.id,
      unitId: s.user.unitId,
      missionIds: s.user.missionIds,
      creationEpoch: a.epoch,
      policyDigest: this.policyDigest(),
      issuedAt: now,
      expiresAt: now + 3600000,
      maxSensitivity: 'DEMO',
    });
  }
  authorityReason(row) {
    const e = parse(row.envelope),
      now = Date.now(),
      g = e.creationGrant?.payload;
    if (
      !verifyPacket(this.publicKey, e.creationGrant) ||
      !g ||
      g.expiresAt <= now ||
      g.issuedAt > now
    )
      return 'STALE_GRANT';
    if (e.expiresAt <= now) return 'EXPIRED_OBJECT';
    const su = this.get('SELECT * FROM users WHERE id=?', row.sender_id),
      ru = this.get('SELECT * FROM users WHERE id=?', row.recipient_id);
    if (!su?.active || !ru?.active) return 'USER_REVOKED';
    const sd = this.get('SELECT * FROM devices WHERE id=?', row.sender_device),
      rd = this.get('SELECT * FROM devices WHERE id=?', row.recipient_device);
    if (sd?.status !== 'approved' || rd?.status !== 'approved') return 'DEVICE_REVOKED';
    if (sd.user_id !== su.id || rd.user_id !== ru.id) return 'DEVICE_OWNER_MISMATCH';
    if (su.role !== 'operator' || !['operator', 'viewer'].includes(ru.role)) return 'ROLE_DENIED';
    // Duty roles are an additive, sponsor-unapproved restriction at the release boundary.
    if (su.duty_role || ru.duty_role) {
      if (e.schemaVersion !== 2) return 'DUTY_PROFILE_REQUIRES_V2';
      if (
        (su.duty_role &&
          !senderDutyAllowed(su.role, su.duty_role, e.messagePriority, e.messageDomain)) ||
        (ru.duty_role &&
          !recipientDutyAllowed(ru.role, ru.duty_role, e.messagePriority, e.messageDomain))
      )
        return 'ROLE_PRIORITY_DENIED';
    }
    if (su.unit_id !== e.senderUnitId || ru.unit_id !== e.recipientUnitId) return 'UNIT_CHANGED';
    if (!parse(su.missions).includes(e.missionId) || !parse(ru.missions).includes(e.missionId))
      return 'MISSION_DENIED';
    if (
      g.userId !== su.id ||
      g.deviceId !== sd.id ||
      g.unitId !== su.unit_id ||
      !g.missionIds.includes(e.missionId)
    )
      return 'GRANT_SCOPE';
    if (keyId(parse(rd.encryption_key)) !== e.recipientKeyId) return 'RECIPIENT_KEY_CHANGED';
    const edge = this.get(
      'SELECT allow FROM policies WHERE from_unit=? AND to_unit=? AND mission_id=?',
      su.unit_id,
      ru.unit_id,
      e.missionId,
    );
    return edge?.allow === 1 ? null : 'POLICY_DENIED';
  }
  validateSubmission(s, b) {
    const e = b.envelope;
    assert(e && [1, 2].includes(e.schemaVersion) && uuid(e.objectId));
    const expected = [
      'schemaVersion',
      'objectId',
      'senderUserId',
      'senderDeviceId',
      'senderUnitId',
      'recipientUserId',
      'recipientDeviceId',
      'recipientUnitId',
      'recipientKeyId',
      'missionId',
      'classification',
      ...(e.schemaVersion === 2 ? ['messagePriority', 'messageDomain'] : []),
      'action',
      'createdAt',
      'expiresAt',
      'creationGrant',
      'cryptoSuite',
      'keyVersion',
      'ciphertextHash',
      'nonce',
      'wrappedKey',
    ];
    assert(
      Object.keys(e).length === expected.length && expected.every((k) => Object.hasOwn(e, k)),
      'ENVELOPE_SCHEMA',
    );
    assert(
      e.senderUserId === s.user.id &&
        e.senderDeviceId === s.device.id &&
        e.senderUnitId === s.user.unitId,
      'SENDER_MISMATCH',
      403,
    );
    assert(
      uuid(e.recipientUserId) &&
        uuid(e.recipientDeviceId) &&
        uuid(e.recipientUnitId) &&
        mission(e.missionId),
    );
    assert(
      e.classification === 'DEMO' &&
        e.action === 'deliver' &&
        e.cryptoSuite === 'P256-HKDF-SHA256-AES256GCM' &&
        e.keyVersion === 1,
    );
    if (e.schemaVersion === 2)
      assert(validMissionProfile(e.messagePriority, e.messageDomain), 'INVALID_MISSION_PROFILE');
    if (s.user.dutyRole) {
      assert(e.schemaVersion === 2, 'DUTY_PROFILE_REQUIRES_V2', 403);
      assert(
        senderDutyAllowed(s.user.role, s.user.dutyRole, e.messagePriority, e.messageDomain),
        'ROLE_PRIORITY_DENIED',
        403,
      );
    }
    assert(
      Number.isSafeInteger(e.createdAt) &&
        Number.isSafeInteger(e.expiresAt) &&
        e.createdAt <= Date.now() + 30000 &&
        e.expiresAt > e.createdAt &&
        e.expiresAt <= e.createdAt + 3600000,
    );
    assert(/^[a-f0-9]{64}$/.test(e.ciphertextHash) && /^[a-f0-9]{64}$/.test(e.recipientKeyId));
    assert(verify(s.device.signingPublicKey, e, b.signature), 'ENVELOPE_SIGNATURE', 403);
    const g = e.creationGrant;
    assert(verifyPacket(this.publicKey, g), 'GRANT_SIGNATURE', 403);
    assert(
      g.payload.userId === s.user.id &&
        g.payload.deviceId === s.device.id &&
        g.payload.unitId === s.user.unitId &&
        g.payload.missionIds.includes(e.missionId) &&
        g.payload.expiresAt > Date.now() &&
        g.payload.issuedAt <= Date.now(),
      'GRANT_SCOPE_OR_EXPIRED',
      403,
    );
    const rd = this.get('SELECT * FROM devices WHERE id=?', e.recipientDeviceId),
      ru = this.get('SELECT * FROM users WHERE id=?', e.recipientUserId);
    assert(
      rd && ru && rd.user_id === ru.id && ru.unit_id === e.recipientUnitId,
      'DESTINATION_INVALID',
      403,
    );
    assert(keyId(parse(rd.encryption_key)) === e.recipientKeyId, 'RECIPIENT_KEY_INVALID', 403);
    assert(decode(e.nonce).length === 12);
    assert(
      e.wrappedKey &&
        Object.keys(e.wrappedKey).sort().join(',') === 'ciphertext,ephemeralPublicKey,iv,salt',
    );
    validateKey(e.wrappedKey.ephemeralPublicKey);
    assert(
      decode(e.wrappedKey.salt).length === 32 &&
        decode(e.wrappedKey.iv).length === 12 &&
        decode(e.wrappedKey.ciphertext).length === 48,
    );
    const bytes = decode(b.ciphertext);
    assert(bytes.length >= 16 && bytes.length <= 1048592, 'OBJECT_SIZE', 413);
    assert(hash(bytes) === e.ciphertextHash, 'CIPHERTEXT_DIGEST');
    return bytes;
  }
  async submit(s, b) {
    s = this.bound(s);
    this.role(s, ['operator']);
    const bytes = this.validateSubmission(s, b);
    await this.relay.putBlob(b.envelope.ciphertextHash, bytes);
    return this.tx(() => {
      s = this.bound(s);
      this.role(s, ['operator']);
      this.validateSubmission(s, b);
      const old = this.get('SELECT * FROM objects WHERE id=?', b.envelope.objectId);
      if (old) {
        assert(
          old.envelope === canonical(b.envelope) && old.signature === b.signature,
          'IDEMPOTENCY_CONFLICT',
          409,
        );
        return { object: this.object(old), receipt: this.findReceipt(old.id, 'SUBMITTED') };
      }
      const e = b.envelope;
      this.run(
        'INSERT INTO objects VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        e.objectId,
        e.senderUserId,
        e.recipientUserId,
        e.senderDeviceId,
        e.recipientDeviceId,
        canonical(e),
        b.signature,
        e.ciphertextHash,
        'PENDING',
        null,
        null,
        Date.now(),
      );
      const receipt = this.event('SUBMITTED', s.user.id, {
        objectId: e.objectId,
        decision: 'PENDING',
        details: { objectDigest: e.ciphertextHash, envelopeDigest: hash(canonical(e)) },
      });
      this.count('submitted');
      return {
        object: this.object(this.get('SELECT * FROM objects WHERE id=?', e.objectId)),
        receipt,
      };
    });
  }
  findReceipt(id, type) {
    return (
      this.all('SELECT record FROM evidence ORDER BY sequence DESC')
        .map((x) => parse(x.record))
        .find((x) => x.payload.objectId === id && x.payload.eventType === type) ?? null
    );
  }
  owned(s, id) {
    const r = this.get('SELECT * FROM objects WHERE id=?', id);
    assert(
      r && (r.sender_id === s.user_id || r.recipient_id === s.user_id),
      'OBJECT_NOT_FOUND',
      404,
    );
    // Priority-sensitive metadata is not revealed through object-ID probe routes.
    if (s.user.dutyRole) {
      const e = parse(r.envelope);
      const checkDuty = r.sender_id === s.user_id ? senderDutyAllowed : recipientDutyAllowed;
      assert(
        e.schemaVersion === 2 &&
          checkDuty(s.user.role, s.user.dutyRole, e.messagePriority, e.messageDomain),
        'OBJECT_NOT_FOUND',
        404,
      );
    }
    return r;
  }
  prepare(s, id) {
    return this.tx(() => {
      s = this.bound(s);
      const r = this.owned(s, id);
      const reason = this.authorityReason(r),
        epoch = this.epoch().epoch;
      const issued = this.get('SELECT * FROM issuances WHERE object_id=?', id);
      const state = reason
        ? 'HELD'
        : issued
          ? r.state === 'DELIVERED'
            ? 'DELIVERED'
            : 'RELEASED'
          : 'READY';
      this.run(
        'UPDATE objects SET state=?,reason=?,prepared_epoch=? WHERE id=?',
        state,
        reason,
        epoch,
        id,
      );
      const receipt = this.event('ADMISSION', s.user_id, {
        objectId: id,
        decision: state,
        reason: reason ?? 'CURRENT_AUTHORITY_VALID',
        details: { objectDigest: r.digest, preparedEpoch: epoch },
      });
      this.count('policyEvaluations');
      if (reason) this.alert('ADMISSION_HELD', s.user_id, reason);
      return { object: this.object(this.get('SELECT * FROM objects WHERE id=?', id)), receipt };
    });
  }
  claim(s, id, expectedEpoch) {
    assert(Number.isSafeInteger(expectedEpoch) && expectedEpoch > 0);
    let out = this.tx(() => {
      s = this.bound(s);
      const r = this.owned(s, id);
      assert(
        r.recipient_id === s.user_id && r.recipient_device === s.device_id,
        'RECIPIENT_ONLY',
        403,
      );
      const epoch = this.epoch().epoch;
      const reason = this.authorityReason(r) ?? (epoch !== expectedEpoch ? 'EPOCH_MISMATCH' : null);
      if (reason) {
        this.run(
          'UPDATE objects SET state=?,reason=?,prepared_epoch=? WHERE id=?',
          'HELD',
          reason,
          epoch,
          id,
        );
        const receipt = this.event('RELEASE_DENIED', s.user_id, {
          objectId: id,
          decision: 'HELD',
          reason,
          details: { objectDigest: r.digest, expectedEpoch, currentEpoch: epoch },
        });
        this.alert('RELEASE_DENIED', s.user_id, reason);
        this.count('held');
        return {
          denied: true,
          object: this.object(this.get('SELECT * FROM objects WHERE id=?', id)),
          receipt,
        };
      }
      const old = this.get('SELECT * FROM issuances WHERE object_id=?', id);
      let receipt;
      if (old) {
        receipt = parse(old.receipt);
        this.event('RELEASE_RETRY', s.user_id, {
          objectId: id,
          decision: 'RELEASED',
          details: { issuanceEventId: receipt.payload.eventId, currentEpoch: epoch },
        });
        this.run(
          "UPDATE objects SET reason=NULL,state=CASE WHEN state='DELIVERED' THEN state ELSE 'RELEASED' END WHERE id=?",
          id,
        );
      } else {
        const e = parse(r.envelope);
        receipt = this.event('RELEASE_ISSUED', s.user_id, {
          objectId: id,
          decision: 'RELEASED',
          reason: 'CURRENT_AUTHORITY_VALID',
          details: {
            objectDigest: r.digest,
            envelopeDigest: hash(canonical(e)),
            senderUserId: r.sender_id,
            senderDeviceId: r.sender_device,
            recipientUserId: r.recipient_id,
            recipientDeviceId: r.recipient_device,
            destinationUnitId: e.recipientUnitId,
            missionId: e.missionId,
            action: e.action,
            creationGrantId: e.creationGrant.payload.grantId,
            creationEpoch: e.creationGrant.payload.creationEpoch,
            policyDigest: this.policyDigest(),
            revocationVersion: this.epoch().revocation_version,
            authorityEpoch: epoch,
            deviceEvidence: 'software-proof-of-possession',
            proofEvidence: s.proofEvidence ?? { source: 'internal-call-no-http-proof' },
          },
        });
        this.hooks.beforeEvidence?.();
        this.run(
          'INSERT INTO issuances VALUES(?,?,?,?)',
          id,
          canonical(receipt),
          epoch,
          Date.now(),
        );
        this.run(
          'UPDATE objects SET state=?,reason=NULL,prepared_epoch=? WHERE id=?',
          'RELEASED',
          epoch,
          id,
        );
        this.count('released');
      }
      this.hooks.beforeCommit?.();
      return {
        object: this.object(this.get('SELECT * FROM objects WHERE id=?', id)),
        envelope: parse(r.envelope),
        signature: r.signature,
        senderSigningPublicKey: parse(
          this.get('SELECT signing_key FROM devices WHERE id=?', r.sender_device).signing_key,
        ),
        receipt,
      };
    });
    if (!out.denied) this.hooks.afterCommit?.();
    return out;
  }
  ack(s, id, receiptId) {
    return this.tx(() => {
      s = this.bound(s);
      const r = this.owned(s, id);
      assert(
        r.recipient_id === s.user_id && r.recipient_device === s.device_id,
        'RECIPIENT_ONLY',
        403,
      );
      const issuance = this.get('SELECT * FROM issuances WHERE object_id=?', id);
      assert(issuance && parse(issuance.receipt).payload.eventId === receiptId, 'RECEIPT_INVALID');
      if (r.state === 'DELIVERED')
        return { object: this.object(r), receipt: this.findReceipt(id, 'DELIVERY_ACK') };
      this.run('UPDATE objects SET state=? WHERE id=?', 'DELIVERED', id);
      const receipt = this.event('DELIVERY_ACK', s.user_id, {
        objectId: id,
        decision: 'DELIVERED',
        details: { issuanceEventId: receiptId, meaning: 'client-acknowledged-not-human-read' },
      });
      return { object: this.object(this.get('SELECT * FROM objects WHERE id=?', id)), receipt };
    });
  }
  change(s, fn, eventType = 'AUTHORITY_CHANGED') {
    return this.tx(() => {
      s = this.bound(s);
      this.role(s, ['admin']);
      const result = fn();
      this.run(
        'UPDATE authority SET epoch=epoch+1,revocation_version=revocation_version+1 WHERE id=1',
      );
      this.event(eventType, s.user_id, {
        details: { revocationVersion: this.epoch().revocation_version },
      });
      this.alert('AUTHORITY_CHANGED', s.user_id, eventType);
      return result;
    });
  }
  metrics() {
    return {
      counters: Object.fromEntries(
        this.all('SELECT * FROM counters').map((x) => [x.name, x.value]),
      ),
      objects: Object.fromEntries(
        this.all('SELECT state,count(*) n FROM objects GROUP BY state').map((x) => [x.state, x.n]),
      ),
      epoch: this.epoch().epoch,
      uptimeSeconds: Math.floor(process.uptime()),
      memoryBytes: process.memoryUsage().rss,
    };
  }
  async dispatch(method, path, b = {}, token, context = { ip: 'local' }) {
    // Exact static routing only: request values never become a callable or a
    // property name. All remaining routes enter the mandatory session gate.
    switch (`${method} ${path}`) {
      case 'GET /health':
      case 'GET /live':
      case 'GET /ready':
        return publicHealth(this);
      case 'GET /api/meta':
        return publicMetadata(this);
      case 'POST /api/auth/login':
        return publicLogin(this, b, context);
      default:
        return this.#authenticatedDispatch(method, path, b, token);
    }
  }
  async #authenticatedDispatch(method, path, b, token) {
    // This is the only entry into protected route dispatch. Authentication is
    // unconditional here and cannot be skipped by a method or path supplied by a client.
    let s = this.authenticate(token);
    this.rate('session:' + s.id, 500);
    let value;
    if (method === 'GET' && path === '/api/auth/me')
      value = {
        user: s.user,
        device: this.device(this.get('SELECT * FROM devices WHERE id=?', s.device_id)),
        expiresAt: s.expires_at,
      };
    else if (method === 'POST' && path === '/api/auth/logout') {
      value = this.tx(() => {
        this.run('UPDATE sessions SET revoked=1 WHERE id=?', s.id);
        this.event('LOGOUT', s.user_id);
        return { ok: true };
      });
    } else if (method === 'POST' && path === '/api/auth/challenge') value = this.challenge(s, b);
    else if (method === 'POST' && path === '/api/devices/enroll') {
      assert(str(b.label, 80));
      validateKey(b.signingPublicKey);
      validateKey(b.encryptionPublicKey);
      value = this.tx(() => {
        const challenge = this.get(
          'SELECT payload FROM challenges WHERE id=?',
          b.challengeId ?? '',
        );
        assert(
          challenge &&
            parse(challenge.payload).requestHash ===
              hash(
                canonical({
                  label: b.label,
                  signingPublicKey: b.signingPublicKey,
                  encryptionPublicKey: b.encryptionPublicKey,
                }),
              ),
          'PROOF_BODY_MISMATCH',
          403,
        );
        this.proof(s, b, 'enroll', null, b.signingPublicKey);
        assert(
          !this.get(
            'SELECT id FROM devices WHERE signing_key=?',
            canonical(publicJwk(b.signingPublicKey)),
          ),
          'DEVICE_KEY_EXISTS',
          409,
        );
        const id = randomUUID();
        this.run(
          'INSERT INTO devices VALUES(?,?,?,?,?,?,?)',
          id,
          s.user_id,
          b.label,
          canonical(publicJwk(b.signingPublicKey)),
          canonical(publicJwk(b.encryptionPublicKey)),
          'pending',
          Date.now(),
        );
        this.event('DEVICE_ENROLLED', s.user_id, { details: { deviceId: id } });
        return { device: this.device(this.get('SELECT * FROM devices WHERE id=?', id)) };
      });
    } else if (method === 'POST' && path === '/api/auth/bind') {
      value = this.tx(() => {
        const d = this.get('SELECT * FROM devices WHERE id=?', b.deviceId);
        assert(d && d.user_id === s.user_id && d.status === 'approved', 'DEVICE_UNTRUSTED', 403);
        this.proof(s, b, 'bind', null, parse(d.signing_key), d.id);
        this.run('UPDATE sessions SET device_id=? WHERE id=?', d.id, s.id);
        this.event('DEVICE_BOUND', s.user_id, { details: { deviceId: d.id } });
        return { device: this.device(d) };
      });
    } else if (method === 'GET' && path === '/api/control') {
      s = this.bound(s);
      this.count('controlRefreshes');
      const now = Date.now();
      value = this.tx(() => {
        const a = this.epoch();
        return packet(this.key, {
          epoch: a.epoch,
          revocationVersion: a.revocation_version,
          policyDigest: this.policyDigest(),
          issuedAt: now,
          expiresAt: now + 60000,
        });
      });
    } else if (method === 'GET' && path === '/api/directory') {
      s = this.bound(s);
      value = this.tx(() => {
        const users = this.all('SELECT * FROM users WHERE active=1').map((x) => this.user(x));
        const devices = this.all(
          "SELECT d.* FROM devices d JOIN users u ON u.id=d.user_id WHERE d.status='approved' AND u.active=1",
        ).map((x) => this.device(x));
        const payload = { users, devices, issuedAt: Date.now(), epoch: this.epoch().epoch };
        return { users, devices, packet: packet(this.key, payload) };
      });
    } else if (method === 'POST' && path === '/api/grants') {
      s = this.operation(s, b, 'grant');
      value = this.tx(() => this.grant(s));
    } else if (method === 'POST' && path === '/api/objects') {
      s = this.operation(s, b, 'submit');
      value = await this.submit(s, b);
    } else if (method === 'GET' && path === '/api/objects') {
      s = this.bound(s);
      value = {
        objects: this.all(
          'SELECT * FROM objects WHERE sender_id=? OR recipient_id=? ORDER BY created_at DESC',
          s.user_id,
          s.user_id,
        )
          .filter((x) => {
            if (!s.user.dutyRole) return true;
            const e = parse(x.envelope);
            if (e.schemaVersion !== 2) return false;
            return x.sender_id === s.user_id
              ? senderDutyAllowed(s.user.role, s.user.dutyRole, e.messagePriority, e.messageDomain)
              : recipientDutyAllowed(
                  s.user.role,
                  s.user.dutyRole,
                  e.messagePriority,
                  e.messageDomain,
                );
          })
          .map((x) => this.object(x)),
      };
    } else if (method === 'POST' && /^\/api\/objects\/[^/]+\/(prepare|claim|ack)$/.test(path)) {
      const [, id, op] = path.match(/^\/api\/objects\/([^/]+)\/(prepare|claim|ack)$/);
      assert(uuid(id));
      s = this.operation(s, b, op + ':' + id);
      if (op === 'prepare') value = this.prepare(s, id);
      else if (op === 'ack') value = this.ack(s, id, b.receiptId);
      else {
        value = this.claim(s, id, b.expectedEpoch);
        if (value.denied)
          return {
            status: 409,
            body: {
              error: 'Admission held',
              code: value.object.reason,
              object: value.object,
              receipt: value.receipt,
            },
          };
        value.ciphertext = (await this.relay.getBlob(value.object.ciphertextHash)).toString(
          'base64url',
        );
      }
    } else if (path.startsWith('/api/admin/') || path === '/api/integration/validate') {
      s = this.bound(s);
      this.role(
        s,
        method === 'GET' && path === '/api/admin/overview' ? ['admin', 'auditor'] : ['admin'],
      );
      if (method !== 'GET') s = this.operation(s, b, 'admin:' + method + ':' + path);
      value = this.admin(method, path, b, s);
    } else if (
      method === 'GET' &&
      ['/api/evidence/export', '/api/evidence/checkpoint', '/api/metrics'].includes(path)
    ) {
      s = this.bound(s);
      this.role(s, ['admin', 'auditor']);
      value = this.tx(() =>
        path === '/api/evidence/export'
          ? {
              records: this.all('SELECT record FROM evidence ORDER BY sequence').map((x) =>
                parse(x.record),
              ),
              checkpoint: this.checkpoint(),
            }
          : path === '/api/evidence/checkpoint'
            ? this.checkpoint()
            : this.metrics(),
      );
    } else fail(404, 'NOT_FOUND');
    return { status: 200, body: value };
  }
  admin(method, path, b, s) {
    if (method === 'GET' && path === '/api/admin/overview')
      return {
        units: this.all('SELECT * FROM units'),
        users: this.all('SELECT * FROM users').map((x) => this.user(x)),
        devices: this.all('SELECT * FROM devices').map((x) => this.device(x)),
        sessions: this.all(
          'SELECT id,user_id userId,device_id deviceId,expires_at expiresAt,revoked FROM sessions',
        ),
        policies: this.all(
          'SELECT from_unit fromUnit,to_unit toUnit,mission_id missionId,allow FROM policies',
        ).map((x) => ({ ...x, allow: !!x.allow })),
        objects: this.all('SELECT * FROM objects ORDER BY created_at DESC LIMIT 1000').map((x) =>
          this.object(x),
        ),
        epoch: this.epoch().epoch,
        revocationVersion: this.epoch().revocation_version,
        alerts: this.all('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100'),
        metrics: this.metrics(),
      };
    if (method === 'POST' && path === '/api/admin/units') {
      assert(str(b.name, 80));
      return this.change(
        s,
        () => {
          const unit = { id: randomUUID(), name: b.name };
          this.run('INSERT INTO units VALUES(?,?)', unit.id, unit.name);
          return { unit };
        },
        'UNIT_CREATED',
      );
    }
    if (method === 'POST' && path === '/api/admin/users') {
      assert(
        /^[a-zA-Z0-9_.-]{3,80}$/.test(b.username) &&
          str(b.password, 256) &&
          b.password.length >= 12 &&
          roles.includes(b.role) &&
          (b.dutyRole === undefined ||
            (DUTY_ROLES.includes(b.dutyRole) && compatibleDutyRole(b.role, b.dutyRole))) &&
          Array.isArray(b.missionIds) &&
          b.missionIds.length <= 32 &&
          b.missionIds.every(mission),
      );
      assert(this.get('SELECT id FROM units WHERE id=?', b.unitId));
      const secret = base32(randomBytes(20));
      return this.change(
        s,
        () => {
          const id = randomUUID();
          this.run(
            'INSERT INTO users(id,username,password,totp,unit_id,role,missions,duty_role) VALUES(?,?,?,?,?,?,?,?)',
            id,
            b.username,
            passwordHash(b.password),
            seal(secret, this.masterKey),
            b.unitId,
            b.role,
            canonical(b.missionIds),
            b.dutyRole ?? null,
          );
          return {
            user: this.user(this.get('SELECT * FROM users WHERE id=?', id)),
            totpSecret: secret,
            otpauthUri:
              'otpauth://totp/SIEPMU:' +
              encodeURIComponent(b.username) +
              '?secret=' +
              secret +
              '&issuer=SIEPMU',
          };
        },
        'USER_CREATED',
      );
    }
    const userMatch = path.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (method === 'PATCH' && userMatch) {
      const fields = Object.keys(b).filter((x) => x !== 'proof');
      assert(
        fields.length > 0 &&
          fields.every((x) => ['active', 'role', 'missionIds', 'dutyRole'].includes(x)),
      );
      if ('active' in b) assert(typeof b.active === 'boolean');
      if ('role' in b) assert(roles.includes(b.role));
      if ('dutyRole' in b) assert(DUTY_ROLES.includes(b.dutyRole), 'INVALID_DUTY_ROLE');
      if ('missionIds' in b)
        assert(
          Array.isArray(b.missionIds) && b.missionIds.length <= 32 && b.missionIds.every(mission),
        );
      return this.change(
        s,
        () => {
          const u = this.get('SELECT * FROM users WHERE id=?', userMatch[1]);
          assert(u, 'NOT_FOUND', 404);
          assert(
            compatibleDutyRole(b.role ?? u.role, b.dutyRole ?? u.duty_role),
            'DUTY_ROLE_INCOMPATIBLE',
          );
          assert(
            !(u.id === s.user_id && (b.active === false || (b.role && b.role !== 'admin'))),
            'SELF_LOCKOUT',
          );
          this.run(
            'UPDATE users SET active=?,role=?,missions=?,duty_role=? WHERE id=?',
            'active' in b ? +b.active : u.active,
            b.role ?? u.role,
            b.missionIds ? canonical(b.missionIds) : u.missions,
            b.dutyRole ?? u.duty_role,
            u.id,
          );
          return { user: this.user(this.get('SELECT * FROM users WHERE id=?', u.id)) };
        },
        'USER_AUTHORITY_CHANGED',
      );
    }
    const dev = path.match(/^\/api\/admin\/devices\/([^/]+)\/(approve|revoke)$/);
    if (method === 'POST' && dev)
      return this.change(
        s,
        () => {
          const d = this.get('SELECT * FROM devices WHERE id=?', dev[1]);
          assert(d, 'NOT_FOUND', 404);
          assert(
            !(dev[2] === 'approve' && d.status === 'revoked'),
            'REVOKED_KEY_REENROLL_REQUIRED',
            409,
          );
          assert(!(dev[2] === 'revoke' && d.id === s.device_id), 'SELF_LOCKOUT');
          this.run(
            'UPDATE devices SET status=? WHERE id=?',
            dev[2] === 'approve' ? 'approved' : 'revoked',
            d.id,
          );
          if (dev[2] === 'revoke')
            this.run('UPDATE sessions SET revoked=1 WHERE device_id=?', d.id);
          return { device: this.device(this.get('SELECT * FROM devices WHERE id=?', d.id)) };
        },
        'DEVICE_' + dev[2].toUpperCase(),
      );
    const ses = path.match(/^\/api\/admin\/sessions\/([^/]+)\/revoke$/);
    if (method === 'POST' && ses)
      return this.change(
        s,
        () => {
          assert(this.get('SELECT id FROM sessions WHERE id=?', ses[1]), 'NOT_FOUND', 404);
          this.run('UPDATE sessions SET revoked=1 WHERE id=?', ses[1]);
          return { ok: true };
        },
        'SESSION_REVOKED',
      );
    if (method === 'PUT' && path === '/api/admin/policies') {
      assert(typeof b.allow === 'boolean' && mission(b.missionId));
      assert(
        this.get('SELECT id FROM units WHERE id=?', b.fromUnit) &&
          this.get('SELECT id FROM units WHERE id=?', b.toUnit),
      );
      return this.change(
        s,
        () => {
          this.run(
            'INSERT INTO policies VALUES(?,?,?,?) ON CONFLICT(from_unit,to_unit,mission_id) DO UPDATE SET allow=excluded.allow',
            b.fromUnit,
            b.toUnit,
            b.missionId,
            +b.allow,
          );
          return {
            policy: {
              fromUnit: b.fromUnit,
              toUnit: b.toUnit,
              missionId: b.missionId,
              allow: b.allow,
            },
          };
        },
        'POLICY_CHANGED',
      );
    }
    if (method === 'POST' && path === '/api/integration/validate') {
      assert(
        b.schemaVersion === 1 &&
          str(b.externalId, 80) &&
          uuid(b.objectId) &&
          uuid(b.destinationUnitId) &&
          mission(b.missionId),
      );
      return this.tx(() => ({
        receipt: this.event('INTEGRATION_SCHEMA_VALIDATED', s.user_id, {
          objectId: b.objectId,
          decision: 'SCHEMA_ONLY',
          details: {
            externalId: b.externalId,
            destinationUnitId: b.destinationUnitId,
            missionId: b.missionId,
            connected: false,
          },
        }),
        connected: false,
      }));
    }
    fail(404, 'NOT_FOUND');
  }
}
