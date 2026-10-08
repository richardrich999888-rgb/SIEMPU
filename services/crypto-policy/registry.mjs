// Public-key-only authority registry. Never import a client provider or private key here.
import { createPublicKey, verify } from 'node:crypto';
import { canonical } from '../../packages/protocol/canonical.mjs';
import { providerKeyId, WRAP_SCHEMA_VERSION } from '../../packages/crypto-provider/engine.mjs';
import {
  validateCryptoPolicy,
  cryptoPolicyDigest,
} from '../../packages/crypto-provider/policy.mjs';
import {
  CLASSICAL_PROVIDER_ID,
  CLASSICAL_SUITE_ID,
} from '../../packages/crypto-provider/classical.mjs';
import {
  decodeBytes,
  exactObject,
  PQC_SUITES,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_SIGNATURE_BYTES,
} from '../../packages/crypto-provider/pqc-identifiers.mjs';

export const CLASSICAL_SELECTION = Object.freeze({
  providerId: CLASSICAL_PROVIDER_ID,
  suiteId: CLASSICAL_SUITE_ID,
});
// Wire identifiers only: endpoint lab providers are never loaded by services.
const suites = PQC_SUITES;
const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const listed = (list, providerId, suiteId) =>
  list.some((s) => s.providerId === providerId && s.suiteId === suiteId);
function suiteFor(providerId, suiteId) {
  const suite = suites.get(suiteId);
  if (!suite || suite.providerId !== providerId)
    throw new TypeError('Unsupported cryptographic suite');
  return suite;
}
export function validatePqcPublicDescriptor(key) {
  exactObject(key, ['keyId', 'providerId', 'suiteId', 'purpose', 'publicKey']);
  if (
    !digest(key.keyId) ||
    !['sign', 'encapsulate'].includes(key.purpose) ||
    providerKeyId(key) !== key.keyId
  )
    throw new TypeError('Invalid public key identity');
  const suite = suiteFor(key.providerId, key.suiteId);
  exactObject(key.publicKey, ['algorithm', 'format', 'bytes']);
  const algorithm = key.purpose === 'sign' ? 'ml-dsa-65' : suite.algorithm;
  const length = key.purpose === 'sign' ? MLDSA65_PUBLIC_KEY_BYTES : suite.keyBytes;
  if (key.publicKey.format !== 'raw-public' || key.publicKey.algorithm !== algorithm)
    throw new TypeError('Invalid public key algorithm');
  const bytes = decodeBytes(key.publicKey.bytes, length);
  if (algorithm !== 'x-wing')
    createPublicKey({ key: bytes, format: 'raw-public', asymmetricKeyType: algorithm });
  return key;
}
export function validatePqcEnvelope(e) {
  const suite = suiteFor(e.providerId, e.cryptoSuite);
  if (
    e.schemaVersion !== 3 ||
    e.suiteVersion !== 1 ||
    !digest(e.senderCryptoKeyId) ||
    !Number.isSafeInteger(e.suitePolicyRevision) ||
    e.suitePolicyRevision < 1
  )
    throw new TypeError('Invalid crypto context');
  decodeBytes(e.providerSignature, MLDSA65_SIGNATURE_BYTES);
  const w = e.wrappedKey;
  exactObject(w, [
    'schemaVersion',
    'providerId',
    'suiteId',
    'recipientKeyId',
    'encapsulation',
    'salt',
    'nonce',
    'ciphertext',
  ]);
  if (
    w.schemaVersion !== WRAP_SCHEMA_VERSION ||
    w.providerId !== e.providerId ||
    w.suiteId !== e.cryptoSuite ||
    w.recipientKeyId !== e.recipientKeyId
  )
    throw new TypeError('Invalid key wrap binding');
  exactObject(w.encapsulation, ['algorithm', 'ciphertext']);
  if (w.encapsulation.algorithm !== suite.algorithm)
    throw new TypeError('Invalid encapsulation algorithm');
  decodeBytes(w.encapsulation.ciphertext, suite.ciphertextBytes);
  decodeBytes(w.salt, 32);
  decodeBytes(w.nonce, 12);
  decodeBytes(w.ciphertext, 48);
}

export class CryptoPolicyRegistry {
  constructor(db, allowPqcLab = false) {
    this.db = db;
    this.allowPqcLab = allowPqcLab;
  }
  validatePolicy(value, enforceRuntime = true) {
    return validateCryptoPolicy(value, {
      resolve: (providerId, suiteId) => {
        if (providerId === CLASSICAL_PROVIDER_ID && suiteId === CLASSICAL_SUITE_ID)
          return { suite: { laboratory: false } };
        suiteFor(providerId, suiteId);
        if (enforceRuntime && !this.allowPqcLab) throw new Error('PQC laboratory mode disabled');
        return { suite: { laboratory: true } };
      },
    });
  }
  policy() {
    return this.validatePolicy(
      JSON.parse(this.db.prepare('SELECT value FROM crypto_policy WHERE id=1').get().value),
      false,
    );
  }
  inventory() {
    return this.db
      .prepare('SELECT * FROM crypto_keys ORDER BY key_id')
      .all()
      .map((r) => ({ deviceId: r.device_id, key: JSON.parse(r.descriptor), status: r.status }));
  }
  /** Registered public descriptor by key ID (any status), validated on read. */
  publicKey(keyId) {
    const row = this.db.prepare('SELECT descriptor FROM crypto_keys WHERE key_id=?').get(keyId);
    if (!row) throw new Error('Crypto key not found');
    return validatePqcPublicDescriptor(JSON.parse(row.descriptor));
  }
  /** Active public descriptors, for the authenticated directory. Empty when the lab is off. */
  activeKeys() {
    if (!this.allowPqcLab) return [];
    return this.db
      .prepare(
        "SELECT device_id, descriptor FROM crypto_keys WHERE status='active' ORDER BY key_id",
      )
      .all()
      .map((r) => ({
        deviceId: r.device_id,
        key: validatePqcPublicDescriptor(JSON.parse(r.descriptor)),
      }));
  }
  register(deviceId, key) {
    if (!this.allowPqcLab) throw new Error('PQC laboratory mode disabled');
    validatePqcPublicDescriptor(key);
    if (this.db.prepare('SELECT key_id FROM crypto_keys WHERE key_id=?').get(key.keyId))
      throw new Error('Crypto key already registered');
    this.db
      .prepare('INSERT INTO crypto_keys VALUES(?,?,?,?,?)')
      .run(key.keyId, deviceId, canonical(key), 'pending', Date.now());
    return { deviceId, key, status: 'pending' };
  }
  setStatus(keyId, status) {
    const row = this.db.prepare('SELECT * FROM crypto_keys WHERE key_id=?').get(keyId);
    if (!row) throw new Error('Crypto key not found');
    const next = {
      pending: ['active', 'revoked'],
      active: ['retired', 'revoked'],
      retired: ['revoked'],
      revoked: [],
    };
    if (!next[row.status]?.includes(status))
      throw new Error('Crypto key status transition forbidden');
    const key = validatePqcPublicDescriptor(JSON.parse(row.descriptor));
    if (key.keyId !== row.key_id) throw new Error('Crypto key persistence binding invalid');
    this.db.prepare('UPDATE crypto_keys SET status=? WHERE key_id=?').run(status, keyId);
    return { deviceId: row.device_id, key, status };
  }
  updatePolicy(value) {
    const policy = this.validatePolicy(value);
    if (policy.revision !== this.policy().revision + 1)
      throw new Error('Crypto policy revision must advance by one');
    this.db.prepare('UPDATE crypto_policy SET value=? WHERE id=1').run(canonical(policy));
    return policy;
  }
  reason(e, creation = false) {
    try {
      const policy = this.policy();
      const selection =
        e.schemaVersion === 3
          ? { providerId: e.providerId, suiteId: e.cryptoSuite }
          : CLASSICAL_SELECTION;
      const inNew = listed(policy.newSuites, selection.providerId, selection.suiteId);
      const inLegacy = listed(policy.legacySuites, selection.providerId, selection.suiteId);
      if (!(creation ? inNew : inNew || inLegacy)) return 'CRYPTO_SUITE_FORBIDDEN';
      if (e.schemaVersion !== 3) return null;
      if (!this.allowPqcLab) return 'PQC_LAB_DISABLED';
      validatePqcEnvelope(e);
      if (
        creation
          ? e.suitePolicyRevision !== policy.revision
          : e.suitePolicyRevision > policy.revision
      )
        return 'CRYPTO_POLICY_REVISION';
      const descriptors = [];
      for (const [id, deviceId, purpose] of [
        [e.senderCryptoKeyId, e.senderDeviceId, 'sign'],
        [e.recipientKeyId, e.recipientDeviceId, 'encapsulate'],
      ]) {
        const row = this.db.prepare('SELECT * FROM crypto_keys WHERE key_id=?').get(id);
        if (!row) return 'CRYPTO_KEY_UNREGISTERED';
        const key = validatePqcPublicDescriptor(JSON.parse(row.descriptor));
        if (
          key.keyId !== id ||
          row.device_id !== deviceId ||
          key.purpose !== purpose ||
          key.providerId !== e.providerId ||
          key.suiteId !== e.cryptoSuite
        )
          return 'CRYPTO_KEY_BINDING';
        if (row.status === 'revoked') return 'CRYPTO_KEY_REVOKED';
        if (row.status !== 'active' && !(row.status === 'retired' && !creation && inLegacy))
          return 'CRYPTO_KEY_INACTIVE';
        descriptors.push(key);
      }
      const publicKey = createPublicKey({
        key: decodeBytes(descriptors[0].publicKey.bytes, MLDSA65_PUBLIC_KEY_BYTES),
        format: 'raw-public',
        asymmetricKeyType: 'ml-dsa-65',
      });
      const { providerSignature, ...signed } = e;
      if (
        !verify(
          null,
          Buffer.from(canonical(signed)),
          publicKey,
          decodeBytes(providerSignature, MLDSA65_SIGNATURE_BYTES),
        )
      )
        return 'PROVIDER_SIGNATURE_INVALID';
      return null;
    } catch {
      return 'CRYPTO_CONTEXT_INVALID';
    }
  }
  evidence(e) {
    if (e?.schemaVersion !== 3) return undefined;
    try {
      const policy = this.policy();
      validatePqcEnvelope(e);
      return {
        envelopeVersion: 3,
        providerId: e.providerId,
        suiteId: e.cryptoSuite,
        suiteVersion: e.suiteVersion,
        senderKeyId: e.senderCryptoKeyId,
        recipientKeyId: e.recipientKeyId,
        creationPolicyRevision: e.suitePolicyRevision,
        currentPolicyRevision: policy.revision,
        policyDigest: cryptoPolicyDigest(policy),
      };
    } catch {
      return undefined;
    }
  }
}
