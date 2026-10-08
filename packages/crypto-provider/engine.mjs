import { canonical } from '../protocol/canonical.mjs';
import { ProviderRegistry } from './registry.mjs';
import { validateCryptoPolicy, requireCryptoPolicy, cryptoPolicyDigest } from './policy.mjs';
import {
  bytes,
  copy,
  decode,
  decryptAes,
  deriveWrapKey,
  digest,
  encode,
  encryptAes,
  identifier,
  members,
  utf8,
} from './primitives.mjs';

const publicMembers = ['keyId', 'providerId', 'suiteId', 'purpose', 'publicKey'];
/** Wrap packet format; v2 binds the context by digest in HKDF info (see primitives.mjs). */
export const WRAP_SCHEMA_VERSION = 2;
const WRAP_AAD_DOMAIN = 'SIEPMU_PROVIDER_KEY_WRAP_AAD_V2';
const wrapMembers = [
  'schemaVersion',
  'providerId',
  'suiteId',
  'recipientKeyId',
  'encapsulation',
  'salt',
  'nonce',
  'ciphertext',
];

export function providerKeyId(key) {
  const { keyId: _keyId, ...identity } = key;
  return digest(identity);
}

export function validateProviderPublicKey(key) {
  members(key, publicMembers);
  identifier(key.providerId);
  identifier(key.suiteId);
  if (!['sign', 'encapsulate'].includes(key.purpose) || key.keyId !== providerKeyId(key))
    throw new TypeError('Invalid provider key identity');
  return copy(key);
}

/** Structural verification needs an independently retained head to detect truncation/rollback.
 * This hash chain is NOT a signature, trusted clock, or independent custody service.
 */
export function verifyCryptoEvidence(events, trustedHead) {
  try {
    if (!Array.isArray(events) || events.length === 0 || typeof trustedHead !== 'string')
      return false;
    let previousHash = '0'.repeat(64);
    for (const [index, event] of events.entries()) {
      members(event, ['schemaVersion', 'sequence', 'at', 'type', 'data', 'previousHash', 'hash']);
      const { hash, ...body } = event;
      if (
        event.schemaVersion !== 1 ||
        event.sequence !== index + 1 ||
        event.previousHash !== previousHash ||
        hash !== digest(body)
      )
        return false;
      previousHash = hash;
    }
    return previousHash === trustedHead;
  } catch {
    return false;
  }
}

/** Endpoint-only registry. Services must never hold this instance's recipient private keys. */
export class CryptoEngine {
  #registry;
  #policy;
  #keys = new Map();
  #events = [];
  #health = new Map();
  #clock;

  constructor({ providers, policy, clock = Date.now }) {
    this.#registry = new ProviderRegistry(providers);
    this.#policy = validateCryptoPolicy(policy, this.#registry);
    this.#clock = clock;
    for (const provider of this.#registry.discover())
      this.#health.set(provider.id, { failures: 0, lastFailure: null });
    this.#emit('policy-initialized', {
      policy: this.#policy,
      policyDigest: cryptoPolicyDigest(this.#policy),
    });
  }

  #emit(type, data) {
    const at = this.#clock();
    if (!Number.isSafeInteger(at) || at < 0) throw new TypeError('Invalid evidence time');
    const body = {
      schemaVersion: 1,
      sequence: this.#events.length + 1,
      at,
      type,
      data: copy(data),
      previousHash: this.#events.at(-1)?.hash ?? '0'.repeat(64),
    };
    this.#events.push({ ...body, hash: digest(body) });
  }

  discover() {
    return this.#registry.discover();
  }
  policy() {
    return { configuration: copy(this.#policy), digest: cryptoPolicyDigest(this.#policy) };
  }
  evidence() {
    return copy(this.#events);
  }
  evidenceHead() {
    return this.#events.at(-1).hash;
  }
  keyInventory() {
    return [...this.#keys.values()].map((key) => ({ ...copy(key.descriptor), status: key.status }));
  }
  health() {
    return [...this.#health.entries()].map(([providerId, health]) => ({
      providerId,
      status: health.failures ? 'degraded' : 'registered',
      ...copy(health),
    }));
  }

  assertAllowed({ providerId, suiteId, legacy = false }) {
    const selected = this.#registry.resolve(providerId, suiteId);
    requireCryptoPolicy(this.#policy, { providerId, suiteId }, legacy);
    return selected.suite;
  }

  updatePolicy({ policy, actor, reason }) {
    identifier(actor);
    if (typeof reason !== 'string' || !reason.trim() || reason.length > 512)
      throw new TypeError('Policy change requires a reason');
    const next = validateCryptoPolicy(policy, this.#registry);
    if (next.revision !== this.#policy.revision + 1)
      throw new Error('Policy revision must advance by exactly one');
    this.#emit('policy-changed', {
      actor,
      reason,
      previousDigest: cryptoPolicyDigest(this.#policy),
      policyDigest: cryptoPolicyDigest(next),
      policy: next,
    });
    this.#policy = next;
    return this.policy();
  }

  async #invoke(selection, operation, args) {
    const { operations } = this.#registry.resolve(selection.providerId, selection.suiteId);
    if (typeof operations[operation] !== 'function')
      throw new Error('Provider capability unavailable');
    try {
      return await operations[operation]({ suiteId: selection.suiteId, ...args });
    } catch {
      const health = this.#health.get(selection.providerId);
      health.failures += 1;
      health.lastFailure = operation;
      // Diagnostics disclose operation names only; provider errors may contain sensitive inputs.
      throw new Error(`Provider operation failed: ${operation}; fallback is forbidden`);
    }
  }

  async #prepare({ providerId, suiteId, purpose }, imported) {
    if (!['sign', 'encapsulate'].includes(purpose)) throw new TypeError('Unsupported key purpose');
    const selection = { providerId, suiteId };
    this.assertAllowed(selection);
    const pair = await this.#invoke(
      selection,
      imported === undefined ? 'generateKey' : 'importKey',
      { purpose, ...(imported === undefined ? {} : { key: copy(imported) }) },
    );
    this.assertAllowed(selection);
    if (!pair || !pair.privateKey || !pair.publicKey)
      throw new Error('Provider returned an invalid key pair');
    const identity = { providerId, suiteId, purpose, publicKey: copy(pair.publicKey) };
    const descriptor = { keyId: providerKeyId(identity), ...identity };
    if (this.#keys.has(descriptor.keyId))
      throw new Error('Key identity already exists; reuse is forbidden');
    return { descriptor, privateKey: pair.privateKey, status: 'active' };
  }

  async generateKey(selection) {
    const key = await this.#prepare(selection);
    const { keyId, providerId, suiteId, purpose } = key.descriptor;
    if (this.#keys.has(keyId)) throw new Error('Key identity already exists; reuse is forbidden');
    this.#emit('key-generated', { keyId, providerId, suiteId, purpose });
    this.#keys.set(key.descriptor.keyId, key);
    return copy(key.descriptor);
  }

  async importKey({ key: source, ...selection }) {
    const key = await this.#prepare(selection, source);
    const { keyId, providerId, suiteId, purpose } = key.descriptor;
    if (this.#keys.has(keyId)) throw new Error('Key identity already exists; reuse is forbidden');
    this.#emit('key-imported', { keyId, providerId, suiteId, purpose });
    this.#keys.set(key.descriptor.keyId, key);
    return copy(key.descriptor);
  }

  #private(keyId, purpose, legacy = false) {
    const key = this.#keys.get(keyId);
    if (!key || key.descriptor.purpose !== purpose)
      throw new Error('Unknown key or wrong key purpose');
    if (key.status === 'revoked' || (key.status === 'retired' && (!legacy || purpose === 'sign')))
      throw new Error(`Key is ${key.status}`);
    this.assertAllowed({ ...key.descriptor, legacy });
    return key;
  }

  #public(source, purpose, legacy = false) {
    const key = validateProviderPublicKey(source);
    if (key.purpose !== purpose) throw new Error('Wrong key purpose');
    this.assertAllowed({ ...key, legacy });
    const local = this.#keys.get(key.keyId);
    if (local?.status === 'revoked' || (local?.status === 'retired' && !legacy))
      throw new Error(`Key is ${local.status}`);
    return key;
  }

  async sign({ keyId, data }) {
    const key = this.#private(keyId, 'sign');
    const signature = bytes(
      await this.#invoke(key.descriptor, 'sign', { privateKey: key.privateKey, data: bytes(data) }),
    );
    this.#private(keyId, 'sign');
    return signature;
  }

  async verify({ key: source, data, signature, legacy = false }) {
    const key = this.#public(source, 'sign', legacy);
    const valid = await this.#invoke(key, 'verify', {
      publicKey: key.publicKey,
      data: bytes(data),
      signature: bytes(signature),
    });
    this.#public(key, 'sign', legacy);
    if (typeof valid !== 'boolean')
      throw new Error('Provider returned an invalid verification result');
    return valid;
  }

  async encapsulate({ key: source }) {
    const key = this.#public(source, 'encapsulate');
    const result = await this.#invoke(key, 'encapsulate', { publicKey: key.publicKey });
    try {
      this.#public(key, 'encapsulate');
      return {
        sharedSecret: bytes(result.sharedSecret, 32),
        encapsulation: copy(result.encapsulation),
      };
    } finally {
      result?.sharedSecret?.fill?.(0);
    }
  }

  async decapsulate({ keyId, encapsulation, legacy = false }) {
    const key = this.#private(keyId, 'encapsulate', legacy);
    const sharedSecret = await this.#invoke(key.descriptor, 'decapsulate', {
      privateKey: key.privateKey,
      encapsulation: copy(encapsulation),
    });
    try {
      this.#private(keyId, 'encapsulate', legacy);
      return bytes(sharedSecret, 32);
    } finally {
      sharedSecret?.fill?.(0);
    }
  }

  async encrypt({ providerId, suiteId, key, plaintext, aad }) {
    this.assertAllowed({ providerId, suiteId });
    const packet = await encryptAes(key, plaintext, aad);
    this.assertAllowed({ providerId, suiteId });
    return packet;
  }

  async decrypt({ providerId, suiteId, key, packet, aad, legacy = false }) {
    this.assertAllowed({ providerId, suiteId, legacy });
    const plaintext = await decryptAes(key, copy(packet), aad);
    try {
      this.assertAllowed({ providerId, suiteId, legacy });
      return new Uint8Array(plaintext);
    } finally {
      plaintext.fill(0);
    }
  }

  async wrapKey({ key: source, contentKey, context }) {
    const key = this.#public(source, 'encapsulate');
    const binding = {
      providerId: key.providerId,
      suiteId: key.suiteId,
      recipientKeyId: key.keyId,
      context: copy(context),
    };
    const content = bytes(contentKey, 32);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    let sharedSecret, wrappingKey;
    try {
      const result = await this.encapsulate({ key });
      sharedSecret = result.sharedSecret;
      wrappingKey = await deriveWrapKey(sharedSecret, salt, binding);
      const metadata = {
        schemaVersion: WRAP_SCHEMA_VERSION,
        providerId: key.providerId,
        suiteId: key.suiteId,
        recipientKeyId: key.keyId,
        encapsulation: result.encapsulation,
        salt: encode(salt),
      };
      const aad = utf8.encode(
        canonical({
          domain: WRAP_AAD_DOMAIN,
          context: binding.context,
          packet: metadata,
        }),
      );
      const packet = { ...metadata, ...(await encryptAes(wrappingKey, content, aad)) };
      this.#public(key, 'encapsulate');
      return packet;
    } finally {
      content.fill(0);
      sharedSecret?.fill(0);
      wrappingKey?.fill(0);
    }
  }

  async unwrapKey({ keyId, packet: input, context, legacy = false }) {
    members(input, wrapMembers);
    const packet = copy(input);
    const key = this.#private(keyId, 'encapsulate', legacy);
    if (
      packet.schemaVersion !== WRAP_SCHEMA_VERSION ||
      packet.providerId !== key.descriptor.providerId ||
      packet.suiteId !== key.descriptor.suiteId ||
      packet.recipientKeyId !== keyId
    )
      throw new Error('Wrapped key binding mismatch');
    const { nonce, ciphertext, ...metadata } = packet;
    const binding = {
      providerId: packet.providerId,
      suiteId: packet.suiteId,
      recipientKeyId: keyId,
      context: copy(context),
    };
    let sharedSecret, wrappingKey, plaintext;
    try {
      sharedSecret = await this.decapsulate({ keyId, encapsulation: packet.encapsulation, legacy });
      wrappingKey = await deriveWrapKey(sharedSecret, decode(packet.salt, 32), binding);
      const aad = utf8.encode(
        canonical({
          domain: WRAP_AAD_DOMAIN,
          context: binding.context,
          packet: metadata,
        }),
      );
      plaintext = await decryptAes(wrappingKey, { nonce, ciphertext }, aad);
      this.#private(keyId, 'encapsulate', legacy);
      return bytes(plaintext, 32, 'unwrapped content key');
    } finally {
      sharedSecret?.fill(0);
      wrappingKey?.fill(0);
      plaintext?.fill(0);
    }
  }

  #changeStatus(keyId, status, reason) {
    if (typeof reason !== 'string' || !reason.trim() || reason.length > 512)
      throw new TypeError('Key change requires a reason');
    const key = this.#keys.get(keyId);
    if (!key) throw new Error('Unknown key');
    if (key.status === 'revoked' || key.status === status)
      throw new Error('Key state cannot be reversed or repeated');
    this.#emit(`key-${status}`, { keyId, reason });
    key.status = status;
    if (status === 'revoked') key.privateKey = null;
    return copy(key.descriptor);
  }

  retireKey({ keyId, reason }) {
    return this.#changeStatus(keyId, 'retired', reason);
  }
  revokeKey({ keyId, reason }) {
    return this.#changeStatus(keyId, 'revoked', reason);
  }

  async migrateKey({ keyId, providerId, suiteId, reason }) {
    if (typeof reason !== 'string' || !reason.trim() || reason.length > 512)
      throw new TypeError('Migration requires a reason');
    const prior = this.#keys.get(keyId);
    if (!prior || prior.status !== 'active')
      throw new Error('Migration requires an active source key');
    const next = await this.#prepare({ providerId, suiteId, purpose: prior.descriptor.purpose });
    if (prior.status !== 'active') throw new Error('Source key changed during migration');
    if (this.#keys.has(next.descriptor.keyId))
      throw new Error('Key identity already exists; reuse is forbidden');
    this.#emit('key-migrated', {
      previousKeyId: keyId,
      keyId: next.descriptor.keyId,
      providerId,
      suiteId,
      reason,
      historicalCiphertextReprotected: false,
    });
    prior.status = 'retired';
    this.#keys.set(next.descriptor.keyId, next);
    return copy(next.descriptor);
  }

  async rotateKey({ keyId, reason }) {
    const key = this.#keys.get(keyId);
    if (!key) throw new Error('Unknown key');
    return this.migrateKey({
      keyId,
      providerId: key.descriptor.providerId,
      suiteId: key.descriptor.suiteId,
      reason,
    });
  }
}
