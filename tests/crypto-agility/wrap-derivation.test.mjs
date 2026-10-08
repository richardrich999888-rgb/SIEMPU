// Pinned application-composition vectors for wrap derivation v2 (ADR-010).
// The expected values were produced by packages/crypto-provider/primitives.mjs and reproduced
// independently with Python's standard library (hmac/hashlib RFC 5869 HKDF and sorted-key JSON);
// the procedure is in research/cryptographic-standards/V3_COMPOSITION.md. Any change to the
// derivation domain, the info member set, the canonical encoding or the context digest breaks
// these vectors, which is the point: such a change needs a new wrap schema version.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonical } from '../../packages/protocol/canonical.mjs';
import {
  deriveWrapKey,
  WRAP_DERIVATION_DOMAIN,
} from '../../packages/crypto-provider/primitives.mjs';

/** 32 consecutive byte values starting at `start` (deterministic synthetic inputs). */
const sequence = (start) => Uint8Array.from({ length: 32 }, (_, i) => start + i);
const hex = (bytes) => Buffer.from(bytes).toString('hex');

const SHARED_SECRET = () => sequence(0x00);
const SALT = () => sequence(0x20);
const BINDING = Object.freeze({
  providerId: 'node-openssl-pqc-lab',
  suiteId: 'ML-KEM-768-ML-DSA-65-AES-256-GCM-v1',
  recipientKeyId: '11'.repeat(32),
  context: Object.freeze({
    objectId: '00000000-0000-4000-8000-000000000001',
    ciphertextHash: '22'.repeat(32),
    schemaVersion: 3,
  }),
});
const binding = (overrides = {}) => ({ ...BINDING, context: { ...BINDING.context }, ...overrides });

const EXPECTED_CONTEXT_DIGEST = 'f9c669dc03db1b3c6cd3b5df0df21612a1efc8bab92cd2d7247b6f526e717ff5';
const EXPECTED_INFO =
  '{"contextDigest":"f9c669dc03db1b3c6cd3b5df0df21612a1efc8bab92cd2d7247b6f526e717ff5",' +
  '"domain":"SIEPMU_PROVIDER_KEY_WRAP_V2","providerId":"node-openssl-pqc-lab",' +
  '"recipientKeyId":"1111111111111111111111111111111111111111111111111111111111111111",' +
  '"suiteId":"ML-KEM-768-ML-DSA-65-AES-256-GCM-v1"}';
const EXPECTED_WRAP_KEY = 'f41e8d6a5e96601baa5a8f7becb4bd3a22c883d7b3caee412532ea5f0f25c985';

test('wrap derivation v2 reproduces the pinned context digest, info bytes and key', async () => {
  assert.equal(WRAP_DERIVATION_DOMAIN, 'SIEPMU_PROVIDER_KEY_WRAP_V2');
  const digest = createHash('sha256').update(canonical(BINDING.context)).digest('hex');
  assert.equal(digest, EXPECTED_CONTEXT_DIGEST);
  const info = canonical({
    domain: WRAP_DERIVATION_DOMAIN,
    providerId: BINDING.providerId,
    suiteId: BINDING.suiteId,
    recipientKeyId: BINDING.recipientKeyId,
    contextDigest: digest,
  });
  assert.equal(info, EXPECTED_INFO);
  // HKDF info must stay within the WebCrypto 1024-byte limit for every context size.
  assert.ok(Buffer.byteLength(info) <= 1024);
  assert.equal(hex(await deriveWrapKey(SHARED_SECRET(), SALT(), binding())), EXPECTED_WRAP_KEY);
});

test('every bound member changes the derived key', async () => {
  const variants = [
    binding({ providerId: 'noble-xwing-lab' }),
    binding({ suiteId: 'ML-KEM-1024-ML-DSA-65-AES-256-GCM-v1' }),
    binding({ recipientKeyId: '33'.repeat(32) }),
    binding({ context: { ...BINDING.context, ciphertextHash: '23'.repeat(32) } }),
    binding({ context: { ...BINDING.context, objectId: '00000000-0000-4000-8000-000000000002' } }),
  ];
  const keys = new Set([EXPECTED_WRAP_KEY]);
  for (const variant of variants)
    keys.add(hex(await deriveWrapKey(SHARED_SECRET(), SALT(), variant)));
  const salt = SALT();
  salt[0] ^= 1;
  keys.add(hex(await deriveWrapKey(SHARED_SECRET(), salt, binding())));
  const secret = SHARED_SECRET();
  secret[31] ^= 1;
  keys.add(hex(await deriveWrapKey(secret, SALT(), binding())));
  assert.equal(keys.size, variants.length + 3, 'no two bindings may derive the same key');
});

test('a context larger than the WebCrypto HKDF info limit still derives (bound by digest)', async () => {
  const large = binding({ context: { ...BINDING.context, grant: 'g'.repeat(8192) } });
  const key = await deriveWrapKey(SHARED_SECRET(), SALT(), large);
  assert.equal(key.length, 32);
  assert.notEqual(hex(key), EXPECTED_WRAP_KEY);
});

test('malformed derivation inputs fail closed', async () => {
  const cases = [
    () => deriveWrapKey(new Uint8Array(31), SALT(), binding()),
    () => deriveWrapKey(new Uint8Array(33), SALT(), binding()),
    () => deriveWrapKey(SHARED_SECRET(), new Uint8Array(16), binding()),
    () => deriveWrapKey('not-bytes', SALT(), binding()),
    () => deriveWrapKey(SHARED_SECRET(), SALT(), { ...binding(), extra: 1 }),
    () => deriveWrapKey(SHARED_SECRET(), SALT(), { ...binding(), context: undefined }),
    () => deriveWrapKey(SHARED_SECRET(), SALT(), binding({ context: { n: 1.5 } })),
  ];
  for (const attempt of cases) await assert.rejects(attempt, TypeError);
});
