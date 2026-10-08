import { copy, digest, identifier, members } from './primitives.mjs';

export function validateCryptoPolicy(value, registry) {
  members(value, ['schemaVersion', 'revision', 'mode', 'newSuites', 'legacySuites']);
  if (
    value.schemaVersion !== 1 ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1 ||
    !['laboratory', 'production'].includes(value.mode)
  )
    throw new TypeError('Invalid cryptographic policy');
  for (const list of [value.newSuites, value.legacySuites]) {
    if (!Array.isArray(list)) throw new TypeError('Suite policy must be an explicit list');
    const unique = new Set();
    for (const selection of list) {
      members(selection, ['providerId', 'suiteId']);
      identifier(selection.providerId);
      identifier(selection.suiteId);
      const { suite } = registry.resolve(selection.providerId, selection.suiteId);
      const pair = `${selection.providerId}/${selection.suiteId}`;
      if (unique.has(pair)) throw new TypeError('Duplicate policy suite');
      if (value.mode === 'production' && suite.laboratory)
        throw new Error('Laboratory suites are forbidden by production policy');
      unique.add(pair);
    }
  }
  return copy(value);
}

export function requireCryptoPolicy(policy, selection, legacy = false) {
  if (typeof legacy !== 'boolean') throw new TypeError('Legacy policy flag must be explicit');
  const list = legacy ? policy.legacySuites : policy.newSuites;
  if (!list.some((s) => s.providerId === selection.providerId && s.suiteId === selection.suiteId))
    throw new Error(`Cryptographic suite forbidden by ${legacy ? 'legacy' : 'new-use'} policy`);
}

export const cryptoPolicyDigest = (policy) => digest(policy);
