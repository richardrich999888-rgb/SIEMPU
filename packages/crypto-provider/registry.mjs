import { copy, identifier } from './primitives.mjs';

const required = ['generateKey', 'sign', 'verify', 'encapsulate', 'decapsulate'];

/** Providers are trusted local implementations, never remotely supplied executable plugins. */
export class ProviderRegistry {
  #providers = new Map();

  constructor(providers) {
    if (!Array.isArray(providers) || providers.length === 0)
      throw new TypeError('At least one provider is required');
    for (const provider of providers) {
      const descriptor = copy(provider.descriptor);
      identifier(descriptor.id);
      if (
        descriptor.apiVersion !== 1 ||
        !Array.isArray(descriptor.suites) ||
        descriptor.suites.length === 0 ||
        required.some((method) => typeof provider[method] !== 'function')
      )
        throw new TypeError('Unsupported provider interface');
      const suites = new Set();
      for (const suite of descriptor.suites) {
        identifier(suite.id);
        if (
          suites.has(suite.id) ||
          typeof suite.signature !== 'string' ||
          typeof suite.establishment !== 'string' ||
          suite.contentEncryption !== 'AES-256-GCM' ||
          typeof suite.laboratory !== 'boolean'
        )
          throw new TypeError('Invalid suite declaration');
        suites.add(suite.id);
      }
      if (this.#providers.has(descriptor.id)) throw new Error('Duplicate provider ID');
      // Capture functions at registration: descriptor mutation cannot change routing.
      const operations = Object.freeze(
        Object.fromEntries(
          [...required, 'importKey']
            .filter((m) => typeof provider[m] === 'function')
            .map((m) => [m, provider[m].bind(provider)]),
        ),
      );
      this.#providers.set(descriptor.id, { descriptor, operations });
    }
  }

  discover() {
    return [...this.#providers.values()].map(({ descriptor }) => copy(descriptor));
  }

  resolve(providerId, suiteId) {
    const selected = this.#providers.get(providerId);
    const suite = selected?.descriptor.suites.find((candidate) => candidate.id === suiteId);
    if (!suite) throw new Error('Unsupported provider or suite; fallback is forbidden');
    return { operations: selected.operations, suite: copy(suite) };
  }
}
