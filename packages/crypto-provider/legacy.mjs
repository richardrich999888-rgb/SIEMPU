import { encryptObject, decryptObject } from '../crypto/crypto.mjs';
import { CLASSICAL_PROVIDER_ID, CLASSICAL_SUITE_ID } from './classical.mjs';

/** Explicit compatibility path; existing envelope bytes, IDs, and signatures are unchanged. */
export function createLegacyAdapter(engine) {
  const selection = { providerId: CLASSICAL_PROVIDER_ID, suiteId: CLASSICAL_SUITE_ID };
  return {
    async encryptObject(context, payload, recipientPublicKey, senderPrivateKey) {
      engine.assertAllowed(selection);
      const result = await encryptObject(context, payload, recipientPublicKey, senderPrivateKey);
      engine.assertAllowed(selection);
      return result;
    },
    async decryptObject(submission, recipientPrivateKey, senderPublicKey, { legacy = false } = {}) {
      if (legacy !== true)
        throw new Error('Historical object access requires explicit legacy policy');
      engine.assertAllowed({ ...selection, legacy });
      const result = await decryptObject(submission, recipientPrivateKey, senderPublicKey);
      engine.assertAllowed({ ...selection, legacy });
      return result;
    },
  };
}
