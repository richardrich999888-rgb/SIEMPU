// Synthetic document-management system: destination side.
// Runs at the destination unit as an ordinary SIEPMU endpoint (its own MFA-bound device and
// keys). It claims released objects, decrypts at the endpoint, validates the document contract,
// acknowledges delivery and keeps the authority-signed DELIVERY_ACK receipt as evidence.

import { fromDeliveredPayload, DocumentRejected } from './document.mjs';

/** States in which the recipient may attempt a claim (RELEASED: issued but not yet acked). */
const CLAIMABLE = new Set(['PENDING', 'READY', 'RELEASED']);

export class DocumentInbox {
  /**
   * @param {{endpoint: import('../../packages/integration/client.mjs').IntegrationEndpoint,
   *   senders: Map<string, JsonWebKey>}} options senders: operator-pinned signing keys by user ID
   */
  constructor({ endpoint, senders }) {
    Object.assign(this, { endpoint, senders });
  }

  /**
   * Processes every claimable object addressed to this endpoint. Each outcome is either
   * DELIVERED (document plus signed acknowledgement) or a refusal code. A refused object is
   * never partially exposed: nothing is returned for it except its ID and code.
   */
  async poll() {
    const me = this.endpoint.profile.userId;
    const outcomes = [];
    for (const object of await this.endpoint.listObjects()) {
      if (object.recipientUserId !== me || !CLAIMABLE.has(object.state)) continue;
      outcomes.push(await this.#accept(object));
    }
    return outcomes;
  }

  async #accept(object) {
    const senderKey = this.senders.get(object.senderUserId);
    if (!senderKey) return { objectId: object.id, outcome: 'REFUSED', code: 'SENDER_NOT_PINNED' };
    let delivered;
    try {
      delivered = await this.endpoint.receiveWithRelease(object.id, senderKey);
    } catch (error) {
      // The authority's refusal code (e.g. USER_REVOKED) is surfaced; content is not.
      return {
        objectId: object.id,
        outcome: 'REFUSED',
        code: /** @type {any} */ (error).code ?? 'RELEASE_FAILED',
      };
    }
    let document;
    try {
      document = fromDeliveredPayload(this.endpoint.crypto.unpackPayload(delivered.plaintext), {
        senderUserId: object.senderUserId,
        recipientUserId: object.recipientUserId,
      });
    } catch (error) {
      // Released and decrypted but not a valid document: do not acknowledge it as delivered.
      const code = error instanceof DocumentRejected ? error.code : 'DOCUMENT_INVALID';
      return { objectId: object.id, outcome: 'REFUSED', code };
    }
    const acknowledgement = await this.endpoint.acknowledge(object.id, delivered.release);
    return {
      objectId: object.id,
      outcome: 'DELIVERED',
      document,
      release: delivered.release,
      acknowledgement,
    };
  }
}
