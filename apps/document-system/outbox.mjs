// Synthetic document-management system: source side.
// Hands validated documents to the SIEPMU integration adapter over mutual TLS and records the
// adapter's answer durably. It holds no SIEPMU credential and no key material: the adapter's
// managed endpoint seals and submits, and the authority decides release.

import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { canonical } from '../../packages/protocol/canonical.mjs';
import { requestBytes } from '../../packages/transport/tls.mjs';
import { validateDocument, toAdapterRequest, DocumentRejected } from './document.mjs';

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

/**
 * Default transport: HTTPS with this system's own client certificate (its source identity).
 * @param {string} adapterUrl e.g. https://127.0.0.1:8446
 * @param {object} tls client material {cert, key, ca}
 */
export function adapterTransport(adapterUrl, tls) {
  if (new URL(adapterUrl).protocol !== 'https:' || !tls) throw new Error('DMS_TLS_REQUIRED');
  return async (method, path, body) => {
    const r = await requestBytes(adapterUrl + path, {
      method,
      tls,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let parsed = null;
    try {
      parsed = JSON.parse(r.body);
    } catch {}
    return { status: r.status, body: parsed };
  };
}

export class DocumentOutbox {
  /**
   * @param {{database: string, send: (method: string, path: string, body?: object) =>
   *   Promise<{status: number, body: any}>, createFilePayload: Function,
   *   clock?: () => number}} options
   */
  constructor({ database, send, createFilePayload, clock = Date.now }) {
    Object.assign(this, { send, createFilePayload, clock });
    this.db = new DatabaseSync(database);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS outbox(' +
        'document_id TEXT PRIMARY KEY, digest TEXT NOT NULL, request TEXT NOT NULL, response TEXT);',
    );
  }

  /**
   * Submits a document once. Resubmitting the same document returns the recorded answer, or
   * re-sends the identical request if the earlier answer was lost (the adapter is idempotent on
   * the request ID). A different document under the same ID is refused locally.
   * @returns {Promise<{documentId: string, requestId: string, objectId: string}>}
   */
  async submit(document) {
    validateDocument(document);
    const digest = sha256(canonical(document));
    let row = this.db
      .prepare('SELECT * FROM outbox WHERE document_id=?')
      .get(/** @type {string} */ (document.documentId));
    if (row && row.digest !== digest) throw new DocumentRejected('DOCUMENT_CONFLICT');
    if (row?.response) return JSON.parse(/** @type {string} */ (row.response));
    if (!row) {
      const request = toAdapterRequest({
        document,
        requestId: randomUUID(),
        issuedAt: this.clock(),
        createFilePayload: this.createFilePayload,
      });
      this.db
        .prepare('INSERT INTO outbox VALUES(?,?,?,NULL)')
        .run(/** @type {string} */ (document.documentId), digest, canonical(request));
      row = { request: canonical(request) };
    }
    const request = JSON.parse(/** @type {string} */ (row.request));
    const answer = await this.send('POST', '/v1/messages', request);
    if (answer.status !== 200 || answer.body?.accepted !== true)
      throw new DocumentRejected(
        answer.status === 403 ? 'SOURCE_NOT_AUTHENTICATED' : 'ADAPTER_REJECTED',
      );
    const response = {
      documentId: document.documentId,
      requestId: request.requestId,
      objectId: answer.body.objectId,
    };
    this.db
      .prepare('UPDATE outbox SET response=? WHERE document_id=?')
      .run(canonical(response), /** @type {string} */ (document.documentId));
    return response;
  }

  /** Current delivery state of a submitted document, via the adapter. */
  async status(documentId) {
    const row = this.db.prepare('SELECT response FROM outbox WHERE document_id=?').get(documentId);
    if (!row?.response) throw new DocumentRejected('DOCUMENT_UNKNOWN');
    const { requestId } = JSON.parse(/** @type {string} */ (row.response));
    const answer = await this.send('GET', `/v1/messages/${requestId}`);
    if (answer.status !== 200) throw new DocumentRejected('STATUS_UNAVAILABLE');
    return { documentId, state: answer.body.state, objectId: answer.body.objectId };
  }

  close() {
    this.db.close();
  }
}
