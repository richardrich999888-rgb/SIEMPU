// Originating endpoint. All encryption, signing, grants and admission proofs stay here.
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { canonical, hash, publicJwk, validateKey } from '../../services/control/primitives.mjs';
import {
  bindDatabase,
  privateDatabase,
  makeTransfer,
  acceptedSubmission,
  validateTransfer,
  insist,
  exact,
  validateSource,
  validateDestinations,
  UUID,
} from '../../packages/integration/sealed-transfer.mjs';
import { validateDocument, DOCUMENT_MIME } from './document.mjs';

export class SealedDocumentOutbox {
  constructor({
    database,
    endpoint,
    destinations,
    send,
    dedupKey,
    maxEntries = 10000,
    maxPending = 32,
    maxStoredBytes = 32 * 1024 * 1024,
  }) {
    insist(dedupKey instanceof Uint8Array && dedupKey.length === 32, 'OUTBOX_KEY_REQUIRED');
    insist(
      Number.isSafeInteger(maxEntries) &&
        maxEntries > 0 &&
        maxEntries <= 100000 &&
        Number.isSafeInteger(maxPending) &&
        maxPending > 0 &&
        maxPending <= 128 &&
        Number.isSafeInteger(maxStoredBytes) &&
        maxStoredBytes > 0 &&
        maxStoredBytes <= 1024 * 1024 * 1024,
      'OUTBOX_LIMIT',
    );
    validateKey(endpoint.profile.keys.signing.publicKey);
    validateKey(endpoint.authorityKey);
    this.source = validateSource({
      userId: endpoint.profile.userId,
      deviceId: endpoint.profile.deviceId,
      signingPublicKey: publicJwk(endpoint.profile.keys.signing.publicKey),
    });
    validateDestinations(destinations?.map((d) => d.userId));
    for (const d of destinations) {
      insist(
        exact(d, ['userId', 'deviceId', 'unitId', 'encryptionPublicKey']) &&
          UUID.test(d.deviceId) &&
          UUID.test(d.unitId),
        'OUTBOX_DESTINATION_CONFIG',
      );
      validateKey(d.encryptionPublicKey);
    }
    this.destinations = JSON.parse(canonical(destinations));
    Object.assign(this, { endpoint, send, maxEntries, maxPending, maxStoredBytes });
    this.dedupKey = Buffer.from(dedupKey);
    this.pending = 0;
    this.tail = Promise.resolve();
    this.db = privateDatabase(database);
    try {
      this.db.exec(
        'CREATE TABLE IF NOT EXISTS sealed_outbox(id TEXT PRIMARY KEY,digest TEXT NOT NULL,sealed TEXT NOT NULL,transfer TEXT NOT NULL,response TEXT,mac TEXT NOT NULL);',
      );
      bindDatabase(
        this.db,
        {
          version: 2,
          source: this.source,
          destinations: this.destinations,
          dedupKeyId: hash(this.dedupKey),
          authorityKeyId: hash(canonical(publicJwk(endpoint.authorityKey))),
        },
        'sealed_outbox',
      );
    } catch (error) {
      this.db.close();
      this.dedupKey.fill(0);
      throw error;
    }
  }
  rowMac(row) {
    return createHmac('sha256', this.dedupKey)
      .update('SIEPMU_OUTBOX_ROW_V2\0')
      .update(
        canonical({
          id: row.id,
          digest: row.digest,
          sealed: row.sealed,
          transfer: row.transfer,
          response: row.response ?? null,
        }),
      )
      .digest('hex');
  }
  checkRow(row) {
    insist(
      typeof row.mac === 'string' &&
        /^[a-f0-9]{64}$/.test(row.mac) &&
        timingSafeEqual(Buffer.from(row.mac, 'hex'), Buffer.from(this.rowMac(row), 'hex')),
      'OUTBOX_STORAGE_INTEGRITY',
    );
  }
  async submit(document) {
    insist(this.pending < this.maxPending, 'OUTBOX_BUSY');
    validateDocument(document);
    document = JSON.parse(canonical(document));
    insist(document.originatorUserId === this.source.userId, 'OUTBOX_SENDER_DENIED');
    const destination = this.destinations.find((d) => d.userId === document.destinationUserId);
    insist(destination, 'OUTBOX_DESTINATION_DENIED');
    const prior = this.tail;
    let unlock;
    this.tail = new Promise((r) => {
      unlock = r;
    });
    this.pending++;
    await prior;
    try {
      const digest = createHmac('sha256', this.dedupKey)
        .update('SIEPMU_OUTBOX_DOCUMENT_V2\0')
        .update(canonical(document))
        .digest('hex');
      let row = this.db.prepare('SELECT * FROM sealed_outbox WHERE id=?').get(document.documentId);
      if (row) this.checkRow(row);
      insist(!row || row.digest === digest, 'OUTBOX_DOCUMENT_CONFLICT');
      if (row?.response) return JSON.parse(row.response);
      if (!row) {
        const { n } = this.db.prepare('SELECT COUNT(*) n FROM sealed_outbox').get();
        insist(n < this.maxEntries, 'OUTBOX_CAPACITY');
        const payload = this.endpoint.crypto.createFilePayload(
          `${document.documentId}.json`,
          DOCUMENT_MIME,
          new TextEncoder().encode(canonical(document)),
        );
        const sealed = await this.endpoint.seal(destination, payload);
        const transfer = await makeTransfer(this.endpoint, sealed, randomUUID(), Date.now());
        validateTransfer(
          transfer,
          this.source,
          this.destinations.map((d) => d.userId),
        );
        row = {
          id: document.documentId,
          digest,
          sealed: canonical(sealed),
          transfer: canonical(transfer),
          response: null,
        };
        const { bytes } = this.db
          .prepare(
            'SELECT COALESCE(SUM(length(sealed)+length(transfer)),0) bytes FROM sealed_outbox',
          )
          .get();
        insist(
          bytes + Buffer.byteLength(row.sealed) + Buffer.byteLength(row.transfer) <=
            this.maxStoredBytes,
          'OUTBOX_CAPACITY',
        );
        this.db
          .prepare('INSERT INTO sealed_outbox VALUES(?,?,?,?,NULL,?)')
          .run(document.documentId, digest, row.sealed, row.transfer, this.rowMac(row));
      }
      const sealed = JSON.parse(row.sealed),
        transfer = JSON.parse(row.transfer);
      validateTransfer(
        transfer,
        this.source,
        this.destinations.map((d) => d.userId),
      );
      const answer = await this.send('POST', '/v2/ciphertext', transfer);
      const a = answer.body,
        m = transfer.manifest;
      insist(
        answer.status === 200 &&
          exact(a, ['version', 'requestId', 'objectId', 'state', 'ciphertextHash', 'bytes']) &&
          a.version === 2 &&
          a.requestId === m.requestId &&
          a.objectId === m.objectId &&
          a.state === 'STAGED_CIPHERTEXT' &&
          a.ciphertextHash === m.ciphertextHash &&
          a.bytes === Buffer.from(transfer.ciphertext, 'base64url').length,
        'OUTBOX_STAGING_REJECTED',
      );
      // A staging acknowledgement is never interpreted as platform admission or delivery.
      const accepted = await this.endpoint.submit(sealed);
      const receipt = acceptedSubmission(this.endpoint.authorityKey, accepted, sealed);
      const response = {
        documentId: document.documentId,
        objectId: m.objectId,
        requestId: m.requestId,
        state: 'ADMITTED',
        receipt,
      };
      row.response = canonical(response);
      this.db
        .prepare('UPDATE sealed_outbox SET response=?,mac=? WHERE id=?')
        .run(row.response, this.rowMac(row), document.documentId);
      return response;
    } finally {
      this.pending--;
      unlock();
    }
  }
  async status(documentId) {
    const row = this.db.prepare('SELECT * FROM sealed_outbox WHERE id=?').get(documentId);
    insist(row?.response, 'OUTBOX_DOCUMENT_UNKNOWN');
    this.checkRow(row);
    const { objectId } = JSON.parse(row.response);
    const object = (await this.endpoint.listObjects()).find((o) => o.id === objectId);
    insist(object, 'OUTBOX_DOCUMENT_UNKNOWN');
    return { documentId, objectId, state: object.state };
  }
  close() {
    this.db.close();
    this.dedupKey.fill(0);
  }
}
