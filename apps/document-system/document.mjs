// Synthetic document-management system: pure document contract (no I/O, no clock reads).
//
// This emulates an existing departmental document application that hands documents to SIEPMU
// through the integration adapter. It is NOT a model of any real IAF, AFNET or e-Office
// interface; the field set is invented, synthetic and unclassified, and exists to show that a
// sponsor-specified interface can be bound to the adapter without changing the security core.
// Sponsor question recorded in research/trl56/16-iaf-clarification-register.md.

import { canonical } from '../../packages/protocol/canonical.mjs';

/** Document contract version; unknown versions fail closed. */
export const DOCUMENT_SCHEMA_VERSION = 1;
/** The only marking this synthetic system accepts. Anything else is refused at the source. */
export const SYNTHETIC_MARKING = 'SYNTHETIC-UNCLASSIFIED';
/** MIME type of the canonical document carried as an encrypted file payload. */
export const DOCUMENT_MIME = 'application/vnd.siepmu.synthetic-document+json';
/** Bounds chosen to stay well below the adapter's 512 KiB request limit after base64. */
export const MAX_TITLE_CHARS = 200;
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_REFERENCE_CHARS = 64;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REFERENCE = /^[A-Z0-9][A-Z0-9/._-]{0,63}$/;
const DOCUMENT_MEMBERS = [
  'version',
  'documentId',
  'reference',
  'title',
  'marking',
  'body',
  'originatorUserId',
  'destinationUserId',
];
const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

/** Error carrying a stable code; messages never contain document content. */
export class DocumentRejected extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** @param {unknown} condition @param {string} code @returns {asserts condition} */
function require_(condition, code) {
  if (!condition) throw new DocumentRejected(code);
}

/** Rejects control characters other than tab/newline/carriage return. */
const printable = (text) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text);

/**
 * Validates a synthetic document exactly: member set, version, identifiers, marking and bounds.
 * @param {Record<string, unknown>} document
 * @returns {Record<string, unknown>} the same document, after validation
 */
export function validateDocument(document) {
  require_(
    document !== null && typeof document === 'object' && !Array.isArray(document),
    'DOCUMENT_SCHEMA',
  );
  const keys = Object.keys(document).sort();
  require_(
    keys.length === DOCUMENT_MEMBERS.length &&
      DOCUMENT_MEMBERS.every((k) => Object.hasOwn(document, k)),
    'DOCUMENT_SCHEMA',
  );
  require_(document.version === DOCUMENT_SCHEMA_VERSION, 'DOCUMENT_VERSION');
  for (const field of ['documentId', 'originatorUserId', 'destinationUserId'])
    require_(typeof document[field] === 'string' && UUID.test(document[field]), 'DOCUMENT_SCHEMA');
  require_(
    typeof document.reference === 'string' && REFERENCE.test(document.reference),
    'DOCUMENT_SCHEMA',
  );
  require_(document.marking === SYNTHETIC_MARKING, 'DOCUMENT_MARKING');
  require_(
    typeof document.title === 'string' &&
      document.title.length >= 1 &&
      document.title.length <= MAX_TITLE_CHARS &&
      printable(document.title),
    'DOCUMENT_SCHEMA',
  );
  require_(
    typeof document.body === 'string' &&
      utf8.encode(document.body).length <= MAX_BODY_BYTES &&
      printable(document.body),
    'DOCUMENT_SCHEMA',
  );
  return document;
}

/**
 * Builds the adapter request for a validated document. The request ID is derived by the caller
 * and stored durably, so a resubmission of the same document is idempotent at the adapter.
 * @param {{document: Record<string, any>, requestId: string, issuedAt: number,
 *   createFilePayload: (name: string, mime: string, bytes: Uint8Array) => object}} input
 */
export function toAdapterRequest({ document, requestId, issuedAt, createFilePayload }) {
  validateDocument(document);
  require_(typeof requestId === 'string' && UUID.test(requestId), 'REQUEST_ID');
  require_(Number.isSafeInteger(issuedAt) && issuedAt >= 0, 'ISSUED_AT');
  return {
    version: 1,
    requestId,
    issuedAt,
    senderUserId: document.originatorUserId,
    destinationUserId: document.destinationUserId,
    payload: createFilePayload(
      `${document.documentId}.json`,
      DOCUMENT_MIME,
      utf8.encode(canonical(document)),
    ),
  };
}

/**
 * Parses a decrypted payload back into a document and checks it is addressed as expected.
 * @param {{kind: string, name: string, mime: string, bytes: Uint8Array}} unpacked
 * @param {{senderUserId: string, recipientUserId: string}} expected authority-attested parties
 */
export function fromDeliveredPayload(unpacked, expected) {
  require_(unpacked?.kind === 'file' && unpacked.mime === DOCUMENT_MIME, 'DOCUMENT_TYPE');
  let document;
  try {
    document = JSON.parse(strictUtf8.decode(unpacked.bytes));
  } catch {
    throw new DocumentRejected('DOCUMENT_ENCODING');
  }
  validateDocument(document);
  // Canonical form only: a re-encoded or padded document is not the one the source signed.
  require_(strictUtf8.decode(unpacked.bytes) === canonical(document), 'DOCUMENT_ENCODING');
  require_(unpacked.name === `${document.documentId}.json`, 'DOCUMENT_NAME');
  // The authority attests sender and recipient; the document must not claim different parties.
  require_(
    document.originatorUserId === expected.senderUserId &&
      document.destinationUserId === expected.recipientUserId,
    'DOCUMENT_PARTY_MISMATCH',
  );
  return document;
}
