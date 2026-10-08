/** Node TLS transport; CA validation and certificate-role authorization are separate checks. */
import { createServer, request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { X509Certificate } from 'node:crypto';

const normalize = (value) => String(value).replaceAll(':', '').toLowerCase();
const validPin = (value) => /^[a-f0-9]{64}$/.test(normalize(value));
export const certificatePin = (cert) => normalize(new X509Certificate(cert).fingerprint256);

export function secureServerFactory(
  { key, cert, ca, allowedClientPins = [] },
  { mutual = true } = {},
) {
  if (
    !key ||
    !cert ||
    !ca ||
    (mutual && !allowedClientPins.length) ||
    !allowedClientPins.every(validPin)
  )
    throw new Error('TLS identity, trust anchor and explicit peer authorization required');
  const pins = new Set(allowedClientPins.map(normalize));
  return (handler) =>
    createServer(
      { key, cert, ca, minVersion: 'TLSv1.3', requestCert: mutual, rejectUnauthorized: true },
      (req, res) => {
        if (
          mutual &&
          (!req.socket.authorized ||
            !pins.has(normalize(req.socket.getPeerCertificate().fingerprint256)))
        ) {
          res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end(JSON.stringify({ error: 'SERVICE_IDENTITY_DENIED' }));
          return;
        }
        handler(req, res);
      },
    );
}

export function secureClientOptions({ ca, key, cert, serverPin }) {
  if (!ca || !validPin(serverPin) || Boolean(key) !== Boolean(cert))
    throw new Error(
      'TLS trust anchor, pinned server and complete optional client identity required',
    );
  return Object.freeze({
    ca,
    key,
    cert,
    minVersion: 'TLSv1.3',
    rejectUnauthorized: true,
    agent: false,
    checkServerIdentity: (host, peer) =>
      checkServerIdentity(host, peer) ||
      (normalize(peer.fingerprint256) === normalize(serverPin)
        ? undefined
        : new Error('SERVICE_IDENTITY_DENIED')),
  });
}

/** Bounded HTTPS-only fetch subset for fixed internal services. Never redirects or falls back. */
export function secureFetch(
  identity,
  { maxResponseBytes = 8 * 1024 * 1024, timeoutMs = 15000 } = {},
) {
  const tls = secureClientOptions(identity);
  return async (input, init = {}) => {
    const url = new URL(input);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Authenticated HTTPS destination required');
    if (
      init.body !== undefined &&
      typeof init.body !== 'string' &&
      !Buffer.isBuffer(init.body) &&
      !(init.body instanceof Uint8Array)
    )
      throw new Error('Only bounded byte request bodies are supported');
    return new Promise((resolve, reject) => {
      const outgoing = request(
        url,
        { ...tls, method: init.method || 'GET', headers: init.headers, signal: init.signal },
        (incoming) => {
          const chunks = [];
          let bytes = 0;
          if (incoming.statusCode >= 300 && incoming.statusCode < 400) {
            incoming.destroy(new Error('Service redirects forbidden'));
          }
          incoming.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > maxResponseBytes)
              incoming.destroy(new Error('Service response exceeds limit'));
            else chunks.push(chunk);
          });
          incoming.once('error', reject);
          incoming.once('end', () => {
            clearTimeout(timer);
            resolve(
              new Response(incoming.statusCode === 204 ? null : Buffer.concat(chunks), {
                status: incoming.statusCode,
                headers: incoming.headers,
              }),
            );
          });
        },
      );
      const timer = setTimeout(
        () => outgoing.destroy(new Error('Service request timed out')),
        timeoutMs,
      );
      outgoing.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      outgoing.once('close', () => clearTimeout(timer));
      outgoing.end(init.body);
    });
  };
}
