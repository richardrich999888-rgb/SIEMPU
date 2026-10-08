import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as httpsServer, request as httpsRequest } from 'node:https';
import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';
import { X509Certificate, constants } from 'node:crypto';

/** @typedef {import('node:https').ServerOptions & {clientFingerprints?: string[]}} ServerTLS */
/** @typedef {import('node:https').RequestOptions} ClientTLS */
const profiles = new Set(['development', 'secure', 'isolated']);
/** @param {NodeJS.ProcessEnv} [env] */
export function secureProfile(env = process.env) {
  const profile = env.SIEPMU_PROFILE ?? 'development';
  if (!profiles.has(profile)) throw new Error('Unknown deployment profile');
  if (profile !== 'development' && env.SIEPMU_ALLOW_REMOTE_HTTP === '1')
    throw new Error('Secure profiles forbid the plaintext override');
  return profile !== 'development';
}
/** @param {string | undefined} path @param {boolean} [secret] */
function readMaterial(path, secret = false) {
  if (!path) throw new Error('Required TLS material missing');
  // Inspect and read the same open descriptor. This avoids a pathname
  // time-of-check/time-of-use race when TLS material is rotated.
  let fd;
  try {
    fd = openSync(path, 'r');
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error('Required TLS material missing');
    if (secret && stat.mode & 0o077) throw new Error('TLS key permissions must be 0600');
    return readFileSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
/** @param {string} value */
export const fingerprint = (value) => value.replaceAll(':', '').toLowerCase();
/** @param {string} role @param {NodeJS.ProcessEnv} [env] @returns {ServerTLS | undefined} */
export function serverTLS(role, env = process.env) {
  if (!secureProfile(env)) return undefined;
  const p = 'SIEPMU_' + role.toUpperCase() + '_TLS_';
  const mutual = role !== 'web';
  const pins = (env[p + 'CLIENT_PINS'] ?? '').split(',').filter(Boolean).map(fingerprint);
  if (mutual && (!pins.length || pins.some((x) => !/^[a-f0-9]{64}$/.test(x))))
    throw new Error('mTLS requires explicit permitted client certificate fingerprints');
  return {
    cert: readMaterial(env[p + 'CERT']),
    key: readMaterial(env[p + 'KEY'], true),
    ca: readMaterial(env.SIEPMU_TLS_CA),
    ...(env.SIEPMU_TLS_CRL ? { crl: readMaterial(env.SIEPMU_TLS_CRL) } : {}),
    requestCert: mutual,
    rejectUnauthorized: true,
    clientFingerprints: pins,
  };
}
/** @param {string} role @param {NodeJS.ProcessEnv} [env] @returns {ClientTLS | undefined} */
export function clientTLS(role, env = process.env) {
  if (!secureProfile(env)) return undefined;
  const p = 'SIEPMU_' + role.toUpperCase() + '_CLIENT_TLS_';
  return {
    ca: readMaterial(env.SIEPMU_TLS_CA),
    cert: readMaterial(env[p + 'CERT']),
    key: readMaterial(env[p + 'KEY'], true),
    ...(env.SIEPMU_TLS_CRL ? { crl: readMaterial(env.SIEPMU_TLS_CRL) } : {}),
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    rejectUnauthorized: true,
  };
}
/** @param {import('node:http').RequestListener} handler @param {ServerTLS | undefined} tls */
export function createTransportServer(handler, tls) {
  if (!tls) return httpServer(handler);
  if (!tls.cert || !tls.key || !tls.ca) throw new Error('Incomplete TLS configuration');
  const pins = new Set((tls.clientFingerprints ?? []).map(fingerprint));
  if (tls.requestCert && (!pins.size || [...pins].some((x) => !/^[a-f0-9]{64}$/.test(x))))
    throw new Error('mTLS identity allowlist missing');
  const server = httpsServer(
    {
      ...tls,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      rejectUnauthorized: true,
      secureOptions: constants.SSL_OP_NO_TICKET,
    },
    (req, res) => {
      const socket = /** @type {import('node:tls').TLSSocket} */ (req.socket);
      const peer = socket.getPeerCertificate();
      if (
        tls.requestCert &&
        (!socket.authorized ||
          !peer.raw ||
          !pins.has(fingerprint(new X509Certificate(peer.raw).fingerprint256)))
      ) {
        res.writeHead(403, { 'content-type': 'application/json', connection: 'close' });
        res.end(JSON.stringify({ code: 'SERVICE_IDENTITY_DENIED' }));
        return;
      }
      // Recheck validity on every request, including an existing keep-alive session.
      if (tls.requestCert && Date.parse(peer.valid_to) <= Date.now()) {
        res.writeHead(403, { connection: 'close' });
        res.end();
        return;
      }
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      handler(req, res);
    },
  );
  return server;
}

/** @param {URL | string} target @param {{method?: string, headers?: import('node:http').OutgoingHttpHeaders,
 * body?: Uint8Array | string, tls?: ClientTLS, timeoutMs?: number, maxBytes?: number}} [options]
 * @returns {Promise<{status:number, headers:import('node:http').IncomingHttpHeaders, body:Buffer}>} */
export function requestBytes(
  target,
  { method = 'GET', headers = {}, body, tls, timeoutMs = 10000, maxBytes = 8 * 1024 * 1024 } = {},
) {
  const url = new URL(target);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash)
    throw new Error('Invalid transport destination');
  if (tls && url.protocol !== 'https:') throw new Error('TLS transport cannot downgrade');
  return new Promise((resolve, reject) => {
    let settled = false;
    /** @type {ReturnType<typeof setTimeout>} */ let timer;
    /** @param {Error | null} error @param {{status:number,headers:import('node:http').IncomingHttpHeaders,body:Buffer}} [response] */
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else if (response) resolve(response);
    };
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
      url,
      {
        ...tls,
        method,
        headers,
        agent: false,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
      },
      (response) => {
        const status = response.statusCode ?? 502;
        if (
          (status >= 300 && status < 400) ||
          Number(response.headers['content-length'] ?? 0) > maxBytes
        ) {
          response.destroy();
          finish(new Error('Redirect or oversized response rejected'));
          return;
        }
        /** @type {Buffer[]} */ const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) {
            response.destroy();
            finish(new Error('Transport response exceeds bound'));
          } else chunks.push(chunk);
        });
        response.on('aborted', () => finish(new Error('Transport response interrupted')));
        response.on('error', (error) => finish(error));
        response.on('end', () =>
          finish(null, { status, headers: response.headers, body: Buffer.concat(chunks) }),
        );
      },
    );
    request.on('error', (error) => finish(error));
    timer = setTimeout(() => request.destroy(new Error('Transport deadline exceeded')), timeoutMs);
    request.end(body);
  });
}
