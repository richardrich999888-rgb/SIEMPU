import { createTelemetryExporter } from '../monitoring/exporter.mjs';
import {
  createRecoveryGuard,
  remoteAnchorQuery,
  remoteCustodyExchange,
} from '../evidence/custody.mjs';
import {
  createTransportServer,
  serverTLS,
  clientTLS,
  secureProfile,
} from '../../packages/transport/tls.mjs';
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { Authority, AppError } from './core.mjs';
import { createRelayClient } from '../relay/client.mjs';
export function createControlServer({
  authority,
  allowedOrigin,
  tls = serverTLS('control'),
  telemetry,
}) {
  const server = createTransportServer(async (req, res) => {
    const started = performance.now(),
      requestId = randomUUID();
    res.setHeader('X-Request-Id', requestId);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    let status = 500,
      code = 'INTERNAL_ERROR';
    try {
      const path = req.url.split('?')[0];
      if (req.url.includes('?') || path.includes('%') || path.includes('..'))
        throw new AppError(400, 'INVALID_PATH');
      if (req.headers.origin && req.headers.origin !== allowedOrigin)
        throw new AppError(403, 'ORIGIN_DENIED');
      const mutation = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method);
      if (mutation && req.headers['content-type']?.split(';')[0] !== 'application/json')
        throw new AppError(415, 'JSON_REQUIRED');
      let chunks = [],
        size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1500000) throw new AppError(413, 'BODY_TOO_LARGE');
        chunks.push(chunk);
      }
      let body = {};
      if (size) {
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          throw new AppError(400, 'INVALID_JSON');
        }
        if (!body || typeof body !== 'object' || Array.isArray(body))
          throw new AppError(400, 'INVALID_JSON');
      }
      const auth = req.headers.authorization;
      const token = auth?.startsWith('Bearer ') ? auth.slice(7) : undefined;
      const result = await authority.dispatch(req.method, path, body, token, {
        ip: req.socket.remoteAddress ?? 'unknown',
        requestId,
      });
      status = result.status;
      code = status < 400 ? 'OK' : result.body.code;
      res.writeHead(status);
      res.end(JSON.stringify(status >= 400 ? { ...result.body, requestId } : result.body));
    } catch (e) {
      status =
        e instanceof AppError ? e.status : e.code?.startsWith('SQLITE_CONSTRAINT') ? 409 : 500;
      code = e instanceof AppError ? e.code : status === 409 ? 'CONFLICT' : 'INTERNAL_ERROR';
      if (status === 500)
        console.error(
          JSON.stringify({
            service: 'control',
            event: 'internal_error',
            requestId,
            errorType: e.name,
            message: process.env.NODE_ENV === 'test' ? e.message : undefined,
          }),
        );
      res.writeHead(status);
      res.end(
        JSON.stringify({ error: code, code, ...(e instanceof AppError ? e.extra : {}), requestId }),
      );
    } finally {
      try {
        authority.count('requests');
        if (status >= 400) authority.count('requestErrors');
        if (status === 403 || status === 401) {
          authority.tx(() => authority.alert('REQUEST_DENIED', null, code));
        }
      } catch {}
      if (telemetry && !(await telemetry.deliver(authority)))
        console.error(
          JSON.stringify({ service: 'control', event: 'monitoring_degraded', requestId }),
        );
      console.log(
        JSON.stringify({
          timestamp: Date.now(),
          service: 'control',
          requestId,
          method: req.method,
          result: status,
          reason: code,
          latencyMs: Math.round((performance.now() - started) * 100) / 100,
        }),
      );
    }
  }, tls);
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}
/**
 * Parses SIEPMU_ALLOW_PQC_LAB. Only omission (disabled) or exactly "1" (enabled) is accepted;
 * any other value fails closed at start-up rather than being interpreted.
 * @param {string | undefined} value
 */
export function parsePqcLabFlag(value) {
  if (value === undefined) return false;
  if (value === '1') return true;
  throw new Error('SIEPMU_ALLOW_PQC_LAB accepts only explicit 1 or omission');
}
export function startControl() {
  const allowPqcLab = parsePqcLabFlag(process.env.SIEPMU_ALLOW_PQC_LAB);
  const dir = resolve(process.env.SIEPMU_DATA_DIR ?? '.data');
  for (const f of ['server-key.json', 'master.key', 'relay.secret']) {
    if ((statSync(resolve(dir, f)).mode & 0o077) !== 0)
      throw new Error('Secret file permissions must be 0600');
  }
  const relay = createRelayClient({
    baseUrl:
      process.env.SIEPMU_RELAY_URL ?? 'http://127.0.0.1:' + (process.env.SIEPMU_RELAY_PORT ?? 8082),
    secretFile: resolve(dir, 'relay.secret'),
    tls: clientTLS('control'),
  });
  const authority = new Authority({
    dbPath: resolve(dir, 'control.sqlite'),
    signingKey: JSON.parse(readFileSync(resolve(dir, 'server-key.json'), 'utf8')),
    masterKey: readFileSync(resolve(dir, 'master.key')),
    relay,
    allowPqcLab,
    recoveryGuard: secureProfile()
      ? createRecoveryGuard({
          custodianKey: JSON.parse(readFileSync(process.env.SIEPMU_CUSTODIAN_PUBLIC_KEY, 'utf8')),
          exchange: remoteCustodyExchange(process.env.SIEPMU_CUSTODY_URL, clientTLS('control')),
          // Incremental custody (ADR-014): ship only records after the custodian's anchor.
          anchorQuery: remoteAnchorQuery(process.env.SIEPMU_CUSTODY_URL, clientTLS('control')),
        })
      : undefined,
  });
  const host = process.env.SIEPMU_CONTROL_HOST ?? '127.0.0.1',
    port = Number(process.env.SIEPMU_CONTROL_PORT ?? 8081);
  if (
    !['127.0.0.1', '::1', 'localhost'].includes(host) &&
    process.env.SIEPMU_ALLOW_REMOTE_HTTP !== '1' &&
    !secureProfile()
  )
    throw new Error('Remote HTTP requires explicit TLS ingress configuration');
  const origin =
    process.env.SIEPMU_PUBLIC_ORIGIN ?? 'http://127.0.0.1:' + (process.env.SIEPMU_WEB_PORT ?? 8080);
  const telemetry = process.env.SIEPMU_COLLECTOR_URL
    ? createTelemetryExporter({
        url: process.env.SIEPMU_COLLECTOR_URL,
        tls: clientTLS('control'),
        collectorKey: JSON.parse(readFileSync(process.env.SIEPMU_COLLECTOR_PUBLIC_KEY, 'utf8')),
      })
    : undefined;
  const server = createControlServer({ authority, allowedOrigin: origin, telemetry });
  server.listen(port, host, () =>
    console.log(JSON.stringify({ service: 'control', event: 'listening', host, port })),
  );
  for (const sig of ['SIGTERM', 'SIGINT'])
    process.on(sig, () =>
      server.close(() => {
        authority.close();
        process.exit(0);
      }),
    );
  return { server, authority };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  startControl();
