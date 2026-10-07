import { createServer, request as requestHttp } from 'node:http';
import { request as requestHttps } from 'node:https';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};
const securityHeaders = {
  'content-security-policy':
    "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob: data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cache-control': 'no-store',
};

export function createWebServer({
  root = resolve('.'),
  controlUrl = process.env.SIEPMU_CONTROL_URL || 'http://127.0.0.1:8081',
  publicOrigin = process.env.SIEPMU_PUBLIC_ORIGIN,
  maxBytes = 6 * 1024 * 1024,
  maxResponseBytes = 8 * 1024 * 1024,
  upstreamTimeoutMs = 20_000,
} = {}) {
  const upstream = new URL(controlUrl);
  if (
    !['http:', 'https:'].includes(upstream.protocol) ||
    upstream.username ||
    upstream.password ||
    upstream.pathname !== '/' ||
    upstream.search ||
    upstream.hash
  )
    throw new Error('Invalid control URL');
  if (
    upstream.protocol !== 'https:' &&
    !['127.0.0.1', 'localhost', '[::1]'].includes(upstream.hostname) &&
    process.env.SIEPMU_ALLOW_REMOTE_HTTP !== '1'
  )
    throw new Error('Remote authority connection requires TLS or internal override');
  // Destination identity is selected only at startup. A request target never enters URL resolution.
  const destination = Object.freeze({
    protocol: upstream.protocol,
    hostname: upstream.hostname.replace(/^\[|\]$/g, ''),
    port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
  });
  const requestTransport = upstream.protocol === 'https:' ? requestHttps : requestHttp;
  const forward = (method, requestPath, headers, body, signal) =>
    new Promise((fulfill, reject) => {
      let settled = false;
      let timer;
      const finish = (error, response) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else fulfill(response);
      };
      const outgoing = requestTransport(
        { ...destination, method, path: requestPath, headers, signal },
        (incoming) => {
          incoming.once('error', (error) => finish(error));
          incoming.once('aborted', () => finish(new Error('Authority response aborted')));
          const status = incoming.statusCode || 502;
          if (status >= 300 && status < 400) {
            incoming.destroy(new Error('Authority redirects are forbidden'));
            return;
          }
          if (Number(incoming.headers['content-length'] || 0) > maxResponseBytes) {
            incoming.destroy(new Error('Authority response exceeds limit'));
            return;
          }
          const chunks = [];
          let bytes = 0;
          incoming.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > maxResponseBytes)
              incoming.destroy(new Error('Authority response exceeds limit'));
            else chunks.push(chunk);
          });
          incoming.once('end', () =>
            finish(null, { status, headers: incoming.headers, body: Buffer.concat(chunks) }),
          );
        },
      );
      outgoing.once('error', (error) => finish(error));
      timer = setTimeout(
        () => outgoing.destroy(new Error('Authority request timed out')),
        upstreamTimeoutMs,
      );
      outgoing.end(body);
    });
  const configuredOrigin = publicOrigin ? new URL(publicOrigin).origin : undefined;
  const expectedHost = publicOrigin ? new URL(publicOrigin).host : undefined;
  const server = createServer(async (req, res) => {
    const send = (status, value) => {
      res.writeHead(status, { ...securityHeaders, 'content-type': 'application/json' });
      res.end(JSON.stringify(value));
    };
    try {
      if (
        !req.url?.startsWith('/') ||
        req.url.startsWith('//') ||
        req.url.includes('\\') ||
        req.url.includes('%')
      ) {
        send(400, { error: 'INVALID_PATH' });
        return;
      }
      const path = req.url.split('?')[0];
      if (['/health', '/health/live'].includes(path) && req.method === 'GET') {
        send(200, { status: 'ok', service: 'web-gateway' });
        return;
      }
      if (path === '/health/ready' && req.method === 'GET') {
        const health = await fetch(new URL('/health', upstream), {
          signal: AbortSignal.timeout(2000),
          redirect: 'error',
        });
        send(health.ok ? 200 : 503, {
          status: health.ok ? 'ok' : 'unavailable',
          service: 'web-gateway',
        });
        return;
      }
      if (path.startsWith('/api/')) {
        // The API currently has no query parameters or encoded path segments. Preserve one unambiguous path.
        if (
          req.url.length > 2048 ||
          !/^\/api\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(req.url)
        ) {
          send(400, { error: 'INVALID_API_PATH' });
          return;
        }
        if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
          send(405, { error: 'METHOD_NOT_ALLOWED' });
          return;
        }
        const host = req.headers.host;
        if (
          typeof host !== 'string' ||
          !/^(?:[a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::\d+)?$/.test(host)
        ) {
          send(400, { error: 'INVALID_HOST' });
          return;
        }
        const parsedHost = new URL(`http://${host}`);
        if (
          (expectedHost && host !== expectedHost) ||
          (!expectedHost && !['localhost', '127.0.0.1', '[::1]'].includes(parsedHost.hostname))
        ) {
          send(403, { error: 'HOST_MISMATCH' });
          return;
        }
        const origin = configuredOrigin || `http://${host}`;
        if (req.headers.origin && req.headers.origin !== origin) {
          send(403, { error: 'ORIGIN_MISMATCH' });
          return;
        }
        if (req.headers['sec-fetch-site'] === 'cross-site') {
          send(403, { error: 'CROSS_SITE' });
          return;
        }
        const mutation = !['GET', 'HEAD'].includes(req.method);
        if (mutation && req.headers['content-type']?.split(';')[0] !== 'application/json') {
          send(415, { error: 'CONTENT_TYPE' });
          return;
        }
        if (Number(req.headers['content-length'] || 0) > maxBytes) {
          send(413, { error: 'BODY_LIMIT' });
          req.resume();
          return;
        }
        let size = 0;
        const chunks = [];
        for await (const chunk of req) {
          size += chunk.length;
          if (size > maxBytes) {
            send(413, { error: 'BODY_LIMIT' });
            return;
          }
          chunks.push(chunk);
        }
        if (!mutation && size) {
          send(400, { error: 'UNEXPECTED_BODY' });
          return;
        }
        const headers = { accept: 'application/json', 'x-siepmu-request-origin': origin };
        if (req.headers.authorization) headers.authorization = req.headers.authorization;
        if (mutation) headers['content-type'] = 'application/json';
        // The gateway has validated the browser Origin. Do not forward caller-controlled proxy headers.
        const abort = new AbortController();
        const clientClosed = () => {
          if (!res.writableEnded) abort.abort();
        };
        res.once('close', clientClosed);
        let response;
        try {
          response = await forward(
            req.method,
            req.url,
            headers,
            mutation ? Buffer.concat(chunks) : undefined,
            abort.signal,
          );
        } finally {
          res.removeListener('close', clientClosed);
        }
        res.writeHead(response.status, {
          ...securityHeaders,
          'content-type': 'application/json',
          ...(typeof response.headers['retry-after'] === 'string'
            ? { 'retry-after': response.headers['retry-after'] }
            : {}),
        });
        res.end(response.body);
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        send(405, { error: 'METHOD_NOT_ALLOWED' });
        return;
      }
      const aliases = {
        '/sw.js': '/apps/unit-client/sw.js',
        '/': '/apps/unit-client/index.html',
        '/unit': '/apps/unit-client/index.html',
        '/admin': '/apps/admin-console/index.html',
        '/admin/': '/apps/admin-console/index.html',
      };
      const asset = aliases[path] || path;
      if (
        !/^\/(apps\/(unit-client|admin-console)|packages)\/[a-zA-Z0-9_./-]+$/.test(asset) ||
        asset.split('/').some((p) => p === '..' || p === '.' || p.startsWith('.'))
      ) {
        send(404, { error: 'NOT_FOUND' });
        return;
      }
      const extension = extname(asset);
      if (!mime[extension] || (extension === '.html' && !Object.values(aliases).includes(asset))) {
        send(404, { error: 'NOT_FOUND' });
        return;
      }
      const absolute = resolve(root, `.${asset}`);
      if (!absolute.startsWith(resolve(root) + sep)) {
        send(404, { error: 'NOT_FOUND' });
        return;
      }
      const data = await readFile(absolute);
      res.writeHead(200, {
        ...securityHeaders,
        'content-type': mime[extension],
        ...(path === '/sw.js' ? { 'service-worker-allowed': '/' } : {}),
      });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch (error) {
      if (!res.headersSent)
        send(error.code === 'ENOENT' ? 404 : 503, {
          error: error.code === 'ENOENT' ? 'NOT_FOUND' : 'GATEWAY_UNAVAILABLE',
        });
      else res.destroy();
    }
  });
  server.requestTimeout = 25_000;
  server.headersTimeout = 10_000;
  server.maxRequestsPerSocket = 100;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const host = process.env.SIEPMU_WEB_HOST || '127.0.0.1';
  if (
    !['127.0.0.1', '::1', 'localhost'].includes(host) &&
    process.env.SIEPMU_ALLOW_REMOTE_HTTP !== '1'
  )
    throw new Error('Remote HTTP requires explicit internal-network override');
  const server = createWebServer();
  server.listen(Number(process.env.SIEPMU_WEB_PORT || 8080), host, () =>
    console.log(`SIEPMU web gateway at http://${host}:${server.address().port}`),
  );
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, () => {
      server.close();
      server.closeIdleConnections();
    });
}
