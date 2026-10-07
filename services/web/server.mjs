import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

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
  const configuredOrigin = publicOrigin ? new URL(publicOrigin).origin : undefined;
  const expectedHost = publicOrigin ? new URL(publicOrigin).host : undefined;
  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    res.setHeader('X-Request-Id', requestId);
    const send = (status, value) => {
      res.writeHead(status, { ...securityHeaders, 'content-type': 'application/json' });
      const code = value.code ?? value.error ?? 'REQUEST_FAILED';
      res.end(JSON.stringify(status >= 400 ? { ...value, error: code, code, requestId } : value));
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
        // Only the path is client-controlled. Never resolve an arbitrary request
        // target against the authority base, which could replace its host.
        if (req.url.includes('?')) {
          send(400, { error: 'INVALID_PATH' });
          return;
        }
        const destination = new URL(upstream.href);
        destination.pathname = path;
        const response = await fetch(destination, {
          method: req.method,
          headers,
          ...(mutation ? { body: Buffer.concat(chunks) } : {}),
          signal: AbortSignal.timeout(20_000),
          redirect: 'error',
        });
        const payload = await response.arrayBuffer();
        res.writeHead(response.status, {
          ...securityHeaders,
          'content-type': 'application/json',
          'x-request-id': response.headers.get('x-request-id') || requestId,
          ...(response.headers.get('retry-after')
            ? { 'retry-after': response.headers.get('retry-after') }
            : {}),
        });
        res.end(Buffer.from(payload));
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
