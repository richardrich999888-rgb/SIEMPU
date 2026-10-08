/* Public app-shell assets only. Never cache API responses, credentials or user data.
 * Bump CACHE whenever any shell asset changes; deploy the release directory atomically.
 * Each installed cache is an immutable generation. Never refresh one module in isolation.
 */
const CACHE = 'siepmu-public-shell-v5';
const ASSETS = [
  '/',
  '/unit',
  '/admin',
  '/admin/',
  '/apps/unit-client/index.html',
  '/apps/admin-console/index.html',
  '/apps/unit-client/app.mjs',
  '/apps/unit-client/dom.mjs',
  '/apps/unit-client/styles.css',
  '/apps/unit-client/vault-store.mjs',
  '/apps/unit-client/challenge.mjs',
  '/apps/unit-client/trust.mjs',
  '/apps/unit-client/authority-pin.mjs',
  '/apps/admin-console/admin.mjs',
  '/apps/admin-console/admin.css',
  '/packages/crypto/crypto.mjs',
  '/packages/protocol/canonical.mjs',
];
self.addEventListener('install', (event) => {
  // addAll is atomic: an unavailable dependency must fail the whole installation.
  // Do not skipWaiting: an active page must finish using its own generation.
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith('siepmu-public-shell-') && name !== CACHE)
            .map((name) => caches.delete(name)),
        ),
      ),
  );
});
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (
    event.request.method !== 'GET' ||
    url.origin !== self.location.origin ||
    !ASSETS.includes(url.pathname) ||
    url.search
  )
    return;
  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(event.request);
      if (cached) return cached;
      // Evicted/incomplete generations require a full reinstall, never a mixed graph.
      return new Response('Application shell unavailable; reconnect and reload to reinstall.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
      });
    }),
  );
});
