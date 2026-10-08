/* Public app-shell assets only. Never cache API responses, credentials or user data. */
const CACHE = 'siepmu-public-shell-v4';
const ASSETS = [
  '/',
  '/apps/unit-client/index.html',
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
  '/packages/crypto/providers/webcrypto.mjs',
  '/packages/protocol/canonical.mjs',
  '/packages/mission/policy.mjs',
  '/packages/object-format/schema.mjs',
];
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting()),
  );
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
      )
      .then(() => self.clients.claim()),
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
    fetch(event.request)
      .then(async (response) => {
        if (response.ok) {
          const cache = await caches.open(CACHE);
          await cache.put(event.request, response.clone());
        }
        return response;
      })
      .catch(async () => {
        const cached = await caches.match(event.request);
        if (cached) return cached;
        throw new Error('Public application shell is not available offline');
      }),
  );
});
