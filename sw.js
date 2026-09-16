// Bump this on every deploy so old caches are discarded.
const CACHE = 'lakhan-register-v15';

const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png',
  './icon-512-maskable.png',
  './icon-64.png',
  './apple-touch-icon.png',
  './logo-header.png',
];

self.addEventListener('install', (event) => {
  // NOTE: no skipWaiting() here on purpose. The page decides when to
  // activate a new version (it posts 'SKIP_WAITING' below), so an update
  // can't swap itself in and force-reload the page while someone is
  // part-way through typing an entry.
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).catch(() => {})
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Only Cache Storage is touched anywhere in this file. Worker/site data
// lives in IndexedDB, which is never read, written or deleted here — so a
// service-worker update can discard stale assets without any risk to
// saved sites, workers, attendance, advances, expenses or contractors.

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // NEVER cache the auth/session endpoints. A cached {authenticated:true}
  // could otherwise be replayed to skip the login screen on a shared
  // device even after logout. Always go straight to the network.
  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) {
    return; // let the browser handle it normally, uncached
  }

  // Network-first for page navigations so a deployed update is picked up
  // immediately instead of a stale shell being served from cache. Falls
  // back to the cached shell when offline.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((resp) => {
          const clone = resp.clone();
          caches.open(CACHE).then((cache) => cache.put('./index.html', clone)).catch(() => {});
          return resp;
        })
        .catch(() => caches.match('./index.html').then((c) => c || caches.match('./')))
    );
    return;
  }

  // Everything else (icons, fonts, the lazily-loaded xlsx library):
  // serve from cache if present, refresh in the background.
  event.respondWith(
    caches.match(req).then((cached) => {
      const fetchPromise = fetch(req)
        .then((networkResp) => {
          if (networkResp && networkResp.status === 200) {
            const clone = networkResp.clone();
            caches.open(CACHE).then((cache) => cache.put(req, clone)).catch(() => {});
          }
          return networkResp;
        })
        .catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
