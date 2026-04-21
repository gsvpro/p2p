const CACHE_NAME = 'ciphernexus-v3.0.3'; // Increment for cache busting
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
      );
    })
  );
});

self.addEventListener('fetch', (event) => {
  // Only handle GET requests for caching
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  
  // Network first for index and manifest to handle GitHub Pages caching
  if (url.pathname.endsWith('/') || url.pathname.endsWith('index.html') || url.pathname.endsWith('manifest.webmanifest')) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const cloned = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, cloned));
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Bypass cache for discovery/signaling nodes
  if (url.hostname.includes('iroh') || url.hostname.includes('pkarr') || url.hostname.includes('nostr')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});
