/* NearTask service worker: offline app shell, cached fonts/photos, push notifications. */
const VERSION = 'nt-v1';
const SHELL = `${VERSION}-shell`;
const RUNTIME = `${VERSION}-runtime`;
const SHELL_FILES = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL).then((c) => c.addAll(SHELL_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => !k.startsWith(VERSION)).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Never cache API, auth or realtime traffic.
  if (url.hostname.endsWith('supabase.co') && !url.pathname.startsWith('/storage/v1/object/public/')) return;

  // Page loads: network first so updates arrive, cached shell when offline.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(SHELL).then((c) => c.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Fonts, library CDN, public listing photos and our own files: cache, refresh in background.
  const cacheable =
    url.origin === self.location.origin ||
    /fonts\.(googleapis|gstatic)\.com$/.test(url.hostname) ||
    url.hostname === 'cdn.jsdelivr.net' ||
    url.pathname.startsWith('/storage/v1/object/public/');
  if (!cacheable) return;

  event.respondWith(
    caches.open(RUNTIME).then(async (cache) => {
      const hit = await cache.match(req);
      const net = fetch(req)
        .then((res) => {
          if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone());
          return res;
        })
        .catch(() => hit);
      return hit || net;
    })
  );
});

// Push payload (JSON): { id, title, body, link }  — link is an app route such as "#/chat/123".
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) { data = { body: event.data && event.data.text() }; }
  const title = data.title || 'NearTask';
  event.waitUntil(
    self.registration.showNotification(title, {
      body: data.body || '',
      icon: 'icon-192.png',
      badge: 'icon-192.png',
      tag: data.id ? String(data.id) : undefined,
      data: { link: data.link || '#/notices' }
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const link = (event.notification.data && event.notification.data.link) || '#/';
  const target = new URL('./' + (link.startsWith('#') ? link : '#' + link), self.registration.scope).href;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      for (const w of wins) {
        if (w.url.startsWith(self.registration.scope)) {
          return w.focus().then(() => w.navigate(target));
        }
      }
      return self.clients.openWindow(target);
    })
  );
});
