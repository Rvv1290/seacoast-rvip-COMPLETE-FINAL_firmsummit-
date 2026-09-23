// Seacoast RVIP Service Worker
var CACHE = 'rvip-v2';
var OFFLINE_URL = '/offline.html';

var PRECACHE = [
  '/',
  '/index.html',
  '/about.html',
  '/services.html',
  '/contact.html',
  '/schedule.html',
  '/payment.html',
  '/offline.html',
  '/seacoast_rvip_favicon_180.png',
  '/seacoast_rvip_favicon_32.png'
];

// Install — cache all core pages
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(cache) {
      return cache.addAll(PRECACHE);
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// Activate — clear old caches
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE; })
            .map(function(k) { return caches.delete(k); })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch strategy:
//  - HTML pages (navigations): NETWORK-FIRST so new deploys always show; fall
//    back to cache, then the offline page. This prevents stale app pages like
//    admin.html being served forever from cache.
//  - Static assets (images, css, js, fonts): cache-first for speed.
self.addEventListener('fetch', function(e) {
  // Skip non-GET and external requests (e.g. Firestore / Google APIs)
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith(self.location.origin)) return;

  var req = e.request;
  var accept = req.headers.get('accept') || '';
  var isHTML = req.mode === 'navigate' || accept.indexOf('text/html') !== -1;

  if (isHTML) {
    e.respondWith(
      fetch(req).then(function(response) {
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE).then(function(cache) { cache.put(req, clone); });
        }
        return response;
      }).catch(function() {
        return caches.match(req).then(function(cached) {
          return cached || caches.match(OFFLINE_URL);
        });
      })
    );
    return;
  }

  // Static assets — cache-first, then network (and cache the result)
  e.respondWith(
    caches.match(req).then(function(cached) {
      if (cached) return cached;
      return fetch(req).then(function(response) {
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE).then(function(cache) { cache.put(req, clone); });
        }
        return response;
      }).catch(function() { /* asset unavailable offline */ });
    })
  );
});

// Push notifications
self.addEventListener('push', function(e) {
  var data = e.data ? e.data.json() : {};
  var title = data.title || 'Seacoast RVIP';
  var options = {
    body: data.body || 'You have a new notification',
    icon: '/seacoast_rvip_favicon_180.png',
    badge: '/seacoast_rvip_favicon_32.png',
    vibrate: [200, 100, 200],
    data: { url: data.url || '/' },
    actions: [
      { action: 'view', title: 'View' },
      { action: 'dismiss', title: 'Dismiss' }
    ]
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

// Notification click
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  if (e.action === 'dismiss') return;
  var url = e.notification.data.url || '/';
  e.waitUntil(clients.openWindow(url));
});
