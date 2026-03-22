// Seacoast RVIP Service Worker
var CACHE = 'rvip-v1';
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

// Fetch — serve from cache, fallback to network, fallback to offline
self.addEventListener('fetch', function(e) {
  // Skip non-GET and external requests
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith(self.location.origin)) return;

  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;

      return fetch(e.request).then(function(response) {
        // Cache successful responses
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE).then(function(cache) {
            cache.put(e.request, clone);
          });
        }
        return response;
      }).catch(function() {
        // Offline fallback for navigation
        if (e.request.mode === 'navigate') {
          return caches.match(OFFLINE_URL);
        }
      });
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
