// Seacoast RVIP — service worker kill switch.
//
// No page registers a service worker any more. But browsers that visited the
// older site still carry a live registration, and an earlier version of this
// file served HTML cache-first, so those browsers kept showing pages from
// their own cache long after the site changed — including the paused
// "Online access is temporarily unavailable" page after /admin was reopened.
//
// A registration keeps checking this URL for updates on navigations within its
// scope, so replacing the file with this is the only way to reach them. It
// takes over immediately, deletes every cache it owns, unregisters itself and
// reloads any open page once. After that the browser has no service worker and
// goes straight to the network, like a first-time visitor.
//
// Do not re-add caching here without also adding a registration; a worker that
// nothing registers cannot be updated except through this same mechanism.

self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  e.waitUntil((async function () {
    try {
      var keys = await caches.keys();
      await Promise.all(keys.map(function (k) { return caches.delete(k); }));
    } catch (err) { /* nothing to clear */ }

    try { await self.registration.unregister(); } catch (err) { /* already gone */ }

    try {
      var windows = await self.clients.matchAll({ type: 'window' });
      windows.forEach(function (c) {
        // Re-request from the network now that no worker is intercepting.
        if (c.url) c.navigate(c.url);
      });
    } catch (err) { /* nothing open */ }
  })());
});

// Deliberately no fetch handler: every request goes straight to the network.
