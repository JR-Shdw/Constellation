// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
// Minimal service worker — enables PWA install banner
// Network-first for CSS/JS so deploys take effect on next load;
// cache-first for icons/manifest which rarely change.

const CACHE = 'constellation-v8';
const SHELL = [
  '/',
  '/css/style.css',
  '/js/app.js',
  '/js/api.js',
  '/site.webmanifest',
  '/favicon.ico',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
  '/apple-touch-icon.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API calls: network only (never cache)
  if (url.pathname.startsWith('/api/')) return;

  // HTML / CSS / JS: network-first so fresh deploys reach users on next load.
  // Falls back to cache if offline. Static assets (icons, manifest) stay
  // cache-first.
  const isDynamic = url.pathname === '/'
    || url.pathname.endsWith('.html')
    || url.pathname.endsWith('.css')
    || url.pathname.endsWith('.js');

  if (isDynamic) {
    e.respondWith(
      fetch(e.request)
        .then((r) => {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
          return r;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Icons / manifest / fonts: cache-first
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request))
  );
});
