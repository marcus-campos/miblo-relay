// Service worker of the Miblo phone app, registered with scope /app/ (and /en/app/).
// Offline shell (the app page and its static files), generic push alerts, and opening the app
// from an alert. Never touches pages outside its scope.
const VERSION = "miblo-phone-v2";
// "/app/" or "/en/app/": the app page itself, with the slash.
const scopePath = new URL(self.registration.scope).pathname;

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(VERSION);
      try {
        const res = await fetch(scopePath, { cache: "no-store" });
        if (res.ok) {
          const html = await res.clone().text();
          await cache.put(scopePath, res);
          // The page's own scripts, styles and fonts, so the shell opens offline.
          const assets = [...new Set(html.match(/\/_next\/static\/[^"'\s)]+/g) || [])];
          await Promise.all(assets.map((url) => cache.add(url).catch(() => {})));
        }
        await cache.addAll([`${scopePath}manifest.webmanifest`, "/app/icon-192.png", "/app/badge-96.png"]).catch(() => {});
      } catch {
        // Offline at install: the cache fills on the next visit.
      }
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (key.startsWith("miblo-phone-") && key !== VERSION) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

  if (req.mode === "navigate") {
    // Network first, the cached shell when offline.
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req);
          if (res.ok && url.pathname === scopePath) (await caches.open(VERSION)).put(scopePath, res.clone());
          return res;
        } catch {
          return (await caches.match(scopePath)) || Response.error();
        }
      })(),
    );
    return;
  }

  if (url.pathname.startsWith("/_next/static/") || /^\/(en\/)?app\/[\w.-]+\.(png|webmanifest)$/.test(url.pathname)) {
    // Immutable build files and the app's icons and manifest: cache first.
    event.respondWith(
      (async () => {
        const hit = await caches.match(req);
        if (hit) return hit;
        const res = await fetch(req);
        if (res.ok) (await caches.open(VERSION)).put(req, res.clone());
        return res;
      })(),
    );
  }
});

self.addEventListener("push", (event) => {
  // The payload is generic ("a session needs you"); nothing from the computer is in it.
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  const en = scopePath.startsWith("/en");
  const title = typeof data.title === "string" ? data.title : "Miblo";
  const body = typeof data.body === "string" ? data.body : en ? "A session needs you" : "Uma sessão precisa de você";
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag: "miblo-needs-you",
      renotify: true,
      icon: "/app/icon-192.png",
      badge: "/app/badge-96.png",
      data: { url: scopePath },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL((event.notification.data && event.notification.data.url) || scopePath, location.origin).href;
  event.waitUntil(
    (async () => {
      const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of all) {
        if (new URL(client.url).pathname.startsWith(scopePath) && "focus" in client) return client.focus();
      }
      return self.clients.openWindow(target);
    })(),
  );
});
