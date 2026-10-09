// Service worker of the Miblo phone app, registered with scope /app/ (and /en/app/). The same as
// miblo.ai's, with this build's asset paths (/assets/, /theme.js).
// Offline shell (the app page and its static files), push notifications with fixed words only,
// and opening the app from one. Never touches pages outside its scope.
const VERSION = "miblo-phone-v3";
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
          const assets = [...new Set(html.match(/\/assets\/[^"'\s)]+/g) || [])];
          await Promise.all(assets.map((url) => cache.add(url).catch(() => {})));
        }
        await cache.addAll([`${scopePath}manifest.webmanifest`, "/app/icon-192.png", "/app/badge-96.png", "/theme.js"]).catch(() => {});
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

  if (url.pathname.startsWith("/assets/") || url.pathname === "/theme.js" || /^\/(en\/)?app\/[\w.-]+\.(png|webmanifest)$/.test(url.pathname)) {
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

// What a notification may be about (the relay's fixed kinds) and the fixed words for each: the
// payload carries nothing from the computer, and anything else in it is ignored. Same list as
// push.ts (PUSH_OPEN, pushTarget).
const WORDS = {
  needs_you: ["A sessão precisa de você", "A session needs you"],
  approval: ["Pedido de permissão", "Permission request"],
  task_done: ["Tarefa concluída", "Task finished"],
  task_failed: ["A tarefa falhou", "Task failed"],
};
const KINDS = Object.keys(WORDS);

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  const en = scopePath.startsWith("/en");
  const kind = KINDS.includes(data && data.t) ? data.t : "needs_you";
  // The words come from this file, in the app's language (the relay's are the same).
  const body = WORDS[kind][en ? 1 : 0];
  // A permission request and "needs you" are the same moment of a session: one notification,
  // replaced; a task's end is its own. It buzzes again only when none of its kind is showing.
  const tag = kind === "task_done" || kind === "task_failed" ? "miblo-task" : "miblo-needs-you";
  event.waitUntil(
    (async () => {
      const showing = await self.registration.getNotifications({ tag }).catch(() => []);
      await self.registration.showNotification("Miblo", {
        body,
        tag,
        renotify: showing.length === 0,
        icon: "/app/icon-192.png",
        badge: "/app/badge-96.png",
        data: { url: `${scopePath}?open=${kind}`, kind },
      });
    })(),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const kind = KINDS.includes(data.kind) ? data.kind : null;
  // Only the app's own page, whatever the notification says.
  const target = new URL(kind ? `${scopePath}?open=${kind}` : scopePath, location.origin).href;
  event.waitUntil(
    (async () => {
      const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of all) {
        if (new URL(client.url).pathname.startsWith(scopePath) && "focus" in client) {
          // Open already: shown, and told to show the "Agora" tab.
          client.postMessage({ t: "miblo-open", kind });
          return client.focus();
        }
      }
      return self.clients.openWindow(target);
    })(),
  );
});
