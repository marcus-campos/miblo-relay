// Everything the phone app keeps in this browser goes on sign-out (its Web Push subscription too), and when another account signs
// in here (security audit 1.21.0, finding 3): the "miblo-phone" IndexedDB (pairings, their
// non-extractable keys, the account identities and the computers they confirmed) and the app's own
// localStorage entries. Never throws.

const PREFIXES = ["miblo-phone-last-at:", "miblo-vault-hw:", "miblo-pet:"];
const KEYS = ["miblo-pets", "miblo-phone-uid"];

export async function wipePhoneData(): Promise<void> {
  // Alerts stop too: the browser's push subscription for the app goes (the relay drops an endpoint
  // that no longer answers).
  try {
    if (typeof navigator !== "undefined" && "serviceWorker" in navigator) {
      for (const reg of await navigator.serviceWorker.getRegistrations()) {
        if (!/\/(en\/)?app\/?$/.test(new URL(reg.scope).pathname)) continue;
        const sub = await reg.pushManager?.getSubscription();
        await sub?.unsubscribe().catch(() => false);
      }
    }
  } catch {
    // No service worker: nothing subscribed.
  }
  try {
    const drop: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (KEYS.includes(k) || PREFIXES.some((p) => k.startsWith(p)))) drop.push(k);
    }
    for (const k of drop) localStorage.removeItem(k);
  } catch {
    // No storage.
  }
  if (typeof indexedDB === "undefined") return;
  await new Promise<void>((resolve) => {
    try {
      const req = indexedDB.deleteDatabase("miblo-phone");
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
      // An open tab still holds it: deleted as soon as that tab lets go.
      req.onblocked = () => resolve();
    } catch {
      resolve();
    }
  });
}
