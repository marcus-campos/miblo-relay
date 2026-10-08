// The app lock's record in the app's IndexedDB (next to the pairings, store.ts), and ending the
// account session when the PIN lock blocks this phone.
import { normalize, memoryStore, type LockRecord, type LockStore } from "./pin-lock";
import { readLockRecord, updateLockRecord } from "./store";

/** The IndexedDB store; memory only when the browser has none (the PIN is then asked again on every load). */
export function browserLockStore(): LockStore {
  if (typeof indexedDB === "undefined") return memoryStore();
  return {
    read: async () => {
      const raw = await readLockRecord();
      return raw ? normalize(raw) : null;
    },
    update: (fn) => updateLockRecord<LockRecord>((raw) => fn(normalize(raw))),
  };
}

/**
 * Ten wrong PINs: this browser's account session ends on the server (the existing sign-out route),
 * which also sends the account's "pin_lockout" security notice (at most once an hour). -> true once
 * the server answered (the session is gone, or there was none).
 */
export async function endSessionForPin(fetchFn: typeof fetch = fetch): Promise<boolean> {
  try {
    const r = await fetchFn("/api/community/auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "pin_lockout" }),
      credentials: "same-origin",
    });
    return r.ok;
  } catch {
    return false;
  }
}
