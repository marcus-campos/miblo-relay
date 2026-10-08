// The phone app's PIN lock (docs/phone-relay-protocol.md, "App lock (PIN)"): the rules a PIN must
// follow, its slow salted hash, and the wrong-PIN counter. Everything here stays on the phone: the
// PIN is never sent anywhere, and only a PBKDF2 hash of it is kept (with the counter) in the app's
// IndexedDB. It is a gate on the app and the session, NOT encryption of the stored keys: someone
// who can read the browser's storage can try every 6-digit PIN offline; the PIN stops a person
// holding an unlocked phone from using the app.

/** Shortest and longest PIN accepted. */
export const PIN_MIN = 6;
export const PIN_MAX = 12;
/** Wrong PINs in a row before a one-minute wait, and before the app is blocked on this device. */
export const PIN_WAIT_AFTER = 5;
export const PIN_BLOCK_AFTER = 10;
export const PIN_WAIT_MS = 60_000;
/** The least PBKDF2-SHA-256 work per hash; raised on fast devices to about TARGET_MS. */
export const PBKDF2_MIN_ITER = 600_000;
const PBKDF2_MAX_ITER = 5_000_000;
const TARGET_MS = 300;

/** How long the app may sit idle before it locks: minutes, or "leave" (as soon as the app is left). */
export type IdleChoice = 1 | 5 | 15 | 60 | "leave";
export const IDLE_CHOICES: IdleChoice[] = [1, 5, 15, 60, "leave"];
export const IDLE_DEFAULT: IdleChoice = 5;

export type PinHash = { salt: string; iter: number; digest: string };

/**
 * The one lock record of this device. `failures`: wrong PINs in a row (counted before each check
 * finishes, so closing the tab mid-check still counts it). `blockUntil`: no attempt before this
 * time. `blocked`: 10 wrong in a row; the PIN hash is gone and only a new account sign-in opens the
 * app again (`logoutDone`: the account session was ended on the server).
 */
export type LockRecord = {
  v: 1;
  hash: PinHash | null;
  failures: number;
  blockUntil: number;
  blocked: boolean;
  logoutDone: boolean;
  idle: IdleChoice;
};

export const emptyRecord = (): LockRecord => ({ v: 1, hash: null, failures: 0, blockUntil: 0, blocked: false, logoutDone: false, idle: IDLE_DEFAULT });

/** Where the record lives (IndexedDB in the app, memory in tests). `update` is atomic. */
export interface LockStore {
  read(): Promise<LockRecord | null>;
  update(fn: (r: LockRecord) => LockRecord): Promise<LockRecord>;
}

/** A record read back from storage: anything malformed counts as the safest reading of it. */
export function normalize(raw: unknown): LockRecord {
  const r = emptyRecord();
  if (!raw || typeof raw !== "object") return r;
  const o = raw as Record<string, unknown>;
  const h = o.hash as Record<string, unknown> | null | undefined;
  if (h && typeof h.salt === "string" && typeof h.digest === "string" && typeof h.iter === "number" && h.iter >= PBKDF2_MIN_ITER) {
    r.hash = { salt: h.salt, digest: h.digest, iter: h.iter };
  }
  r.failures = typeof o.failures === "number" && o.failures >= 0 ? Math.floor(o.failures) : 0;
  r.blockUntil = typeof o.blockUntil === "number" && o.blockUntil > 0 ? o.blockUntil : 0;
  r.blocked = o.blocked === true || r.failures >= PIN_BLOCK_AFTER;
  r.logoutDone = o.logoutDone === true;
  r.idle = IDLE_CHOICES.includes(o.idle as IdleChoice) ? (o.idle as IdleChoice) : IDLE_DEFAULT;
  // A blocked device keeps nothing the PIN could open.
  if (r.blocked) r.hash = null;
  return r;
}

// --- what the app shows -------------------------------------------------------------------------

/** Where the account stands in the app: signed in with the second factor passed ("in"), not ("out"), or not known yet. */
export type LockAccount = "unknown" | "out" | "in";
export type LockKind = "loading" | "setup" | "locked" | "blocked" | "open";

/**
 * What the app shows. With a PIN: locked until it is typed. Without one: the PIN is created as soon
 * as the account is known to be signed in (or this phone has pairings), and until the account check
 * answers nothing shows; only a phone signed out with nothing stored opens without a PIN.
 */
export function lockKind(rec: LockRecord | null, unlocked: boolean, account: LockAccount, hasData: boolean): LockKind {
  if (!rec) return "loading";
  if (rec.blocked) return "blocked";
  if (rec.hash) return unlocked ? "open" : "locked";
  if (account === "in" || hasData) return "setup";
  return account === "unknown" ? "loading" : "open";
}

// --- the rules ------------------------------------------------------------------------------------

export type PinProblem = "digits" | "short" | "long" | "trivial";

/** Why `pin` cannot be used, or null. Trivial: one digit, a short pattern repeated, or a run. */
export function pinProblem(pin: string): PinProblem | null {
  if (!/^\d*$/.test(pin)) return "digits";
  if (pin.length < PIN_MIN) return "short";
  if (pin.length > PIN_MAX) return "long";
  return trivialPin(pin) ? "trivial" : null;
}

export function trivialPin(pin: string): boolean {
  const n = pin.length;
  // The same short pattern over and over: 000000, 121212, 123123, 12341234.
  for (let p = 1; p <= n / 2; p++) {
    if (n % p === 0 && pin.slice(0, p).repeat(n / p) === pin) return true;
  }
  // A run up or down, also through 9 -> 0: 123456, 654321, 890123.
  const d = [...pin].map(Number);
  for (const step of [1, 9]) {
    if (d.every((x, i) => i === 0 || x === (d[i - 1] + step) % 10)) return true;
  }
  // A few more that people pick first.
  return COMMON.has(pin);
}
const COMMON = new Set(["112233", "123321", "147258", "159753", "102030", "111222", "121314", "131313", "520520"]);

// --- the hash -------------------------------------------------------------------------------------

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function pbkdf2(pin: string, salt: Uint8Array, iter: number): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt as Uint8Array<ArrayBuffer>, iterations: iter }, base, 256);
  return new Uint8Array(bits);
}

/** Iterations for this device: at least 600k, more when it hashes faster than ~300 ms. */
export async function calibrate(now: () => number = () => performance.now()): Promise<number> {
  const probe = 100_000;
  const t0 = now();
  await pbkdf2("000000", new Uint8Array(16), probe);
  const ms = Math.max(1, now() - t0);
  const fit = Math.floor((probe * TARGET_MS) / ms / 10_000) * 10_000;
  return Math.min(PBKDF2_MAX_ITER, Math.max(PBKDF2_MIN_ITER, fit));
}

export async function hashPin(pin: string, iter: number, salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16))): Promise<PinHash> {
  return { salt: b64(salt), iter, digest: b64(await pbkdf2(pin, salt, iter)) };
}

/** Equal bytes, in time that does not depend on where they differ. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export async function pinMatches(pin: string, h: PinHash): Promise<boolean> {
  return sameBytes(await pbkdf2(pin, unb64(h.salt), h.iter), unb64(h.digest));
}

// --- setting and checking -----------------------------------------------------------------------

/** Sets a new PIN (first one, after a block, or a change already authorised): the counter restarts. */
export async function setPin(store: LockStore, pin: string, iter: number): Promise<PinProblem | null> {
  const problem = pinProblem(pin);
  if (problem) return problem;
  const hash = await hashPin(pin, iter);
  await store.update((r) => ({ ...r, hash, failures: 0, blockUntil: 0, blocked: false, logoutDone: false }));
  return null;
}

export type TryResult =
  | { ok: true }
  | { ok: false; why: "wrong"; left: number; until: number }
  | { ok: false; why: "wait"; until: number }
  | { ok: false; why: "blocked" }
  | { ok: false; why: "none" };

/**
 * One PIN attempt. The attempt is counted in storage before the (slow) check: a reload or a closed
 * tab cannot undo it. 5 wrong in a row: no attempt for a minute; 10 wrong in a row (the minute does
 * not reset them): blocked, and the hash is deleted. A right PIN sets the count back to zero.
 */
export async function tryPin(store: LockStore, pin: string, now: number): Promise<TryResult> {
  let refused = null as TryResult | null;
  let hash = null as PinHash | null;
  let count = 0;
  await store.update((r) => {
    if (r.blocked) return (refused = { ok: false, why: "blocked" }), r;
    if (!r.hash) return (refused = { ok: false, why: "none" }), r;
    if (now < r.blockUntil) return (refused = { ok: false, why: "wait", until: r.blockUntil }), r;
    hash = r.hash;
    count = r.failures + 1;
    return { ...r, failures: count, blockUntil: count === PIN_WAIT_AFTER ? now + PIN_WAIT_MS : r.blockUntil };
  });
  if (refused) return refused;
  const good = !!hash && (await pinMatches(pin, hash));
  if (good) {
    await store.update((r) => ({ ...r, failures: 0, blockUntil: 0 }));
    return { ok: true };
  }
  if (count >= PIN_BLOCK_AFTER) {
    await store.update((r) => ({ ...r, blocked: true, hash: null, logoutDone: false, blockUntil: 0 }));
    return { ok: false, why: "blocked" };
  }
  const until = count === PIN_WAIT_AFTER ? now + PIN_WAIT_MS : 0;
  return { ok: false, why: "wrong", left: PIN_BLOCK_AFTER - count, until };
}

/** A store in memory (tests; and the fallback when the browser has no IndexedDB). */
export function memoryStore(initial: LockRecord | null = null): LockStore & { raw: () => LockRecord | null } {
  let rec: LockRecord | null = initial ? structuredClone(initial) : null;
  return {
    raw: () => (rec ? structuredClone(rec) : null),
    read: async () => (rec ? normalize(structuredClone(rec)) : null),
    update: async (fn) => {
      rec = fn(normalize(rec ? structuredClone(rec) : null));
      return structuredClone(rec);
    },
  };
}
