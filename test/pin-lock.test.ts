// Mirrored from miblo.ai's web/tests/unit/pin-lock.test.ts. The phone app's PIN lock (components/phone/pin-lock.ts, idle-lock.ts, lock-state.ts): the PIN
// rules, the slow hash, the wrong-PIN counter (5 -> one-minute wait -> 10 -> blocked) and that it
// survives a reload or a tab closed mid-check, the idle lock on a fake clock, and that nothing is
// sent to a computer or the account while the app is locked.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  emptyRecord,
  hashPin,
  lockKind,
  memoryStore,
  normalize,
  PBKDF2_MIN_ITER,
  PIN_WAIT_MS,
  pinMatches,
  pinProblem,
  sameBytes,
  setPin,
  tryPin,
  type LockRecord,
  type LockStore,
} from "@/components/phone/pin-lock";
import { IdleLock } from "@/components/phone/idle-lock";
import { isAppLocked, setAppLocked } from "@/components/phone/lock-state";
import { RelayClient } from "@/components/phone/relay-client";
import { answerCode, askAgain, confirmComputer, rejectComputer, sendSasAnswers } from "@/components/phone/account-join";
import { endSessionForPin } from "@/components/phone/lock-store";
import type { AccountIdentity, StoredPairing } from "@/components/phone/store";

// The account calls go through fetch (stubbed per test); the real module needs Next's router shim.
vi.mock("@/components/community/security", () => ({
  call: async (url: string, body: unknown) => {
    const r = await fetch(url, { method: "POST", body: JSON.stringify(body) });
    return { status: r.status, data: {} };
  },
}));

const ITER = PBKDF2_MIN_ITER;
const T0 = Date.UTC(2026, 9, 8, 12, 0, 0);

async function withPin(pin = "482915"): Promise<LockStore & { raw: () => LockRecord | null }> {
  const store = memoryStore();
  expect(await setPin(store, pin, ITER)).toBeNull();
  return store;
}

describe("PIN rules", () => {
  it("needs 6 to 12 digits, digits only", () => {
    expect(pinProblem("48291")).toBe("short");
    expect(pinProblem("48a915")).toBe("digits");
    expect(pinProblem("48 915")).toBe("digits");
    expect(pinProblem("4829157361234")).toBe("long");
    expect(pinProblem("482915")).toBeNull();
    expect(pinProblem("48291573")).toBeNull();
  });
  it("refuses trivial PINs: one digit, short patterns repeated, runs up or down", () => {
    for (const p of ["000000", "111111", "999999", "121212", "123123", "909090", "12341234", "123456", "654321", "234567", "890123", "098765", "1234567890", "112233", "123321"]) {
      expect(pinProblem(p), p).toBe("trivial");
    }
    for (const p of ["482915", "120394", "135792", "100200", "246813"]) expect(pinProblem(p), p).toBeNull();
  });
});

describe("the hash", () => {
  it("is PBKDF2-SHA-256 with a random salt and at least 600k iterations", async () => {
    const a = await hashPin("482915", ITER);
    const b = await hashPin("482915", ITER);
    expect(a.iter).toBeGreaterThanOrEqual(600_000);
    expect(a.salt).not.toBe(b.salt);
    expect(a.digest).not.toBe(b.digest);
    expect(await pinMatches("482915", a)).toBe(true);
    expect(await pinMatches("482916", a)).toBe(false);
    // The PIN itself is nowhere in what is stored.
    expect(JSON.stringify(a)).not.toContain("482915");
  });
  it("compares bytes without stopping at the first difference", () => {
    expect(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(sameBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
  it("a stored hash weaker than 600k iterations is not trusted", () => {
    expect(normalize({ ...emptyRecord(), hash: { salt: "AA==", iter: 1000, digest: "AA==" } }).hash).toBeNull();
  });
});

describe("wrong PINs", () => {
  it("5 in a row: a one-minute wait; 10 in a row (across the wait): blocked, the hash deleted", async () => {
    const store = await withPin();
    let now = T0;
    for (let i = 1; i <= 4; i++) expect(await tryPin(store, "111222", now)).toEqual({ ok: false, why: "wrong", left: 10 - i, until: 0 });
    expect(await tryPin(store, "111222", now)).toEqual({ ok: false, why: "wrong", left: 5, until: now + PIN_WAIT_MS });
    // During the minute nothing is checked, not even the right PIN, and nothing is counted.
    expect(await tryPin(store, "482915", now + 30_000)).toEqual({ ok: false, why: "wait", until: now + PIN_WAIT_MS });
    expect(store.raw()!.failures).toBe(5);
    now += PIN_WAIT_MS;
    for (let i = 6; i <= 9; i++) expect(await tryPin(store, "111222", now)).toMatchObject({ ok: false, why: "wrong", left: 10 - i });
    expect(await tryPin(store, "111222", now)).toEqual({ ok: false, why: "blocked" });
    const r = store.raw()!;
    expect(r.blocked).toBe(true);
    expect(r.hash).toBeNull();
    expect(r.logoutDone).toBe(false);
    // Nothing opens it any more: not the right PIN.
    expect(await tryPin(store, "482915", now + 3_600_000)).toEqual({ ok: false, why: "blocked" });
  });

  it("the right PIN sets the count back to zero", async () => {
    const store = await withPin();
    for (let i = 0; i < 4; i++) await tryPin(store, "111222", T0);
    expect(await tryPin(store, "482915", T0)).toEqual({ ok: true });
    expect(store.raw()!.failures).toBe(0);
    for (let i = 0; i < 4; i++) await tryPin(store, "111222", T0);
    expect(store.raw()!.blockUntil).toBe(0);
  });

  it("survives a reload: the count, the wait and the block live in storage", async () => {
    const first = await withPin();
    for (let i = 0; i < 5; i++) await tryPin(first, "111222", T0);
    // A new page (or a closed and reopened tab) reads the same record.
    const second = memoryStore(first.raw());
    expect(await tryPin(second, "482915", T0 + 1_000)).toMatchObject({ why: "wait" });
    for (let i = 0; i < 4; i++) await tryPin(second, "111222", T0 + PIN_WAIT_MS);
    const third = memoryStore(second.raw());
    expect((await third.read())!.failures).toBe(9);
    expect(await tryPin(third, "000111", T0 + PIN_WAIT_MS)).toEqual({ ok: false, why: "blocked" });
    expect((await memoryStore(third.raw()).read())!.blocked).toBe(true);
  });

  it("an attempt is counted before the check: closing the tab mid-check does not undo it", async () => {
    const store = await withPin();
    let updates = 0;
    // The tab dies right after the attempt was reserved (the second write never happens).
    const dying: LockStore = {
      read: () => store.read(),
      update: (fn) => (++updates === 1 ? store.update(fn) : Promise.reject(new Error("tab closed"))),
    };
    await expect(tryPin(dying, "482915", T0)).rejects.toThrow("tab closed");
    expect(store.raw()!.failures).toBe(1);
    // Nine attempts reserved and the tenth cut short still read as blocked after a reload.
    const nine = memoryStore({ ...store.raw()!, failures: 10 });
    const r = await nine.read();
    expect(r!.blocked).toBe(true);
    expect(r!.hash).toBeNull();
  });

  it("a new PIN after a block starts clean", async () => {
    const store = memoryStore({ ...emptyRecord(), blocked: true, logoutDone: true, failures: 10 });
    await store.update((r) => ({ ...r, blocked: false, logoutDone: false, failures: 0, hash: null }));
    expect(await setPin(store, "123456", ITER)).toBe("trivial");
    expect(await setPin(store, "736251", ITER)).toBeNull();
    expect(await tryPin(store, "736251", T0)).toEqual({ ok: true });
  });
});

describe("idle lock", () => {
  it("locks after the chosen minutes without a touch or key, counting the time in the background", () => {
    let now = T0;
    const onLock = vi.fn();
    const idle = new IdleLock(5, () => now, onLock);
    now += 4 * 60_000;
    expect(idle.check()).toBe(false);
    idle.activity();
    now += 4 * 60_000;
    expect(idle.check()).toBe(false);
    now += 60_000;
    expect(idle.check()).toBe(true);
    expect(onLock).toHaveBeenCalledTimes(1);

    idle.reset();
    onLock.mockClear();
    // Hidden for 6 minutes: a tap that reaches the page while hidden does not count; back = locked.
    idle.hidden();
    now += 6 * 60_000;
    idle.activity();
    idle.visible();
    expect(onLock).toHaveBeenCalledTimes(1);

    // Back after 2 minutes away: still open.
    idle.reset();
    onLock.mockClear();
    idle.hidden();
    now += 2 * 60_000;
    idle.visible();
    expect(onLock).not.toHaveBeenCalled();
  });

  it("1 minute is the shortest, and 'leave' locks as soon as the app is hidden", () => {
    let now = T0;
    const onLock = vi.fn();
    const idle = new IdleLock(1, () => now, onLock);
    now += 59_000;
    expect(idle.check()).toBe(false);
    now += 1_000;
    expect(idle.check()).toBe(true);
    idle.setChoice("leave");
    onLock.mockClear();
    now += 24 * 3_600_000;
    expect(idle.check()).toBe(false);
    idle.hidden();
    expect(onLock).toHaveBeenCalledTimes(1);
  });
});

describe("while the app is locked nothing is sent", () => {
  afterEach(() => setAppLocked(true));

  it("starts locked", () => {
    expect(isAppLocked()).toBe(true);
  });

  it("RelayClient.sendUp refuses, and sends once unlocked", async () => {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const client = new RelayClient({ room: "r".repeat(22) } as StoredPairing, { onState: () => {}, onPayload: () => {} } as never);
    const sent: string[] = [];
    const inner = client as unknown as { ws: unknown; identity: Promise<unknown> };
    inner.ws = { readyState: WebSocket.OPEN, send: (s: string) => sent.push(s) };
    inner.identity = Promise.resolve({ phone: "p".repeat(22), token: "t", key });
    setAppLocked(true);
    expect(await client.sendUp("approval", { kind: "decision" })).toBe(false);
    expect(sent).toHaveLength(0);
    setAppLocked(false);
    expect(await client.sendUp("approval", { kind: "decision" })).toBe(true);
    expect(sent).toHaveLength(1);
  });

  it("the code typed for a computer, and confirming or turning one down, are refused", async () => {
    setAppLocked(true);
    const post = vi.fn();
    const assert = vi.fn();
    const me = { uid: "u", id: "p".repeat(22), pub: "x", credId: "c" } as unknown as AccountIdentity;
    const q = { device: { id: "d", name: "Mac" }, cpub: "c", pake: { n: 1, rs: "r", ya: "y" } } as never;
    expect((await answerCode("csrf", me, q, "123456", { post, assert })).result).toBe("error");
    expect(post).not.toHaveBeenCalled();
    expect(assert).not.toHaveBeenCalled();
    await expect(confirmComputer(me, { cpub: "c", device: "d", name: "Mac" })).rejects.toThrow("app_locked");
    await expect(rejectComputer(me, "c")).rejects.toThrow("app_locked");
  });

  it("asking the computers again and the pairing answers wait for the PIN too", async () => {
    setAppLocked(true);
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    try {
      expect(await askAgain("csrf", "p".repeat(22))).toBe(false);
      await sendSasAnswers("csrf", "p".repeat(22), [{ device: "d", commit: "c", pnonce: "n" }]);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("what the app shows", () => {
  const withHash = { ...emptyRecord(), hash: { salt: "s", iter: ITER, digest: "d" } };
  it("the PIN is mandatory: created as soon as the account is signed in or the phone has pairings", () => {
    expect(lockKind(emptyRecord(), false, "in", false)).toBe("setup");
    expect(lockKind(emptyRecord(), false, "out", true)).toBe("setup");
    expect(lockKind(emptyRecord(), false, "unknown", true)).toBe("setup");
  });
  it("nothing shows until the storage and the account check answered", () => {
    expect(lockKind(null, false, "in", true)).toBe("loading");
    expect(lockKind(emptyRecord(), false, "unknown", false)).toBe("loading");
    // Only a signed-out phone with nothing stored opens (the sign-in screen) without a PIN.
    expect(lockKind(emptyRecord(), false, "out", false)).toBe("open");
  });
  it("with a PIN: locked until it is typed, whatever the account; blocked wins over everything", () => {
    expect(lockKind(withHash, false, "out", false)).toBe("locked");
    expect(lockKind(withHash, true, "in", true)).toBe("open");
    expect(lockKind({ ...withHash, blocked: true }, true, "in", true)).toBe("blocked");
  });
});

describe("the sign-out on a block", () => {
  it("posts the existing sign-out route with the reason, and says whether the server answered", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const ok = (async (url: string, init: RequestInit) => (calls.push({ url, init }), new Response("{}", { status: 200 }))) as unknown as typeof fetch;
    expect(await endSessionForPin(ok)).toBe(true);
    expect(calls[0].url).toBe("/api/community/auth/logout");
    expect(calls[0].init.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ reason: "pin_lockout" });
    const offline = (async () => {
      throw new TypeError("offline");
    }) as unknown as typeof fetch;
    expect(await endSessionForPin(offline)).toBe(false);
  });
});
