"use client";

// The phone app's PIN lock (docs/phone-relay-protocol.md, "App lock (PIN)"). Every phone that uses
// the app has a PIN: it is created right after the account sign-in (before anything else shows),
// asked on every open and after the chosen idle time, and changed (never removed) in Ajustes.
// While the app is locked nothing from the phone's storage is on screen and nothing is sent to a
// computer or the account (lock-state.ts gates the send functions too). 5 wrong PINs in a row: a
// one-minute wait; 10: the app is blocked on this phone, the PIN hash is deleted and the account
// session ends on the server; only a new sign-in with the account's second factor, then a new PIN,
// opens it again.
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { accountUrl } from "@/lib/account";
import type { Locale } from "@/lib/i18n";
import { IdleLock } from "./idle-lock";
import { setAppLocked } from "./lock-state";
import { browserLockStore, endSessionForPin } from "./lock-store";
import { lockStrings, type LockStrings } from "./lock-strings";
import { calibrate, IDLE_CHOICES, lockKind, pinProblem, setPin, tryPin, type IdleChoice, type LockAccount, type LockKind, type LockRecord, type LockStore, type PinProblem, type TryResult } from "./pin-lock";
import { Group, PixelCube } from "./AppParts";
import styles from "./phone.module.css";

export type { LockAccount, LockKind } from "./pin-lock";

export type AppLock = {
  k: LockKind;
  /** The lock record could not be read: the app stays closed. */
  failed: boolean;
  rec: LockRecord | null;
  /** The setup follows a block (a new PIN after signing in again). */
  renew: boolean;
  create: (pin: string) => Promise<PinProblem | "storage" | null>;
  /** Reads the record again (after the app's storage was wiped for another account). */
  refresh: () => Promise<void>;
  unlock: (pin: string) => Promise<TryResult>;
  change: (current: string, next: string) => Promise<TryResult | { ok: false; why: "problem"; problem: PinProblem | "storage" }>;
  setIdle: (c: IdleChoice) => Promise<boolean>;
  lockNow: () => void;
};

let storeCache: LockStore | null = null;
const lockStore = () => (storeCache ??= browserLockStore());
let iterCache: Promise<number> | null = null;
const iterations = () => (iterCache ??= calibrate());

/**
 * The lock record (written once, empty, on first use). Storage that fails: null, and the app stays
 * closed (a lock kept only in memory could be skipped by making the storage fail once).
 */
async function readRecord(): Promise<LockRecord | null> {
  try {
    return await lockStore().update((x) => x);
  } catch {
    return null;
  }
}

const ACTIVITY = ["pointerdown", "keydown", "touchstart", "wheel"] as const;
const CHECK_MS = 5_000;
const LOGOUT_RETRY_MS = 30_000;

/**
 * The lock's state for the app. `account`: from the app's own account check; `hasData`: pairings
 * of this phone are loaded (a phone from before the lock existed gets its PIN before they show).
 */
export function useAppLock(account: LockAccount, hasData: boolean): AppLock {
  const [rec, setRec] = useState<LockRecord | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [renew, setRenew] = useState(false);
  // A block whose sign-out finished before this page loaded: any sign-in seen here is a new one.
  const freshSignIn = useRef(false);

  const [failed, setFailed] = useState(false);
  const reload = useCallback(async () => {
    const r = await readRecord();
    // A failed read never replaces a record already read (the screen keeps its state).
    if (r) setRec(r);
    return r;
  }, []);

  useEffect(() => {
    (async () => {
      const r = await readRecord();
      if (r?.blocked && r.logoutDone) freshSignIn.current = true;
      if (r) setRec(r);
      else setFailed(true);
    })();
  }, []);

  const k = lockKind(rec, unlocked, account, hasData);

  // The send functions read this (lock-state.ts); also set at once by lock() below.
  useLayoutEffect(() => {
    setAppLocked(k !== "open");
  }, [k]);

  const lock = useCallback(() => {
    setAppLocked(true);
    setUnlocked(false);
  }, []);

  // Blocked: the account session ends on the server (retried until it answers), then a new sign-in
  // (seen as "in" after the sign-out) opens the way to a new PIN.
  const blocked = !!rec?.blocked;
  const logoutDone = !!rec?.logoutDone;
  useEffect(() => {
    if (!blocked || logoutDone) return;
    let alive = true;
    const attempt = async () => {
      if (!(await endSessionForPin()) || !alive) return;
      await lockStore().update((r) => (r.blocked ? { ...r, logoutDone: true } : r)).catch(() => null);
      if (alive) await reload();
    };
    void attempt();
    const timer = window.setInterval(() => void attempt(), LOGOUT_RETRY_MS);
    window.addEventListener("online", attempt);
    return () => {
      alive = false;
      window.clearInterval(timer);
      window.removeEventListener("online", attempt);
    };
  }, [blocked, logoutDone, reload]);
  useEffect(() => {
    if (!blocked || !logoutDone) return;
    if (account !== "in") {
      freshSignIn.current = true;
      return;
    }
    if (!freshSignIn.current) return;
    void (async () => {
      await lockStore().update((r) => ({ ...r, blocked: false, logoutDone: false, failures: 0, blockUntil: 0, hash: null })).catch(() => null);
      setRenew(true);
      await reload();
    })();
  }, [blocked, logoutDone, account, reload]);

  // The idle lock, while the app is open with a PIN.
  const idleChoice = rec?.idle ?? 5;
  const guarded = k === "open" && !!rec?.hash;
  const idle = useRef<IdleLock | null>(null);
  useEffect(() => {
    if (!guarded) return;
    const watch = new IdleLock(idleChoice, Date.now, lock);
    idle.current = watch;
    const onActivity = () => watch.activity();
    const onVisibility = () => (document.visibilityState === "hidden" ? watch.hidden() : watch.visible());
    const onHide = () => watch.hidden();
    const onShow = () => watch.visible();
    for (const e of ACTIVITY) window.addEventListener(e, onActivity, { capture: true, passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("pagehide", onHide);
    window.addEventListener("pageshow", onShow);
    const timer = window.setInterval(() => watch.check(), CHECK_MS);
    return () => {
      for (const e of ACTIVITY) window.removeEventListener(e, onActivity, { capture: true });
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("pagehide", onHide);
      window.removeEventListener("pageshow", onShow);
      window.clearInterval(timer);
      idle.current = null;
    };
  }, [guarded, idleChoice, lock]);

  const create = useCallback(
    async (pin: string) => {
      try {
        const problem = await setPin(lockStore(), pin, await iterations());
        if (problem) return problem;
      } catch {
        return "storage" as const;
      }
      await reload();
      setUnlocked(true);
      setRenew(false);
      return null;
    },
    [reload],
  );

  const unlock = useCallback(
    async (pin: string) => {
      const r = await tryPin(lockStore(), pin, Date.now()).catch((): TryResult => ({ ok: false, why: "none" }));
      await reload();
      if (r.ok) setUnlocked(true);
      return r;
    },
    [reload],
  );

  const change = useCallback(
    async (current: string, next: string) => {
      const problem = pinProblem(next);
      if (problem) return { ok: false as const, why: "problem" as const, problem };
      const r = await tryPin(lockStore(), current, Date.now()).catch((): TryResult => ({ ok: false, why: "none" }));
      if (!r.ok) {
        await reload();
        if (r.why === "blocked") lock();
        return r;
      }
      try {
        await setPin(lockStore(), next, await iterations());
      } catch {
        return { ok: false as const, why: "problem" as const, problem: "storage" as const };
      }
      await reload();
      return r;
    },
    [reload, lock],
  );

  const setIdle = useCallback(
    async (c: IdleChoice) => {
      try {
        await lockStore().update((r) => ({ ...r, idle: c }));
        await reload();
        return true;
      } catch {
        return false;
      }
    },
    [reload],
  );

  const refresh = useCallback(async () => {
    const r = await readRecord();
    if (!r) return setFailed(true), setRec(null);
    setUnlocked(false);
    setRec(r);
  }, []);

  return { k, failed, rec, renew, create, refresh, unlock, change, setIdle, lockNow: lock };
}

// --- screens -------------------------------------------------------------------------------------

function useNow(on: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!on) return;
    const t = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(t);
  }, [on]);
  return now;
}

/** A PIN field: digits only, the numeric keypad, hidden as typed, never offered to autofill. */
function PinInput({ id, label, value, onChange, autoFocus, disabled, describedBy }: { id: string; label: string; value: string; onChange: (v: string) => void; autoFocus?: boolean; disabled?: boolean; describedBy?: string }) {
  return (
    <div>
      <label htmlFor={id} className="text-[0.95rem] font-bold">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type="password"
        inputMode="numeric"
        pattern="[0-9]*"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        enterKeyHint="done"
        maxLength={12}
        data-1p-ignore="true"
        data-lpignore="true"
        className={`${styles.input} mono mt-1 w-full text-center text-[1.5rem] tracking-[0.3em]`}
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 12))}
        autoFocus={autoFocus}
        disabled={disabled}
        aria-describedby={describedBy}
        data-testid={id}
      />
    </div>
  );
}

/** The screen shown instead of the app while it is locked, blocked, waiting for a PIN, or loading. */
export function LockScreen({ lang, lock }: { lang: Locale; lock: AppLock }) {
  const s = lockStrings(lang);
  return (
    <div className={styles.app}>
      <main className={styles.content} data-tabs="false" data-testid="app-lock" data-state={lock.k}>
        <div className="flex items-center gap-2 pt-6" aria-hidden="true">
          <PixelCube size={26} />
          <span className="font-display text-[1.375rem] font-semibold leading-none">miblo</span>
        </div>
        {lock.k === "loading" ? (
          <p className="py-16 text-center text-ink-2" role="status">
            {lock.failed ? s.storageRead : "…"}
          </p>
        ) : lock.k === "setup" ? (
          <SetupForm s={s} lock={lock} />
        ) : lock.k === "locked" ? (
          <UnlockForm s={s} lock={lock} />
        ) : (
          <Blocked s={s} lang={lang} lock={lock} />
        )}
      </main>
    </div>
  );
}

function SetupForm({ s, lock }: { s: LockStrings; lock: AppLock }) {
  const [pin, setPinValue] = useState("");
  const [again, setAgain] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const rulesId = useId();
  const submit = async () => {
    const problem = pinProblem(pin);
    if (problem) return setNote(s.problem[problem]);
    if (pin !== again) return setNote(s.mismatch);
    setBusy(true);
    setNote(null);
    const r = await lock.create(pin);
    setBusy(false);
    if (r) setNote(r === "storage" ? s.storage : s.problem[r]);
  };
  return (
    <form className="mt-2" onSubmit={(e) => (e.preventDefault(), void submit())} aria-labelledby="lock-title" noValidate>
      <h1 id="lock-title" className={styles.pairTitle}>
        {lock.renew ? s.newTitle : s.setupTitle}
      </h1>
      <p className="mt-2 text-[1.0625rem] text-ink-2">{lock.renew ? s.newBody : s.setupBody}</p>
      <div className={`${styles.joinCard} grid gap-3`}>
        <PinInput id="pin-new" label={s.pinLabel} value={pin} onChange={setPinValue} autoFocus describedBy={rulesId} />
        <PinInput id="pin-again" label={s.confirmLabel} value={again} onChange={setAgain} describedBy={rulesId} />
        <p id={rulesId} className="text-[0.95rem] text-ink-2">
          {s.rules}
        </p>
        <p role="status" aria-live="polite" className="font-bold text-amber-ink empty:hidden" data-testid="pin-note">
          {note}
        </p>
        <button type="submit" className="btn btn-primary w-full" disabled={busy || pin.length < 6 || again.length < 6} aria-busy={busy} data-testid="pin-save">
          {busy ? s.saving : s.save}
        </button>
      </div>
    </form>
  );
}

function waitLeft(rec: LockRecord | null, now: number): number {
  return rec && rec.blockUntil > now ? Math.ceil((rec.blockUntil - now) / 1000) : 0;
}

function UnlockForm({ s, lock }: { s: LockStrings; lock: AppLock }) {
  const [pin, setPinValue] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const now = useNow(true);
  const left = waitLeft(lock.rec, now);
  const submit = async () => {
    if (busy || left > 0 || pin.length < 6) return;
    setBusy(true);
    setNote(null);
    const r = await lock.unlock(pin);
    setBusy(false);
    setPinValue("");
    if (!r.ok && r.why === "wrong" && !r.until) setNote(s.wrong(r.left));
    window.setTimeout(() => document.getElementById("pin-unlock")?.focus(), 0);
  };
  return (
    <form className="mt-2" onSubmit={(e) => (e.preventDefault(), void submit())} aria-labelledby="lock-title" noValidate>
      <h1 id="lock-title" className={styles.pairTitle}>
        {s.lockedTitle}
      </h1>
      <p className="mt-2 text-[1.0625rem] text-ink-2">{s.lockedBody}</p>
      <div className={`${styles.joinCard} grid gap-3`}>
        <PinInput id="pin-unlock" label="PIN" value={pin} onChange={setPinValue} autoFocus disabled={left > 0} />
        <p role="status" aria-live="polite" className="font-bold text-amber-ink empty:hidden" data-testid="pin-note">
          {left > 0 ? s.wait(left) : note}
        </p>
        <button type="submit" className="btn btn-primary w-full" disabled={busy || left > 0 || pin.length < 6} aria-busy={busy} data-testid="pin-unlock-button">
          {left > 0 ? s.waitShort(left) : busy ? s.checking : s.unlock}
        </button>
      </div>
    </form>
  );
}

function Blocked({ s, lang, lock }: { s: LockStrings; lang: Locale; lock: AppLock }) {
  const next = encodeURIComponent(lang === "en" ? "/en/app" : "/app");
  return (
    <section className="mt-2" aria-labelledby="lock-title">
      <h1 id="lock-title" className={styles.pairTitle}>
        {s.blockedTitle}
      </h1>
      <div className={`${styles.joinCard} grid gap-3`} role="alert">
        <p className="font-bold" data-testid="pin-blocked">
          {s.blocked}
        </p>
        <p className="text-[0.95rem] text-ink-2">{lock.rec?.logoutDone ? s.blockedNote : s.blockedPending}</p>
        <a className="btn btn-primary w-full" href={`${accountUrl(lang)}?next=${next}`}>
          {s.signIn}
        </a>
      </div>
    </section>
  );
}

// --- Ajustes -------------------------------------------------------------------------------------

/** The lock's group in Ajustes: when it locks, change the PIN (with the current one), lock now. */
export function LockSettings({ lang, lock }: { lang: Locale; lock: AppLock }) {
  const s = lockStrings(lang);
  const [note, setNote] = useState<string | null>(null);
  const [changing, setChanging] = useState(false);
  const [current, setCurrent] = useState("");
  const [pin, setPinValue] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const now = useNow(changing);
  const left = waitLeft(lock.rec, now);
  const idleId = useId();
  const choice = lock.rec?.idle ?? 5;
  const submit = async () => {
    const problem = pinProblem(pin);
    if (problem) return setNote(s.problem[problem]);
    if (pin !== again) return setNote(s.mismatch);
    setBusy(true);
    setNote(null);
    const r = await lock.change(current, pin);
    setBusy(false);
    setCurrent("");
    if (r.ok) {
      setPinValue("");
      setAgain("");
      setChanging(false);
      setNote(s.changed);
    } else if (r.why === "problem") setNote(r.problem === "storage" ? s.storage : s.problem[r.problem]);
    else if (r.why === "wrong" && !r.until) setNote(s.wrong(r.left));
  };
  return (
    <Group title={s.settingsTitle} id="lock-settings-title">
      <p className="text-ink-2">{s.settingsBody}</p>
      <label htmlFor={idleId} className="mt-3 block text-[0.95rem] font-bold">
        {s.idleLabel}
      </label>
      <select
        id={idleId}
        className={`${styles.input} mt-1 w-full`}
        value={String(choice)}
        data-testid="lock-idle"
        onChange={async (e) => {
          const v = e.target.value === "leave" ? "leave" : (Number(e.target.value) as IdleChoice);
          setNote((await lock.setIdle(v)) ? s.idleSaved : s.storage);
        }}
      >
        {IDLE_CHOICES.map((c) => (
          <option key={String(c)} value={String(c)}>
            {s.idle[`${c}`]}
          </option>
        ))}
      </select>
      {changing ? (
        <form className="mt-4 grid gap-3" onSubmit={(e) => (e.preventDefault(), void submit())} noValidate>
          <PinInput id="pin-current" label={s.currentLabel} value={current} onChange={setCurrent} autoFocus disabled={left > 0} />
          <PinInput id="pin-change" label={s.newLabel} value={pin} onChange={setPinValue} />
          <PinInput id="pin-change-again" label={s.confirmLabel} value={again} onChange={setAgain} />
          <p className="text-[0.95rem] text-ink-2">{s.rules}</p>
          <div className="flex gap-2">
            <button type="submit" className="btn btn-primary flex-1" disabled={busy || left > 0 || current.length < 6 || pin.length < 6 || again.length < 6} aria-busy={busy} data-testid="pin-change-save">
              {left > 0 ? s.waitShort(left) : busy ? s.saving : s.save}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => (setChanging(false), setNote(null))}>
              {s.changeCancel}
            </button>
          </div>
        </form>
      ) : (
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" className="btn btn-ghost" onClick={() => (setChanging(true), setNote(null))} data-testid="pin-change-open">
            {s.change}
          </button>
          <button type="button" className="btn btn-ghost" onClick={lock.lockNow} data-testid="lock-now">
            {s.lockNow}
          </button>
        </div>
      )}
      <p role="status" aria-live="polite" className="mt-2 font-bold empty:hidden">
        {left > 0 && changing ? s.wait(left) : note}
      </p>
    </Group>
  );
}
