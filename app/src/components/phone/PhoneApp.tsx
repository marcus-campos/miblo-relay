"use client";

// The Miblo phone companion (/app, /en/app). Protocol v6: the phone joins the person's Miblo
// account (account-join.ts) and every computer linked to that account seals its pairing to this
// phone's own key; no QR code, link or vault. It shows each computer's live, end-to-end encrypted
// snapshot and turns on generic push alerts.
// Miblo+ (protocol v3): each session's latest messages, replies and permission approvals, only
// when the computer's status frame says its room is on the plan (free rooms close on any other
// channel, so nothing Miblo+ is ever sent before that).
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { accountUrl } from "@/lib/account";
import { href, type Locale } from "@/lib/i18n";
import { assertPhonePasskey, platformPasskeys, rpIdFor } from "@/lib/webauthn";
import { MfaVerify, call, loadMfa, type MfaState } from "@/components/community/security";
import {
  currentSubscription,
  isIos,
  isStandalone,
  openedFor,
  pushSupported,
  registerWorker,
  subFrame,
  subscribe,
  unsubFrame,
  unsubscribeAll,
} from "./push";
import { RelayClient, type LinkState } from "./relay-client";
import { acceptFrameAt, duration, elapsed, frameAt, money, parseSnapshot, resetWhen, type LimitView, type SessionView, type SnapshotView } from "./snapshot";
import { canSend, deleteIdentity, listIdentities, listPairings, loadIdentity, purgeLegacy, rekeyPairing, removePairing, saveIdentity, type AccountIdentity, type StoredPairing } from "./store";
import {
  askAgain,
  confirmComputer,
  deviceName,
  fetchAccountPhones,
  fetchGrants,
  makeIdentity,
  pairingsFor,
  registerIdentity,
  rejectComputer,
  sasStep,
  sendSasAnswers,
  syncGrants,
  waitingFor,
  waitDetail,
  type WaitDetail,
  type GrantIssue,
  answerCode,
  passkeyPlan,
  type PhonePk,
  type GrantsResult,
  type RequestRow,
  type ShownCode,
} from "./account-join";
import { wipePhoneData } from "./wipe";
import { TaskList, TaskSheet, type TaskSendResult } from "./TaskViews";
import {
  allowChallenge,
  decisionPayload,
  newerHistory,
  openPayload,
  parseRekey,
  parseApproval,
  parseApprovalDone,
  parseConfirm,
  parseConfirmDone,
  parseConfirmResult,
  confirmChallenge,
  confirmPayload,
  type ConfirmView,
  parseHistory,
  parseReplyAck,
  parseTaskAck,
  parseTaskInfo,
  plusCaps,
  replyPayload,
  stopPayload,
  syncPayload,
  taskInfoPayload,
  taskPayload,
  type ApprovalView,
  type HistoryView,
  type PlusCaps,
  type ReplyAck,
  type ReplyHow,
  type TaskAck,
  type TaskInfo,
} from "./plus";
import { ApprovalCard, CodeEntry, ConfirmCard, ReuseQuestion, SessionScreen, Upsell, type ActBlock } from "./PlusViews";
import { sentHowOf } from "./reply-model";
import { MibloHero, MibloThumb } from "./MibloHero";
import { LiveMiblo } from "./LiveMiblo";
import { PhoneApps } from "./PhoneApps";
import { acceptPetFrame } from "./pet-cache";
import {
  agoText,
  attentionCount,
  deviceKind,
  featuredMiblo,
  installHint,
  mergeApproval,
  notifyHelp,
  pendingApprovals,
  type AppTab,
  type DeviceKind,
  type InstallHint,
} from "./app-model";
import { CatEyes, Group, Icon, Notice, PixelCube, Steps, TabBar, Tech, TopBar, type AccountLinks } from "./AppParts";
import { phoneStrings, type PhoneStrings } from "./strings";
import { LockScreen, LockSettings, useAppLock } from "./AppLock";
import { isAppLocked } from "./lock-state";
import styles from "./phone.module.css";

type Live = { link: LinkState; snap: SnapshotView | null };
/** Miblo+ state of one paired computer (memory only: nothing of it is stored on the phone). */
type PlusRoom = {
  caps: PlusCaps | null;
  histories: Record<string, HistoryView>;
  approvals: ApprovalView[];
  /** Approval id -> what happened, shown on its card for a few seconds. */
  outcomes: Record<string, string>;
  /** Reply nonce -> the computer's acknowledgement; session -> its last reply's nonce. */
  acks: Record<string, ReplyAck>;
  /** `how`: the session's `replyHow` (1.24) when the reply was sent, for "Entregue" to say how it went in. */
  lastReply: Record<string, { nonce: string; at: number; how?: ReplyHow | null }>;
  /** v6 "Nova tarefa": what the computer allows (null until asked), and its answers to tasks. */
  taskInfo: TaskInfo | null;
  taskAcks: Record<string, TaskAck>;
  /** v7: what the computer asks to turn on, confirmed here with the code it shows; how each ended. */
  confirms: ConfirmView[];
  confirmDone: Record<string, string>;
};
/** After a 4402 (room not on Miblo+), the phone sends nothing Miblo+ to that room for this long. */
const PLAN_REFUSED_MS = 10 * 60 * 1000;
const emptyPlus = (): PlusRoom => ({ caps: null, histories: {}, approvals: [], outcomes: {}, acks: {}, lastReply: {}, taskInfo: null, taskAcks: {}, confirms: [], confirmDone: {} });
/** v7: the person chose to re-use this phone's passkey: later joins re-use it without asking. */
const REUSE_KEY = "miblo.passkeyReuse";
/** The time now, for event handlers (frames are stamped with it). */
const wallClock = () => Date.now();
/** Cards of answered or expired approvals linger this long, then go. */
const DONE_LINGER_MS = 8_000;
/** An open conversation asks the computer again this often (it sends that session only while asked). */
const REOPEN_MS = 2 * 60 * 1000;
/** Grants are read again this often while no computer accepted this phone yet, and this often after. */
// While no computer let this phone in yet (or one is asking the person): a long poll follows each
// computer's next step within about a second (fetchGrants `wait`); this timer is only its fallback.
const GRANTS_WAITING_MS = 15_000;
/** The long poll after a failed answer (429: the account's request budget is spent for the minute). */
const LONG_POLL_RETRY_MS = 5_000;
const LONG_POLL_LIMITED_MS = 30_000;
/** A long poll's answer is used by the pass it starts while this fresh (one request instead of two). */
const PREFETCH_FRESH_MS = 2_000;
const GRANTS_EVERY_MS = 2 * 60 * 1000;
/** A task's answer waits this long for the computer. */
const TASK_ANSWER_MS = 20_000;

/** Why this phone cannot act on a computer (approve, deny, reply, start a task), or null when it can. */
function actBlock(p: StoredPairing, caps: PlusCaps | null, passkeys: boolean | null, link?: LinkState): ActBlock {
  if (link === "revoked") return "revoked";
  if (!p.phone) return passkeys === false ? "noPasskeys" : "notEnrolled";
  if (!caps?.phones.includes(p.phone.id)) return "notEnrolled";
  // v6: a phone without a passkey follows along only.
  return p.phone.credId ? null : "noPasskeys";
}

/** Where this phone stands with the account (protocol v6). */
type JoinState =
  | { k: "loading" }
  | { k: "signedOut" }
  | { k: "mfa"; state: MfaState }
  | { k: "mfaSetup" }
  | { k: "join"; uid: string; email: string; csrf: string; passkeys: PhonePk[] }
  | { k: "ready"; uid: string; email: string; csrf: string; me: AccountIdentity; requests: RequestRow[] }
  | { k: "error" };
type NotifyState = "unknown" | "unsupported" | "ios-install" | "default" | "denied" | "enabled" | "busy";
type InstallPrompt = Event & { prompt(): Promise<void> };

// The computer re-sends an unchanged snapshot every 4 minutes (plugin REFRESH_MS): older than
// this means it stopped talking.
const STALE_MS = 6 * 60 * 1000;
const LAST_AT_KEY = "miblo-phone-last-at:";
/** The account last signed in here: its pairings show while the account cannot be asked (offline). */
const UID_KEY = "miblo-phone-uid";
function lastUid(): string | null {
  try {
    return localStorage.getItem(UID_KEY);
  } catch {
    return null;
  }
}
function setLastUid(uid: string): void {
  try {
    localStorage.setItem(UID_KEY, uid);
  } catch {
    // No storage.
  }
}

// The newest frame time accepted per computer: this page's own (strictly newer frames only) and
// the one kept across reloads (a replayed frame from before a reload is still refused; the same
// frame is shown again). Storage may be unavailable: then it only lasts for the page.
const lastAtMemory = new Map<string, number>();
function storedLastAt(room: string): number | undefined {
  try {
    const v = Number(localStorage.getItem(LAST_AT_KEY + room));
    return Number.isFinite(v) && v > 0 ? v : undefined;
  } catch {
    return undefined;
  }
}
function acceptFrame(room: string, at: number | null): boolean {
  const seen = lastAtMemory.get(room);
  return seen !== undefined ? acceptFrameAt(at, seen, Date.now()) : acceptFrameAt(at, storedLastAt(room), Date.now(), true);
}
function setLastAt(room: string, at: number): void {
  lastAtMemory.set(room, at);
  try {
    localStorage.setItem(LAST_AT_KEY + room, String(at));
  } catch {
    // No storage.
  }
}

// Platform facts only the browser knows (null while prerendering), read once.
type Platform = { ios: boolean; standalone: boolean };
let platformCache: Platform | null = null;
const noSubscribe = () => () => {};
const clientPlatform = () => (platformCache ??= { ios: isIos(), standalone: isStandalone() });
const serverPlatform = () => null;

// Whether the phone itself is online: shown at once, before a socket notices it dropped.
const onlineSubscribe = (cb: () => void) => {
  window.addEventListener("online", cb);
  window.addEventListener("offline", cb);
  return () => {
    window.removeEventListener("online", cb);
    window.removeEventListener("offline", cb);
  };
};
const clientOnline = () => navigator.onLine;
const serverOnline = () => true;

export function PhoneApp({ lang }: { lang: Locale }) {
  const t = phoneStrings(lang);
  const [pairings, setPairings] = useState<StoredPairing[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [live, setLive] = useState<Record<string, Live>>({});
  const [now, setNow] = useState(() => Date.now());
  const [toast, setToast] = useState<string | null>(null);
  const [notify, setNotify] = useState<NotifyState>("unknown");
  const [installPrompt, setInstallPrompt] = useState<InstallPrompt | null>(null);
  const platform = useSyncExternalStore(noSubscribe, clientPlatform, serverPlatform);
  const phoneOnline = useSyncExternalStore(onlineSubscribe, clientOnline, serverOnline);
  const clients = useRef(new Map<string, RelayClient>());
  const [plus, setPlus] = useState<Record<string, PlusRoom>>({});
  const [openSession, setOpenSession] = useState<string | null>(null);
  /** Room -> until when the relay said it is not on Miblo+ (4402): no "up" frames, the upsell shows. */
  const planRefused = useRef(new Map<string, number>());
  const updatePlus = useCallback((room: string, fn: (r: PlusRoom) => PlusRoom) => {
    setPlus((all) => ({ ...all, [room]: fn(all[room] ?? emptyPlus()) }));
  }, []);
  const subRef = useRef<PushSubscription | null>(null);
  /** Rooms whose connection opened since they last asked for the approvals still waiting. */
  const syncDue = useRef(new Set<string>());
  const [syncTick, setSyncTick] = useState(0);
  /** This device has passkeys (a user-verifying platform authenticator); null while unknown. */
  const [passkeys, setPasskeys] = useState<boolean | null>(null);
  /** v6: this phone and the account. */
  const [join, setJoin] = useState<JoinState>({ k: "loading" });
  const [joinBusy, setJoinBusy] = useState(false);
  const [joinNote, setJoinNote] = useState<string | null>(null);
  /** Pairings from QR codes were deleted on this load (v5 -> v6). */
  const [legacy, setLegacy] = useState(false);
  const [joinTick, setJoinTick] = useState(0);
  // The grants' sig last seen, and a long poll's answer for the pass it starts.
  const grantsSig = useRef<string | null>(null);
  const prefetched = useRef<{ got: GrantsResult; at: number } | null>(null);
  const [taskOpen, setTaskOpen] = useState(false);
  /** The codes this phone shows for computers waiting for the person (protocol v6 "Verifying a new phone"). */
  const [codes, setCodes] = useState<ShownCode[]>([]);
  /** A computer was shown another key for this phone (its code would never match): warn. */
  const [keyMismatch, setKeyMismatch] = useState(false);
  /** More code exchanges than a person pairing makes: someone may be trying to get in. */
  const [sasAlert, setSasAlert] = useState(false);
  // Why the grant this phone holds was not used (the waiting screen says so).
  const [grantIssue, setGrantIssue] = useState<GrantIssue | null>(null);
  /** Computers whose code this phone showed and that granted it: the person confirms them here. */
  const [toConfirm, setToConfirm] = useState<ShownCode[]>([]);
  // The PIN lock (AppLock.tsx): nothing below shows until it is open.
  const lock = useAppLock(join.k === "join" || join.k === "ready" ? "in" : join.k === "loading" ? "unknown" : "out", !!pairings?.length);
  const refreshLock = lock.refresh;

  const say = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast((current) => (current === message ? null : current)), 3500);
  }, []);

  // First load: the service worker, saved pairings (only those from the account: QR pairings of
  // v5 are deleted), and a v5 pairing link in the fragment, which is dropped unread.
  useEffect(() => {
    void registerWorker(lang);
    const onPrompt = (e: Event) => {
      e.preventDefault();
      setInstallPrompt(e as InstallPrompt);
    };
    window.addEventListener("beforeinstallprompt", onPrompt);

    (async () => {
      if (location.hash.includes("p=")) {
        // The secrets leave the address bar (and the history entry) right away; they are not used.
        history.replaceState(null, "", location.pathname + location.search);
        setLegacy(true);
      }
      try {
        if ((await purgeLegacy()) > 0) setLegacy(true);
        // Until the account answers: only the pairings of the account last signed in here (the
        // join pass below hides them when signed out, deletes another account's).
        const { keep } = pairingsFor(await listPairings(), lastUid());
        setPairings(keep);
        setSelected((s) => s ?? keep[0]?.room ?? null);
      } catch {
        setPairings([]);
        say(t.storageError);
      }
    })();

    void platformPasskeys().then(setPasskeys);
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.removeEventListener("beforeinstallprompt", onPrompt);
      window.clearInterval(tick);
    };
    // Runs once; say/t are stable for a given language.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // v6: where this phone stands with the account, and its pairings from the computers' grants.
  // Read on load, when the page gets the focus back (signed in, second factor passed), and on a
  // timer: often while no computer accepted this phone yet, rarely after.
  useEffect(() => {
    let alive = true;
    // Pairings show only while their account is signed in (security audit 1.21.0, finding 3).
    const hide = () => {
      setPairings((cur) => (cur && cur.length ? [] : cur));
      setCodes([]);
      setToConfirm([]);
      setGrantIssue(null);
    };
    (async () => {
      const st = await loadMfa();
      if (!alive) return;
      if (!st) return setJoin({ k: "error" });
      if (!st.signedIn) return hide(), setJoin({ k: "signedOut" });
      if (st.pending) return hide(), setJoin({ k: "mfa", state: st });
      if (!st.mfa?.enrolled) return hide(), setJoin({ k: "mfaSetup" });
      if (!st.mfa.valid) return hide(), setJoin({ k: "mfa", state: st });
      const acct = await fetchAccountPhones();
      if (!alive) return;
      if (typeof acct === "number") return setJoin(acct === 403 ? { k: "mfa", state: st } : { k: "error" });
      // Another account signed in here: everything of the previous one goes (pairings, keys,
      // identities, the confirmed computers).
      const here = await listPairings().catch(() => [] as StoredPairing[]);
      const others = (await listIdentities().catch(() => [] as AccountIdentity[])).filter((x) => x.uid !== acct.uid);
      if (pairingsFor(here, acct.uid).wipe || others.length) {
        if (lastUid() && lastUid() !== acct.uid) {
          // The lock record went with the rest: the new account creates its own PIN.
          await wipePhoneData();
          await refreshLock();
        }
        else {
          for (const p of here) if (p.acct?.uid !== acct.uid) await removePairing(p.room).catch(() => {});
          for (const x of others) await deleteIdentity(x.uid).catch(() => {});
        }
        if (!alive) return;
        const left = pairingsFor(await listPairings().catch(() => []), acct.uid).keep;
        setPairings(left);
        setSelected((cur) => (cur && left.some((x) => x.room === cur) ? cur : (left[0]?.room ?? null)));
      }
      setLastUid(acct.uid);
      const loaded = await loadIdentity(acct.uid).catch(() => null);
      if (!loaded || !loaded.registered || !acct.phones.some((x) => x.id === loaded.id)) {
        // Not joined yet, or removed from the account: (again) a new identity.
        if (loaded) await deleteIdentity(acct.uid).catch(() => {});
        return setJoin({ k: "join", uid: acct.uid, email: st.email ?? "", csrf: st.csrf ?? "", passkeys: Array.isArray(acct.passkeys) ? acct.passkeys : [] });
      }
      let me: AccountIdentity = loaded;
      const meNow = me;
      setJoin((cur) => ({ k: "ready", uid: acct.uid, email: st.email ?? "", csrf: st.csrf ?? "", me: meNow, requests: cur.k === "ready" && cur.me.id === meNow.id ? cur.requests : [] }));
      const pre = prefetched.current;
      prefetched.current = null;
      const got = pre && Date.now() - pre.at < PREFETCH_FRESH_MS ? pre.got : await fetchGrants(me.id);
      if (!alive || typeof got === "number") return;
      if (got.sig) grantsSig.current = got.sig;
      // The code exchange: answer new commitments, show the codes of revealed ones.
      const step = await sasStep(me, me.rounds ?? [], got.requests);
      if (JSON.stringify(step.rounds) !== JSON.stringify(me.rounds ?? [])) {
        me = { ...me, rounds: step.rounds };
        await saveIdentity(me).catch(() => {});
      }
      await sendSasAnswers(st.csrf ?? "", me.id, step.answers);
      if (!alive) return;
      setCodes(step.codes);
      setKeyMismatch(step.mismatch.length > 0);
      setSasAlert(step.alert);
      const meSynced = me;
      setJoin((cur) => (cur.k === "ready" && cur.me.id === meSynced.id ? { ...cur, me: meSynced, requests: got.requests } : cur));
      const before = (await listPairings()).filter((x) => x.acct).map((x) => x.room);
      const r = await syncGrants(me, got.grants);
      if (!alive || !r) return;
      setToConfirm(r.confirm);
      setGrantIssue(r.issue);
      if (r.changed) {
        setPairings(r.pairings);
        setSelected((cur) => (cur && r.pairings.some((x) => x.room === cur) ? cur : (r.pairings[0]?.room ?? null)));
        const added = r.pairings.find((x) => x.acct && !before.includes(x.room));
        if (added) say(t.join.joined(added.name));
      }
    })();
    return () => {
      alive = false;
    };
  }, [joinTick, say, t, refreshLock]);
  const hasPairings = !!pairings?.length;
  // Waiting for a computer's next step (no computer let this phone in yet, or one is asking the
  // person): a long poll, so its commitment, its nonce (the code) and its grant show at once.
  const waitingId = join.k === "ready" && (!hasPairings || join.requests.some((r) => r.state === "pending")) ? join.me.id : null;
  useEffect(() => {
    if (!waitingId) return;
    let alive = true;
    const ac = new AbortController();
    const pause = (ms: number) => new Promise((r) => window.setTimeout(r, ms));
    (async () => {
      while (alive) {
        const got = await fetchGrants(waitingId, grantsSig.current, ac.signal);
        if (!alive) return;
        if (typeof got === "number") {
          await pause(got === 429 ? LONG_POLL_LIMITED_MS : LONG_POLL_RETRY_MS);
          continue;
        }
        // A server without the long poll: the timer below reads the grants.
        if (!got.sig) return;
        if (got.sig !== grantsSig.current) {
          grantsSig.current = got.sig;
          prefetched.current = { got, at: Date.now() };
          setJoinTick((n) => n + 1);
        }
      }
    })();
    return () => {
      alive = false;
      ac.abort();
    };
  }, [waitingId]);
  useEffect(() => {
    const again = () => setJoinTick((n) => n + 1);
    window.addEventListener("focus", again);
    const timer = window.setInterval(again, hasPairings ? GRANTS_EVERY_MS : GRANTS_WAITING_MS);
    return () => {
      window.removeEventListener("focus", again);
      window.clearInterval(timer);
    };
  }, [hasPairings]);

  // Joining: the identity (ECDH key, id, passkey) made here, registered with the account. v7: a
  // passkey of this account may already be on this phone: the person chooses once whether to use
  // it (remembered); a new one is made only when there is none, or the person asks for another.
  const [reuseAsk, setReuseAsk] = useState(false);
  const [repair, setRepair] = useState<"idle" | "busy" | "failed">("idle");
  const joinAccount = async (choice: "reuse" | "create" | null = null) => {
    if (join.k !== "join") return;
    let remembered = false;
    try {
      remembered = localStorage.getItem(REUSE_KEY) === "1";
    } catch {
      remembered = false;
    }
    const plan = passkeys === true ? passkeyPlan(join.passkeys.length, remembered, choice) : "create";
    if (plan === "ask") return setReuseAsk(true);
    setReuseAsk(false);
    if (choice === "reuse") {
      try {
        localStorage.setItem(REUSE_KEY, "1");
      } catch {
        // No storage: asked again next time.
      }
    }
    setJoinBusy(true);
    setJoinNote(null);
    try {
      const made = await makeIdentity(join.uid, deviceName(navigator.userAgent), passkeys === true, plan === "reuse" ? join.passkeys : []);
      const r = await registerIdentity(join.csrf, made);
      if (r === "ok") setJoinTick((n) => n + 1);
      else if (r === "mfa") {
        const st = await loadMfa();
        if (st) setJoin({ k: "mfa", state: st });
      } else if (r === "mfa_setup") setJoin({ k: "mfaSetup" });
      else setJoinNote(r === "limit" ? t.join.limit : t.join.failed);
    } catch {
      setJoinNote(t.join.cancelled);
    } finally {
      setJoinBusy(false);
    }
  };

  // A computer whose code this phone showed granted it: the person confirms it here (pinned) or
  // turns it down (its grants stay refused).
  const answerComputer = async (c: ShownCode, yes: boolean) => {
    if (join.k !== "ready") return;
    const next = yes ? await confirmComputer(join.me, c) : await rejectComputer(join.me, c.cpub);
    setJoin((cur) => (cur.k === "ready" && cur.me.id === next.id ? { ...cur, me: next } : cur));
    setToConfirm((list) => list.filter((x) => x.cpub !== c.cpub));
    say(yes ? t.trust.confirmed(c.name) : t.trust.rejected);
    setJoinTick((n) => n + 1);
  };
  // v7: the person typed a computer's code here.
  const typeCode = async (q: RequestRow, code: string) => {
    if (join.k !== "ready") return "error" as const;
    const r = await answerCode(join.csrf, join.me, q, code);
    setJoin((cur) => (cur.k === "ready" && cur.me.id === r.me.id ? { ...cur, me: r.me } : cur));
    if (r.result === "ok") setJoinTick((n) => n + 1);
    return r.result;
  };
  const trustCards = (
    <>
      {join.k === "ready" && <CodeEntry t={t} requests={join.requests} now={now} hasPasskey={!!join.me.credId} onSubmit={typeCode} />}
      <TrustCards t={t} codes={codes} toConfirm={toConfirm} keyMismatch={keyMismatch} sasAlert={sasAlert} onAnswer={(c, yes) => void answerComputer(c, yes)} />
    </>
  );
  // v7: joining, from the join screen or after "Ligar de novo": the passkey question, or the button.
  const joinCard = join.k === "join" && reuseAsk ? <ReuseQuestion t={t} busy={joinBusy} onChoose={(c) => void joinAccount(c)} /> : null;

  // Alerts: what the browser allows, and the existing subscription (re-sent to every room).
  useEffect(() => {
    if (!platform) return;
    (async () => {
      if (!pushSupported()) return setNotify(platform.ios && !platform.standalone ? "ios-install" : "unsupported");
      if (Notification.permission === "denied") return setNotify("denied");
      const sub = await currentSubscription(lang).catch(() => null);
      subRef.current = sub;
      setNotify(sub ? "enabled" : "default");
      if (sub) clients.current.forEach((c) => c.send(subFrame(sub, lang)));
    })();
  }, [platform, lang]);

  // The rooms whose status says Miblo+ is on (a frame up on a free room would close the socket).
  const plusOn = useRef(new Set<string>());
  useEffect(() => {
    plusOn.current = new Set(Object.entries(plus).filter(([, r]) => r.caps?.on).map(([room]) => room));
  }, [plus]);

  // A phone was revoked on the computer: it replaced the pairing's read token and status key and
  // sent them sealed to this phone alone (on the status channel, so it works on every plan). Kept,
  // and in the vault; confirmed when the room is on Miblo+ (the computer re-sends a few times).
  const applyRekey = useCallback((p: StoredPairing, payload: unknown, sealed: boolean): boolean => {
    if (!payload || typeof payload !== "object" || (payload as { kind?: unknown }).kind !== "rekey") return false;
    const rk = parseRekey(payload, sealed, p.epoch ?? 0, Date.now());
    if (!rk) return true;
    const { readToken, key, epoch } = rk;
    void rekeyPairing(p.room, readToken, key, epoch).then(async (next) => {
      if (!next) return;
      if (plusOn.current.has(p.room)) await clients.current.get(p.room)?.sendUp("approval", { v: 5, kind: "rekeyed", epoch, at: Date.now() });
      setPairings((all) => all?.map((x) => (x.room === next.room ? next : x)) ?? all);
      say(t.plus.rekeyed);
    });
    return true;
  }, [say, t]);

  // Miblo+ frames (history, approval, reply acks): parsed defensively, kept in memory only.
  const onPlusPayload = useCallback((p: StoredPairing, payload: unknown, ch: string) => {
    if (ch === "history") {
      // v6: what "Nova tarefa" may run comes on the history channel (larger frames).
      const info = parseTaskInfo(payload);
      if (info) {
        updatePlus(p.room, (r) => (r.taskInfo && r.taskInfo.at >= info.at ? r : { ...r, taskInfo: info }));
        return;
      }
      const h = parseHistory(payload);
      if (!h) return;
      updatePlus(p.room, (r) =>
        newerHistory(r.histories[h.session], h, Date.now()) ? { ...r, histories: { ...r.histories, [h.session]: h } } : r,
      );
    } else if (ch === "approval") {
      // v7: a change asked on the computer, its end, or a wrong code.
      const cdone = parseConfirmDone(payload);
      if (cdone) {
        updatePlus(p.room, (r) => ({ ...r, confirmDone: { ...r.confirmDone, [cdone.id]: cdone.outcome } }));
        return;
      }
      const cres = parseConfirmResult(payload);
      if (cres) {
        updatePlus(p.room, (r) => ({ ...r, confirms: r.confirms.map((c) => (c.id === cres.id ? { ...c, left: cres.left } : c)) }));
        say(t.code.wrong(cres.left));
        return;
      }
      if ((payload as { kind?: unknown } | null)?.kind === "confirm") {
        void parseConfirm(payload, Date.now()).then((c) => {
          if (c) updatePlus(p.room, (r) => (r.confirmDone[c.id] ? r : { ...r, confirms: [...r.confirms.filter((x) => x.id !== c.id), c].slice(-4) }));
        });
        return;
      }
      const done = parseApprovalDone(payload);
      if (done) {
        updatePlus(p.room, (r) => ({
          ...r,
          outcomes: { ...r.outcomes, [done.id]: t.plus.outcome[done.outcome] },
          approvals: r.approvals.map((a) => (a.id === done.id ? { ...a, expires: Math.min(a.expires, Date.now() + DONE_LINGER_MS) } : a)),
        }));
        return;
      }
      void parseApproval(payload, Date.now()).then((a) => {
        if (!a) return;
        updatePlus(p.room, (r) => (r.outcomes[a.id] ? r : { ...r, approvals: mergeApproval(r.approvals, a, r.outcomes) }));
      });
    } else if (ch === "reply") {
      const ack = parseReplyAck(payload);
      if (ack) updatePlus(p.room, (r) => ({ ...r, acks: { ...r.acks, [ack.nonce]: ack } }));
      const tack = parseTaskAck(payload);
      if (tack) updatePlus(p.room, (r) => ({ ...r, taskAcks: { ...r.taskAcks, [tack.nonce]: tack } }));
    }
  }, [t, updatePlus, say]);

  // The approvals still waiting on each computer, asked for when this phone's connection opens (the
  // relay keeps none: a card sent while the app was closed or its socket was down would be lost)
  // and when the app is unlocked. Only on Miblo+, from an enrolled phone, with the app open.
  const lockOpen = lock.k === "open";
  useEffect(() => {
    if (lockOpen) for (const p of pairings ?? []) syncDue.current.add(p.room);
  }, [lockOpen, pairings]);
  useEffect(() => {
    if (!lockOpen || !pairings) return;
    for (const room of [...syncDue.current]) {
      const p = pairings.find((x) => x.room === room);
      if (!p) {
        syncDue.current.delete(room);
        continue;
      }
      const client = clients.current.get(room);
      if (!p.phone || !plus[room]?.caps?.on || live[room]?.link !== "open" || !client) continue;
      syncDue.current.delete(room);
      void client.sendUp("approval", syncPayload(p.phone.id, Date.now()));
    }
  }, [lockOpen, pairings, plus, live, syncTick]);

  // One relay connection per paired computer.
  useEffect(() => {
    if (!pairings) return;
    const map = clients.current;
    const rooms = new Set(pairings.map((p) => p.room));
    for (const [room, client] of map) {
      if (!rooms.has(room)) {
        client.stop();
        map.delete(room);
      }
    }
    for (const p of pairings) {
      const had = map.get(p.room);
      // A new identity (just enrolled) or new keys (re-keyed): a new connection with them.
      if (had && had.signature === `${p.phone?.id ?? ""}|${p.readToken}`) continue;
      had?.stop();
      const client = new RelayClient(p, {
        onState: (link) => {
          setLive((l) => ({ ...l, [p.room]: { snap: l[p.room]?.snap ?? null, link } }));
          if (link === "open") {
            // A new connection may have missed approvals sent while it was away: ask for them.
            syncDue.current.add(p.room);
            setSyncTick((n) => n + 1);
          }
          if (link === "open" && subRef.current) {
            // After the auth frame: tell the room where to send alerts.
            window.setTimeout(() => subRef.current && client.send(subFrame(subRef.current, lang)), 50);
          }
        },
        onPlanRefused: () => {
          planRefused.current.set(p.room, Date.now() + PLAN_REFUSED_MS);
          updatePlus(p.room, (r) => ({ ...r, caps: null, approvals: [] }));
        },
        onPayload: (payload, ch, sealed) => {
          if (ch !== "status") return onPlusPayload(p, payload, ch);
          if (applyRekey(p, payload, !!sealed)) return;
          // My pet's file, sealed to this phone alone (never part of a snapshot).
          if ((payload as { kind?: unknown } | null)?.kind === "pet") {
            if (sealed) void acceptPetFrame(payload);
            return;
          }
          // Replayed (not newer than the last one shown) or from the future: dropped.
          const at = frameAt(payload);
          if (!acceptFrame(p.room, at)) return;
          const snap = parseSnapshot(payload, t);
          if (!snap) return;
          setLastAt(p.room, at!);
          setLive((l) => ({ ...l, [p.room]: { link: l[p.room]?.link ?? "open", snap } }));
          const refused = (planRefused.current.get(p.room) ?? 0) > Date.now();
          const caps = refused ? null : plusCaps(payload);
          updatePlus(p.room, (r) => ({ ...r, caps }));
        },
      });
      map.set(p.room, client);
      client.start();
    }
  }, [pairings, lang, t, onPlusPayload, updatePlus, applyRekey]);

  useEffect(() => {
    const map = clients.current;
    return () => map.forEach((c) => c.stop());
  }, []);


  const decide = async (p: StoredPairing, a: ApprovalView, decision: "allow" | "deny"): Promise<boolean> => {
    const client = clients.current.get(p.room);
    if (!client || !p.phone) return false;
    let wa;
    if (decision === "allow") {
      // The passkey, with the user's biometric or PIN, over this exact request: the computer checks it.
      try {
        wa = await assertPhonePasskey({ rpId: rpIdFor(location.hostname), credId: p.phone.credId, challenge: await allowChallenge(a, p.room) });
      } catch {
        say(t.plus.passkeyCancelled);
        return false;
      }
    }
    const payload = await decisionPayload({ phone: p.phone.id, macKey: p.phone.macKey }, p.room, a, decision, wallClock(), wa);
    if (!payload || !(await client.sendUp("approval", payload))) {
      say(t.plus.replyOffline);
      return false;
    }
    say(t.plus.approvalSent);
    return true;
  };

  // v7: the person typed the computer's code for a change it asks for (or denies it).
  const answerConfirm = async (p: StoredPairing, c: ConfirmView, verdict: "confirm" | "deny", code: string): Promise<boolean> => {
    const client = clients.current.get(p.room);
    if (!client || !p.phone) return false;
    const built = await confirmPayload({ phone: p.phone.id, macKey: p.phone.macKey }, p.room, c, verdict, code, wallClock());
    let wa;
    if (verdict === "confirm") {
      try {
        wa = await assertPhonePasskey({ rpId: rpIdFor(location.hostname), credId: p.phone.credId, challenge: await confirmChallenge(p.room, p.phone.id, c, built.proof) });
      } catch {
        say(t.code.cancelled);
        return false;
      }
    }
    if (!(await client.sendUp("approval", { ...built.payload, ...(wa ? { wa } : {}) }))) {
      say(t.plus.replyOffline);
      return false;
    }
    say(t.code.sent);
    return true;
  };

  const sendReply = async (p: StoredPairing, session: string, text: string): Promise<"ok" | "empty" | "too_long" | "offline" | "cancelled" | "no_token"> => {
    if (!p.phone) return "offline";
    const rt = plus[p.room]?.histories[session]?.rt ?? null;
    const built = await replyPayload({ phone: p.phone.id, macKey: p.phone.macKey }, p.room, session, rt, text, wallClock());
    if ("error" in built) return built.error;
    // The passkey, with the person's biometric or PIN, over this very text: the computer checks it.
    let wa;
    try {
      wa = await assertPhonePasskey({ rpId: rpIdFor(location.hostname), credId: p.phone.credId, challenge: built.challenge });
    } catch {
      return "cancelled";
    }
    const client = clients.current.get(p.room);
    if (!client || !(await client.sendUp("reply", { ...built.payload, wa }))) return "offline";
    const how = sentHowOf(plus[p.room]?.histories[session]);
    updatePlus(p.room, (r) => ({ ...r, lastReply: { ...r.lastReply, [session]: { nonce: built.nonce, at: wallClock(), how } } }));
    return "ok";
  };

  // v6 "Nova tarefa": the computer's answer to one task, waited for (by its nonce).
  const plusRef = useRef(plus);
  useEffect(() => {
    plusRef.current = plus;
  }, [plus]);
  const waitTaskAck = (room: string, nonce: string): Promise<TaskAck | null> =>
    new Promise((resolve) => {
      const end = Date.now() + TASK_ANSWER_MS;
      const look = () => {
        const a = plusRef.current[room]?.taskAcks[nonce];
        if (a) return resolve(a);
        if (Date.now() > end) return resolve(null);
        window.setTimeout(look, 150);
      };
      look();
    });

  const askTaskInfo = (p: StoredPairing) => {
    const client = clients.current.get(p.room);
    if (!client || !p.phone) return;
    void client.sendUp("reply", taskInfoPayload(p.phone.id, wallClock(), lang === "en" ? "en" : "pt"));
  };

  const sendTask = async (p: StoredPairing, tool: string, folder: string, text: string): Promise<TaskSendResult> => {
    if (!p.phone?.credId) return "offline";
    const info = plus[p.room]?.taskInfo ?? null;
    const built = await taskPayload({ phone: p.phone.id, macKey: p.phone.macKey }, p.room, tool, folder, info?.tt ?? null, text, wallClock());
    if ("error" in built) return built.error;
    // The passkey, with the person's biometric or PIN, over the AI, the folder and this very text.
    let wa;
    try {
      wa = await assertPhonePasskey({ rpId: rpIdFor(location.hostname), credId: p.phone.credId, challenge: built.challenge });
    } catch {
      return "cancelled";
    }
    const client = clients.current.get(p.room);
    if (!client || !(await client.sendUp("reply", { ...built.payload, wa }))) return "offline";
    // The token is spent: ask for a fresh one (and the list of tasks) right away.
    window.setTimeout(() => askTaskInfo(p), 600);
    const ack = await waitTaskAck(p.room, built.nonce);
    if (!ack) return "offline";
    if (ack.state === "refused") return { refused: ack.reason };
    if (ack.task) {
      setTaskOpen(false);
      openConversation(ack.task);
    }
    return "ok";
  };

  const stopTask = async (p: StoredPairing, task: string): Promise<boolean> => {
    const client = clients.current.get(p.room);
    if (!client || !p.phone) return false;
    const ok = await client.sendUp("reply", await stopPayload({ phone: p.phone.id, macKey: p.phone.macKey }, p.room, task, wallClock()));
    window.setTimeout(() => askTaskInfo(p), 1500);
    return ok;
  };

  // Push off in the settings: every room drops this phone's subscription, then the browser's goes.
  const disableAlerts = async () => {
    setNotify("busy");
    const sub = subRef.current ?? (await currentSubscription(lang).catch(() => null));
    clients.current.forEach((c) => c.send(unsubFrame(sub)));
    await unsubscribeAll(lang).catch(() => {});
    subRef.current = null;
    setNotify("default");
  };

  const enableAlerts = async () => {
    setNotify("busy");
    try {
      const sub = await subscribe(lang);
      subRef.current = sub;
      clients.current.forEach((c) => c.send(subFrame(sub, lang)));
      setNotify("enabled");
    } catch (e) {
      const denied = e instanceof Error && e.message === "denied";
      setNotify(denied ? (Notification.permission === "denied" ? "denied" : "default") : "default");
      if (!denied) say(t.notify.failed);
    }
  };

  const current = pairings?.find((p) => p.room === selected) ?? pairings?.[0] ?? null;
  const currentLive = current ? live[current.room] : undefined;
  const currentOn = !!(current && plus[current.room]?.caps?.on);
  const currentOpen = currentLive?.link === "open";

  // History on demand: the open conversation asks the computer for that session's last messages
  // (at most 50), and again every couple of minutes while it stays open. Nothing is asked for
  // sessions not opened, and nothing of it is stored on the phone.
  useEffect(() => {
    if (!current || !openSession || !currentOn || !currentOpen || !canSend(current)) return;
    const client = clients.current.get(current.room);
    if (!client) return;
    const ask = () => void client.sendUp("history", openPayload(openSession, Date.now()));
    ask();
    const timer = window.setInterval(ask, REOPEN_MS);
    return () => window.clearInterval(timer);
  }, [current, openSession, currentOn, currentOpen]);

  // --- navigation: bottom tabs, and a conversation as its own screen (the system back closes it) --
  const [tab, setTabState] = useState<AppTab>("now");
  const setTab = useCallback((next: AppTab) => {
    setTabState(next);
    window.scrollTo({ top: 0 });
  }, []);
  // Opened from a notification (sw.js: ?open=approval, or a message when the app was open already):
  // the "Agora" tab (where a fresh start is anyway), where the request or the session is; the
  // address goes back to the app's own.
  useEffect(() => {
    if (openedFor(location.search)) history.replaceState(history.state, "", location.pathname + location.hash);
    const onMessage = (e: MessageEvent) => {
      if ((e.data as { t?: unknown } | null)?.t === "miblo-open") setTab("now");
    };
    navigator.serviceWorker?.addEventListener("message", onMessage);
    return () => navigator.serviceWorker?.removeEventListener("message", onMessage);
  }, [setTab]);
  const openConversation = useCallback((id: string) => {
    history.pushState({ mibloSession: id }, "");
    setOpenSession(id);
  }, []);
  const closeConversation = useCallback(() => {
    if ((history.state as { mibloSession?: string } | null)?.mibloSession) history.back();
    else setOpenSession(null);
  }, []);
  useEffect(() => {
    const pop = () => setOpenSession((history.state as { mibloSession?: string } | null)?.mibloSession ?? null);
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  // Read once on the client (the card itself only renders after hydration, with the platform known).
  const [installDismissed, setInstallDismissed] = useState(() => {
    try {
      return typeof window !== "undefined" && !!localStorage.getItem(INSTALL_DISMISSED_KEY);
    } catch {
      return false;
    }
  });
  const dismissInstall = () => {
    setInstallDismissed(true);
    try {
      localStorage.setItem(INSTALL_DISMISSED_KEY, "1");
    } catch {
      // No storage: hidden for this page only.
    }
  };

  const device = useMemo(() => (platform ? deviceKind(navigator.userAgent, platform.ios, platform.standalone) : null), [platform]);
  const hint = device ? installHint(device, !!installPrompt) : null;
  const install = async () => {
    if (!installPrompt) return;
    await installPrompt.prompt();
    setInstallPrompt(null);
  };

  // What waits for the person, on every computer: approvals first (they expire).
  const all = pairings ?? [];
  const waiting = all.flatMap((p) => {
    const room = plus[p.room];
    if (!room?.caps?.on) return [];
    return room.approvals.filter((a) => a.expires + DONE_LINGER_MS > now).map((a) => ({ p, a, room }));
  });
  const pendingOf = (room: string) => {
    const r = plus[room];
    return r?.caps?.on ? pendingApprovals(r.approvals, r.outcomes, now).length : 0;
  };
  const pendingTotal = all.reduce((n, p) => n + pendingOf(p.room), 0);
  // Nothing of the sessions while the app is locked (PIN), not even a count in the title or icon.
  const badge = lock.k !== "open" ? 0 : all.reduce((n, p) => n + attentionCount(live[p.room]?.snap?.sessions, pendingOf(p.room)), 0);

  // The installed app's icon and the tab title carry the same count.
  useEffect(() => {
    document.title = badge > 0 ? `(${badge}) ${t.appName}` : t.appName;
    const nav = navigator as Navigator & { setAppBadge?: (n: number) => Promise<void>; clearAppBadge?: () => Promise<void> };
    if (badge > 0) void nav.setAppBadge?.(badge).catch(() => {});
    else void nav.clearAppBadge?.().catch(() => {});
  }, [badge, t.appName]);

  const signedIn = join.k === "loading" || join.k === "error" ? null : join.k !== "signedOut";
  const email = join.k === "join" || join.k === "ready" ? join.email : null;
  const links: AccountLinks = {
    signedIn,
    initial: email ? email.trim().charAt(0).toUpperCase() : null,
    account: signedIn ? accountUrl(lang) : `${accountUrl(lang)}?next=${encodeURIComponent(lang === "en" ? "/en/app" : "/app")}`,
    help: href(lang, "docs", lang === "en" ? "phone" : "celular"),
    site: href(lang, "home"),
  };

  const goWaiting = () => {
    if (openSession) closeConversation();
    setTab("now");
  };
  const waitingBanner = pendingTotal > 0 && (
    <button type="button" className={styles.waitingBanner} onClick={goWaiting}>
      <Icon name="alert" size={18} />
      <span className="flex-1 text-left">{t.approvalsWaiting(pendingTotal)}</span>
      <span className="underline underline-offset-2">{t.see}</span>
    </button>
  );

  const toastEl = (
    <div className={styles.toast} role="status" aria-live="polite" data-above={pairings?.length ? (openSession && currentOn ? "composer" : "tabs") : undefined}>
      {toast && <span>{toast}</span>}
    </div>
  );

  if (lock.k !== "open") return <LockScreen lang={lang} lock={lock} />;

  // --- a conversation (Miblo+): its own screen ------------------------------------------------
  const room = current ? plus[current.room] : undefined;
  const caps = room?.caps ?? null;
  const sessionOf = (id: string) => currentLive?.snap?.sessions.find((s) => s.id === id);
  if (current && caps?.on && openSession) {
    const s = sessionOf(openSession);
    const h = room?.histories[openSession];
    const last = room?.lastReply[openSession];
    return (
      <div className={styles.app}>
        <SessionScreen
          t={t}
          lang={lang}
          label={h?.title || s?.label || openSession}
          stateText={s ? [t.state[s.kind], s.activity].filter(Boolean).join(" · ") : null}
          stateKind={s?.kind ?? null}
          history={h}
          harness={h?.harness ?? "claude"}
          block={actBlock(current, caps, passkeys, currentLive?.link)}
          repliesOn={caps.replies}
          historyOn={caps.history}
          online={phoneOnline && currentLive?.link === "open"}
          ack={last ? (room?.acks[last.nonce] ?? null) : null}
          sentAt={last?.at ?? null}
          sentHow={last?.how ?? null}
          now={now}
          banner={waitingBanner}
          task={h?.task ?? null}
          canTask={!!caps.tasks}
          onBack={closeConversation}
          onSend={(text) => sendReply(current, openSession, text)}
          onStop={() => stopTask(current, openSession)}
          onNewTask={() => {
            closeConversation();
            setTab("now");
            setTaskOpen(true);
            askTaskInfo(current);
          }}
        />
        {toastEl}
      </div>
    );
  }

  // --- not connected yet: the account, then waiting for a computer ----------------------------------
  if (pairings === null || !current) {
    return (
      <div className={styles.app}>
        <TopBar t={t} links={links} />
        <main className={styles.content} data-tabs="false">
          {pairings === null ? (
            <p className="py-16 text-center text-ink-2">{t.status.connecting}</p>
          ) : (
            <JoinScreen
              t={t}
              lang={lang}
              join={join}
              legacy={legacy}
              passkeys={passkeys}
              busy={joinBusy}
              note={joinNote}
              links={links}
              onJoin={() => void joinAccount()}
              reuse={joinCard}
              onCheck={() => setJoinTick((n) => n + 1)}
              detail={join.k === "ready" ? waitDetail(join.requests, grantIssue, join.me, now) : null}
              trust={trustCards}
              now={now}
              onAskAgain={async () => {
                if (join.k !== "ready") return;
                const ok = await askAgain(join.csrf, join.me.id);
                say(ok ? t.join.askedAgain : t.join.failed);
                setJoinTick((n) => n + 1);
              }}
            />
          )}
          {hint && hint !== "installed" && !installDismissed && pairings !== null && (
            <section className={styles.installCard} aria-labelledby="install-title">
              <div className="flex items-start justify-between gap-3">
                <h2 id="install-title" className="text-[1.0625rem] font-bold">
                  {t.install.title}
                </h2>
                <button type="button" className={styles.iconButton} onClick={dismissInstall} aria-label={t.install.dismiss}>
                  <Icon name="close" size={20} />
                </button>
              </div>
              <InstallBlock t={t} hint={hint} onInstall={install} />
            </section>
          )}
          <p className={styles.footnote}>{t.pair.privacy}</p>
        </main>
        {toastEl}
      </div>
    );
  }

  // --- paired: three tabs ------------------------------------------------------------------------
  const snap = currentLive?.snap ?? null;
  const status = linkLabel(t, lang, phoneOnline ? currentLive : offlineLive(currentLive), now);
  const stale = !!snap && now - snap.at > STALE_MS;
  const block = actBlock(current, caps, passkeys, currentLive?.link);
  const link = currentLive?.link ?? "connecting";
  // "Ligar de novo" after the computer refused this phone (it revoked it: it never takes the same
  // phone identity again) or deleted its room: a real new pairing. The stale pairing and this
  // phone's identity go (the identity's account entry too when no other computer uses it), and the
  // join card asks to join again; the computer then shows a new code to type here.
  const pairAgain = async () => {
    if (repair === "busy" || isAppLocked()) return;
    setRepair("busy");
    try {
      const room = current.room;
      const others = (pairings ?? []).filter((x) => x.room !== room && x.acct);
      if (join.k === "ready") {
        if (!others.length) await call("/api/phones/revoke", { id: join.me.id }, join.csrf).catch(() => null);
        await deleteIdentity(join.uid);
      }
      await removePairing(room);
      setPairings((cur) => cur?.filter((x) => x.room !== room) ?? cur);
      setSelected((cur) => (cur === room ? (others[0]?.room ?? null) : cur));
      setRepair("idle");
      setJoinTick((n) => n + 1);
    } catch {
      setRepair("failed");
    }
  };

  const picker = all.length > 1 && (
    <nav aria-label={t.computerPicker} className={styles.tabs}>
      {all.map((p) => {
        const n = attentionCount(live[p.room]?.snap?.sessions, pendingOf(p.room));
        return (
          <button key={p.room} type="button" aria-pressed={p.room === current.room} className={styles.tab} onClick={() => setSelected(p.room)}>
            {p.name}
            {n > 0 && <span className={styles.tabBadge}>{n}</span>}
          </button>
        );
      })}
    </nav>
  );

  const phoneOnly = !!device && !device.ios && !device.android;
  const confirmCards = all.flatMap((p) =>
    (plus[p.room]?.confirms ?? [])
      .filter((c) => c.expires + DONE_LINGER_MS > now)
      .map((c) => (
        <ConfirmCard key={c.id} t={t} c={c} where={p.name} now={now} outcome={plus[p.room]?.confirmDone[c.id] ?? null} phoneOnly={phoneOnly}
          onAnswer={(cv, verdict, code) => answerConfirm(p, cv, verdict, code)} />
      )),
  );
  const nowTab = (
    <>
      {picker}
      {confirmCards}
      {join.k === "join" && (
        <div className={styles.joinCard}>
          <p>{t.join.joinBody(join.email)}</p>
          {joinNote && <p role="status" className="font-bold text-amber-ink">{joinNote}</p>}
          {joinCard ?? (
            <button type="button" className="btn btn-primary w-full" onClick={() => void joinAccount()} disabled={joinBusy || passkeys === null} aria-busy={joinBusy} data-testid="join-button">
              {joinBusy ? t.join.joining : t.join.joinButton}
            </button>
          )}
        </div>
      )}
      {trustCards}
      {(status.tone === "bad" || link === "limit") && (
        <Notice
          tone={status.tone === "bad" ? "bad" : "warn"}
          role="alert"
          action={
            link === "refused" || link === "deleted" ? (
              <>
                <button type="button" className="btn btn-primary mt-3 w-full" onClick={() => void pairAgain()} disabled={repair === "busy"} aria-busy={repair === "busy"} data-testid="pair-again">
                  {repair === "busy" ? t.code.repairing : repair === "failed" ? t.code.retry : t.status.pairAgain}
                </button>
                {repair === "failed" && <p role="status" className="mt-2">{t.code.repairFailed}</p>}
              </>
            ) : link === "revoked" ? (
              <Tech t={t} commands={[t.tech.link]} />
            ) : undefined
          }
        >
          <p className="font-bold">{status.text}</p>
        </Notice>
      )}

      {caps?.on && !canSend(current) && (
        <Notice tone="info">
          <p>{t.plus.repair}</p>
          <Tech t={t} commands={[t.tech.link]} />
        </Notice>
      )}
      {caps?.on && block === "notEnrolled" && (
        <Notice tone="info">
          <p>{t.plus.notEnrolled}</p>
          <Tech t={t} commands={[t.tech.link, t.tech.on]} />
        </Notice>
      )}

      {waiting.length > 0 && (
        <section className="mt-5" aria-labelledby="approvals-title">
          <h2 id="approvals-title" className={styles.sectionTitle}>
            {t.plus.approvals}
          </h2>
          <div className="grid gap-3">
            {waiting.map(({ p, a, room: r }) => (
              <ApprovalCard
                key={`${p.room}-${a.id}`}
                t={t}
                a={a}
                now={now}
                sessionLabel={live[p.room]?.snap?.sessions.find((s) => s.id === a.session)?.label ?? a.session}
                where={all.length > 1 ? p.name : undefined}
                outcome={r.outcomes[a.id] ?? null}
                block={actBlock(p, r.caps, passkeys, live[p.room]?.link)}
                onDecide={(x, d) => decide(p, x, d)}
              />
            ))}
          </div>
        </section>
      )}

      <StatusCard t={t} name={current.name} snap={snap} status={status} stale={stale} now={now} lang={lang} onOpen={() => setTab("miblo")} />
      {stale && <p className={styles.hint}>{t.status.staleHint}</p>}

      {snap && (
        <section className={stale ? `mt-6 ${styles.stale}` : "mt-6"} aria-labelledby="sessions-title">
          <h2 id="sessions-title" className={styles.sectionTitle}>
            {t.sessions}
            {snap.sessions.length > 0 && <span className={styles.sectionCount}>{snap.sessions.length + snap.more}</span>}
          </h2>
          {snap.sessions.length === 0 ? (
            <div className={styles.empty}>
              <span className={styles.emptyFace}>
                <CatEyes />
              </span>
              <p className="font-bold">{t.noSessions}</p>
              <p className="text-ink-2">{t.noSessionsHint}</p>
            </div>
          ) : (
            <ul className={styles.sessions}>
              {snap.sessions.map((s) => (
                <SessionRow key={s.id} s={s} t={t} lang={lang} now={now} onOpen={caps?.on ? openConversation : undefined} />
              ))}
            </ul>
          )}
          {snap.more > 0 && <p className="mt-2 text-[0.95rem] text-ink-2">{t.more(snap.more)}</p>}
        </section>
      )}

      {caps?.on && (
        // v6 "Nova tarefa": a new AI run on the computer, from here.
        taskOpen ? (
          <TaskSheet
            t={t}
            info={room?.taskInfo ?? null}
            online={phoneOnline && link === "open"}
            canSign={!block}
            onClose={() => setTaskOpen(false)}
            onSend={(tool, folder, text) => sendTask(current, tool, folder, text)}
            onOpenTask={(id) => openConversation(id)}
          />
        ) : (
          <>
            <button
              type="button"
              className={styles.taskButton}
              data-testid="new-task"
              onClick={() => {
                setTaskOpen(true);
                askTaskInfo(current);
              }}
            >
              <Icon name="spark" size={20} />
              {t.task.newTask}
            </button>
            {room?.taskInfo && room.taskInfo.tasks.length > 0 && (
              <div className="mt-4">
                <TaskList t={t} tasks={room.taskInfo.tasks} onOpen={(id) => openConversation(id)} />
              </div>
            )}
          </>
        )
      )}

      {snap && !caps?.on && (
        <div className="mt-6">
          <Upsell t={t} />
        </div>
      )}
    </>
  );

  const mibloTab = (
    <>
      {picker}
      {snap && snap.miblos.length > 0 ? (
        <MibloHero t={t} miblos={snap.miblos} host={current.name} needs={attentionCount(snap.sessions, 0)} stale={stale} restingFace={<CatEyes />} />
      ) : (
        <>
          <section aria-label={current.name} className={styles.bezel} data-stale={stale ? "true" : undefined}>
            <div className={styles.glass}>
              <p className={styles.host}>{current.name}</p>
              <p className={styles.face}>
                <CatEyes />
                <span className={styles.faceText}>{snap ? t.miblo.none : t.status.connecting}</span>
              </p>
            </div>
          </section>
        </>
      )}
      {snap && (
        <div className={stale ? styles.stale : undefined}>
          <LiveMiblo t={t} snap={snap} lang={lang} />
          {snap.apps.length > 0 && (
            <Group title={t.apps.title} id="apps-title">
              <PhoneApps t={t} apps={snap.apps} />
            </Group>
          )}
        </div>
      )}
      {snap && (
        <div className={stale ? styles.stale : undefined}>
          <Group title={t.limits} id="limits-title">
            {snap.h5 || snap.d7 ? (
              <div className="grid gap-4">
                {snap.h5 && <Meter label={t.h5} limit={snap.h5} t={t} lang={lang} now={now} />}
                {snap.d7 && <Meter label={t.d7} limit={snap.d7} t={t} lang={lang} now={now} />}
              </div>
            ) : (
              <p className="text-ink-2">{t.noLimits}</p>
            )}
          </Group>
          {snap.today && ((snap.today.turns ?? 0) > 0 || (snap.today.work ?? 0) > 0 || (snap.today.usd ?? 0) > 0) && (
            <Group title={t.today} id="today-title">
              <ul className={styles.today}>
                {snap.today.turns !== null && snap.today.turns > 0 && <li>{t.turns(snap.today.turns)}</li>}
                {snap.today.work !== null && snap.today.work > 0 && <li>{t.work(duration(snap.today.work))}</li>}
                {snap.today.usd !== null && snap.today.usd > 0 && <li>{t.cost(money(snap.today.usd, lang))}</li>}
              </ul>
            </Group>
          )}
        </div>
      )}
    </>
  );

  const settingsTab = (
    <>
      <Group title={t.computers} id="computers-title">
        <ul className={styles.rows}>
          {all.map((p) => (
            <ComputerRow
              key={p.room}
              t={t}
              lang={lang}
              p={p}
              live={phoneOnline ? live[p.room] : offlineLive(live[p.room])}
              now={now}
              current={p.room === current.room}
              several={all.length > 1}
              onShow={() => {
                setSelected(p.room);
                setTab("now");
              }}
            />
          ))}
        </ul>
        {/* v6: computers come from the account; another one appears here once it is linked. */}
        <p className="mt-3 text-[0.95rem] text-ink-2">{t.join.waitingBody}</p>
        <a className={`${styles.linkButton} mt-1 inline-flex`} href={accountUrl(lang, "devices")}>
          {t.manageDevices}
        </a>
      </Group>

      <LockSettings lang={lang} lock={lock} />

      <Group title={t.notify.title} id="notify-title">
        <AlertsBlock t={t} state={notify} device={device} hint={hint} ios={!!platform?.ios} onEnable={enableAlerts} onDisable={disableAlerts} onInstall={install} />
      </Group>

      {hint && hint !== "installed" && (
        <Group title={t.install.title} id="install-title">
          <InstallBlock t={t} hint={hint} onInstall={install} />
        </Group>
      )}

      <Group title={t.plus.name} id="plus-title">
        {caps?.on ? (
          <>
            <p className="flex items-center gap-2 font-bold">
              <span className={styles.okDot} aria-hidden="true">
                <Icon name="check" size={14} />
              </span>
              {t.plus.active}
            </p>
            <p className="mt-1 text-ink-2">{t.plus.activeBody}</p>
            <a className={`${styles.linkButton} mt-1 inline-flex`} href={accountUrl(lang, "plus")}>
              {t.plus.manage}
            </a>
          </>
        ) : (
          <>
            <p className="font-bold">{t.plus.upsellTitle}</p>
            <p className="mt-1 text-ink-2">{t.plus.upsellBody}</p>
            <a className="btn btn-ghost mt-3 w-full" href={t.plus.url}>
              {t.plus.upsellCta}
            </a>
          </>
        )}
      </Group>

      <Group title={t.account.title} id="account-title">
        <ul className={styles.linkRows}>
          <li>
            <a href={links.account}>
              <Icon name="user" size={20} />
              <span className="flex-1">{signedIn ? t.account.account : t.account.signIn}</span>
              <Icon name="chevron" size={18} />
            </a>
          </li>
          <li>
            <a href={links.help}>
              <Icon name="bell" size={20} />
              <span className="flex-1">{t.account.help}</span>
              <Icon name="chevron" size={18} />
            </a>
          </li>
          <li>
            <a href={links.site}>
              <PixelCube size={20} />
              <span className="flex-1">{t.account.site}</span>
              <Icon name="chevron" size={18} />
            </a>
          </li>
        </ul>
      </Group>
      <p className={styles.footnote}>{t.pair.privacy}</p>
    </>
  );

  return (
    <div className={styles.app}>
      <TopBar t={t} title={tab === "now" ? undefined : t.tabs[tab]} links={links} />
      {tab !== "now" && waitingBanner && <div className={styles.bannerWrap}>{waitingBanner}</div>}
      <main className={styles.content} data-tabs="true">
        {tab === "now" ? nowTab : tab === "miblo" ? mibloTab : settingsTab}
      </main>
      <TabBar t={t} tab={tab} badge={badge} onTab={setTab} />
      {toastEl}
    </div>
  );
}

const INSTALL_DISMISSED_KEY = "miblo-phone-install-dismissed";

// --- the live dashboard ------------------------------------------------------------------------

type Tone = "ok" | "warn" | "bad" | "idle";

/** The phone has no network: whatever the socket still thinks, the link reads as offline. */
function offlineLive(live: Live | undefined): Live {
  const link = live?.link;
  const final = link === "revoked" || link === "refused" || link === "deleted";
  return { snap: live?.snap ?? null, link: final ? link : "offline" };
}

function linkLabel(t: PhoneStrings, lang: Locale, live: Live | undefined, now: number): { text: string; tone: Tone } {
  const link = live?.link ?? "connecting";
  if (link === "revoked") return { text: t.plus.revoked, tone: "bad" };
  if (link === "refused") return { text: t.status.refused, tone: "bad" };
  if (link === "deleted") return { text: t.status.deleted, tone: "bad" };
  if (link === "limit") return { text: t.status.limit, tone: "warn" };
  // Old data is flagged whatever the connection is doing: the screen must never pass it off as live.
  if (live?.snap && now - live.snap.at > STALE_MS) return { text: t.status.stale(elapsed(now - live.snap.at, lang)), tone: "warn" };
  if (link === "offline") return { text: t.status.offline, tone: "warn" };
  if (link === "retrying") return { text: t.status.retrying, tone: "warn" };
  if (link === "connecting") return { text: t.status.connecting, tone: "idle" };
  if (!live?.snap) return { text: t.status.waiting, tone: "idle" };
  return { text: t.status.live, tone: "ok" };
}

/**
 * The compact card on "Agora": the person's Miblo (or the computer's face when there is none),
 * its state, how many sessions need them, and whether the data is live. Opens "Meu Miblo".
 */
function StatusCard({
  t,
  lang,
  name,
  snap,
  status,
  stale,
  now,
  onOpen,
}: {
  t: PhoneStrings;
  lang: Locale;
  name: string;
  snap: SnapshotView | null;
  status: { text: string; tone: Tone };
  stale: boolean;
  now: number;
  onOpen: () => void;
}) {
  const needs = snap?.sessions.filter((s) => s.kind === "needs").length ?? 0;
  const miblos = snap?.miblos ?? [];
  const m = miblos.length ? miblos[featuredMiblo(miblos)] : null;
  const title = m ? m.name : name;
  const state = m ? (m.online ? (m.screen ? t.miblo.screen[m.screen] : t.miblo.online) : t.miblo.offlineHint) : snap ? t.allCalm : t.status.connecting;
  const time = snap ? new Date(snap.at).toLocaleTimeString(lang === "pt" ? "pt-BR" : "en", { hour: "2-digit", minute: "2-digit" }) : null;
  void now;
  return (
    <button
      type="button"
      className={styles.statusCard}
      data-alert={needs > 0 ? "true" : undefined}
      data-stale={stale ? "true" : undefined}
      onClick={onOpen}
      aria-label={`${t.miblo.open(title)}: ${needs > 0 ? `${needs} ${t.needsYouCount(needs)}` : state}. ${status.tone === "bad" ? "" : status.text}`}
    >
      <span className={styles.statusFace}>
        {m ? (
          <MibloThumb m={m} restingFace={<CatEyes />} />
        ) : (
          <span className={styles.thumb}>
            <span className={styles.thumbScreen}>
              <span className={styles.thumbResting}>
                <CatEyes />
              </span>
            </span>
          </span>
        )}
      </span>
      <span className={styles.statusBody}>
        <span className={styles.statusName}>
          <span className="truncate">{title}</span>
          {m && (
            <span className={styles.mibloOnline} data-online={m.online ? "true" : "false"}>
              <span className={styles.dot} aria-hidden="true" />
              {m.online ? t.miblo.online : t.miblo.offline}
            </span>
          )}
        </span>
        {needs > 0 ? (
          <span className={styles.statusNeeds}>
            <b>{needs}</b> {t.needsYouCount(needs)}
          </span>
        ) : (
          <span className={styles.statusState}>{state}</span>
        )}
        {m && miblos.length > 1 && <span className={styles.statusMore}>{t.miblo.others(miblos.length - 1)}</span>}
        {status.tone !== "bad" && (
          <span className={styles.link} data-tone={status.tone}>
            <span className={styles.dot} aria-hidden="true" />
            <span className="min-w-0">
              {status.text}
              {time && status.tone === "ok" ? ` · ${time}` : ""}
            </span>
          </span>
        )}
      </span>
      <Icon name="chevron" size={20} className={styles.chevron} />
    </button>
  );
}

function SessionRow({ s, t, lang, now, onOpen }: { s: SessionView; t: PhoneStrings; lang: Locale; now: number; onOpen?: (session: string) => void }) {
  const ago = s.since ? agoText(now - s.since, lang, elapsed(now - s.since, lang)) : null;
  const body = (
    <>
      <span className={styles.sessionDot} aria-hidden="true" />
      <span className="min-w-0 flex-1">
        <span className={styles.sessionTop}>
          <span className={styles.sessionName}>{s.label}</span>
          {ago && <span className={styles.elapsed}>{ago}</span>}
        </span>
        <span className={styles.sessionState}>
          <span className={styles.stateWord}>{t.state[s.kind]}</span>
          {s.activity && <span className={styles.activity}>{s.activity}</span>}
        </span>
      </span>
      {onOpen && <Icon name="chevron" size={20} className={styles.chevron} />}
    </>
  );
  return (
    <li className={styles.session} data-kind={s.kind}>
      {onOpen ? (
        <button type="button" className={styles.sessionButton} onClick={() => onOpen(s.id)} aria-label={`${s.label}: ${t.plus.open}`}>
          {body}
        </button>
      ) : (
        <div className={styles.sessionButton}>{body}</div>
      )}
    </li>
  );
}

function Meter({ label, limit, t, lang, now }: { label: string; limit: LimitView; t: PhoneStrings; lang: Locale; now: number }) {
  const tone = limit.pct >= 90 ? "high" : limit.pct >= 70 ? "mid" : "low";
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-bold">{label}</span>
        <span className="font-display text-[1.3125rem] font-semibold tabular-nums">{limit.pct}%</span>
      </div>
      <div
        className={styles.meter}
        data-tone={tone}
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={limit.pct}
      >
        <span style={{ width: `${limit.pct}%` }} />
      </div>
      {limit.reset && limit.reset > now && <p className="mt-1 text-[0.95rem] text-ink-2">{t.resets(resetWhen(limit.reset, lang, now))}</p>}
    </div>
  );
}

// --- settings ------------------------------------------------------------------------------------

function ComputerRow({
  t,
  lang,
  p,
  live,
  now,
  current,
  several,
  onShow,
}: {
  t: PhoneStrings;
  lang: Locale;
  p: StoredPairing;
  live: Live | undefined;
  now: number;
  current: boolean;
  several: boolean;
  onShow: () => void;
}) {
  const status = linkLabel(t, lang, live, now);
  return (
    <li>
      <details className={styles.computer}>
        <summary>
          <span className={styles.computerIcon} aria-hidden="true">
            <Icon name="miblo" size={20} />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate font-bold">{p.name}</span>
            <span className={styles.link} data-tone={status.tone}>
              <span className={styles.dot} aria-hidden="true" />
              <span className="min-w-0 truncate">{status.text}</span>
            </span>
          </span>
          <Icon name="chevron" size={20} className={styles.chevronDown} />
        </summary>
        <div className={styles.computerBody}>
          <p>{p.phone?.credId ? t.computer.approvalsOn : t.computer.approvalsOff}</p>
          {several && (
            <div className="mt-3 flex flex-wrap gap-2">
              {current ? (
                <span className={styles.currentChip}>{t.computer.current}</span>
              ) : (
                <button type="button" className="btn btn-ghost" onClick={onShow}>
                  {t.computer.show}
                </button>
              )}
            </div>
          )}
        </div>
      </details>
    </li>
  );
}

function InstallBlock({ t, hint, onInstall }: { t: PhoneStrings; hint: InstallHint; onInstall: () => void }) {
  if (hint === "installed") return <p className="text-ink-2">{t.install.installed}</p>;
  return (
    <>
      <p className="text-ink-2">{t.install.lead}</p>
      {hint === "prompt" ? (
        <button type="button" className="btn btn-primary mt-3 w-full" onClick={onInstall}>
          <Icon name="download" size={20} />
          {t.install.button}
        </button>
      ) : hint === "ios" ? (
        <Steps items={t.install.ios} first={<Icon name="share" size={18} className={styles.inlineIcon} />} />
      ) : hint === "android" ? (
        <Steps items={t.install.android} />
      ) : (
        <p className="mt-2">{t.install.other}</p>
      )}
    </>
  );
}

function AlertsBlock({
  t,
  state,
  device,
  hint,
  ios,
  onEnable,
  onDisable,
  onInstall,
}: {
  t: PhoneStrings;
  state: NotifyState;
  device: DeviceKind | null;
  hint: InstallHint | null;
  /** An iPhone or iPad: the note on iOS 16.4+ and the Home Screen goes with the switch. */
  ios: boolean;
  onEnable: () => void;
  onDisable: () => void;
  onInstall: () => void;
}) {
  if (state === "unknown") return <p className="text-ink-2">{t.status.connecting}</p>;
  if (state === "unsupported") return <p className="text-ink-2">{t.notify.unsupported}</p>;
  if (state === "ios-install")
    return (
      <>
        <p>{t.notify.iosInstall}</p>
        <InstallBlock t={t} hint={hint ?? "ios"} onInstall={onInstall} />
      </>
    );
  if (state === "denied")
    return (
      <>
        <p className="font-bold text-amber-ink">{t.notify.denied}</p>
        <Steps items={t.notify.deniedHow[device ? notifyHelp(device) : "other"]} />
      </>
    );
  const on = state === "enabled";
  return (
    <>
      <button
        type="button"
        role="switch"
        aria-checked={on}
        className={styles.switchRow}
        onClick={on ? onDisable : onEnable}
        disabled={state === "busy"}
        aria-busy={state === "busy"}
        data-testid="push-switch"
      >
        <span className="min-w-0 flex-1 text-left">
          <span className="block font-bold">{t.notify.switchLabel}</span>
          <span className="block text-[0.9rem] text-ink-2">{on ? t.notify.enabled : t.notify.off}</span>
        </span>
        <span className={styles.switchTrack} data-on={on ? "true" : undefined} aria-hidden="true">
          <span className={styles.switchKnob} />
        </span>
      </button>
      <p className="mt-3 text-[0.95rem] text-ink-2">{t.notify.explain}</p>
      {ios && <p className="mt-2 text-[0.9rem] text-ink-2">{t.notify.iosNote}</p>}
    </>
  );
}

// --- joining through the account (protocol v6) -----------------------------------------------------

/**
 * The first screen: sign in to the Miblo account, pass its second factor, connect this phone, then
 * wait for a computer of the account to accept it. No QR code and no link: the computers seal their
 * keys to this phone through the account.
 */
function JoinScreen({
  t,
  lang,
  join,
  legacy,
  passkeys,
  busy,
  note,
  links,
  onJoin,
  onCheck,
  now,
  onAskAgain,
  trust,
  reuse,
  detail,
}: {
  t: PhoneStrings;
  lang: Locale;
  join: JoinState;
  legacy: boolean;
  passkeys: boolean | null;
  busy: boolean;
  note: string | null;
  links: AccountLinks;
  onJoin: () => void;
  onCheck: () => void;
  trust: React.ReactNode;
  reuse?: React.ReactNode;
  now: number;
  onAskAgain: () => Promise<void>;
  detail: WaitDetail;
}) {
  const waiting = join.k === "ready" ? waitingFor(join.requests, now) : null;
  return (
    <section aria-labelledby="join-title" className="pt-2" data-testid="join-screen" data-state={join.k}>
      <h1 id="join-title" className={styles.pairTitle}>
        {join.k === "ready" ? (waiting?.kind === "pending" || waiting?.kind === "code" ? t.join.allowTitle : t.join.waitingTitle) : join.k === "join" ? t.join.joinTitle : join.k === "mfa" ? t.join.confirmTitle : t.join.title}
      </h1>
      {legacy && join.k !== "ready" && (
        <div className="mt-3">
          <Notice tone="warn" role="status">
            <p>{t.join.legacy}</p>
          </Notice>
        </div>
      )}
      {join.k === "loading" ? (
        <p className="mt-4 text-ink-2">{t.status.connecting}</p>
      ) : join.k === "signedOut" || join.k === "error" ? (
        <>
          <p className="mt-2 text-[1.0625rem] text-ink-2">{t.join.lead}</p>
          <a className="btn btn-primary mt-5 w-full" href={links.account}>
            {t.join.signIn}
          </a>
        </>
      ) : join.k === "mfa" ? (
        <div className={styles.joinCard}>
          <MfaVerify lang={lang} compact onDone={onCheck} />
        </div>
      ) : join.k === "mfaSetup" ? (
        <div className={styles.joinCard}>
          <p>{t.join.mfaSetup}</p>
          <a className="btn btn-primary w-full" href={accountUrl(lang, "security")}>
            {t.join.mfaSetupLink}
          </a>
        </div>
      ) : join.k === "join" ? (
        <div className={styles.joinCard}>
          <p>{t.join.joinBody(join.email)}</p>
          <p className="text-[0.95rem] text-ink-2">{passkeys === false ? t.join.joinNoPasskey : t.join.joinPasskey}</p>
          {note && (
            <p role="status" className="font-bold text-amber-ink">
              {note}
            </p>
          )}
          {reuse ?? (
            <button type="button" className="btn btn-primary w-full" onClick={onJoin} disabled={busy || passkeys === null} aria-busy={busy} data-testid="join-button">
              {busy ? t.join.joining : t.join.joinButton}
            </button>
          )}
        </div>
      ) : (
        <div className={styles.joinCard} data-testid="join-waiting" data-state={waiting?.kind ?? "none"}>
          <p className="text-[0.95rem] text-ink-2">{t.join.signedInAs(join.email)}</p>
          {waiting?.kind === "code" ? (
            <p className="font-bold" role="status">{t.code.help(waiting.device)}</p>
          ) : waiting?.kind === "confirm" ? null : waiting?.kind === "pending" ? (
            <div role="status" aria-live="polite">
              <p className="font-bold">{t.join.allowBody}</p>
              <p className="text-[0.95rem] text-ink-2">{t.join.allowOn(waiting.device, Math.max(1, Math.round((waiting.expiresAt - now) / 60_000)))}</p>
            </div>
          ) : waiting?.kind === "expired" ? (
            <div role="status" aria-live="polite">
              <p className="font-bold">{t.join.expiredOn(waiting.device)}</p>
              <button type="button" className="btn btn-primary mt-3 w-full" onClick={() => void onAskAgain()} data-testid="ask-again">
                {t.join.askAgain}
              </button>
            </div>
          ) : waiting?.kind === "denied" ? (
            <p role="status" className="font-bold text-amber-ink">
              {t.join.deniedOn(waiting.device)}
            </p>
          ) : (
            <p>{t.join.waitingBody}</p>
          )}
          {trust}
          {detail && (
            <p className="text-[0.9rem] text-ink-2" data-testid="join-detail" data-kind={detail.k}>
              {detail.k === "no_answer" ? t.join.detail.no_answer : t.join.detail[detail.k](detail.device)}
            </p>
          )}
          <Tech t={t} commands={waiting?.kind === "pending" ? t.join.allowTech : t.join.waitingTech} />
          <button type="button" className="btn btn-ghost w-full" onClick={onCheck}>
            {t.join.checkNow}
          </button>
        </div>
      )}
      <p className="mt-5 text-center text-[0.95rem] text-ink-2">
        {t.pair.noApp}{" "}
        <a className="font-bold text-blue-ink underline underline-offset-2" href={href(lang, "downloads")}>
          {t.pair.noAppLink}
        </a>
      </p>
    </section>
  );
}

/**
 * The phone's side of letting a computer in (protocol v6 "Verifying a new phone"): the code to
 * type on each computer waiting for the person, with that computer's key fingerprint; a warning
 * when a computer was given another key for this phone; and each new computer that granted this
 * phone after its code was shown, confirmed (or turned down) here before anything of it is used.
 */
function TrustCards({ t, codes, toConfirm, keyMismatch, sasAlert, onAnswer }: { t: PhoneStrings; codes: ShownCode[]; toConfirm: ShownCode[]; keyMismatch: boolean; sasAlert: boolean; onAnswer: (c: ShownCode, yes: boolean) => void }) {
  if (!codes.length && !toConfirm.length && !keyMismatch && !sasAlert) return null;
  return (
    <div className="grid gap-3" data-testid="trust-cards">
      {sasAlert && (
        <Notice tone="bad" role="alert">
          <p data-testid="sas-alert">{t.trust.tooMany}</p>
        </Notice>
      )}
      {keyMismatch && (
        <Notice tone="bad" role="alert">
          <p>{t.trust.mismatch}</p>
        </Notice>
      )}
      {codes
        .filter((c) => !toConfirm.some((x) => x.cpub === c.cpub))
        .map((c) => (
          <section key={c.device} className={styles.joinCard} data-testid="sas-code" aria-label={t.trust.codeTitle(c.name)}>
            <p className="font-bold">{t.trust.codeTitle(c.name)}</p>
            <p className="text-center font-mono text-[2.5rem] font-bold tracking-[0.2em]" data-testid="sas-digits">
              {c.code.slice(0, 3)} {c.code.slice(3)}
            </p>
            <p className="text-[0.95rem] text-ink-2">{t.trust.codeHelp}</p>
            <p className="font-mono text-[0.85rem] text-ink-2">{t.trust.fp(c.fp)}</p>
          </section>
        ))}
      {toConfirm.map((c) => (
        <section key={c.cpub} className={styles.joinCard} data-testid="confirm-computer" role="alert">
          <p className="font-bold">{t.trust.newTitle(c.name)}</p>
          <p>{t.trust.newBody(`${c.code.slice(0, 3)} ${c.code.slice(3)}`)}</p>
          <p className="font-mono text-[0.85rem] text-ink-2">{t.trust.fp(c.fp)}</p>
          <button type="button" className="btn btn-primary w-full" onClick={() => onAnswer(c, true)} data-testid="confirm-computer-yes">
            {t.trust.confirm}
          </button>
          <button type="button" className="btn btn-ghost w-full" onClick={() => onAnswer(c, false)}>
            {t.trust.reject}
          </button>
        </section>
      ))}
    </div>
  );
}
