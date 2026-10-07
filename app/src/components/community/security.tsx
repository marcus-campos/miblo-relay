"use client";

// The account's second factor in the browser (docs/miblo-plus.md, "Account security"): the step
// after signing in (MfaVerify), the same step inline when a sensitive change needs it fresh, and
// the account's Security section (passkeys, the authenticator app, recovery codes, sign-ins, the
// pairing vault). Every call is a same-origin JSON request with the session's CSRF token; the
// server checks everything again. Secrets (the TOTP key, recovery codes) are shown once and never
// stored here.
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { toast } from "@/components/ui/Toast";
import { securityCopy, type SecurityCopy } from "@/content/security";
import type { Locale } from "@/lib/i18n";
import { qrPath } from "@/lib/qr";
import { rememberPasskey } from "@/lib/passkey-hint";
import { describeAgent } from "@/lib/user-agent";
import { createAccountPasskey, getAccountAssertion, type AssertionOptions, type RegistrationOptions } from "@/lib/webauthn";

type Res = { status: number; data: Record<string, unknown> };

export async function call(path: string, body: unknown, csrf: string, method = "POST"): Promise<Res> {
  try {
    const res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: (await res.json().catch(() => ({}))) as Record<string, unknown> };
  } catch {
    return { status: 0, data: {} };
  }
}

export type MfaState = {
  signedIn: boolean;
  pending?: boolean;
  email?: string;
  csrf?: string;
  factors?: { passkeys: { id: string; name: string; prf: boolean; createdAt: string; lastUsedAt: string | null }[]; totp: boolean; recoveryLeft: number };
  totpAvailable?: boolean;
  required?: boolean;
  mfa?: { enrolled: boolean; method: string | null; valid: boolean; fresh: boolean };
  vault?: { salt: string; creds: string[] } | null;
};

export async function loadMfa(): Promise<MfaState | null> {
  try {
    const res = await fetch("/api/community/mfa", { headers: { Accept: "application/json" } });
    if (!res.ok) return null;
    return (await res.json()) as MfaState;
  } catch {
    return null;
  }
}

/** Passes the second factor with a passkey (optionally evaluating PRF with `prfSalt`). */
export async function passkeyStep(csrf: string, prfSalt?: Uint8Array<ArrayBuffer>, only?: string[]): Promise<{ ok: true; prf: Uint8Array<ArrayBuffer> | null; cred: string } | { ok: false; reason: string }> {
  const o = await call("/api/community/mfa/passkey/options", { purpose: "verify" }, csrf);
  if (o.status !== 200) return { ok: false, reason: String(o.data.error ?? "failed") };
  const opts = o.data as unknown as AssertionOptions;
  if (only) opts.allowCredentials = opts.allowCredentials.filter((c) => only.includes(c));
  let got;
  try {
    got = await getAccountAssertion(opts, prfSalt);
  } catch {
    return { ok: false, reason: "cancelled" };
  }
  const v = await call("/api/community/mfa/passkey/verify", { wa: got.wa }, csrf);
  if (v.status !== 200) return { ok: false, reason: String(v.data.error ?? "failed") };
  rememberPasskey();
  return { ok: true, prf: got.prf, cred: got.wa.cred };
}

const reasonText = (t: SecurityCopy, reason: string) =>
  reason === "locked" ? t.locked : reason === "cancelled" ? t.cancelled : reason === "bad_code" || reason === "replayed_code" ? t.badCode : t.failed;

/** The second-factor step: a passkey, the authenticator app's code or a recovery code. */
export function MfaVerify({ lang, onDone, compact = false }: { lang: Locale; onDone: () => void; compact?: boolean }) {
  const t = securityCopy(lang);
  const [state, setState] = useState<MfaState | null>(null);
  const [mode, setMode] = useState<"choose" | "totp" | "recovery">("choose");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    void loadMfa().then(setState);
  }, []);

  if (!state?.signedIn || !state.csrf) return null;
  const csrf = state.csrf;
  const hasPasskeys = !!state.factors?.passkeys.length;

  const withPasskey = async () => {
    setBusy(true);
    setMsg("");
    const r = await passkeyStep(csrf);
    setBusy(false);
    if (r.ok) onDone();
    else setMsg(reasonText(t, r.reason));
  };
  const withCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    const r = await call(mode === "totp" ? "/api/community/mfa/totp/verify" : "/api/community/mfa/recovery/verify", { code }, csrf);
    setBusy(false);
    if (r.status === 200) onDone();
    else setMsg(reasonText(t, String(r.data.error ?? "")));
  };

  return (
    <div className={compact ? "grid gap-3" : "grid max-w-md gap-4"} data-testid="mfa-verify">
      {mode === "choose" ? (
        <>
          {hasPasskeys && (
            <button type="button" className="btn btn-primary" onClick={withPasskey} disabled={busy}>
              {busy ? t.checking : t.usePasskey}
            </button>
          )}
          {state.factors?.totp && (
            <button type="button" className="btn btn-ghost" onClick={() => setMode("totp")}>
              {t.useTotp}
            </button>
          )}
          <button type="button" className="link text-left text-sm" onClick={() => setMode("recovery")}>
            {t.useRecovery}
          </button>
        </>
      ) : (
        <form onSubmit={withCode} className="grid gap-3">
          <label className="font-bold" htmlFor="mfa-code">
            {mode === "totp" ? t.code : t.recoveryCode}
          </label>
          <input
            id="mfa-code"
            className="min-h-12 w-full rounded-xl border-2 border-line bg-surface px-4 py-2 font-mono"
            inputMode={mode === "totp" ? "numeric" : "text"}
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={busy || !code.trim()}>
            {busy ? t.checking : t.confirm}
          </button>
          {mode === "recovery" && <p className="text-sm text-ink-2">{t.recoveryNote}</p>}
          <button type="button" className="link min-h-11 text-left text-sm" onClick={() => setMode("choose")}>
            ← {t.back}
          </button>
        </form>
      )}
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </div>
  );
}

/**
 * A session approved from another browser re-confirms with a code sent to the account's email
 * before it may change the account's security (then `onDone` retries what was asked).
 */
export function EmailReconfirm({ lang, csrf, onDone }: { lang: Locale; csrf: string; onDone: () => void }) {
  const t = securityCopy(lang);
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const send = async () => {
    setBusy(true);
    setMsg("");
    const r = await call("/api/community/auth/reconfirm/start", {}, csrf);
    setBusy(false);
    if (r.status === 200 && r.data.needed === false) return onDone();
    if (r.status === 202) setSent(true);
    else setMsg(t.error);
  };
  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    const r = await call("/api/community/auth/reconfirm", { code }, csrf);
    setBusy(false);
    if (r.status === 200) {
      setMsg(t.reconfirmDone);
      return onDone();
    }
    setCode("");
    setMsg(r.data.error === "bad_code" ? t.badCode : t.error);
  };
  return (
    <div className="grid gap-3 rounded-xl border-2 border-amber p-4" data-testid="email-reconfirm">
      <p className="font-bold">{t.reconfirmTitle}</p>
      <p className="text-sm text-ink-2">{t.reconfirmBody}</p>
      {sent ? (
        <form onSubmit={confirm} className="grid gap-3">
          <label htmlFor="reconfirm-code" className="font-bold">
            {t.reconfirmCode}
          </label>
          <input
            id="reconfirm-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={7}
            className="min-h-12 w-full rounded-xl border-2 border-line bg-surface px-4 py-2 font-mono text-2xl tracking-widest"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^\d ]/g, ""))}
          />
          <button type="submit" className="btn btn-primary" disabled={busy || code.replace(/\D/g, "").length !== 6}>
            {busy ? t.checking : t.confirm}
          </button>
        </form>
      ) : (
        <button type="button" className="btn btn-primary" onClick={send} disabled={busy}>
          {t.reconfirmSend}
        </button>
      )}
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </div>
  );
}

/** The step page after signing in: passes the second factor, then goes on to `next`. */
export function VerifyStep({ lang, next }: { lang: Locale; next: string }) {
  const router = useRouter();
  return (
    <MfaVerify
      lang={lang}
      onDone={() => {
        router.replace(next);
        router.refresh();
      }}
    />
  );
}

function Qr({ text }: { text: string }) {
  const { size, d } = qrPath(text);
  return (
    <svg viewBox={`0 0 ${size} ${size}`} width={200} height={200} role="img" aria-label="QR" shapeRendering="crispEdges" className="rounded-lg">
      <rect width="100%" height="100%" fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}

const fmtDay = (lang: Locale, iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(lang === "pt" ? "pt-BR" : "en-GB", { day: "numeric", month: "short", year: "numeric" });
};

/** Creates a passkey for the account, named after this browser and system. */
export async function createPasskey(csrf: string, lang: Locale, fallbackName: string): Promise<Res> {
  const o = await call("/api/community/mfa/passkey/options", { purpose: "register" }, csrf);
  if (o.status !== 200) return o;
  let made;
  try {
    made = await createAccountPasskey(o.data as unknown as RegistrationOptions);
  } catch {
    return { status: 400, data: { error: "cancelled" } };
  }
  const name = describeAgent(navigator.userAgent, lang).slice(0, 40) || fallbackName;
  const r = await call("/api/community/mfa/passkey/register", { name, ...made }, csrf);
  if (r.status === 200) rememberPasskey();
  return r;
}

/**
 * Runs account changes that the server may refuse until the second factor is passed again
 * ("mfa_fresh_required") or, for a session approved from another device, until the email is
 * re-confirmed ("email_reconfirm_required"): it shows that step inline (`prompt`), then retries.
 * The server decides; this only makes the step reachable where the person is.
 */
export function useGuarded(lang: Locale, csrf: string | undefined) {
  const t = securityCopy(lang);
  const [fresh, setFresh] = useState<null | (() => Promise<void>)>(null);
  const [reconfirm, setReconfirm] = useState<null | (() => Promise<void>)>(null);
  const box = useRef<HTMLDivElement>(null);

  const run = useCallback(async function guarded(action: () => Promise<Res>, done: (r: Res) => void | Promise<void>): Promise<void> {
    const r = await action();
    if (r.status === 403 && r.data.error === "email_reconfirm_required") {
      setReconfirm(() => async () => {
        setReconfirm(null);
        await guarded(action, done);
      });
      return;
    }
    if (r.status === 403 && r.data.error === "mfa_fresh_required") {
      setFresh(() => async () => {
        setFresh(null);
        await guarded(action, done);
      });
      return;
    }
    await done(r);
  }, []);

  useEffect(() => {
    if (fresh || reconfirm) box.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [fresh, reconfirm]);

  const prompt: ReactNode =
    csrf && (reconfirm || fresh) ? (
      <div ref={box} className="grid gap-3">
        {reconfirm && <EmailReconfirm lang={lang} csrf={csrf} onDone={() => void reconfirm()} />}
        {fresh && (
          <div className="grid gap-3 rounded-xl border-2 border-amber p-4" data-testid="mfa-fresh">
            <p className="font-bold">{t.freshNeeded}</p>
            <MfaVerify lang={lang} compact onDone={() => void fresh()} />
          </div>
        )}
      </div>
    ) : null;
  return { run, prompt, waiting: Boolean(fresh || reconfirm) };
}

type SessionRow = { id: string; userAgent: string; lastSeenAt: string; mfa: boolean; current: boolean };

async function loadSecurity(): Promise<{ mfa: MfaState | null; sessions: SessionRow[] }> {
  const mfa = await loadMfa();
  try {
    const res = await fetch("/api/community/account/sessions");
    return { mfa, sessions: res.ok ? ((await res.json()) as { sessions: SessionRow[] }).sessions : [] };
  } catch {
    return { mfa, sessions: [] };
  }
}

const block = "grid content-start gap-3 rounded-2xl border-2 border-line bg-surface p-5 sm:p-6";
const rowBtn = "btn btn-ghost min-h-11 shrink-0 px-4 py-2 text-sm";

/** The emergency codes, shown once: copy, download, done. */
function CodesShown({ t, codes, onDone }: { t: SecurityCopy; codes: string[]; onDone?: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = codes.join("\n");
  return (
    <div className="grid gap-3 rounded-xl border-2 border-green p-4" data-testid="recovery-shown">
      <p className="font-bold">{t.recoveryShown}</p>
      <ul className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-lg" data-testid="recovery-codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className={rowBtn}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(text);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? t.codesCopied : t.codesCopy}
        </button>
        <a className={rowBtn} download={t.codesFile} href={`data:text/plain;charset=utf-8,${encodeURIComponent(`Miblo\n\n${text}\n`)}`}>
          {t.codesDownload}
        </a>
        {onDone && (
          <button type="button" className="btn btn-primary min-h-11 px-4 py-2 text-sm" onClick={onDone}>
            {t.codesDone}
          </button>
        )}
      </div>
    </div>
  );
}

/** The account's Security section: one recommended action first, then each part in plain words. */
export function SecurityPanel({ lang }: { lang: Locale }) {
  const t = securityCopy(lang);
  const [state, setState] = useState<MfaState | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [busy, setBusy] = useState("");
  const [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [newId, setNewId] = useState<string | null>(null);
  const [justProtected, setJustProtected] = useState(false);
  const [canPasskey, setCanPasskey] = useState(true);
  const { run, prompt } = useGuarded(lang, state?.csrf);

  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);
  useEffect(() => {
    let alive = true;
    void loadSecurity().then((x) => {
      if (!alive) return;
      setState(x.mfa);
      setSessions(x.sessions);
    });
    return () => {
      alive = false;
    };
  }, [tick]);
  useEffect(() => {
    queueMicrotask(() => setCanPasskey(typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined"));
  }, []);

  if (!state) return <div aria-busy="true" className="h-40 animate-pulse rounded-2xl bg-bg-2" data-testid="security-loading" />;
  if (!state.signedIn || !state.csrf) return null;
  const csrf = state.csrf;
  const passkeys = state.factors?.passkeys ?? [];
  const enrolled = Boolean(state.mfa?.enrolled || passkeys.length || state.factors?.totp);

  /** Runs `action` (guarded), then shows `ok` or the error and reloads. */
  const act = async (key: string, action: () => Promise<Res>, ok: string | null, then?: (r: Res) => void) => {
    setBusy(key);
    await run(action, async (r) => {
      if (r.status >= 200 && r.status < 300) {
        if (ok) toast(ok);
        then?.(r);
      } else if (r.data.error !== "cancelled") {
        toast(r.data.error === "last_factor" ? t.removeLast : t.error, "error");
      }
      reload();
    });
    setBusy("");
  };

  const addPasskey = () =>
    act("passkey", () => createPasskey(csrf, lang, t.passkeyDefault), t.passkeyAdded, (r) => {
      if (typeof r.data.id === "string") setNewId(r.data.id);
      if (!enrolled) setJustProtected(true);
    });
  const generateCodes = () =>
    act("codes", () => call("/api/community/mfa/recovery/generate", {}, csrf), null, (r) => setCodes(r.data.codes as string[]));

  return (
    <section className="grid gap-6" aria-label={t.title} data-testid="security-panel">
      {prompt}

      {!enrolled ? (
        <div className="grid gap-3 rounded-2xl border-2 border-amber bg-surface p-5 sm:p-6" data-testid="security-recommended">
          <span className="justify-self-start rounded-full bg-[color-mix(in_oklab,var(--amber)_22%,transparent)] px-3 py-1 text-sm font-bold text-amber-ink">{t.recommended}</span>
          <h2 className="t-h3">{t.statusWeak}</h2>
          <p className="text-ink-2">{t.statusWeakBody}</p>
          {canPasskey ? (
            <button type="button" className="btn btn-primary justify-self-start" onClick={() => void addPasskey()} disabled={busy !== ""}>
              {busy === "passkey" ? t.protectBusy : t.protectNow}
            </button>
          ) : (
            <p className="font-bold">{t.noWebauthn}</p>
          )}
        </div>
      ) : justProtected && !codes ? (
        <div className="grid gap-3 rounded-2xl border-2 border-green bg-surface p-5 sm:p-6" data-testid="security-next-codes">
          <p className="font-bold text-green-ink">✓ {t.passkeyAdded}</p>
          <h2 className="t-h3">{t.nextCodesTitle}</h2>
          <p className="text-ink-2">{t.nextCodesBody}</p>
          <button type="button" className="btn btn-primary justify-self-start" onClick={() => void generateCodes()} disabled={busy !== ""}>
            {t.nextCodesButton}
          </button>
        </div>
      ) : (
        <div className="flex items-start gap-4 rounded-2xl border-2 border-green bg-surface p-5 sm:p-6" data-testid="security-ok">
          <span aria-hidden="true" className="grid size-10 shrink-0 place-items-center rounded-full bg-green text-lg font-bold text-[#0b2a17]">
            ✓
          </span>
          <div>
            <h2 className="t-h3">{t.statusOk}</h2>
            <p className="mt-1 text-ink-2">{t.statusOkBody}</p>
          </div>
        </div>
      )}

      {codes && <CodesShown t={t} codes={codes} onDone={() => { setCodes(null); setJustProtected(false); }} />}

      <div className={block}>
        <h2 className="t-h3">{t.passkeys}</h2>
        <p className="text-ink-2">{t.passkeysHint}</p>
        {passkeys.length ? (
          <ul className="divide-y divide-line border-y border-line">
            {passkeys.map((p) => (
              <li key={p.id} className={`flex flex-wrap items-center justify-between gap-3 py-3 ${p.id === newId ? "-mx-2 rounded-lg bg-[color-mix(in_oklab,var(--green)_14%,transparent)] px-2" : ""}`}>
                <div className="min-w-0">
                  <p className="break-words font-bold">
                    {p.name}
                    {p.id === newId && <span className="ml-2 inline-block whitespace-nowrap rounded-full bg-green px-2 py-0.5 text-xs text-[#0b2a17]">{t.passkeyNew}</span>}
                  </p>
                  <p className="text-sm text-ink-2">
                    {t.passkeyCreated(fmtDay(lang, p.createdAt))} · {p.prf ? t.prfYes : t.prfNo}
                  </p>
                </div>
                <button
                  type="button"
                  className={rowBtn}
                  disabled={busy !== ""}
                  onClick={() => {
                    if (window.confirm(t.removeConfirm(p.name))) void act(`rm-${p.id}`, () => call("/api/community/mfa/passkey/remove", { id: p.id }, csrf), t.removed);
                  }}
                >
                  {t.remove}
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-ink-2">{t.noPasskeys}</p>
        )}
        {enrolled && canPasskey && (
          <button type="button" className="btn btn-ghost justify-self-start" onClick={() => void addPasskey()} disabled={busy !== ""}>
            {busy === "passkey" ? t.protectBusy : passkeys.length ? t.addAnother : t.addPasskey}
          </button>
        )}
      </div>

      {enrolled && !(justProtected && !codes) && (
        <div className={block}>
          <h2 className="t-h3">{t.recovery}</h2>
          <p className="text-ink-2">{t.recoveryHint}</p>
          <p className="font-bold">{state.factors?.recoveryLeft ? t.recoveryLeft(state.factors.recoveryLeft) : t.recoveryNone}</p>
          <button type="button" className="btn btn-ghost justify-self-start" onClick={() => void generateCodes()} disabled={busy !== ""}>
            {t.recoveryGenerate}
          </button>
        </div>
      )}

      <div className={block}>
        <h2 className="t-h3">{t.sessions}</h2>
        <p className="text-ink-2">{t.sessionsHint}</p>
        <ul className="divide-y divide-line border-y border-line">
          {sessions.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="break-words font-bold">
                  {describeAgent(s.userAgent, lang) || t.unknownDevice}
                  {s.current && <span className="ml-2 inline-block whitespace-nowrap rounded-full bg-bg-2 px-2 py-0.5 align-middle text-xs">{t.thisOne}</span>}
                </p>
                <p className="text-sm text-ink-2">
                  {t.lastSeen(fmtDay(lang, s.lastSeenAt))} · {s.mfa ? t.verified : t.notVerified}
                </p>
              </div>
              {!s.current && (
                <button type="button" className={rowBtn} disabled={busy !== ""} onClick={() => void act(`rv-${s.id}`, () => call("/api/community/account/sessions/revoke", { id: s.id }, csrf), t.revoked)}>
                  {t.revoke}
                </button>
              )}
            </li>
          ))}
        </ul>
        {sessions.length > 1 && (
          <button type="button" className="btn btn-ghost justify-self-start" disabled={busy !== ""} onClick={() => void act("rv-all", () => call("/api/community/account/sessions", {}, csrf), t.revokedOthers)}>
            {t.revokeOthers}
          </button>
        )}
      </div>

      <details className="group rounded-2xl border-2 border-line bg-surface" open={!canPasskey || Boolean(totp) || undefined}>
        <summary className="flex min-h-14 cursor-pointer list-none items-center justify-between gap-3 px-5 py-3 sm:px-6 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="block font-bold">{t.more}</span>
            <span className="block text-sm text-ink-2">{t.moreHint}</span>
          </span>
          <span aria-hidden="true" className="text-xl transition-transform group-open:rotate-180">
            ⌄
          </span>
        </summary>
        <div className="grid gap-8 border-t-2 border-line px-5 py-5 sm:px-6">
          <div className="grid gap-2">
            <h3 className="font-bold">{t.totp}</h3>
            <p className="text-sm text-ink-2">{t.totpHint}</p>
            {state.factors?.totp ? (
              <p className="flex flex-wrap items-center gap-3">
                <span className="font-bold text-green-ink">✓ {t.totpOn}</span>
                <button type="button" className={rowBtn} disabled={busy !== ""} onClick={() => void act("totp-rm", () => call("/api/community/mfa/totp/remove", {}, csrf), t.removed)}>
                  {t.remove}
                </button>
              </p>
            ) : !state.totpAvailable ? (
              <p className="text-ink-2">{t.totpUnavailable}</p>
            ) : totp ? (
              <div className="grid max-w-sm gap-3">
                <p>{t.totpScan}</p>
                <Qr text={totp.uri} />
                <p className="break-all font-mono text-sm">
                  {t.totpKey}: {totp.secret}
                </p>
                <label htmlFor="totp-first" className="font-bold">
                  {t.totpConfirm}
                </label>
                <input id="totp-first" inputMode="numeric" autoComplete="one-time-code" className="min-h-12 rounded-xl border-2 border-line bg-surface px-3 font-mono text-xl tracking-widest" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} />
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy !== ""}
                  onClick={() =>
                    void act("totp-ok", () => call("/api/community/mfa/totp/confirm", { code: totpCode }, csrf), t.totpDone, () => {
                      setTotp(null);
                      if (!enrolled) setJustProtected(true);
                    })
                  }
                >
                  {t.confirm}
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn btn-ghost justify-self-start"
                disabled={busy !== ""}
                onClick={() => void act("totp", () => call("/api/community/mfa/totp/setup", {}, csrf), null, (r) => setTotp(r.data as { secret: string; uri: string }))}
              >
                {t.totpSetup}
              </button>
            )}
          </div>
          <div className="grid gap-2">
            <h3 className="font-bold">{t.vault}</h3>
            <p className="text-sm text-ink-2">{t.vaultHint}</p>
            <p>{state.vault ? t.vaultOn : t.vaultOff}</p>
            {state.vault && (
              <button
                type="button"
                className={`${rowBtn} justify-self-start`}
                disabled={busy !== ""}
                onClick={() => {
                  if (window.confirm(t.vaultDeleteConfirm)) void act("vault", () => call("/api/vault", {}, csrf, "DELETE"), t.saved);
                }}
              >
                {t.vaultDelete}
              </button>
            )}
          </div>
        </div>
      </details>

    </section>
  );
}
