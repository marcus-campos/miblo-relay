"use client";

// The account page of a self-hosted Miblo relay (/conta, /en/account, /plus/link): first-run
// setup with the operator's setup token, signing in (password + second factor, or a passkey
// alone), linking a computer with the code its terminal shows (`miblo account link`), the linked
// computers and phones, and the account's security (the same Security section as miblo.ai's).
// Every call goes to this server only.
import { useCallback, useEffect, useState } from "react";
import { call, loadMfa, MfaVerify, SecurityPanel, type MfaState } from "@/components/community/security";
import { Toaster, toast } from "@/components/ui/Toast";
import { getAccountAssertion, type AssertionOptions } from "@/lib/webauthn";
import type { Locale } from "@/lib/i18n";
import { accountStrings, type AccountStrings } from "./strings";

type Device = { id: string; name: string; platform: string; created_at: string; last_seen_at: string | null; rooms: number };
type Phone = { id: string; name: string; created_at: string; passkey: boolean; granted_at: string | null; computers: number };
type Pending = { user_code: string; name: string; platform: string; expires_at: string; created_at: string; minutesAgo: number };

const card = "grid content-start gap-3 rounded-2xl border-2 border-line bg-surface p-5 sm:p-6";
const input = "min-h-12 w-full rounded-xl border-2 border-line bg-surface px-4 py-2";
const rowBtn = "btn btn-ghost min-h-11 shrink-0 px-4 py-2 text-sm";

/** Where to go back after signing in: only the phone app's own pages. */
function nextTarget(): string | null {
  try {
    const n = new URLSearchParams(location.search).get("next");
    return n === "/app" || n === "/app/" || n === "/en/app" || n === "/en/app/" ? (n.endsWith("/") ? n : `${n}/`) : null;
  } catch {
    return null;
  }
}

const fmt = (lang: Locale, iso: string | null) => {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(lang === "pt" ? "pt-BR" : "en-GB", { dateStyle: "medium", timeStyle: "short" });
};

export function AccountPage({ lang }: { lang: Locale }) {
  const t = accountStrings(lang);
  const [mfa, setMfa] = useState<MfaState | null>(null);
  const [setup, setSetup] = useState<{ needed: boolean; available: boolean; used?: boolean } | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const [m, s] = await Promise.all([loadMfa(), fetch("/api/setup").then((r) => r.json()).catch(() => null)]);
      if (!alive) return;
      setMfa(m ?? { signedIn: false });
      setSetup(s as { needed: boolean; available: boolean; used?: boolean } | null);
    })();
    return () => {
      alive = false;
    };
  }, [tick]);

  const next = nextTarget();
  let body: React.ReactNode;
  if (!mfa || !setup) body = <div aria-busy="true" className="h-40 animate-pulse rounded-2xl bg-bg-2" />;
  else if (!mfa.signedIn) body = setup.needed ? <SetupForm t={t} lang={lang} available={setup.available} used={!!setup.used} onDone={reload} /> : <SignIn t={t} onDone={reload} />;
  else if (mfa.pending || (mfa.mfa?.enrolled && !mfa.mfa.valid))
    body = (
      <section className={card}>
        <h2 className="t-h3">{t.verifyTitle}</h2>
        <p className="text-ink-2">{t.verifyBody}</p>
        <MfaVerify lang={lang} onDone={reload} />
        <SignOut t={t} />
      </section>
    );
  else if (!mfa.mfa?.enrolled)
    body = (
      <>
        <section className={card} data-testid="factor-needed">
          <h2 className="t-h3">{t.factorTitle}</h2>
          <p>{t.factorBody}</p>
        </section>
        <SecurityPanel lang={lang} />
        <button type="button" className="btn btn-primary justify-self-start" onClick={reload}>
          {t.factorDone}
        </button>
      </>
    );
  else
    body = (
      <>
        {next && (
          <a className="btn btn-primary justify-self-start" href={next}>
            {t.backToApp}
          </a>
        )}
        <LinkComputer t={t} lang={lang} csrf={mfa.csrf ?? ""} onLinked={reload} />
        <Computers t={t} lang={lang} csrf={mfa.csrf ?? ""} tick={tick} />
        <Phones t={t} lang={lang} csrf={mfa.csrf ?? ""} tick={tick} />
        <SecurityPanel lang={lang} />
        <Password t={t} csrf={mfa.csrf ?? ""} />
        <SignOut t={t} />
      </>
    );

  return (
    <div className="mx-auto grid max-w-2xl gap-5 px-4 py-8 sm:py-12">
      <header className="grid gap-1">
        <p className="font-display text-sm uppercase tracking-wider text-ink-2">{t.kicker}</p>
        <h1 className="t-h2">{mfa?.signedIn && mfa.email ? t.titleFor(mfa.email) : t.title}</h1>
        <p className="text-ink-2">
          {t.lead} <a className="link" href={lang === "en" ? "/en/app/" : "/app/"}>{t.openApp}</a>
        </p>
      </header>
      {body}
      <Toaster closeLabel={t.close} />
    </div>
  );
}

function SetupForm({ t, lang, available, used, onDone }: { t: AccountStrings; lang: Locale; available: boolean; used: boolean; onDone: () => void }) {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  if (!available) return <section className={card}><p>{t.setupUnavailable}</p></section>;
  if (used) return <section className={card}><p>{t.errors.setup_token_used}</p></section>;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== again) return setMsg(t.passwordsDiffer);
    setBusy(true);
    setMsg("");
    const r = await call("/api/setup", { token: token.trim(), username: username.trim(), password, lang }, "");
    setBusy(false);
    if (r.status === 200) return onDone();
    setMsg(t.errors[String(r.data.error)] ?? t.failed);
  };
  return (
    <form className={card} onSubmit={submit} data-testid="setup-form">
      <h2 className="t-h3">{t.setupTitle}</h2>
      <p className="text-ink-2">{t.setupBody}</p>
      <label className="grid gap-1 font-bold">
        {t.setupToken}
        <input className={`${input} font-mono`} value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
      </label>
      <label className="grid gap-1 font-bold">
        {t.username}
        <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required maxLength={60} />
      </label>
      <label className="grid gap-1 font-bold">
        {t.password}
        <input className={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required minLength={12} />
      </label>
      <label className="grid gap-1 font-bold">
        {t.passwordAgain}
        <input className={input} type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required minLength={12} />
      </label>
      <p className="text-sm text-ink-2">{t.passwordHint}</p>
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? t.working : t.setupSubmit}
      </button>
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </form>
  );
}

function SignIn({ t, onDone }: { t: AccountStrings; onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    const r = await call("/api/community/auth/password", { username: username.trim(), password }, "");
    setBusy(false);
    if (r.status === 200) return onDone();
    setMsg(t.errors[String(r.data.error)] ?? t.failed);
  };
  const withPasskey = async () => {
    setBusy(true);
    setMsg("");
    try {
      const o = await call("/api/community/auth/passkey/options", {}, "");
      if (o.status !== 200) throw new Error(String(o.data.error ?? "failed"));
      const got = await getAccountAssertion(o.data as unknown as AssertionOptions);
      const v = await call("/api/community/auth/passkey/verify", { wa: got.wa }, "");
      if (v.status !== 200) throw new Error(String(v.data.error ?? "failed"));
      onDone();
    } catch (e) {
      setMsg(t.errors[(e as Error).message] ?? t.passkeyFailed);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className={card} onSubmit={submit} data-testid="signin-form">
      <h2 className="t-h3">{t.signInTitle}</h2>
      <button type="button" className="btn btn-primary" onClick={() => void withPasskey()} disabled={busy}>
        {t.signInPasskey}
      </button>
      <p className="text-center text-sm text-ink-2">{t.or}</p>
      <label className="grid gap-1 font-bold">
        {t.username}
        <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username webauthn" required />
      </label>
      <label className="grid gap-1 font-bold">
        {t.password}
        <input className={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
      </label>
      <button type="submit" className="btn btn-ghost" disabled={busy}>
        {busy ? t.working : t.signIn}
      </button>
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </form>
  );
}

/** The device-code step of `miblo account link`: only a code typed here, never one from a link. */
function LinkComputer({ t, lang, csrf, onLinked }: { t: AccountStrings; lang: Locale; csrf: string; onLinked: () => void }) {
  const [form, setForm] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [fresh, setFresh] = useState<null | (() => void)>(null);
  useEffect(() => {
    void fetch("/api/plus/device/form")
      .then((r) => r.json())
      .then((d: { form?: string }) => setForm(d.form ?? ""))
      .catch(() => {});
  }, []);
  const lookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    const r = await call("/api/plus/device/lookup", { userCode: code, form }, csrf);
    setBusy(false);
    if (r.status === 200) setPending((r.data as { code: Pending }).code);
    else setMsg(r.data.error === "invalid_code" ? t.codeUnknown : (t.errors[String(r.data.error)] ?? t.failed));
  };
  const answer = async (approve: boolean) => {
    if (!pending) return;
    setBusy(true);
    setMsg("");
    const r = await call("/api/plus/device/confirm", { userCode: pending.user_code, approve, form }, csrf);
    setBusy(false);
    if (r.status === 403 && r.data.error === "mfa_fresh_required") return setFresh(() => () => void answer(approve));
    if (r.status === 200) {
      toast(approve ? t.linked(pending.name) : t.refused);
      setPending(null);
      setCode("");
      onLinked();
    } else setMsg(r.data.error === "device_limit" ? t.deviceLimit : (t.errors[String(r.data.error)] ?? t.failed));
  };
  return (
    <section className={card} data-testid="link-computer" id="link">
      <h2 className="t-h3">{t.linkTitle}</h2>
      <p className="text-ink-2">{t.linkBody}</p>
      <p className="rounded-xl border-2 border-amber p-3 text-sm">{t.linkWarning}</p>
      {fresh ? (
        <div className="grid gap-3 rounded-xl border-2 border-amber p-4">
          <p className="font-bold">{t.freshNeeded}</p>
          <MfaVerify
            lang={lang}
            compact
            onDone={() => {
              const f = fresh;
              setFresh(null);
              f();
            }}
          />
        </div>
      ) : pending ? (
        <div className="grid gap-3">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
            <dt className="text-ink-2">{t.computer}</dt>
            <dd className="font-bold">{pending.name}</dd>
            <dt className="text-ink-2">{t.platform}</dt>
            <dd>{pending.platform}</dd>
            <dt className="text-ink-2">{t.asked}</dt>
            <dd>{t.minutesAgo(pending.minutesAgo)}</dd>
          </dl>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void answer(true)}>
              {t.approve}
            </button>
            <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => void answer(false)}>
              {t.refuse}
            </button>
          </div>
        </div>
      ) : (
        <form className="flex flex-wrap gap-2" onSubmit={lookup}>
          <input
            className={`${input} max-w-xs font-mono text-xl uppercase tracking-widest`}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="BCDF-GHJK"
            autoComplete="off"
            aria-label={t.codeLabel}
            maxLength={12}
          />
          <button type="submit" className="btn btn-primary" disabled={busy || !form || code.replace(/[^A-Za-z]/g, "").length !== 8}>
            {t.continue}
          </button>
        </form>
      )}
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </section>
  );
}

function Computers({ t, lang, csrf, tick }: { t: AccountStrings; lang: Locale; csrf: string; tick: number }) {
  const [list, setList] = useState<Device[] | null>(null);
  const [n, setN] = useState(0);
  useEffect(() => {
    void fetch("/api/plus/devices")
      .then((r) => (r.ok ? r.json() : { devices: [] }))
      .then((d: { devices: Device[] }) => setList(d.devices))
      .catch(() => setList([]));
  }, [tick, n]);
  const revoke = async (d: Device) => {
    if (!window.confirm(t.unlinkConfirm(d.name))) return;
    const r = await call("/api/plus/devices/revoke", { deviceId: d.id }, csrf);
    if (r.status === 200) toast(t.unlinked);
    else toast(t.failed, "error");
    setN((x) => x + 1);
  };
  return (
    <section className={card} data-testid="computers">
      <h2 className="t-h3">{t.computersTitle}</h2>
      {list && !list.length && <p className="text-ink-2">{t.noComputers}</p>}
      <ul className="grid gap-2">
        {(list ?? []).map((d) => (
          <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line p-3">
            <span>
              <span className="font-bold">{d.name}</span>
              <span className="block text-sm text-ink-2">
                {d.platform} · {t.since(fmt(lang, d.created_at))}
                {d.last_seen_at ? ` · ${t.seen(fmt(lang, d.last_seen_at))}` : ""}
              </span>
            </span>
            <button type="button" className={rowBtn} onClick={() => void revoke(d)}>
              {t.unlink}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Phones({ t, lang, csrf, tick }: { t: AccountStrings; lang: Locale; csrf: string; tick: number }) {
  const [list, setList] = useState<Phone[] | null>(null);
  const [n, setN] = useState(0);
  useEffect(() => {
    void fetch("/api/phones")
      .then((r) => (r.ok ? r.json() : { phones: [] }))
      .then((d: { phones: Phone[] }) => setList(d.phones))
      .catch(() => setList([]));
  }, [tick, n]);
  const revoke = async (p: Phone) => {
    if (!window.confirm(t.revokePhoneConfirm(p.name))) return;
    const r = await call("/api/phones/revoke", { id: p.id }, csrf);
    if (r.status === 200) toast(t.phoneRevoked);
    else toast(t.failed, "error");
    setN((x) => x + 1);
  };
  return (
    <section className={card} data-testid="phones">
      <h2 className="t-h3">{t.phonesTitle}</h2>
      <p className="text-ink-2">{t.phonesBody}</p>
      {list && !list.length && <p className="text-ink-2">{t.noPhones}</p>}
      <ul className="grid gap-2">
        {(list ?? []).map((p) => (
          <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line p-3">
            <span>
              <span className="font-bold">{p.name}</span>
              <span className="block text-sm text-ink-2">
                {t.since(fmt(lang, p.created_at))} · {p.passkey ? t.withPasskey : t.withoutPasskey} · {t.computersCount(p.computers)}
              </span>
            </span>
            <button type="button" className={rowBtn} onClick={() => void revoke(p)}>
              {t.revoke}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Password({ t, csrf }: { t: AccountStrings; csrf: string }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg("");
    const r = await call("/api/community/account/password", { password }, csrf);
    setBusy(false);
    if (r.status === 200) {
      setPassword("");
      toast(t.passwordChanged);
    } else setMsg(r.data.error === "mfa_fresh_required" ? t.freshNeeded : (t.errors[String(r.data.error)] ?? t.failed));
  };
  return (
    <form className={card} onSubmit={submit}>
      <h2 className="t-h3">{t.passwordTitle}</h2>
      <input className={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={12} aria-label={t.password} />
      <button type="submit" className="btn btn-ghost justify-self-start" disabled={busy || password.length < 12}>
        {t.passwordChange}
      </button>
      <p role="alert" className="text-sm font-bold text-amber-ink empty:hidden">
        {msg}
      </p>
    </form>
  );
}

function SignOut({ t }: { t: AccountStrings }) {
  return (
    <button
      type="button"
      className="link justify-self-start text-sm"
      onClick={() => void call("/api/community/auth/logout", {}, "").then(() => location.reload())}
    >
      {t.signOut}
    </button>
  );
}
