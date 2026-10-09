"use client";

// Miblo+ views of the phone app: the upsell for free users, approval cards and a session's
// conversation with its reply box. Every message, command and title is rendered as React text
// (never as HTML). History is cleaned of hidden characters by plus.ts; an approval shows every
// character, invisible ones as visible escapes, so what the AI wrote can neither inject markup nor
// disguise what would run.
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Locale } from "@/lib/i18n";
import { countdown, toolKind } from "./app-model";
import { CountdownRing, Icon, Tech } from "./AppParts";
import { allowable, inputView, type ApprovalView, type ConfirmView, type HistoryView, type ReplyAck, type ReplyHow, type TaskView, type Visible } from "./plus";
import { offText, replyPlan } from "./reply-model";
import { SessionReplyCard } from "./SessionReplyCard";
import type { RequestRow } from "./account-join";
import { ChatMessages, useScrollAnchor } from "./ChatView";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

export function Upsell({ t }: { t: PhoneStrings }) {
  return (
    <div className={styles.upsell}>
      <span className={styles.plusBadge}>{t.plus.name}</span>
      <p className="mt-2 text-[1.0625rem] font-bold">{t.plus.upsellTitle}</p>
      <p className="mt-1 text-ink-2">{t.plus.upsellBody}</p>
      <a className="btn btn-primary mt-3 w-full" href={t.plus.url}>
        {t.plus.upsellCta}
      </a>
    </div>
  );
}

type Confirm = null | "allow" | "deny";
/** A reply not delivered after this long: the session was probably not opened with the channel. */
const REPLY_STUCK_MS = 20_000;

/** Shown text with its escapes (↵, ⇥, ⟨U+202E⟩) styled apart, so they can never pass for real text. */
function Shown({ v }: { v: Visible }) {
  return (
    <>
      {v.segs.map((s, i) =>
        s.esc ? (
          <span key={i} className={styles.esc}>
            {s.t}
          </span>
        ) : (
          <span key={i}>{s.t}</span>
        ),
      )}
    </>
  );
}

/**
 * Why this phone cannot act on the computer, or null when it can: no passkeys on this device, not
 * enrolled (or enrolled elsewhere), or revoked on the computer.
 */
export type ActBlock = null | "noPasskeys" | "notEnrolled" | "revoked";

/** The computer's deadline as a time of day on this phone ("23:45"). */
function clockTime(ms: number, lang: "pt" | "en"): string {
  return new Date(ms).toLocaleTimeString(lang === "pt" ? "pt-BR" : "en-GB", { hour: "2-digit", minute: "2-digit" });
}

export function ApprovalCard({
  t,
  a,
  now,
  sessionLabel,
  where,
  outcome,
  block,
  onDecide,
}: {
  t: PhoneStrings;
  a: ApprovalView;
  now: number;
  sessionLabel: string;
  /** The computer's name, when the phone follows more than one. */
  where?: string;
  outcome: string | null;
  block: ActBlock;
  onDecide: (a: ApprovalView, decision: "allow" | "deny") => Promise<boolean>;
}) {
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [busy, setBusy] = useState(false);
  // Approve stays off until the end of the request has been on screen (the whole input was seen).
  // (Without IntersectionObserver, an old browser that has no passkeys either, it counts as seen.)
  const [seenEnd, setSeenEnd] = useState(() => typeof IntersectionObserver === "undefined");
  const end = useRef<HTMLDivElement | null>(null);
  const clock = countdown(a, now);
  const left = clock.left;
  const expired = left === 0;
  const title = t.plus.kindTitle[toolKind(a.tool)];
  const view = useMemo(() => (a.full ? inputView(a.tool, a.input) : null), [a.full, a.tool, a.input]);
  const canAllow = allowable(a, view, now) && seenEnd && !block;

  useEffect(() => {
    const el = end.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        setSeenEnd(true);
        io.disconnect();
      }
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const decide = async (decision: "allow" | "deny") => {
    setBusy(true);
    const ok = await onDecide(a, decision);
    setBusy(false);
    if (ok) setConfirm(null);
  };

  return (
    <article className={styles.approval} aria-label={`${title} (${a.tool})`} data-done={outcome ? "true" : undefined}>
      <div className={styles.approvalHead}>
        {outcome ? (
          <span className={styles.ringDone} aria-hidden="true">
            <Icon name="check" size={22} />
          </span>
        ) : (
          <CountdownRing left={left} fraction={clock.fraction} urgent={clock.urgent} label={expired ? t.plus.approvalExpired : t.plus.approvalExpires(left)} />
        )}
        <div className="min-w-0 flex-1">
          <p className={styles.approvalTool}>{title}</p>
          <p className={styles.approvalMeta}>
            <span className={styles.toolChip}>{a.tool}</span>
            <span className="min-w-0 truncate">
              {sessionLabel}
              {where ? ` · ${where}` : ""}
            </span>
          </p>
        </div>
      </div>
      {!expired && !outcome && (
        <p className={styles.approvalWait} data-testid="approval-wait" data-urgent={clock.urgent ? "true" : undefined}>
          {t.plus.approvalWaits(left, clockTime(a.expires, t.lang))}
        </p>
      )}
      {expired && !outcome && <p className={styles.warn}>{t.plus.approvalExpired}</p>}
      {outcome ? null : view ? (
        <>
          {view.path && (
            <div className={styles.field}>
              <p className={styles.fieldKey}>{t.plus.file}</p>
              <p className={styles.path} data-testid="approval-path">
                <Shown v={view.path} />
              </p>
            </div>
          )}
          {view.command && (
            <div className={styles.field}>
              <p className={styles.fieldKey}>{t.plus.command}</p>
              <pre className={styles.code} data-testid="approval-command">
                <Shown v={view.command} />
              </pre>
            </div>
          )}
          {view.diff.map((d, i) => (
            <div key={`d${i}`} className={styles.field}>
              <p className={styles.fieldKey}>
                {t.plus.diff}
                {d.title ? ` ${d.title}` : ""}
              </p>
              <pre className={styles.code} data-testid="approval-diff">
                {d.lines.map((l, j) => (
                  <span key={j} className={styles.diffLine} data-sign={l.sign}>
                    {l.sign} <Shown v={l.text} />
                    {"\n"}
                  </span>
                ))}
              </pre>
            </div>
          ))}
          {view.fields.map((f) => (
            <div key={f.key} className={styles.field}>
              <p className={styles.fieldKey}>{f.key}</p>
              <pre className={styles.code}>
                <Shown v={f.value} />
              </pre>
            </div>
          ))}
          {view.description && (
            <div className={styles.aiNote}>
              <p className={styles.fieldKey}>{t.plus.descriptionByAi}</p>
              <p>
                <Shown v={view.description} />
              </p>
            </div>
          )}
          <p className="mt-2 text-[0.875rem] text-ink-2" data-testid="approval-counts">
            {t.plus.counts(view.lines, view.chars)}
          </p>
          {view.hidden && <p className={styles.warn}>{t.plus.hidden}</p>}
          {view.nonAscii && <p className={styles.warn}>{t.plus.nonAscii}</p>}
          {view.multiline && <p className={styles.warn}>{t.plus.multiline}</p>}
          {view.long && <p className={styles.warn}>{t.plus.long}</p>}
        </>
      ) : (
        <p className={styles.warn}>{t.plus.approvalPartial}</p>
      )}
      <div ref={end} aria-hidden="true" className={styles.endMark} />
      {a.full && !a.verified && !outcome && <p className={styles.warn}>{t.plus.approvalUnverified}</p>}
      {block && !outcome && (
        <>
          <p className={styles.warn}>{t.plus[block]}</p>
          {block !== "noPasskeys" && <Tech t={t} commands={[t.tech.link]} />}
        </>
      )}
      {outcome ? (
        <p className={styles.outcome} role="status">
          {outcome}
        </p>
      ) : confirm ? (
        <div className={styles.actions}>
          <button type="button" className="btn btn-ghost" onClick={() => setConfirm(null)} disabled={busy}>
            {t.plus.cancel}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => decide(confirm)}
            disabled={busy || (confirm === "allow" && !canAllow)}
            aria-busy={busy}
          >
            {confirm === "allow" ? t.plus.confirmApprove : t.plus.confirmDeny}
          </button>
        </div>
      ) : (
        <>
          {!block && allowable(a, view, now) && !seenEnd && <p className="mt-2 text-[0.875rem] text-ink-2">{t.plus.readToEnd}</p>}
          {!block && allowable(a, view, now) && <p className="mt-2 text-[0.875rem] text-ink-2">{t.plus.passkeyNeeded}</p>}
          <div className={styles.actions}>
            {/* Denying needs no passkey, but it is signed by this phone: an unregistered phone cannot. */}
            <button type="button" className="btn btn-ghost" onClick={() => setConfirm("deny")} disabled={block === "notEnrolled" || block === "revoked"}>
              {t.plus.deny}
            </button>
            {/* Approving needs the whole, verified, clean input seen to its end, and this phone's passkey. */}
            {allowable(a, view, now) && !block && (
              <button type="button" className="btn btn-primary" onClick={() => setConfirm("allow")} disabled={!canAllow}>
                {t.plus.approve}
              </button>
            )}
          </div>
        </>
      )}
    </article>
  );
}

/** Why the composer is off here, in one line, with how to turn it on folded away. */
type ComposerOff = { reason: string; commands?: string[]; action?: ReactNode } | null;

/**
 * A session's conversation, full screen: a sticky bar (back, the session's name and state; for a
 * task from the phone, its state and "Parar"), the chat (ChatView.tsx), kept at the newest message
 * with a "↓ novas mensagens" pill when the person scrolled up, and the composer always pinned to the
 * bottom: enabled where replies work, otherwise disabled with one line saying why and how to turn
 * it on.
 */
export function SessionScreen({
  t,
  lang,
  label,
  stateText,
  stateKind,
  history,
  harness,
  block,
  repliesOn,
  historyOn = true,
  online,
  ack,
  sentAt,
  sentHow = null,
  now,
  banner,
  task,
  canTask,
  onBack,
  onSend,
  onStop,
  onNewTask,
}: {
  t: PhoneStrings;
  lang: Locale;
  label: string;
  /** The session's state in words ("Trabalhando"), when the computer listed it. */
  stateText: string | null;
  stateKind: "needs" | "working" | "done" | "idle" | null;
  history: HistoryView | undefined;
  harness: string;
  /** Why this phone cannot send replies (not accepted, revoked, no passkeys), or null. */
  block: ActBlock;
  /** Replies are on for this computer (off by default; turned on in a terminal there). */
  repliesOn: boolean;
  /**
   * The computer sends this conversation (its `history` setting, off too while it waits to be
   * confirmed again): when off, no history ever comes and no reply can be answered.
   */
  historyOn?: boolean;
  online: boolean;
  ack: ReplyAck | null;
  /** When the last reply left the phone (null: none yet). */
  sentAt: number | null;
  /** 1.24: the `replyHow` the history said when that reply was sent. */
  sentHow?: ReplyHow | null;
  now: number;
  /** Approvals waiting elsewhere: a strip under the bar. */
  banner?: ReactNode;
  /** v6: this conversation is a task started from the phone. */
  task?: TaskView | null;
  /** "Nova tarefa" is available on this computer. */
  canTask?: boolean;
  onBack: () => void;
  onSend: (text: string) => Promise<"ok" | "empty" | "too_long" | "offline" | "cancelled" | "no_token">;
  onStop?: () => Promise<boolean>;
  onNewTask?: () => void;
}) {
  const [text, setText] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stopping, setStopping] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);
  const listRef = useRef<HTMLOListElement | null>(null);
  const convo = history?.session ?? label;
  const ids = useMemo(() => [...(history?.msgs ?? []).map((m) => m.id), ...(history?.state === "working" ? ["~working"] : [])], [history]);
  const anchor = useScrollAnchor(ids, listRef, convo);
  const minute = Math.floor(now / 60_000) * 60_000;

  // The box grows with the text, up to about six lines.
  const grow = () => {
    const el = area.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 168)}px`;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const r = await onSend(text);
    setBusy(false);
    if (r === "ok") {
      setText("");
      requestAnimationFrame(grow);
      setNote(t.plus.replySent);
      anchor.jump();
    } else {
      setNote(
        r === "empty"
          ? t.plus.replyEmpty
          : r === "too_long"
            ? t.plus.replyTooLong
            : r === "cancelled"
              ? t.plus.replyCancelled
              : r === "no_token"
                ? t.plus.replyNoToken
                : t.plus.replyOffline,
      );
    }
  };

  // Honest states: "sending" until the computer answers, "sent" once Claude Code got it (not yet
  // in the conversation), "delivered" only when it shows in the session's transcript.
  const ackText = ack ? (ack.state === "delivered" ? t.plus.replyDelivered : ack.state === "refused" ? t.plus.replyRefused : t.plus.replyHanded) : null;
  const stuck = sentAt !== null && ack?.state !== "delivered" && ack?.state !== "refused" && now - sentAt > REPLY_STUCK_MS;
  const isClaude = harness === "claude";
  const tech = t.tech;
  const newTaskButton = canTask && onNewTask ? (
    <button type="button" className={styles.linkButton} onClick={onNewTask}>
      {t.task.newTask}
    </button>
  ) : undefined;
  // 1.24: the computer says how a reply would go in (`replyHow`), for every AI tool and for tasks.
  const plan = history?.replyHow ? replyPlan(history.replyHow, history.state ?? stateKind) : null;
  const blockOff: ComposerOff =
    block === "noPasskeys"
      ? { reason: t.chat.noPasskey }
      : block === "notEnrolled"
        ? { reason: t.chat.notLinked, commands: [tech.link, tech.on] }
        : block === "revoked"
          ? { reason: t.chat.revoked, commands: [tech.link] }
          : null;
  const historyOff: ComposerOff = !historyOn ? { reason: t.plus.historyOff } : null;
  const repliesOff: ComposerOff = !repliesOn ? { reason: t.chat.replyOff, commands: [tech.replies] } : null;
  const planOff: ComposerOff =
    !plan || plan.k === "send"
      ? null
      : plan.why === "off"
        ? { reason: t.chat.replyOff, commands: [tech.replies] }
        : { reason: offText(plan.why, harness, lang), action: plan.why === "unsupported" || plan.why === "idleUnsupported" ? newTaskButton : undefined };
  // Before 1.24 (no `replyHow`): replies only in Claude Code, through its channel, never to a task.
  const v6Off: ComposerOff = task
    ? { reason: t.chat.replyTask, action: newTaskButton }
    : !isClaude
      ? { reason: t.chat.replyOther, action: newTaskButton }
      : (blockOff ?? historyOff ?? repliesOff ?? (history && !history.reply ? { reason: t.chat.replyChannel, commands: [tech.replies, tech.channel] } : null));
  const off: ComposerOff = plan ? (blockOff ?? historyOff ?? repliesOff ?? planOff) : v6Off;
  const taskRunning = task?.state === "running";

  return (
    <div className={styles.sessionScreen}>
      <header className={styles.sessionBar}>
        <div className={styles.sessionBarInner}>
          <button type="button" className={styles.backButton} onClick={onBack}>
            <Icon name="back" />
            <span>{t.plus.back}</span>
          </button>
          <div className="min-w-0 flex-1">
            <h1 className={styles.sessionTitle}>{label}</h1>
            {task ? (
              <p className={styles.sessionSub} data-kind={taskRunning ? "working" : task.state === "done" ? "done" : "needs"}>
                <span className={styles.dot} aria-hidden="true" />
                {[t.task.states[task.state], task.folder, task.reason && !taskRunning ? (t.task.reasons[task.reason] ?? task.reason) : null].filter(Boolean).join(" · ")}
              </p>
            ) : (
              stateText && (
                <p className={styles.sessionSub} data-kind={stateKind ?? undefined}>
                  <span className={styles.dot} aria-hidden="true" />
                  {stateText}
                </p>
              )
            )}
          </div>
          {task && taskRunning && onStop && (
            <button
              type="button"
              className={styles.stopButton}
              disabled={stopping}
              onClick={async () => {
                if (!window.confirm(t.task.stopConfirm)) return;
                setStopping(true);
                await onStop();
                setStopping(false);
              }}
            >
              <Icon name="stop" size={16} />
              {stopping ? t.task.stopping : t.task.stop}
            </button>
          )}
        </div>
        {banner}
      </header>

      <section className={styles.chatBody} aria-label={label}>
        <p className={styles.untrusted}>{t.plus.untrusted}</p>
        {!history ? (
          <p className={styles.chatEmpty} data-testid={!historyOn && block !== "notEnrolled" && block !== "revoked" ? "history-off" : undefined}>
            {block === "notEnrolled" || block === "revoked" ? t.plus.historyBlocked : !historyOn ? t.plus.historyOff : t.plus.loading}
          </p>
        ) : history.msgs.length === 0 && history.state !== "working" ? (
          <p className={styles.chatEmpty}>{t.plus.noHistory}</p>
        ) : (
          <ChatMessages history={history} t={t} lang={lang} now={minute} listRef={listRef} />
        )}
      </section>

      <footer className={styles.composer}>
        {!anchor.pinned && (
          <button type="button" className={styles.jumpPill} onClick={anchor.jump} data-testid="jump-pill">
            <Icon name="down" size={16} />
            {anchor.unseen > 0 ? t.chat.jumpNew(anchor.unseen) : t.chat.jump}
          </button>
        )}
        <div className={styles.composerInner}>
          <form onSubmit={submit} data-off={off ? "true" : undefined}>
            {off ? (
              <div className={styles.composerOff} data-testid="composer-off">
                <p>{off.reason}</p>
                {off.commands && (
                  <details className={styles.howTo}>
                    <summary>{t.chat.disabledHow}</summary>
                    <Tech t={t} commands={off.commands} />
                  </details>
                )}
                {off.action}
              </div>
            ) : plan?.k === "send" ? (
              <SessionReplyCard lang={lang} when={plan.when} ack={ack} sentHow={sentHow} note={note} />
            ) : (
              <>
                {(ackText ?? note) && (
                  <p className={styles.composerStatus} role="status">
                    {ackText ?? note}
                  </p>
                )}
                {stuck && (
                  <div className={styles.composerNote}>
                    <p className="font-bold text-amber-ink">{t.plus.replyStuck}</p>
                    <Tech t={t} commands={[tech.channel]} />
                  </div>
                )}
              </>
            )}
            <div className={styles.composerRow}>
              <label htmlFor="reply" className="sr-only">
                {t.plus.replyLabel}
              </label>
              <textarea
                id="reply"
                ref={area}
                rows={1}
                className={styles.textarea}
                value={text}
                maxLength={4000}
                disabled={!!off}
                onChange={(e) => {
                  setText(e.target.value);
                  grow();
                }}
                placeholder={off ? t.chat.offPlaceholder : t.plus.replyPlaceholder}
                autoComplete="off"
              />
              <button type="submit" className={styles.sendButton} disabled={!!off || !online || busy || !text.trim()} aria-busy={busy} aria-label={t.plus.send}>
                <Icon name="send" />
              </button>
            </div>
            {!off && (
              <p className={styles.composerHint}>
                <span className={styles.betaChip}>beta</span>
                {online ? t.plus.replyPasskey : t.chat.offline}
              </p>
            )}
          </form>
        </div>
      </footer>
    </div>
  );
}

// --- v7: the computer shows the code, this phone types it ------------------------------------------

/** Six digits typed in (spaces and dashes ignored), or null. */
const sixDigits = (v: string) => {
  const d = v.replace(/[\s-]/g, "");
  return /^\d{6}$/.test(d) ? d : null;
};

function CodeInput({ id, value, onChange, label }: { id: string; value: string; onChange: (v: string) => void; label: string }) {
  return (
    <>
      <label htmlFor={id} className="text-[0.95rem] font-bold">
        {label}
      </label>
      <input
        id={id}
        className="input mono mt-1 w-full text-center text-[1.5rem] tracking-[0.3em]"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={7}
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/[^\d ]/g, "").slice(0, 7))}
        data-testid={id}
      />
    </>
  );
}

/**
 * The computers waiting for this phone (v7): each shows a 6-digit code on its screen; the person
 * types it here and confirms with the passkey. A computer holding this phone until a phone it
 * already has confirms it says so.
 */
export function CodeEntry({ t, requests, now, hasPasskey, onSubmit }: {
  t: PhoneStrings;
  requests: RequestRow[];
  now: number;
  hasPasskey: boolean;
  onSubmit: (q: RequestRow, code: string) => Promise<"ok" | "cancelled" | "error" | "gone">;
}) {
  const typed = requests.filter((r) => r.state === "pending" && r.pake && Date.parse(r.expires_at ?? "") > now).slice(0, 3);
  const held = requests.filter((r) => r.state === "confirm" && Date.parse(r.expires_at ?? "") > now).slice(0, 3);
  if (!typed.length && !held.length) return null;
  return (
    <>
      {typed.map((q) => (
        <CodeCard key={`${q.device.id}-${q.pake!.n}`} t={t} q={q} hasPasskey={hasPasskey} onSubmit={onSubmit} />
      ))}
      {held.map((q) => (
        <div key={q.device.id} className={styles.joinCard} role="status" data-testid="code-held">
          <p className="font-bold">{t.code.held(q.device.name)}</p>
        </div>
      ))}
    </>
  );
}

function CodeCard({ t, q, hasPasskey, onSubmit }: { t: PhoneStrings; q: RequestRow; hasPasskey: boolean; onSubmit: (q: RequestRow, code: string) => Promise<"ok" | "cancelled" | "error" | "gone"> }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const wrong = q.pake?.wrong ?? 0;
  const send = async () => {
    const c = sixDigits(code);
    if (!c) return setNote(t.code.invalid);
    setBusy(true);
    setNote(null);
    const r = await onSubmit(q, c);
    setBusy(false);
    setNote(r === "ok" ? t.code.sent : r === "cancelled" ? t.code.cancelled : r === "gone" ? t.code.gone : t.code.failed);
    if (r === "ok") setCode("");
  };
  return (
    <form className={styles.joinCard} data-testid="code-entry" onSubmit={(e) => (e.preventDefault(), void send())}>
      <p className="text-[1.0625rem] font-bold">{t.code.title(q.device.name)}</p>
      <p className="text-[0.95rem] text-ink-2">{t.code.help(q.device.name)}</p>
      <CodeInput id={`code-${q.device.id}`} value={code} onChange={setCode} label={t.code.label} />
      {wrong > 0 && <p className="font-bold text-amber-ink" role="status">{t.code.wrong(Math.max(0, 3 - wrong))}</p>}
      {note && <p role="status" aria-live="polite">{note}</p>}
      <button type="submit" className="btn btn-primary w-full" disabled={busy || !sixDigits(code)} aria-busy={busy} data-testid="code-submit">
        {busy ? t.code.sending : hasPasskey ? t.code.submit : t.code.submitNoPasskey}
      </button>
    </form>
  );
}

/** What a confirmation turns on, in this phone's own words (never text from the computer). */
function confirmLines(t: PhoneStrings, c: ConfirmView): string[] {
  if (c.what.kind === "admit") return [];
  const out = c.what.on.map((id) => t.confirm.on[id] ?? id);
  if (c.what.timeoutS !== null) out.push(t.confirm.timeout(c.what.timeoutS));
  if (c.what.taskMaxMin !== null) out.push(t.confirm.taskMax(c.what.taskMaxMin));
  for (const f of c.what.folders) out.push(t.confirm.folder(f));
  return out;
}

/** A change asked on the computer `where`: the person types the code it shows and approves with the passkey. */
export function ConfirmCard({ t, c, where, now, outcome, phoneOnly, onAnswer }: {
  t: PhoneStrings;
  c: ConfirmView;
  where: string;
  now: number;
  outcome: string | null;
  phoneOnly: boolean;
  onAnswer: (c: ConfirmView, verdict: "confirm" | "deny", code: string) => Promise<boolean>;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const left = Math.max(0, Math.round((c.expires - now) / 1000));
  const answer = async (verdict: "confirm" | "deny") => {
    setBusy(true);
    const ok = await onAnswer(c, verdict, sixDigits(code) ?? "");
    setBusy(false);
    if (ok) setCode("");
  };
  const lines = confirmLines(t, c);
  const admit = c.what.kind === "admit" ? c.what.phone : null;
  return (
    <article className={styles.approval} data-testid="confirm-card" data-done={outcome ? "true" : undefined} aria-label={admit ? t.confirm.admitTitle(where) : t.confirm.title(where)}>
      <p className={styles.approvalTool}>{admit ? t.confirm.admitTitle(where) : t.confirm.title(where)}</p>
      {admit ? (
        <p className="mt-1">{t.confirm.admitBody(admit.name, [admit.model, admit.place].filter(Boolean).join(", "))}</p>
      ) : (
        <ul className="mt-1 list-disc pl-5">
          {lines.map((l) => (
            <li key={l} className="break-words">{l}</li>
          ))}
        </ul>
      )}
      {outcome ? (
        <p className="mt-2 font-bold" role="status">{t.confirm.done[outcome] ?? outcome}</p>
      ) : left === 0 ? (
        <p className="mt-2 font-bold" role="status">{t.confirm.done.expired}</p>
      ) : phoneOnly ? (
        <p className="mt-2 font-bold text-amber-ink">{t.confirm.phoneOnly}</p>
      ) : (
        <div className="mt-2 flex flex-col gap-2">
          <p className="text-[0.95rem] text-ink-2">{t.confirm.help} {t.confirm.expires(left)}</p>
          {c.left < 3 && <p className="font-bold text-amber-ink">{t.code.wrong(c.left)}</p>}
          <CodeInput id={`confirm-${c.id}`} value={code} onChange={setCode} label={t.code.label} />
          <button type="button" className="btn btn-primary w-full" disabled={busy || !sixDigits(code)} aria-busy={busy} onClick={() => void answer("confirm")} data-testid="confirm-approve">
            {busy ? t.code.sending : t.confirm.approve}
          </button>
          <button type="button" className="btn btn-ghost w-full" disabled={busy} onClick={() => void answer("deny")} data-testid="confirm-deny">
            {t.confirm.deny}
          </button>
        </div>
      )}
    </article>
  );
}

/** v7: this phone already has a Miblo passkey: use it (recommended) or make another. Asked once. */
export function ReuseQuestion({ t, busy, onChoose }: { t: PhoneStrings; busy: boolean; onChoose: (choice: "reuse" | "create") => void }) {
  return (
    <div className={styles.joinCard} role="dialog" aria-labelledby="reuse-title" data-testid="reuse-question">
      <p id="reuse-title" className="font-bold">{t.code.reuseTitle}</p>
      <button type="button" className="btn btn-primary w-full" disabled={busy} onClick={() => onChoose("reuse")} data-testid="reuse-yes">
        {t.code.reuseYes}
      </button>
      <button type="button" className="btn btn-ghost w-full" disabled={busy} onClick={() => onChoose("create")} data-testid="reuse-no">
        {t.code.reuseNo}
      </button>
    </div>
  );
}
