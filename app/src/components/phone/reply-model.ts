// 1.24 replies on the phone, as pure functions (SessionReplyCard.tsx draws them): what a reply to a
// session will do before it is sent (from the history frame's `replyHow` and the session's state),
// and what happened to it after (the computer's `reply_ack`). Nothing here decides anything: the
// computer routes and refuses; the phone only says honestly what it was told.
import type { Locale } from "@/lib/i18n";
import type { ReplyAck, ReplyHow } from "./plus";
import { replyStrings, toolName } from "./reply-strings";

export type SessionState = "working" | "needs" | "idle" | "done" | null;

/** The field is on, and the reply goes in now, at the end of this turn or at the next one. */
export type ReplyPlan = { k: "send"; when: "now" | "turnEnd" | "nextTime" } | { k: "off"; why: "idleUnsupported" | "autoMode" | "oldSession" | "unsupported" | "off" };

/**
 * What a reply would do. `turn_end` while the session works (or waits on a permission prompt, still
 * inside its turn) goes in when that turn ends; `turn_end` while it is idle means the tool has no
 * way to take it now, so it waits for the session's next turn.
 */
export function replyPlan(how: ReplyHow, state: SessionState): ReplyPlan {
  switch (how) {
    case "now":
      return { k: "send", when: "now" };
    case "turn_end":
      return { k: "send", when: state === "working" || state === "needs" ? "turnEnd" : "nextTime" };
    case "idle_unsupported":
      return { k: "off", why: "idleUnsupported" };
    case "unknown_mode":
    case "permissive_session":
      return { k: "off", why: "autoMode" };
    case "old_session":
      return { k: "off", why: "oldSession" };
    case "unsupported":
      return { k: "off", why: "unsupported" };
    default:
      return { k: "off", why: "off" };
  }
}

/** The line under the field before sending ("Entra agora."). */
export function whenText(when: "now" | "turnEnd" | "nextTime", lang: Locale): string {
  const r = replyStrings(lang);
  return when === "now" ? r.whenNow : when === "turnEnd" ? r.whenTurnEnd : r.whenNextTime;
}

/** Why the field is off, for a reason the computer gave in `replyHow` (`off` keeps the app's own text). */
export function offText(why: Exclude<Extract<ReplyPlan, { k: "off" }>["why"], "off">, harness: string, lang: Locale): string {
  const r = replyStrings(lang);
  if (why === "idleUnsupported") return r.idleUnsupported(toolName(harness, lang));
  if (why === "autoMode") return r.autoMode;
  if (why === "oldSession") return r.oldSession;
  return r.unsupported;
}

/** A refusal reason in plain words (any `passkey_*` is the passkey's). */
export function reasonText(reason: string, lang: Locale): string {
  const r = replyStrings(lang);
  const key = reason.startsWith("passkey_") ? "passkey" : reason;
  return r.reasons[key] ?? r.other(reason || "?");
}

/**
 * What to remember of a reply as it leaves, so "Entregue" can say how it went in: `now`, or
 * `turn_end` while the session works. An idle session of a tool with no idle path (`turn_end`
 * while idle) may get it at its next turn or typed by the desktop app at once, so nothing is
 * claimed for it (null: plain "Entregue.").
 */
export function sentHowOf(h: { replyHow: ReplyHow | null; state: SessionState } | undefined): ReplyHow | null {
  if (!h?.replyHow) return null;
  const plan = replyPlan(h.replyHow, h.state);
  return plan.k === "send" && plan.when === "nextTime" ? null : h.replyHow;
}

export type AckLine = { text: string; kind: "wait" | "ok" | "bad" };

/**
 * What happened to the last reply. `sentHow`: the `replyHow` the phone saw when it sent it, so
 * "Entregue" can say whether it went in at once or at the end of the turn.
 */
export function ackLine(ack: ReplyAck, sentHow: ReplyHow | null, lang: Locale): AckLine {
  const r = replyStrings(lang);
  if (ack.state === "queued") return { text: r.queued, kind: "wait" };
  if (ack.state === "sent") return { text: r.sent, kind: "wait" };
  if (ack.state === "refused") return { text: r.refused(reasonText(ack.reason, lang)), kind: "bad" };
  const how = sentHow === "now" || sentHow === "turn_end" ? sentHow : ack.how;
  return { text: how === "now" ? r.deliveredNow : how === "turn_end" ? r.deliveredTurnEnd : r.delivered, kind: "ok" };
}
