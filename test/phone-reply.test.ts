// 1.24 replies on the phone: the history's `replyHow`, the `queued` acknowledgement, what the
// field says before sending and every refusal in plain words (reply-model.ts, reply-strings.ts).
// The same file as miblo-platform web/tests/unit/phone-reply.test.ts without its rendering part
// (the screen imports next/navigation, which only the app build maps here).
import { describe, expect, it } from "vitest";
import { parseHistory, parseReplyAck, plusCaps } from "@/components/phone/plus";
import { phoneStrings } from "@/components/phone/strings";
import { ackLine, offText, reasonText, replyPlan, sentHowOf, whenText } from "@/components/phone/reply-model";
import { replyStrings } from "@/components/phone/reply-strings";

const NONCE = "a".repeat(22);
const history = (extra: Record<string, unknown>) => parseHistory({ v: 6, kind: "history", at: 1, session: "a1b2c3d4", harness: "copilot", title: "x", msgs: [], ...extra });

describe("1.24 replies on the phone", () => {
  it("reads replyHow from the history, and only the values the protocol has", () => {
    expect(history({ reply: true, replyHow: "turn_end" })?.replyHow).toBe("turn_end");
    expect(history({ reply: false, replyHow: "idle_unsupported" })?.replyHow).toBe("idle_unsupported");
    // A computer before 1.24 sends none; an unknown value is treated the same way.
    expect(history({ reply: true })?.replyHow).toBeNull();
    expect(history({ reply: true, replyHow: "reopen" })?.replyHow).toBeNull();
  });

  it("reads the queued acknowledgement and its how", () => {
    expect(parseReplyAck({ kind: "reply_ack", nonce: NONCE, state: "queued", how: "turn_end" })).toEqual({ nonce: NONCE, state: "queued", reason: "", how: "turn_end" });
    expect(parseReplyAck({ kind: "reply_ack", nonce: NONCE, state: "queued", how: "later" })?.how).toBeNull();
    expect(parseReplyAck({ kind: "reply_ack", nonce: NONCE, state: "waiting" })).toBeNull();
  });

  it("says before sending what the reply will do, per session", () => {
    expect(replyPlan("now", "idle")).toEqual({ k: "send", when: "now" });
    expect(replyPlan("turn_end", "working")).toEqual({ k: "send", when: "turnEnd" });
    // Waiting on a permission prompt is still inside the turn.
    expect(replyPlan("turn_end", "needs")).toEqual({ k: "send", when: "turnEnd" });
    // Idle and still turn_end: this tool has no way in while idle, so it waits for the next turn.
    expect(replyPlan("turn_end", "idle")).toEqual({ k: "send", when: "nextTime" });
    expect(replyPlan("turn_end", null)).toEqual({ k: "send", when: "nextTime" });
    expect(whenText("now", "pt")).toBe("Entra agora.");
    expect(whenText("turnEnd", "pt")).toBe("Entra quando a sessão terminar a vez.");
    expect(whenText("nextTime", "pt")).toBe("Esta IA não recebe respostas parada: entra na próxima vez.");
    expect(whenText("turnEnd", "en")).toBe("Goes in when the session finishes its turn.");
  });

  it("turns the field off with the computer's reason, never a dead button", () => {
    expect(replyPlan("idle_unsupported", "idle")).toEqual({ k: "off", why: "idleUnsupported" });
    expect(replyPlan("unknown_mode", "idle")).toEqual({ k: "off", why: "autoMode" });
    expect(replyPlan("permissive_session", "idle")).toEqual({ k: "off", why: "autoMode" });
    expect(replyPlan("old_session", "idle")).toEqual({ k: "off", why: "oldSession" });
    expect(replyPlan("unsupported", "idle")).toEqual({ k: "off", why: "unsupported" });
    expect(replyPlan("off", "idle")).toEqual({ k: "off", why: "off" });
    expect(offText("idleUnsupported", "gemini", "pt")).toBe("Sessão parada: o Gemini CLI não aceita mensagens de fora enquanto está parado.");
    expect(offText("idleUnsupported", "copilot", "en")).toBe("Idle: Copilot CLI cannot take outside messages while idle.");
    expect(offText("oldSession", "claude", "pt")).toBe("Respostas valem para sessões abertas depois da atualização.");
    expect(offText("autoMode", "claude", "en")).toBe("This session runs in auto mode; replies only go to sessions that ask first.");
  });

  it("after sending: queued, sent, delivered with how it went in, refused in plain words", () => {
    const ack = (state: "queued" | "sent" | "delivered" | "refused", reason = "", how: "now" | "turn_end" | null = null) => ({ nonce: NONCE, state, reason, how });
    expect(ackLine(ack("queued", "", "turn_end"), "turn_end", "pt")).toEqual({ text: "Na fila: entra quando a sessão terminar a vez.", kind: "wait" });
    expect(ackLine(ack("sent"), "now", "pt")).toEqual({ text: "Enviada.", kind: "wait" });
    expect(ackLine(ack("delivered"), "now", "pt").text).toBe("Entregue: entrou na hora.");
    expect(ackLine(ack("delivered"), "turn_end", "pt").text).toBe("Entregue: entrou no fim da vez.");
    expect(ackLine(ack("delivered"), null, "en").text).toBe("Delivered.");
    expect(ackLine(ack("refused", "session_ended"), "turn_end", "pt")).toEqual({ text: "Não entregue: a sessão terminou antes de pegar a resposta.", kind: "bad" });
    expect(ackLine(ack("refused", "expired"), "turn_end", "en").text).toBe("Not delivered: it waited an hour and the session never took it.");
  });

  it("remembers how a reply went out only when it is sure", () => {
    expect(sentHowOf({ replyHow: "now", state: "idle" })).toBe("now");
    expect(sentHowOf({ replyHow: "turn_end", state: "working" })).toBe("turn_end");
    // Idle, no idle path: the next turn, or the desktop app types it at once. Nothing claimed.
    expect(sentHowOf({ replyHow: "turn_end", state: "idle" })).toBeNull();
    expect(sentHowOf({ replyHow: null, state: "idle" })).toBeNull();
    expect(sentHowOf(undefined)).toBeNull();
  });

  it("has words for every refusal the 1.24 computer sends, in both languages", () => {
    const reasons = ["unsupported", "idle_unsupported", "old_session", "expired", "session_ended", "deliver_failed", "busy", "rate_limited", "folder_changed", "unknown_tool", "stopped", "unknown_mode", "permissive_session", "off", "too_long", "stale", "bad_token", "unknown_session", "no_channel", "not_claude", "unknown_phone", "bad_mac", "malformed"];
    for (const lang of ["pt", "en"] as const) {
      const r = replyStrings(lang);
      for (const reason of reasons) expect(r.reasons[reason], `${lang} ${reason}`).toBeTruthy();
      expect(Object.keys(r.reasons).sort()).toEqual(Object.keys(replyStrings("pt").reasons).sort());
    }
    expect(reasonText("passkey_bad_signature", "pt")).toBe("o computador não aceitou o Face ID, a digital ou o PIN deste celular.");
    // Something newer than this app: said with its code, never hidden.
    expect(reasonText("brand_new", "en")).toBe("the computer refused it (brand_new).");
  });
});

describe("the computer's history off on the phone", () => {
  it("reads history from the status frame: off (or waiting to be confirmed again) is false, unsaid is on", () => {
    expect(plusCaps({ kind: "snapshot", plus: { on: true, history: false } })?.history).toBe(false);
    expect(plusCaps({ kind: "snapshot", plus: { on: true, history: true } })?.history).toBe(true);
    expect(plusCaps({ kind: "snapshot", plus: { on: true } })?.history).toBe(true);
  });

  it("says so in both languages, with how to turn it on", () => {
    expect(phoneStrings("pt").plus.historyOff).toBe("O histórico está desligado no computador. Confirme as configurações no app Miblo (ou: miblo plus set history=on).");
    expect(phoneStrings("en").plus.historyOff).toBe("The history is off on the computer. Confirm the settings in the Miblo app (or: miblo plus set history=on).");
  });
});
