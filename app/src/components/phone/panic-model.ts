// The panic button on the phone (plugin lib/plus/panic.js, docs/phone-relay-protocol.md v8): held
// for 2 s, then the person's biometric or PIN (the passkey), then a signed `panic` frame that the
// computer checks exactly like a reply. Once the computer accepts it, the phone shows the bridge off
// and offers no reply, approval or task for that computer until a status from it is newer than the
// panic (the person turned the bridge back on at the computer: a phone cannot).
import { panicChallenge, panicMacText, phoneMac, randomNonce } from "@/lib/relay-crypto";
import type { Signer } from "./plus";

export const HOLD_MS = 2_000;
export const PANIC_ANSWER_MS = 15_000;
const NONCE_RE = /^[A-Za-z0-9_-]{16,43}$/;
const KEY = "miblo-panic:";

/** How far the hold has gone (0..1), from when the finger went down. */
export function holdProgress(startedAt: number | null, now: number, ms = HOLD_MS): number {
  if (startedAt === null || now < startedAt) return 0;
  return Math.min(1, (now - startedAt) / ms);
}

/**
 * The hold: start() when the finger goes down, cancel() when it lets go, tick(now) on a timer. A
 * tick past HOLD_MS fires once (`fire: true`); letting go before that never fires.
 */
export function holdController(ms = HOLD_MS) {
  let startedAt: number | null = null;
  return {
    start(now: number) {
      if (startedAt === null) startedAt = now;
    },
    cancel() {
      startedAt = null;
    },
    tick(now: number): { progress: number; fire: boolean } {
      const progress = holdProgress(startedAt, now, ms);
      if (progress < 1) return { progress, fire: false };
      startedAt = null;
      return { progress: 0, fire: true };
    },
    get holding() {
      return startedAt !== null;
    },
  };
}

/** The panic frame, signed by this phone (MAC), and the challenge its passkey must sign (the caller adds the assertion as `wa`). */
export async function panicPayload(signer: Signer, room: string, now: number): Promise<{ payload: Record<string, unknown>; nonce: string; challenge: Uint8Array<ArrayBuffer> }> {
  const f = { phone: signer.phone, nonce: randomNonce(), ts: now };
  return { payload: { v: 8, kind: "panic", ...f, mac: await phoneMac(signer.macKey, panicMacText(room, f)) }, nonce: f.nonce, challenge: await panicChallenge(room, f) };
}

export type PanicAck = { at: number; state: "accepted" | "done" | "refused"; reason: string; nonce: string | null; by: "phone" | "computer" };

/** The computer's answer (on the reply channel, sealed to this phone): accepted, done, or refused with a reason. */
export function parsePanicAck(payload: unknown): PanicAck | null {
  const p = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as Record<string, unknown>) : null;
  if (!p || p.kind !== "panic_ack" || typeof p.at !== "number" || !Number.isFinite(p.at)) return null;
  if (p.state !== "accepted" && p.state !== "done" && p.state !== "refused") return null;
  return {
    at: p.at,
    state: p.state,
    reason: typeof p.reason === "string" ? p.reason.slice(0, 40) : "",
    nonce: typeof p.nonce === "string" && NONCE_RE.test(p.nonce) ? p.nonce : null,
    by: p.by === "computer" ? "computer" : "phone",
  };
}

export type PanicResult = "ok" | "cancelled" | "offline" | "no_answer" | { refused: string };

/**
 * After the hold: the frame, the passkey over it (the person's biometric or PIN; a cancelled prompt
 * sends nothing), the frame up, and the computer's answer to it.
 */
export async function panicFlow(io: {
  build: () => Promise<{ payload: Record<string, unknown>; nonce: string; challenge: Uint8Array<ArrayBuffer> }>;
  assert: (challenge: Uint8Array<ArrayBuffer>) => Promise<unknown>;
  send: (payload: Record<string, unknown>) => Promise<boolean>;
  answer: (nonce: string) => Promise<PanicAck | null>;
}): Promise<{ result: PanicResult; ack: PanicAck | null }> {
  const built = await io.build();
  let wa: unknown;
  try {
    wa = await io.assert(built.challenge);
  } catch {
    return { result: "cancelled", ack: null };
  }
  if (!wa) return { result: "cancelled", ack: null };
  if (!(await io.send({ ...built.payload, wa }))) return { result: "offline", ack: null };
  const ack = await io.answer(built.nonce);
  if (!ack) return { result: "no_answer", ack: null };
  if (ack.state === "refused") return { result: { refused: ack.reason }, ack };
  return { result: "ok", ack };
}

/** A computer turned off by panic: since `at` (the computer's clock, from its answer). */
export type PanicState = { at: number; by: "phone" | "computer" };

/** The computer is back once a status from it is newer than the panic. */
export const panicCleared = (state: PanicState | null | undefined, statusAt: number | null): boolean => !!state && statusAt !== null && statusAt > state.at;

// Kept per computer (room) so a reload still shows it off. Only the time and who: nothing secret.
export function loadPanic(room: string): PanicState | null {
  try {
    const v = JSON.parse(localStorage.getItem(KEY + room) ?? "null") as unknown;
    if (v && typeof v === "object" && typeof (v as PanicState).at === "number") return { at: (v as PanicState).at, by: (v as PanicState).by === "computer" ? "computer" : "phone" };
  } catch {
    // No storage: in memory only.
  }
  return null;
}
export function savePanic(room: string, state: PanicState | null): void {
  try {
    if (state) localStorage.setItem(KEY + room, JSON.stringify(state));
    else localStorage.removeItem(KEY + room);
  } catch {
    // No storage: in memory only.
  }
}

export type PanicStrings = {
  button: string;
  hold: string;
  holding: string;
  explain: string;
  verifying: string;
  off: string;
  offBody: string;
  offByComputer: string;
  back: string;
  cancelled: string;
  noAnswer: string;
  offline: string;
  refused: (reason: string) => string;
};

const REASONS_PT: Record<string, string> = {
  stale: "o relógio do celular e o do computador não batem, ou o pedido demorou demais",
  bad_mac: "a assinatura do celular não confere",
  unknown_phone: "este celular não está mais liberado neste computador",
  passkey_none: "este celular não tem chave de acesso",
};
const REASONS_EN: Record<string, string> = {
  stale: "the phone's and the computer's clocks disagree, or it took too long",
  bad_mac: "the phone's signature does not match",
  unknown_phone: "this phone is no longer allowed on this computer",
  passkey_none: "this phone has no passkey",
};

export const panicStrings: Record<"pt" | "en", PanicStrings> = {
  pt: {
    button: "Pânico",
    hold: "Segure por 2 s para desligar a ponte",
    holding: "Continue segurando…",
    explain: "Desliga a ponte deste computador e encerra todas as sessões de IA. Só dá para religar no próprio computador.",
    verifying: "Confirme com sua digital, rosto ou PIN…",
    off: "Ponte desligada. Para religar, use o app Miblo no computador.",
    offBody: "Respostas, aprovações e tarefas ficam desligadas até o computador voltar.",
    offByComputer: "A ponte foi desligada no computador. Para religar, use o app Miblo no computador.",
    back: "A ponte foi religada no computador.",
    cancelled: "Pânico cancelado: a confirmação não foi feita.",
    noAnswer: "O computador não respondeu. Se ele estiver ligado, tente de novo.",
    offline: "Sem conexão com o computador agora.",
    refused: (r) => `O computador recusou: ${REASONS_PT[r] ?? (r.startsWith("passkey_") ? "a chave de acesso não confere" : r)}.`,
  },
  en: {
    button: "Panic",
    hold: "Hold for 2 s to turn the bridge off",
    holding: "Keep holding…",
    explain: "Turns this computer's bridge off and ends every AI session. It can only be turned back on at the computer itself.",
    verifying: "Confirm with your fingerprint, face or PIN…",
    off: "Bridge off. To turn it back on, use the Miblo app on the computer.",
    offBody: "Replies, approvals and tasks stay off until the computer is back.",
    offByComputer: "The bridge was turned off at the computer. To turn it back on, use the Miblo app on the computer.",
    back: "The bridge was turned back on at the computer.",
    cancelled: "Panic cancelled: it was not confirmed.",
    noAnswer: "The computer did not answer. If it is on, try again.",
    offline: "No connection to the computer right now.",
    refused: (r) => `The computer refused: ${REASONS_EN[r] ?? (r.startsWith("passkey_") ? "the passkey does not match" : r)}.`,
  },
};
