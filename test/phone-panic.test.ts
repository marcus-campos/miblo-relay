// The panic button on the phone (panic-model.ts, PanicButton.tsx): the 2 s hold, the frame's MAC
// and passkey challenge exactly as the plugin checks them (vector made by claude_gadget
// plugin/lib/plus/panic.js), the flow after the hold with fakes (passkey, relay, the computer's
// answer), the computer's answers, and the locked state until a newer status arrives.
// The same file as miblo-platform web/tests/unit/phone-panic.test.ts; next/navigation is the app
// build's shim here (app/shims), as the app build maps it.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => import("../app/shims/next-navigation"));
import { b64url, fromB64url, importMacKey, panicChallenge, panicMacText, phoneMac } from "@/lib/relay-crypto";
import { HOLD_MS, holdController, holdProgress, panicCleared, panicFlow, panicPayload, panicStrings, parsePanicAck, type PanicAck } from "@/components/phone/panic-model";
import { PanicButton, PanicOffNotice } from "@/components/phone/PanicButton";

const ROOM = "L1gSdhO9Ek4aT4GMMWUbwT";
const PHONE = "P".repeat(22);
const NONCE = "N".repeat(22);
const TS = 1_790_000_000_000;
// From the plugin: phoneMac(macKey, panicMacText(...)) and panicChallenge(...) for these fields.
const VECTOR = { macKey: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", mac: "6zJM06ZZOdg7H-ivoPpQ_q_5pmIQQ74FJEXsKnDsmLU", challenge: "nyLplGd45IrLFuMRkd0ySHHoTERaHBeI182d4FsNbDk" };

describe("the panic button on the phone", () => {
  it("fires only after a full 2 s hold; letting go early never fires", () => {
    const h = holdController();
    expect(h.tick(0)).toEqual({ progress: 0, fire: false });
    h.start(1000);
    expect(h.holding).toBe(true);
    expect(h.tick(2000).progress).toBeCloseTo(0.5);
    h.cancel();
    expect(h.tick(3100)).toEqual({ progress: 0, fire: false });
    h.start(5000);
    expect(h.tick(5000 + HOLD_MS - 1).fire).toBe(false);
    expect(h.tick(5000 + HOLD_MS)).toEqual({ progress: 0, fire: true });
    // Once: holding on does not fire again.
    expect(h.tick(5000 + HOLD_MS + 500).fire).toBe(false);
    expect(h.holding).toBe(false);
    expect(holdProgress(null, 10)).toBe(0);
    expect(holdProgress(10, 5)).toBe(0);
  });

  it("signs the frame as the plugin checks it (MAC and passkey challenge)", async () => {
    const macKey = await importMacKey(fromB64url(VECTOR.macKey));
    const f = { phone: PHONE, nonce: NONCE, ts: TS };
    expect(panicMacText(ROOM, f)).toBe(`miblo-panic-v8|${ROOM}|${PHONE}|${NONCE}|${TS}`);
    expect(await phoneMac(macKey, panicMacText(ROOM, f))).toBe(VECTOR.mac);
    expect(b64url(await panicChallenge(ROOM, f))).toBe(VECTOR.challenge);
    const built = await panicPayload({ phone: PHONE, macKey }, ROOM, TS);
    expect(built.payload).toMatchObject({ v: 8, kind: "panic", phone: PHONE, ts: TS, nonce: built.nonce });
    expect(built.payload.mac).toBe(await phoneMac(macKey, panicMacText(ROOM, { phone: PHONE, nonce: built.nonce, ts: TS })));
    expect(b64url(built.challenge)).toBe(b64url(await panicChallenge(ROOM, { phone: PHONE, nonce: built.nonce, ts: TS })));
  });

  it("after the hold: the passkey over the frame, then the frame, then the computer's answer", async () => {
    const macKey = await importMacKey(fromB64url(VECTOR.macKey));
    const sent: Record<string, unknown>[] = [];
    const asked: string[] = [];
    const flow = (over: Partial<Parameters<typeof panicFlow>[0]> = {}, answer: PanicAck | null = null) =>
      panicFlow({
        build: () => panicPayload({ phone: PHONE, macKey }, ROOM, TS),
        assert: async (c) => {
          asked.push(b64url(c));
          return { cred: "c", ad: "a", cdj: "d", sig: "s" };
        },
        send: async (p) => (sent.push(p), true),
        answer: async (nonce) => (answer ? { ...answer, nonce } : null),
        ...over,
      });
    const accepted: PanicAck = { at: TS + 5, state: "accepted", reason: "", nonce: null, by: "phone" };
    const ok = await flow({}, accepted);
    expect(ok.result).toBe("ok");
    expect(ok.ack?.at).toBe(TS + 5);
    expect(sent).toHaveLength(1);
    expect(sent[0].wa).toEqual({ cred: "c", ad: "a", cdj: "d", sig: "s" });
    expect(asked[0]).toBe(b64url(await panicChallenge(ROOM, { phone: PHONE, nonce: sent[0].nonce as string, ts: TS })));
    // The person cancelled the biometric or PIN: nothing is sent.
    const cancelled = await flow({ assert: async () => Promise.reject(new Error("NotAllowedError")) }, accepted);
    expect(cancelled.result).toBe("cancelled");
    expect(sent).toHaveLength(1);
    expect((await flow({ send: async () => false }, accepted)).result).toBe("offline");
    expect((await flow({}, null)).result).toBe("no_answer");
    expect((await flow({}, { ...accepted, state: "refused", reason: "stale" })).result).toEqual({ refused: "stale" });
  });

  it("reads the computer's answers defensively", () => {
    expect(parsePanicAck({ v: 8, kind: "panic_ack", at: 5, state: "accepted", nonce: NONCE, by: "phone" })).toEqual({ at: 5, state: "accepted", reason: "", nonce: NONCE, by: "phone" });
    expect(parsePanicAck({ kind: "panic_ack", at: 5, state: "done", by: "computer" })).toEqual({ at: 5, state: "done", reason: "", nonce: null, by: "computer" });
    expect(parsePanicAck({ kind: "panic_ack", at: 5, state: "refused", reason: "passkey_no_uv", nonce: "bad nonce" })?.nonce).toBeNull();
    expect(parsePanicAck({ kind: "panic_ack", at: "5", state: "accepted" })).toBeNull();
    expect(parsePanicAck({ kind: "panic_ack", at: 5, state: "maybe" })).toBeNull();
    expect(parsePanicAck({ kind: "reply_ack", at: 5, state: "accepted" })).toBeNull();
  });

  it("stays off until a status from the computer is newer than the panic", () => {
    const st = { at: TS, by: "phone" as const };
    expect(panicCleared(st, TS - 1)).toBe(false);  // a status from before (the relay keeps the last one)
    expect(panicCleared(st, TS)).toBe(false);
    expect(panicCleared(st, null)).toBe(false);
    expect(panicCleared(st, TS + 1)).toBe(true);   // the bridge was turned back on at the computer
    expect(panicCleared(null, TS + 1)).toBe(false);
  });

  it("says what it does, in Portuguese and English, and what the phone shows once it is off", () => {
    const html = renderToStaticMarkup(createElement(PanicButton, { s: panicStrings.pt, onConfirm: () => {} }));
    expect(html).toContain("Pânico");
    expect(html).toContain("Segure por 2 s");
    expect(html).toContain('data-testid="panic-button"');
    expect(renderToStaticMarkup(createElement(PanicButton, { s: panicStrings.pt, busy: true, onConfirm: () => {} }))).toContain("Confirme com sua digital");
    expect(renderToStaticMarkup(createElement(PanicButton, { s: panicStrings.en, disabled: true, onConfirm: () => {} }))).toContain("disabled");
    expect(panicStrings.pt.off).toBe("Ponte desligada. Para religar, use o app Miblo no computador.");
    const off = renderToStaticMarkup(createElement(PanicOffNotice, { s: panicStrings.pt, state: { at: TS, by: "phone" } }));
    expect(off).toContain('role="alert"');
    expect(off).toContain("Ponte desligada. Para religar, use o app Miblo no computador.");
    expect(off).toContain("Respostas, aprovações e tarefas ficam desligadas");
    expect(renderToStaticMarkup(createElement(PanicOffNotice, { s: panicStrings.pt, state: { at: TS, by: "computer" } }))).toContain("desligada no computador");
    expect(panicStrings.pt.refused("stale")).toContain("relógio");
    expect(panicStrings.en.refused("passkey_bad_signature")).toBe("The computer refused: the passkey does not match.");
  });
});
