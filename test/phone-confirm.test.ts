// v7 on the phone (the same code as miblo.ai): a confirmation is shown exactly as the computer sent
// it, so a folder or a phone name with hidden or direction-changing characters is refused.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseConfirm } from "@/components/phone/plus";

const canon = (x: unknown): string => (x === null || typeof x !== "object" ? JSON.stringify(x) : Array.isArray(x) ? `[${x.map(canon).join(",")}]`
  : `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canon((x as Record<string, unknown>)[k])}`).join(",")}}`);
const capOf = (w: unknown) => createHash("sha256").update(canon(w)).digest("base64url");

describe("v7 confirmation on the phone", () => {
  it("refuses what it could not show as sent, even with the right cap", async () => {
    const now = Date.now();
    const ask = (what: unknown) => parseConfirm({ kind: "confirm", id: "I".repeat(22), nonce: "N".repeat(22), what, cap: capOf(what), at: now, expires: now + 60_000 }, now);
    const settings = (folders: string[]) => ({ kind: "settings", on: ["tasks"], timeoutS: null, taskMaxMin: null, folders });
    expect(await ask(settings(["/Users/ana/code"]))).not.toBeNull();
    expect(await ask(settings(["/Users/ana/‮edoc"]))).toBeNull();
    const admit = (name: string) => ({ kind: "admit", phone: { id: "A".repeat(22), name, model: null, place: null } });
    expect(await ask(admit("iPhone da Ana"))).not.toBeNull();
    expect(await ask(admit("iPhone‮ anA ad"))).toBeNull();
  });
});
