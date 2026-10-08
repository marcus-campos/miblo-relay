// Protocol v7 on the phone (the same code as miblo.ai): the code exchange (app/src/lib/pake.ts)
// matches the plugin, byte for byte (shared vector, test/fixtures/plus-v7-vector.json).
import { describe, expect, it } from "vitest";
import v from "./fixtures/plus-v7-vector.json";
import { generator, phoneAnswer, x25519, x25519Big, confOf, pakeChallenge, sidOf } from "@/lib/pake";

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const raw = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const p = v.pake;

describe("v7 code exchange", () => {
  it("matches the plugin's vector: session, generator, shares, tag, confirmation, passkey challenge", async () => {
    expect(sidOf(p)).toBe(p.sid);
    expect(b64(await generator(p.code, p.sid))).toBe(p.generator);
    expect(b64(await x25519(raw(p.a), await generator(p.code, p.sid)))).toBe(p.ya);
    const ans = await phoneAnswer(p.code, p.sid, p.ya, () => raw(p.b));
    expect([ans.yb, ans.tag, ans.isk]).toEqual([p.yb, p.tag, p.isk]);
    expect(await confOf(ans.isk)).toBe(p.conf);
    expect(b64(await pakeChallenge({ ...p, tag: ans.tag }))).toBe(p.challenge);
  });
  it("the BigInt X25519 (browsers without WebCrypto X25519) gives the same results", async () => {
    const g = await generator(p.code, p.sid);
    expect(b64(x25519Big(raw(p.a), g))).toBe(p.ya);
    expect(b64(x25519Big(raw(p.b), raw(p.ya)))).toBe(b64(x25519Big(raw(p.a), raw(p.yb))));
  });
  it("another code, or another view of the keys, gives another tag", async () => {
    const other = await phoneAnswer("048214", p.sid, p.ya, () => raw(p.b));
    expect(other.tag).not.toBe(p.tag);
    const moved = await phoneAnswer(p.code, p.sid.replace("|1|", "|2|"), p.ya, () => raw(p.b));
    expect(moved.tag).not.toBe(p.tag);
  });
});
