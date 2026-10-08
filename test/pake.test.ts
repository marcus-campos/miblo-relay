// Protocol v7 on the phone (the same code as miblo.ai): the code exchange (app/src/lib/pake.ts)
// matches the plugin, byte for byte (shared vector, test/fixtures/plus-v7-vector.json).
import { createCipheriv, createECDH, hkdfSync, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import v from "./fixtures/plus-v7-vector.json";
import { generator, phoneAnswer, x25519, x25519Big, confOf, pakeChallenge, sidOf } from "@/lib/pake";
import { openGrant } from "@/lib/relay-crypto";
import { pinByCode } from "@/components/phone/account-join";
import type { AccountIdentity } from "@/components/phone/store";

// The identity store is IndexedDB (the browser); here only what pinByCode saves is of interest.
const saved: AccountIdentity[] = [];
// account-join.ts reaches the account through the site's helper (Next.js there); not used here.
vi.mock("@/components/community/security", () => ({ call: async () => ({ status: 500, data: {} }) }));
vi.mock("@/components/phone/store", () => ({
  saveIdentity: async (id: AccountIdentity) => {
    saved.push(id);
  },
  listPairings: async () => [],
  savePairingFromGrant: async () => false,
}));

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const raw = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const p = v.pake;

// What the computer does (plugin lib/plus/plus-crypto.js sealGrant, with the v7 `conf` inside).
function sealGrant(pub: string, phone: string, room: string, epoch: number, extra: Record<string, unknown>) {
  const eph = createECDH("prime256v1");
  eph.generateKeys();
  const z = eph.computeSecret(Buffer.from(pub, "base64url"));
  const epk = eph.getPublicKey().toString("base64url");
  const key = Buffer.from(hkdfSync("sha256", z, Buffer.from(`miblo-grant-v6|${phone}|${room}`), Buffer.from(epk), 32));
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(`v6|grant|${phone}|${room}|${epoch}`));
  const rnd = () => randomBytes(32).toString("base64url");
  const pt = Buffer.from(JSON.stringify({ v: 6, kind: "grant", room, readToken: rnd(), key: rnd(), macKey: rnd(), epoch, name: "mbp", at: Date.now(), ...extra }));
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  return { room, epoch, epk, iv: iv.toString("base64url"), ct: ct.toString("base64url") };
}

describe("v7: the computer's confirmation pins it on the phone", () => {
  it("the grant's conf survives opening, and a run of any age pins the computer (1.23.0: the phone waited for ever)", async () => {
    saved.length = 0;
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const pub = b64(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
    const g = { ...sealGrant(pub, p.phone, "room000000000000000000", 3, { conf: p.conf }), device: { id: "dev_1", name: "mbp-marcus" }, at: "", cpub: p.cpub, sig: "x" };
    const payload = await openGrant(pair.privateKey, p.phone, g);
    expect(payload.conf).toBe(p.conf);
    // Typed two hours ago (the phone read its grant late): still the same exchange, still pinned.
    const me = { id: p.phone, pub: p.pub, priv: pair.privateKey, uid: "u", pins: [], pakes: [{ device: "dev_1", cpub: p.cpub, isk: p.isk, at: Date.now() - 2 * 3_600_000 }] } as unknown as AccountIdentity;
    const pinned = await pinByCode(me, g, payload);
    expect(pinned?.pins?.map((x) => x.cpub)).toEqual([p.cpub]);
    expect(pinned?.pakes).toEqual([]);
    expect(saved).toHaveLength(1);
    // Another computer's confirmation (another code or key) pins nothing.
    const other = await openGrant(pair.privateKey, p.phone, { ...g, ...sealGrant(pub, p.phone, "room000000000000000000", 3, { conf: p.conf.slice(1) + "A" }) });
    expect(await pinByCode(me, g, other)).toBeNull();
    // A grant without one (a v6 computer, or a tampered field) opens as before, without conf.
    const plain = await openGrant(pair.privateKey, p.phone, { ...g, ...sealGrant(pub, p.phone, "room000000000000000000", 3, {}) });
    expect(plain.conf).toBeUndefined();
    expect(await pinByCode(me, g, plain)).toBeNull();
  });
});

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
