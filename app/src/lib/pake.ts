// Protocol v7 on the phone (docs/phone-relay-protocol.md, "v7: a new phone types the computer's
// code"): the phone's side of the code exchange. The computer shows a 6-digit code; the person types
// it here; this phone answers the computer's share with its own, a tag that proves it used the same
// code over the same keys, and its passkey (the caller adds it). Same construction as the plugin's
// lib/plus/pake.js (CPace-style over X25519; test vector tests/fixtures/plus-v7-vector.json):
//   sid = "miblo-pake-v7|phone|pub|cpub|n|rs"
//   G   = Elligator2(SHA-512(lv("miblo-cpace-g-v7") lv(code) lv(sid))[0..32], bit 255 cleared)
//   Yb  = X25519(b, G); K = X25519(b, Ya); ISK = SHA-256(lv("miblo-cpace-isk-v7") lv(sid) lv(K) lv(Ya) lv(Yb))
//   tag = HMAC-SHA256(ISK, "miblo-pake-phone-v7"); the computer's conf = HMAC(ISK, "miblo-pake-computer-v7")
// The code is never sent: what travels (Ya, Yb, tag) gives nothing to test a guess against without
// one of the two secret scalars.

const enc = new TextEncoder();
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s: string): Uint8Array<ArrayBuffer> => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const concat = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, p) => n + p.length, 0)));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
const lv = (x: Uint8Array | string) => {
  const b = typeof x === "string" ? enc.encode(x) : x;
  return concat(new Uint8Array([(b.length >> 8) & 0xff, b.length & 0xff]), b);
};

// BigInt constants (the build targets ES2017, without BigInt literals).
const N0 = BigInt(0);
const N1 = BigInt(1);
const N2 = BigInt(2);
const N8 = BigInt(8);
const N19 = BigInt(19);
const N254 = BigInt(254);
const N255 = BigInt(255);
const N121665 = BigInt(121665);
const N486662 = BigInt(486662);
const N255B = BigInt(255);
const P = N2 ** N255 - N19;
const J = N486662;
const mod = (a: bigint) => ((a % P) + P) % P;
function pow(b: bigint, e: bigint): bigint {
  let r = N1;
  b = mod(b);
  while (e > N0) {
    if (e & N1) r = (r * b) % P;
    b = (b * b) % P;
    e >>= N1;
  }
  return r;
}
const inv = (a: bigint) => pow(a, P - N2);
function elligator2(u: bigint): bigint {
  const t = mod(N1 + N2 * u * u);
  let x1 = t === N0 ? mod(-J) : mod(-J * inv(t));
  if (x1 === N0) x1 = mod(-J);
  const gx1 = mod(x1 * x1 * x1 + J * x1 * x1 + x1);
  const square = gx1 === N0 || pow(gx1, (P - N1) / N2) === N1;
  return square ? x1 : mod(-x1 - J);
}
const leToBig = (b: Uint8Array) => {
  let n = N0;
  for (let i = b.length - 1; i >= 0; i--) n = (n << N8) | BigInt(b[i]);
  return n;
};
const bigToLe = (n: bigint): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(new ArrayBuffer(32));
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & N255B);
    n >>= N8;
  }
  return out;
};

export const sidOf = (p: { phone: string; pub: string; cpub: string; n: number; rs: string }) => ["miblo-pake-v7", p.phone, p.pub, p.cpub, String(p.n), p.rs].join("|");

export async function generator(code: string, sid: string): Promise<Uint8Array<ArrayBuffer>> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-512", concat(lv("miblo-cpace-g-v7"), lv(code), lv(sid)))).slice(0, 32);
  h[31] &= 0x7f;
  return bigToLe(elligator2(mod(leToBig(h))));
}

// RFC 7748 X25519 in BigInt: the fallback where WebCrypto has no X25519 (the scalar is a one-time
// random of this exchange).
export function x25519Big(k: Uint8Array, u: Uint8Array): Uint8Array<ArrayBuffer> {
  const s = new Uint8Array(k);
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  const scalar = leToBig(s);
  const uu = new Uint8Array(u);
  uu[31] &= 127;
  const x1 = mod(leToBig(uu));
  let x2 = N1, z2 = N0, x3 = x1, z3 = N1, swap = N0;
  for (let t = N254; t >= N0; t--) {
    const kt = (scalar >> t) & N1;
    swap ^= kt;
    if (swap) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = kt;
    const A = mod(x2 + z2), AA = mod(A * A), B = mod(x2 - z2), BB = mod(B * B), E = mod(AA - BB);
    const C = mod(x3 + z3), D = mod(x3 - z3), DA = mod(D * A), CB = mod(C * B);
    x3 = mod((DA + CB) ** N2);
    z3 = mod(x1 * mod((DA - CB) ** N2));
    x2 = mod(AA * BB);
    z2 = mod(E * (AA + N121665 * E));
  }
  if (swap) [x2, z2] = [x3, z3];
  return bigToLe(mod(x2 * inv(z2)));
}

const PKCS8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
/** X25519(scalar, u); throws on a low-order point (an all-zero result). */
export async function x25519(scalar: Uint8Array, u: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  let out: Uint8Array<ArrayBuffer>;
  try {
    const priv = await crypto.subtle.importKey("pkcs8", concat(PKCS8, scalar), { name: "X25519" }, false, ["deriveBits"]);
    const pub = await crypto.subtle.importKey("raw", concat(u), { name: "X25519" }, false, []);
    out = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  } catch {
    out = x25519Big(scalar, u);
  }
  if (out.every((b) => b === 0)) throw new Error("low-order point");
  return out;
}

async function hmac(key: Uint8Array<ArrayBuffer>, label: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(label))));
}

export type PakeAnswer = { yb: string; tag: string; isk: string };

/** The phone's answer to share `ya` with the typed `code`. `random`: tests (a fixed scalar). */
export async function phoneAnswer(code: string, sid: string, ya: string, random: () => Uint8Array = () => crypto.getRandomValues(new Uint8Array(32))): Promise<PakeAnswer> {
  const b = random();
  const g = await generator(code, sid);
  const yb = await x25519(b, g);
  const yaB = fromB64url(ya);
  const k = await x25519(b, yaB);
  const isk = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(lv("miblo-cpace-isk-v7"), lv(sid), lv(k), lv(yaB), lv(yb))));
  return { yb: b64url(yb), tag: await hmac(isk, "miblo-pake-phone-v7"), isk: b64url(isk) };
}

/** The computer's confirmation this phone expects (sealed in its first grant): pins that computer. */
export const confOf = (isk: string) => hmac(fromB64url(isk), "miblo-pake-computer-v7");

/** The challenge this phone's passkey signs with its answer. */
export async function pakeChallenge(p: { phone: string; pub: string; cpub: string; ya: string; yb: string; tag: string }): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(["miblo-pake-wa-v7", p.phone, p.pub, p.cpub, p.ya, p.yb, p.tag].join("|"))));
}

/** v7: the challenge a new identity's assertion of the passkey this phone already has signs. */
export async function phoneReuseChallenge(phone: string, pub: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`miblo-phone-reuse-v7|${phone}|${pub}`)));
}
