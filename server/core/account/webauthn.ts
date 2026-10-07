// WebAuthn (passkeys) on the server, for the account's second factor. Registration with "none" attestation (no device model is trusted, only the key) and
// assertions with user presence and user verification, checked for the challenge, the origin, the
// relying party and a sign counter that moves forward. ES256 (P-256) and RS256 keys (Windows Hello
// uses RS256), verified with the Web Crypto API. Nothing here throws on hostile input.
import { cborDecode } from "../../../app/src/lib/webauthn";
import { base64url, base64urlDecode } from "../crypto";
import { publicOrigin } from "../config";

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;
const enc = new TextEncoder();

export type StoredKey = { alg: -7 | -257; jwk: JsonWebKey };
export type Relying = { rpId: string; origin: string };

/**
 * The relying party passkeys are made for and checked against: the server's PUBLIC_ORIGIN (its
 * host is the rpId), never taken from the request's Host header, so a request reaching the server
 * under another name cannot get options or assertions for its own origin. Null when PUBLIC_ORIGIN
 * is not a valid origin (the passkey routes then refuse).
 */
export function relyingParty(scope: { env: { PUBLIC_ORIGIN?: string; MIBLO_RELAY_DEV?: string } }): Relying | null {
  const o = publicOrigin(scope.env);
  return o ? { rpId: o.hostname, origin: o.origin } : null;
}

function b64(value: unknown, max: number): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== "string" || value.length > max || !/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    return base64urlDecode(value);
  } catch {
    return null;
  }
}

async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function clientData(bytes: Uint8Array<ArrayBuffer>, type: string, challenge: string, origin: string): string | null {
  let cd: Record<string, unknown>;
  try {
    cd = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  } catch {
    return "bad_client_data";
  }
  if (!cd || cd.type !== type) return "bad_type";
  if (typeof cd.challenge !== "string" || cd.challenge !== challenge) return "bad_challenge";
  if (cd.origin !== origin || cd.crossOrigin === true || cd.topOrigin !== undefined) return "bad_origin";
  return null;
}

type AuthData = { rpIdHash: Uint8Array; flags: number; signCount: number; credId?: Uint8Array; key?: StoredKey };

function parseAuthData(ad: Uint8Array<ArrayBuffer>): AuthData | null {
  try {
    if (ad.length < 37) return null;
    const view = new DataView(ad.buffer, ad.byteOffset, ad.byteLength);
    const out: AuthData = { rpIdHash: ad.slice(0, 32), flags: ad[32], signCount: view.getUint32(33) };
    if (!(out.flags & FLAG_AT)) return out;
    if (ad.length < 55) return null;
    const idLen = view.getUint16(53);
    if (idLen < 1 || idLen > 1023 || 55 + idLen > ad.length) return null;
    out.credId = ad.slice(55, 55 + idLen);
    const { value: cose, end } = cborDecode(ad, 55 + idLen);
    if (end !== ad.length && !(out.flags & FLAG_ED)) return null;
    if (!(cose instanceof Map)) return null;
    const kty = cose.get(1);
    const alg = cose.get(3);
    if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
      const x = cose.get(-2);
      const y = cose.get(-3);
      if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) return null;
      out.key = { alg: -7, jwk: { kty: "EC", crv: "P-256", x: base64url(x), y: base64url(y) } };
    } else if (kty === 3 && alg === -257) {
      const n = cose.get(-1);
      const e = cose.get(-2);
      if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 256 || n.length > 512 || e.length > 8) return null;
      out.key = { alg: -257, jwk: { kty: "RSA", n: base64url(n), e: base64url(e), alg: "RS256" } };
    } else {
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

/** A DER ECDSA signature as the r||s pair Web Crypto verifies (P-256: 64 bytes). */
export function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> | null {
  try {
    if (der[0] !== 0x30) return null;
    let p = 2;
    if (der[1] & 0x80) p = 2 + (der[1] & 0x7f);
    const out = new Uint8Array(64);
    for (let k = 0; k < 2; k++) {
      if (der[p] !== 0x02) return null;
      const len = der[p + 1];
      let v = der.slice(p + 2, p + 2 + len);
      p += 2 + len;
      while (v.length > 32 && v[0] === 0) v = v.slice(1);
      if (v.length > 32) return null;
      out.set(v, k * 32 + (32 - v.length));
    }
    return p === der.length ? out : null;
  } catch {
    return null;
  }
}

async function verifySig(key: StoredKey, data: Uint8Array<ArrayBuffer>, sig: Uint8Array<ArrayBuffer>): Promise<boolean> {
  try {
    if (key.alg === -7) {
      const raw = derToRaw(sig);
      if (!raw) return false;
      const pub = await crypto.subtle.importKey("jwk", key.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, raw, data);
    }
    const pub = await crypto.subtle.importKey("jwk", key.jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pub, sig, data);
  } catch {
    return false;
  }
}

export type Registration = { ok: true; credId: string; key: StoredKey; signCount: number } | { ok: false; reason: string };

/** A passkey's creation (attestationObject and clientDataJSON, base64url) over `challenge`. */
export async function verifyRegistration(p: { att: unknown; cdj: unknown; challenge: string; rp: Relying }): Promise<Registration> {
  const att = b64(p.att, 8192);
  const cdj = b64(p.cdj, 4096);
  if (!att || !cdj) return { ok: false, reason: "malformed" };
  const bad = clientData(cdj, "webauthn.create", p.challenge, p.rp.origin);
  if (bad) return { ok: false, reason: bad };
  let obj;
  try {
    obj = cborDecode(att).value;
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!(obj instanceof Map) || typeof obj.get("fmt") !== "string") return { ok: false, reason: "malformed" };
  const authData = obj.get("authData");
  if (!(authData instanceof Uint8Array)) return { ok: false, reason: "malformed" };
  const ad = parseAuthData(new Uint8Array(authData));
  if (!ad?.credId || !ad.key) return { ok: false, reason: "bad_key" };
  if (!same(ad.rpIdHash, await sha256(enc.encode(p.rp.rpId)))) return { ok: false, reason: "bad_rp" };
  if (!(ad.flags & FLAG_UP) || !(ad.flags & FLAG_UV)) return { ok: false, reason: "no_uv" };
  return { ok: true, credId: base64url(ad.credId), key: ad.key, signCount: ad.signCount };
}

export type Verified = { ok: true; signCount: number } | { ok: false; reason: string };

/** An assertion ({ cred, ad, cdj, sig }, base64url) of a stored passkey over `challenge`. */
export async function verifyAssertion(p: {
  key: StoredKey;
  credId: string;
  signCount: number;
  wa: { cred?: unknown; ad?: unknown; cdj?: unknown; sig?: unknown };
  challenge: string;
  rp: Relying;
}): Promise<Verified> {
  if (p.wa.cred !== p.credId) return { ok: false, reason: "other_credential" };
  const ad = b64(p.wa.ad, 2048);
  const cdj = b64(p.wa.cdj, 4096);
  const sig = b64(p.wa.sig, 1024);
  if (!ad || !cdj || !sig) return { ok: false, reason: "malformed" };
  const bad = clientData(cdj, "webauthn.get", p.challenge, p.rp.origin);
  if (bad) return { ok: false, reason: bad };
  const parsed = parseAuthData(ad);
  if (!parsed) return { ok: false, reason: "malformed" };
  if (!same(parsed.rpIdHash, await sha256(enc.encode(p.rp.rpId)))) return { ok: false, reason: "bad_rp" };
  if (!(parsed.flags & FLAG_UP) || !(parsed.flags & FLAG_UV)) return { ok: false, reason: "no_uv" };
  const data = new Uint8Array(ad.length + 32);
  data.set(ad, 0);
  data.set(await sha256(cdj), ad.length);
  if (!(await verifySig(p.key, data, sig))) return { ok: false, reason: "bad_signature" };
  if ((parsed.signCount !== 0 || p.signCount !== 0) && parsed.signCount <= p.signCount) return { ok: false, reason: "sign_count" };
  return { ok: true, signCount: parsed.signCount };
}
