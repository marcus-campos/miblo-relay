// Web Push on the Web Crypto API: VAPID (RFC 8292, ES256 JWT) and the aes128gcm payload
// encryption (RFC 8291 / RFC 8188). No dependencies, runs on Workers, browsers and Node 20.
import { base64url, base64urlDecode } from "../crypto";
import type { PushSubscriptionJson } from "./protocol";

const enc = new TextEncoder();

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(parts.reduce((n, p) => n + p.length, 0)));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey("raw", concat(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, concat(data)));
}

/** HKDF-SHA256 with a single expand block (every length here is at most 32 bytes). */
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number) {
  const prk = await hmac(salt, ikm);
  return (await hmac(prk, concat(info, new Uint8Array([1])))).slice(0, length);
}

export type VapidKeys = { publicKey: string; privateKey: string };

/** A fresh VAPID key pair: public = uncompressed P-256 point, private = the JWK "d", base64url. */
export async function generateVapidKeys(): Promise<VapidKeys> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return { publicKey: base64url(raw), privateKey: jwk.d! };
}

async function vapidSigningKey(keys: VapidKeys): Promise<CryptoKey> {
  const pub = base64urlDecode(keys.publicKey);
  if (pub.length !== 65 || pub[0] !== 4) throw new Error("vapid_public_key_invalid");
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: keys.privateKey,
    x: base64url(pub.slice(1, 33)),
    y: base64url(pub.slice(33, 65)),
    ext: false,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

/** The "Authorization: vapid t=…, k=…" header for a push service origin. */
export async function vapidAuthorization(endpoint: string, keys: VapidKeys, subject: string, nowMs = Date.now()): Promise<string> {
  const header = base64url(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = { aud: new URL(endpoint).origin, exp: Math.floor(nowMs / 1000) + 12 * 3600, sub: subject };
  const body = base64url(enc.encode(JSON.stringify(claims)));
  const key = await vapidSigningKey(keys);
  // Web Crypto produces the raw r||s signature JWS expects.
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${body}`)));
  return `vapid t=${header}.${body}.${base64url(sig)}, k=${keys.publicKey}`;
}

/** RFC 8291 payload encryption: a single aes128gcm record for the subscription's keys. */
export async function encryptPayload(
  sub: PushSubscriptionJson,
  plaintext: Uint8Array,
  // Injectable for tests; fresh random values otherwise.
  salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16)),
): Promise<Uint8Array<ArrayBuffer>> {
  const uaPublic = base64urlDecode(sub.keys.p256dh);
  const authSecret = base64urlDecode(sub.keys.auth);
  const ua = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const as = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const asPublic = new Uint8Array((await crypto.subtle.exportKey("raw", as.publicKey)) as ArrayBuffer);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: ua }, as.privateKey, 256));

  const ikm = await hkdf(authSecret, ecdh, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  // 0x02 = padding delimiter of the last (and only) record.
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, concat(plaintext, new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]); // record size 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ct);
}

export type PushResult = { status: number; gone: boolean };

/** Sends one encrypted push. `gone` = the subscription no longer exists (404/410). */
export async function sendPush(
  sub: PushSubscriptionJson,
  payload: unknown,
  keys: VapidKeys,
  options: { subject: string; ttl?: number; topic?: string; fetcher?: typeof fetch },
): Promise<PushResult> {
  const body = await encryptPayload(sub, enc.encode(JSON.stringify(payload)));
  const headers: Record<string, string> = {
    "Content-Encoding": "aes128gcm",
    "Content-Type": "application/octet-stream",
    TTL: String(options.ttl ?? 3600),
    Urgency: "high",
    Authorization: await vapidAuthorization(sub.endpoint, keys, options.subject),
  };
  if (options.topic) headers.Topic = options.topic;
  const res = await (options.fetcher ?? fetch)(sub.endpoint, { method: "POST", headers, body });
  // The body is irrelevant; drain it so the connection can be reused.
  await res.body?.cancel().catch(() => {});
  return { status: res.status, gone: res.status === 404 || res.status === 410 };
}
