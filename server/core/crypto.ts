// Small crypto helpers on the Web Crypto API (Workers and Node 22).
import type { RequestScope } from "./env";

export function randomToken(bytes = 24): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  const s = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time string comparison (compares SHA-256 digests so lengths do not leak). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([sha256Hex(a), sha256Hex(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** The secret behind sessions, CSRF tokens and challenges (32+ characters), or null. */
export function sessionSecret(scope: RequestScope): string | null {
  const s = scope.env.SESSION_SECRET;
  return s && s.length >= 32 ? s : null;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  const id = `hmac:${secret}`;
  let k = keyCache.get(id);
  if (!k) {
    k = crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    keyCache.set(id, k);
  }
  return k;
}

export async function hmac(secret: string, message: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(message));
  return base64url(new Uint8Array(sig));
}

/** Constant-time check of an HMAC (crypto.subtle.verify). */
export async function hmacVerify(secret: string, message: string, signature: string): Promise<boolean> {
  try {
    return await crypto.subtle.verify("HMAC", await hmacKey(secret), base64urlDecode(signature), new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

/** A short random id with a prefix ("usr_…", "dev_…"). */
export function newId(prefix: string): string {
  return `${prefix}_${randomToken(12)}`;
}
