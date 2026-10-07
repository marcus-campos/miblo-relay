// The pairing vault on the phone (docs/miblo-plus.md, "Pairing vault"): the pairings (each
// computer's room, read token, frame key and name) encrypted here with a random data key; the data
// key wrapped once per passkey with a key derived from that passkey's PRF output (WebAuthn PRF
// extension, evaluated with the vault's salt). The server stores only ciphertext, the salt, the
// credential ids and the wrapped keys; it never sees a PRF output or a key. Without PRF (some
// browsers and authenticators) there is no vault on that device.
//
// Restoring a pairing gives the phone the status only: approvals and replies need this phone to
// enroll its own passkey with the computer (a new QR code from the computer's terminal), so a
// restored device never inherits another phone's rights, and a phone revoked on the computer stays
// revoked.
//
// v2: the ciphertext is bound to the account and to its version (AAD "miblo-vault-v2|<user
// id>|<version>"), and the phone keeps the highest version it opened (highWater): the server can
// neither hand back an older vault (bringing back pairings the person removed) nor another
// account's, unnoticed. Every write carries the key check (keyCheck), which shows the server the
// writer holds the data key without revealing it.
import { b64url, fromB64url, type Pairing } from "@/lib/relay-crypto";

const enc = new TextEncoder();
const aad = (uid: string, version: number) => enc.encode(`miblo-vault-v2|${uid}|${version}`);
const HKDF_INFO = "miblo-vault-kek-v1";
const HIGH_WATER_KEY = "miblo-vault-hw:";

export type VaultEntry = { room: string; readToken: string; key: string; name: string; addedAt: number; lastSeen: number | null };
export type VaultPlain = { v: 1; pairings: VaultEntry[] };
export type Wrap = { cred: string; iv: string; key: string };
export type VaultBlob = { salt: string; wraps: Wrap[]; iv: string; ct: string; version: number };

const ROOM_RE = /^[A-Za-z0-9_-]{22}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/** A fresh PRF salt (32 bytes, base64url). */
export const newSalt = (): string => b64url(crypto.getRandomValues(new Uint8Array(32)));

/** The key that wraps the data key for one passkey: HKDF-SHA256 over its PRF output. */
async function kek(prf: Uint8Array<ArrayBuffer>, salt: string, cred: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: fromB64url(salt), info: enc.encode(`${HKDF_INFO}|${cred}`) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Wraps the raw data key for the passkey `cred` whose PRF output is `prf`. */
export async function wrapKey(dataKey: Uint8Array<ArrayBuffer>, prf: Uint8Array<ArrayBuffer>, salt: string, cred: string): Promise<Wrap> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`wrap|${cred}`) }, await kek(prf, salt, cred), dataKey);
  return { cred, iv: b64url(iv), key: b64url(new Uint8Array(ct)) };
}

/** The raw data key, from the wrap of the passkey that was just used. Throws on a wrong PRF output. */
export async function unwrapKey(w: Wrap, prf: Uint8Array<ArrayBuffer>, salt: string): Promise<Uint8Array<ArrayBuffer>> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64url(w.iv), additionalData: enc.encode(`wrap|${w.cred}`) },
    await kek(prf, salt, w.cred),
    fromB64url(w.key),
  );
  return new Uint8Array(pt);
}

const dataCryptoKey = (raw: Uint8Array<ArrayBuffer>) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

/** Seals the pairings for account `uid` as version `version` (the one the server will store). */
export async function sealVault(dataKey: Uint8Array<ArrayBuffer>, plain: VaultPlain, uid: string, version: number): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(uid, version) }, await dataCryptoKey(dataKey), enc.encode(JSON.stringify(plain)));
  return { iv: b64url(iv), ct: b64url(new Uint8Array(ct)) };
}

/** The key check every write carries: HMAC-SHA256(data key, "miblo-vault-kc-v2|<uid>"), base64url. */
export async function keyCheck(dataKey: Uint8Array<ArrayBuffer>, uid: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", dataKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`miblo-vault-kc-v2|${uid}`))));
}

/** The highest vault version this phone opened for `uid` (0: none, or no storage). */
export function highWater(uid: string): number {
  try {
    const v = Number(localStorage.getItem(HIGH_WATER_KEY + uid));
    return Number.isSafeInteger(v) && v > 0 ? v : 0;
  } catch {
    return 0;
  }
}

export function noteVersion(uid: string, version: number): void {
  try {
    if (version > highWater(uid)) localStorage.setItem(HIGH_WATER_KEY + uid, String(version));
  } catch {
    // No storage: the check lasts for this page only.
  }
}

/**
 * The vault's pairings, each field checked; anything malformed is left out. Throws on a wrong key,
 * another account's vault, or a version other than the one it was sealed as.
 */
export async function openVault(dataKey: Uint8Array<ArrayBuffer>, blob: { iv: string; ct: string }, uid: string, version: number): Promise<VaultPlain> {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64url(blob.iv), additionalData: aad(uid, version) }, await dataCryptoKey(dataKey), fromB64url(blob.ct));
  const v = JSON.parse(new TextDecoder().decode(pt)) as { pairings?: unknown };
  const pairings = (Array.isArray(v.pairings) ? v.pairings : [])
    .map((e): VaultEntry | null => {
      const o = e as Record<string, unknown>;
      if (!o || typeof o.room !== "string" || !ROOM_RE.test(o.room) || typeof o.readToken !== "string" || !TOKEN_RE.test(o.readToken)) return null;
      if (typeof o.key !== "string" || !TOKEN_RE.test(o.key)) return null;
      return {
        room: o.room,
        readToken: o.readToken,
        key: o.key,
        name: typeof o.name === "string" ? o.name.slice(0, 40) : "Miblo",
        addedAt: typeof o.addedAt === "number" ? o.addedAt : 0,
        lastSeen: typeof o.lastSeen === "number" ? o.lastSeen : null,
      };
    })
    .filter((e): e is VaultEntry => e !== null)
    .slice(0, 50);
  return { v: 1, pairings };
}

/** A vault entry from a pairing link the phone just read. */
export function entryOf(p: Pairing, now: number): VaultEntry {
  return { room: p.room, readToken: p.readToken, key: p.key, name: p.name, addedAt: now, lastSeen: null };
}

/** The pairing a vault entry restores: the status only (no enrollment secret, no phone identity). */
export function pairingOf(e: VaultEntry): Pairing {
  return { v: 2, room: e.room, readToken: e.readToken, key: e.key, name: e.name };
}

/** Adds or refreshes one entry (a newer pairing of the same room replaces the old one). */
export function upsertEntry(plain: VaultPlain, e: VaultEntry): VaultPlain {
  const rest = plain.pairings.filter((x) => x.room !== e.room);
  const old = plain.pairings.find((x) => x.room === e.room);
  return { v: 1, pairings: [...rest, { ...e, addedAt: old?.addedAt ?? e.addedAt }] };
}

export function removeEntry(plain: VaultPlain, room: string): VaultPlain {
  return { v: 1, pairings: plain.pairings.filter((x) => x.room !== room) };
}
