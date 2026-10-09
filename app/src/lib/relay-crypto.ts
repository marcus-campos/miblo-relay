// End-to-end encryption of the phone relay frames (docs/phone-relay-protocol.md, v2): AES-256-GCM,
// a fresh 12-byte iv per frame, AAD = "v2|<t>|<ch>|<room>" (UTF-8; ch "status" when absent),
// base64url without padding. The key lives only on the computer and the paired phones; the relay
// sees ciphertext and cannot move a frame to another room, type or channel.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(value: string): Uint8Array<ArrayBuffer> {
  const s = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Imports the pairing key (32 bytes, base64url). Non-extractable: IndexedDB keeps the CryptoKey. */
export async function importRoomKey(key: string, usages: KeyUsage[] = ["decrypt"]): Promise<CryptoKey> {
  const raw = fromB64url(key);
  if (raw.length !== 32) throw new Error("bad_key");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

export type FrameType = "msg" | "up";
export type Frame = { t: FrameType; ch?: string; iv: string; ct: string };

/** The additional authenticated data binding a frame to its type, channel and room. */
export function frameAad(room: string, t: FrameType, ch?: string): Uint8Array<ArrayBuffer> {
  return enc.encode(`v2|${t}|${ch ?? "status"}|${room}`);
}

export async function encryptFrame(
  key: CryptoKey,
  room: string,
  payload: unknown,
  { t = "msg", ch = "status" }: { t?: FrameType; ch?: string } = {},
): Promise<Frame> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: frameAad(room, t, ch) },
    key,
    enc.encode(JSON.stringify(payload)),
  );
  return { t, ch, iv: b64url(iv), ct: b64url(new Uint8Array(ct)) };
}

/** The decrypted JSON payload of a frame; throws when the key, room, type, channel or bytes do not match. */
export async function decryptFrame(key: CryptoKey, room: string, frame: { t: FrameType; ch?: string; iv: string; ct: string }): Promise<unknown> {
  const iv = fromB64url(frame.iv);
  if (iv.length !== 12) throw new Error("bad_iv");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: frameAad(room, frame.t, frame.ch) },
    key,
    fromB64url(frame.ct),
  );
  return JSON.parse(dec.decode(plain));
}

/**
 * A pairing link's contents. `enroll` (Miblo+, v4): the secret of the computer's open pairing window,
 * with which this phone enrolls its own passkey and MAC key (absent: no window was open).
 */
export type Pairing = { v: 2; room: string; readToken: string; key: string; name: string; enroll?: string };

/** Reads the `p` value of a pairing link (#p=<base64url JSON>), validating every field. */
export function parsePairing(value: string): Pairing | null {
  try {
    const data = JSON.parse(dec.decode(fromB64url(value))) as Record<string, unknown>;
    if (data.v !== 2) return null;
    if (typeof data.room !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(data.room)) return null;
    if (typeof data.readToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(data.readToken)) return null;
    if (typeof data.key !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(data.key)) return null;
    const name = typeof data.name === "string" ? data.name.trim().slice(0, 40) : "";
    const enroll = typeof data.en === "string" && /^[A-Za-z0-9_-]{43}$/.test(data.en) ? { enroll: data.en } : {};
    return { v: 2, room: data.room, readToken: data.readToken, key: data.key, name: name || "Miblo", ...enroll };
  } catch {
    return null;
  }
}

/** The pairing value inside a link or a bare fragment ("https://miblo.ai/app#p=…", "#p=…"). */
export function pairingFromText(text: string): Pairing | null {
  const m = /[#&]p=([A-Za-z0-9_-]+)/.exec(text.trim()) ?? /^p=([A-Za-z0-9_-]+)$/.exec(text.trim());
  return m ? parsePairing(m[1]) : null;
}

// --- Miblo+ (protocol v5) ------------------------------------------------------------------------
// Each phone has a MAC key of its own (32 random bytes made when it enrolled with the computer,
// docs/phone-relay-protocol.md "Phones"). It goes to the computer once, sealed under a key derived
// from the QR code's pairing window secret (enrollKey): no other holder of the pairing key can read
// it. From it both sides derive the phone's reader token at the relay and its frame key: Miblo+
// frames are sealed per phone (sealed frames below). Decisions and replies carry an HMAC under it,
// so each is attributable to one phone and stops counting once that phone is revoked. An "allow"
// and every reply also carry a passkey assertion (src/lib/webauthn.ts). Shared test vector:
// tests/fixtures/plus-vector.json (identical in the plugin).

const DECISION_PREFIX = "miblo-decision-v4";
const REPLY_PREFIX = "miblo-reply-v5";

/** The pairing's frame key as the phone keeps it: non-extractable, for frames both ways. */
export async function importPairingKeys(key: string): Promise<{ key: CryptoKey }> {
  const raw = fromB64url(key);
  if (raw.length !== 32) throw new Error("bad_key");
  return { key: await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]) };
}

/** A phone's own MAC key (32 bytes), imported non-extractable for signing (and deriving its keys). */
export async function importMacKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("bad_key");
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

export type DecisionFields = {
  phone: string;
  id: string;
  session: string;
  tool: string;
  hash: string;
  decision: "allow" | "deny";
  nonce: string;
  ts: number;
};

export function decisionMacText(room: string, f: DecisionFields): string {
  return [DECISION_PREFIX, room, f.phone, f.id, f.session, f.tool, f.hash, f.decision, f.nonce, String(f.ts)].join("|");
}

/** `rt`: the reply token the computer issued for the session in its latest history frame. */
export type ReplyFields = { phone: string; session: string; nonce: string; ts: number; rt: string; text: string };

export async function replyMacText(room: string, f: ReplyFields): Promise<string> {
  return [REPLY_PREFIX, room, f.phone, f.session, f.nonce, String(f.ts), f.rt, await sha256Text(f.text)].join("|");
}

/** The challenge a reply's passkey assertion is made over (binds the text by its hash). */
export async function replyChallenge(room: string, f: ReplyFields): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-reply-wa-v5|${room}|${f.phone}|${f.session}|${f.nonce}|${f.ts}|${f.rt}|${await sha256Text(f.text)}`);
}

export async function phoneMac(macKey: CryptoKey, text: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", macKey, enc.encode(text))));
}

async function sha256Bytes(text: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

/** The challenge this phone's passkey is created over at enrollment (binds room, phone, window secret, MAC key). */
export function enrollChallenge(p: { room: string; phone: string; secret: string; macKey: string }): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-enroll-v4|${p.room}|${p.phone}|${p.secret}|${p.macKey}`);
}

/** The challenge an "allow" is signed over: H(request id | tool | input hash | room | request nonce). */
export function approveChallenge(p: { id: string; tool: string; hash: string; room: string; nonce: string }): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-approve-v4|${p.id}|${p.tool}|${p.hash}|${p.room}|${p.nonce}`);
}

/** base64url(SHA-256(UTF-8 text)). */
export async function sha256Text(text: string): Promise<string> {
  return b64url(await sha256Bytes(text));
}

/** A fresh random id (base64url): reply and decision nonces, phone ids. */
export function randomNonce(bytes = 16): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

// --- v5: keys derived from the MAC key, and sealed frames ------------------------------------------

async function macBytes(macKey: CryptoKey, label: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", macKey, enc.encode(label)));
}

/** This phone's token at the relay (the computer registers its SHA-256). */
export async function readerToken(macKey: CryptoKey, room: string, phone: string): Promise<string> {
  return b64url(await macBytes(macKey, `miblo-reader-v5|${room}|${phone}`));
}

/** This phone's frame key (AES-256-GCM), non-extractable. */
export async function phoneFrameKey(macKey: CryptoKey, room: string, phone: string): Promise<CryptoKey> {
  const raw = await macBytes(macKey, `miblo-phone-key-v5|${room}|${phone}`);
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  } finally {
    raw.fill(0);
  }
}

/** The key an enrollment (and the computer's answer) travels under: HKDF over the window secret. */
export async function enrollKey(secret: string, room: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", fromB64url(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(room), info: enc.encode("miblo-enroll-key-v5") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function gcmSeal(key: CryptoKey, data: Uint8Array<ArrayBuffer>, aad: string): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, data);
  return { iv: b64url(iv), ct: b64url(new Uint8Array(ct)) };
}

async function gcmOpen(key: CryptoKey, iv: Uint8Array<ArrayBuffer>, ct: Uint8Array<ArrayBuffer>, aad: string): Promise<Uint8Array<ArrayBuffer>> {
  if (iv.length !== 12) throw new Error("bad_iv");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, ct));
}

/** A frame the relay handed this phone: {t:"msg", ch, iv, ct, k} with `k` its wrap of the content key. */
export type SealedFrame = { t: "msg"; ch: string; iv: string; ct: string; k: string };

/** Opens a frame sealed to this phone; throws when it is not for it or was changed. */
export async function openSealed(key: CryptoKey, room: string, phone: string, frame: SealedFrame): Promise<unknown> {
  const w = fromB64url(frame.k);
  if (w.length !== 60) throw new Error("bad_wrap");
  const raw = await gcmOpen(key, w.slice(0, 12), w.slice(12), `v5|ck|${frame.ch}|${room}|${phone}`);
  try {
    const ck = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
    return JSON.parse(dec.decode(await gcmOpen(ck, fromB64url(frame.iv), fromB64url(frame.ct), `v5|msg|${frame.ch}|${room}`)));
  } finally {
    raw.fill(0);
  }
}

/** A frame from this phone to the computer, sealed under its own key. */
export async function sealUp(key: CryptoKey, room: string, phone: string, ch: string, payload: unknown): Promise<Frame> {
  const { iv, ct } = await gcmSeal(key, enc.encode(JSON.stringify(payload)), `v5|up|${ch}|${room}|${phone}`);
  return { t: "up", ch, iv, ct };
}

/** The enrollment frame (this phone has no identity yet), sealed under enrollKey(). */
export async function sealEnroll(key: CryptoKey, room: string, payload: unknown): Promise<Frame> {
  const { iv, ct } = await gcmSeal(key, enc.encode(JSON.stringify(payload)), `v5|enroll|${room}`);
  return { t: "up", ch: "approval", iv, ct };
}

/** The computer's answer to an enrollment ({t:"msg", ch:"approval", g:1}). */
export async function openEnrolled(key: CryptoKey, room: string, frame: { iv: string; ct: string }): Promise<unknown> {
  return JSON.parse(dec.decode(await gcmOpen(key, fromB64url(frame.iv), fromB64url(frame.ct), `v5|enrolled|${room}`)));
}

// --- protocol v6 (docs/phone-relay-protocol.md, "v6") -----------------------------------------------

/** The challenge this phone's passkey is created over when it joins the account. */
export function phoneRegChallenge(phone: string, pub: string): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-phone-v6|${phone}|${pub}`);
}

/** `auto` (1.26, an automatic task: no approvals) is appended to both only when true. */
export type TaskFields = { phone: string; tool: string; folder: string; nonce: string; ts: number; tt: string; text: string; auto?: boolean };
export async function taskMacText(room: string, f: TaskFields): Promise<string> {
  return ["miblo-task-v6", room, f.phone, f.tool, f.folder, f.nonce, String(f.ts), f.tt, await sha256Text(f.text), ...(f.auto === true ? ["auto"] : [])].join("|");
}
export async function taskChallenge(room: string, f: TaskFields): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-task-wa-v6|${room}|${f.phone}|${f.tool}|${f.folder}|${f.nonce}|${f.ts}|${f.tt}|${await sha256Text(f.text)}${f.auto === true ? "|auto" : ""}`);
}
export type StopFields = { phone: string; task: string; nonce: string; ts: number };
export function stopMacText(room: string, f: StopFields): string {
  return ["miblo-stop-v6", room, f.phone, f.task, f.nonce, String(f.ts)].join("|");
}

/**
 * The panic button (plugin lib/plus/panic.js): the phone's MAC and its passkey's challenge bind the
 * room, the phone, a fresh nonce and the phone's time. Checked on the computer exactly like a reply.
 */
export type PanicFields = { phone: string; nonce: string; ts: number };
export function panicMacText(room: string, f: PanicFields): string {
  return ["miblo-panic-v8", room, f.phone, f.nonce, String(f.ts)].join("|");
}
export function panicChallenge(room: string, f: PanicFields): Promise<Uint8Array<ArrayBuffer>> {
  return sha256Bytes(`miblo-panic-wa-v8|${room}|${f.phone}|${f.nonce}|${f.ts}`);
}

/** A pairing a computer sealed to this phone's ECDH key (stored by the account, opened only here). */
export type Grant = { room: string; epoch: number; epk: string; iv: string; ct: string };
/** `conf` (v7): the computer's confirmation of the code exchange this phone ran with it; pinByCode (account-join.ts) pins that computer with it. */
export type GrantPayload = { room: string; readToken: string; key: string; macKey: string; epoch: number; name: string; at: number; conf?: string };
const KEY43 = /^[A-Za-z0-9_-]{43}$/;

/**
 * Opens a grant with this phone's private ECDH key: ECDH with the computer's ephemeral key, HKDF-SHA256
 * (salt "miblo-grant-v6|<phone>|<room>", info the ephemeral key), AES-256-GCM with AAD
 * "v6|grant|<phone>|<room>|<epoch>". Throws when it is not for this phone, room and generation.
 */
export async function openGrant(priv: CryptoKey, phone: string, g: Grant): Promise<GrantPayload> {
  const epk = await crypto.subtle.importKey("raw", fromB64url(g.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const z = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, priv, 256);
  const base = await crypto.subtle.importKey("raw", z, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(`miblo-grant-v6|${phone}|${g.room}`), info: enc.encode(g.epk) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64url(g.iv), additionalData: enc.encode(`v6|grant|${phone}|${g.room}|${g.epoch}`) }, key, fromB64url(g.ct));
  const p = JSON.parse(new TextDecoder().decode(pt)) as Record<string, unknown>;
  if (p.room !== g.room || p.epoch !== g.epoch) throw new Error("bad grant");
  if (typeof p.readToken !== "string" || !KEY43.test(p.readToken) || typeof p.key !== "string" || !KEY43.test(p.key) || typeof p.macKey !== "string" || !KEY43.test(p.macKey)) {
    throw new Error("bad grant");
  }
  return {
    room: g.room,
    readToken: p.readToken,
    key: p.key,
    macKey: p.macKey,
    epoch: g.epoch,
    name: typeof p.name === "string" ? p.name.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 40) || "Miblo" : "Miblo",
    at: typeof p.at === "number" ? p.at : 0,
    // v7: without it a phone that typed the right code never pins the computer and waits for ever.
    ...(typeof p.conf === "string" && KEY43.test(p.conf) ? { conf: p.conf } : {}),
  };
}

// --- v6 trust (docs/phone-relay-protocol.md "Verifying a new phone"; security audit 1.21.0) --------
// Mirrors the plugin's lib/plus/plus-crypto.js (shared vector: tests/fixtures/plus-v6-vector.json
// "trust"). The code a waiting phone shows covers its id and key, the computer's identity key and
// two nonces: the computer's, committed to first, and this phone's, sent before the computer's is
// revealed. Grants are signed by the computer's identity key (ECDSA P-256, SHA-256, r||s).

/** The computer's commitment to its nonce, as the phone checks it with its own key. */
export function sasCommit(phone: string, pub: string, cpub: string, nonce: string): Promise<string> {
  return sha256Text(["miblo-sas-commit-v6", phone, pub, cpub, nonce].join("|"));
}

/** The 6 digits ("042917"). */
export async function sasCode(phone: string, pub: string, cpub: string, nonce: string, pnonce: string): Promise<string> {
  const h = await sha256Bytes(["miblo-sas-v6", phone, pub, cpub, nonce, pnonce].join("|"));
  const n = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
  return String(n % 1_000_000).padStart(6, "0");
}

/** "3F2A 9C10 77B4 E2D1": the first 8 bytes of SHA-256 over the computer's raw public key. */
export async function computerFingerprint(cpub: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64url(cpub)));
  const hex = Array.from(h.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{4}/g)!.join(" ");
}

export type SignedGrant = Grant & { cpub: string; sig: string };
const CPUB_RE = /^[A-Za-z0-9_-]{87}$/;

/** Whether `g` carries a valid signature by the computer key it names (who that is: the caller's question). */
export async function verifyGrantSig(phone: string, g: SignedGrant): Promise<boolean> {
  try {
    if (typeof g.cpub !== "string" || !CPUB_RE.test(g.cpub) || typeof g.sig !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(g.sig)) return false;
    const key = await crypto.subtle.importKey("raw", fromB64url(g.cpub), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const text = ["miblo-grant-sig-v6", phone, g.room, String(g.epoch), g.epk, g.iv, g.ct, g.cpub].join("|");
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, fromB64url(g.sig), enc.encode(text));
  } catch {
    return false;
  }
}
