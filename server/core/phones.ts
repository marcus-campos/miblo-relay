// Protocol v6, "phones through the account" (docs/protocol.md): the phones of the account and the
// grants the account's linked computers sealed to them. The server never opens a grant: it stores
// what a computer sealed to a phone's own key and hands it back to that phone. Adding a phone
// needs the account's second factor passed in the last 5 minutes (the route checks it).
// Same code as miblo.ai's phone registry.
import { nowIso } from "./crypto";
import { attestedKey } from "../../app/src/lib/webauthn";
import type { RequestScope } from "./env";
import type { LinkedDevice } from "./devices";

export const MAX_PHONES = 5;
/** Revoked phones are listed to the computers this long, so they revoke them too. */
export const REVOKED_LISTED_DAYS = 90;
export const PHONE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64 = /^[A-Za-z0-9_-]+$/;

export type Pk = { id: string; x: string; y: string };
export type Wa = { cred: string; ad: string; cdj: string; sig: string };
export type PhoneInput = { id: string; name: string; pub: string; att?: string; cdj?: string; pk?: Pk; pkwa?: Wa };
/** What the computers show the person about a new phone (approximate, never used for a decision). */
export type PhoneMeta = { model: string | null; place: string | null };
export type PhoneRow = {
  id: string;
  user_id: string;
  name: string;
  pub: string;
  att: string | null;
  cdj: string | null;
  model: string | null;
  place: string | null;
  created_at: string;
  asked_at: string | null;
  revoked_at: string | null;
  pk?: string | null;
  pkwa?: string | null;
};
export type RequestState = "pending" | "confirm" | "denied" | "expired";
export type PakeRound = { n: number; rs: string; ya: string; wrong: number };
export type PakeAnswer = { n: number; ya: string; yb: string; tag: string; wa?: Wa };
export type GrantInput = { room: string; epoch: number; epk: string; iv: string; ct: string; cpub: string; sig: string };

/** The raw uncompressed P-256 point a phone's ECDH public key must be (65 bytes, 0x04 first). */
export function validPub(pub: string): boolean {
  if (!/^[A-Za-z0-9_-]{87}$/.test(pub)) return false;
  try {
    return atob(pub.slice(0, 4).replace(/-/g, "+").replace(/_/g, "/")).charCodeAt(0) === 4;
  } catch {
    return false;
  }
}

export async function activePhones(scope: RequestScope, userId: string): Promise<PhoneRow[]> {
  const r = await scope.env.DB.prepare(`SELECT * FROM account_phones WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at`).bind(userId).all<PhoneRow>();
  return r.results;
}

export type RegisterPhoneResult = { ok: true; phone: PhoneRow } | { ok: false; error: "phone_limit" | "phone_exists" | "invalid_request" };

/** The browser and system a User-Agent names ("iPhone · Safari"), for the computers' confirmation. */
export function phoneModel(ua: string): string | null {
  const system = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Macintosh|Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : null;
  const browser = /EdgA?\/|EdgiOS\//.test(ua) ? "Edge" : /SamsungBrowser\//.test(ua) ? "Samsung Internet" : /Firefox\/|FxiOS\//.test(ua) ? "Firefox" : /Chrome\/|CriOS\//.test(ua) ? "Chrome" : /Safari\//.test(ua) && /Version\//.test(ua) ? "Safari" : null;
  const out = [system, browser].filter(Boolean).join(" · ");
  return out || null;
}

/** "São Paulo, BR" from a stored "city|CC" place. */
const placeText = (place: string | null) => (place ? place.split("|").filter(Boolean).join(", ") || null : null);

/** A phone joins the account (the caller checked the session and its fresh second factor). */
export async function registerPhone(scope: RequestScope, userId: string, input: PhoneInput, now = Date.now(), meta: PhoneMeta = { model: null, place: null }): Promise<RegisterPhoneResult> {
  if (!PHONE_ID_RE.test(input.id) || !validPub(input.pub)) return { ok: false, error: "invalid_request" };
  if (!!input.att !== !!input.cdj || !!input.pk !== !!input.pkwa || (input.att && input.pk)) return { ok: false, error: "invalid_request" };
  const ts = new Date(now).toISOString();
  // One statement: the limit is checked and the row inserted together (parallel registrations
  // cannot all pass a count read before any of them was written).
  try {
    const r = await scope.env.DB.prepare(
      `INSERT INTO account_phones (id, user_id, name, pub, att, cdj, model, place, created_at, pk, pkwa)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?9, ?10, ?7, ?11, ?12
        WHERE (SELECT COUNT(*) FROM account_phones WHERE user_id = ?2 AND revoked_at IS NULL) < ?8`,
    )
      .bind(input.id, userId, input.name, input.pub, input.att ?? null, input.cdj ?? null, ts, MAX_PHONES, meta.model?.slice(0, 60) ?? null, meta.place?.slice(0, 80) ?? null,
        input.pk ? JSON.stringify(input.pk) : null, input.pkwa ? JSON.stringify(input.pkwa) : null)
      .run();
    if (!r.meta.changes) return { ok: false, error: "phone_limit" };
  } catch {
    return { ok: false, error: "phone_exists" };
  }
  return {
    ok: true,
    phone: { id: input.id, user_id: userId, name: input.name, pub: input.pub, att: input.att ?? null, cdj: input.cdj ?? null, model: meta.model, place: meta.place, created_at: ts, asked_at: null, revoked_at: null },
  };
}

/** The account revokes one of its phones: its grants go at once; the computers revoke it on their next read. */
export async function revokePhone(scope: RequestScope, userId: string, id: string): Promise<PhoneRow | null> {
  if (!PHONE_ID_RE.test(id)) return null;
  const row = await scope.env.DB.prepare(`UPDATE account_phones SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL RETURNING *`)
    .bind(nowIso(), id, userId)
    .first<PhoneRow>();
  if (!row) return null;
  await scope.env.DB.batch([
    scope.env.DB.prepare(`DELETE FROM phone_grants WHERE phone_id = ?`).bind(id),
    scope.env.DB.prepare(`DELETE FROM phone_requests WHERE phone_id = ?`).bind(id),
    bumpRev(scope, id),
  ]);
  return row;
}

/** The account's phones as the account page and the phone app list them (no keys). */
export async function listPhones(scope: RequestScope, userId: string) {
  const rows = await scope.env.DB.prepare(
    `SELECT p.id, p.name, p.created_at, (p.att IS NOT NULL OR p.pk IS NOT NULL) AS passkey,
            (SELECT MAX(g.updated_at) FROM phone_grants g WHERE g.phone_id = p.id) AS granted_at,
            (SELECT COUNT(*) FROM phone_grants g WHERE g.phone_id = p.id) AS computers
       FROM account_phones p WHERE p.user_id = ? AND p.revoked_at IS NULL ORDER BY p.created_at`,
  )
    .bind(userId)
    .all<{ id: string; name: string; created_at: string; passkey: number; granted_at: string | null; computers: number }>();
  return rows.results.map((r) => ({ ...r, passkey: !!r.passkey }));
}

/**
 * v7: the public keys of the passkeys this account's phones registered (revoked ones too: the
 * passkey itself may still be on the device), so a new identity of the same phone can re-use its
 * passkey instead of making another. Public data; the phone proves it holds one with an assertion.
 */
export async function listPasskeys(scope: RequestScope, userId: string): Promise<{ id: string; x: string; y: string }[]> {
  const rows = await scope.env.DB.prepare(`SELECT att, pk FROM account_phones WHERE user_id = ? AND (att IS NOT NULL OR pk IS NOT NULL) ORDER BY created_at DESC LIMIT 32`)
    .bind(userId)
    .all<{ att: string | null; pk: string | null }>();
  const out = new Map<string, { id: string; x: string; y: string }>();
  for (const r of rows.results) {
    let k: { id: string; x: string; y: string } | null = null;
    if (r.pk) k = parseJson<{ id: string; x: string; y: string }>(r.pk);
    else if (r.att) {
      const a = attestedKey(Uint8Array.from(atob(r.att.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((r.att.length + 3) % 4)), (c) => c.charCodeAt(0)));
      if (a) k = { id: a.credId, x: a.x, y: a.y };
    }
    if (k && !out.has(k.id)) out.set(k.id, k);
  }
  return [...out.values()].slice(0, 16);
}

/** One phone's grants (only for its own account, only while it is not revoked). */
export async function grantsFor(scope: RequestScope, userId: string, phoneId: string) {
  if (!PHONE_ID_RE.test(phoneId)) return null;
  const phone = await scope.env.DB.prepare(`SELECT id FROM account_phones WHERE id = ? AND user_id = ? AND revoked_at IS NULL`).bind(phoneId, userId).first();
  if (!phone) return null;
  const rows = await scope.env.DB.prepare(
    `SELECT g.device_id, d.name AS device_name, g.room, g.epoch, g.epk, g.iv, g.ct, g.cpub, g.sig, g.updated_at
       FROM phone_grants g JOIN plus_devices d ON d.id = g.device_id
      WHERE g.phone_id = ? AND d.revoked_at IS NULL AND d.user_id = ? ORDER BY d.created_at`,
  )
    .bind(phoneId, userId)
    .all<{ device_id: string; device_name: string; room: string; epoch: number; epk: string; iv: string; ct: string; cpub: string | null; sig: string | null; updated_at: string }>();
  return rows.results.map((r) => ({ device: { id: r.device_id, name: r.device_name }, room: r.room, epoch: r.epoch, epk: r.epk, iv: r.iv, ct: r.ct, cpub: r.cpub, sig: r.sig, at: r.updated_at }));
}

/** Where each of the account's computers stands on letting this phone in (only for its own account). */
export async function requestsFor(scope: RequestScope, userId: string, phoneId: string) {
  if (!PHONE_ID_RE.test(phoneId)) return [];
  const rows = await scope.env.DB.prepare(
    `SELECT q.device_id, d.name AS device_name, q.state, q.expires_at, q.updated_at, q.commit_h, q.cpub, q.cnonce, q.pake
       FROM phone_requests q JOIN plus_devices d ON d.id = q.device_id
       JOIN account_phones p ON p.id = q.phone_id
      WHERE q.phone_id = ? AND p.user_id = ? AND p.revoked_at IS NULL AND d.revoked_at IS NULL AND d.user_id = ? ORDER BY d.created_at`,
  )
    .bind(phoneId, userId, userId)
    .all<{ device_id: string; device_name: string; state: RequestState; expires_at: string | null; updated_at: string; commit_h: string | null; cpub: string | null; cnonce: string | null; pake: string | null }>();
  // The round of the code exchange: the commitment and the computer key, and the computer's nonce
  // once the phone answered (the phone keeps its own nonce; it is not handed back).
  return rows.results.map((r) => ({
    device: { id: r.device_id, name: r.device_name },
    state: r.state,
    expires_at: r.expires_at,
    at: r.updated_at,
    commit: r.commit_h,
    cpub: r.cpub,
    nonce: r.cnonce,
    // v7: the computer's share of the current attempt (the phone answers it with the typed code).
    ...(r.pake ? { pake: parseJson<PakeRound>(r.pake) } : {}),
  }));
}

/** The phone asks the computers again after a request expired (they each ask the person again). */
export async function askAgain(scope: RequestScope, userId: string, phoneId: string, now = Date.now()): Promise<boolean> {
  if (!PHONE_ID_RE.test(phoneId)) return false;
  const r = await scope.env.DB.prepare(`UPDATE account_phones SET asked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`)
    .bind(new Date(now).toISOString(), phoneId, userId)
    .run();
  return r.meta.changes > 0;
}

/** What a linked computer reads: the account's phones (with what it needs to admit them) and the recently revoked ones. */
export async function phonesForDevice(scope: RequestScope, device: LinkedDevice, now = Date.now()) {
  const phones = await activePhones(scope, device.user_id);
  // This computer's round of the code exchange with each phone: its commitment and the phone's nonce.
  const rounds = await scope.env.DB.prepare(`SELECT phone_id, commit_h, pnonce, pake, pake_answer FROM phone_requests WHERE device_id = ? AND (commit_h IS NOT NULL OR pake IS NOT NULL)`)
    .bind(device.id)
    .all<{ phone_id: string; commit_h: string | null; pnonce: string | null; pake: string | null; pake_answer: string | null }>();
  const roundOf = new Map(rounds.results.map((r) => [r.phone_id, r]));
  const since = new Date(now - REVOKED_LISTED_DAYS * 86_400_000).toISOString();
  const revoked = await scope.env.DB.prepare(`SELECT id, revoked_at FROM account_phones WHERE user_id = ? AND revoked_at IS NOT NULL AND revoked_at > ? ORDER BY revoked_at DESC LIMIT 200`)
    .bind(device.user_id, since)
    .all<{ id: string; revoked_at: string }>();
  return {
    phones: phones.map((p) => ({
      id: p.id,
      name: p.name,
      pub: p.pub,
      ...(p.att && p.cdj ? { att: p.att, cdj: p.cdj } : {}),
      ...(p.pk && p.pkwa ? { pk: parseJson<Pk>(p.pk), pkwa: parseJson<Wa>(p.pkwa) } : {}),
      ...(p.model ? { model: p.model } : {}),
      ...(placeText(p.place) ? { place: placeText(p.place) } : {}),
      created_at: p.created_at,
      ...(p.asked_at ? { asked_at: p.asked_at } : {}),
      ...(roundOf.has(p.id) ? { request: requestView(roundOf.get(p.id)!) } : {}),
    })),
    revoked: revoked.results,
  };
}

export type PutGrantResult = { ok: true } | { ok: false; error: "not_found" | "invalid_request" | "not_your_room"; status: number };

/** A computer stores the pairing it sealed to one of its account's phones (in one of its own rooms). */
export async function putGrant(scope: RequestScope, device: LinkedDevice, phoneId: string, g: GrantInput, now = Date.now()): Promise<PutGrantResult> {
  if (!PHONE_ID_RE.test(phoneId)) return { ok: false, error: "not_found", status: 404 };
  if (!B64.test(g.epk) || !B64.test(g.iv) || !B64.test(g.ct)) return { ok: false, error: "invalid_request", status: 400 };
  const phone = await scope.env.DB.prepare(`SELECT id FROM account_phones WHERE id = ? AND user_id = ? AND revoked_at IS NULL`).bind(phoneId, device.user_id).first();
  if (!phone) return { ok: false, error: "not_found", status: 404 };
  // Only for a room this computer registered (a computer cannot hand phones someone else's room).
  const room = await scope.env.DB.prepare(`SELECT room FROM plus_rooms WHERE room = ? AND device_id = ?`).bind(g.room, device.id).first();
  if (!room) return { ok: false, error: "not_your_room", status: 409 };
  const ts = new Date(now).toISOString();
  await scope.env.DB.prepare(
    `INSERT INTO phone_grants (device_id, phone_id, room, epoch, epk, iv, ct, cpub, sig, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(device_id, phone_id) DO UPDATE SET room = excluded.room, epoch = excluded.epoch, epk = excluded.epk, iv = excluded.iv, ct = excluded.ct,
       cpub = excluded.cpub, sig = excluded.sig, updated_at = excluded.updated_at`,
  )
    .bind(device.id, phoneId, g.room, g.epoch, g.epk, g.iv, g.ct, g.cpub, g.sig, ts)
    .run();
  // The person allowed it on that computer: its request is answered.
  await scope.env.DB.batch([scope.env.DB.prepare(`DELETE FROM phone_requests WHERE device_id = ? AND phone_id = ?`).bind(device.id, phoneId), bumpRev(scope, phoneId)]);
  return { ok: true };
}

const parseJson = <T>(v: string | null | undefined): T | null => {
  if (!v) return null;
  try {
    return JSON.parse(v) as T;
  } catch {
    return null;
  }
};

/** What a computer reads of its round with a phone: v6 (commit, pnonce) or v7 (pake with the phone's answer). */
function requestView(r: { commit_h: string | null; pnonce: string | null; pake: string | null; pake_answer: string | null }) {
  const pake = parseJson<PakeRound>(r.pake);
  if (pake) return { pake: { ...pake, answer: parseJson<PakeAnswer>(r.pake_answer) } };
  return { commit: r.commit_h, pnonce: r.pnonce };
}

export type PutRequestResult = { ok: true } | { ok: false; error: "not_found" | "invalid_request"; status: number };

/** A computer says where the person's confirmation of one of its account's phones stands. */
export type RequestInput = { state: RequestState; expiresAt: string | null; commit?: string; cpub?: string; nonce?: string | null; pake?: PakeRound };
export async function putRequest(scope: RequestScope, device: LinkedDevice, phoneId: string, r: RequestInput, now = Date.now()): Promise<PutRequestResult> {
  if (!PHONE_ID_RE.test(phoneId)) return { ok: false, error: "not_found", status: 404 };
  const timed = r.state === "pending" || r.state === "confirm";
  const expires = timed ? Date.parse(r.expiresAt ?? "") : NaN;
  if (timed && (!Number.isFinite(expires) || expires > now + 60 * 60_000)) return { ok: false, error: "invalid_request", status: 400 };
  // A pending request always carries its round of the code exchange: v6 (commit) or v7 (pake).
  if (r.state === "pending" && (!r.cpub || (!r.commit && !r.pake) || (r.commit && r.pake))) return { ok: false, error: "invalid_request", status: 400 };
  const phone = await scope.env.DB.prepare(`SELECT id FROM account_phones WHERE id = ? AND user_id = ? AND revoked_at IS NULL`).bind(phoneId, device.user_id).first();
  if (!phone) return { ok: false, error: "not_found", status: 404 };
  const ts = new Date(now).toISOString();
  if (r.state === "confirm") {
    // v7: the phone typed the code right; a phone the computer already has must confirm it.
    await scope.env.DB.prepare(
      `INSERT INTO phone_requests (device_id, phone_id, state, expires_at, updated_at) VALUES (?, ?, 'confirm', ?, ?)
       ON CONFLICT(device_id, phone_id) DO UPDATE SET state = 'confirm', expires_at = excluded.expires_at, pake = NULL, pake_answer = NULL, updated_at = excluded.updated_at`,
    )
      .bind(device.id, phoneId, new Date(expires).toISOString(), ts)
      .run();
    await bumpRev(scope, phoneId).run();
    return { ok: true };
  }
  if (r.pake) {
    // v7: this attempt's share; the phone's answer is kept only while the share stays the same.
    await scope.env.DB.prepare(
      `INSERT INTO phone_requests (device_id, phone_id, state, expires_at, cpub, pake, pake_answer, commit_h, pnonce, cnonce, updated_at) VALUES (?1, ?2, 'pending', ?3, ?4, ?5, NULL, NULL, NULL, NULL, ?7)
       ON CONFLICT(device_id, phone_id) DO UPDATE SET
         state = 'pending',
         expires_at = excluded.expires_at,
         pake_answer = CASE WHEN json_extract(phone_requests.pake, '$.ya') = ?6 THEN phone_requests.pake_answer ELSE NULL END,
         pake = excluded.pake,
         cpub = excluded.cpub,
         commit_h = NULL, pnonce = NULL, cnonce = NULL,
         updated_at = excluded.updated_at`,
    )
      .bind(device.id, phoneId, new Date(expires).toISOString(), r.cpub, JSON.stringify(r.pake), r.pake.ya, ts)
      .run();
    await bumpRev(scope, phoneId).run();
    return { ok: true };
  }
  if (r.state !== "pending") {
    await scope.env.DB.prepare(
      `INSERT INTO phone_requests (device_id, phone_id, state, expires_at, updated_at) VALUES (?, ?, ?, NULL, ?)
       ON CONFLICT(device_id, phone_id) DO UPDATE SET state = excluded.state, expires_at = NULL, commit_h = NULL, cpub = NULL, pnonce = NULL, cnonce = NULL, pake = NULL, pake_answer = NULL, updated_at = excluded.updated_at`,
    )
      .bind(device.id, phoneId, r.state, ts)
      .run();
    await bumpRev(scope, phoneId).run();
    return { ok: true };
  }
  // The same round: its expiry, and the computer's nonce only once the phone answered. A new
  // commitment: a new round, both nonces cleared.
  await scope.env.DB.prepare(
    `INSERT INTO phone_requests (device_id, phone_id, state, expires_at, commit_h, cpub, pnonce, cnonce, updated_at) VALUES (?1, ?2, 'pending', ?3, ?4, ?5, NULL, NULL, ?7)
     ON CONFLICT(device_id, phone_id) DO UPDATE SET
       state = 'pending',
       expires_at = excluded.expires_at,
       cnonce = CASE WHEN phone_requests.commit_h = excluded.commit_h AND phone_requests.pnonce IS NOT NULL THEN COALESCE(?6, phone_requests.cnonce) ELSE NULL END,
       pnonce = CASE WHEN phone_requests.commit_h = excluded.commit_h THEN phone_requests.pnonce ELSE NULL END,
       cpub = excluded.cpub,
       commit_h = excluded.commit_h,
       updated_at = excluded.updated_at`,
  )
    .bind(device.id, phoneId, new Date(expires).toISOString(), r.commit, r.cpub, r.nonce ?? null, ts)
    .run();
  await bumpRev(scope, phoneId).run();
  return { ok: true };
}

export type PakeResult = { ok: true; fresh: boolean } | { ok: false; error: "not_found" | "already_answered"; status: number };

/**
 * v7: the phone's answer to one attempt of a computer's code exchange (the person typed the code
 * the computer shows): once per attempt, only while the attempt is the computer's current one.
 */
export async function answerPake(scope: RequestScope, userId: string, phoneId: string, a: { device: string } & PakeAnswer): Promise<PakeResult> {
  if (!PHONE_ID_RE.test(phoneId)) return { ok: false, error: "not_found", status: 404 };
  const row = await scope.env.DB.prepare(
    `SELECT q.pake, q.pake_answer FROM phone_requests q JOIN account_phones p ON p.id = q.phone_id JOIN plus_devices d ON d.id = q.device_id
      WHERE q.phone_id = ? AND q.device_id = ? AND q.state = 'pending' AND q.pake IS NOT NULL
        AND p.user_id = ? AND p.revoked_at IS NULL AND d.user_id = ? AND d.revoked_at IS NULL`,
  )
    .bind(phoneId, a.device, userId, userId)
    .first<{ pake: string; pake_answer: string | null }>();
  const round = parseJson<PakeRound>(row?.pake);
  if (!row || !round || round.n !== a.n || round.ya !== a.ya) return { ok: false, error: "not_found", status: 404 };
  const answer = JSON.stringify({ n: a.n, ya: a.ya, yb: a.yb, tag: a.tag, ...(a.wa ? { wa: a.wa } : {}) });
  if (row.pake_answer !== null) return row.pake_answer === answer ? { ok: true, fresh: false } : { ok: false, error: "already_answered", status: 409 };
  const r = await scope.env.DB.prepare(`UPDATE phone_requests SET pake_answer = ? WHERE phone_id = ? AND device_id = ? AND pake = ? AND pake_answer IS NULL`)
    .bind(answer, phoneId, a.device, row.pake)
    .run();
  if (!r.meta.changes) return { ok: false, error: "already_answered", status: 409 };
  await bumpRev(scope, phoneId).run();
  return { ok: true, fresh: true };
}

export type SasResult = { ok: true; fresh: boolean } | { ok: false; error: "not_found" | "already_answered"; status: number };

/** The phone answers one computer's commitment with its own nonce: once per round (`fresh`: stored now). */
export async function answerSas(scope: RequestScope, userId: string, phoneId: string, a: { device: string; commit: string; pnonce: string }): Promise<SasResult> {
  if (!PHONE_ID_RE.test(phoneId)) return { ok: false, error: "not_found", status: 404 };
  const row = await scope.env.DB.prepare(
    `SELECT q.pnonce FROM phone_requests q JOIN account_phones p ON p.id = q.phone_id JOIN plus_devices d ON d.id = q.device_id
      WHERE q.phone_id = ? AND q.device_id = ? AND q.commit_h = ? AND q.state = 'pending'
        AND p.user_id = ? AND p.revoked_at IS NULL AND d.user_id = ? AND d.revoked_at IS NULL`,
  )
    .bind(phoneId, a.device, a.commit, userId, userId)
    .first<{ pnonce: string | null }>();
  if (!row) return { ok: false, error: "not_found", status: 404 };
  if (row.pnonce !== null) return row.pnonce === a.pnonce ? { ok: true, fresh: false } : { ok: false, error: "already_answered", status: 409 };
  const r = await scope.env.DB.prepare(`UPDATE phone_requests SET pnonce = ? WHERE phone_id = ? AND device_id = ? AND commit_h = ? AND pnonce IS NULL`)
    .bind(a.pnonce, phoneId, a.device, a.commit)
    .run();
  return r.meta.changes > 0 ? { ok: true, fresh: true } : { ok: false, error: "already_answered", status: 409 };
}

// --- push: the computers hear at once that the account's phones changed ----------------------

/** A relay room's internal "phones changed" call (only reachable through the RELAY binding). */
export const PHONES_HINT_PATH = "/__phones";
/** At most this many rooms are told per change (an account has a few computers). */
const HINT_ROOMS_MAX = 32;

/**
 * Tells each linked computer of the account, through the relay room it is connected to, that the
 * account's phones changed (a phone joined, answered a code round, asked again or was revoked).
 * The room sends its writer a fixed {"t":"phones_changed"} with nothing in it; the computer then
 * reads GET /api/plus/phones as it always does. Best effort: a computer that misses it (offline,
 * or a bridge without push) reads on its own timer. Never throws. -> the rooms told.
 */
export async function nudgeComputers(scope: RequestScope, userId: string): Promise<number> {
  const ns = scope.env.RELAY;
  if (!ns) return 0;
  try {
    const rows = await scope.env.DB.prepare(
      `SELECT DISTINCT r.room FROM plus_rooms r JOIN plus_devices d ON d.id = r.device_id
        WHERE r.user_id = ? AND d.user_id = ? AND d.revoked_at IS NULL LIMIT ?`,
    )
      .bind(userId, userId, HINT_ROOMS_MAX)
      .all<{ room: string }>();
    let told = 0;
    await Promise.all(
      rows.results.map(async ({ room }) => {
        try {
          const res = await ns.get(ns.idFromName(room)).fetch(`https://relay.internal${PHONES_HINT_PATH}`, { method: "POST" });
          if (res.ok) told += 1;
        } catch {
          // That room's relay is unreachable: its computer reads on its timer.
        }
      }),
    );
    return told;
  } catch {
    return 0;
  }
}

/** nudgeComputers after the response (the phone never waits for the relay). */
export function nudgeComputersLater(scope: RequestScope, userId: string): void {
  scope.waitUntil(nudgeComputers(scope, userId));
}

/** The phone's change counter moves: what it reads (requests, grants) may have changed. */
export function bumpRev(scope: RequestScope, phoneId: string) {
  return scope.env.DB.prepare(`UPDATE account_phones SET rev = rev + 1 WHERE id = ?`).bind(phoneId);
}

/** Every phone of the account (a computer was unlinked: its grants and requests went). */
export function bumpAccountRevs(scope: RequestScope, userId: string) {
  return scope.env.DB.prepare(`UPDATE account_phones SET rev = rev + 1 WHERE user_id = ?`).bind(userId);
}

/** How long GET /api/phones/<id>/grants?wait= holds the answer at most, and how often it looks. */
export const GRANTS_WAIT_MS = 20_000;
export const GRANTS_CHECK_MS = 500;
export const SIG_RE = /^[0-9a-f]{32}$/;

async function sigOf(v: unknown): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(v))));
  return Array.from(d.subarray(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * One phone's grants and requests (as grantsFor and requestsFor give them) and `sig`, a digest of
 * both. With `since` (the sig the phone last saw), the answer waits until they change or `waitMs`
 * passed (a long poll: the phone sees a computer's next step within about GRANTS_CHECK_MS, with
 * one request instead of one a second). While it waits it reads only the phone's change counter
 * (`rev`, one primary-key read per GRANTS_CHECK_MS) and reads everything again only when it moved.
 * A write that forgot to move it only delays the answer to the end of the wait.
 * -> null when the phone is not the account's.
 */
export async function waitForGrants(
  scope: RequestScope,
  userId: string,
  phoneId: string,
  { since = null, signal, waitMs = GRANTS_WAIT_MS, checkMs = GRANTS_CHECK_MS }: { since?: string | null; signal?: AbortSignal; waitMs?: number; checkMs?: number } = {},
) {
  const read = async () => {
    const grants = await grantsFor(scope, userId, phoneId);
    if (!grants) return null;
    const requests = await requestsFor(scope, userId, phoneId);
    return { grants, requests, sig: await sigOf({ grants, requests }) };
  };
  const rev = async () =>
    (await scope.env.DB.prepare(`SELECT rev FROM account_phones WHERE id = ? AND user_id = ?`).bind(phoneId, userId).first<{ rev: number }>())?.rev ?? null;
  if (!since || !SIG_RE.test(since)) return read();
  // The counter first: a write between it and the read below is seen by the next look.
  let seen = await rev();
  let v = await read();
  const end = Date.now() + Math.min(waitMs, GRANTS_WAIT_MS);
  while (v && v.sig === since && Date.now() + checkMs <= end && !signal?.aborted) {
    await new Promise((r) => setTimeout(r, checkMs));
    const now = await rev();
    if (now === seen) continue;
    seen = now;
    v = await read();
  }
  return v;
}

export async function deleteGrant(scope: RequestScope, device: LinkedDevice, phoneId: string): Promise<boolean> {
  if (!PHONE_ID_RE.test(phoneId)) return false;
  const r = await scope.env.DB.prepare(`DELETE FROM phone_grants WHERE device_id = ? AND phone_id = ?`).bind(device.id, phoneId).run();
  if (r.meta.changes > 0) await bumpRev(scope, phoneId).run();
  return r.meta.changes > 0;
}
